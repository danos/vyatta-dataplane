/*
 * Handle L2TPv3 GeNetlink events
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>
#include <linux/genetlink.h>
#include <linux/l2tp.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_udp.h>

#include "compiler.h"
#include "dp_event.h"
#include "pipeline/nodes/cross_connect/cross_connect.h"
#include "if_var.h"
#include "l2tpeth.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

struct nlattr;
struct nlmsghdr;

#define L2TP_TUNNEL_HASH_MIN 16
#define L2TP_TUNNEL_HASH_BITS 9
#define L2TP_TUNNEL_HASH_MAX (1u << L2TP_TUNNEL_HASH_BITS)
#define L2TP_PAYLOAD_OFFSET GENL_HDRLEN

struct l2tp_session_hash_tbl {
	struct cds_lfht *sess_hash;
	unsigned long sess_seed;
};
static struct l2tp_session_hash_tbl *l2tp_sessions;

/* List to iterate over all tunnels. */
static CDS_LIST_HEAD(l2tp_tunnel_list);

static struct ifnet *l2tpeth_attach_session(const char *ifname,
					    struct l2tp_session *session,
					    uint16_t mtu);

static struct l2tp_tunnel_cfg *
l2tp_tunnel_byid(uint32_t tunnel_id)
{
	struct l2tp_tunnel_cfg *tunnel = NULL;

	cds_list_for_each_entry_rcu(tunnel, &l2tp_tunnel_list,
				    tunnel_list) {
		if (tunnel->tunnel_id == tunnel_id)
			return tunnel;
	}
	return NULL;
}

static inline uint32_t
l2tp_session_hash(uint32_t key, unsigned long seed)
{
	return hash32(key ^ seed, L2TP_TUNNEL_HASH_BITS);
}

static inline int
l2tp_session_match(struct cds_lfht_node *node,
		   const void *key)
{
	const struct l2tp_session *session
		= caa_container_of(node, const struct l2tp_session,
				   session_node);

	return session->session_id == *(const uint32_t *)key;
}

struct l2tp_session *
l2tp_session_byid(uint32_t session_id)
{
	struct cds_lfht_iter iter;

	cds_lfht_lookup(l2tp_sessions->sess_hash,
			l2tp_session_hash(session_id,
					  l2tp_sessions->sess_seed),
			l2tp_session_match, &session_id, &iter);
	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);

	if (likely(node != NULL))
		return caa_container_of(node, struct l2tp_session,
					session_node);
	else
		return NULL;

}

void l2tp_session_walk(l2tp_iter_func_t func, void *arg)
{
	struct cds_lfht_iter iter;
	struct l2tp_session *session;

	cds_lfht_for_each_entry(l2tp_sessions->sess_hash, &iter,
				session, session_node) {
		(func)(session, arg);
	}
}

void l2tp_tunnel_walk(l2tp_iter_func_t func, void *arg)
{

	struct l2tp_tunnel_cfg *tunnel = NULL;

	cds_list_for_each_entry_rcu(tunnel, &l2tp_tunnel_list,
				    tunnel_list) {
		(func)(tunnel, arg);
	}
}

static void l2tp_xconnect_update(struct ifnet *dpifp,
				 struct l2tp_session *old_session,
				 struct l2tp_session *new_session,
				 struct ifnet *l2tpifp, uint8_t ttl)
{
	if (likely(old_session != NULL)) {
		struct ifnet *old_dpifp;

		old_session->flags |= L2TP_LNS_MODE;
		old_dpifp = ifnet_byifindex(old_session->xconnect_ifidx);
		if (old_dpifp) {
			cross_connect_unlink(old_dpifp, true);
			cross_connect_unlink(l2tpifp, true);
		}
		old_session->xconnect_ifidx = 0;
	}

	if (likely(new_session != NULL)) {
		new_session->xconnect_ifidx = dpifp->if_index;
		new_session->flags &= ~L2TP_LNS_MODE;
		new_session->ttl = ttl;

		cross_connect_link(l2tpifp, dpifp, true);
		cross_connect_link(dpifp, l2tpifp, true);
	}
}

static int
l2tp_session_insert(struct l2tp_session *sess, uint32_t s_id)
{
	struct cds_lfht_node *ret_node;

	cds_lfht_node_init(&sess->session_node);

	unsigned long hash = l2tp_session_hash(s_id,
					       l2tp_sessions->sess_seed);

	ret_node = cds_lfht_add_unique(l2tp_sessions->sess_hash, hash,
				       l2tp_session_match, &s_id,
				       &sess->session_node);

	return (ret_node != &sess->session_node) ? EEXIST : 0;
}

static void
l2tp_session_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct l2tp_session, session_rcu));
}

static inline void l2tp_session_inc_refcnt(struct l2tp_session *session)
{
	rte_atomic16_inc(&session->refcnt);
}

static inline void l2tp_session_dec_refcnt(struct l2tp_session *session)
{
	if (rte_atomic16_dec_and_test(&session->refcnt))
		call_rcu(&session->session_rcu, l2tp_session_free);
}

static void
l2tp_session_delete(struct l2tp_session *session)
{
	if (likely(session != NULL)) {
		cds_lfht_del(l2tp_sessions->sess_hash, &session->session_node);
		l2tp_session_dec_refcnt(session);
	}
}

static void
l2tp_tunnel_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct l2tp_tunnel_cfg, tunnel_rcu));
}


static inline void l2tp_tunnel_inc_refcnt(struct l2tp_tunnel_cfg *tunnel)
{
	rte_atomic16_inc(&tunnel->refcnt);
}

static inline void l2tp_tunnel_dec_refcnt(struct l2tp_tunnel_cfg *tunnel)
{
	if (rte_atomic16_dec_and_test(&tunnel->refcnt))
		call_rcu(&tunnel->tunnel_rcu, l2tp_tunnel_free);
}

static struct l2tp_session *
l2tp_session_set_info(struct l2tp_session *session, uint32_t session_id,
		      uint32_t peer_session_id,
		      uint8_t cookie_len, const uint8_t *cookie,
		      uint8_t peer_cookie_len, const uint8_t *peer_cookie,
		      bool seq, const char *ifname, uint16_t mtu)
{
	uint16_t hdr_len = 0;

	session->session_id = session_id;
	session->peer_session_id = peer_session_id;

	if (cookie_len) {
		session->cookie_len = cookie_len;
		memcpy((char *)&session->cookie[0],
		       cookie,
		       session->cookie_len);

		hdr_len += session->cookie_len;
	} else
		session->cookie_len = 0;

	if (peer_cookie_len) {
		session->peer_cookie_len = peer_cookie_len;
		memcpy((char *)&session->peer_cookie[0], peer_cookie,
		       session->peer_cookie_len);
	}

	session->flags |= L2TP_LNS_MODE;

	if (seq) {
		session->flags |= L2TP_ENCAP_SEQ;

		hdr_len += 4;
	} else {
		session->flags &= ~L2TP_ENCAP_SEQ;
		session->local_seq = session->peer_seq = 0;
	}

	if (!(session->tunnel->flags & L2TP_TUNNEL_ENCAP_UDP)) {
		hdr_len += 4;
		session->flags &= ~L2TP_ENCAP_UDP;
	} else {
		hdr_len += 8 + sizeof(struct udp_hdr);
		session->flags |= L2TP_ENCAP_UDP;
	}
	session->flags |= L2TP_LNS_MODE;

	session->sport = session->tunnel->local_udp_port;
	session->dport = session->tunnel->peer_udp_port;

	memcpy(&session->s_addr,
	       &session->tunnel->s_addr,
	       sizeof(session->s_addr));
	memcpy(&session->d_addr,
	       &session->tunnel->d_addr,
	       sizeof(session->s_addr));
	if (session->tunnel->flags & L2TP_TUNNEL_ENCAP_IPV4) {
		hdr_len += 20;
		session->flags |= L2TP_ENCAP_IPV4;
	} else  {
		hdr_len += 40;
		session->flags &= ~L2TP_ENCAP_IPV4;
	}

	session->hdr_len = hdr_len;

	session->ifp = l2tpeth_attach_session(ifname, session, mtu);
	if (!session->ifp)
		RTE_LOG(ERR, L2TP,
			"couldn't find l2tpeth interface %s for %d:%d\n",
			ifname, session_id, peer_session_id);

	return session;
}

static int
l2tp_genl_session_create_modify(uint32_t tunnel_id, uint32_t session_id,
				uint32_t peer_session_id,
				uint8_t cookie_len, const uint8_t *cookie,
				uint8_t peer_cookie_len, const uint8_t *peer_cookie,
				uint8_t seq, const char *ifname, uint16_t mtu)
{
	struct l2tp_tunnel_cfg *tunnel = NULL;
	struct l2tp_session *session = NULL;
	struct l2tp_session *old_session = NULL;
	size_t sz;

	tunnel = l2tp_tunnel_byid(tunnel_id);

	if (unlikely(tunnel == NULL)) {
		RTE_LOG(ERR, L2TP,
			"couldn't find l2tp tunnel:session for %d:%d\n",
			tunnel_id, session_id);
		return MNL_CB_ERROR;
	}

	old_session = l2tp_session_byid(session_id);

	sz = sizeof(struct l2tp_session) +
		((get_lcore_max() + 1) * sizeof(struct l2tp_stats));
	session = zmalloc_aligned(sz);
	if (unlikely(session == NULL)) {
		RTE_LOG(ERR, L2TP,
			"can't allocate l2tp session %d:%d\n",
			tunnel_id, session_id);

		return MNL_CB_ERROR;
	}

	l2tp_tunnel_inc_refcnt(tunnel);
	session->tunnel = tunnel;
	rte_atomic16_set(&session->refcnt, 1);
	l2tp_session_set_info(session, session_id, peer_session_id,
			      cookie_len, cookie,
			      peer_cookie_len, peer_cookie,
			      seq, ifname, mtu);

	if (old_session) {
		if (old_session->xconnect_ifidx)
			l2tp_xconnect_update(
				  ifnet_byifindex(old_session->xconnect_ifidx),
				  old_session,
				  session,
				  session->ifp,
				  session->ttl);

		l2tp_session_delete(old_session);
		l2tp_tunnel_dec_refcnt(tunnel);
	}
	l2tp_session_insert(session, session_id);

	return MNL_CB_OK;
}

static int
l2tp_genl_session_delete(uint32_t tunnel_id, uint32_t session_id)
{
	struct l2tp_tunnel_cfg *tunnel = NULL;
	struct l2tp_session *session = NULL;

	tunnel = l2tp_tunnel_byid(tunnel_id);
	if (unlikely(tunnel == NULL)) {
		RTE_LOG(ERR, L2TP,
			"can't find l2tp tunnel for %d:%d\n",
			tunnel_id, session_id);
	}

	session = l2tp_session_byid(session_id);
	if (unlikely(session == NULL)) {
		RTE_LOG(ERR, L2TP,
			"can't find l2tp session %d:%d\n",
			tunnel_id, session_id);
	} else {
		l2tp_session_delete(session);
		if (likely(tunnel != NULL))
			l2tp_tunnel_dec_refcnt(tunnel);
	}

	return MNL_CB_OK;
}

static void
l2tp_tunnel_set_info(struct l2tp_tunnel_cfg *tunnel, struct nlattr **tb)
{

	if (tb[L2TP_ATTR_IP_SADDR] &&
	    tb[L2TP_ATTR_IP_DADDR]) {
		tunnel->s_addr.ipv4.s_addr =
		  mnl_attr_get_u32(tb[L2TP_ATTR_IP_SADDR]);
		tunnel->d_addr.ipv4.s_addr =
		  mnl_attr_get_u32(tb[L2TP_ATTR_IP_DADDR]);
		tunnel->flags |= L2TP_TUNNEL_ENCAP_IPV4;
	} else {
		tunnel->flags &= ~L2TP_TUNNEL_ENCAP_IPV4;
		memcpy(&tunnel->s_addr.ipv6,
		       mnl_attr_get_payload(tb[L2TP_ATTR_IP6_SADDR]),
		       sizeof(tunnel->s_addr.ipv6));
		memcpy(&tunnel->d_addr.ipv6,
		       mnl_attr_get_payload(tb[L2TP_ATTR_IP6_DADDR]),
		       sizeof(tunnel->d_addr.ipv6));

	}

	tunnel->peer_tunnel_id = mnl_attr_get_u32(tb[L2TP_ATTR_PEER_CONN_ID]);

	if (mnl_attr_get_u32(tb[L2TP_ATTR_ENCAP_TYPE]) == L2TP_ENCAPTYPE_IP)
		tunnel->flags &= ~L2TP_TUNNEL_ENCAP_UDP;
	else
		tunnel->flags |= L2TP_TUNNEL_ENCAP_UDP;

	if (tb[L2TP_ATTR_UDP_SPORT] &&
	    tb[L2TP_ATTR_UDP_DPORT]) {
		tunnel->local_udp_port =
		  mnl_attr_get_u32(tb[L2TP_ATTR_UDP_SPORT]);
		tunnel->peer_udp_port =
		  mnl_attr_get_u32(tb[L2TP_ATTR_UDP_DPORT]);
	}
}

static int
l2tp_genl_tunnel_create_modify(uint32_t tunnel_id, struct nlattr **tb)
{
	struct l2tp_tunnel_cfg *tunnel = NULL;

	/* Find existing, or create new */
	tunnel = l2tp_tunnel_byid(tunnel_id);
	if (!tunnel) {
		tunnel = zmalloc_aligned(sizeof(*tunnel));
		if (!tunnel) {
			RTE_LOG(ERR, L2TP, "can't allocate l2tp tunnel %d\n",
				tunnel_id);
			return MNL_CB_ERROR;
		}

		rte_atomic16_set(&tunnel->refcnt, 1);
		tunnel->tunnel_id = tunnel_id;
		l2tp_tunnel_set_info(tunnel, tb);
		cds_list_add_tail_rcu(&tunnel->tunnel_list, &l2tp_tunnel_list);

		return MNL_CB_OK;
	}

	/* Modify existing */
	l2tp_tunnel_set_info(tunnel, tb);

	struct l2tp_session *old_session = l2tp_session_byid(tunnel->tunnel_id);
	if (!old_session)
		return MNL_CB_OK;

	if (!old_session->ifp) {
		l2tp_session_delete(old_session);
		RTE_LOG(ERR, L2TP, "old session has null ifp (%d)\n",
			tunnel_id);
		return MNL_CB_OK;
	}

	l2tp_genl_session_create_modify(
			    tunnel->tunnel_id,
			    old_session->session_id,
			    old_session->peer_session_id,
			    old_session->cookie_len,
			    old_session->cookie,
			    old_session->peer_cookie_len,
			    old_session->peer_cookie,
			    (old_session->flags & L2TP_ENCAP_SEQ),
			    old_session->ifp->if_name,
			    old_session->mtu);

	return MNL_CB_OK;
}

static int
l2tp_genl_tunnel_delete(uint32_t tunnel_id)
{
	struct l2tp_tunnel_cfg *tunnel = NULL;

	tunnel = l2tp_tunnel_byid(tunnel_id);

	if (!tunnel)
		RTE_LOG(ERR, L2TP, "couldn't find l2tp tunnel %d\n", tunnel_id);
	else {
		cds_list_del_rcu(&tunnel->tunnel_list);

		l2tp_tunnel_dec_refcnt(tunnel);
	}

	return MNL_CB_OK;
}

static int
l2tp_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (unlikely(mnl_attr_type_valid(attr, L2TP_ATTR_MAX) < 0))
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int
rtnl_process_l2tp_tunnel(const struct nlmsghdr *nlh)
{
	struct genlmsghdr *genlhdr = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[L2TP_ATTR_MAX+1] = { NULL };
	int ret;

	ret = mnl_attr_parse(nlh, GENL_HDRLEN, l2tp_attr, tb);
	if (unlikely(ret != MNL_CB_OK)) {
		RTE_LOG(ERR, L2TP,
			"l2tp: unparseable genl tunnel attributes\n");
		return ret;
	}

	uint32_t tunnel_id = mnl_attr_get_u32(tb[L2TP_ATTR_CONN_ID]);

	switch (genlhdr->cmd) {
	case L2TP_CMD_TUNNEL_GET:
	case L2TP_CMD_TUNNEL_CREATE:
	case L2TP_CMD_TUNNEL_MODIFY:
		ret = l2tp_genl_tunnel_create_modify(tunnel_id, tb);
		break;
	case L2TP_CMD_TUNNEL_DELETE:
		ret = l2tp_genl_tunnel_delete(tunnel_id);
		break;
	default:
		RTE_LOG(ERR, L2TP, "unsupported l2tp commands\n");
		ret = MNL_CB_ERROR;
	}

	return ret;
}

static int
rtnl_process_l2tp_session(const struct nlmsghdr *nlh)
{
	struct genlmsghdr *genlhdr = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[L2TP_ATTR_MAX + 1] = { NULL };

	int ret = mnl_attr_parse(nlh, GENL_HDRLEN, l2tp_attr, tb);
	if (unlikely(ret != MNL_CB_OK)) {
		RTE_LOG(ERR, L2TP,
			"l2tp: unparseable genl session attributes\n");
		return ret;
	}

	uint32_t tunnel_id = mnl_attr_get_u32(tb[L2TP_ATTR_CONN_ID]);
	uint32_t session_id = mnl_attr_get_u32(tb[L2TP_ATTR_SESSION_ID]);

	if (genlhdr->cmd == L2TP_CMD_SESSION_DELETE)
		return l2tp_genl_session_delete(tunnel_id, session_id);

	uint32_t peer_session_id =
			mnl_attr_get_u32(tb[L2TP_ATTR_PEER_SESSION_ID]);

	uint8_t our_cookie_len = 0;
	const uint8_t *our_cookie = NULL;
	if (tb[L2TP_ATTR_COOKIE]) {
		our_cookie_len = mnl_attr_get_payload_len(tb[L2TP_ATTR_COOKIE]);
		our_cookie = mnl_attr_get_payload(tb[L2TP_ATTR_COOKIE]);
	}

	uint8_t peer_cookie_len = 0;
	const uint8_t *peer_cookie = NULL;
	if (tb[L2TP_ATTR_PEER_COOKIE]) {
		peer_cookie_len =
			mnl_attr_get_payload_len(tb[L2TP_ATTR_PEER_COOKIE]);
		peer_cookie = mnl_attr_get_payload(tb[L2TP_ATTR_PEER_COOKIE]);
	}

	uint8_t seq = (tb[L2TP_ATTR_DATA_SEQ]) ? 1 : 0;
	const char *ifname = mnl_attr_get_str(tb[L2TP_ATTR_IFNAME]);

	/* As of commit e9697e2effad5 ("l2tp: ignore L2TP_ATTR_MTU") in the
	 * linux kernel, L2TP_ATTR_MTU is no longer signaled. One should
	 * rely on IFLA_MTU to set the interface MTU.
	 */

	uint16_t mtu = tb[L2TP_ATTR_MTU] ?
		       mnl_attr_get_u16(tb[L2TP_ATTR_MTU]) : ETHER_MTU;

	switch (genlhdr->cmd) {
	case L2TP_CMD_SESSION_GET:
	case L2TP_CMD_SESSION_CREATE:
	case L2TP_CMD_SESSION_MODIFY:
		ret = l2tp_genl_session_create_modify(
				tunnel_id, session_id, peer_session_id,
				our_cookie_len, our_cookie,
				peer_cookie_len, peer_cookie,
				seq, ifname, mtu);
		break;
	default:
		RTE_LOG(ERR, L2TP,
			"unsupported l2tp commands\n");
		ret = MNL_CB_ERROR;
	}
	return ret;
}

int
rtnl_process_l2tp(const struct nlmsghdr *nlh,
		      void *data __unused)
{
	int ret = MNL_CB_OK;
	struct genlmsghdr *genlhdr = mnl_nlmsg_get_payload(nlh);

	switch (genlhdr->cmd) {
	case L2TP_CMD_TUNNEL_CREATE:
	case L2TP_CMD_TUNNEL_MODIFY:
	case L2TP_CMD_TUNNEL_DELETE:
	case L2TP_CMD_TUNNEL_GET:
		ret = rtnl_process_l2tp_tunnel(nlh);
		break;
	case L2TP_CMD_SESSION_CREATE:
	case L2TP_CMD_SESSION_MODIFY:
	case L2TP_CMD_SESSION_DELETE:
	case L2TP_CMD_SESSION_GET:
		ret = rtnl_process_l2tp_session(nlh);
		break;
	default:
		RTE_LOG(ERR, L2TP,
			"unsupported l2tp commands\n");
		ret = MNL_CB_ERROR;
	}

	return ret;
}

static struct ifnet *
l2tpeth_create_internal(const char *ifname, unsigned int mtu,
			const struct ether_addr *addr)
{
	struct ifnet *ifp;

	ifp = if_alloc(ifname, IFT_L2TPETH, mtu, addr, SOCKET_ID_ANY);
	if (!ifp)
		goto bad;

	return ifp;

bad:
	RTE_LOG(NOTICE, L2TP, "out of memory for l2tp_ifnet\n");
	return NULL;
}

static struct ifnet *
l2tpeth_attach_session(const char *ifname, struct l2tp_session *session,
		       uint16_t mtu)
{
	struct ifnet *ifp;

	ifp = ifnet_byifname(ifname);
	if (!ifp) {
		ifp = l2tpeth_create_internal(ifname, mtu, NULL);
		if (!ifp)
			return NULL;
	}

	struct l2tp_softc *sc = ifp->if_softc;

	if (sc->sclp_session && sc->sclp_session != session)
		l2tp_session_dec_refcnt(sc->sclp_session);
	l2tp_session_inc_refcnt(session);
	rcu_assign_pointer(sc->sclp_session, session);

	return ifp;
}

static struct ifnet *
l2tpeth_reuse(struct ifnet *ifp, const struct ether_addr *addr)
{
	if (ifp->if_type != IFT_L2TPETH) {
		RTE_LOG(ERR, L2TP, "mismatch type for %s\n", ifp->if_name);
		return NULL;
	}

	RTE_LOG(DEBUG, L2TP, "reusing existing interface: %s\n", ifp->if_name);

	if_unset_ifindex(ifp); /* if_set_ifindex does this. */

	ether_addr_copy(addr, &ifp->eth_addr);

	return ifp;
}

struct ifnet *
l2tpeth_create(int ifindex, const char *ifname, unsigned int mtu,
	       const struct ether_addr *addr)
{
	struct ifnet *ifp;

	if (!addr) {
		RTE_LOG(ERR, L2TP, "missing mac address for %s\n", ifname);
		return NULL;
	}

	/* Try to reuse an existing interface */
	ifp = ifnet_byifname(ifname);
	if (ifp)
		ifp = l2tpeth_reuse(ifp, addr);
	else
		ifp = l2tpeth_create_internal(ifname, mtu, addr);

	if (!ifp)
		return NULL;

	if_set_ifindex(ifp, ifindex);

	return ifp;
}

static int l2tpeth_if_init(struct ifnet *ifp)
{
	struct l2tp_softc *sc = NULL;

	sc = zmalloc_aligned(sizeof(*sc));
	if (!sc)
		return -ENOMEM;

	if (!if_setup_vlan_storage(ifp)) {
		free(sc);
		return -ENOMEM;
	}

	rcu_assign_pointer(ifp->if_softc, sc);

	return 0;
}

static void
l2tp_sc_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct l2tp_softc, sclp_rcu));
}

static void
l2tpeth_if_uninit(struct ifnet *ifp)
{
	struct l2tp_softc *sc = ifp->if_softc;

	if (!sc)
		return;

	if (sc->sclp_session) {
		sc->sclp_session->ifp = NULL;
		l2tp_session_dec_refcnt(sc->sclp_session);
	}
	ifp->if_softc = NULL;
	call_rcu(&sc->sclp_rcu, l2tp_sc_free);
}

void l2tp_stats(const struct l2tp_session *session, struct l2tp_stats *stats)
{
	unsigned int lcore, i, n = sizeof(struct l2tp_stats) / sizeof(uint64_t);
	uint64_t *sum = (uint64_t *) stats;

	memset(sum, 0, sizeof(struct l2tp_stats));

	FOREACH_DP_LCORE(lcore) {
		const uint64_t *pcpu
			= (const uint64_t *) &session->stats[lcore];

		for (i = 0; i < n; i++)
			sum[i] += pcpu[i];
	}
}

static void l2tp_session_init_stats(struct l2tp_session *session)
{
	unsigned int lcore;

	FOREACH_DP_LCORE(lcore) {
		struct l2tp_stats *stats = &session->stats[lcore];

		stats->rx_oos_discards = 0;
		stats->rx_cookie_discards = 0;
	}
}

static void l2tp_init_stats_all(void)
{
	struct cds_lfht_iter iter;
	struct l2tp_session *session;

	cds_lfht_for_each_entry(l2tp_sessions->sess_hash, &iter,
				session, session_node) {
		l2tp_session_init_stats(session);
	}
}

void l2tp_init_stats(struct l2tp_session *session)
{
	if (session != NULL)
		return l2tp_session_init_stats(session);
	return l2tp_init_stats_all();
}

int l2tp_set_xconnect(char *cmd, char *dpifname, char *l2tpifname, char *ttl)
{
	struct ifnet *dpifp = ifnet_byifname(dpifname);

	if (unlikely(dpifp == NULL)) {
		RTE_LOG(ERR, L2TP,
			"Xconnect couldn't find dataplane interface %s for l2tpeth i/f %s\n",
			dpifname, l2tpifname);
		return -1;
	}

	struct ifnet *l2tpifp = ifnet_byifname(l2tpifname);

	if (unlikely(l2tpifp == NULL)) {
		RTE_LOG(ERR, L2TP,
			"Xconnect couldn't find l2tpeth interface %s for dataplane i/f %s\n",
			l2tpifname, dpifname);
		return -1;
	}

	struct l2tp_session *session =
		((struct l2tp_softc *)l2tpifp->if_softc)->sclp_session;

	if (unlikely(session == NULL)) {
		RTE_LOG(ERR, L2TP,
			"Xconnect couldn't find l2tp session for l2tpeth interface %s and dataplane i/f %s\n",
			l2tpifname, dpifname);
		return -1;
	}

	if (strcmp(cmd, "add") == 0) {
		if (session->xconnect_ifidx)
			l2tp_xconnect_update(dpifp, session, session,
					     l2tpifp, atoi(ttl));
		else
			l2tp_xconnect_update(dpifp, NULL, session, l2tpifp,
					     atoi(ttl));
	} else if (strcmp(cmd, "remove") == 0) {
		l2tp_xconnect_update(dpifp, session, NULL, l2tpifp,
				     atoi(ttl));
		session->ttl = 0;
	} else if (strcmp(cmd, "update") == 0) {
		if (session->xconnect_ifidx != dpifp->if_index)
			l2tp_xconnect_update(dpifp, session, session,
					     l2tpifp, atoi(ttl));
		else
			session->ttl = atoi(ttl);
	}

	return 0;
}

static const struct ift_ops l2tpeth_if_ops = {
	.ifop_init = l2tpeth_if_init,
	.ifop_uninit = l2tpeth_if_uninit,
};

static void l2tpeth_init(void)
{
	int ret = if_register_type(IFT_L2TPETH, &l2tpeth_if_ops);

	if (ret < 0)
		rte_panic("Failed to register L2TPEth type: %s",
			  strerror(-ret));

	l2tp_sessions = zmalloc_aligned(sizeof(struct l2tp_session_hash_tbl));
	if (unlikely(l2tp_sessions == NULL))
		rte_panic("Out of memory for l2tp session hash table\n");

	l2tp_sessions->sess_hash = cds_lfht_new(L2TP_TUNNEL_HASH_MIN,
						L2TP_TUNNEL_HASH_MIN,
						L2TP_TUNNEL_HASH_MAX,
						CDS_LFHT_AUTO_RESIZE,
						NULL);

	if (unlikely(l2tp_sessions->sess_hash == NULL))
		rte_panic("Can't allocate sess_hash\n");

	l2tp_sessions->sess_seed = random();
}

static const struct dp_event_ops l2tpeth_events = {
	.init = l2tpeth_init,
};

DP_STARTUP_EVENT_REGISTER(l2tpeth_events);
