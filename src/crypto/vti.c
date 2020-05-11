/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <libmnl/libmnl.h>
#define _LINUX_IP_H /* linux/ip.h conflicts with netinet/ip.h */
#include <linux/if_ether.h>
#include <linux/if_tunnel.h>
#include <linux/snmp.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/xfrm.h>
#include <linux/icmp.h>

#include <netinet/icmp6.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memory.h>

#include "capture.h"
#include "control.h"
#include "crypto.h"
#include "crypto_internal.h"
#include "dp_event.h"
#include "esp.h"
#include "if_var.h"
#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "pktmbuf_internal.h"
#include "shadow.h"
#include "snmp_mib.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "vti.h"

struct rte_ether_addr;
struct nlattr;

#define VTI_DEBUG(args...)			\
	DP_DEBUG(VTI, DEBUG, VTI, args)

#define VTI_ERR(args...)			\
	DP_DEBUG(VTI, ERR, VTI, args)

#define VTI_INFO(args...)			\
	DP_DEBUG(VTI, INFO, VTI, args)

/* Dummy logging function to force checking of args */
static inline void __attribute__((format(printf, 1, 2)))
no_printf(const char *fmt __attribute__((unused)), ...) {  }

#define VTI_DEBUG_PKT(args...) no_printf(args)

struct vti_ctxt_table {
	struct cds_lfht *vti_ctxt_ht;
	unsigned long vti_ctxt_seed;
};

struct vti_tunnel_key {
	xfrm_address_t src;
	xfrm_address_t dst;
	uint8_t        family;
	uint32_t       mark;
};

struct vti_tunnel_ctxt {
	struct vti_tunnel_key key;
	struct ifnet        *ifp;
	struct cds_lfht_node hash_node;
	vrfid_t              t_vrfid; /* Transport VRF ID */
	bool                 reqid_valid;
	uint32_t             reqid;
	struct crypto_overhead ipsec_overhead;
	bool                 overhead_subscribed;
	struct rcu_head      rcu;
	uint16_t             mtu;
};

static unsigned int vti_ctxt_hash(const struct vti_tunnel_key *key,
				  unsigned long seed)
{
	if (key->family == AF_INET)
		return rte_jhash_2words(key->dst.a4,
					key->mark,
					seed);

	else
		return rte_jhash_2words(key->dst.a6[0] +
					key->dst.a6[1] +
					key->dst.a6[2] +
					key->dst.a6[3],
					key->mark,
					seed);
}

static int vti_ctxt_match(struct cds_lfht_node *node, const void *_key)
{
	struct vti_tunnel_ctxt *ctxt = caa_container_of(node,
							struct vti_tunnel_ctxt,
							hash_node);
	const struct vti_tunnel_key *key = _key;
	int result = 1;

	if ((key->mark != ctxt->key.mark) ||
	    (key->family != ctxt->key.family) ||
	    !xfrm_addr_eq(&key->dst, &ctxt->key.dst, key->family))
		result = 0;

	return result;
}

static struct vti_tunnel_ctxt *vti_ctxt_lookup(const struct vti_ctxt_table *tbl,
					       const struct vti_tunnel_key *key)
{
	struct cds_lfht_iter iter;

	cds_lfht_lookup(tbl->vti_ctxt_ht,
			vti_ctxt_hash(key, tbl->vti_ctxt_seed),
			vti_ctxt_match, key, &iter);

	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);

	if (!node)
		return NULL;

	return caa_container_of(node, struct vti_tunnel_ctxt, hash_node);
}

static int vti_ctxt_insert(const struct vti_ctxt_table *tbl,
			   struct vti_tunnel_ctxt *ctxt)
{
	char dst_str[INET6_ADDRSTRLEN+1];
	struct cds_lfht_node *ret_node;

	DP_DEBUG_W_VRF(VTI, DEBUG, VTI, ctxt->t_vrfid,
		       "INSERT: dst %s family %x mark %x\n",
		       inet_ntop(ctxt->key.family,
				 &ctxt->key.dst,
				 dst_str,
				 sizeof(dst_str)) ?: "<bad address>",
		       ctxt->key.family,
		       ctxt->key.mark);

	cds_lfht_node_init(&ctxt->hash_node);

	ret_node = cds_lfht_add_unique(tbl->vti_ctxt_ht,
				       vti_ctxt_hash(&ctxt->key,
						     tbl->vti_ctxt_seed),
				       vti_ctxt_match,
				       &ctxt->key,
				       &ctxt->hash_node);

	return (ret_node != &ctxt->hash_node) ? EEXIST : 0;
}

static void vti_ctxt_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct vti_tunnel_ctxt, rcu));
}

static void vti_ctxt_remove(const struct vti_ctxt_table *tbl,
			    struct vti_tunnel_ctxt *ctxt)
{
	cds_lfht_del(tbl->vti_ctxt_ht, &ctxt->hash_node);
	call_rcu(&ctxt->rcu, vti_ctxt_free);
}

static int
vti_get_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);
	int len = mnl_attr_get_payload_len(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_VTI_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_VTI_IKEY:
	case IFLA_VTI_OKEY:
	case IFLA_VTI_LINK:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case IFLA_VTI_LOCAL:
	case IFLA_VTI_REMOTE:
		if (len != 4 && len != 16)
			return MNL_CB_ERROR;
		break;
	case IFLA_VTI_UNSPEC:
	default:
		/*Only parse options we care about*/
		tb[type] = NULL;
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int vti_tunnel_key_from_nlattr(struct vti_tunnel_key *cfg,
				      const struct nlattr *data)
{
	struct nlattr *vti_attr[IFLA_VTI_MAX+1] = { NULL };

	if (mnl_attr_parse_nested(data,	vti_get_attr, vti_attr) != MNL_CB_OK)
		return -1;

	if (vti_attr[IFLA_VTI_OKEY]) {
		cfg->mark = htonl(mnl_attr_get_u32(vti_attr[IFLA_VTI_OKEY]));
		VTI_INFO("okey is %x\n", cfg->mark);
	}
	if (vti_attr[IFLA_VTI_LINK]) {
		uint32_t link = mnl_attr_get_u32(vti_attr[IFLA_VTI_LINK]);

		VTI_INFO("link is %x\n", link);
	}
	if (vti_attr[IFLA_VTI_LOCAL]) {
		void *src = mnl_attr_get_payload(vti_attr[IFLA_VTI_LOCAL]);
		uint16_t src_len = mnl_attr_get_payload_len(
			vti_attr[IFLA_VTI_LOCAL]);
		char buf[INET6_ADDRSTRLEN];

		memcpy(&cfg->src, src,
			(src_len < sizeof(cfg->src)) ?
			src_len : sizeof(cfg->src));
		cfg->family = (src_len == 4) ? AF_INET : AF_INET6;
		inet_ntop(cfg->family, &cfg->src, buf, sizeof(buf));
		VTI_INFO("local is %s\n", buf);
	}
	if (vti_attr[IFLA_VTI_REMOTE]) {
		void *dst = mnl_attr_get_payload(vti_attr[IFLA_VTI_REMOTE]);
		uint16_t dst_len = mnl_attr_get_payload_len(
			vti_attr[IFLA_VTI_REMOTE]);
		char buf[INET6_ADDRSTRLEN];

		memcpy(&cfg->dst, dst,
			(dst_len < sizeof(cfg->dst)) ?
			dst_len : sizeof(cfg->dst));
		if (cfg->family != ((dst_len == 4) ? AF_INET : AF_INET6)) {
			VTI_ERR("address family mismatch in netlink data\n");
			return -1;
		}
		inet_ntop(cfg->family, &cfg->dst, buf, sizeof(buf));
		VTI_INFO("remote is %s\n", buf);
	}

	return 0;
}

struct ifnet *
vti_tunnel_create(int ifindex, const char *ifname,
		  const struct rte_ether_addr *addr, const unsigned int mtu,
		  struct nlattr *data)
{
	struct ifnet *ifp;
	struct vti_tunnel_ctxt *ctxt;
	/* Assume default transport VRF for now */
	vrfid_t t_vrfid = VRF_DEFAULT_ID;
	struct vrf *vrf;

	VTI_DEBUG("CREATE index %d name %s mtu %d\n", ifindex, ifname, mtu);

	ctxt = zmalloc_aligned(sizeof(*ctxt));
	if (!ctxt) {
		VTI_ERR("%s: can't allocate tunnel context\n", ifname);
		return NULL;
	}
	ctxt->t_vrfid = t_vrfid;

	if (vti_tunnel_key_from_nlattr(&ctxt->key, data)) {
		VTI_ERR("%s: can't parse netlink attributes\n",	ifname);
		goto free_ctxt;
	}

	/*
	 * set MTU to max since we don't yet track the effective mtu
	 * according to the crypto algo overhead. vti_tunnel_out will
	 * take care of doing fragmentation.
	 */
	ifp = if_alloc(ifname, IFT_TUNNEL_VTI, UINT16_MAX, addr,
		       SOCKET_ID_ANY);
	if (!ifp) {
		VTI_ERR("%s: can't allocate ifnet\n", ifname);
		goto free_ctxt;
	}

	if_set_ifindex(ifp, ifindex);

	/*
	 * Take a lock on the vrf to track the
	 * existence of the context.
	 */
	vrf = vrf_find_or_create(t_vrfid);
	if (!vrf) {
		DP_DEBUG_W_VRF(VTI, ERR, VTI, t_vrfid,
			       "Unable to setup VTI tunnel\n");
		goto free_ifp;
	}

	if (!vrf->v_vti_contexts) {
		VTI_ERR("Unable to setup VTI tunnel, missing context table\n");
		goto release_vrf;
	}

	if (vti_ctxt_insert(vrf->v_vti_contexts, ctxt)) {
		char addr1[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN];

		inet_ntop(ctxt->key.family, &ctxt->key.src,
			addr1, sizeof(addr1));
		inet_ntop(ctxt->key.family, &ctxt->key.dst,
			addr2, sizeof(addr2));
		VTI_ERR("%s: tunnel context insertion failed (%s -> %s)\n",
			ifname, addr1, addr2);
		goto release_vrf;
	}

	/*
	 * If the policy for this tunnel is already in the  policy database,
	 * set the reqid, otherwise wait for the policy DB to tell us.
	 */
	if (crypto_policy_get_vti_reqid(t_vrfid,
					&ctxt->key.dst, ctxt->key.family,
					ctxt->key.mark, &ctxt->reqid) < 0) {
		VTI_DEBUG("Policy reqid unavailable on create for %s\n",
			  ifname);
		ctxt->overhead_subscribed = false;
		ctxt->reqid_valid = false;
	} else {
		VTI_DEBUG("Policy reqid set to %x on create for %s\n",
			  ctxt->reqid, ifname);
		crypto_sadb_peer_overhead_subscribe(&ctxt->key.dst,
						    ctxt->key.family,
						    ctxt->reqid,
						    &ctxt->ipsec_overhead,
						    t_vrfid);
		ctxt->overhead_subscribed = true;
		ctxt->reqid_valid = true;
	}

	/* no need for rcu_assign_pointer in this case */
	ctxt->ifp  = ifp;
	ctxt->mtu = mtu;
	ifp->if_softc = ctxt;
	return ifp;

release_vrf:
	vrf_delete(t_vrfid);
free_ifp:
	if_free(ifp);
free_ctxt:
	free(ctxt);
	return NULL;
}

void vti_tunnel_modify(__unused struct ifnet *ifp,
		       __unused struct nlattr *data)
{
	/* TODO: support changes of tunnel configuration */
}

static int vti_tunnel_set_mtu(struct ifnet *ifp, uint32_t mtu)
{
	struct vti_tunnel_ctxt *ctxt = ifp->if_softc;

	VTI_INFO("Changing MTU on %s from %d to %d\n",
		 ifp->if_name, ctxt->mtu, mtu);

	ctxt->mtu = mtu;
	/* Note: don't update ifp->if_mtu as this is always set to max */

	return 0;
}

static void vti_tunnel_delete(struct ifnet *ifp)
{
	struct vti_tunnel_ctxt *ctxt = ifp->if_softc;
	vrfid_t t_vrfid = ctxt->t_vrfid;
	struct vrf *vrf = vrf_get_rcu(t_vrfid);

	VTI_INFO("DELETE %s(%d)\n", ifp->if_name, ifp->if_index);

	if (!vrf) {
		DP_DEBUG_W_VRF(VTI, ERR, VTI, t_vrfid,
			       "Unable to delete tunnel %s\n", ifp->if_name);
		return;
	}

	if (!vrf->v_vti_contexts) {
		VTI_ERR("Unable to delete tunnel %s, missing context table\n",
			ifp->if_name);
		return;
	}

	ifp->if_softc = NULL;
	ctxt->ifp = NULL;
	if (ctxt->overhead_subscribed) {
		crypto_sadb_peer_overhead_unsubscribe(&ctxt->key.dst,
						      ctxt->key.family,
						      &ctxt->ipsec_overhead,
						      t_vrfid);
		ctxt->overhead_subscribed = false;
	}

	vti_ctxt_remove(vrf->v_vti_contexts, ctxt);
	/* Release the lock on the transport VRF */
	vrf_delete(t_vrfid);
}

void vti_reqid_set(const xfrm_address_t *dst, uint8_t family,
		   uint32_t mark, uint32_t reqid)
{
	/* Assume default transport VRF for now */
	vrfid_t t_vrfid = VRF_DEFAULT_ID;
	struct vrf *vrf = vrf_get_rcu(t_vrfid);
	struct vti_tunnel_ctxt *ctxt;
	struct vti_tunnel_key key = {.family = family,
				     .mark = mark};

	if (!vrf) {
		DP_DEBUG_W_VRF(VTI, ERR, VTI, t_vrfid,
			       "Unable to set tunnel reqid\n");
		return;
	}

	if (!vrf->v_vti_contexts) {
		VTI_ERR("Unable to set tunnel reqid: missing context table\n");
		return;
	}

	memcpy(&key.dst, dst,
	       (family == AF_INET) ? sizeof(dst->a4) : sizeof(dst->a6));
	ctxt = vti_ctxt_lookup(vrf->v_vti_contexts, &key);
	if (!ctxt)
		return;

	if (ctxt->reqid_valid) {
		if (ctxt->reqid != reqid) {
			VTI_ERR("Cannot change valid reqid, %s disabled",
				ctxt->ifp->if_name);
			ctxt->reqid_valid = false;
		}
		return;
	}

	/*
	 * If we've not previously subscribed to IPsec encryption
	 * overhead information from the peer, do so now. Otherwise,
	 * we need to tell the SADB that we're now interested in a
	 * (possibly) different reqid.
	 */
	if (!ctxt->overhead_subscribed) {
		crypto_sadb_peer_overhead_subscribe(&ctxt->key.dst,
						    ctxt->key.family, reqid,
						    &ctxt->ipsec_overhead,
						    t_vrfid);
		ctxt->overhead_subscribed = true;
	} else {
		crypto_sadb_peer_overhead_change_reqid(&ctxt->key.dst,
						       ctxt->key.family, reqid,
						       &ctxt->ipsec_overhead,
						       t_vrfid);
	}

	ctxt->reqid = reqid;
	rte_wmb();
	ctxt->reqid_valid = true;
}

void vti_reqid_clear(const xfrm_address_t *dst, uint8_t family, uint32_t mark)
{
	/* Assume default transport VRF for now */
	vrfid_t t_vrfid = VRF_DEFAULT_ID;
	struct vrf *vrf = vrf_get_rcu(t_vrfid);
	struct vti_tunnel_ctxt *ctxt = NULL;
	struct vti_tunnel_key key = {.family = family,
				     .mark = mark};

	if (!vrf) {
		DP_DEBUG_W_VRF(VTI, ERR, VTI, t_vrfid,
			       "Unable to clear tunnel reqid\n");
		return;
	}

	if (!vrf->v_vti_contexts) {
		VTI_ERR("Unable to set tunnel reqid: missing context table\n");
		return;
	}

	memcpy(&key.dst, dst,
	       (family == AF_INET) ? sizeof(dst->a4) : sizeof(dst->a6));
	ctxt = vti_ctxt_lookup(vrf->v_vti_contexts, &key);
	if (ctxt) {
		ctxt->reqid_valid = false;
	}
}

void vti_tunnel_out(struct ifnet *in_ifp, struct ifnet *nxt_ifp,
		    struct rte_mbuf *m, uint16_t proto)
{
	struct vti_tunnel_ctxt *ctxt = rcu_dereference(nxt_ifp->if_softc);
	unsigned int effective_mtu;
	uint16_t inner_len;
	struct iphdr *ip = iphdr(m);
	struct ip6_hdr *ip6 = ip6hdr(m);
	bool dont_frag = false;

	/*
	 * need a valid input interface pointer and the tunnel is the
	 * best we've got
	 */
	if (!in_ifp)
		in_ifp = nxt_ifp;

	/* check if tunnel is on its way out */
	if (!ctxt) {
		VTI_DEBUG_PKT("Not soft context - send failed\n");
		if_incr_oerror(nxt_ifp);
		IPSEC_CNT_INC(DROPPED_NO_CTX);
		icmp_error(in_ifp, m, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
		goto drop;
	}

	if (!ctxt->reqid_valid) {
		VTI_DEBUG_PKT("IPsec reqid unavailable - send failed\n");
		if_incr_oerror(nxt_ifp);
		icmp_error(in_ifp, m, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
		IPSEC_CNT_INC(DROPPED_INVALID_REQID);
		goto drop;
	}

	/*
	 * VTI tunnels are created with the MTU that already takes in to
	 * account the encap length added by the VTI tunnels
	 */
	effective_mtu = ctxt->mtu;

	if (likely(proto == ETH_P_IP)) {
		inner_len = esp_payload_padded_len(&ctxt->ipsec_overhead,
						   ntohs(ip->tot_len));
		dont_frag = ip->frag_off & htons(IP_DF);
	} else if (likely(proto == ETH_P_IPV6)) {
		inner_len = esp_payload_padded_len(&ctxt->ipsec_overhead,
						   ntohs(ip6->ip6_plen) +
						   sizeof(*ip6));
		/*
		 * Only frag originated ipv6 packets
		 */
		if (in_ifp != get_lo_ifp(CONT_SRC_MAIN))
			dont_frag = true;
	} else {
		IPSEC_CNT_INC(DROPPED_INVALID_VERSION);
		goto drop;
	}

	if (inner_len > effective_mtu) {
		struct crypto_fragment_ctx frag_ctx;

		/*
		 * Lower the effective MTU to be a multiple of block_size - 2.
		 */
		effective_mtu =
			RTE_ALIGN_FLOOR(effective_mtu + 2,
					ctxt->ipsec_overhead.block_size) - 2;

		if (dont_frag) {
			IPSTAT_INC_MBUF(m, IPSTATS_MIB_FRAGFAILS);
			IPSEC_CNT_INC(DROPPED_DF);
			if (ip->version == 4) {
				icmp_error_out(in_ifp, m, ICMP_DEST_UNREACH,
					       ICMP_FRAG_NEEDED,
					       htons(effective_mtu), nxt_ifp);
				goto drop;
			} else {
				icmp6_error(in_ifp, m, ICMP6_PACKET_TOO_BIG,
					    0, htonl(effective_mtu));
				/* faulting packet freed by icmp6 */
				return;
			}
		}

		frag_ctx.family = ctxt->key.family;
		frag_ctx.orig_family = ctxt->key.family;
		frag_ctx.dst = &ctxt->key.dst;
		frag_ctx.in_ifp = in_ifp;
		frag_ctx.reqid = ctxt->reqid;
		frag_ctx.pmd_dev_id = ctxt->ipsec_overhead.pmd_dev_id;
		frag_ctx.spi = ctxt->ipsec_overhead.spi;
		if (ip->version == 4)
			ip_fragment_mtu(nxt_ifp, effective_mtu, m,
					&frag_ctx, crypto_enqueue_fragment);
		else
			ip6_fragment_mtu(nxt_ifp, effective_mtu, m,
					 &frag_ctx, crypto_enqueue_fragment);
	} else {
		crypto_enqueue_outbound(m, ctxt->key.family, ctxt->key.family,
					&ctxt->key.dst,
					in_ifp, nxt_ifp, ctxt->reqid,
					ctxt->ipsec_overhead.pmd_dev_id,
					ctxt->ipsec_overhead.spi);
	}

	return;

drop:
	rte_pktmbuf_free(m);
}

int vti_handle_inbound(const xfrm_address_t *dst, const uint8_t family,
		       const uint32_t mark, struct rte_mbuf *m,
		       struct ifnet **vti_ifp)
{
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	const struct vti_tunnel_ctxt *ctxt;
	struct vti_tunnel_key key;
	struct vrf *vrf;

	vrf = vrf_get_rcu(vrfid);
	if (!vrf || !vrf->v_vti_contexts)
		return -1;

	key.family = family;
	key.mark   = mark;
	memcpy(&key.dst, dst,
	       (family == AF_INET) ? sizeof(dst->a4) : sizeof(dst->a6));

	ctxt = vti_ctxt_lookup(vrf->v_vti_contexts, &key);
	if (!ctxt) {
		VTI_DEBUG_PKT("LOOKUP softc: Found nothing!\n");
		return -1;
	}

	VTI_DEBUG_PKT("IN: from interface %s(%d) %d\n", ctxt->ifp->if_name,
		      ctxt->ifp->if_index, rte_pktmbuf_pkt_len(m));
	if (vti_ifp)
		*vti_ifp = ctxt->ifp;
	return 0;
}

/* Size of the softc table. Must be a power of two. */
#define VTI_RTHASH_MIN  32
#define VTI_RTHASH_MAX  0 /* unlimited */

int vti_table_init(struct vrf *vrf)
{
	struct vti_ctxt_table *vct;

	vct = malloc(sizeof(*vct));
	if (!vct) {
		DP_DEBUG_W_VRF(VTI, ERR, VTI, vrf->v_id,
			       "Failed to allocate vti table\n");
		return -1;
	}

	vct->vti_ctxt_ht = cds_lfht_new(VTI_RTHASH_MIN,
					VTI_RTHASH_MIN,
					VTI_RTHASH_MAX,
					CDS_LFHT_AUTO_RESIZE,
					NULL);
	vct->vti_ctxt_seed = random();

	if (!vct->vti_ctxt_ht) {
		DP_DEBUG_W_VRF(VTI, ERR, VTI, vrf->v_id,
			       "Failed to initialise vti table\n");
		free(vct);
		return -1;
	}

	DP_DEBUG_W_VRF(VTI, DEBUG, VTI, vrf->v_id,
		       "Added VTI context table\n");

	vrf->v_vti_contexts = vct;

	return 0;
}

void vti_table_uninit(struct vrf *vrf)
{
	struct vti_ctxt_table *vct;

	if (!vrf  || !vrf->v_vti_contexts)
		return;

	vct = vrf->v_vti_contexts;
	vrf->v_vti_contexts = NULL;
	dp_ht_destroy_deferred(vct->vti_ctxt_ht);
	free(vct);

	DP_DEBUG_W_VRF(VTI, DEBUG, VTI, vrf->v_id,
		       "Delete VTI context table\n");
}

int vti_set_output_vrf(const struct ifnet *ifp, struct rte_mbuf *m)
{
	struct vti_tunnel_ctxt *ctxt = rcu_dereference(ifp->if_softc);

	if (ctxt) {
		pktmbuf_set_vrf(m, ctxt->t_vrfid);
		return 0;
	}

	return -1;
}

int vti_get_peer_addr(const struct ifnet *ifp, uint32_t *af, void **addr)
{
	struct vti_tunnel_ctxt *ctxt = rcu_dereference(ifp->if_softc);

	if (ctxt) {
		*af = ctxt->key.family;
		*addr = &ctxt->key.dst;
		return 0;
	}
	return -1;
}

static enum dp_ifnet_iana_type
vti_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_TUNNEL;
}

static const struct ift_ops vti_if_ops = {
	.ifop_set_mtu = vti_tunnel_set_mtu,
	.ifop_uninit = vti_tunnel_delete,
	.ifop_iana_type = vti_iana_type,
};

static void vti_type_init(void)
{
	int ret = if_register_type(IFT_TUNNEL_VTI, &vti_if_ops);
	if (ret < 0)
		rte_panic("Failed to register VTI type: %s", strerror(-ret));
}

static const struct dp_event_ops vti_events = {
	.init = vti_type_init,
};

DP_STARTUP_EVENT_REGISTER(vti_events);
