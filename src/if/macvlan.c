/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Macvlan pseudo-ethernet module
 */

#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "dp_event.h"
#include "ether.h"
#include "if_var.h"
#include "macvlan.h"
#include "pktmbuf_internal.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

#define MACVLAN_MODE_PRIVATE 1	/* don't talk to other macvlans */
#define MACVLAN_MODE_VEPA 2	/* talk to other ports through ext bridge */
#define MACVLAN_MODE_BRIDGE 4	/* talk to bridge ports directly */
#define MACVLAN_MODE_PASSTHRU 8 /* take over the underlying device */

#define MACVLAN_MAX_NODES 65535 /*  macvlans per interface */

struct mvl_entry {
	struct cds_lfht_node	mvl_node;   /* hash table node	*/
	struct rcu_head		mvl_rcu;    /* for deletion via rcu */
	struct ifnet		*ifp;
	int			mode;
};

struct mvl_tbl {
	struct cds_lfht	    *mvlt_hash;	    /* hash table linkage */
	struct ifnet	    *parent_ifp;
	struct rcu_head	    rcu;
};

#define MACVLAN_HASHTBL_BITS  14
#define MACVLAN_HASHTBL_MIN   16
#define MACVLAN_HASHTBL_MAX   1024

#define MVL_DEBUG(format, args...)	\
	DP_DEBUG(MACVLAN, DEBUG, MACVLAN, format, ##args)

static struct mvl_tbl *macvlan_table_init(struct ifnet *ifp);
static void macvlan_table_free(struct ifnet *ifp, int flush);
static bool is_vrrp_mac_addr(struct ether_addr *ll_addr);

/* Given key (ether address) generate a hash using jhash */
static inline unsigned long
macvlan_hash(const struct ether_addr *key)
{
	return eth_addr_hash(key, MACVLAN_HASHTBL_BITS);
}

/* Test if ether address matches value for this entry */
static inline int
macvlan_match(struct cds_lfht_node *node, const void *key)
{
	const struct mvl_entry *mvle
		= caa_container_of(node, const struct mvl_entry, mvl_node);

	return ether_addr_equal(&mvle->ifp->eth_addr, key);
}

static struct ifnet *
macvlan_lookup(struct mvl_tbl *mvlt, const struct ether_addr *addr,
	       bool return_parent_if)
{
	/* lookup macvlan in hash by dest macaddr */
	struct cds_lfht_iter iter;

	cds_lfht_lookup(mvlt->mvlt_hash,
			macvlan_hash(addr),
			macvlan_match, addr, &iter);

	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);
	if (node) {
		struct mvl_entry *mvle
			= caa_container_of(node, struct mvl_entry, mvl_node);

		if (is_vrrp_mac_addr(&mvle->ifp->eth_addr) && return_parent_if)
			return mvle->ifp->if_parent;

		return mvle->ifp;
	}

	return NULL;
}

static void
macvlan_add_mac(struct ifnet *ifp, struct ether_addr *eth_addr)
{
	MVL_DEBUG("%s adding %s to parent %s\n", ifp->if_name,
		ether_ntoa(eth_addr), ifp->if_parent->if_name);
	if_add_l2_addr(ifp->if_parent, eth_addr);
}

static void
macvlan_del_mac(struct ifnet *ifp, struct ether_addr *eth_addr)
{
	MVL_DEBUG("%s deleting %s from parent %s\n", ifp->if_name,
		ether_ntoa(eth_addr), ifp->if_parent->if_name);
	if_del_l2_addr(ifp->if_parent, eth_addr);
}

static int
macvlan_entry_insert(struct mvl_tbl *mvlt, struct mvl_entry *mvle)
{
	struct cds_lfht_node *ret_node;
	cds_lfht_node_init(&mvle->mvl_node);
	MVL_DEBUG("adding macvlan: %s to %s\n", mvle->ifp->if_name,
		mvle->ifp->if_parent->if_name);
	unsigned long hash =
	      macvlan_hash(&mvle->ifp->eth_addr);
	ret_node = cds_lfht_add_unique(mvlt->mvlt_hash, hash,
			macvlan_match, &mvle->ifp->eth_addr, &mvle->mvl_node);
	return (ret_node != &mvle->mvl_node) ? EEXIST : 0;
}

static void
macvlan_entry_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct mvl_entry, mvl_rcu));
}

static void
macvlan_entry_destroy(struct mvl_tbl *mvlt, struct mvl_entry *mvle)
{
	cds_lfht_del(mvlt->mvlt_hash, &mvle->mvl_node);
	call_rcu(&mvle->mvl_rcu, macvlan_entry_free);
}

struct ifnet *
macvlan_create(struct ifnet *ifp, const char *mvl_name,
	       const struct ether_addr *eth_addr, int ifindex)
{
	struct ifnet *vifp;
	int err;

	if (!eth_addr) {
		RTE_LOG(NOTICE, MACVLAN,
			"missing lladdress for macvlan\n");
		return NULL;
	}

	MVL_DEBUG("macvlan_create(%s,%s,%s,%d)\n", ifp->if_name, mvl_name,
		ether_ntoa(eth_addr), ifindex);

	if (ifp->if_macvlantbl) {
		vifp = macvlan_lookup(ifp->if_macvlantbl, eth_addr, true);
		if (vifp)
			return vifp;
	} else {
		struct mvl_tbl *mvlt;

		MVL_DEBUG("macvlan_create creating a new macvlan_table\n");
		mvlt = macvlan_table_init(ifp);
		if (!mvlt)
			return NULL;
		rcu_assign_pointer(ifp->if_macvlantbl, mvlt);
	}

	vifp = if_alloc(mvl_name, IFT_MACVLAN, ifp->if_mtu, eth_addr,
			ifp->if_socket);
	if (vifp) {
		vifp->if_parent = ifp;
		if_port_inherit(ifp, vifp);
		if_set_ifindex(vifp, ifindex);

		struct mvl_entry *mvle;
		mvle = malloc_aligned(sizeof(struct mvl_entry));
		if (!mvle) {
			if_free(vifp);
			RTE_LOG(ERR, DATAPLANE,
				"cannot allocate space for macvlan\n");
			return NULL;
		}
		mvle->ifp = vifp;
		vifp->if_softc = mvle;

		/* For now default to private */
		mvle->mode = MACVLAN_MODE_PRIVATE;
		err = macvlan_entry_insert(ifp->if_macvlantbl, mvle);
		if (err) {
			free(mvle);
			if_free(vifp);
			return NULL;
		}
	}
	return vifp;
}

static void
macvlan_change_addr(struct ifnet *ifp, struct ether_addr *eth_addr)
{
	struct ifnet *pifp = ifp->if_parent;
	struct mvl_entry *mvle, *omvle = ifp->if_softc;
	int err;

	MVL_DEBUG("changing macvlan address to %s\n", ether_ntoa(eth_addr));
	mvle = malloc_aligned(sizeof(struct mvl_entry));
	if (!mvle) {
		RTE_LOG(ERR, MACVLAN, "cannot allocate space for macvlan\n");
		return;
	}
	macvlan_del_mac(ifp, &ifp->eth_addr);
	memcpy(&ifp->eth_addr, eth_addr, sizeof(struct ether_addr));
	mvle->ifp = ifp;
	mvle->mode = omvle->mode;

	err = macvlan_entry_insert(pifp->if_macvlantbl, mvle);
	if (err) {
		RTE_LOG(ERR, MACVLAN, "error inserting entry\n");
		free(mvle);
		return;
	}
	macvlan_add_mac(ifp, eth_addr);
	rcu_assign_pointer(ifp->if_softc, mvle);

	/* destroy the old entry */
	macvlan_entry_destroy(pifp->if_macvlantbl, omvle);
}

static void
macvlan_table_free_ifempty(struct ifnet *ifp)
{
	struct mvl_tbl *mvlt = ifp->if_macvlantbl;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_first(mvlt->mvlt_hash, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node == NULL)
		macvlan_table_free(ifp, 0);
}

static void
macvlan_delete(struct ifnet *ifp)
{
	struct ifnet *pifp = ifp->if_parent;
	struct mvl_entry *mvl = ifp->if_softc;

	if (pifp->if_macvlantbl == NULL)
		rte_panic("if_macvlan_delete: missing macvlan table?\n");

	macvlan_entry_destroy(pifp->if_macvlantbl, mvl);
	macvlan_table_free_ifempty(pifp);
}

static struct mvl_tbl *
macvlan_table_init(struct ifnet *ifp)
{
	struct mvl_tbl *mvlt;

	mvlt = malloc_aligned(sizeof(struct mvl_tbl));
	if (!mvlt)
		rte_panic("Can't allocate mvl_tbl\n");

	mvlt->parent_ifp = ifp;
	mvlt->mvlt_hash = cds_lfht_new(MACVLAN_HASHTBL_MIN,
				       MACVLAN_HASHTBL_MIN,
				       MACVLAN_HASHTBL_MAX,
				       CDS_LFHT_AUTO_RESIZE,
				       NULL);
	if (!mvlt->mvlt_hash)
		rte_panic("Can't allocate mvl_tbl hash\n");

	return mvlt;
}

void
macvlan_table_flush(struct mvl_tbl *mvlt)
{
	struct mvl_entry *mvle;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(mvlt->mvlt_hash, &iter, mvle, mvl_node) {
		MVL_DEBUG("deleting macvlan: %s from %s\n", mvle->ifp->if_name,
			mvle->ifp->if_parent->if_name);
		macvlan_entry_destroy(mvlt, mvle);
	}
}

static void
macvlan_rcu_table_free(struct rcu_head *head)
{
	struct mvl_tbl *mvl = caa_container_of(head, struct mvl_tbl, rcu);

	dp_ht_destroy_deferred(mvl->mvlt_hash);
	free(mvl);
}

static void
macvlan_table_free(struct ifnet *ifp, int flush)
{
	struct mvl_tbl *mvlt = ifp->if_macvlantbl;

	if (flush)
		macvlan_table_flush(mvlt);

	ifp->if_macvlantbl = NULL;
	call_rcu(&mvlt->rcu, macvlan_rcu_table_free);
}

/* For multicast, clone packet to all non-VRRP macvlan devices
 * original copy received on the parent interface.
 */
void macvlan_flood(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct mvl_tbl *mvlt = rcu_dereference(ifp->if_macvlantbl);
	struct mvl_entry *mvle;
	struct cds_lfht_iter iter;

	if (!mvlt)
		return;

	cds_lfht_for_each_entry(mvlt->mvlt_hash, &iter, mvle, mvl_node) {
		if (!is_vrrp_mac_addr(&mvle->ifp->eth_addr)) {
			struct rte_mbuf *clone = pktmbuf_clone(m, m->pool);
			if (clone)
				ether_input(mvle->ifp, clone);
		}
	}
}

struct ifnet *macvlan_get_vrrp_ip_if(struct ifnet *ifp, struct sockaddr *target)
{
	struct mvl_tbl *mvlt = rcu_dereference(ifp->if_macvlantbl);
	struct mvl_entry *mvle;
	struct cds_lfht_iter iter;
	struct if_addr *ifa;

	if (!mvlt)
		return NULL;

	cds_lfht_for_each_entry(mvlt->mvlt_hash, &iter, mvle, mvl_node) {
		if (!is_vrrp_mac_addr(&mvle->ifp->eth_addr))
			continue;

		cds_list_for_each_entry_rcu(ifa, &mvle->ifp->if_addrhead,
					    ifa_link) {
			struct sockaddr *sa
				= (struct sockaddr *) &ifa->ifa_addr;

			if (sa->sa_family != target->sa_family)
				continue;
			if (target->sa_family == AF_INET &&
				satosin(target)->sin_addr.s_addr !=
				satosin(sa)->sin_addr.s_addr)
				continue;
			if (target->sa_family == AF_INET6 &&
				!IN6_ARE_ADDR_EQUAL(
					satosin6(target)->sin6_addr.s6_addr,
					satosin6(sa)->sin6_addr.s6_addr))
				continue;

			return mvle->ifp;
		}
	}

	return NULL;
}

/* Find macvlan (child device) for incoming packet,
 * or returns NULL and consumes packet
 */
struct ifnet *
macvlan_input(struct ifnet *ifp, struct rte_mbuf *m)
{
	const struct ether_hdr *eth
		= rte_pktmbuf_mtod(m, struct ether_hdr *);
	struct mvl_tbl *mvlt
		= rcu_dereference(ifp->if_macvlantbl);

	ifp = mvlt ? macvlan_lookup(mvlt, &eth->d_addr, true) : NULL;

	if (!ifp)
		rte_pktmbuf_free(m);

	return ifp;
}

static bool
is_vrrp_mac_addr(struct ether_addr *ll_addr)
{
	if (ll_addr->addr_bytes[0] == 0x00 &&
		ll_addr->addr_bytes[1] == 0x00 &&
		ll_addr->addr_bytes[2] == 0x5e &&
		ll_addr->addr_bytes[3] == 0x00 &&
		(
			ll_addr->addr_bytes[4] == 0x01 ||
			ll_addr->addr_bytes[4] == 0x02
		))
		return true;
	return false;
}

ALWAYS_INLINE
struct ifnet *macvlan_check_vrrp_if(struct ifnet *ifp)
{
	struct mvl_entry *mvle;

	if (unlikely(ifp->if_type == IFT_MACVLAN)) {
		mvle = rcu_dereference(ifp->if_softc);
		if (likely(mvle != NULL) &&
		    is_vrrp_mac_addr(&mvle->ifp->eth_addr))
			return ifp->if_parent;
	}

	return ifp;
}

struct ifnet *macvlan_get_vrrp_if(const struct ifnet *ifp,
				  const struct ether_addr *dst_mac)
{
	struct mvl_tbl *mvlt
		= rcu_dereference(ifp->if_macvlantbl);

	return mvlt ? macvlan_lookup(mvlt, dst_mac, false) : NULL;
}

void macvlan_output(struct ifnet *ifp, struct rte_mbuf *mbuf,
		    struct ifnet *input_ifp, uint16_t proto)
{
	if_output(ifp->if_parent, mbuf, input_ifp, proto);
}

static int macvlan_if_set_l2_address(struct ifnet *ifp, uint32_t l2_addr_len,
				     void *l2_addr)
{
	struct ether_addr *macaddr = l2_addr;
	char b1[32], b2[32];

	if (l2_addr_len != ETHER_ADDR_LEN) {
		RTE_LOG(NOTICE, DATAPLANE,
			"link address is not ethernet (len=%u)!\n",
			l2_addr_len);
		return -EINVAL;
	}

	if (ether_addr_equal(&ifp->eth_addr, macaddr))
		return 1;

	RTE_LOG(INFO, DATAPLANE, "%s change MAC from %s to %s\n",
		ifp->if_name,
		ether_ntoa_r(&ifp->eth_addr, b1),
		ether_ntoa_r(macaddr, b2));

	macvlan_change_addr(ifp, macaddr);

	return 0;
}

static int macvlan_if_start(struct ifnet *ifp)
{
	macvlan_add_mac(ifp, &ifp->eth_addr);

	return 0;
}

static int macvlan_if_stop(struct ifnet *ifp)
{
	macvlan_del_mac(ifp, &ifp->eth_addr);

	return 0;
}

static int
macvlan_if_dump(struct ifnet *ifp, json_writer_t *wr,
		enum if_dump_state_type type)
{
	struct ifnet *ifp_root;

	switch (type) {
	case IF_DS_STATE:
		/*
		 * For backwards compatibility with commands that rely
		 * on this.
		 */
		for (ifp_root = ifp; ifp_root->if_parent;
		     ifp_root = ifp_root->if_parent)
			;
		if (ifp_root->if_type == IFT_ETHER)
			if_dump_state(ifp_root, wr, IF_DS_STATE);
		break;
	default:
		break;
	}

	return 0;
}

static enum dp_ifnet_iana_type
macvlan_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_OTHER;
}

static const struct ift_ops macvlan_if_ops = {
	.ifop_set_l2_address = macvlan_if_set_l2_address,
	.ifop_start = macvlan_if_start,
	.ifop_stop = macvlan_if_stop,
	.ifop_uninit = macvlan_delete,
	.ifop_dump = macvlan_if_dump,
	.ifop_iana_type = macvlan_iana_type,
};

static void macvlan_init(void)
{
	int ret = if_register_type(IFT_MACVLAN, &macvlan_if_ops);
	if (ret < 0)
		rte_panic("Failed to register VLAN type: %s", strerror(-ret));
}

static const struct dp_event_ops macvlan_events = {
	.init = macvlan_init,
};

DP_STARTUP_EVENT_REGISTER(macvlan_events);
