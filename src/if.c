/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 1980, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if.c	8.5 (Berkeley) 1/9/95
 * $FreeBSD$
 */

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>
#include <linux/if_ether.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_pci.h>
#include <rte_sched.h>
#include <rte_timer.h>
#ifdef HAVE_RTE_BUS_PCI_H
#include <rte_bus_pci.h>
#endif

#include "bridge.h"
#include "capture.h"
#include "commands.h"
#include "compiler.h"
#include "config.h"
#include "control.h"
#include "pipeline/nodes/cross_connect/cross_connect.h"
#include "crypto/crypto_policy.h"
#include "crypto/vti.h"
#include "dp_event.h"
#include "dpdk_eth_if.h"
#include "ether.h"
#include "fal.h"
#include "gre.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "ip_addr.h"
#include "json_writer.h"
#include "l2_rx_fltr.h"
#include "l2tp/l2tpeth.h"
#include "lag.h"
#include "macvlan.h"
#include "main.h"
#include "master.h"
#include "netinet6/in6.h"
#include "netlink.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pktmbuf.h"
#include "pl_node.h"
#include "portmonitor/portmonitor.h"
#include "pipeline/nodes/pppoe/pppoe.h"
#include "qos.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf.h"
#include "vrf_if.h"
#include "vxlan.h"
#include "backplane.h"

#include "protobuf.h"
#include "protobuf/VFPSetConfig.pb-c.h"

struct pl_feature_registration;

/* A child interface should only inherit the parents if_port value if it is
 * valid.
 */
void
if_port_inherit(struct ifnet *parent, struct ifnet *child)
{
	if (parent->if_local_port) {
		child->if_port = parent->if_port;
		child->if_local_port = 1;
	} else {
		child->if_port = IF_PORT_ID_INVALID;
		child->if_local_port = 0;
	}
}

/* Hash of interface type to type registrations */
static struct cds_lfht *ift_reg_hash;

/* List to iterate over all interfaces. Stores them in newest first order. */
static CDS_LIST_HEAD(ifnet_list);

/* Hash to find interface based on ifindex.
 *  New interfaces without ifindex will not be in this hash.
 */
static struct cds_lfht *ifnet_hash;

/* Hash to find interface based on ifname. */
static struct cds_lfht *ifname_hash;

/* Key used to find entries in name hash. */
struct ifname_key {
	const char *ifname;
	enum cont_src_en cont_src;
};

struct if_type_reg {
	enum if_type ift_type;
	const struct ift_ops *ift_fns;
	struct cds_lfht_node ift_hash;
};

static inline int iftype_match_fn(struct cds_lfht_node *node,
				  const void *key)
{
	const enum if_type *type = key;
	const struct if_type_reg *ift;

	ift = caa_container_of(node, const struct if_type_reg, ift_hash);
	if (ift->ift_type != *type)
		return 0;

	return 1;
}

int if_register_type(enum if_type type, const struct ift_ops *fns)
{
	struct cds_lfht_node *ret_node;
	struct if_type_reg *ift;

	if (!ift_reg_hash) {
		ift_reg_hash = cds_lfht_new(4, 4, 0, 0, NULL);
		if (!ift_reg_hash)
			return -ENOMEM;
	}

	ift = malloc(sizeof(*ift));
	if (!ift)
		return -ENOMEM;
	ift->ift_type = type;
	ift->ift_fns = fns;

	ret_node = cds_lfht_add_unique(ift_reg_hash, type,
				       iftype_match_fn,
				       &type,
				       &ift->ift_hash);

	if (ret_node != &ift->ift_hash) {
		free(ift);
		return -EEXIST;
	}

	return 0;
}

static const struct ift_ops *if_lookup_type(enum if_type type)
{
	struct if_type_reg *ift = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(ift_reg_hash,
			type,
			iftype_match_fn,
			&type, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node)
		return NULL;

	ift = caa_container_of(node, struct if_type_reg, ift_hash);
	return ift->ift_fns;
}

static const struct ift_ops *if_get_ops(struct ifnet *ifp)
{
	return if_lookup_type(ifp->if_type);
}

/* Hash for ifname_hash.  Don't use cont_src, so that interfaces
 * with the same names stay on the same chain.
 */
static inline uint32_t interface_ifname_hash(const char *ifname)
{
	char __ifname[IFNAMSIZ] __rte_aligned(sizeof(uint32_t));
	int len = MIN(strlen(ifname), sizeof(__ifname));

	memcpy(__ifname, ifname, len);
	return rte_jhash(__ifname, len, 0);
}

#define IFNET_HASH_MIN 4
#define IFNET_HASH_MAX 0 /* unlimited */

void interface_init(void)
{
	ifnet_hash = cds_lfht_new(IFNET_HASH_MIN,
				  IFNET_HASH_MIN,
				  IFNET_HASH_MAX,
				  CDS_LFHT_AUTO_RESIZE |
				  CDS_LFHT_ACCOUNTING,
				  NULL);
	if (!ifnet_hash)
		rte_panic("Can't allocate if_index hash for interfaces\n");

	ifname_hash = cds_lfht_new(IFNET_HASH_MIN,
				   IFNET_HASH_MIN,
				   IFNET_HASH_MAX,
				   CDS_LFHT_AUTO_RESIZE |
				   CDS_LFHT_ACCOUNTING,
				   NULL);
	if (!ifname_hash)
		rte_panic("Can't allocate if_name hash for interfaces\n");
}

void interface_cleanup(void)
{
	struct cds_lfht_iter iter;
	struct ifnet *ifp;
	struct if_type_reg *if_reg;

	cds_lfht_for_each_entry(ifnet_hash, &iter,
				ifp, ifindex_hash) {
		if_free(ifp);
	}
	cds_lfht_destroy(ifnet_hash, NULL);
	cds_lfht_destroy(ifname_hash, NULL);

	cds_lfht_for_each_entry(ift_reg_hash, &iter,
				if_reg, ift_hash) {
		cds_lfht_del(ift_reg_hash, &if_reg->ift_hash);
		free(if_reg);
	}
	cds_lfht_destroy(ift_reg_hash, NULL);
}

static inline int interface_ifindex_match_fn(struct cds_lfht_node *node,
					     const void *key)
{
	const uint32_t *ifindex = key;
	const struct ifnet *ifp;

	ifp = caa_container_of(node, const struct ifnet, ifindex_hash);
	if (ifp->if_index != *ifindex)
		return 0;

	return 1;
}

static inline int interface_ifname_match_fn(struct cds_lfht_node *node,
					    const void *arg)
{
	const struct ifname_key *key = arg;
	const struct ifnet *ifp;

	ifp = caa_container_of(node, const struct ifnet, ifname_hash);
	if ((strncmp(key->ifname, ifp->if_name, IFNAMSIZ) == 0) &&
	     key->cont_src == ifp->if_cont_src)
		return 1;

	return 0;
}

/*
 * Lookup ifnet information by the kernel ifindex.
 * Only called from master thread (no locking)
 */
struct ifnet *ifnet_byifindex(unsigned int ifindex)
{
	struct ifnet *ifp = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(ifnet_hash,
			ifindex,
			interface_ifindex_match_fn,
			&ifindex, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		ifp = caa_container_of(node, struct ifnet, ifindex_hash);

	return ifp;
}

struct ifnet *ifnet_byifname_cont_src(enum cont_src_en cont_src,
				      const char *ifname)
{
	struct ifnet *ifp = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct ifname_key key = { .ifname = ifname, .cont_src = cont_src };

	cds_lfht_lookup(ifname_hash,
			interface_ifname_hash(ifname),
			interface_ifname_match_fn,
			&key, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		ifp = caa_container_of(node, struct ifnet, ifname_hash);

	return ifp;
}

struct ifnet *ifnet_byifname(const char *ifname)
{
	struct ifnet *ifp;

	ifp = ifnet_byifname_cont_src(CONT_SRC_MAIN, ifname);
	if (!ifp)
		ifp = ifnet_byifname_cont_src(CONT_SRC_UPLINK, ifname);

	return ifp;
}

/**
 * Find local DPDK interface by the eth_dev->data->name
 */
struct ifnet *ifnet_byethname(const char *ethname)
{
	struct ifnet *ifp;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(ifname_hash, &iter, ifp, ifname_hash) {
		if (ifp->if_local_port) {
			struct rte_eth_dev *eth_dev =
				&rte_eth_devices[ifp->if_port];

			if (strcmp(eth_dev->data->name, ethname) == 0)
				return ifp;
		}
	}

	return NULL;
}

void ifnet_walk(ifnet_iter_func_t func, void *arg)
{
	struct ifnet *ifp;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(ifname_hash, &iter, ifp, ifname_hash) {
		(func)(ifp, arg);
	}
}

static void
ifname_hash_insert(struct ifnet *ifp)
{
	struct ifname_key key;
	struct cds_lfht_node *ret_node;

	key.ifname = ifp->if_name;
	key.cont_src = ifp->if_cont_src;
	ret_node = cds_lfht_add_replace(ifname_hash,
					interface_ifname_hash(ifp->if_name),
					interface_ifname_match_fn,
					&key,
					&ifp->ifname_hash);
	if (ret_node) {
		struct ifnet *replaced =
			caa_container_of(ret_node, struct ifnet, ifname_hash);

		RTE_LOG(ERR, DATAPLANE, "found duplicate ifname %s?\n",
			replaced->if_name);
		if_free(replaced);
	}
}

/* Deassign ifindex */
void if_unset_ifindex(struct ifnet *ifp)
{
	uint32_t old_ifindex = ifp->if_index;

	if (ifp->if_index == 0)
		return;

	/*
	 * notify features of impending interface deletion
	 * This allows features to notify plugins to perform the
	 * necessary cleanup before the interface is deleted
	 */
	dp_event(DP_EVT_IF_INDEX_PRE_UNSET, 0, ifp, 0, 0, NULL);
	fal_l2_del_port(ifp->if_index);
	cds_lfht_del(ifnet_hash, &ifp->ifindex_hash);
	ifp->if_index = 0;
	cds_list_del(&ifp->if_list);
	dp_event(DP_EVT_IF_INDEX_UNSET, 0, ifp, old_ifindex, 0, NULL);
}

/* Assign ifindex to interface */
void if_set_ifindex(struct ifnet *ifp, unsigned int ifindex)
{
	struct cds_lfht_node *ret_node;
	struct ifnet *found_ifp;

	/*
	 * This can happen if the netlink has renamed a port that isn't
	 * a shadow i.e. bonding interfaces. We just need to send the
	 * SET_IFINDEX event to indicate the interface is now ready.
	 */
	if (ifp->if_index == ifindex)
		goto out;

	if_unset_ifindex(ifp);

	if (!ifindex)
		return;

	/*
	 * Use ...add_replace to make sure no other interface is using our
	 * ifindex. If there is one, clean it up.  This avoids an inconsistent
	 * state and makes sure the insertion below will be successful.
	 */
	ifp->if_index = ifindex;
	ret_node = cds_lfht_add_replace(ifnet_hash, ifindex,
				       interface_ifindex_match_fn,
				       &ifindex,
				       &ifp->ifindex_hash);

	if (ret_node) {
		found_ifp = caa_container_of(ret_node, struct ifnet,
					     ifindex_hash);
		if_unset_ifindex(found_ifp);
		RTE_LOG(ERR, DATAPLANE, "%s cleared invalid ifindex %u\n",
			found_ifp->if_name, found_ifp->if_index);

	}

	ifname_hash_insert(ifp);
	cds_list_add_rcu(&ifp->if_list, &ifnet_list);
out:
	dp_event(DP_EVT_IF_INDEX_SET, 0, ifp, ifindex, 0, NULL);
}

/*
 * Bind interface to a new VRF.
 * Increment refcount on new VRF and decrement on previous unless the
 * previous VRF is the INVALID VRF which will be the case if the
 * interface has just been initialised or has failed to bind to a VRF
 * previously.
 * If the new VRF doesn't yet exist then create it.
 */
void
if_set_vrf(struct ifnet *ifp, vrfid_t vrf_id)
{
	vrfid_t old_vrf_id;
	struct vrf *vrf;

	if (unlikely(vrf_id == VRF_INVALID_ID)) {
		DP_DEBUG_W_VRF(VRF, NOTICE, DATAPLANE, vrf_id,
			       "Invalid VRF ID\n");
		return;
	}

	if (ifp->if_vrfid == vrf_id)
		return;

	/*
	 * If we fail to create the new vrf bind to the invalid
	 * vrf - this will cause all traffic to be dropped.
	 * NB/ we don't take a refcount here because we don't
	 * unlock the invalid vrf on unbind.
	 */
	vrf = vrf_find_or_create(vrf_id);
	if (vrf) {
		/*
		 * Ignore initial setting of VRF master interface into
		 * default VRF.
		 */
		if (ifp->if_type == IFT_VRFMASTER &&
		    vrf_id != VRF_DEFAULT_ID) {
			uint32_t vrf_tableid = vrfmaster_get_tableid(ifp);

			route_link_vrf_to_table(vrf, vrf_tableid);
			route6_link_vrf_to_table(vrf, vrf_tableid);
			vrf_set_external_id(vrf, ifp->if_index);

			dp_event(DP_EVT_VRF_CREATE, 0, vrf, 0, 0, NULL);
		}
	} else {
		vrf_id = VRF_INVALID_ID;
	}

	old_vrf_id = ifp->if_vrfid;

	CMM_STORE_SHARED(ifp->if_vrfid, vrf_id);

	/*
	 * Delete old vrf only after assigning new value to ensure
	 * that vrf id in ifp always yields a valid vrf.
	 */
	if (old_vrf_id != VRF_INVALID_ID)
		vrf_delete(old_vrf_id);

	dp_event(DP_EVT_IF_VRF_SET, 0, ifp, 0, 0, NULL);
}

/* Callback from RCU to free interface */
static void if_free_rcu(struct rcu_head *head)
{
	struct ifnet *ifp = caa_container_of(head, struct ifnet, if_rcu);

	l2_rx_fltr_delete_rcu(ifp);

	lltable_free_rcu(ifp->if_lltable);
	lltable_free_rcu(ifp->if_lltable6);

	if (ifp->if_type == IFT_LOOP)
		free(ifp->if_softc);

	if (ifp->vlan_feat_table)
		dp_ht_destroy_deferred(ifp->vlan_feat_table);

	rte_free(ifp->if_vlantbl);
	rte_free(ifp);
}

static void if_unset_netconf(struct ifnet *ifp)
{
	ifp->ip_proxy_arp = false;
	ifp->ip_mc_forwarding = false;
	ifp->ip6_mc_forwarding = false;
	ifp->ip_rpf_strict = false;
	pl_node_remove_feature_by_inst(&ipv4_rpf_feat, ifp);
	pl_node_add_feature_by_inst(&ipv4_in_no_forwarding_feat, ifp);
	pl_node_add_feature_by_inst(&ipv6_in_no_forwarding_feat, ifp);
}

/*
 * Create interface table entry
 *
 * Note: it is floating (not in any table)
 */
struct ifnet *if_alloc(const char *ifname, enum if_type type,
		       unsigned int mtu, const struct ether_addr *eth_addr,
		       int socket)
{
	const struct ift_ops *ops;
	struct ifnet *ifp;
	int ret = 0;

	ops = if_lookup_type(type);
	if (!ops) {
		RTE_LOG(WARNING, DATAPLANE,
			"No ops registered during alloc for interface type %d",
			type);
		return NULL;
	}

	ifp = rte_zmalloc_socket("ifnet", sizeof(struct ifnet),
				 RTE_CACHE_LINE_SIZE, socket);
	if (!ifp)
		return NULL;

	if (eth_addr)
		ether_addr_copy(eth_addr, &ifp->eth_addr);

	if (strlen(ifname) >= IFNAMSIZ)
		RTE_LOG(NOTICE, DATAPLANE,
			"Truncating too long interface name: %s\n", ifname);
	snprintf(ifp->if_name, IFNAMSIZ, "%s", ifname);

	ifp->if_type = type;
	ifp->if_port = IF_PORT_ID_INVALID;
	ifp->if_mtu = mtu;
	ifp->if_mtu_adjusted = mtu;
	ifp->if_socket = socket;
	rte_timer_init(&ifp->if_stats_timer);

	CDS_INIT_LIST_HEAD(&ifp->if_addrhead);

	if_unset_netconf(ifp);

	ifp->if_lltable = in_domifattach(ifp);
	ifp->if_lltable6 = in6_domifattach(ifp);

	ifp->tpid = ETH_P_8021Q;
	ifp->tpid_offloaded = 1;
	ifp->qinq_vif_cnt = 0;
	if_set_vrf(ifp, VRF_DEFAULT_ID);

	/* set default GARP behaviour */
	get_garp_cfg(&ifp->ip_garp_op);

	if (l2_rx_fltr_init(ifp))
		RTE_LOG(ERR, DATAPLANE, "%s: mcast Rx filter init failed.\n",
			ifp->if_name);

	if (ops->ifop_init) {
		ret = ops->ifop_init(ifp);
		if (ret < 0) {
			if_free(ifp);
			return NULL;
		}
	}

	dp_event(DP_EVT_IF_CREATE, 0, ifp, 0, 0, NULL);

	return ifp;
}

/* Append vlan tag (preserve priority bits) to outgoing mbuf
 * and increment stats
 */
void if_add_vlan(struct ifnet *ifp, struct rte_mbuf **m)
{
	(*m)->ol_flags |= PKT_TX_VLAN_PKT;

	if (ifp->qinq_inner) {
		if_incr_out(ifp, *m);
		vid_encap(ifp->if_vlan, m, ETHER_TYPE_VLAN);
		ifp = ifp->if_parent;
	}

	if ((*m)->ol_flags & PKT_RX_VLAN) {
		(*m)->vlan_tci &= ~VLAN_VID_MASK;
		(*m)->vlan_tci |= ifp->if_vlan;
		(*m)->ol_flags &= ~PKT_RX_VLAN;
	} else
		(*m)->vlan_tci = ifp->if_vlan;

	if_incr_out(ifp, *m);
}

int if_add_l2_addr(struct ifnet *ifp, struct ether_addr *addr)
{
	const struct ift_ops *ops;
	int ret = 0;
	char buf[32];

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return 0;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (ops->ifop_add_l2_addr)
		ret = ops->ifop_add_l2_addr(ifp, addr);

	if (ret < -ENOTSUP) {
		DP_DEBUG(INIT, ERR, DATAPLANE,
			 "%s can't add MAC address %s: %s\n",
			 ifp->if_name,
			 ether_ntoa_r(addr, buf),
			 strerror(-ret));
	} else {
		/* we use promisc mode as a fallback */
		ifpromisc(ifp, 1);
		ret = 0;
	}

	return ret;
}

int if_del_l2_addr(struct ifnet *ifp, struct ether_addr *addr)
{
	const struct ift_ops *ops;
	int ret = 0;
	char buf[32];

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return 0;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (ops->ifop_del_l2_addr)
		ret = ops->ifop_del_l2_addr(ifp, addr);

	if (ret < -ENOTSUP) {
		DP_DEBUG(INIT, ERR, DATAPLANE,
			 "%s can't remove MAC address %s: %s\n",
			 ifp->if_name,
			 ether_ntoa_r(addr, buf),
			 strerror(-ret));
	} else {
		/* we use promisc mode as a fallback */
		ifpromisc(ifp, 0);
		ret = 0;
	}

	return ret;
}

/*
 * Currently, for qinq, driver/hw is configured to process one vlan
 * and DP processes the second tag.
 * Intel hardware NIC seems to calculate the MRU based on the MTU, so
 * we need to add 4 bytes of overhead for QinQ if there is at least one
 * QinQ vif on the corresponding physical interface.
 * Once, we configure the HW to process both vlan tags, we need to
 * check if this is still needed.
 * Note that for virtual dirvers such as virtio and VMX, it would work
 * without this change.
 */
void
if_qinq_created(struct ifnet *phy_ifp)
{
	phy_ifp->qinq_vif_cnt++;

	if (phy_ifp->qinq_vif_cnt == 1)  {
		if (phy_ifp->if_team)
			lag_walk_bond_slaves(phy_ifp,
					     lag_set_phy_qinq_mtu_slave,
					     NULL);

		if_set_mtu(phy_ifp, phy_ifp->if_mtu, true);
	}
}

void
if_qinq_deleted(struct ifnet *phy_ifp)
{
	phy_ifp->qinq_vif_cnt--;

	if (phy_ifp->qinq_vif_cnt == 0) {
		if (phy_ifp->if_team)
			lag_walk_bond_slaves(phy_ifp,
					     lag_set_phy_qinq_mtu_slave,
					     NULL);

		if_set_mtu(phy_ifp, phy_ifp->if_mtu, true);
	}
}

int if_vlan_proto_set(struct ifnet *ifp, uint16_t proto)
{
	struct ifnet *ifp_phy = ifp;
	const struct ift_ops *ops;
	int ret = 0;

	if (!ifp)
		return -ENODEV;

	/*
	 * The protocol for an inner VLAN cannot be changed (it is hardwired
	 * as 0x8100). If support to change it is added then the code below
	 * will need updated to not copy the inner VLAN proto into the outer
	 * and physical VLAN interfaces.
	 */
	if (ifp->qinq_inner) {
		if (proto != ETHER_TYPE_VLAN)
			RTE_LOG(ERR, DATAPLANE,
				"%s: can't change QinQ inner tpid - 0x%x\n",
				ifp->if_name, proto);
		return ret;
	}

	while (ifp_phy->if_type == IFT_L2VLAN && ifp_phy->if_parent)
		ifp_phy = ifp_phy->if_parent;

	if (!ifp_phy->if_local_port)
		return -ENODEV;

	if (ifp_phy->tpid != proto) {
		ops = if_get_ops(ifp_phy);
		ret = -ENOTSUP;
		if (ops && ops->ifop_set_vlan_proto)
			ret = ops->ifop_set_vlan_proto(
				ifp_phy, IF_VLAN_HEADER_OUTER, proto);
		if (ret == -ENOTSUP) {
			ifp_phy->tpid_offloaded = 0;
			pl_node_add_feature_by_inst(
				&sw_vlan_in_feat, ifp_phy);
			ret = 0;
		} else if (ret == 0) {
			ifp_phy->tpid_offloaded = 1;
			pl_node_remove_feature_by_inst(
				&sw_vlan_in_feat, ifp_phy);
		} else
			RTE_LOG(ERR, DATAPLANE, "%s: can't set tpid %x\n",
				ifp_phy->if_name, proto);
	}

	if (!ret) {
		ifp_phy->tpid = proto;
		while (ifp->if_type == IFT_L2VLAN && ifp->if_parent) {
			ifp->tpid = ifp_phy->tpid;
			ifp->tpid_offloaded = ifp_phy->tpid_offloaded;
			ifp = ifp->if_parent;
		}
	}

	return ret;
}

/*
 * Do not delete the interface associated with a hardware port, unless
 * it is due to a hotplug remove. Reinitialise the port with the
 * controller so it has a new ifindex and is ready to be configured.
 */
void netlink_if_free(struct ifnet *ifp)
{
	if (if_is_hwport(ifp) && !ifp->unplugged) {
		teardown_interface_portid(ifp->if_port);
		if_unset_ifindex(ifp);
		setup_interface_portid(ifp->if_port);
		return;
	}
	if_free(ifp);
}

static void
if_clean(struct ifnet *ifp)
{
	if_stop(ifp);
	ifp->if_flags = 0;

	ifa_flush(ifp);
	if_unset_netconf(ifp);

	capture_cancel(ifp);
	portmonitor_cleanup(ifp);
	l2_rx_fltr_cleanup(ifp);
	if (ifp->if_macvlantbl)
		macvlan_table_flush(ifp->if_macvlantbl);

	lltable_flush(ifp->if_lltable6);
	lltable_flush(ifp->if_lltable);
	lltable_stop_timer(ifp->if_lltable6);
	lltable_stop_timer(ifp->if_lltable);
}

static bool
if_remove_pl_feat(struct pl_feature_registration *feat_reg, void *context)
{
	pl_node_remove_feature(feat_reg, context);
	return true;
}

/* Callback from netlink to delete interface */
void
if_free(struct ifnet *ifp)
{
	const struct ift_ops *ops;

	ops = if_get_ops(ifp);
	if (!ops)
		RTE_LOG(WARNING, DATAPLANE,
			"No ops registered during free for interface type %d",
			ifp->if_type);

	if (ops && ops->ifop_pre_uninit)
		ops->ifop_pre_uninit(ifp);

	/* First make ifp unreachable by ifindex and ifname */
	if_unset_ifindex(ifp);
	cds_lfht_del(ifname_hash, &ifp->ifname_hash);

	/* Send event prior to freeing features */
	dp_event(DP_EVT_IF_DELETE, 0, ifp, 0, 0, NULL);

	if_clean(ifp);

	pl_node_iter_features(ipv4_validate_node_ptr, ifp,
			      if_remove_pl_feat, ifp);
	pl_node_iter_features(ipv4_out_node_ptr, ifp,
			      if_remove_pl_feat, ifp);
	pl_node_iter_features(ipv6_validate_node_ptr, ifp,
			      if_remove_pl_feat, ifp);
	pl_node_iter_features(ipv6_out_node_ptr, ifp,
			      if_remove_pl_feat, ifp);

	/*
	 * Turn off promiscuous mode if left on so we don't leak
	 * promiscuous mode refcounts in parent interfaces (if
	 * present) and also so if this is a physical interface then
	 * when an ifp is recreated for it the hardware is in the
	 * state that we expect.
	 */
	if (ifp->if_pcount && !ifp->unplugged) {
		ifp->if_pcount = 1;
		ifpromisc(ifp, 0);
	}

	if (ops && ops->ifop_uninit)
		ops->ifop_uninit(ifp);

	vrf_delete(ifp->if_vrfid);

	call_rcu(&ifp->if_rcu, if_free_rcu);
}

bool
if_setup_vlan_storage(struct ifnet *ifp)
{
	ifp->if_vlantbl = rte_calloc_socket("vlan", VLAN_N_VID,
					    sizeof(*ifp->if_vlantbl),
					    0, ifp->if_socket);
	return ifp->if_vlantbl != NULL;
}

/*
 * Set/clear promiscuous mode on interface ifp based on the truth value
 * of onswitch. The calls are reference counted so that only the first
 * "on" request actually has an effect, as does the final "off" request.
 * Results are undefined if the "off" and "on" requests are not matched.
 */
void ifpromisc(struct ifnet *ifp, int onswitch)
{
	const struct ift_ops *ops;
	int ret;

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return;

	ops = if_get_ops(ifp);
	if (!ops)
		return;

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Attempt to %s promiscuous mode for %s.\n",
		 onswitch ? "enable" : "disable",  ifp->if_name);

	if (onswitch) {
		if (ifp->if_pcount++)
			return;	/* already in on */

		DP_DEBUG(INIT, DEBUG, DATAPLANE,
			 "%s: promiscuous enabled\n", ifp->if_name);
	} else {
		if (--ifp->if_pcount)
			return;

		DP_DEBUG(INIT, DEBUG, DATAPLANE,
			 "%s: promiscuous disabled\n",
			 ifp->if_name);
	}

	if (ops->ifop_set_promisc)
		ret = ops->ifop_set_promisc(ifp, onswitch);
	else
		ret = 0;

	if (ret < 0)
		RTE_LOG(ERR, DATAPLANE,
			"%s promiscuous for %s failed: %d (%s)\n",
			onswitch ? "enable" : "disable",
			ifp->if_name, ret, strerror(-ret));

	l2_rx_fltr_state_change(ifp);
}

/* Enable promiscuous reception of IP multicasts from the interface */
void if_allmulti(struct ifnet *ifp, int onoff)
{
	/* Changing mode on vlan, changes parent */
	if (ifp->if_parent)
		if_allmulti(ifp->if_parent, onoff);

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Attempt to %s multicast promiscuous mode for %s.\n",
		 onoff ? "enable" : "disable",  ifp->if_name);

	if (onoff)
		ifp->if_allmcast_ref++;
	else {
		ifp->if_allmcast_ref--;
		assert(ifp->if_allmcast_ref >= 0);
	}

	l2_rx_fltr_state_change(ifp);
}

static void if_team_init(struct ifnet *ifp)
{
	struct rte_eth_dev_info dev_info;

	if (ifp->if_type != IFT_ETHER)
		return;

	rte_eth_dev_info_get(ifp->if_port, &dev_info);

	DP_DEBUG(INIT, DEBUG, DATAPLANE,
		"%d:%s dev_info.driver_name %s\n",
		ifp->if_index, ifp->if_name, dev_info.driver_name);

	if (strstr(dev_info.driver_name, "rte_bond_pmd") != NULL)
		ifp->if_team = 1;
}

static struct ifnet *
if_hwport_init(const char *if_name, unsigned int portid,
	       const struct ether_addr *eth, int socketid)
{
	struct ifnet *ifp;

	/* device driver couldn't find MAC address */
	if (is_zero_ether_addr(eth)) {
		RTE_LOG(NOTICE, DATAPLANE,
			"%s port %u: address not set!\n", if_name, portid);
		return NULL;
	}

	ifp = if_alloc(if_name, IFT_ETHER, ETHER_MTU, eth, socketid);
	if (!ifp)
		return NULL;

	ifp->if_port = portid;

	/*
	 * Temporarily turn off VLAN insertion offload for Mellanox
	 * ConnectX5 devices. This should be removed when DPDK is
	 * up-reved to 1908
	 */
	if (is_device_mlx5(portid))
		ifp->tpid_offloaded = 0;

	if (!if_setup_vlan_storage(ifp)) {
		if_free(ifp);
		return NULL;
	}

	ifname_hash_insert(ifp);

	return ifp;
}

/*
 * Initialize a hardwired port.
 */
struct ifnet *if_hwport_alloc(unsigned int portid,
			      const struct ether_addr *eth, int socketid)
{
	struct ifnet *ifp;
	char if_name[IFNAMSIZ];

	/* Temporary name during boot up.
	 * Should never be visible, but set a value to avoid any potential
	 * issues from messages during startup.
	 */
	snprintf(if_name, IFNAMSIZ, "port%u", portid);


	ifp = if_hwport_init(if_name, portid, eth, socketid);
	if (!ifp)
		return NULL;

	/* Can't set ifp->if_dp_id, we have not been told our dp_id yet */

	/* port is on this dataplane, so if_port is valid */
	ifp->if_local_port = 1;

	/*
	 * Set mac-address driver filtering as initially
	 * supported. This will be reset later if any subsequent
	 * attempt to program filtering in the driver should fail.
	 */
	ifp->if_mac_filtr_supported = 1;
	ifp->if_mac_filtr_reprogram = 0;

	if_team_init(ifp);
	return ifp;
}

/* Cleanup all pseudo-interfaces. */
void if_cleanup(enum cont_src_en cont_src)
{
	struct ifnet *ifp, *tmp;

	/*
	 * Walk in newest first order, thus guaranteeing that children
	 * are deleted before parents, as parents are created first.
	 */
	cds_list_for_each_entry_safe(ifp, tmp, &ifnet_list, if_list) {
		if (ifp->if_cont_src == cont_src) {
			fal_l2_del_port(ifp->if_index);

			/* eth ports are only registered on boot, remove
			 * signaled state, but dont free ifnet.
			 */
			if (ifp->if_type == IFT_ETHER && ifp->if_local_port) {
				if_unset_ifindex(ifp);
				if_clean(ifp);
				if_set_vrf(ifp, VRF_DEFAULT_ID);
			} else
				if_free(ifp);
		}
	}
}

/* Sum the per-pcore statistics to get one set of data */
bool if_stats(struct ifnet *ifp, struct if_data *stats)
{
	unsigned int lcore, i, n = sizeof(struct if_data) / sizeof(uint64_t);
	uint64_t *sum = (uint64_t *) stats;
	const struct ift_ops *ops;
	int ret;

	memset(sum, 0, sizeof(struct if_data));

	FOREACH_DP_LCORE(lcore) {
		const uint64_t *pcpu
			= (const uint64_t *) &ifp->if_data[lcore];

		for (i = 0; i < n; i++)
			sum[i] += pcpu[i];
	}

	ops = if_get_ops(ifp);
	if (!ops)
		return false;

	if (ops->ifop_get_stats) {
		ret = ops->ifop_get_stats(ifp, stats);
		if (ret < 0)
			return false;
	}

	if (ifp->if_type == IFT_L2VLAN) {
		struct sched_info *qinfo = qos_handle(ifp->if_parent);
		struct rte_sched_subport_stats64 subport_stats;
		uint64_t bytes_dropped = 0;
		uint64_t total_drops = 0;
		uint64_t red_drops = 0;
		uint32_t tc;

		/*
		 * If we don't have QoS configured on the VLAN's parent
		 * interface, then we're not running QoS on the VLAN
		 * and the VLAN counters don't need adjusted.
		 */
		if (!qinfo)
			return true;

		if (!qos_sched_subport_get_stats(qinfo, ifp->if_vlan,
						 &subport_stats))
			return false;

		for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
			bytes_dropped += subport_stats.n_bytes_tc_dropped[tc];
			total_drops += subport_stats.n_pkts_tc_dropped[tc];
			red_drops += subport_stats.n_pkts_red_dropped[tc];
		}
		stats->ifi_obytes -= bytes_dropped;
		stats->ifi_opackets -= total_drops;
		stats->ifi_odropped_txring = total_drops - red_drops;
		stats->ifi_odropped_proto = red_drops;
	}

	return true;
}

/* Sum the per-pcore mpls statistics to get one set of data */
void if_mpls_stats(const struct ifnet *ifp, struct if_mpls_data *stats)
{
	unsigned int lcore, i, n = sizeof(struct if_mpls_data) / sizeof(uint64_t);
	uint64_t *sum = (uint64_t *) stats;

	memset(sum, 0, sizeof(struct if_mpls_data));

	FOREACH_DP_LCORE(lcore) {
		const uint64_t *pcpu
			= (const uint64_t *) &ifp->if_mpls_data[lcore];

		for (i = 0; i < n; i++)
			sum[i] += pcpu[i];
	}

}


/* Load average based on code from FreeBSD */
#define	FSHIFT	11		/* bits to right of fixed binary point */
#define FSCALE	(1<<FSHIFT)

/*
 * Constants for averages over 1, 5, and 15 minutes
 * when sampling at 5 second intervals.
 */
static const uint32_t cexp[3] = {
	0.9200444146293232 * FSCALE,	/* exp(-1/12) */
	0.9834714538216174 * FSCALE,	/* exp(-1/60) */
	0.9944598480048967 * FSCALE,	/* exp(-1/180) */
};

/* Convert from scaled value to displayable counter
 * Note: could do floating point here but not worth it,
 *       no one really cares of about 3.250 packets/sec
 */
uint64_t if_scaled(uint64_t value)
{
	return value / FSCALE;
}

/* Update the last sample and moving performance averages */
static bool if_perf_update(struct if_perf *stats, uint64_t val)
{
	uint64_t est = ((val - stats->last) << FSHIFT) / SAMPLE_INTERVAL;
	int i;

	stats->cur = est;
	stats->last = val;

	for (i = 0; i < 3; i++)
		stats->avg[i] = (cexp[i] * stats->avg[i]
			 + est * (FSCALE - cexp[i])) >> FSHIFT;

	return est != 0;
}


/* Clear rolling average, done when stopping statistics update */
static void if_perf_clear(struct if_perf *stats)
{
	int i;

	stats->cur = 0;
	for (i = 0; i < 3; i++)
		stats->avg[i] = 0;
}

/* Update interface statistics */
static void if_perf_timer(struct rte_timer *tim __rte_unused, void *arg)
{
	struct ifnet *ifp = arg;
	struct if_data swstats;
	bool changed;

	if_stats(ifp, &swstats);

	changed = if_perf_update(&ifp->if_rxpps, swstats.ifi_ipackets);
	changed |= if_perf_update(&ifp->if_rxbps, swstats.ifi_ibytes);
	changed |= if_perf_update(&ifp->if_txpps, swstats.ifi_opackets);
	changed |= if_perf_update(&ifp->if_txbps, swstats.ifi_obytes);

	if (changed && ifp->if_type != IFT_ETHER)
		send_if_stats(ifp, &swstats);
}

/* Enable updating and propagation of software statistics */
static void if_stats_enable(struct ifnet *ifp)
{
	rte_timer_reset(&ifp->if_stats_timer,
		SAMPLE_INTERVAL * rte_get_timer_hz(),
		PERIODICAL, rte_get_master_lcore(),
		if_perf_timer,
		ifp);
}

/* Disable timer used for collecting statistics */
static void if_stats_disable(struct ifnet *ifp)
{
	rte_timer_stop(&ifp->if_stats_timer);

	if_perf_clear(&ifp->if_rxpps);
	if_perf_clear(&ifp->if_rxbps);
	if_perf_clear(&ifp->if_txpps);
	if_perf_clear(&ifp->if_txbps);
}

int if_blink(struct ifnet *ifp, bool on)
{
	const struct ift_ops *ops;
	int rc = -ENOTSUP;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (ops->ifop_set_mtu)
		rc = ops->ifop_blink(ifp, on);

	return rc;
}

void if_rename(struct ifnet *ifp, const char *ifname)
{
	char old_ifname[IFNAMSIZ];

	if (!strcmp(ifp->if_name, ifname))
		return;

	cds_lfht_del(ifname_hash, &ifp->ifname_hash);
	snprintf(old_ifname, IFNAMSIZ, "%s", ifp->if_name);
	if (strlen(ifname) >= IFNAMSIZ)
		RTE_LOG(NOTICE, DATAPLANE,
			"Truncating too long interface name: %s\n", ifname);
	snprintf(ifp->if_name, IFNAMSIZ, "%s", ifname);
	ifname_hash_insert(ifp);
	if (ifp->if_index)
		dp_event(DP_EVT_IF_RENAME, 0, ifp, 0, 0, old_ifname);
	cross_connect_rename(ifp, ifname);
}

struct incomplete_if_stats {
	uint64_t if_ignore_add;
	uint64_t if_ignore_del;
	uint64_t if_complete;
	uint64_t inserted;
	uint64_t route_add;
	uint64_t route_del;
	uint64_t route_del_missing;
	uint64_t route_update;
	uint64_t missed_replayed;
	uint64_t missed_add;
	uint64_t missed_del;
	uint64_t missed_del_missing;
	uint64_t missed_update;
	uint64_t mem_fails;
};

struct ignored_interface {
	struct cds_lfht_node hash_node;
	struct rcu_head if_rcu;
	uint32_t ifindex;
};

struct incomplete_route {
	struct cds_lfht_node hash_node;
	struct rcu_head rcu;

	/* keys */
	struct ip_addr dest;
	uint32_t label;
	vrfid_t vrf_id;
	uint32_t table;
	uint8_t depth;
	uint8_t scope;
	uint8_t proto;

	/* netlink message */
	struct nlmsghdr *nlh;
};

enum missed_nl_type {
	MISSED_UNSPEC_LINK,
	MISSED_UNSPEC_ADDR,
	MISSED_INET_ADDR,
	MISSED_INET6_ADDR,
	MISSED_INET_NETCONF,
	MISSED_INET6_NETCONF,
	MISSED_CHILD_LINK,
};

struct missed_netlink {
	struct cds_lfht_node hash_node;
	struct rcu_head rcu;

	/* keys -- be sure to zero unused keys! */
	enum missed_nl_type type;
	uint32_t ifindex;
	union {
		struct ether_addr addr;
		struct ip_addr ip;
		unsigned int ifindex;
	} keys;

	/* netlink message */
	struct nlmsghdr *nlh;
};

static struct incomplete_if_stats incomplete_stats;

static struct cds_lfht *incomplete_routes;
static struct cds_lfht *ignored_interfaces;
static struct cds_lfht *missed_netlinks;

#define INCOMPLETE_HASH_MIN 2
#define INCOMPLETE_HASH_MAX 64

void incomplete_interface_init(void)
{
	missed_netlinks = cds_lfht_new(INCOMPLETE_HASH_MIN,
					INCOMPLETE_HASH_MAX,
					INCOMPLETE_HASH_MAX,
					CDS_LFHT_AUTO_RESIZE |
					CDS_LFHT_ACCOUNTING,
					NULL);
	if (!missed_netlinks)
		rte_panic("Can't allocate hash for incomplete links\n");
	incomplete_routes = cds_lfht_new(INCOMPLETE_HASH_MIN,
					 INCOMPLETE_HASH_MAX,
					 INCOMPLETE_HASH_MAX,
					 CDS_LFHT_AUTO_RESIZE |
					 CDS_LFHT_ACCOUNTING,
					 NULL);
	if (!incomplete_routes)
		rte_panic("Can't allocate hash for incomplete interfaces\n");
	ignored_interfaces = cds_lfht_new(INCOMPLETE_HASH_MIN,
					  INCOMPLETE_HASH_MAX,
					  INCOMPLETE_HASH_MAX,
					  CDS_LFHT_AUTO_RESIZE |
					  CDS_LFHT_ACCOUNTING,
					  NULL);
	if (!ignored_interfaces)
		rte_panic("Can't allocate hash for ignored interfaces\n");
}

static void
ignored_if_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct ignored_interface, if_rcu));
}

static void
incomplete_route_free(struct rcu_head *head)
{
	struct incomplete_route *route;

	route = caa_container_of(head, struct incomplete_route, rcu);
	free(route->nlh);
	free(route);
}

static void
missed_netlink_free(struct rcu_head *head)
{
	struct missed_netlink *missed;

	missed = caa_container_of(head, struct missed_netlink, rcu);
	free(missed->nlh);
	free(missed);
}

void incomplete_interface_cleanup(void)
{
	struct cds_lfht_iter iter;
	struct incomplete_route *route;
	struct ignored_interface *ignored;
	struct missed_netlink *missed;

	cds_lfht_for_each_entry(incomplete_routes, &iter,
				route, hash_node) {
		cds_lfht_del(incomplete_routes, &route->hash_node);
		call_rcu(&route->rcu, incomplete_route_free);
	}
	cds_lfht_destroy(incomplete_routes, NULL);

	cds_lfht_for_each_entry(ignored_interfaces, &iter,
				ignored, hash_node) {
		cds_lfht_del(ignored_interfaces, &ignored->hash_node);
		call_rcu(&ignored->if_rcu, ignored_if_free);
	}
	cds_lfht_destroy(ignored_interfaces, NULL);

	cds_lfht_for_each_entry(missed_netlinks, &iter,
				missed, hash_node) {
		cds_lfht_del(missed_netlinks, &missed->hash_node);
		call_rcu(&missed->rcu, missed_netlink_free);
	}
	cds_lfht_destroy(missed_netlinks, NULL);
}

static inline int ignored_interface_match_fn(struct cds_lfht_node *node,
					     const void *key)
{
	const uint32_t *ifindex = key;
	const struct ignored_interface *info;

	info = caa_container_of(node, const struct ignored_interface,
				hash_node);
	if (info->ifindex != *ifindex)
		return 0;

	return 1;
}

/*
 * Interface is incomplete if we don't have an ifp and it is not on the
 * ignored list.
 */
bool is_ignored_interface(uint32_t ifindex)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	/* Can pass the ifindex in as the hash value */
	cds_lfht_lookup(ignored_interfaces,
			ifindex,
			ignored_interface_match_fn,
			&ifindex, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return true;

	return false;
}

/* Add an interface to the set that we chose not to create an ifp for */
void incomplete_if_add_ignored(uint32_t ifindex)
{
	struct ignored_interface *incmpl;
	struct cds_lfht_node *ret_node;

	incmpl = malloc(sizeof(*incmpl));
	if (!incmpl) {
		incomplete_stats.mem_fails++;
		return;
	}
	incmpl->ifindex = ifindex;

	ret_node = cds_lfht_add_unique(ignored_interfaces, ifindex,
				       ignored_interface_match_fn,
				       &incmpl->ifindex,
				       &incmpl->hash_node);

	if (ret_node == &incmpl->hash_node)
		incomplete_stats.if_ignore_add++;
	else
		free(incmpl);

	incomplete_routes_make_complete();
}

void incomplete_if_del_ignored(uint32_t ifindex)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct ignored_interface *incmpl;

	/* Can pass the ifindex in as the has value */
	cds_lfht_lookup(ignored_interfaces,
			ifindex,
			ignored_interface_match_fn,
			&ifindex, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node)
		return;

	cds_lfht_del(ignored_interfaces, node);

	incmpl = caa_container_of(node, struct ignored_interface, hash_node);
	call_rcu(&incmpl->if_rcu, ignored_if_free);
	incomplete_stats.if_ignore_del++;
}

/*
 * Call this each time a new ifindex arrives to see if there are any
 * routes that can now be made completed.
 */
void incomplete_routes_make_complete(void)
{
	struct cds_lfht_iter iter;
	struct incomplete_route *route;

	incomplete_stats.if_complete++;

	cds_lfht_for_each_entry(incomplete_routes, &iter,
				route, hash_node) {
		/* CONT_SRC_UPLINK does not use the rib broker */
		notify_route(route->nlh, CONT_SRC_MAIN);
	}
}

static uint32_t incomplete_route_hash(struct incomplete_route *route)
{
	int num_words;

	num_words = (offsetof(struct incomplete_route, nlh) -
		     offsetof(struct incomplete_route, dest) + 3) / 4;
	return rte_jhash_32b((uint32_t *)&route->dest, num_words, 0);
}

static inline int incomplete_route_match_fn(struct cds_lfht_node *node,
					    const void *key)
{
	const struct incomplete_route *route;
	const struct incomplete_route *route_key = key;

	route = caa_container_of(node, struct incomplete_route, hash_node);

	if (route->proto != route_key->proto)
		return 0;
	if (route->scope != route_key->scope)
		return 0;
	if (route->depth != route_key->depth)
		return 0;
	if (route->table != route_key->table)
		return 0;
	if (route->vrf_id != route_key->vrf_id)
		return 0;
	if (route->label != route_key->label)
		return 0;
	if (memcmp(&route->dest, &route_key->dest, sizeof(struct ip_addr)))
		return 0;

	return 1;
}

/*
 * Add an incomplete route. If we already have an entry for that key then
 * update the message to new one.
 */
void incomplete_route_add(vrfid_t vrf_id, const void *dst,
			  uint8_t family, uint8_t depth, uint32_t table,
			  uint8_t scope, uint8_t proto,
			  const struct nlmsghdr *nlh)
{
	struct incomplete_route *route;
	struct cds_lfht_node *ret_node;

	route = calloc(1, sizeof(*route));
	if (!route) {
		incomplete_stats.mem_fails++;
		return;
	}

	switch (family) {
	case AF_INET:
		route->dest.address.ip_v4 = *(const struct in_addr *)dst;
		break;
	case AF_INET6:
		route->dest.address.ip_v6 = *(const struct in6_addr *)dst;
		break;
	case AF_MPLS:
		route->label = *(const uint32_t *)dst;
		break;
	}
	route->dest.type = family;
	route->depth = depth;
	route->table = table;
	route->scope = scope;
	route->proto = proto;
	route->vrf_id = vrf_id;
	route->nlh = malloc(nlh->nlmsg_len);
	if (!route->nlh) {
		free(route);
		incomplete_stats.mem_fails++;
		return;
	}
	memcpy(route->nlh, nlh, nlh->nlmsg_len);

	ret_node = cds_lfht_add_replace(incomplete_routes,
					incomplete_route_hash(route),
					incomplete_route_match_fn,
					route,
					&route->hash_node);
	if (ret_node == NULL) {
		/* added, but was no old entry */
		incomplete_stats.route_add++;
	} else if (ret_node != &route->hash_node) {
		/* replaced, so free old one */
		incomplete_stats.route_update++;
		route = caa_container_of(ret_node, struct incomplete_route,
					 hash_node);
		call_rcu(&route->rcu, incomplete_route_free);
	}
}

void incomplete_route_del(vrfid_t vrf_id, const void *dst,
			  uint8_t family, uint8_t depth,
			  uint32_t table, uint8_t scope,
			  uint8_t proto)
{
	struct incomplete_route route;
	struct incomplete_route *found;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	memset(&route, 0, sizeof(route));

	switch (family) {
	case AF_INET:
		route.dest.address.ip_v4 = *(const struct in_addr *)dst;
		break;
	case AF_INET6:
		route.dest.address.ip_v6 = *(const struct in6_addr *)dst;
		break;
	case AF_MPLS:
		route.label = *(const uint32_t *)dst;
		break;
	}
	route.dest.type = family;
	route.depth = depth;
	route.table = table;
	route.scope = scope;
	route.proto = proto;
	route.vrf_id = vrf_id;

	cds_lfht_lookup(incomplete_routes,
			incomplete_route_hash(&route),
			incomplete_route_match_fn,
			&route,
			&iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		incomplete_stats.route_del_missing++;
		return;
	}

	cds_lfht_del(incomplete_routes, node);
	found = caa_container_of(node, struct incomplete_route, hash_node);
	call_rcu(&found->rcu, incomplete_route_free);
	incomplete_stats.route_del++;
}

static void missed_netlink_replay_type(unsigned int ifindex,
				       enum missed_nl_type type)
{
	struct cds_lfht_iter iter;
	struct missed_netlink *missed;

	cds_lfht_for_each_entry(missed_netlinks, &iter, missed, hash_node) {
		if (missed->ifindex == ifindex &&
		    missed->type == type) {
			incomplete_stats.missed_replayed++;
			rtnl_process(missed->nlh, (void *)CONT_SRC_MAIN);
			cds_lfht_del(missed_netlinks, &missed->hash_node);
			call_rcu(&missed->rcu, missed_netlink_free);
		}
	}
}

/*
 * Call this each time a new ifindex arrives to see if there are any
 * netlink messages that need to be replayed.
 */
void missed_netlink_replay(unsigned int ifindex)
{
	missed_netlink_replay_type(ifindex, MISSED_UNSPEC_LINK);
	missed_netlink_replay_type(ifindex, MISSED_UNSPEC_ADDR);
	missed_netlink_replay_type(ifindex, MISSED_INET_ADDR);
	missed_netlink_replay_type(ifindex, MISSED_INET6_ADDR);
	missed_netlink_replay_type(ifindex, MISSED_INET_NETCONF);
	missed_netlink_replay_type(ifindex, MISSED_INET6_NETCONF);
	missed_netlink_replay_type(ifindex, MISSED_CHILD_LINK);
}

static uint32_t missed_netlink_hash(struct missed_netlink *missed)
{
	int num_words;

	num_words = (offsetof(struct missed_netlink, nlh) -
		     offsetof(struct missed_netlink, ifindex) + 3) / 4;
	return rte_jhash_32b((uint32_t *)&missed->ifindex, num_words, 0);
}

static inline int missed_netlink_match_fn(struct cds_lfht_node *node,
					  const void *key)
{
	const struct missed_netlink *missed;
	const struct missed_netlink *missed_key = key;

	missed = caa_container_of(node, struct missed_netlink, hash_node);

	if (missed->type != missed_key->type)
		return 0;
	if (missed->ifindex != missed_key->ifindex)
		return 0;
	if (missed->type == MISSED_UNSPEC_ADDR) {
		if (memcmp(&missed->keys.addr,
			   &missed_key->keys.addr,
			   sizeof(struct ether_addr)) != 0)
			return 0;
	}
	if (missed->type == MISSED_INET_ADDR) {
		if (memcmp(&missed->keys.ip.address.ip_v4,
			   &missed_key->keys.ip.address.ip_v4,
			   4) != 0)
			return 0;
	}
	if (missed->type == MISSED_INET6_ADDR) {
		if (memcmp(&missed->keys.ip.address.ip_v6,
			   &missed_key->keys.ip.address.ip_v6,
			   16) != 0)
			return 0;
	}
	if (missed->type == MISSED_CHILD_LINK) {
		if (memcmp(&missed->keys.ifindex,
			   &missed_key->keys.ifindex,
			   sizeof(unsigned int)) != 0)
			return 0;
	}

	return 1;
}

/*
 * Add a missed netlink message.
 * If we already have an entry for that key then update the message to new one.
 */
static void missed_netlink_add(enum missed_nl_type type,
			       unsigned int ifindex,
			       const void *addr,
			       const struct nlmsghdr *nlh)
{
	struct missed_netlink *missed;
	struct cds_lfht_node *ret_node;

	missed = calloc(1, sizeof(*missed));
	if (!missed) {
		incomplete_stats.mem_fails++;
		return;
	}

	missed->type = type;
	if (type == MISSED_UNSPEC_ADDR)
		memcpy(&missed->keys.addr, addr, sizeof(struct ether_addr));
	if (type == MISSED_INET_ADDR)
		memcpy(&missed->keys.ip.address.ip_v4,
						addr, sizeof(struct in_addr));
	if (type == MISSED_INET6_ADDR)
		memcpy(&missed->keys.ip.address.ip_v6,
						addr, sizeof(struct in6_addr));
	if (type == MISSED_CHILD_LINK)
		memcpy(&missed->keys.ifindex,
		       addr, sizeof(unsigned int));
	missed->ifindex = ifindex;
	missed->nlh = malloc(nlh->nlmsg_len);
	if (!missed->nlh) {
		free(missed);
		incomplete_stats.mem_fails++;
		return;
	}
	memcpy(missed->nlh, nlh, nlh->nlmsg_len);

	ret_node = cds_lfht_add_replace(missed_netlinks,
					missed_netlink_hash(missed),
					missed_netlink_match_fn,
					missed,
					&missed->hash_node);
	if (ret_node == NULL) {
		/* added, but was no old entry */
		incomplete_stats.missed_add++;
	} else if (ret_node != &missed->hash_node) {
		/* replaced, so free old one */
		incomplete_stats.missed_update++;
		missed = caa_container_of(ret_node, struct missed_netlink,
					hash_node);
		call_rcu(&missed->rcu, missed_netlink_free);
	}
}

static void missed_netlink_del(enum missed_nl_type type,
			       unsigned int ifindex,
			       const void *addr)
{
	struct missed_netlink missed, *found;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	memset(&missed, 0, sizeof(missed));
	missed.type = type;
	if (type == MISSED_UNSPEC_ADDR)
		memcpy(&missed.keys.addr, addr, sizeof(struct ether_addr));
	if (type == MISSED_INET_ADDR)
		memcpy(&missed.keys.ip.address.ip_v4,
						addr, sizeof(struct in_addr));
	if (type == MISSED_INET6_ADDR)
		memcpy(&missed.keys.ip.address.ip_v6,
						addr, sizeof(struct in6_addr));
	if (type == MISSED_CHILD_LINK)
		memcpy(&missed.keys.ifindex,
		       addr, sizeof(unsigned int));
	missed.ifindex = ifindex;

	cds_lfht_lookup(missed_netlinks,
			missed_netlink_hash(&missed),
			missed_netlink_match_fn,
			&missed,
			&iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		incomplete_stats.missed_del_missing++;
		return;
	}

	cds_lfht_del(missed_netlinks, node);
	found = caa_container_of(node, struct missed_netlink, hash_node);
	call_rcu(&found->rcu, missed_netlink_free);
	incomplete_stats.missed_del++;
}

void missed_nl_unspec_link_add(unsigned int ifindex,
				const struct nlmsghdr *nlh)
{
	missed_netlink_add(MISSED_UNSPEC_LINK, ifindex, NULL, nlh);
}

void missed_nl_unspec_link_del(unsigned int ifindex)
{
	missed_netlink_del(MISSED_UNSPEC_LINK, ifindex, NULL);
}

void missed_nl_child_link_add(unsigned int ifindex,
			      unsigned int child_ifindex,
			      const struct nlmsghdr *nlh)
{
	missed_netlink_add(MISSED_CHILD_LINK, ifindex, &child_ifindex, nlh);
}

void missed_nl_child_link_del(unsigned int ifindex,
			      unsigned int child_ifindex)
{
	missed_netlink_del(MISSED_CHILD_LINK, ifindex, &child_ifindex);
}

void missed_nl_unspec_addr_add(unsigned int ifindex,
			       const struct ether_addr *addr,
			       const struct nlmsghdr *nlh)
{
	missed_netlink_add(MISSED_UNSPEC_ADDR, ifindex, addr, nlh);
}

void missed_nl_unspec_addr_del(unsigned int ifindex,
			       const struct ether_addr *addr)
{
	missed_netlink_del(MISSED_UNSPEC_ADDR, ifindex, addr);
}

void missed_nl_inet_addr_add(unsigned int ifindex,
			     unsigned char family,
			     const void *addr,
			     const struct nlmsghdr *nlh)
{
	if (family == AF_INET)
		missed_netlink_add(MISSED_INET_ADDR, ifindex, addr, nlh);
	else if (family == AF_INET6)
		missed_netlink_add(MISSED_INET6_ADDR, ifindex, addr, nlh);
	else
		RTE_LOG(ERR, DATAPLANE, "%s: unsupported family\n", __func__);
}

void missed_nl_inet_addr_del(unsigned int ifindex,
			     unsigned char family,
			     const void *addr)
{
	if (family == AF_INET)
		missed_netlink_del(MISSED_INET_ADDR, ifindex, addr);
	else if (family == AF_INET6)
		missed_netlink_del(MISSED_INET6_ADDR, ifindex, addr);
	else
		RTE_LOG(ERR, DATAPLANE, "%s: unsupported family\n", __func__);
}

void missed_nl_inet_netconf_add(unsigned int ifindex,
				unsigned char family,
				const struct nlmsghdr *nlh)
{
	if (family == AF_INET)
		missed_netlink_add(MISSED_INET_NETCONF, ifindex, NULL, nlh);
	else if (family == AF_INET6)
		missed_netlink_add(MISSED_INET6_NETCONF, ifindex, NULL, nlh);
	else
		RTE_LOG(ERR, DATAPLANE, "%s: unsupported family\n", __func__);
}

void missed_nl_inet_netconf_del(unsigned int ifindex,
				unsigned char family)
{
	if (family == AF_INET)
		missed_netlink_del(MISSED_INET_NETCONF, ifindex, NULL);
	else if (family == AF_INET6)
		missed_netlink_del(MISSED_INET6_NETCONF, ifindex, NULL);
	else
		RTE_LOG(ERR, DATAPLANE, "%s: unsupported family\n", __func__);
}

int cmd_incomplete(FILE *f, int argc __unused, char **argv __unused)
{
	json_writer_t *wr = jsonw_new(f);
	unsigned long incmpl_cnt;
	unsigned long ign_cnt;
	long dummy;

	if (!wr)
		return -1;

	cds_lfht_count_nodes(incomplete_routes, &dummy, &incmpl_cnt, &dummy);
	cds_lfht_count_nodes(ignored_interfaces, &dummy, &ign_cnt, &dummy);

	jsonw_name(wr, "incomplete");
	jsonw_start_object(wr);

	jsonw_uint_field(wr, "incomplete", (uint32_t)incmpl_cnt);
	jsonw_uint_field(wr, "ignored", (uint32_t)ign_cnt);
	jsonw_uint_field(wr, "if_ignore_add", incomplete_stats.if_ignore_add);
	jsonw_uint_field(wr, "if_ignore_del", incomplete_stats.if_ignore_del);
	jsonw_uint_field(wr, "if_complete", incomplete_stats.if_complete);
	jsonw_uint_field(wr, "inserted", incomplete_stats.inserted);
	jsonw_uint_field(wr, "route_add", incomplete_stats.route_add);
	jsonw_uint_field(wr, "route_del", incomplete_stats.route_del);
	jsonw_uint_field(wr, "route_del_miss",
			 incomplete_stats.route_del_missing);
	jsonw_uint_field(wr, "route_update", incomplete_stats.route_update);
	jsonw_uint_field(wr, "missed_replayed",
			 incomplete_stats.missed_replayed);
	jsonw_uint_field(wr, "missed_add", incomplete_stats.missed_add);
	jsonw_uint_field(wr, "missed_update", incomplete_stats.missed_update);
	jsonw_uint_field(wr, "missed_del", incomplete_stats.missed_del);
	jsonw_uint_field(wr, "missed_del_miss",
			 incomplete_stats.missed_del_missing);
	jsonw_uint_field(wr, "mem_fail", incomplete_stats.mem_fails);

	jsonw_name(wr, "outstanding_missed");
	jsonw_start_array(wr);

	struct cds_lfht_iter iter;
	struct missed_netlink *missed;

	cds_lfht_for_each_entry(missed_netlinks, &iter, missed, hash_node) {
		jsonw_start_object(wr);

		jsonw_uint_field(wr, "ifindex", missed->ifindex);
		jsonw_uint_field(wr, "type", missed->type);

		jsonw_end_object(wr);
	}

	jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	return 0;
}

void if_set_cont_src(struct ifnet *ifp, enum cont_src_en cont_src)
{
	ifp->if_cont_src = cont_src;
}

/* Uplink is identified by mac addr (config.uplink_addr)
 * This check should only be used to identify the uplink on
 * boot.  If the mac gets overwritten it will not work.
 * TODO: Allow uplink to be specified by other config options
 */
bool if_port_is_uplink(portid_t portid)
{
	if (is_local_controller() || (portid == IF_PORT_ID_INVALID))
		return false;

	struct ether_addr mac_addr;

	rte_eth_macaddr_get(portid, &mac_addr);
	return is_same_ether_addr(&mac_addr, &config.uplink_addr);
}

/* Backplane ports connect switch to CPU
 * and are identified by backplane PCI info in platform config file.
 * All devices connected to defined backplane PCI domain/bus are considered
 * backplane ports.
 * Return true if port is backplane
 */
bool if_port_is_bkplane(portid_t portid)
{
	int index, rv;

	rv = backplane_port_get_index(portid, &index);
	return (rv < 0 ? false : true);
}

bool if_is_control_channel(struct ifnet *ifp)
{
	if (is_local_controller())
		return false;

	if (!ifp)
		return false;

	if (!config.ctrl_intf_name)
		return if_is_uplink(ifp);

	return (!strcmp(ifp->if_name, config.ctrl_intf_name));
}

/* Is this port owned by the cont_src passed in ?
 * Ports are owned by the cont_src that created them
 */
bool if_port_is_owned_by_src(enum cont_src_en cont_src, portid_t portid)
{
	const struct ifnet *ifp = ifnet_byport(portid);

	return (ifp && ifp->if_cont_src == cont_src);
}

/*
 * Used in json output so consider backwards compatibility
 * before changing existing values
 */
const char *iftype_name(uint8_t type)
{
	switch (type) {
	case IFT_ETHER:	 return "ether";
	case IFT_PPP:	 return "ppp";
	case IFT_LOOP:	 return "loopback";
	case IFT_TUNNEL_OTHER: return "tunnel";
	case IFT_TUNNEL_GRE: return "tunnel";
	case IFT_TUNNEL_VTI: return "tunnel";
	case IFT_L2VLAN: return "vlan";
	case IFT_BRIDGE: return "bridge";
	case IFT_VXLAN:	 return "vxlan";
	case IFT_L2TPETH: return "l2tpeth";
	case IFT_MACVLAN: return "macvlan";
	case IFT_VRFMASTER: return "vrf";
	default:	 return "UNKNOWN";
	}
}

bool if_ignore_df(const struct ifnet *ifp)
{
	return is_gre(ifp) && gre_tunnel_ignore_df(ifp);
}

ALWAYS_INLINE bool
is_lo(const struct ifnet *ifp)
{
	struct vfp_softc *vsc;

	if (!ifp)
		return false;

	/*
	 * VRF master devices have the semantics of loopbacks in a
	 * particular VRF.
	 */
	if (ifp->if_type == IFT_VRFMASTER)
		return true;

	if (ifp->if_type != IFT_LOOP)
		return false;

	vsc = ifp->if_softc;
	if (!vsc)
		return false;

	return vsc->vfp_type == VFP_NONE;
}

bool is_s2s_feat_attach(const struct ifnet *ifp)
{
	struct vfp_softc *vsc;

	if (!ifp || ifp->if_type != IFT_LOOP)
		return false;

	vsc = ifp->if_softc;
	if (!vsc)
		return false;

	return vsc->vfp_type == VFP_S2S_CRYPTO;
}

/*
 * Set the type of a virtual feature point.
 *
 * Each virtual feature point can only be used for one purpose, eg. if
 * a vfp is a feature attachment point bound to a crypto s2s tunnel it can
 * be used for other crypto s2s tunnels but not for any other object.
 *
 * Note that the refcount maintained on the vfp guarantees its type will
 * not change but doesn't protect the vfp from being deleted by netlink.
 */
static int if_get_vfp(struct ifnet *ifp, enum vfp_type vfp_type)
{
	struct vfp_softc *vsc = ifp->if_softc;

	if (!((vsc->refcount == 0 && vsc->vfp_type == VFP_NONE) ||
	      vsc->vfp_type == vfp_type)) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to get vfp %s type %d, existing %d\n",
			ifp->if_name, vfp_type, vsc->vfp_type);
		return -EINVAL;
	}

	if (vsc->refcount++ == 0) {
		vsc->vfp_type = vfp_type;

		/*
		 * Make sure packets forwarded directly to the virtual feature
		 * point don't get punted to slowpath.
		 */
		rt_if_handle_in_dataplane(ifp);
		rt6_if_handle_in_dataplane(ifp);

		/* Special per-type handling goes here */
		switch (vfp_type) {
		case VFP_S2S_CRYPTO:
			crypto_policy_update_pending_if(ifp);
			break;
		default:
			break;
		}
	}

	return 0;
}

/*
 * Give up use of a virtual feature point.
 *
 * If the vfp is no longer in use (refcount drops to zero) then
 * return it to being a regular loopback interface.
 */
static int if_put_vfp(struct ifnet *ifp, enum vfp_type vfp_type)
{
	struct vfp_softc *vsc = ifp->if_softc;

	if (vsc->vfp_type != vfp_type) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to put vfp %s type %d, existing %d\n",
			ifp->if_name, vfp_type, vsc->vfp_type);
		return -EINVAL;
	}

	if (--vsc->refcount == 0) {
		/*
		 * Interface is now a loopback. Make sure packets
		 * forwarded directly to it get punted to slowpath.
		 */
		rt_if_punt_to_slowpath(ifp);
		rt6_if_punt_to_slowpath(ifp);
		vsc->vfp_type = VFP_NONE;
	}

	return 0;
}

static int vfp_set_cfg(struct pb_msg *msg)
{
	int ret = -1;
	void *payload = msg->msg;
	int len = msg->msg_len;

	VFPSetConfig *vfp_msg =
		vfpset_config__unpack(NULL, len,
				       payload);
	if (!vfp_msg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read vfp-set protobuf command\n");
		goto done;
	}

	struct ifnet *vfp;

	if (!vfp_msg->has_if_index)
		goto done;

	if (strlen(vfp_msg->if_name) >= IFNAMSIZ)
		goto done;

	if (!vfp_msg->has_type)
		goto done;

	if (vfp_msg->type != VFPSET_CONFIG__VFPTYPE__VFP_S2S_CRYPTO)
		goto done;

	if (!vfp_msg->has_action)
		goto done;

	vfp = ifnet_byifindex(vfp_msg->if_index);
	if (!vfp) {
		/* Interface delete netlink may already have deleted it. */
		if (vfp_msg->action != VFPSET_CONFIG__ACTION__VFP_ACTION_GET)
			goto done;

		 /*
		  * Interface create netlink might not have arrived yet.
		  * If so, go ahead and create the vfp, but leave the netlink
		  * to set any flags.
		  */
		vfp = lo_or_dummy_create(CONT_SRC_MAIN, vfp_msg->if_index, 0,
					 vfp_msg->if_name, 16384, NULL);
		if (!vfp) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to create vfp %s(%u)\n",
				vfp_msg->if_name,
				vfp_msg->if_index);
			goto done;
		}
	}

	if (vfp->if_type != IFT_LOOP) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to set vfp type on %s, not a dummy\n",
			vfp->if_name);
		goto done;
	}

	if (vfp_msg->action == VFPSET_CONFIG__ACTION__VFP_ACTION_GET)
		ret = if_get_vfp(vfp, VFP_S2S_CRYPTO);
	else
		ret = if_put_vfp(vfp, VFP_S2S_CRYPTO);
done:
	vfpset_config__free_unpacked(vfp_msg, NULL);
	return ret;
}

PB_REGISTER_CMD(vfp_set_cmd) = {
	.cmd = "vyatta:vfp-set",
	.handler = vfp_set_cfg,
};


/*
 * vfp <ifindex> <vfp-name> <vfp-type> <action>
 *
 * Supported types:
 *
 * "s2s"  - VFP_S2S_CRYPTO
 *
 * Action is either "get" or "put".
 */
int cmd_set_vfp(FILE *f __unused, int argc, char **argv)
{
	struct ifnet *vfp;
	enum vfp_type vfp_type;
	uint ifindex;
	bool is_get;

	if (argc != 5)
		return -1;

	if (get_unsigned(argv[1], &ifindex) < 0)
		return -1;

	if (strlen(argv[2]) >= IFNAMSIZ)
		return -1;

	if (!strcmp(argv[3], "s2s"))
		vfp_type = VFP_S2S_CRYPTO;
	else
		return -1;

	if (!strcmp(argv[4], "get"))
		is_get = true;
	else if (!strcmp(argv[4], "put"))
		is_get = false;
	else
		return -1;

	vfp = ifnet_byifindex(ifindex);
	if (!vfp) {
		/* Interface delete netlink may already have deleted it. */
		if (!is_get)
			return 0;

		 /*
		  * Interface create netlink might not have arrived yet.
		  * If so, go ahead and create the vfp, but leave the netlink
		  * to set any flags.
		  */
		vfp = lo_or_dummy_create(CONT_SRC_MAIN, ifindex, 0, argv[2],
					 16384, NULL);
		if (!vfp) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to create vfp %s(%u)\n", argv[2],
				ifindex);
			return -1;
		}
	}

	if (vfp->if_type != IFT_LOOP) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to set vfp type on %s, not a dummy\n",
			vfp->if_name);
		return -1;
	}

	if (is_get)
		return if_get_vfp(vfp, vfp_type);
	else
		return if_put_vfp(vfp, vfp_type);
}

/* update MTU of tunnels bound to specified device */
static void update_tunnel_mtu(struct ifnet *ifp)
{
	vxlan_mtu_update(ifp);
}

int if_set_mtu(struct ifnet *ifp, uint32_t mtu, bool force_update)
{
	struct fal_attribute_t mtu_attr = { FAL_PORT_ATTR_MTU, };
	struct fal_attribute_t l3_mtu_attr = {
		.id = FAL_ROUTER_INTERFACE_ATTR_MTU,
	};
	const struct ift_ops *ops;
	int ret = 0;

	if (!force_update && ifp->if_mtu == mtu)
		return 0;

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return 0;

	RTE_LOG(INFO, DATAPLANE,
		"%s changing MTU from %"PRIu32" to %"PRIu32"\n",
		ifp->if_name, ifp->if_mtu, mtu);

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (ops->ifop_set_mtu)
		ret = ops->ifop_set_mtu(ifp, mtu);
	else
		ifp->if_mtu = mtu;

	if (ret >= 0) {
		l3_mtu_attr.value.u16 = mtu;
		if_set_l3_intf_attr(ifp, &l3_mtu_attr);

		/*
		 * In case the interface also has an L2 representation
		 */
		mtu_attr.value.u16 = mtu;
		fal_l2_upd_port(ifp->if_index, &mtu_attr);

		update_tunnel_mtu(ifp);
	} else {
		RTE_LOG(ERR, DATAPLANE,
			"%s changing MTU failed: %d (%s)\n",
			ifp->if_name, ret, strerror(-ret));
	}


	return 0;
}

int if_set_l2_address(struct ifnet *ifp, uint32_t l2_addr_len, void *l2_addr)
{
	struct fal_attribute_t mac_attr = { FAL_PORT_ATTR_MAC_ADDRESS, };
	struct fal_attribute_t l3_mac_attr = {
		.id = FAL_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
	};
	const struct ift_ops *ops;
	int ret;

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return 0;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	/*
	 * Note: this assumes the L2 address is an Ethernet MAC. This
	 * will have to be changed if this assumption ever changes.
	 */
	struct ether_addr old_mac_addr = ifp->eth_addr;

	if (ops->ifop_set_l2_address)
		ret = ops->ifop_set_l2_address(ifp, l2_addr_len, l2_addr);
	else
		return 0;

	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"%s changing L2 address failed: %d (%s)\n",
			ifp->if_name, ret, strerror(-ret));
		return ret;
	}

	/*
	 * Generate the event after the dust settles, but only if
	 * there was actually a change.
	 */
	if (ret == 0) {
		dp_event(DP_EVT_IF_MAC_ADDR_CHANGE, 0, ifp, 0, 0,
			 &old_mac_addr);

		memcpy(&l3_mac_attr.value.mac, l2_addr,
		       sizeof(l3_mac_attr.value.mac));
		if_set_l3_intf_attr(ifp, &l3_mac_attr);

		/*
		 * In case the interface also/instead has an L2
		 * representation.
		 */
		memcpy(&mac_attr.value.mac, l2_addr,
		       sizeof(mac_attr.value.mac));
		fal_l2_upd_port(ifp->if_index, &mac_attr);
	}

	return 0;
}

int if_set_poe(struct ifnet *ifp, bool enable)
{
	struct fal_attribute_t poe_attr = { FAL_PORT_ATTR_POE_ADMIN_STATUS, };

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return 0;

	/* No ift_ops since we only need to support the FAL for now */

	if (ifp->if_poe != enable) {
		poe_attr.value.booldata = enable;
		fal_l2_upd_port(ifp->if_index, &poe_attr);
		ifp->if_poe = enable;
	}

	return 0;
}

int if_get_poe(struct ifnet *ifp, bool *admin_status, bool *oper_status)
{
	struct fal_attribute_t poe_attr;
	int rc;

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return -1;

	/* No ift_ops since we only need to support the FAL for now */

	*admin_status = ifp->if_poe;
	poe_attr.id = FAL_PORT_ATTR_POE_OPER_STATUS;
	rc = fal_l2_get_attrs(ifp->if_index, 1, &poe_attr);
	if (rc != 0)
		return rc;	/* doesn't support PoE */

	*oper_status = poe_attr.value.booldata;
	return 0;
}

void if_finish_create(struct ifnet *ifp, const char *ifi_type,
		      const char *kind,
		      const struct ether_addr *mac_addr)
{
	struct fal_attribute_t attrs[10];
	unsigned int nattrs = 5;

	attrs[0].id = FAL_PORT_ATTR_KIND;
	attrs[0].value.ptr = kind ? kind : "";
	attrs[1].id = FAL_PORT_ATTR_IFI_TYPE;
	attrs[1].value.ptr = ifi_type;
	attrs[2].id = FAL_PORT_ATTR_IFI_FLAGS;
	attrs[2].value.u32 = ifp->if_flags;
	attrs[3].id = FAL_PORT_ATTR_VRF_ID;
	attrs[3].value.u32 = ifp->if_vrfid;
	attrs[4].id = FAL_PORT_ATTR_NAME;
	snprintf(attrs[4].value.if_name, sizeof(attrs[4].value.if_name),
		 "%s", ifp->if_name);
	if (ifp->if_mtu) {
		attrs[nattrs].id = FAL_PORT_ATTR_MTU;
		attrs[nattrs].value.u16 = ifp->if_mtu;
		nattrs++;
	}
	if ((ifp->if_type == IFT_ETHER) &&
	    ifp->if_local_port) {
		attrs[nattrs].id = FAL_PORT_ATTR_DPDK_PORT;
		attrs[nattrs].value.u8 = ifp->if_port;
		nattrs++;
	}
	if (ifp->if_vlan) {
		attrs[nattrs].id = FAL_PORT_ATTR_VLAN_ID;
		attrs[nattrs].value.u16 = ifp->if_vlan;
		nattrs++;
	}
	if (ifp->if_vlan && ifp->if_parent) {
		attrs[nattrs].id = FAL_PORT_ATTR_PARENT_IFINDEX;
		attrs[nattrs].value.u32 = ifp->if_parent->if_index;
		nattrs++;
	}
	if (mac_addr) {
		attrs[nattrs].id = FAL_PORT_ATTR_MAC_ADDRESS;
		memcpy(&attrs[nattrs].value.mac, mac_addr,
		       sizeof(attrs[nattrs].value.mac));
		nattrs++;
	}
	fal_l2_new_port(ifp->if_index, nattrs, attrs);

	incomplete_routes_make_complete();
	missed_netlink_replay(ifp->if_index);

	ifp->if_created = true;
	if_create_finished(ifp, mac_addr);
	dp_event(DP_EVT_IF_CREATE_FINISHED, 0, ifp, 0, 0, NULL);
}

int if_start(struct ifnet *ifp)
{
	const struct ift_ops *ops;
	int ret;

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return 0;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (ops->ifop_start)
		ret = ops->ifop_start(ifp);
	else
		ret = 0;

	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"starting %s failed: %d (%s)\n",
			ifp->if_name, ret, strerror(-ret));
		return ret;
	}

	if_stats_enable(ifp);
	/* Enable forwarding in the FAL */
	fal_if_update_forwarding_all(ifp);

	RTE_LOG(NOTICE, DATAPLANE, "%s changed state to admin up\n",
		ifp->if_name);

	return 0;
}

int if_stop(struct ifnet *ifp)
{
	const struct ift_ops *ops;
	int ret = 0;

	/*
	 * Don't call ifop_stop if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (!ifp->unplugged) {

		ops = if_get_ops(ifp);
		if (!ops)
			return -EINVAL;

		if (ops->ifop_stop)
			ret = ops->ifop_stop(ifp);
	}

	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"stopping %s failed: %d (%s)\n",
			ifp->if_name, ret, strerror(-ret));
		return ret;
	}
	/* Disable forwarding in the FAL */
	fal_if_update_forwarding_all(ifp);

	if_stats_disable(ifp);

	mrt_purge(ifp);

	RTE_LOG(WARNING, DATAPLANE, "%s changed state to admin down\n",
		ifp->if_name);

	return 0;
}

int if_set_vlan_filter(struct ifnet *ifp, uint16_t vlan, bool enable)
{
	const struct ift_ops *ops;
	int ret;

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return 0;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (ops->ifop_set_vlan_filter)
		ret = ops->ifop_set_vlan_filter(ifp, vlan, enable);
	else
		ret = 0;

	/*
	 * If there are drivers that only support a limited number of
	 * VLANs being filtered (rather than the full 4K), then we
	 * might want to do something similar to if_add_l2_addr and
	 * turn on VLAN promiscuity as a fall-back. However, there are
	 * no known DPDK drivers or interface implementations that
	 * operate in such a way so this is not done for the moment.
	 */
	if (ret < 0 && ret != -ENOTSUP) {
		RTE_LOG(ERR, DATAPLANE,
			"%s vlan filter for vlan %d, %s failed: %d (%s)\n",
			enable ? "enable" : "disable", vlan,
			ifp->if_name, ret, strerror(-ret));
	}

	return ret;
}

int if_set_broadcast(struct ifnet *ifp, bool enable)
{
	const struct ift_ops *ops;
	int ret;

	/*
	 * Don't make any changes if the device has been hot
	 * unplugged. Only bad things can happen.
	 */
	if (ifp->unplugged)
		return 0;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (ops->ifop_set_broadcast)
		ret = ops->ifop_set_broadcast(ifp, enable);
	else
		ret = 0;

	if (ret < 0)
		RTE_LOG(ERR, DATAPLANE,
			"%s broadcast for %s failed: %d (%s)\n",
			enable ? "enable" : "disable",
			ifp->if_name, ret, strerror(-ret));

	return ret;
}

void if_create_finished(struct ifnet *ifp, const struct ether_addr *mac_addr)
{
	const struct ift_ops *ops;

	ops = if_get_ops(ifp);
	if (!ops)
		return;

	if (ops->ifop_create_finished)
		ops->ifop_create_finished(ifp, mac_addr);
}

void if_get_link_status(struct ifnet *ifp,
			struct if_link_status *if_link)
{
	struct rte_eth_link link;

	if (ifp->if_type == IFT_ETHER && ifp->if_local_port &&
	    !ifp->unplugged) {
		memset(&link, 0, sizeof(link));
		rte_eth_link_get_nowait(ifp->if_port, &link);

		if_link->link_status = link.link_status;
		if_link->link_duplex =
			link.link_duplex ? IF_LINK_DUPLEX_FULL :
			IF_LINK_DUPLEX_HALF;
		if_link->link_speed = link.link_speed;
	} else {
		if_link->link_status = ifp->if_flags & IFF_RUNNING;
		if_link->link_speed = IF_LINK_SPEED_UNKNOWN;
		if_link->link_duplex = IF_LINK_DUPLEX_UNKNOWN;
	}
}

int if_dump_state(struct ifnet *ifp, json_writer_t *wr,
		  enum if_dump_state_type type)
{
	const struct ift_ops *ops;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (!ops->ifop_dump)
		return -EOPNOTSUPP;

	return ops->ifop_dump(ifp, wr, type);
}

static inline int vlan_feat_match_fn(struct cds_lfht_node *node,
				     const void *key)
{
	const struct if_vlan_feat *vf, *vf_key = key;

	vf = caa_container_of(node, const struct if_vlan_feat, vlan_feat_node);
	if (vf->vlan != vf_key->vlan)
		return 0;

	return 1;
}

int if_vlan_feat_create(struct ifnet *ifp, uint16_t vlan,
			fal_object_t fal_obj)
{
	struct cds_lfht_node *ret_node;
	struct if_vlan_feat *vlan_feat;

	if (!ifp->vlan_feat_table) {
		ifp->vlan_feat_table = cds_lfht_new(IFNET_HASH_MIN,
						    IFNET_HASH_MIN,
						    IFNET_HASH_MAX,
						    CDS_LFHT_AUTO_RESIZE |
						    CDS_LFHT_ACCOUNTING,
						    NULL);
		if (!ifp->vlan_feat_table)
			return -ENOMEM;
	}

	vlan_feat = calloc(1, sizeof(*vlan_feat));
	if (!vlan_feat)
		return -ENOMEM;
	vlan_feat->vlan = vlan;
	vlan_feat->fal_vlan_feat = fal_obj;

	ret_node = cds_lfht_add_unique(ifp->vlan_feat_table, vlan,
				       vlan_feat_match_fn,
				       &vlan_feat,
				       &vlan_feat->vlan_feat_node);

	if (ret_node != &vlan_feat->vlan_feat_node) {
		free(vlan_feat);
		return -EEXIST;
	}

	return 0;
}

struct if_vlan_feat *if_vlan_feat_get(struct ifnet *ifp, uint16_t vlan)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct if_vlan_feat vf_key, *vlan_feat;

	if (!ifp->vlan_feat_table)
		return NULL;

	vf_key.vlan = vlan;
	cds_lfht_lookup(ifp->vlan_feat_table, vlan,
			vlan_feat_match_fn, &vf_key, &iter);
	node = cds_lfht_iter_get_node(&iter);

	if (node) {
		vlan_feat =  caa_container_of(node, struct if_vlan_feat,
					      vlan_feat_node);
		return rcu_dereference(vlan_feat);
	}

	return NULL;
}

static void if_vlan_feat_destroy(struct rcu_head *head)
{
	struct if_vlan_feat *vlan_feat = caa_container_of(head,
							  struct if_vlan_feat,
							  rcu);
	free(vlan_feat);
}

int if_vlan_feat_delete(struct ifnet *ifp, uint16_t vlan)
{
	struct if_vlan_feat *vlan_feat;

	vlan_feat = if_vlan_feat_get(ifp, vlan);
	if (!vlan_feat)
		return -ENOENT;

	cds_lfht_del(ifp->vlan_feat_table, &vlan_feat->vlan_feat_node);
	call_rcu(&vlan_feat->rcu, if_vlan_feat_destroy);

	return 0;
}

void
fal_if_update_forwarding(struct ifnet *ifp, uint8_t family, bool multicast)
{
	bool fwd_enable = (ifp->if_flags & IFF_UP);
	struct fal_attribute_t state;
	int ret;

	switch (family) {
	case AF_INET:
		if (multicast) {
			state.id = FAL_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE;
			fwd_enable = ifp->ip_mc_forwarding;
		} else {
			state.id = FAL_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE;
			if (pl_node_is_feature_enabled(
				    &ipv4_in_no_forwarding_feat, ifp))
				fwd_enable = false;
		}
		break;
	case AF_INET6:
		if (multicast) {
			state.id = FAL_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE;
			fwd_enable = ifp->ip6_mc_forwarding;
		} else {
			state.id = FAL_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE;
			if (pl_node_is_feature_enabled(
				    &ipv6_in_no_forwarding_feat, ifp))
				fwd_enable = false;
		}
		break;
	case AF_MPLS:
		state.id = FAL_ROUTER_INTERFACE_ATTR_ADMIN_MPLS_STATE;
		if (!rcu_dereference(ifp->mpls_label_table))
			fwd_enable = false;
		break;
	default:
		RTE_LOG(ERR, DATAPLANE,
			"Unable to reset forwarding on %s, Invalid addr family (%d)\n",
			ifp->if_name, family);
		return;
	}

	state.value.booldata = fwd_enable;
	ret = if_set_l3_intf_attr(ifp, &state);
	if (ret < 0) {
		if (ret != -EOPNOTSUPP)
			RTE_LOG(ERR, DATAPLANE,
				"Unable to reset forwarding on %s, %d (%s)\n",
				ifp->if_name, ret, strerror(-ret));
	} else
		RTE_LOG(NOTICE, DATAPLANE,
			"%s Forwarding %s for %s\n",
			((family == AF_INET) ? "IPv4" :
			 ((family == AF_INET6) ? "IPv6" : "MPLS")),
			fwd_enable ? "enabled" : "disabled", ifp->if_name);

}

void
fal_if_update_forwarding_all(struct ifnet *ifp)
{
	fal_if_update_forwarding(ifp, AF_INET, false);
	fal_if_update_forwarding(ifp, AF_INET6, false);
	fal_if_update_forwarding(ifp, AF_MPLS, false);
	fal_if_update_forwarding(ifp, AF_INET, true);
	fal_if_update_forwarding(ifp, AF_INET6, true);
}

void
if_create_l3_intf(struct ifnet *ifp, const struct ether_addr *mac_addr)
{
	struct fal_attribute_t l3_attrs[10];
	unsigned int l3_nattrs = 2;
	int ret = 0;

	l3_attrs[0].id = FAL_ROUTER_INTERFACE_ATTR_IFINDEX;
	l3_attrs[0].value.u32 = ifp->if_index;
	l3_attrs[1].id = FAL_ROUTER_INTERFACE_ATTR_VRF_ID;
	l3_attrs[1].value.u32 = ifp->if_vrfid;

	if (ifp->if_vlan) {
		if (ifp->if_vlan) {
			l3_attrs[l3_nattrs].id =
				FAL_ROUTER_INTERFACE_ATTR_VLAN_ID;
			l3_attrs[l3_nattrs].value.u16 = ifp->if_vlan;
			l3_nattrs++;
		}
		if (ifp->if_parent) {
			l3_attrs[l3_nattrs].id =
				FAL_ROUTER_INTERFACE_ATTR_PARENT_IFINDEX;
			l3_attrs[l3_nattrs].value.u32 =
				ifp->if_parent->if_index;
			l3_nattrs++;
		}
	}
	if (ifp->if_mtu) {
		l3_attrs[l3_nattrs].id = FAL_ROUTER_INTERFACE_ATTR_MTU;
		l3_attrs[l3_nattrs].value.u16 = ifp->if_mtu;
		l3_nattrs++;
	}
	if (mac_addr) {
		l3_attrs[l3_nattrs].id =
			FAL_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
		memcpy(&l3_attrs[l3_nattrs].value.mac, mac_addr,
		       sizeof(l3_attrs[l3_nattrs].value.mac));
		l3_nattrs++;
	}

	ret = fal_create_router_interface(l3_nattrs, l3_attrs,
					  &ifp->fal_l3);
	if ((ret == 0) && !ifp->fal_l3) {
		RTE_LOG(ERR, DATAPLANE,
			"Invalid L3 object ID returned for %s\n",
			ifp->if_name);
		return;
	}
	if ((ret < 0) && (ret != -EOPNOTSUPP))
		RTE_LOG(ERR, DATAPLANE,
			"Failed to create L3 FAL object for %s, %d (%s)\n",
			ifp->if_name, ret, strerror(ret));
}

void
if_delete_l3_intf(struct ifnet *ifp)
{
	int ret = 0;

	if (!ifp->fal_l3)
		return;

	ret = fal_delete_router_interface(ifp->fal_l3);
	if (ret == 0)
		ifp->fal_l3 = 0;

	if ((ret < 0) && (ret != -EOPNOTSUPP))
		RTE_LOG(ERR, DATAPLANE,
			"Failed to delete L3 FAL object for %s, %d (%s)\n",
			ifp->if_name, ret, strerror(ret));
}

int
if_set_l3_intf_attr(struct ifnet *ifp, struct fal_attribute_t *attr)
{
	struct fal_attribute_t l2_attr;

	/* for backwards compatibility */
	switch (attr->id) {
	case FAL_ROUTER_INTERFACE_ATTR_VLAN_ID:
		l2_attr.id = FAL_PORT_ATTR_VLAN_ID;
		l2_attr.value.u16 = attr->value.u16;
		fal_l2_upd_port(ifp->if_index, &l2_attr);
		break;
	case FAL_ROUTER_INTERFACE_ATTR_VRF_ID:
		l2_attr.id = FAL_PORT_ATTR_VRF_ID;
		l2_attr.value.u32 = attr->value.u32;
		fal_l2_upd_port(ifp->if_index, &l2_attr);
		break;
	}

	if (!ifp->fal_l3)
		return -EOPNOTSUPP;

	return fal_set_router_interface_attr(ifp->fal_l3, attr);
}

int if_set_backplane(struct ifnet *ifp, unsigned int ifindex)
{
	const struct ift_ops *ops;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (!ops->ifop_set_backplane)
		return -EOPNOTSUPP;

	return ops->ifop_set_backplane(ifp, ifindex);
}

int if_get_backplane(struct ifnet *ifp, unsigned int *ifindex)
{
	const struct ift_ops *ops;

	ops = if_get_ops(ifp);
	if (!ops)
		return -EINVAL;

	if (!ops->ifop_get_backplane)
		return -EOPNOTSUPP;

	return ops->ifop_get_backplane(ifp, ifindex);
}
