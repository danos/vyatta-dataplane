/*
 * l3_v6_encap.c
 *
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/if_ether.h>
#include <linux/snmp.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stddef.h>

#include "compiler.h"
#include "if_var.h"
#include "ip6_funcs.h"
#include "ip_mcast.h"
#include "nd6_nbr.h"
#include "nh_common.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "route_flags.h"
#include "route_v6.h"
#include "snmp_mib.h"

struct pl_node;

static inline struct pl_node *ifp_to_ipv6_encap_node(struct ifnet *ifp)
{
	/* our imaginary node */
	return (struct pl_node *)ifp;
}

static inline struct ifnet *ipv6_encap_node_to_ifp(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct ifnet *)node;
}

/*
 * Set the ether encapsulation on the packet.
 * Copy dest mac from NH lle if possible, otherwise try to trigger
 * L2 dest mac resolution, and set from that.
 */
static ALWAYS_INLINE bool
ipv6_encap_eth_from_nh6(struct rte_mbuf *mbuf, const struct next_hop *nh,
			struct in6_addr *addr, struct ifnet *in_ifp)
{
	struct rte_ether_hdr *eth_hdr =
				rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
	struct ifnet *out_ifp = dp_nh_get_ifp(nh); /* Needed for VRRP */

	rte_ether_addr_copy(&out_ifp->eth_addr, &eth_hdr->s_addr);

	/* If already resolved, use the link level encap */
	struct llentry *lle = nh_get_lle(nh);
	if (likely(lle != NULL)) {
		if (llentry_copy_mac(lle, &eth_hdr->d_addr))
			return true;
	}

	/* Derive a multicast MAC address from the IP address */
	if (unlikely(nh->flags & RTF_MULTICAST)) {
		mcast_dst_eth_addr_t eth_daddr = mcast6_dst_eth_addr(addr);
		rte_ether_addr_copy(&eth_daddr.as_addr, &eth_hdr->d_addr);
		return true;
	}

	/* Not yet resolved, so try to do so */
	if (likely(nd6_resolve_fast(in_ifp, out_ifp, mbuf, addr,
				    &eth_hdr->d_addr) == 0))
		return true;

	return false;
}

/*
 * Returns false to indicate packet consumed.
 */
static ALWAYS_INLINE bool
ipv6_encap_features(struct pl_packet *pkt, enum pl_mode mode)
{
	struct ifnet *out_ifp = pkt->out_ifp;

	/* May be called with pkt->l2_proto != ETH_P_IPV6 */

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv6_encap_features(
			    pkt, ifp_to_ipv6_encap_node(out_ifp)))
			return false;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv6_encap_no_dyn_features(
			    pkt, ifp_to_ipv6_encap_node(out_ifp)))
			return false;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    ipv6_encap_node_ptr,
			    ifp_to_ipv6_encap_node(out_ifp),
			    pkt))
			return false;
		break;
	}

	return true;
}

static ALWAYS_INLINE unsigned int
ipv6_encap_process_internal(struct pl_packet *pkt, enum pl_mode mode)
{
	if (!ipv6_encap_features(pkt, mode))
		return IPV6_ENCAP_FEAT_CONSUME;

	struct next_hop *nh = pkt->nxt.v6;
	/*
	 * Incase of ND packets, we dont want to resolve Nexthop,
	 * Just run the features
	 */
	if (nh->flags & RTF_DONT_RESOLVE_NH)
		return IPV6_ENCAP_L2_OUT;


	struct ifnet *in_ifp = pkt->in_ifp;
	struct ifnet *out_ifp = pkt->out_ifp;
	struct rte_mbuf *mbuf = pkt->mbuf;

	if (unlikely(nh->flags & RTF_NH_NEEDS_HW_RES))
		nd6_resolve_hw_ecmp(mbuf, nh);

	/* Get the nexthop address */
	struct in6_addr addr;

	if (nh->flags & RTF_GATEWAY) {
		addr = nh->gateway.address.ip_v6;
	} else {
		struct ip6_hdr *ip6;

		ip6 = ip6hdr(mbuf);
		addr = ip6->ip6_dst;
	}

	/*
	 * If the interface has IFF_NOARP set then nexthop resolution
	 * isn't required and the interface output function is
	 * responsible for putting the encap on the packet.
	 */
	if (unlikely(out_ifp->if_flags & IFF_NOARP))
		return IPV6_ENCAP_L2_OUT;

	/* Assume all other interface types use ethernet encap. */
	if (!ipv6_encap_eth_from_nh6(mbuf, nh, &addr, in_ifp))
		return IPV6_ENCAP_NEIGH_RES_CONSUME;

	return IPV6_ENCAP_L2_OUT;
}

ALWAYS_INLINE unsigned int
ipv6_encap_process_common(struct pl_packet *pkt, void *context __unused,
			  enum pl_mode mode)
{
	struct ifnet *out_ifp = pkt->out_ifp;

	int rc = ipv6_encap_process_internal(pkt, mode);

	/*
	 * Either way the packet has been handed to "lower layers" to
	 * be transmitted.
	 */
	if (rc == IPV6_ENCAP_L2_OUT || rc == IPV6_ENCAP_NEIGH_RES_CONSUME) {
		if (pkt->nxt.v6->flags & RTF_MULTICAST)
			IP6STAT_INC_IFP(out_ifp, IPSTATS_MIB_OUTMCASTPKTS);
		else
			IP6STAT_INC_IFP(out_ifp, IPSTATS_MIB_OUTFORWDATAGRAMS);
	}

	return rc;
}

ALWAYS_INLINE unsigned int
ipv6_encap_only_process_common(struct pl_packet *pkt, void *context __unused,
			       enum pl_mode mode)
{
	return ipv6_encap_process_internal(pkt, mode);
}

ALWAYS_INLINE unsigned int
ipv6_encap_process(struct pl_packet *p, void *context)
{
	return ipv6_encap_process_common(p, context, PL_MODE_REGULAR);
}

ALWAYS_INLINE unsigned int
ipv6_encap_only_process(struct pl_packet *p, void *context)
{
	return ipv6_encap_only_process_common(p, context, PL_MODE_REGULAR);
}

static int
ipv6_encap_feat_change(struct pl_node *node,
		       struct pl_feature_registration *feat,
		       enum pl_node_feat_action action)
{
	struct ifnet *ifp = ipv6_encap_node_to_ifp(node);

	return pl_node_feat_change_u8(&ifp->ip6_encap_features, feat,
				      action);
}

static int
ipv6_encap_feat_change_all(struct pl_feature_registration *feat,
			   enum pl_node_feat_action action)
{
	return if_node_instance_feat_change_all(feat, action,
						ipv6_encap_feat_change);
}

ALWAYS_INLINE bool
ipv6_encap_feat_iterate(struct pl_node *node, bool first,
			unsigned int *feature_id, void **context,
			void **storage_ctx)
{
	struct ifnet *ifp = ipv6_encap_node_to_ifp(node);
	bool ret;

	ret = pl_node_feat_iterate_u8(&ifp->ip6_encap_features, first,
				      feature_id, context);
	if (ret)
		*storage_ctx = if_node_instance_get_storage_internal(
			ifp,
			PL_FEATURE_POINT_IPV6_ENCAP_ID,
			*feature_id);

	return ret;
}

ALWAYS_INLINE bool
ipv6_encap_only_feat_iterate(struct pl_node *node, bool first,
			     unsigned int *feature_id, void **context,
			     void **storage_ctx)
{
	return ipv6_encap_feat_iterate(node, first, feature_id, context,
				       storage_ctx);
}

static struct pl_node *
ipv6_encap_node_lookup(const char *name)
{
	struct ifnet *ifp = dp_ifnet_byifname(name);
	return ifp ? ifp_to_ipv6_encap_node(ifp) : NULL;
}

/* Register Node */
PL_REGISTER_NODE(ipv6_encap_node) = {
	.name = "vyatta:ipv6-encap",
	.type = PL_PROC,
	.handler = ipv6_encap_process,
	.feat_change = ipv6_encap_feat_change,
	.feat_change_all = ipv6_encap_feat_change_all,
	.feat_iterate = ipv6_encap_feat_iterate,
	.lookup_by_name = ipv6_encap_node_lookup,
	.feat_reg_context = if_node_instance_register_storage,
	.feat_unreg_context = if_node_instance_unregister_storage,
	.feat_get_context = if_node_instance_get_storage,
	.feat_setup_cleanup_cb = if_node_instance_set_cleanup_cb,
	.num_next = IPV6_ENCAP_NUM,
	.next = {
		[IPV6_ENCAP_L2_OUT] = "l2-out",
		[IPV6_ENCAP_FEAT_CONSUME] = "term-finish",
		[IPV6_ENCAP_NEIGH_RES_CONSUME] = "term-finish",
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv6_encap_only_node) = {
	.name = "vyatta:ipv6-encap-only",
	.type = PL_PROC,
	.handler = ipv6_encap_only_process,
	.feat_iterate = ipv6_encap_only_feat_iterate,
	.num_next = IPV6_ENCAP_ONLY_NUM,
	.next = {
		[IPV6_ENCAP_ONLY_L2_OUT] = "term-noop",
		[IPV6_ENCAP_ONLY_FEAT_CONSUME] = "term-finish",
		[IPV6_ENCAP_ONLY_NEIGH_RES_CONSUME] = "term-finish",
	}
};

struct pl_node_registration *const ipv6_encap_node_ptr = &ipv6_encap_node;

/*
 * show features ipv6_encap [interface <ifname>]
 */
static int cmd_pl_show_feat_ipv6_encap(struct pl_command *cmd)
{
	return if_node_instance_feat_print(cmd, ipv6_encap_node_ptr);
}

PL_REGISTER_OPCMD(pl_show_feat_ipv6_encap) = {
	.cmd = "show features ipv6_encap",
	.handler = cmd_pl_show_feat_ipv6_encap,
};
