/*
 * l3_v6_out.c
 *
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/if_ether.h>
#include <linux/snmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stddef.h>

#include "compiler.h"
#include "if_var.h"
#include "ip6_funcs.h"
#include "netinet6/ip6_mroute.h"
#include "npf/npf_cache.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "route_flags.h"
#include "route_v6.h"
#include "snmp_mib.h"
#include "npf.h"

struct pl_node;

static inline struct pl_node *ifp_to_ipv6_out_node(struct ifnet *ifp)
{
	/* our imaginary node */
	return (struct pl_node *)ifp;
}

static inline struct ifnet *ipv6_out_node_to_ifp(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct ifnet *)node;
}

struct ipv6_out_frag_ctx {
	struct next_hop *nh;
	struct ifnet *in_ifp;
	enum l2_packet_type l2_pkt_type;
};

static void
ipv6_out_frag(struct ifnet *out_ifp, struct rte_mbuf *m, void *ctx)
{
	struct ipv6_out_frag_ctx *frag_ctx = ctx;
	struct pl_packet pkt = {
		.mbuf = m,
		.l2_pkt_type = frag_ctx->l2_pkt_type,
		.l2_proto = ETH_P_IPV6,
		.l3_hdr = ip6hdr(m),
		.in_ifp = frag_ctx->in_ifp,
		.out_ifp = out_ifp,
		.nxt.v6 = frag_ctx->nh,
		.npf_flags = NPF_FLAG_CACHE_EMPTY,
	};

	pipeline_fused_ipv6_encap(&pkt);
}

static ALWAYS_INLINE bool
ipv6_out_features(struct pl_packet *pkt, enum pl_mode mode)
{
	struct ifnet *out_ifp = pkt->out_ifp;

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv6_out_features(
			    pkt, ifp_to_ipv6_out_node(out_ifp)))
			return false;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv6_out_no_dyn_features(
			    pkt, ifp_to_ipv6_out_node(out_ifp)))
			return false;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    ipv6_out_node_ptr,
			    ifp_to_ipv6_out_node(out_ifp),
			    pkt))
			return false;
		break;
	}

	return true;
}

ALWAYS_INLINE unsigned int
ipv6_out_process_common(struct pl_packet *pkt, void *context __unused,
			enum pl_mode mode)
{
	if (!ipv6_out_features(pkt, mode))
		return IPV6_OUT_FINISH;

	struct next_hop *nxt = pkt->nxt.v6;
	struct ifnet *in_ifp = pkt->in_ifp;
	struct ifnet *out_ifp = pkt->out_ifp;
	struct ip6_hdr *ip6 = pkt->l3_hdr;
	unsigned int ip6_len = ntohs(ip6->ip6_plen);
	const bool too_big = ip6_len + sizeof(*ip6) > out_ifp->if_mtu;

	const bool reassembled =
		pktmbuf_mdata_exists(pkt->mbuf, PKT_MDATA_DEFRAG);

	/*
	 * Do we need to fragment but can not, and so have to send
	 * an ICMP error?
	 *
	 * If we have a reassembled packet then the cached gleaned_mtu
	 * is our guess at the MTU used by the sender.
	 */
	if (unlikely(too_big)) {
		if (!reassembled || npf_cache_mtu() > out_ifp->if_mtu) {
			if (unlikely(nxt->flags & RTF_MULTICAST)) {
				struct vrf *vrf = vrf_get_rcu(if_vrfid(in_ifp));
				if (vrf) {
					struct mcast6_vrf *mvrf6 =
								&vrf->v_mvrf6;
					MRT6STAT_INC(mvrf6, mrt6s_pkttoobig);
				}
			}
			IP6STAT_INC_MBUF(pkt->mbuf, IPSTATS_MIB_FRAGFAILS);
			icmp6_error(in_ifp, pkt->mbuf, ICMP6_PACKET_TOO_BIG, 0,
				    htonl(out_ifp->if_mtu));
			/* The error consumed the original; indicate such */
			return IPV6_OUT_FINISH;
		}
	}

	/* We can either transmit the packet as we have it, or re-fragment it */
	if (likely(!reassembled)) {
		pkt->l2_proto = ETH_P_IPV6;
		return IPV6_OUT_ENCAP;
	} else {
		struct ipv6_out_frag_ctx ctx = {nxt, in_ifp, pkt->l2_pkt_type};
		ip6_refragment_packet(out_ifp, pkt->mbuf, &ctx, ipv6_out_frag);
	}

	return IPV6_OUT_FINISH;
}

ALWAYS_INLINE unsigned int
ipv6_out_process(struct pl_packet *p, void *context __unused)
{
	return ipv6_out_process_common(p, context, PL_MODE_REGULAR);
}

static int
ipv6_out_feat_change(struct pl_node *node,
		     struct pl_feature_registration *feat,
		     enum pl_node_feat_action action)
{
	struct ifnet *ifp = ipv6_out_node_to_ifp(node);

	return pl_node_feat_change_u16(&ifp->ip6_out_features, feat,
				       action);
}

static int
ipv6_out_feat_change_all(struct pl_feature_registration *feat,
			 enum pl_node_feat_action action)
{
	return if_node_instance_feat_change_all(feat, action,
						ipv6_out_feat_change);
}

ALWAYS_INLINE bool
ipv6_out_feat_iterate(struct pl_node *node, bool first,
		      unsigned int *feature_id, void **context,
		      void **storage_ctx)
{
	struct ifnet *ifp = ipv6_out_node_to_ifp(node);
	bool ret;

	ret = pl_node_feat_iterate_u16(&ifp->ip6_out_features, first,
				       feature_id, context);
	if (ret)
		*storage_ctx = if_node_instance_get_storage_internal(
			ifp,
			PL_FEATURE_POINT_IPV6_OUT_ID,
			*feature_id);

	return ret;
}

static struct pl_node *
ipv6_out_node_lookup(const char *name)
{
	struct ifnet *ifp = dp_ifnet_byifname(name);
	return ifp ? ifp_to_ipv6_out_node(ifp) : NULL;
}

/* Register Node */
PL_REGISTER_NODE(ipv6_out_node) = {
	.name = "vyatta:ipv6-out",
	.type = PL_PROC,
	.handler = ipv6_out_process,
	.feat_change = ipv6_out_feat_change,
	.feat_change_all = ipv6_out_feat_change_all,
	.feat_iterate = ipv6_out_feat_iterate,
	.lookup_by_name = ipv6_out_node_lookup,
	.feat_reg_context = if_node_instance_register_storage,
	.feat_unreg_context = if_node_instance_unregister_storage,
	.feat_get_context = if_node_instance_get_storage,
	.feat_setup_cleanup_cb = if_node_instance_set_cleanup_cb,
	.num_next = IPV6_OUT_NUM,
	.next = {
		[IPV6_OUT_ENCAP] = "ipv6-encap",
		[IPV6_OUT_FINISH] = "term-finish",
	}
};

struct pl_node_registration *const ipv6_out_node_ptr = &ipv6_out_node;
