/*
 * l3_v4_out.c
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/if_ether.h>
#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stddef.h>

#include "compiler.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "route.h"
#include "route_flags.h"
#include "snmp_mib.h"
#include "npf.h"

struct pl_node;

static inline struct pl_node *ifp_to_ipv4_out_node(struct ifnet *ifp)
{
	/* our imaginary node */
	return (struct pl_node *)ifp;
}

static inline struct ifnet *ipv4_out_node_to_ifp(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct ifnet *)node;
}

struct ipv4_out_frag_ctx {
	struct next_hop *nh;
	struct ifnet *in_ifp;
	enum l2_packet_type l2_pkt_type;
};

static void
ipv4_out_frag(struct ifnet *out_ifp, struct rte_mbuf *m, void *ctx)
{
	struct ipv4_out_frag_ctx *frag_ctx = ctx;
	struct pl_packet pkt = {
		.mbuf = m,
		.l2_pkt_type = frag_ctx->l2_pkt_type,
		.l2_proto = ETH_P_IP,
		.l3_hdr = iphdr(m),
		.in_ifp = frag_ctx->in_ifp,
		.out_ifp = out_ifp,
		.nxt.v4 = frag_ctx->nh,
		.npf_flags = NPF_FLAG_CACHE_EMPTY,
	};

	pipeline_fused_ipv4_encap(&pkt);
}

static ALWAYS_INLINE bool
ipv4_out_features(struct pl_packet *pkt, enum pl_mode mode)
{
	struct ifnet *out_ifp = pkt->out_ifp;

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv4_out_features(
			    pkt, ifp_to_ipv4_out_node(out_ifp)))
			return false;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv4_out_no_dyn_features(
			    pkt, ifp_to_ipv4_out_node(out_ifp)))
			return false;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    ipv4_out_node_ptr,
			    ifp_to_ipv4_out_node(out_ifp),
			    pkt))
			return false;
		break;
	}

	return true;
}

ALWAYS_INLINE unsigned int
ipv4_out_process_common(struct pl_packet *pkt, enum pl_mode mode)
{
	if (!ipv4_out_features(pkt, mode))
		return IPV4_OUT_FINISH;

	struct next_hop *nxt = pkt->nxt.v4;
	struct ifnet *in_ifp = pkt->in_ifp;
	struct ifnet *out_ifp = pkt->out_ifp;
	struct iphdr *ip4 = pkt->l3_hdr;
	unsigned int ip4_len = ntohs(ip4->tot_len);
	const bool too_big = ip4_len > out_ifp->if_mtu;

	/*
	 * Do we need to fragment but can not, and so have to send
	 * an ICMP error?
	 */
	if (unlikely(too_big)) {
		if ((ip4->frag_off & htons(IP_DF)) && !if_ignore_df(out_ifp)) {
			IPSTAT_INC_IFP(out_ifp, IPSTATS_MIB_FRAGFAILS);
			icmp_error_out(in_ifp, pkt->mbuf, ICMP_DEST_UNREACH,
				       ICMP_FRAG_NEEDED, htons(out_ifp->if_mtu),
				       out_ifp);
			/* The error preserved the original; make caller drop */
			return IPV4_OUT_DROP;
		}
	}

	/* We can either transmit the packet as we have it, or fragment it */
	if (likely(!too_big)) {
		pkt->l2_proto = ETH_P_IP;
		return IPV4_OUT_ENCAP;
	} else {
		struct ipv4_out_frag_ctx ctx = {nxt, in_ifp, pkt->l2_pkt_type};
		ip_fragment(out_ifp, pkt->mbuf, &ctx, ipv4_out_frag);
	}

	return IPV4_OUT_FINISH;
}

ALWAYS_INLINE unsigned int
ipv4_out_process(struct pl_packet *p)
{
	return ipv4_out_process_common(p, PL_MODE_REGULAR);
}

static int
ipv4_out_feat_change(struct pl_node *node,
		     struct pl_feature_registration *feat,
		     enum pl_node_feat_action action)
{
	struct ifnet *ifp = ipv4_out_node_to_ifp(node);

	return pl_node_feat_change_u16(&ifp->ip_out_features, feat,
				       action);
}

ALWAYS_INLINE bool
ipv4_out_feat_iterate(struct pl_node *node, bool first,
		      unsigned int *feature_id, void **context)
{
	struct ifnet *ifp = ipv4_out_node_to_ifp(node);

	return pl_node_feat_iterate_u16(&ifp->ip_out_features, first,
					feature_id, context);
}

static struct pl_node *
ipv4_out_node_lookup(const char *name)
{
	struct ifnet *ifp = ifnet_byifname(name);
	return ifp ? ifp_to_ipv4_out_node(ifp) : NULL;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_out_node) = {
	.name = "vyatta:ipv4-out",
	.type = PL_PROC,
	.handler = ipv4_out_process,
	.feat_change = ipv4_out_feat_change,
	.feat_iterate = ipv4_out_feat_iterate,
	.lookup_by_name = ipv4_out_node_lookup,
	.num_next = IPV4_OUT_NUM,
	.next = {
		[IPV4_OUT_ENCAP] = "ipv4-encap",
		[IPV4_OUT_FINISH] = "term-finish",
		[IPV4_OUT_DROP] = "term-drop",
	}
};

struct pl_node_registration *const ipv4_out_node_ptr = &ipv4_out_node;
