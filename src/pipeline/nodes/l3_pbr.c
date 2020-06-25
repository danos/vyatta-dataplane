/*
 * l3_pbr.c
 *
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <stdbool.h>
#include <stdint.h>

#include "compat.h"
#include "compiler.h"
#include "if_var.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "route.h"
#include "route_flags.h"
#include "route_v6.h"
#include "urcu.h"
#include "util.h"
#include "vrf_internal.h"

struct rte_mbuf;

enum {
	V4_PKT = true,
	V6_PKT = false
};

static ALWAYS_INLINE bool
	ip_pbr_is_tblid_valid(const struct rte_mbuf *m, uint32_t tblid, bool v4)
{
	if (v4)
		return rt_valid_tblid(pktmbuf_get_vrf(m), tblid);
	else
		return rt6_valid_tblid(pktmbuf_get_vrf(m), tblid);
}

static ALWAYS_INLINE unsigned int
ip_pbr_process_common(struct pl_packet *pkt, bool v4)
{
	struct ifnet *ifp = pkt->in_ifp;
	struct npf_if *nif = rcu_dereference(ifp->if_npf);
	vrfid_t vrfid = pktmbuf_get_vrf(pkt->mbuf);
	struct vrf *vrf = vrf_get_rcu_fast(vrfid);

	/*
	 * For backwards compatibility PBR should not be
	 * applied to packets that are destined locally.
	 */
	if (v4) {
		struct iphdr *ip = pkt->l3_hdr;
		struct next_hop *nxt = rt_lookup_fast(
			vrf, ip->daddr, RT_TABLE_MAIN, pkt->mbuf);
		if (nxt && unlikely(nxt->flags & RTF_LOCAL))
			return IPV4_PBR_ACCEPT;
	} else {
		struct ip6_hdr *ip6 = pkt->l3_hdr;
		struct next_hop *nxt;

		nxt = rt6_lookup_fast(vrf, &ip6->ip6_dst,
				      RT_TABLE_MAIN,
				      pkt->mbuf);
		if (nxt && unlikely(nxt->flags & RTF_LOCAL))
			return IPV6_PBR_ACCEPT;
	}

	/* Protect against race in disable */
	struct npf_config *npf_config = npf_if_conf(nif);

	struct rte_mbuf *m = pkt->mbuf;
	npf_result_t result =
		npf_hook_notrack(npf_get_ruleset(npf_config, NPF_RS_PBR),
				 &m, ifp, PFIL_IN, 0,
				 v4 ? htons(RTE_ETHER_TYPE_IPV4)
				 : htons(RTE_ETHER_TYPE_IPV6), NULL);

	if (unlikely(m != pkt->mbuf)) {
		pkt->mbuf = m;
		pkt->l3_hdr = dp_pktmbuf_mtol3(m, void *);
	}

	if (unlikely(result.decision == NPF_DECISION_BLOCK))
		return v4 ? IPV4_PBR_DROP : IPV6_PBR_DROP;

	if (result.tag_set)
		pkt->tblid = result.tag;

	if (unlikely(!ip_pbr_is_tblid_valid(pkt->mbuf,
					    pkt->tblid, v4)))
		return v4 ? IPV4_PBR_DROP : IPV6_PBR_DROP;

	return v4 ? IPV4_PBR_ACCEPT : IPV6_PBR_ACCEPT;
}


ALWAYS_INLINE unsigned int
ipv4_pbr_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_pbr_process_common(pkt, V4_PKT);
}

ALWAYS_INLINE unsigned int
ipv6_pbr_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_pbr_process_common(pkt, V6_PKT);
}


/* Register Node */
PL_REGISTER_NODE(ipv4_pbr_node) = {
	.name = "vyatta:ipv4-pbr",
	.type = PL_PROC,
	.handler = ipv4_pbr_process,
	.num_next = IPV4_PBR_NUM,
	.next = {
		[IPV4_PBR_ACCEPT] = "term-noop",
		[IPV4_PBR_DROP]   = "term-drop",
	}
};

PL_REGISTER_NODE(ipv6_pbr_node) = {
	.name = "vyatta:ipv6-pbr",
	.type = PL_PROC,
	.handler = ipv6_pbr_process,
	.num_next = IPV6_PBR_NUM,
	.next = {
		[IPV6_PBR_ACCEPT] = "term-noop",
		[IPV6_PBR_DROP]   = "ipv6-drop"
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_pbr_feat) = {
	.name = "vyatta:ipv4-pbr",
	.node_name = "ipv4-pbr",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_PBR,
};

PL_REGISTER_FEATURE(ipv6_pbr_feat) = {
	.name = "vyatta:ipv6-pbr",
	.node_name = "ipv6-pbr",
	.feature_point = "ipv6-validate",
	.id = PL_L3_V6_IN_FUSED_FEAT_PBR,
};
