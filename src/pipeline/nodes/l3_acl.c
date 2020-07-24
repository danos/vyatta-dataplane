/*
 * l3_acl.c
 *
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
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
#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf/npf_cache.h"
#include "npf/npf_rc.h"
#include "npf/rproc/npf_ext_log.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "util.h"

struct rte_mbuf;

enum {
	V4_PKT = true,
	V6_PKT = false
};

static ALWAYS_INLINE unsigned int
ip_acl_process_common(struct pl_packet *pkt, bool v4, int dir)
{
	struct ifnet *ifp;
	unsigned long bitmask;
	enum npf_ruleset_type rs_type;
	npf_decision_t decision = NPF_DECISION_UNMATCHED;
	int rc = NPF_RC_UNMATCHED;

	if (dir == PFIL_IN) {
		bitmask = NPF_ACL_IN;
		rs_type = NPF_RS_ACL_IN;
		ifp = pkt->in_ifp;
	} else {
		bitmask = NPF_ACL_OUT;
		rs_type = NPF_RS_ACL_OUT;
		ifp = pkt->out_ifp;

		/* Not for MPLS encapsulated packets */
		if (unlikely(v4 && pkt->l2_proto != ETH_P_IP))
			goto accept;
		if (unlikely(!v4 && pkt->l2_proto != ETH_P_IPV6))
			goto accept;
	}

	/*
	 * Do we have anything to do?
	 *
	 * This is really a sanity check, and potentially covering
	 * race conditions around enable/disable.
	 */
	struct npf_if *nif = rcu_dereference(ifp->if_npf);
	struct npf_config *nif_conf = npf_if_conf(nif);
	if (unlikely(!npf_active(nif_conf, bitmask)))
		goto accept;
	const npf_ruleset_t *npf_ruleset = npf_get_ruleset(nif_conf, rs_type);
	if (unlikely(!npf_ruleset))
		goto accept;

	/* As this sees fragments, it never shares with others */
	npf_cache_t npc;
	struct rte_mbuf *m = pkt->mbuf;

	uint16_t const ethertype =
		v4 ? htons(RTE_ETHER_TYPE_IPV4) : htons(RTE_ETHER_TYPE_IPV6);

	npf_cache_init(&npc);
	rc = npf_cache_all(&npc, m, ethertype);
	if (unlikely(rc < 0))
		goto drop;

	/* Run the ruleset, get the decision */
	npf_rule_t *rl =
		npf_ruleset_inspect(&npc, m, npf_ruleset, NULL, ifp, dir);
	decision = npf_rule_decision(rl);

	/* Optimise for specific drops, and implicit accept */
	if (likely(decision == NPF_DECISION_UNMATCHED)) {
accept:
		/* Increment return code counter */
		npf_rc_inc(ifp, v4 ? NPF_RCT_ACL4 : NPF_RCT_ACL6,
			   PFIL2RC(dir), rc, decision);

		if (dir == PFIL_IN)
			return v4 ? IPV4_ACL_IN_ACCEPT : IPV6_ACL_IN_ACCEPT;

		return v4 ? IPV4_ACL_OUT_ACCEPT : IPV6_ACL_OUT_ACCEPT;
	}

	/* Log any matched rule immediately */
	if (unlikely(npf_rule_has_rproc_logger(rl)))
		npf_log_pkt(&npc, m, rl, dir);

	/* Now perform any rprocs, e.g. ctr */
	npf_rproc_result_t rproc_result = {
		.decision = decision,
	};

	npf_rproc_action(&npc, &m, dir, rl, NULL, &rproc_result);

	if (unlikely(m != pkt->mbuf)) {
		pkt->mbuf = m;
		pkt->l3_hdr = dp_pktmbuf_mtol3(m, void *);
	}

	if (decision == NPF_DECISION_PASS)
		goto accept;

	rc = NPF_RC_BLOCK;

drop:
	/* Increment return code counter */
	npf_rc_inc(ifp, v4 ? NPF_RCT_ACL4 : NPF_RCT_ACL6,
		   PFIL2RC(dir), rc, NPF_DECISION_BLOCK);

	if (dir == PFIL_IN)
		return v4 ? IPV4_ACL_IN_DROP : IPV6_ACL_IN_DROP;

	return v4 ? IPV4_ACL_OUT_DROP : IPV6_ACL_OUT_DROP;
}


ALWAYS_INLINE unsigned int
ipv4_acl_process_in(struct pl_packet *pkt, void *context __unused)
{
	return ip_acl_process_common(pkt, V4_PKT, PFIL_IN);
}

ALWAYS_INLINE unsigned int
ipv6_acl_process_in(struct pl_packet *pkt, void *context __unused)
{
	return ip_acl_process_common(pkt, V6_PKT, PFIL_IN);
}

ALWAYS_INLINE unsigned int
ipv4_acl_process_out(struct pl_packet *pkt, void *context __unused)
{
	return ip_acl_process_common(pkt, V4_PKT, PFIL_OUT);
}

ALWAYS_INLINE unsigned int
ipv6_acl_process_out(struct pl_packet *pkt, void *context __unused)
{
	return ip_acl_process_common(pkt, V6_PKT, PFIL_OUT);
}


/* Register Node */
PL_REGISTER_NODE(ipv4_acl_in_node) = {
	.name = "vyatta:ipv4-acl-in",
	.type = PL_PROC,
	.handler = ipv4_acl_process_in,
	.num_next = IPV4_ACL_IN_NUM,
	.next = {
		[IPV4_ACL_IN_ACCEPT] = "term-noop",
		[IPV4_ACL_IN_DROP]   = "term-drop",
	}
};

PL_REGISTER_NODE(ipv6_acl_in_node) = {
	.name = "vyatta:ipv6-acl-in",
	.type = PL_PROC,
	.handler = ipv6_acl_process_in,
	.num_next = IPV6_ACL_IN_NUM,
	.next = {
		[IPV6_ACL_IN_ACCEPT] = "term-noop",
		[IPV6_ACL_IN_DROP]   = "ipv6-drop",
	}
};

PL_REGISTER_NODE(ipv4_acl_out_node) = {
	.name = "vyatta:ipv4-acl-out",
	.type = PL_PROC,
	.handler = ipv4_acl_process_out,
	.num_next = IPV4_ACL_OUT_NUM,
	.next = {
		[IPV4_ACL_OUT_ACCEPT] = "term-noop",
		[IPV4_ACL_OUT_DROP]   = "term-drop",
	}
};

PL_REGISTER_NODE(ipv6_acl_out_node) = {
	.name = "vyatta:ipv6-acl-out",
	.type = PL_PROC,
	.handler = ipv6_acl_process_out,
	.num_next = IPV6_ACL_OUT_NUM,
	.next = {
		[IPV6_ACL_OUT_ACCEPT] = "term-noop",
		[IPV6_ACL_OUT_DROP]   = "ipv6-drop",
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_acl_in_feat) = {
	.name = "vyatta:ipv4-acl-in",
	.node_name = "ipv4-acl-in",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_ACL,
};

PL_REGISTER_FEATURE(ipv6_acl_in_feat) = {
	.name = "vyatta:ipv6-acl-in",
	.node_name = "ipv6-acl-in",
	.feature_point = "ipv6-validate",
	.id = PL_L3_V6_IN_FUSED_FEAT_ACL,
};

PL_REGISTER_FEATURE(ipv4_acl_out_feat) = {
	.name = "vyatta:ipv4-acl-out",
	.node_name = "ipv4-acl-out",
	.feature_point = "ipv4-encap",
	.id = PL_L3_V4_ENCAP_FUSED_FEAT_ACL,
};

PL_REGISTER_FEATURE(ipv6_acl_out_feat) = {
	.name = "vyatta:ipv6-acl-out",
	.node_name = "ipv6-acl-out",
	.feature_point = "ipv6-encap",
	.id = PL_L3_V6_ENCAP_FUSED_FEAT_ACL,
};
