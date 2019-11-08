/*
 * l3_v6_nptv6.c
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * IPv6 Network Prefix Translator feature
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet6/in6.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_funcs.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <urcu/list.h>
#include <stdbool.h>

#include "compat.h"
#include "compiler.h"
#include "dp_event.h"
#include "if_var.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf/npf_cache.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/rproc/npf_ext_nptv6.h"
#include "pktmbuf.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "util.h"

struct rte_mbuf;

static ALWAYS_INLINE unsigned int
nptv6_process_common(struct pl_packet *pkt, int dir)
{
	bool in = (dir == PFIL_IN);
	struct rte_mbuf *m = pkt->mbuf;
	struct ifnet *ifp = in ? pkt->in_ifp : pkt->out_ifp;
	struct npf_if *nif = rcu_dereference(ifp->if_npf);
	int icmp_type = 0, icmp_code = 0;
	struct npf_config *npf_config;
	const npf_ruleset_t *rlset;
	npf_cache_t npc_local, *npc;
	npf_decision_t decision;
	uint16_t npf_flags = 0;
	npf_rule_t *rl;
	void *handle;

	if (!nif)
		return in ? NPTV6_IN_ACCEPT : NPTV6_OUT_ACCEPT;

	npf_config = npf_if_conf(nif);

	rlset = npf_get_ruleset(npf_config,
				in ? NPF_RS_NPTV6_IN : NPF_RS_NPTV6_OUT);
	if (!rlset)
		return in ? NPTV6_IN_ACCEPT : NPTV6_OUT_ACCEPT;

	if (pktmbuf_mdata_exists(m, PKT_MDATA_DEFRAG)) {
		npc = npf_get_cache(&npf_flags, m, htons(ETHER_TYPE_IPv6));
		if (!npc)
			return in ? NPTV6_IN_DROP : NPTV6_OUT_DROP;
	} else {
		npc = &npc_local;
		/* Initialize packet information cache.	 */
		npf_cache_init(npc);

		/* Cache everything. drop if junk. */
		if (unlikely(!npf_cache_all(npc, m, htons(ETHER_TYPE_IPv6))))
			return in ? NPTV6_IN_DROP : NPTV6_OUT_DROP;
	}

	rl = npf_ruleset_inspect(npc, m, rlset, NULL, ifp, dir);
	decision = npf_rule_decision(rl);

	if (decision == NPF_DECISION_UNMATCHED)
		return in ? NPTV6_IN_ACCEPT : NPTV6_OUT_ACCEPT;

	/* matched nptv6 rule - do stats */
	npf_add_pkt(rl, rte_pktmbuf_pkt_len(m));

	/* Get pointer to nptv6 structure from rule */
	handle = npf_rule_rproc_handle_from_id(rl, NPF_RPROC_ID_NPTV6);
	if (!handle)
		/* Should never happen */
		return in ? NPTV6_IN_DROP : NPTV6_OUT_DROP;

	/* Do the nptv6 translation */
	decision = nptv6_translate(npc, &m, handle, &icmp_type, &icmp_code);

	if (unlikely(m != pkt->mbuf)) {
		pkt->mbuf = m;
		pkt->l3_hdr = pktmbuf_mtol3(m, void *);
	}

	if (unlikely(decision == NPF_DECISION_BLOCK)) {
		if (unlikely(icmp_type != 0)) {
			/* Consumes 'm' */
			icmp6_error(pkt->in_ifp, m, icmp_type, icmp_code, 0);

			return in ? NPTV6_IN_CONSUME : NPTV6_OUT_CONSUME;
		}
		return in ? NPTV6_IN_DROP : NPTV6_OUT_DROP;
	}

	return in ? NPTV6_IN_ACCEPT : NPTV6_OUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
nptv6_in_process(struct pl_packet *pkt)
{
	return nptv6_process_common(pkt, PFIL_IN);
}

ALWAYS_INLINE unsigned int
nptv6_out_process(struct pl_packet *pkt)
{
	return nptv6_process_common(pkt, PFIL_OUT);
}

/* Register Node */
PL_REGISTER_NODE(nptv6_in_node) = {
	.name = "vyatta:ipv6-nptv6-in",
	.type = PL_PROC,
	.handler = nptv6_in_process,
	.num_next = IPV6_NPTV6_IN_NUM,
	.next = {
		[NPTV6_IN_ACCEPT] = "term-noop",
		[NPTV6_IN_DROP]   = "ipv6-drop",
		[NPTV6_IN_CONSUME] = "term-finish"
	}
};

PL_REGISTER_NODE(nptv6_out_node) = {
	.name = "vyatta:ipv6-nptv6-out",
	.type = PL_PROC,
	.handler = nptv6_out_process,
	.num_next = IPV6_NPTV6_OUT_NUM,
	.next = {
		[NPTV6_OUT_ACCEPT] = "term-noop",
		[NPTV6_OUT_DROP]   = "ipv6-drop",
		[NPTV6_OUT_CONSUME] = "term-finish"
	}
};

/* Register Features */
PL_REGISTER_FEATURE(nptv6_in_feat) = {
	.name = "vyatta:ipv6-nptv6-in",
	.node_name = "ipv6-nptv6-in",
	.feature_point = "ipv6-validate",
	.id = PL_L3_V6_IN_FUSED_FEAT_NPTV6,
};

PL_REGISTER_FEATURE(nptv6_out_feat) = {
	.name = "vyatta:ipv6-nptv6-out",
	.node_name = "ipv6-nptv6-out",
	.feature_point = "ipv6-out",
	.id = PL_L3_V6_OUT_FUSED_FEAT_NPTV6,
};
