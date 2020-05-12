/*
 * l3_v4_defrag.c
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <rte_branch_prediction.h>
#include <stdbool.h>

#include "compiler.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "urcu.h"

ALWAYS_INLINE unsigned int
ipv4_defrag_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;
	/* Reassemble packets if required */
	struct iphdr *ip = pkt->l3_hdr;

	if (unlikely(ip_is_fragment(ip))) {
		/*
		 * The conditional below should be enough to handle
		 * both in/out stages of frag support for normal l3
		 * processing paths.
		 *
		 * Need to review once other paths (i.e. local)
		 * access this node.
		 */
		pkt->mbuf = ipv4_handle_fragment(m);
		if (!pkt->mbuf)
			/* consumed by reassembly */
			return IPV4_DEFRAG_IN_FINISH;
		pkt->l3_hdr = iphdr(pkt->mbuf);
	}
	return IPV4_DEFRAG_IN_ACCEPT;
}

static ALWAYS_INLINE unsigned int
ipv4_defrag_out_internal(struct pl_packet *pkt)
{
	struct iphdr *ip = pkt->l3_hdr;

	if (unlikely(ip_is_fragment(ip))) {
		/*
		 * Reassemble packets if required.  This is optimised away for
		 * originated packets (e.g. post tunnel encap),  it is retained
		 * for the MPLS -> IP path, and normal IP forwarding.
		 *
		 * We have to keep it in the latter case such that the stateful
		 * firewall and NAT on the output interface can operate.
		 */
		pkt->mbuf = ipv4_handle_fragment(pkt->mbuf);
		if (!pkt->mbuf)
			/* consumed by reassembly */
			return IPV4_DEFRAG_OUT_FINISH;
		pkt->l3_hdr = iphdr(pkt->mbuf);
	}

	return IPV4_DEFRAG_OUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_defrag_out_process(struct pl_packet *pkt, void *context __unused)
{
	return ipv4_defrag_out_internal(pkt);
}

ALWAYS_INLINE unsigned int
ipv4_defrag_out_spath_process(struct pl_packet *pkt, void *context __unused)
{
	return ipv4_defrag_out_internal(pkt);
}

/* Register Node */
PL_REGISTER_NODE(ipv4_defrag_in_node) = {
	.name = "vyatta:ipv4-defrag-in",
	.type = PL_PROC,
	.handler = ipv4_defrag_in_process,
	.num_next = IPV4_DEFRAG_IN_NUM,
	.next = {
		[IPV4_DEFRAG_IN_ACCEPT] = "term-noop",
		[IPV4_DEFRAG_IN_FINISH] = "term-finish"
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv4_defrag_out_node) = {
	.name = "vyatta:ipv4-defrag-out",
	.type = PL_PROC,
	.handler = ipv4_defrag_out_process,
	.num_next = IPV4_DEFRAG_OUT_NUM,
	.next = {
		[IPV4_DEFRAG_OUT_ACCEPT] = "term-noop",
		[IPV4_DEFRAG_OUT_FINISH] = "term-finish"
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv4_defrag_out_spath_node) = {
	.name = "vyatta:ipv4-defrag-out-spath",
	.type = PL_PROC,
	.handler = ipv4_defrag_out_spath_process,
	.num_next = IPV4_DEFRAG_OUT_SPATH_NUM,
	.next = {
		[IPV4_DEFRAG_OUT_SPATH_ACCEPT] = "ipv4-fw-orig",
		[IPV4_DEFRAG_OUT_SPATH_FINISH] = "term-finish"
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_defrag_in_feat) = {
	.name = "vyatta:ipv4-defrag-in",
	.node_name = "ipv4-defrag-in",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_DEFRAG,
};

PL_REGISTER_FEATURE(ipv4_defrag_out_feat) = {
	.name = "vyatta:ipv4-defrag-out",
	.node_name = "ipv4-defrag-out",
	.feature_point = "ipv4-out",
	.id = PL_L3_V4_OUT_FUSED_FEAT_DEFRAG,
};
