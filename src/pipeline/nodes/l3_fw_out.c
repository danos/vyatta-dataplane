/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <stdbool.h>

#include "compiler.h"
#include "if_var.h"
#include "npf/config/npf_config.h"
#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "urcu.h"
#include "ip_funcs.h"
#include "ip6_funcs.h"

enum {
	V4_PKT = true,
	V6_PKT = false
};

static ALWAYS_INLINE unsigned int
ip_fw_out_process_common(struct pl_packet *pkt, bool v4)
{
	struct ifnet *ifp = pkt->out_ifp;
	unsigned long bitmask;

	if (v4)
		bitmask = NPF_IF_SESSION | NPF_V4_TRACK_OUT;
	else
		bitmask = NPF_IF_SESSION | NPF_V6_TRACK_OUT;

	struct npf_if *nif = rcu_dereference(ifp->if_npf);

	/* Output NPF Firewall and NAT or Zone and NAT */
	if  (npf_if_active(nif, bitmask)) {
		npf_result_t result;
		struct rte_mbuf *m = pkt->mbuf;

		result = npf_hook_track(pkt->in_ifp, &m, nif, PFIL_OUT,
					pkt->npf_flags,
					v4 ? htons(RTE_ETHER_TYPE_IPV4) :
					htons(RTE_ETHER_TYPE_IPV6));
		if (unlikely(m != pkt->mbuf)) {
			pkt->mbuf = m;
			pkt->l3_hdr = dp_pktmbuf_mtol3(m, void *);
		}
		if (unlikely(result.decision != NPF_DECISION_PASS))
			return v4 ? IPV4_FW_OUT_DROP : IPV6_FW_OUT_DROP;

		/* Update npf_flags for nat64 */
		pkt->npf_flags = result.flags;

	} else if ((pkt->npf_flags & NPF_FLAG_FROM_ZONE) &&
		   !(pkt->npf_flags & NPF_FLAG_FROM_US))
		/* Zone to non-zone (no fw) -> drop */
		return v4 ? IPV4_FW_OUT_DROP : IPV6_FW_OUT_DROP;

	return v4 ? IPV4_FW_OUT_ACCEPT : IPV6_FW_OUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_fw_out_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_fw_out_process_common(pkt, V4_PKT);
}

ALWAYS_INLINE unsigned int
ipv6_fw_out_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_fw_out_process_common(pkt, V6_PKT);
}

ALWAYS_INLINE unsigned int
ipv4_fw_out_spath_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_fw_out_process_common(pkt, V4_PKT);
}

ALWAYS_INLINE unsigned int
ipv4_fw_orig_process(struct pl_packet *pkt, void *context __unused)
{
	if (pkt->npf_flags & NPF_FLAG_FROM_US) {
		if (ipv4_originate_filter_flags(pkt->out_ifp, pkt->mbuf,
				pkt->npf_flags))
			return IPV4_FW_ORIG_DROP;
	}

	return IPV4_FW_ORIG_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv6_fw_orig_process(struct pl_packet *pkt, void *context __unused)
{
	if (pkt->npf_flags & NPF_FLAG_FROM_US) {
		if (ipv6_originate_filter_flags(pkt->out_ifp, pkt->mbuf,
				pkt->npf_flags))
			return IPV6_FW_ORIG_DROP;
	}

	return IPV6_FW_ORIG_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_fw_out_node) = {
	.name = "vyatta:ipv4-fw-out",
	.type = PL_PROC,
	.handler = ipv4_fw_out_process,
	.num_next = IPV4_FW_OUT_NUM,
	.next = {
		[IPV4_FW_OUT_ACCEPT]       = "term-noop",
		[IPV4_FW_OUT_DROP]         = "term-drop",
	}
};

PL_REGISTER_NODE(ipv6_fw_out_node) = {
	.name = "vyatta:ipv6-fw-out",
	.type = PL_PROC,
	.handler = ipv6_fw_out_process,
	.num_next = IPV6_FW_OUT_NUM,
	.next = {
		[IPV6_FW_OUT_ACCEPT]       = "term-noop",
		[IPV6_FW_OUT_DROP]         = "ipv6-drop",
	}
};

PL_REGISTER_NODE(ipv4_fw_orig_node) = {
	.name = "vyatta:ipv4-fw-orig",
	.type = PL_PROC,
	.handler = ipv4_fw_orig_process,
	.num_next = IPV4_FW_ORIG_NUM,
	.next = {
		[IPV4_FW_ORIG_ACCEPT]   = "term-noop",
		[IPV4_FW_ORIG_DROP]     = "term-drop",
	}
};

PL_REGISTER_NODE(ipv6_fw_orig_node) = {
	.name = "vyatta:ipv6-fw-orig",
	.type = PL_PROC,
	.handler = ipv6_fw_orig_process,
	.num_next = IPV6_FW_ORIG_NUM,
	.next = {
		[IPV6_FW_ORIG_ACCEPT]       = "ipv6-fw-out",
		[IPV6_FW_ORIG_DROP]         = "ipv6-drop",
	}
};

PL_REGISTER_NODE(ipv4_fw_out_spath_node) = {
	.name = "vyatta:ipv4-fw-out-spath",
	.type = PL_PROC,
	.handler = ipv4_fw_out_spath_process,
	.num_next = IPV4_FW_OUT_SPATH_NUM,
	.next = {
		[IPV4_FW_OUT_SPATH_ACCEPT]  = "term-noop",
		[IPV4_FW_OUT_SPATH_DROP]    = "term-drop",
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_fw_out_feat) = {
	.name = "vyatta:ipv4-fw-out",
	.node_name = "ipv4-fw-out",
	.feature_point = "ipv4-out",
	.id = PL_L3_V4_OUT_FUSED_FEAT_FW,
	.visit_after = "vyatta:ipv4-cgnat-out",
};

PL_REGISTER_FEATURE(ipv6_fw_out_feat) = {
	.name = "vyatta:ipv6-fw-out",
	.node_name = "ipv6-fw-out",
	.feature_point = "ipv6-out",
	.id = PL_L3_V6_OUT_FUSED_FEAT_FW,
	.visit_after = "vyatta:ipv6-defrag-out",
};

PL_REGISTER_FEATURE(ipv4_fw_orig_feat) = {
	.name = "vyatta:ipv4-fw-orig",
	.node_name = "ipv4-fw-orig",
	.feature_point = "ipv4-out-spath",
	.id = PL_L3_V4_OUT_FUSED_FEAT_FW_ORIG,
};

PL_REGISTER_FEATURE(ipv4_fw_out_spath_feat) = {
	.name = "vyatta:ipv4-fw-out-spath",
	.node_name = "ipv4-fw-out-spath",
	.feature_point = "ipv4-out-spath",
	.id = PL_L3_V4_OUT_SPATH_FUSED_FEAT_FW,
};
