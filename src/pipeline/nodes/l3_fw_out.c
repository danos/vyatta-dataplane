/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdbool.h>

#include "if_var.h"
#include "ip_funcs.h"
#include "npf/config/npf_config.h"
#include "npf/npf_if.h"
#include "netinet6/ip6_funcs.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "npf/npf.h"
#include "fw_out_snat/npf_shim_out.h"

ALWAYS_INLINE unsigned int
ipv4_fw_out_process(struct pl_packet *pkt, void *context __unused)
{
	npf_decision_t result = npf_hook_out_track_fw(pkt);

	if (result != NPF_DECISION_PASS)
		return IPV4_FW_OUT_DROP;

	return IPV4_FW_OUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv6_fw_out_process(struct pl_packet *pkt, void *context __unused)
{
	unsigned long bitmask =
		NPF_IF_SESSION | NPF_V6_TRACK_OUT;

	struct npf_if *nif = rcu_dereference(pkt->out_ifp->if_npf);
	if  (npf_if_active(nif, bitmask)) {
		npf_decision_t result = npf_hook_out_track_v6_fw(pkt);
		if (result != NPF_DECISION_PASS)
			return IPV6_FW_OUT_DROP;
	} else if ((pkt->npf_flags & NPF_FLAG_FROM_ZONE) &&
		   !(pkt->npf_flags & NPF_FLAG_FROM_US))
		/* Zone to non-zone (no fw) -> drop */
		return IPV6_FW_OUT_DROP;

	return IPV6_FW_OUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_fw_out_spath_process(struct pl_packet *pkt, void *context)
{
	return ipv4_fw_out_process(pkt, context);
}

ALWAYS_INLINE unsigned int
ipv6_fw_out_spath_process(struct pl_packet *pkt, void *context)
{
	return ipv6_fw_out_process(pkt, context);
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

PL_REGISTER_NODE(ipv6_fw_out_spath_node) = {
	.name = "vyatta:ipv6-fw-out-spath",
	.type = PL_PROC,
	.handler = ipv6_fw_out_spath_process,
	.num_next = IPV6_FW_OUT_SPATH_NUM,
	.next = {
		[IPV6_FW_OUT_SPATH_ACCEPT]  = "term-noop",
		[IPV6_FW_OUT_SPATH_DROP]    = "term-drop",
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_fw_orig_feat) = {
	.name = "vyatta:ipv4-fw-orig",
	.node_name = "ipv4-fw-orig",
	.feature_point = "ipv4-out-spath",
	.id = PL_L3_V4_OUT_FUSED_FEAT_FW_ORIG,
};

PL_REGISTER_FEATURE(ipv6_fw_orig_feat) = {
	.name = "vyatta:ipv6-fw-orig",
	.node_name = "ipv6-fw-orig",
	.feature_point = "ipv6-out-spath",
	.id = PL_L3_V6_OUT_FUSED_FEAT_FW_ORIG,
};

PL_REGISTER_FEATURE(ipv6_fw_out_feat) = {
	.name = "vyatta:ipv6-fw-out",
	.node_name = "ipv6-fw-out",
	.feature_point = "ipv6-out",
	.id = PL_L3_V6_OUT_FUSED_FEAT_FW_OUT,
	.visit_after = "vyatta:ipv6-defrag-out",
};

PL_REGISTER_FEATURE(ipv6_fw_out_spath_feat) = {
	.name = "vyatta:ipv6-fw-out-spath",
	.node_name = "ipv6-fw-out-spath",
	.feature_point = "ipv6-out-spath",
	.id = PL_L3_V6_OUT_SPATH_FUSED_FEAT_FW_OUT,
};
