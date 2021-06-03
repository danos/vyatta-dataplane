/*
 * Copyright (c) 2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdbool.h>

#include "pl_common.h"
#include "pl_fused.h"
#include "if_var.h"
#include "npf/config/npf_config.h"
#include "npf/npf_if.h"
#include "npf/npf.h"
#include "ip_funcs.h"
#include "fw_out_snat/npf_shim_out.h"

static ALWAYS_INLINE unsigned int
ip_snat_process(struct pl_packet *pkt)
{
	unsigned long bitmask =
		NPF_IF_SESSION | NPF_V4_TRACK_OUT;

	struct npf_if *nif = rcu_dereference(pkt->out_ifp->if_npf);
	if  (npf_if_active(nif, bitmask)) {
		struct rte_mbuf *m = pkt->mbuf;

		npf_decision_t result = npf_hook_out_track_snat(pkt->in_ifp, &m, nif,
								&pkt->npf_flags,
								htons(RTE_ETHER_TYPE_IPV4));

		if (unlikely(m != pkt->mbuf)) {
			pkt->mbuf = m;
			pkt->l3_hdr = dp_pktmbuf_mtol3(m, void *);
		}

		if (result == NPF_DECISION_BLOCK)
			return IPV4_SNAT_DROP;
		if (result == NPF_DECISION_UNMATCHED)
			return IPV4_SNAT_DOFW;

	} else if ((pkt->npf_flags & NPF_FLAG_FROM_ZONE) &&
		   !(pkt->npf_flags & NPF_FLAG_FROM_US))
		/* Zone to non-zone (no fw) -> drop */
		return IPV4_SNAT_DROP;

	return IPV4_SNAT_ACCEPT;
}

static ALWAYS_INLINE unsigned int
ip_pre_fw_out_process(struct pl_packet *pkt)
{
	unsigned long bitmask =
		NPF_IF_SESSION | NPF_V6_TRACK_OUT;

	struct npf_if *nif = rcu_dereference(pkt->out_ifp->if_npf);
	if  (npf_if_active(nif, bitmask)) {
		struct rte_mbuf *m = pkt->mbuf;

		npf_decision_t result = npf_hook_out_track_snat(pkt->in_ifp, &m, nif,
								&pkt->npf_flags,
								htons(RTE_ETHER_TYPE_IPV6));

		if (unlikely(m != pkt->mbuf)) {
			pkt->mbuf = m;
			pkt->l3_hdr = dp_pktmbuf_mtol3(m, void *);
		}

		if (result == NPF_DECISION_BLOCK)
			return IPV6_PRE_FW_OUT_DROP;
		if (result == NPF_DECISION_UNMATCHED)
			return IPV6_PRE_FW_OUT_DOFW;

	} else if ((pkt->npf_flags & NPF_FLAG_FROM_ZONE) &&
		   !(pkt->npf_flags & NPF_FLAG_FROM_US))
		/* Zone to non-zone (no fw) -> drop */
		return IPV6_PRE_FW_OUT_DROP;

	return IPV6_PRE_FW_OUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_snat_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_snat_process(pkt);
}

ALWAYS_INLINE unsigned int
ipv6_pre_fw_out_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_pre_fw_out_process(pkt);
}

ALWAYS_INLINE unsigned int
ipv4_snat_spath_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_snat_process(pkt);
}

ALWAYS_INLINE unsigned int
ipv6_pre_fw_out_spath_process(struct pl_packet *pkt, void *context __unused)
{
	return ip_pre_fw_out_process(pkt);
}

/* Register Node */
PL_REGISTER_NODE(ipv4_snat_node) = {
	.name = "vyatta:ipv4-snat",
	.type = PL_PROC,
	.handler = ipv4_snat_process,
	.num_next = IPV4_SNAT_NUM,
	.next = {
		[IPV4_SNAT_DOFW]       = "ipv4-fw-out",
		[IPV4_SNAT_ACCEPT]       = "term-noop",
		[IPV4_SNAT_DROP]         = "term-drop",
	}
};

PL_REGISTER_NODE(ipv6_pre_fw_out_node) = {
	.name = "vyatta:ipv6-pre-fw-out",
	.type = PL_PROC,
	.handler = ipv6_pre_fw_out_process,
	.num_next = IPV6_PRE_FW_OUT_NUM,
	.next = {
		[IPV6_PRE_FW_OUT_DOFW]       = "ipv6-fw-out",
		[IPV6_PRE_FW_OUT_ACCEPT]       = "term-noop",
		[IPV6_PRE_FW_OUT_DROP]         = "ipv6-drop",
	}
};

PL_REGISTER_NODE(ipv4_snat_spath_node) = {
	.name = "vyatta:ipv4-snat-spath",
	.type = PL_PROC,
	.handler = ipv4_snat_spath_process,
	.num_next = IPV4_SNAT_SPATH_NUM,
	.next = {
		[IPV4_SNAT_SPATH_DOFW]  = "ipv4-fw-out",
		[IPV4_SNAT_SPATH_ACCEPT]  = "term-noop",
		[IPV4_SNAT_SPATH_DROP]    = "term-drop",
	}
};

PL_REGISTER_NODE(ipv6_pre_fw_out_spath_node) = {
	.name = "vyatta:ipv6-pre-fw-out-spath",
	.type = PL_PROC,
	.handler = ipv6_pre_fw_out_spath_process,
	.num_next = IPV6_PRE_FW_OUT_SPATH_NUM,
	.next = {
		[IPV6_PRE_FW_OUT_SPATH_DOFW]  = "ipv6-fw-out",
		[IPV6_PRE_FW_OUT_SPATH_ACCEPT]  = "term-noop",
		[IPV6_PRE_FW_OUT_SPATH_DROP]    = "term-drop",
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_snat_feat) = {
	.name = "vyatta:ipv4-snat",
	.node_name = "ipv4-snat",
	.feature_point = "ipv4-out",
	.id = PL_L3_V4_OUT_FUSED_FEAT_SNAT,
	.visit_after = "vyatta:ipv4-cgnat-out",
};

PL_REGISTER_FEATURE(ipv6_pre_fw_out_feat) = {
	.name = "vyatta:ipv6-pre-fw-out",
	.node_name = "ipv6-pre-fw-out",
	.feature_point = "ipv6-out",
	.id = PL_L3_V6_OUT_FUSED_FEAT_PRE_FW_OUT,
	.visit_after = "vyatta:ipv6-defrag-out",
};

PL_REGISTER_FEATURE(ipv4_snat_spath_feat) = {
	.name = "vyatta:ipv4-snat-spath",
	.node_name = "ipv4-snat-spath",
	.feature_point = "ipv4-out-spath",
	.id = PL_L3_V4_OUT_SPATH_FUSED_FEAT_SNAT,
};

PL_REGISTER_FEATURE(ipv6_pre_fw_out_spath_feat) = {
	.name = "vyatta:ipv6-pre-fw-out-spath",
	.node_name = "ipv6-pre-fw-out-spath",
	.feature_point = "ipv6-out-spath",
	.id = PL_L3_V6_OUT_SPATH_FUSED_FEAT_PRE_FW_OUT,
};
