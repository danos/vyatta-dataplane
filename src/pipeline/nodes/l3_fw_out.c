/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
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
#include "pktmbuf.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "urcu.h"

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

	/* Output NPF Firewall and NAT */
	if  (npf_if_active(nif, bitmask) ||
	     (nif &&
	      (pkt->npf_flags & (NPF_FLAG_FROM_IPV6 | NPF_FLAG_FROM_IPV4)))) {
		npf_result_t result;
		struct rte_mbuf *m = pkt->mbuf;

		result = npf_hook_track(pkt->in_ifp, &m, nif, PFIL_OUT,
					pkt->npf_flags,
					v4 ? htons(ETHER_TYPE_IPv4) :
					htons(ETHER_TYPE_IPv6));
		if (unlikely(m != pkt->mbuf)) {
			pkt->mbuf = m;
			pkt->l3_hdr = pktmbuf_mtol3(m, void *);
		}
		if (unlikely(result.decision != NPF_DECISION_PASS))
			return v4 ? IPV4_FW_OUT_DROP : IPV6_FW_OUT_DROP;
		/* Discard result.flags as no change can happen */
	}

	return v4 ? IPV4_FW_OUT_ACCEPT : IPV6_FW_OUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_fw_out_process(struct pl_packet *pkt)
{
	return ip_fw_out_process_common(pkt, V4_PKT);
}

ALWAYS_INLINE unsigned int
ipv6_fw_out_process(struct pl_packet *pkt)
{
	return ip_fw_out_process_common(pkt, V6_PKT);
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
