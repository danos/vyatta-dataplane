/*
 * l3_fw_in.c
 *
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <stdbool.h>

#include "compiler.h"
#include "if_var.h"
#include "npf/config/npf_config.h"
#include "npf/npf.h"
#include "npf/npf_cmd.h"
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
ip_fw_in_process_common(struct pl_packet *pkt, bool v4)
{
	struct ifnet *ifp = pkt->in_ifp;
	unsigned long bitmask;

	if (v4)
		bitmask = NPF_IF_SESSION | NPF_V4_TRACK_IN;
	else
		bitmask = NPF_IF_SESSION | NPF_V6_TRACK_IN;

	struct npf_if *nif = rcu_dereference(ifp->if_npf);

	/* what is the best way to define app specific data? */
	if (npf_if_active(nif, bitmask)) {
		struct rte_mbuf *m = pkt->mbuf;

		npf_result_t result =
			npf_hook_track(ifp, &m, nif, PFIL_IN,
				       pkt->npf_flags,
				       v4 ? htons(ETHER_TYPE_IPv4) :
				       htons(ETHER_TYPE_IPv6));

		if (unlikely(m != pkt->mbuf)) {
			pkt->mbuf = m;
			pkt->l3_hdr = pktmbuf_mtol3(m, void *);
		}

		if (unlikely(result.decision != NPF_DECISION_PASS))
			return v4 ? IPV4_FW_IN_DROP : IPV6_FW_IN_DROP;

		pkt->npf_flags = result.flags;

		if (unlikely(result.action == NPF_ACTION_TO_V6))
			return IPV4_FW_IN_TO_V6;
		else if (unlikely(result.action == NPF_ACTION_TO_V4))
			return IPV6_FW_IN_TO_V4;
		else if (unlikely(result.action == NPF_ACTION_TO_LOCAL))
			return IPV4_FW_IN_TO_LOCAL;
	}
	return v4 ? IPV4_FW_IN_ACCEPT : IPV6_FW_IN_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_fw_in_process(struct pl_packet *pkt)
{
	return ip_fw_in_process_common(pkt, V4_PKT);
}

ALWAYS_INLINE unsigned int
ipv6_fw_in_process(struct pl_packet *pkt)
{
	return ip_fw_in_process_common(pkt, V6_PKT);
}

/* Register Node */
PL_REGISTER_NODE(ipv4_fw_in_node) = {
	.name = "vyatta:ipv4-fw-in",
	.type = PL_PROC,
	.handler = ipv4_fw_in_process,
	.num_next = IPV4_FW_NUM,
	.next = {
		[IPV4_FW_IN_ACCEPT] = "term-noop",
		[IPV4_FW_IN_TO_V6]  = "term-v4-to-v6",
		[IPV4_FW_IN_TO_LOCAL] = "ipv4-local",
		[IPV4_FW_IN_DROP]   = "term-drop",
	}
};

PL_REGISTER_NODE(ipv6_fw_in_node) = {
	.name = "vyatta:ipv6-fw-in",
	.type = PL_PROC,
	.handler = ipv6_fw_in_process,
	.num_next = IPV6_FW_NUM,
	.next = {
		[IPV6_FW_IN_ACCEPT] = "term-noop",
		[IPV6_FW_IN_TO_V4]  = "term-v6-to-v4",
		[IPV6_FW_IN_DROP]   = "ipv6-drop"
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_fw_in_feat) = {
	.name = "vyatta:ipv4-fw-in",
	.node_name = "ipv4-fw-in",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_FW,
	.visit_after = "vyatta:ipv4-defrag-in",
};

PL_REGISTER_FEATURE(ipv6_fw_in_feat) = {
	.name = "vyatta:ipv6-fw-in",
	.node_name = "ipv6-fw-in",
	.feature_point = "ipv6-validate",
	.id = PL_L3_V6_IN_FUSED_FEAT_FW,
	.visit_after = "vyatta:ipv6-defrag-in",
};


/* Register Commands */

/*
 *  For now duplicate of existing show FW command, but
 *  with prepended "pipeline" to dispatch through
 *  pipeline framework.
 */
static int
cmd_show_fw(struct pl_command *cmd)
{
	/*
	 * note fp is being used here to support older
	 * op mode output. However json is preferred and
	 * should be used for all new commands.
	 */
	cmd_show_rulesets(cmd->fp, cmd->argc, cmd->argv);
	return 0;
}

PL_REGISTER_OPCMD(fw_show) = {
	.cmd = "npf-op show",
	.handler = cmd_show_fw,
};
