/*
 * l2_capture.c
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "compiler.h"
#include "capture.h"
#include "pl_common.h"
#include "pl_fused.h"

ALWAYS_INLINE unsigned int
capture_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;

	if (capture_if_use_common_cap_points(pkt->in_ifp))
		capture_burst(pkt->in_ifp, &m, 1);

	return CAPTURE_IN_ACCEPT;
}

ALWAYS_INLINE unsigned int
capture_out_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;

	if (capture_if_use_common_cap_points(pkt->out_ifp))
		capture_burst(pkt->out_ifp, &m, 1);

	return CAPTURE_IN_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(capture_in_node) = {
	.name = "vyatta:capture-in",
	.type = PL_PROC,
	.handler = capture_in_process,
	.num_next = CAPTURE_IN_NUM,
	.next = {
		[CAPTURE_IN_ACCEPT]  = "term-noop",
	}
};

PL_REGISTER_FEATURE(capture_ether_in_feat) = {
	.name = "vyatta:capture-ether-in",
	.node_name = "capture-in",
	.feature_point = "ether-lookup",
	.id = PL_ETHER_LOOKUP_FUSED_FEAT_CAPTURE,
	.visit_after = "sw-vlan-in",
};

/* Register Node */
PL_REGISTER_NODE(capture_out_node) = {
	.name = "vyatta:capture-out",
	.type = PL_PROC,
	.handler = capture_out_process,
	.num_next = CAPTURE_OUT_NUM,
	.next = {
		[CAPTURE_OUT_ACCEPT]  = "term-noop",
	}
};

PL_REGISTER_FEATURE(capture_l2_output_feat) = {
	.name = "vyatta:capture-l2-output",
	.node_name = "capture-out",
	.feature_point = "l2-output",
	.id = PL_L2_OUTPUT_FUSED_FEAT_CAPTURE_OUT,
	.visit_after = "portmonitor-out",
};
