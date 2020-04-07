/*
 * l2_portmonitor.c
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <rte_branch_prediction.h>

#include "compiler.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "portmonitor/portmonitor.h"

ALWAYS_INLINE unsigned int
portmonitor_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;

	if (portmonitor_dest_output(pkt->in_ifp, m))
		return PORTMONITOR_IN_FINISH;

	portmonitor_src_vif_rx_output(pkt->in_ifp, &m);

	if (unlikely(m != pkt->mbuf)) {
		pkt->mbuf = m;
		pkt->l3_hdr = dp_pktmbuf_mtol3(m, void *);
	}

	return PORTMONITOR_IN_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(portmonitor_in_node) = {
	.name = "vyatta:portmonitor-in",
	.type = PL_PROC,
	.handler = portmonitor_in_process,
	.num_next = PORTMONITOR_IN_NUM,
	.next = {
		[PORTMONITOR_IN_ACCEPT]  = "term-noop",
		[PORTMONITOR_IN_FINISH]  = "term-finish",
	}
};

PL_REGISTER_FEATURE(portmonitor_in_feat) = {
	.name = "vyatta:portmonitor-in",
	.node_name = "portmonitor-in",
	.feature_point = "ether-lookup",
	.id = PL_ETHER_LOOKUP_FUSED_FEAT_PORTMONITOR,
	.visit_after = "capture-ether-in",
};
