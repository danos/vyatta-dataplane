/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_branch_prediction.h>

#include "compiler.h"
#include "pktmbuf.h"
#include "pl_node.h"
#include "pl_fused.h"
#include "fal.h"
#include "portmonitor/portmonitor_hw.h"

ALWAYS_INLINE unsigned int
portmonitor_hw_in_process(struct pl_packet *pkt)
{
	struct ifnet *ifp;
	struct rte_mbuf *m = pkt->mbuf;
	void *data = NULL;
	union fal_pkt_feature_info *feat_info;

	ifp = pkt->in_ifp;
	if (!ifp)
		goto drop;

	pl_get_node_data(pkt, fal_feat_storageid(), &data);

	feat_info = data;

	if (!feat_info)
		goto drop;

	if (portmonitor_src_hw_mirror_process(ifp, m, &feat_info->fal_pm))
		return PORTMONITOR_HW_IN_CONSUME;

drop:
	if_incr_dropped(pkt->in_ifp);
	return PORTMONITOR_HW_IN_DROP;
}

/* Register Node */
PL_REGISTER_NODE(portmonitor_hw_in_node) = {
	.name = "vyatta:portmonitor-hw-in",
	.type = PL_PROC,
	.handler = portmonitor_hw_in_process,
	.num_next = PORTMONITOR_HW_IN_NUM,
	.next = {
		[PORTMONITOR_HW_IN_CONSUME]  = "term-finish",
		[PORTMONITOR_HW_IN_DROP]  = "term-drop",
	}
};
