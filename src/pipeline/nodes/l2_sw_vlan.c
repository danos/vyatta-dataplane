/*
 * l2_sw_vlan.c
 *
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "ether.h"
#include "if_var.h"
#include "pl_common.h"
#include "pl_fused.h"

ALWAYS_INLINE unsigned int
sw_vlan_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;
	struct ifnet *ifp = pkt->in_ifp;

	if (ethhdr(m)->ether_type == htons(ifp->tpid) && ifp->tpid != 0 &&
	    !(m->ol_flags & PKT_RX_VLAN)) {
		m->ol_flags |= PKT_RX_VLAN;
		m->vlan_tci = vid_decap(m, ifp->tpid);
	}

	return SW_VLAN_IN_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(sw_vlan_in_node) = {
	.name = "vyatta:sw-vlan-in",
	.type = PL_PROC,
	.handler = sw_vlan_in_process,
	.num_next = SW_VLAN_IN_NUM,
	.next = {
		[SW_VLAN_IN_ACCEPT]  = "term-noop",
	}
};

PL_REGISTER_FEATURE(sw_vlan_in_feat) = {
	.name = "vyatta:sw-vlan-in",
	.node_name = "sw-vlan-in",
	.feature_point = "ether-lookup",
	.id = PL_ETHER_LOOKUP_FUSED_FEAT_SW_VLAN,
	.visit_after = "hw-hdr-in",
};
