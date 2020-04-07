/*
 * l2_bridge_in.c
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stddef.h>

#include "compiler.h"
#include "if/bridge/bridge.h"
#include "if/bridge/bridge_port.h"
#include "if_var.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "urcu.h"

static inline bool
bridge_has_vlan_filter(struct ifnet *master)
{
	struct bridge_softc *sc = master->if_softc;

	return sc->scbr_vlan_filter;
}

ALWAYS_INLINE unsigned int
bridge_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct ifnet *ifp = pkt->in_ifp;
	struct rte_mbuf *m = pkt->mbuf;
	struct bridge_port *brport;

	/*
	 * Is device is member of bridge?  A vlan sub-interface and its parent
	 * may both be members of a bridge group, so ensure vlan packets are
	 * received on vlan interfaces.
	 */
	brport = rcu_dereference(ifp->if_brport);
	if (brport != NULL &&
	    (((m->ol_flags & PKT_RX_VLAN) != 0) ==
	     (ifp->if_type == IFT_L2VLAN) ||
	     bridge_has_vlan_filter(bridge_port_get_bridge(brport)))) {
		bridge_input(brport, m);
		return BRIDGE_IN_FINISH;
	}

	return BRIDGE_IN_CONTINUE;
}

/* Register Node */
PL_REGISTER_NODE(bridge_in_node) = {
	.name = "vyatta:bridge-in",
	.type = PL_PROC,
	.handler = bridge_in_process,
	.num_next = BRIDGE_IN_NUM,
	.next = {
		[BRIDGE_IN_CONTINUE] = "term-noop",
		[BRIDGE_IN_FINISH]   = "term-finish",
	}
};

PL_REGISTER_FEATURE(bridge_in_feat) = {
	.name = "vyatta:bridge-in",
	.node_name = "bridge-in",
	.feature_point = "ether-lookup",
	.id = PL_ETHER_LOOKUP_FUSED_FEAT_BRIDGE,
	.visit_after = "vlan-modify-in",
};
