/*
 * l2_cross_connect_node.c
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/if_ether.h>

#include "compiler.h"
#include "cross_connect.h"
#include "if_var.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "l2tp/l2tpeth.h"
#include "urcu.h"

ALWAYS_INLINE unsigned int
cross_connect_process(struct pl_packet *pkt, void *context __unused)
{
	struct ifnet *ifp = pkt->in_ifp;
	struct rte_mbuf *m = pkt->mbuf;
	struct ifnet *out_ifp = rcu_dereference(ifp->if_xconnect);

	if (unlikely(out_ifp == NULL)) {
		if_incr_dropped(ifp);
		return CROSS_CONNECT_DROP;
	}

	if (unlikely(!(out_ifp->if_flags & IFF_UP))) {
		if_incr_full_proto(out_ifp, 1);
		return CROSS_CONNECT_DROP;
	}

	if (out_ifp->if_type == IFT_L2TPETH) {
		if (ifp->if_parent)
			pktmbuf_convert_rx_to_tx_vlan(m);
		l2tp_output(out_ifp, m);
	} else {
		pkt->l2_proto = ETH_P_TEB;
		pkt->out_ifp = out_ifp;
		return CROSS_CONNECT_FORWARD;
	}

	return CROSS_CONNECT_FINISH;
}

/* Register Node */
PL_REGISTER_NODE(cross_connect_node) = {
	.name = "vyatta:cross-connect",
	.type = PL_PROC,
	.handler = cross_connect_process,
	.num_next = CROSS_CONNECT_NUM,
	.next = {
		[CROSS_CONNECT_FORWARD]  = "l2-out",
		[CROSS_CONNECT_FINISH]  = "term-finish",
		[CROSS_CONNECT_DROP]  = "term-drop",
	}
};

PL_REGISTER_FEATURE(cross_connect_ether_feat) = {
	.name = "vyatta:cross-connect-ether",
	.node_name = "cross-connect",
	.feature_point = "ether-lookup",
	.id = PL_ETHER_LOOKUP_FUSED_FEAT_CROSS_CONNECT,
	.visit_after = "bridge-in",
};
