/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "compiler.h"
#include "vrf_internal.h"
#include "if/gre.h"
#include "ip_funcs.h"
#include "l2tp/l2tpeth.h"

#include "../pl_node.h"
#include "../pl_fused.h"

ALWAYS_INLINE unsigned int
ipv4_l2tpv3_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;
	struct iphdr *ip = iphdr(m);
	int rc;

	rc = l2tp_ipv4_recv_encap(m, ip);
	if (likely(rc == 0))
		return IPV4_L2TPV3_CONSUME;
	if (rc < 0)
		return IPV4_L2TPV3_DROP;

	return IPV4_L2TPV3_ACCEPT;
}

/* GRE decap feature */
PL_REGISTER_NODE(ipv4_l2tpv3_in_node) = {
	.name = "vyatta:ipv4-l2tpv3-in",
	.type = PL_PROC,
	.handler = ipv4_l2tpv3_in_process,
	.num_next = IPV4_L2TPV3_NUM,
	.next = {
		[IPV4_L2TPV3_ACCEPT]   = "term-noop",
		[IPV4_L2TPV3_DROP]     = "term-drop",
		[IPV4_L2TPV3_CONSUME]  = "term-finish",
	}
};

PL_REGISTER_FEATURE(ipv4_l2tpv3_in_feat) = {
	.name = "vyatta:ipv4-l2tpv3-in",
	.node_name = "ipv4-l2tpv3-in",
	.feature_point = "ipv4-l4",
	.always_on = true,
	.id = PL_L3_V4_L4_FUSED_FEAT_L2TPV3_IN,
	.feat_type = IPPROTO_L2TPV3,
};
