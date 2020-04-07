/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "vrf_internal.h"
#include "if/gre.h"
#include "ip_funcs.h"

#include "../pl_node.h"
#include "../pl_fused.h"

ALWAYS_INLINE unsigned int
ipv4_gre_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;
	struct iphdr *ip = iphdr(m);
	int rc;

	rc = ip_gre_tunnel_in(&m, ip);
	if (likely(rc == 0))
		return IPV4_GRE_CONSUME;
	else if (rc < 0)
		return IPV4_GRE_DROP;

	pkt->mbuf = m;
	return IPV4_GRE_ACCEPT;
}

/* GRE decap feature */
PL_REGISTER_NODE(ipv4_gre_in_node) = {
	.name = "vyatta:ipv4-gre-in",
	.type = PL_PROC,
	.handler = ipv4_gre_in_process,
	.num_next = IPV4_GRE_NUM,
	.next = {
		[IPV4_GRE_ACCEPT]   = "term-noop",
		[IPV4_GRE_DROP]     = "term-drop",
		[IPV4_GRE_CONSUME]  = "term-finish",
	}
};

PL_REGISTER_FEATURE(ipv4_gre_in_feat) = {
	.name = "vyatta:ipv4-gre-in",
	.node_name = "ipv4-gre-in",
	.feature_point = "ipv4-l4",
	.always_on = true,
	.id = PL_L3_V4_L4_FUSED_FEAT_GRE_IN,
	.feat_type = IPPROTO_GRE,
};
