/*
 * l3_v4_rpf.c
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "compat.h"
#include "compiler.h"
#include "if_var.h"
#include "nh_common.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "route.h"
#include "route_flags.h"
#include "snmp_mib.h"

struct rte_mbuf;

/*
 * Validate source address matches to prevent IP spoofing per RFC3704.
 */
static __attribute__((noinline)) bool
verify_path(in_addr_t src, struct ifnet *ifp, uint32_t tbl,
	    struct rte_mbuf *m)
{
	struct next_hop *nxt;

	/* Always allow unspecified such that e.g. DHCP requests are received */
	if (!src)
		return true;

	nxt = dp_rt_lookup(src, tbl, m);
	if (nxt == NULL)
		return false;

	/* check if route is flagged as blackhole/reject route */
	if (nxt->flags & (RTF_BLACKHOLE|RTF_REJECT))
		return false;

	/* if ifp is in strict mode, check for that incoming
	 * interface matches the route.
	 */
	if (ifp->ip_rpf_strict && dp_nh_get_ifp(nxt) != ifp)
		return false;

	/* found valid route */
	return true;
}

ALWAYS_INLINE unsigned int
ipv4_rpf_process(struct pl_packet *pkt, void *context __unused)
{
	struct iphdr *ip = pkt->l3_hdr;
	struct ifnet *ifp = pkt->in_ifp;

	/* Ingress unicast Reverse Path Filter check */
	if (unlikely(!verify_path(ip->saddr, ifp, RT_TABLE_MAIN, pkt->mbuf))) {
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INADDRERRORS);
		return IPV4_RPF_DROP;
	}

	return IPV4_RPF_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_rpf_node) = {
	.name = "vyatta:ipv4-rpf",
	.type = PL_PROC,
	.handler = ipv4_rpf_process,
	.num_next = IPV4_RPF_NUM,
	.next = {
		[IPV4_RPF_ACCEPT]  = "term-noop",
		[IPV4_RPF_DROP]    = "term-drop",
	}
};

PL_REGISTER_FEATURE(ipv4_rpf_feat) = {
	.name = "vyatta:ipv4-rpf",
	.node_name = "ipv4-rpf",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_RPF,
};
