/*
 * l3_v4_l4.c
 *
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdbool.h>

#include "compiler.h"
#include "ip_funcs.h"
#include "pl_common.h"
#include "pl_fused.h"

struct pl_node;

ALWAYS_INLINE unsigned int
ipv4_l4_process_common(struct pl_packet *pkt, enum pl_mode mode __unused)
{
	int rc;
	struct rte_mbuf *m = pkt->mbuf;
	struct ifnet *ifp = pkt->in_ifp;

	rc = l4_input(&m, ifp);
	if (rc == 0)
		return IPV4_L4_CONSUME;
	else if (rc > 0) {
		pkt->mbuf = m;
		return IPV4_L4_ACCEPT;
	} else
		return IPV4_L4_DROP;
}

ALWAYS_INLINE unsigned int
ipv4_l4_process(struct pl_packet *pkt)
{
	return ipv4_l4_process_common(pkt, PL_MODE_REGULAR);
}

static int
ipv4_l4_feat_change(struct pl_node *node __unused,
		    struct pl_feature_registration *feat __unused,
		    enum pl_node_feat_action action __unused)
{
	/*
	 * TODO - Will be added as hash table where only the relevant feature
	 * will be called based on the registered proto
	 */
	return 0;
}

ALWAYS_INLINE bool
ipv4_l4_feat_iterate(struct pl_node *node __unused, bool first __unused,
		     unsigned int *feature_id __unused, void **context __unused)
{
	/*
	 * TODO - Will be added as hash table where only the relevant feature
	 * will be called based on the registered proto
	 */
	return false;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_l4_node) = {
	.name = "vyatta:ipv4-l4",
	.type = PL_PROC,
	.handler = ipv4_l4_process,
	.feat_change = ipv4_l4_feat_change,
	.feat_iterate = ipv4_l4_feat_iterate,
	.num_next = IPV4_L4_NUM,
	.next = {
		[IPV4_L4_ACCEPT]  = "ipv4-local",
		[IPV4_L4_DROP]    = "term-drop",
		[IPV4_L4_CONSUME] = "term-finish",
	}
};
