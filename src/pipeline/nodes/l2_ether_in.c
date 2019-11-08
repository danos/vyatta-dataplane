/*
 * l2_ether_in.c
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdio.h>

#include "compiler.h"
#include "pktmbuf.h"
#include "pl_common.h"
#include "pl_fused.h"

ALWAYS_INLINE unsigned int
ether_in_process(struct pl_packet *pkt)
{
	struct rte_mbuf *mbuf = pkt->mbuf;

	mbuf->tx_offload = 0;
	pktmbuf_l2_len(mbuf) = ETHER_HDR_LEN;

	return ETHER_IN_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(ether_in_node) = {
	.name = "vyatta:ether-in",
	.type = PL_PROC,
	.init = NULL,
	.handler = ether_in_process,
	.disable = false,
	.num_next = ETHER_IN_NUM,
	.next = {
		[ETHER_IN_ACCEPT] = "ether-lookup",
	}
};
