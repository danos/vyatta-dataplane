/*
 * l2_ether_in.c
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/if_ether.h>

#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "arp.h"
#include "compat.h"
#include "compiler.h"
#include "ether.h"
#include "if_var.h"
#include "main.h"
#include "mpls/mpls_forward.h"
#include "pl_common.h"
#include "pl_fused.h"

ALWAYS_INLINE unsigned int
ether_forward_process(struct pl_packet *pkt)
{
	uint16_t et = ethhdr(pkt->mbuf)->ether_type;

	if (likely(et == htons(ETHER_TYPE_IPv4)))
		return ETHER_FORWARD_V4_ACCEPT;
	if (likely(et == htons(ETHER_TYPE_IPv6)))
		return ETHER_FORWARD_V6_ACCEPT;
	if (et == htons(ETHER_TYPE_ARP))
		return ETHER_FORWARD_ARP_ACCEPT;
	else if (et == htons(ETH_P_MPLS_UC))
		mpls_labeled_input(pkt->in_ifp, pkt->mbuf);
	else if (et == htons(ETH_P_PPP_DISC) || et == htons(ETH_P_PPP_SES))
		return ETHER_FORWARD_PPPOE_ACCEPT;
	else if (unlikely(et != htons(ETH_P_LLDP))) {
		/* Assume 802.2 is used for IEEE control protocols */
		if (unlikely(ntohs(et) > ETH_P_802_3_MIN)) {
			/* Drop unknown protocols */
			if_incr_unknown(pkt->in_ifp);
			return ETHER_FORWARD_DROP;
		} else
			return ETHER_FORWARD_LOCAL;
	} else {
		/* always LLDP packets through to kernel*/
		return ETHER_FORWARD_LOCAL;
	}

	return ETHER_FORWARD_FINISH;
}

/* Register Node */
PL_REGISTER_NODE(ether_forward_node) = {
	.name = "vyatta:ether-forward",
	.type = PL_PROC,
	.init = NULL,
	.handler = ether_forward_process,
	.disable = false,
	.num_next = ETHER_FORWARD_NUM,
	.next = {
		[ETHER_FORWARD_V4_ACCEPT] = "ipv4-validate",
		[ETHER_FORWARD_V6_ACCEPT] = "ipv6-validate",
		[ETHER_FORWARD_PPPOE_ACCEPT] = "pppoe-in",
		[ETHER_FORWARD_ARP_ACCEPT] = "arp-in",
		[ETHER_FORWARD_FINISH] = "term-finish",
		[ETHER_FORWARD_LOCAL] = "l2-local",
		[ETHER_FORWARD_DROP] = "term-drop",
	}
};
