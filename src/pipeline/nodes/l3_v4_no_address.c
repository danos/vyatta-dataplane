/*
 * IPv4 no address feature
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>

#include "compiler.h"
#include "if_var.h"
#include "pktmbuf_internal.h"

#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "vrf_internal.h"

ALWAYS_INLINE unsigned int
ipv4_in_no_address_process(struct pl_packet *pkt __unused,
			   void *context __unused)
{
	/*
	 * Special case of DHCP client, RFC2131 semantics
	 *
	 * The TCP/IP software SHOULD accept and forward to the IP layer any
	 * IP packets delivered to the client's hardware address before the
	 * IP address is configured.
	 *
	 * Subjecting the packet to L4 processing rather than just
	 * punting is for backwards compatibility.
	 */
	return IPV4_IN_NO_ADDRESS_L4;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_in_no_address_node) = {
	.name = "vyatta:ipv4-in-no-address",
	.type = PL_PROC,
	.handler = ipv4_in_no_address_process,
	.num_next = IPV4_IN_NO_ADDRESS_NUM,
	.next = {
		[IPV4_IN_NO_ADDRESS_L4] = "ipv4-l4",
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_in_no_address_feat) = {
	.name = "vyatta:ipv4-in-no-address",
	.node_name = "ipv4-in-no-address",
	.feature_point = "ipv4-validate",
	.visit_after = "ipv4-pbr",
	.id = PL_L3_V4_IN_FUSED_FEAT_NO_ADDRESS,
};
