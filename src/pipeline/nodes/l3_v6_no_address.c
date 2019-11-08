/*
 * IPv6 no address feature
 *
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>

#include "compiler.h"
#include "if_var.h"
#include "pktmbuf.h"

#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "vrf.h"

ALWAYS_INLINE unsigned int
ipv6_in_no_address_process(struct pl_packet *pkt __unused)
{
	/*
	 * Special case of DHCP client, RFC2131 semantics
	 *
	 * The TCP/IP software SHOULD accept and forward to the IP layer any
	 * IP packets delivered to the client's hardware address before the
	 * IP address is configured.
	 */
	return IPV6_IN_NO_ADDRESS_LOCAL;
}

/* Register Node */
PL_REGISTER_NODE(ipv6_in_no_address_node) = {
	.name = "vyatta:ipv6-in-no-address",
	.type = PL_PROC,
	.handler = ipv6_in_no_address_process,
	.num_next = IPV6_IN_NO_ADDRESS_NUM,
	.next = {
		[IPV6_IN_NO_ADDRESS_LOCAL] = "ipv6-local",
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv6_in_no_address_feat) = {
	.name = "vyatta:ipv6-in-no-address",
	.node_name = "ipv6-in-no-address",
	.feature_point = "ipv6-validate",
	.visit_after = "ipv6-pbr",
	.id = PL_L3_V6_IN_FUSED_FEAT_NO_ADDRESS,
};
