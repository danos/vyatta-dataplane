/*
 * IPv6 no address feature
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdbool.h>

#include "compiler.h"
#include "ether.h"
#include "if_var.h"
#include "pktmbuf_internal.h"

#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "vrf_internal.h"

static struct rte_ether_addr micro_bfd_dst = {
	{ 0x01, 0x0, 0x5e, 0x90, 0x0, 0x01 } };

ALWAYS_INLINE unsigned int
ipv6_in_no_address_process(struct pl_packet *pkt __unused,
			   void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;
	const struct rte_ether_hdr *eth = ethhdr(m);

	/*
	 * If this is a micro BFD packet, we need to handle it as
	 * normal, even if we don't have an IPv6 address. It's likely
	 * that this is a LAG member and will never have a valid IPv6
	 * address.
	 */
	if (unlikely(rte_ether_addr_equal(&eth->d_addr, &micro_bfd_dst)))
		return IPV6_IN_SPECIAL_PACKET;

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
		[IPV6_IN_SPECIAL_PACKET] = "ipv6-l4",
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
