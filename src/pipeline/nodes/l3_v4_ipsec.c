/*
 * l3_v4_ipsec.c
 *
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <stdio.h>

#include "compiler.h"
#include "crypto/crypto.h"
#include "crypto/crypto_forward.h"
#include "ip_funcs.h"
#include "nh.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"

ALWAYS_INLINE unsigned int
ipv4_ipsec_out_process(struct pl_packet *pkt, void *context __unused)
{
	struct ifnet *ifp = pkt->in_ifp;
	union next_hop_v4_or_v6_ptr nh = {NULL};

	/* Returns true if packet was consumed by IPsec */
	struct rte_mbuf *m = pkt->mbuf;
	if (unlikely(crypto_policy_check_outbound(ifp, &m, pkt->tblid,
						  htons(ETHER_TYPE_IPv4), &nh)))
		return IPV4_IPSEC_OUT_CONSUME;

	/*
	 * If the crypto code returned a next hop, then the policy
	 * matched but we need to run features attached to the interface
	 * the next hop is pointing at. The packet will then be put back
	 * in the crypto path.
	 */
	if (unlikely(nh.v4 != NULL))
		pkt->nxt.v4 = nh.v4;

	if (unlikely(m != pkt->mbuf)) {
		pkt->mbuf = m;
		pkt->l3_hdr = iphdr(m);
	}
	return IPV4_IPSEC_OUT_ACCEPT;
}

inline __attribute__((always_inline)) unsigned int
ipv4_ipsec_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;
	struct iphdr *ip = iphdr(m);
	struct ifnet *ifp = pkt->in_ifp;
	int rc, spi;

	spi = crypto_retrieve_spi((unsigned char *)ip +
				  dp_pktmbuf_l3_len(m));
	rc = crypto_enqueue_inbound_v4(m, ip, ifp, spi);
	if (likely(rc == 0))
		return IPV4_IPSEC_IN_CONSUME;
	else if (rc < 0)
		return IPV4_IPSEC_IN_DROP;
	else
		return IPV4_IPSEC_IN_ACCEPT;

}

/* Crypto encryption feature */
PL_REGISTER_NODE(ipv4_ipsec_out_node) = {
	.name = "vyatta:ipv4-ipsec-out",
	.type = PL_PROC,
	.handler = ipv4_ipsec_out_process,
	.num_next = IPV4_IPSEC_OUT_NUM,
	.next = {
		[IPV4_IPSEC_OUT_ACCEPT]   = "term-noop",
		[IPV4_IPSEC_OUT_CONSUME]   = "term-finish",
	}
};

PL_REGISTER_FEATURE(ipv4_ipsec_out_feat) = {
	.name = "vyatta:ipv4-ipsec-out",
	.node_name = "ipv4-ipsec-out",
	.feature_point = "ipv4-route-lookup",
	.id = PL_L3_V4_ROUTE_LOOKUP_FUSED_FEAT_IPSEC,
};

/* Crypto encryption feature */
PL_REGISTER_NODE(ipv4_ipsec_in_node) = {
	.name = "vyatta:ipv4-ipsec-in",
	.type = PL_PROC,
	.handler = ipv4_ipsec_in_process,
	.num_next = IPV4_IPSEC_IN_NUM,
	.next = {
		[IPV4_IPSEC_IN_ACCEPT]   = "term-noop",
		[IPV4_IPSEC_IN_CONSUME]  = "term-finish",
		[IPV4_IPSEC_IN_DROP]     = "term-drop",
	}
};

PL_REGISTER_FEATURE(ipv4_ipsec_in_feat) = {
	.name = "vyatta:ipv4-ipsec-in",
	.node_name = "ipv4-ipsec-in",
	.feature_point = "ipv4-l4",
	.always_on = true,
	.id = PL_L3_V4_L4_FUSED_FEAT_IPSEC_IN,
	.feat_type = IPPROTO_ESP,
};
