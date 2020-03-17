/*
 * l2_pppoe_node.c
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "pl_common.h"
#include "pl_node.h"
#include "pl_fused_gen.h"

#include "pppoe.h"

ALWAYS_INLINE unsigned int
pppoe_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;
	struct pppoe_packet *pppoe_hdr =
		rte_pktmbuf_mtod(m, struct pppoe_packet *);

	/* If PPPoE session packet, get the inner proto and forward */
	if (htons(pppoe_hdr->eth_hdr.ether_type) == ETH_P_PPP_SES) {
		u_short inner_proto;

		if (rte_pktmbuf_data_len(m) < sizeof(*pppoe_hdr)) {
			if_incr_error(pkt->in_ifp);
			return PPP_FORWARD_DROP;
		}

		inner_proto = ntohs(pppoe_hdr->protocol);

		/* Pass control protocols to pppd */
		if (inner_proto == PPP_LCP ||
			inner_proto == PPP_IPCP ||
			 inner_proto == PPP_IPV6CP ||
			  inner_proto == PPP_PAP)
			return PPP_FORWARD_LOCAL;

		/* Set input interface to corresponding PPP device */
		struct ifnet *ppp = ppp_lookup_ses(pkt->in_ifp,
				ntohs(pppoe_hdr->session));

		if (!ppp)
			return PPP_FORWARD_LOCAL;

		pkt->in_ifp = ppp;

		/* Trim ONLY PPP overhead, keep length for ether_hdr */
		struct ether_hdr *eh =
			(struct ether_hdr *)rte_pktmbuf_adj(
			m, (sizeof(struct pppoe_packet) -
				sizeof(struct ether_hdr)));
		m->l2_len = sizeof(struct ether_hdr);
		memcpy(&eh->d_addr, &pppoe_hdr->eth_hdr.d_addr,
				sizeof(struct rte_ether_addr));
		memcpy(&eh->s_addr, &pppoe_hdr->eth_hdr.s_addr,
				sizeof(struct rte_ether_addr));

		switch (inner_proto) {
		case PPP_IP:
			eh->ether_type = htons(ETHER_TYPE_IPv4);
			return PPP_FORWARD_V4_ACCEPT;
		case PPP_IPV6:
			eh->ether_type = htons(ETHER_TYPE_IPv6);
			return PPP_FORWARD_V6_ACCEPT;
		default:
			/* Unsupported inner protocol */
			if_incr_unknown(pkt->in_ifp);
			return PPP_FORWARD_DROP;
		}
	}

	/* Pass DISCOVERY packet to pppd */
	return PPP_FORWARD_LOCAL;
}

/* Register Node */
PL_REGISTER_NODE(pppoe_in_node) = {
	.name = "vyatta:pppoe-in",
	.type = PL_PROC,
	.handler = pppoe_in_process,
	.num_next = PPP_FORWARD_NUM,
	.next = {
		[PPP_FORWARD_V4_ACCEPT] = "ipv4-validate",
		[PPP_FORWARD_V6_ACCEPT] = "ipv6-validate",
		[PPP_FORWARD_FINISH] = "term-finish",
		[PPP_FORWARD_DROP] = "term-drop",
		[PPP_FORWARD_LOCAL] = "l2-local",
	}
};
