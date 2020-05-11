/*
 * l3_dpi.c
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <stdbool.h>
#include <stdint.h>

#include "compat.h"
#include "compiler.h"
#include "if_var.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "npf/dpi/dpi_internal.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "util.h"

struct rte_mbuf;

enum {
	V4_PKT = true,
	V6_PKT = false
};

static ALWAYS_INLINE unsigned int
ip_dpi_process_common(struct pl_packet *pkt, bool v4, int dir)
{
	struct rte_mbuf *m = pkt->mbuf;

	npf_session_t *se = npf_session_find_cached(m);

	/* If already present, we have nothing to do; e.g. f/w did it */
	if (se && npf_session_get_dpi(se))
		goto done;

	/* Ensure we have a cached packet */
	uint16_t const ethertype =
		v4 ? htons(RTE_ETHER_TYPE_IPV4) : htons(RTE_ETHER_TYPE_IPV6);
	/*
	 * Avoid passing &pkt->npf_flags into npf_get_cache as doing
	 * so prevents an optimisation in fused mode whereby the
	 * compiler can avoid storing struct pl_packet on the stack,
	 * instead using registers.
	 */
	uint16_t npf_flags = pkt->npf_flags;
	npf_cache_t *npc = npf_get_cache(&npf_flags, m, ethertype);
	if (!npc)
		goto done;
	pkt->npf_flags = npf_flags;

	/* Ensure we have a TCP or UDP session */
	if (!se) {
		/* DPI alone does not attempt reassembly */
		if (npf_iscached(npc, NPC_IPFRAG))
			goto done;

		const uint8_t ipproto = npf_cache_ipproto(npc);
		if (ipproto != IPPROTO_TCP && ipproto != IPPROTO_UDP)
			goto done;

		struct ifnet *ifp = pkt->in_ifp;
		int error = 0;
		se = npf_session_find_or_create(npc, m, ifp, dir, &error);
		if (!se || error)
			goto done;
	}

	/* Attach the DPI flow info, do first packet inspection */
	(void)dpi_session_first_packet(se, npc, m, dir);

done:
	if (dir == PFIL_IN)
		return v4 ? IPV4_DPI_IN_ACCEPT : IPV6_DPI_IN_ACCEPT;

	return v4 ? IPV4_DPI_OUT_ACCEPT : IPV6_DPI_OUT_ACCEPT;
}


ALWAYS_INLINE unsigned int
ipv4_dpi_process_in(struct pl_packet *pkt)
{
	return ip_dpi_process_common(pkt, V4_PKT, PFIL_IN);
}

ALWAYS_INLINE unsigned int
ipv6_dpi_process_in(struct pl_packet *pkt)
{
	return ip_dpi_process_common(pkt, V6_PKT, PFIL_IN);
}

ALWAYS_INLINE unsigned int
ipv4_dpi_process_out(struct pl_packet *pkt)
{
	return ip_dpi_process_common(pkt, V4_PKT, PFIL_OUT);
}

ALWAYS_INLINE unsigned int
ipv6_dpi_process_out(struct pl_packet *pkt)
{
	return ip_dpi_process_common(pkt, V6_PKT, PFIL_OUT);
}


/* Register Node */
PL_REGISTER_NODE(ipv4_dpi_in_node) = {
	.name = "vyatta:ipv4-dpi-in",
	.type = PL_PROC,
	.handler = ipv4_dpi_process_in,
	.num_next = IPV4_DPI_IN_NUM,
	.next = {
		[IPV4_DPI_IN_ACCEPT] = "term-noop",
	}
};

PL_REGISTER_NODE(ipv6_dpi_in_node) = {
	.name = "vyatta:ipv6-dpi-in",
	.type = PL_PROC,
	.handler = ipv6_dpi_process_in,
	.num_next = IPV6_DPI_IN_NUM,
	.next = {
		[IPV6_DPI_IN_ACCEPT] = "term-noop",
	}
};

PL_REGISTER_NODE(ipv4_dpi_out_node) = {
	.name = "vyatta:ipv4-dpi-out",
	.type = PL_PROC,
	.handler = ipv4_dpi_process_out,
	.num_next = IPV4_DPI_OUT_NUM,
	.next = {
		[IPV4_DPI_OUT_ACCEPT] = "term-noop",
	}
};

PL_REGISTER_NODE(ipv6_dpi_out_node) = {
	.name = "vyatta:ipv6-dpi-out",
	.type = PL_PROC,
	.handler = ipv6_dpi_process_out,
	.num_next = IPV6_DPI_OUT_NUM,
	.next = {
		[IPV6_DPI_OUT_ACCEPT] = "term-noop",
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_dpi_in_feat) = {
	.name = "vyatta:ipv4-dpi-in",
	.node_name = "ipv4-dpi-in",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_DPI,
};

PL_REGISTER_FEATURE(ipv6_dpi_in_feat) = {
	.name = "vyatta:ipv6-dpi-in",
	.node_name = "ipv6-dpi-in",
	.feature_point = "ipv6-validate",
	.id = PL_L3_V6_IN_FUSED_FEAT_DPI,
};

PL_REGISTER_FEATURE(ipv4_dpi_out_feat) = {
	.name = "vyatta:ipv4-dpi-out",
	.node_name = "ipv4-dpi-out",
	.feature_point = "ipv4-out",
	.id = PL_L3_V4_OUT_FUSED_FEAT_DPI,
};

PL_REGISTER_FEATURE(ipv6_dpi_out_feat) = {
	.name = "vyatta:ipv6-dpi-out",
	.node_name = "ipv6-dpi-out",
	.feature_point = "ipv6-out",
	.id = PL_L3_V6_OUT_FUSED_FEAT_DPI,
};
