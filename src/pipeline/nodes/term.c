/*
 * term.c
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
#include <netinet/ip6.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "compiler.h"
#include "if_var.h"
#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "npf/npf.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "route.h"
#include "route_flags.h"
#include "route_v6.h"
#include "snmp_mib.h"

ALWAYS_INLINE unsigned int
term_v4_to_v6_process(struct pl_packet *pkt, void *context __unused)
{
	pkt->npf_flags |= NPF_FLAG_CACHE_EMPTY;
	pktmbuf_prepare_encap_out(pkt->mbuf);
	ip6_lookup_and_forward(pkt->mbuf, pkt->in_ifp, false, pkt->npf_flags);
	return 0;
}

/* Register Node */
PL_REGISTER_NODE(term_v4_to_v6_node) = {
	.name = "vyatta:term-v4-to-v6",
	.type = PL_OUTPUT,
	.handler = term_v4_to_v6_process,
	.num_next = 0,
};

ALWAYS_INLINE unsigned int
term_v6_to_v4_process(struct pl_packet *pkt, void *context __unused)
{
	pkt->npf_flags |= NPF_FLAG_CACHE_EMPTY;
	pktmbuf_prepare_encap_out(pkt->mbuf);
	ip_lookup_and_forward(pkt->mbuf, pkt->in_ifp, false,
			      pkt->npf_flags);
	return 0;
}

/* Register Node */
PL_REGISTER_NODE(term_v6_to_v4_node) = {
	.name = "vyatta:term-v6-to-v4",
	.type = PL_OUTPUT,
	.handler = term_v6_to_v4_process,
	.num_next = 0,
};

ALWAYS_INLINE unsigned int
ipv4_local_process(struct pl_packet *pkt, void *context __unused)
{
	ip_local_deliver(pkt->in_ifp, pkt->mbuf);
	return 0;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_local_node) = {
	.name = "vyatta:ipv4-local",
	.type = PL_OUTPUT,
	.handler = ipv4_local_process,
	.num_next = 0,
};

ALWAYS_INLINE unsigned int
ipv6_local_process(struct pl_packet *pkt, void *context __unused)
{
	ip6_local_deliver(pkt->in_ifp, pkt->mbuf);
	return 0;
}

/* Register Node */
PL_REGISTER_NODE(ipv6_local_node) = {
	.name = "vyatta:ipv6-local",
	.type = PL_OUTPUT,
	.handler = ipv6_local_process,
	.num_next = 0,
};

ALWAYS_INLINE unsigned int
term_finish_process(struct pl_packet *p __unused, void *context __unused)
{
	return 0;
}

/* Register Node */
PL_REGISTER_NODE(term_finish_node) = {
	.name = "vyatta:term-finish",
	.type = PL_OUTPUT,
	.handler = term_finish_process,
	.num_next = 0,
};

/*
 * No-op node
 *
 * Does nothing and doesn't indicate that the packet was consume. This
 * is used for feature processing to indicate that processing can
 * proceed with the next feature or the next node of the feature-point
 * node if no further features enabled on that node remain.
 *
 * Behaviour is undefined if this node is encountered outside of
 * feature processing.
 */
ALWAYS_INLINE unsigned int
term_noop_process(struct pl_packet *p __unused, void *context __unused)
{
	return 0;
}

/* Register Node */
PL_REGISTER_NODE(term_noop_node) = {
	.name = "vyatta:term-noop",
	.type = PL_CONTINUE,
	.handler = term_noop_process,
	.num_next = 0,
};

ALWAYS_INLINE unsigned int
l2_out_process(struct pl_packet *pkt, void *context __unused)
{
	if_output_internal(pkt);
	return 0;
}

/*
 * L2 Out Node
 *
 * Send an L2-encapsulated packet out of an interface.
 *
 * Requires pkt->out_ifp, pkt->in_ifp and pkt->l2_proto to be set
 * before being invoked.
 */
PL_REGISTER_NODE(l2_out_node) = {
	.name = "vyatta:l2-out",
	.type = PL_OUTPUT,
	.handler = l2_out_process,
	.num_next = 0,
};
