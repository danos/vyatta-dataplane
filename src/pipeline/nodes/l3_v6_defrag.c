/*
 * l3_v6_defrag.c
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdint.h>

#include "compiler.h"
#include "if_var.h"
#include "netinet6/ip6_funcs.h"
#include "npf/config/npf_config.h"
#include "npf/fragment/ipv6_rsmbl.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_if.h"
#include "npf_shim.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "urcu.h"

ALWAYS_INLINE unsigned int
ipv6_defrag_in_process(struct pl_packet *pkt, void *context __unused)
{
	pkt->npf_flags = NPF_FLAG_CACHE_EMPTY;

	/*
	 * If there is a zone use zone configuration for zone and NAT
	 * Otherwise use firewall configuration for firewall and NAT
	 */
	struct npf_if *nif = rcu_dereference(pkt->in_ifp->if_npf);

	/* Reassemble packets if required */
	if (npf_if_active(nif, NPF_V6_TRACK_IN | NPF_PBR)) {
		/*
		 * Avoid passing &pkt->npf_flags into
		 * npf_ipv6_is_fragment/ipv6_handle_fragment as doing
		 * so prevents an optimisation in fused mode whereby
		 * the compiler can avoid storing struct pl_packet on
		 * the stack, instead using registers.
		 */
		uint16_t npf_flags = pkt->npf_flags;

		if (npf_ipv6_is_fragment(pkt->mbuf,
					 &npf_flags)) {
			pkt->mbuf = ipv6_handle_fragment(pkt->mbuf,
							 &npf_flags);
			if (!pkt->mbuf) {
				pkt->npf_flags = npf_flags;
				/* Consumed by reassembly */
				return IPV6_DEFRAG_IN_FINISH;
			}
			pkt->l3_hdr = ip6hdr(pkt->mbuf);
		}
		pkt->npf_flags = npf_flags;
	}

	return IPV6_DEFRAG_IN_ACCEPT;
}

static ALWAYS_INLINE unsigned int
ipv6_defrag_out_internal(struct pl_packet *pkt)
{
	struct npf_if *nif = rcu_dereference(pkt->out_ifp->if_npf);

	/*
	 * Reassemble packets if required.  This is optimised away for
	 * originated packets (e.g. post tunnel encap),  it is retained
	 * for the MPLS -> IP path, and normal IP forwarding.
	 *
	 * We have to keep it in the latter case such that the stateful
	 * firewall on the output interface can operate.
	 */
	if (npf_if_active(nif, NPF_V6_TRACK_OUT)) {
		/*
		 * Avoid passing &pkt->npf_flags into
		 * npf_ipv6_is_fragment/ipv6_handle_fragment as doing
		 * so prevents an optimisation in fused mode whereby
		 * the compiler can avoid storing struct pl_packet on
		 * the stack, instead using registers.
		 */
		uint16_t npf_flags = pkt->npf_flags;

		if (unlikely(npf_ipv6_is_fragment(pkt->mbuf,
						  &npf_flags))) {

			pkt->mbuf = ipv6_handle_fragment(pkt->mbuf,
							 &npf_flags);
			if (!pkt->mbuf) {
				/* Consumed by reassembly */
				pkt->npf_flags = npf_flags;
				return IPV6_DEFRAG_OUT_FINISH;
			}
			pkt->l3_hdr = ip6hdr(pkt->mbuf);
		}
		pkt->npf_flags = npf_flags;
	}

	return IPV6_DEFRAG_OUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv6_defrag_out_process(struct pl_packet *pkt, void *context __unused)
{
	return ipv6_defrag_out_internal(pkt);
}

ALWAYS_INLINE unsigned int
ipv6_defrag_out_spath_process(struct pl_packet *pkt, void *context __unused)
{
	return ipv6_defrag_out_internal(pkt);
}

/* Register Node */
PL_REGISTER_NODE(ipv6_defrag_in_node) = {
	.name = "vyatta:ipv6-defrag-in",
	.type = PL_PROC,
	.handler = ipv6_defrag_in_process,
	.num_next = IPV6_DEFRAG_IN_NUM,
	.next = {
		[IPV6_DEFRAG_IN_ACCEPT] = "term-noop",
		[IPV6_DEFRAG_IN_FINISH] = "term-finish"
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv6_defrag_out_node) = {
	.name = "vyatta:ipv6-defrag-out",
	.type = PL_PROC,
	.handler = ipv6_defrag_out_process,
	.num_next = IPV6_DEFRAG_OUT_NUM,
	.next = {
		[IPV6_DEFRAG_OUT_ACCEPT]      = "term-noop",
		[IPV6_DEFRAG_OUT_FINISH]      = "term-finish"
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv6_defrag_out_spath_node) = {
	.name = "vyatta:ipv6-defrag-out-spath",
	.type = PL_PROC,
	.handler = ipv6_defrag_out_spath_process,
	.num_next = IPV6_DEFRAG_OUT_SPATH_NUM,
	.next = {
		[IPV6_DEFRAG_OUT_SPATH_ACCEPT] = "ipv6-fw-out",
		[IPV6_DEFRAG_OUT_SPATH_FINISH] = "term-finish"
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv6_defrag_in_feat) = {
	.name = "vyatta:ipv6-defrag-in",
	.node_name = "ipv6-defrag-in",
	.feature_point = "ipv6-validate",
	.id = PL_L3_V6_IN_FUSED_FEAT_DEFRAG,
};

PL_REGISTER_FEATURE(ipv6_defrag_out_feat) = {
	.name = "vyatta:ipv6-defrag-out",
	.node_name = "ipv6-defrag-out",
	.feature_point = "ipv6-out",
	.id = PL_L3_V6_OUT_FUSED_FEAT_DEFRAG,
};
