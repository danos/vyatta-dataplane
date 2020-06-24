/*
 * l3_nat64.c
 *
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <stdbool.h>

#include "compiler.h"
#include "if_var.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "urcu.h"

#include "npf/config/npf_config.h"
#include "npf/npf.h"
#include "npf/npf_cmd.h"
#include "npf/npf_if.h"
#include "npf/npf_rc.h"
#include "npf_shim.h"
#include "npf/npf_nat64.h"

/*
 * For NAT 6-to-4 the packet flow sequence is:
 *
 *   request:   v6(in) -> v4(in) -> v4(out)
 *   response:  v4(in) -> v6(in) -> v6(out)
 *
 * Two session are created for the first packet in a data flow - An IPv6
 * session at v6-in and an IPv4 session at v4-out.
 *
 * The input code will add PKT_MDATA_INVAR_NAT64 metadata to the first packet.
 * The output code will detect that metadata, create a session, and link it to
 * the input session.
 *
 * For subsequent times through the output session, the only work done by the
 * output code is to increment stats.
 *
 * NAT 4-to-6 for a new packet flow is similar.
 *
 * npf_nat64_4to6_in or npf_nat64_6to4_in are called at input when either of
 * the following are true:
 *
 *  1. A NAT64 rule exists on the interface, or
 *  2. A NAT64 session is found on ingress
 *
 * npf_nat64_4to6_out or npf_nat64_6to4_out are called at output when the
 * packet npf_flags say that the packet has been switched from the other
 * address family path.
 */
enum {
	V4_PKT = true,
	V6_PKT = false
};

/*
 * First look for a session cached in the packet, else lookup session table.
 */
static npf_session_t *
nat64_session_find(npf_cache_t *npc, struct rte_mbuf *m, struct ifnet *ifp,
		   int dir, int *error)
{
	npf_session_t *se;

	se = npf_session_find_cached(m);
	if (se)
		return se;

	se = npf_session_inspect(npc, m, ifp, dir, error, NULL);

	if (*error || !se)
		return NULL;

	/* Attach the session to the packet */
	struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);
	mdata->md_session = se;
	pktmbuf_mdata_set(m, PKT_MDATA_SESSION);

	return se;
}

/*
 * NAT64 Common Input Process
 */
static ALWAYS_INLINE unsigned int
nat64_in_process_common(struct pl_packet *pkt, struct npf_if *nif, bool v4,
			uint16_t eth_type)
{
	struct ifnet *ifp = pkt->in_ifp;
	struct npf_config *nif_config;
	nat64_decision_t decision = NAT64_DECISION_UNMATCHED;
	struct rte_mbuf *m;
	uint16_t npf_flags;
	npf_session_t *se;
	npf_cache_t *npc;
	int rc = NPF_RC_UNMATCHED;
	int rv = v4 ? IPV4_NAT46_IN_ACCEPT : IPV6_NAT64_IN_ACCEPT;

	npf_flags = pkt->npf_flags;
	m = pkt->mbuf;
	nif_config = npf_if_conf(nif);

	npc = npf_get_cache(&npf_flags, m, eth_type, &rc);
	if (unlikely(!npc))
		goto end;

	se = nat64_session_find(npc, m, ifp, PFIL_IN, &rc);

	if (unlikely(rc < 0))
		goto end;

	if (!npf_active(nif_config, v4 ? NPF_NAT46 : NPF_NAT64) &&
	    !npf_session_is_nat64(se))
		/*
		 * We don't want to increment the rc counter when there is no
		 * nat64 config or session on an interface.
		 */
		return rv;

	/*
	 * Either we found a nat64 session, or there is nat64 config on the
	 * interface.
	 */
	/* Hook */
	if (v4)
		decision = npf_nat64_4to6_in(nif_config, &se, ifp, npc,
					     &m, &npf_flags, &rc);
	else
		decision = npf_nat64_6to4_in(nif_config, &se, ifp, npc,
					     &m, &npf_flags, &rc);

	if (se) {
		if (decision != NAT64_DECISION_DROP) {
			rc = npf_session_activate(se, ifp, npc, m);
			if (rc == NPF_RC_OK) {
				/* Attach the session to the packet */
				struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);
				mdata->md_session = se;
				pktmbuf_mdata_set(m, PKT_MDATA_SESSION);

				/* Save session stats. */
				if (decision == NAT64_DECISION_PASS)
					npf_save_stats(se, PFIL_IN,
						       rte_pktmbuf_pkt_len(m));
			} else {
				if (rc != -NPF_RC_ENOSTR)
					decision = NAT64_DECISION_DROP;
			}
		} else if (!npf_session_is_active(se)) {
			npf_session_destroy(se);
		} else if (rc < 0) {
			pktmbuf_mdata_clear(m, PKT_MDATA_SESSION);
			npf_session_expire(se);
		}
	}

	if (unlikely(m != pkt->mbuf)) {
		pkt->mbuf = m;
		pkt->l3_hdr = dp_pktmbuf_mtol3(m, void *);
	}

end:
	switch (decision) {
	case NAT64_DECISION_UNMATCHED:
		rv = v4 ? IPV4_NAT46_IN_ACCEPT : IPV6_NAT64_IN_ACCEPT;
		rc = NPF_RC_UNMATCHED;
		break;
	case NAT64_DECISION_TO_V4:
		pkt->npf_flags = npf_flags;
		rv = IPV6_NAT64_IN_TO_V4;
		rc = NPF_RC_NAT64_6T4;
		break;
	case NAT64_DECISION_TO_V6:
		pkt->npf_flags = npf_flags;
		rv = IPV4_NAT46_IN_TO_V6;
		rc = NPF_RC_NAT64_4T6;
		break;
	case NAT64_DECISION_PASS:
		pkt->npf_flags = npf_flags;
		rv = v4 ? IPV4_NAT46_IN_ACCEPT : IPV6_NAT64_IN_ACCEPT;
		rc = NPF_RC_PASS;
		break;
	case NAT64_DECISION_DROP:
		rv = v4 ? IPV4_NAT46_IN_DROP : IPV6_NAT64_IN_DROP;
		break;
	};

	/* Increment return code counter */
	npf_rc_inc_nat64(ifp, NPF_RC_IN, rc);

	return rv;
}


/*
 * NAT64 Common Output Process
 *
 * This function will *only* be called for packets that have switched paths.
 */
static ALWAYS_INLINE unsigned int
nat64_out_process_common(struct pl_packet *pkt, bool v4, uint16_t eth_type)
{
	struct ifnet *ifp = pkt->out_ifp;
	nat64_decision_t decision = NAT64_DECISION_UNMATCHED;
	struct rte_mbuf *m;
	uint16_t npf_flags;
	npf_session_t *se;
	npf_cache_t *npc;
	int rc = NPF_RC_UNMATCHED;
	int rv = v4 ? IPV4_NAT64_OUT_ACCEPT : IPV6_NAT46_OUT_ACCEPT;

	npf_flags = pkt->npf_flags;
	m = pkt->mbuf;

	npc = npf_get_cache(&npf_flags, m, eth_type, &rc);
	if (unlikely(!npc))
		goto end;

	se = nat64_session_find(npc, m, ifp, PFIL_OUT, &rc);

	if (unlikely(rc < 0))
		goto end;

	/* Hook */
	if (v4)
		decision = npf_nat64_6to4_out(&se, ifp, npc, &m, &npf_flags,
					      &rc);
	else
		decision = npf_nat64_4to6_out(&se, ifp, npc, &m, &npf_flags,
					      &rc);

	if (se) {
		if (decision != NAT64_DECISION_DROP) {
			rc = npf_session_activate(se, ifp, npc, m);
			if (rc == NPF_RC_OK) {
				/* Attach the session to the packet */
				struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);
				mdata->md_session = se;
				pktmbuf_mdata_set(m, PKT_MDATA_SESSION);

				/* Save session stats. */
				if (decision == NAT64_DECISION_PASS)
					npf_save_stats(se, PFIL_OUT,
						       rte_pktmbuf_pkt_len(m));
			} else {
				if (rc != -NPF_RC_ENOSTR)
					decision = NAT64_DECISION_DROP;
			}
		} else if (!npf_session_is_active(se)) {
			npf_session_destroy(se);
		} else if (rc < 0) {
			pktmbuf_mdata_clear(m, PKT_MDATA_SESSION);
			npf_session_expire(se);
		}
	}

	if (unlikely(m != pkt->mbuf)) {
		pkt->mbuf = m;
		pkt->l3_hdr = dp_pktmbuf_mtol3(m, void *);
	}

end:
	switch (decision) {
	case NAT64_DECISION_UNMATCHED:
		rv = v4 ? IPV4_NAT64_OUT_ACCEPT : IPV6_NAT46_OUT_ACCEPT;
		rc = NPF_RC_UNMATCHED;
		break;
	case NAT64_DECISION_TO_V4: /* Will not occur in output. For compiler */
	case NAT64_DECISION_TO_V6: /* Will not occur in output. For compiler */
	case NAT64_DECISION_PASS:
		rv = v4 ? IPV4_NAT64_OUT_ACCEPT : IPV6_NAT46_OUT_ACCEPT;
		rc = NPF_RC_PASS;
		break;
	case NAT64_DECISION_DROP:
		rv = v4 ? IPV4_NAT64_OUT_DROP : IPV6_NAT46_OUT_DROP;
		break;
	};

	/* Increment return code counter */
	npf_rc_inc_nat64(ifp, NPF_RC_OUT, rc);

	return rv;
}

/*
 * NAT64 In.  v6 packet
 */
ALWAYS_INLINE unsigned int ipv6_nat64_in_process(struct pl_packet *pkt,
						 void *context __unused)
{
	struct npf_if *nif = rcu_dereference(pkt->in_ifp->if_npf);
	unsigned int rv;

	/*
	 * Input process expects either a session or active nat64 config.
	 */
	if (!npf_if_active(nif, NPF_IF_SESSION | NPF_NAT64))
		return IPV6_NAT64_IN_ACCEPT;

	/*
	 * Packet is IPv6
	 */
	rv = nat64_in_process_common(pkt, nif,
				     V6_PKT, htons(RTE_ETHER_TYPE_IPV6));

	return rv;
}

/*
 * NAT64 Out.  v4 packet
 */
ALWAYS_INLINE unsigned int ipv4_nat64_out_process(struct pl_packet *pkt,
						  void *context __unused)
{
	unsigned int rv;

	/*
	 * Output process only expects packet to have switched paths from
	 * IPv6.  An output session may or may not exist yet.
	 */
	if ((pkt->npf_flags & NPF_FLAG_FROM_IPV6) == 0)
		return IPV4_NAT64_OUT_ACCEPT;

	/*
	 * Packet is IPv4
	 */
	rv = nat64_out_process_common(pkt, V4_PKT, htons(RTE_ETHER_TYPE_IPV4));

	return rv;
}

/*
 * NAT46 In.  v4 packet
 */
ALWAYS_INLINE unsigned int ipv4_nat46_in_process(struct pl_packet *pkt,
						 void *context __unused)
{
	struct npf_if *nif = rcu_dereference(pkt->in_ifp->if_npf);
	unsigned int rv;

	/*
	 * Input process expects either a session or active nat46 config.
	 */
	if (!npf_if_active(nif, NPF_IF_SESSION | NPF_NAT46))
		return IPV4_NAT46_IN_ACCEPT;

	/*
	 * Packet is IPv4
	 */
	rv = nat64_in_process_common(pkt, nif,
				     V4_PKT, htons(RTE_ETHER_TYPE_IPV4));

	return rv;
}

/*
 * NAT46 In.  v6 packet
 */
ALWAYS_INLINE unsigned int ipv6_nat46_out_process(struct pl_packet *pkt,
						  void *context __unused)
{
	unsigned int rv;

	/*
	 * Output process only expects packet to have switched paths from
	 * IPv4.  An output session may or may not exist yet.
	 */
	if ((pkt->npf_flags & NPF_FLAG_FROM_IPV4) == 0)
		return IPV6_NAT46_OUT_ACCEPT;

	/*
	 * Packet is IPv6
	 */
	rv = nat64_out_process_common(pkt, V6_PKT, htons(RTE_ETHER_TYPE_IPV6));
	return rv;
}

/* Register Node */
PL_REGISTER_NODE(ipv6_nat64_in_node) = {
	.name = "vyatta:ipv6-nat64-in",
	.type = PL_PROC,
	.handler = ipv6_nat64_in_process,
	.num_next = IPV6_NAT64_IN_NUM,
	.next = {
		[IPV6_NAT64_IN_ACCEPT] = "term-noop",
		[IPV6_NAT64_IN_TO_V4]  = "term-v6-to-v4",
		[IPV6_NAT64_IN_DROP]   = "term-drop",
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv4_nat64_out_node) = {
	.name = "vyatta:ipv4-nat64-out",
	.type = PL_PROC,
	.handler = ipv4_nat64_out_process,
	.num_next = IPV4_NAT64_OUT_NUM,
	.next = {
		[IPV4_NAT64_OUT_ACCEPT] = "term-noop",
		[IPV4_NAT64_OUT_DROP]   = "term-drop",
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv4_nat46_in_node) = {
	.name = "vyatta:ipv4-nat46-in",
	.type = PL_PROC,
	.handler = ipv4_nat46_in_process,
	.num_next = IPV4_NAT46_IN_NUM,
	.next = {
		[IPV4_NAT46_IN_ACCEPT] = "term-noop",
		[IPV4_NAT46_IN_TO_V6]  = "term-v4-to-v6",
		[IPV4_NAT46_IN_DROP]   = "term-drop",
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv6_nat46_out_node) = {
	.name = "vyatta:ipv6-nat46-out",
	.type = PL_PROC,
	.handler = ipv6_nat46_out_process,
	.num_next = IPV6_NAT46_OUT_NUM,
	.next = {
		[IPV6_NAT46_OUT_ACCEPT] = "term-noop",
		[IPV6_NAT46_OUT_DROP]   = "term-drop",
	}
};

/* Register Features */
PL_REGISTER_FEATURE(ipv6_nat64_in_feat) = {
	.name = "vyatta:ipv6-nat64-in",
	.node_name = "ipv6-nat64-in",
	.feature_point = "ipv6-validate",
	.id = PL_L3_V6_IN_FUSED_FEAT_NAT64,
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_nat64_out_feat) = {
	.name = "vyatta:ipv4-nat64-out",
	.node_name = "ipv4-nat64-out",
	.feature_point = "ipv4-out",
	.id = PL_L3_V4_OUT_FUSED_FEAT_NAT64,
	.visit_after = "vyatta:ipv4-fw-out",
};

/* Register Features */
PL_REGISTER_FEATURE(ipv4_nat46_in_feat) = {
	.name = "vyatta:ipv4-nat46-in",
	.node_name = "ipv4-nat46-in",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_NAT46,
};

/* Register Features */
PL_REGISTER_FEATURE(ipv6_nat46_out_feat) = {
	.name = "vyatta:ipv6-nat46-out",
	.node_name = "ipv6-nat46-out",
	.feature_point = "ipv6-out",
	.id = PL_L3_V6_OUT_FUSED_FEAT_NAT46,
	.visit_after = "vyatta:ipv6-fw-out",
};
