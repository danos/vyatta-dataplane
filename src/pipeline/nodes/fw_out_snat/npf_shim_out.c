/*
 * Copyright (c) 2021, AT&T Intellectual Property.	 All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "if_var.h"
#include "npf/npf.h"
#include "npf/alg/alg_npf.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_cache.h"
#include "npf/npf_rc.h"
#include "npf/npf_if.h"
#include "npf/npf_nat.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_session.h"
#include "npf/zones/npf_zone_public.h"
#include "npf/rproc/npf_rproc.h"
#include "npf_shim.h"
#include "npf/rproc/npf_ext_log.h"
#include "ip_icmp.h"

static ALWAYS_INLINE npf_decision_t
process_result(struct ifnet *ifp, uint16_t type, int rc, npf_decision_t decision)
{
	/* Increment return code counter */
	npf_rc_inc(ifp, type, NPF_RC_OUT, rc, decision);
	return decision;
}


static ALWAYS_INLINE npf_decision_t
process_done(struct ifnet *ifp, struct rte_mbuf *m, npf_session_t *se, npf_cache_t *npc,
	     int rc, npf_decision_t decision)
{
	if (se) {
		if (decision != NPF_DECISION_BLOCK) {
			/* N.B. se may be consumed */
			rc = npf_session_activate(se, ifp, npc, m);
			if (rc == 0) {
				/* Save session stats. */
				npf_save_stats(se, PFIL_OUT,
					       rte_pktmbuf_pkt_len(m));
			} else if (rc != -NPF_RC_ENOSTR)
				decision = NPF_DECISION_BLOCK;
		} else if (!npf_session_is_active(se)) {
			npf_session_destroy(se);
		} else if (rc < 0) {
			pktmbuf_mdata_clear(m, PKT_MDATA_SESSION);
			npf_session_expire(se);
		}
	}
	enum npf_rc_type type = (npc->npc_info & NPC_IP4) ? NPF_RCT_FW4 : NPF_RCT_FW6;
	return process_result(ifp, type, rc, decision);
}

static ALWAYS_INLINE npf_decision_t
process_stats(struct ifnet *ifp, struct rte_mbuf *m, npf_session_t *se, npf_rule_t *rl,
	      npf_cache_t *npc, int rc, npf_decision_t decision)
{
	/* Stats and rule procedures. */
	if (rl) {
		if (!se || !npf_session_is_pass(se, NULL) ||
		    npf_session_forward_dir(se, PFIL_OUT))
			npf_add_pkt(rl, rte_pktmbuf_pkt_len(m));
		npf_shim_rproc(npc, &m, PFIL_OUT, rl, se, &decision);
	}
	return process_done(ifp, m, se, npc, rc, decision);
}


static ALWAYS_INLINE npf_decision_t
process_pass(struct ifnet *ifp, struct rte_mbuf *m, npf_session_t *se,
	     npf_rule_t *rl, npf_cache_t *npc, int rc)
{
	/* Log any firewall matched rule now */
	if (unlikely(npf_rule_has_rproc_logger(rl)))
		npf_log_pkt(npc, m, rl, PFIL_OUT);

	/* ALGs may need/want to inspect non-NATd pkts. */
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);
	if (unlikely(sa))
		npf_alg_inspect(se, npc, m, PFIL_OUT, sa);

	return process_stats(ifp, m, se, rl, npc, rc, NPF_DECISION_PASS);
}


npf_decision_t
npf_hook_out_track_fw(struct pl_packet *pkt)
{
	struct npf_if *nif = rcu_dereference(pkt->out_ifp->if_npf);
	struct ifnet *in_ifp = pkt->in_ifp;
	struct rte_mbuf *m = pkt->mbuf;
	uint16_t npf_flags = pkt->npf_flags;
	const npf_ruleset_t *rlset;
	struct npf_config *fw_config = npf_if_conf(nif);
	struct ifnet *ifp = nif->nif_ifp;
	npf_decision_t decision = NPF_DECISION_UNMATCHED;
	npf_rule_t *rl = NULL;
	npf_session_t *se = NULL;

	/* for now always prepped due to snat call before */
	npf_cache_t *npc = &RTE_PER_LCORE(npf_cache);

	/*
	 * Try to find (and validate) an existing session, or failing that
	 * try to create a 'parent' tuple based session.
	 */
	if (pktmbuf_mdata_exists(m, PKT_MDATA_SESSION)) {
		struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);
		se = mdata->md_session;
	}

	/*
	 * Determine the ruleset type and any reverse ruleset,
	 * allowing for possible stateful ZBF pass session.
	 */
	bool reverse_stateful = false;
	if (fw_config)
		reverse_stateful = fw_config->nc_active_flags & NPF_FW_STATE_IN;

	enum npf_ruleset_type rlset_type = NPF_RS_FW_OUT;

	if (unlikely((npf_flags & NPF_FLAG_FROM_ZONE) ||
		     npf_nif_zone(nif))) {
		if (npf_zone_hook(in_ifp, nif, npf_flags, &fw_config,
				  &decision, &rlset_type,
				  &reverse_stateful))
			return process_done(ifp, m, se, npc, NPF_RC_UNMATCHED, decision);
	}

	/* Inspect FW ruleset */
	rlset = npf_get_ruleset(fw_config, rlset_type);

	decision = npf_apply_firewall(rlset, se, npc, ifp, m, PFIL_OUT, &rl,
				      npf_flags, reverse_stateful);
	if (decision == NPF_DECISION_UNMATCHED)
		return process_done(ifp, m, se, npc, NPF_RC_UNMATCHED, NPF_DECISION_UNMATCHED);
	if (decision == NPF_DECISION_BLOCK)
		return process_stats(ifp, m, se, rl, npc, NPF_RC_UNMATCHED, NPF_DECISION_BLOCK);

	/*
	 * Establish a "pass" session, if required. Just proceed, if session
	 * creation fails (e.g. due to unsupported protocol).
	 */
	if (rl && npf_rule_stateful(rl)) {
		if (!se) {
			int rc = NPF_RC_UNMATCHED;
			se = npf_session_establish(npc, m, ifp, PFIL_OUT, &rc);
			if (unlikely(rc < 0))
				return process_stats(ifp, m, se, rl, npc, rc, NPF_DECISION_BLOCK);
		}
		npf_session_add_fw_rule(se, rl);
	}
	return process_pass(ifp, m, se, rl, npc, NPF_RC_UNMATCHED);
}



/*
 * Processor entry point given packet, interface, direction
 * and configuration set.
 *
 * Packets passed in here must not be fragments.
 */
npf_decision_t
npf_hook_out_track_v6_fw(struct pl_packet *pkt)
{
	uint16_t *npf_flags = &pkt->npf_flags;
	struct rte_mbuf *m = pkt->mbuf;
	struct npf_if *nif = rcu_dereference(pkt->out_ifp->if_npf);
	npf_rule_t *rl = NULL;
	bool internal_hairpin = false;
	struct ifnet *ifp = nif->nif_ifp;
	int rc = NPF_RC_UNMATCHED;
	struct ifnet *in_ifp = pkt->in_ifp;
	const npf_ruleset_t *rlset;
	struct npf_config *fw_config = npf_if_conf(nif);
	npf_decision_t decision = NPF_DECISION_UNMATCHED;

	/*
	 * Parse the packet, note this also clears any cached tag.
	 *
	 * If Firewall or NAT are enabled, we will never see a fragment,
	 * however if we get here due to DPI, we may.  That is fine as
	 * the subsequent logic should simply pass those fragments.
	 */
	npf_cache_t *npc = npf_get_cache(npf_flags, m, htons(RTE_ETHER_TYPE_IPV6), &rc);
	if (unlikely(!npc))
		return process_result(ifp, NPF_RCT_FW6, rc, NPF_DECISION_BLOCK);

	/*
	 * Try to find (and validate) an existing session, or failing that
	 * try to create a 'parent' tuple based session.
	 */
	npf_session_t *se = npf_session_inspect_or_create(npc, m, ifp, PFIL_OUT,
							  npf_flags, &rc, &internal_hairpin);
	if (unlikely(rc < 0))
		return process_result(ifp, NPF_RCT_FW6, rc, NPF_DECISION_BLOCK);

	/*
	 * If "passing" session found - skip the ruleset inspection.
	 * Similarly, session backwards NAT packets, and secondary
	 * sessions (i.e. ALG created) skip the firewall.
	 */
	if (se && (npf_session_is_pass(se, &rl) ||
		   npf_session_is_child(se))) {
		if (unlikely(internal_hairpin))
			rl = NULL;	/* avoid running fw stats and rprocs */
		return process_pass(ifp, m, se, rl, npc, rc);
	}

	/*
	 * Determine the ruleset type and any reverse ruleset,
	 * allowing for possible stateful ZBF pass session.
	 */
	bool reverse_stateful = false;
	if (fw_config)
		reverse_stateful = fw_config->nc_active_flags & NPF_FW_STATE_IN;

	enum npf_ruleset_type rlset_type = NPF_RS_FW_OUT;

	if (unlikely((*npf_flags & NPF_FLAG_FROM_ZONE) ||
		     npf_nif_zone(nif))) {
		if (npf_zone_hook(in_ifp, nif, *npf_flags, &fw_config,
				  &decision, &rlset_type,
				  &reverse_stateful))
			return process_done(ifp, m, se, npc, NPF_RC_UNMATCHED, decision);
	}

	/* Inspect FW ruleset */
	rlset = npf_get_ruleset(fw_config, rlset_type);

	decision = npf_apply_firewall(rlset, se, npc, ifp, m, PFIL_OUT, &rl,
				      *npf_flags, reverse_stateful);
	if (decision == NPF_DECISION_UNMATCHED)
		return process_done(ifp, m, se, npc, NPF_RC_UNMATCHED, NPF_DECISION_UNMATCHED);
	if (decision == NPF_DECISION_BLOCK)
		return process_stats(ifp, m, se, rl, npc, NPF_RC_UNMATCHED, NPF_DECISION_BLOCK);

	/*
	 * Establish a "pass" session, if required. Just proceed, if session
	 * creation fails (e.g. due to unsupported protocol).
	 */
	if (rl && npf_rule_stateful(rl)) {
		if (!se) {
			int rc = NPF_RC_UNMATCHED;
			se = npf_session_establish(npc, m, ifp, PFIL_OUT, &rc);
			if (unlikely(rc < 0))
				return process_stats(ifp, m, se, rl, npc, rc, NPF_DECISION_BLOCK);
		}
		npf_session_add_fw_rule(se, rl);
	}
	return process_pass(ifp, m, se, rl, npc, NPF_RC_UNMATCHED);
}

/*
 * Processor entry point given packet, interface, direction
 * and configuration set.
 *
 * Packets passed in here must not be fragments.
 */
npf_decision_t
npf_hook_out_track_snat(struct ifnet *in_ifp, struct rte_mbuf **m,
			struct npf_if *nif, uint16_t *npf_flags)
{
	struct npf_config *nif_config = npf_if_conf(nif);
	npf_rule_t *rl = NULL;
	bool internal_hairpin = false;
	struct ifnet *ifp = nif->nif_ifp;
	int rc = NPF_RC_UNMATCHED;

	/*
	 * Parse the packet, note this also clears any cached tag.
	 *
	 * If Firewall or NAT are enabled, we will never see a fragment,
	 * however if we get here due to DPI, we may.  That is fine as
	 * the subsequent logic should simply pass those fragments.
	 */
	npf_cache_t *npc = npf_get_cache(npf_flags, *m, htons(RTE_ETHER_TYPE_IPV4), &rc);
	if (unlikely(!npc))
		return process_result(ifp, NPF_RCT_FW4, rc, NPF_DECISION_BLOCK);

	/*
	 * Try to find (and validate) an existing session, or failing that
	 * try to create a 'parent' tuple based session.
	 */
	npf_session_t *se = npf_session_inspect_or_create(npc, *m, ifp, PFIL_OUT,
							  npf_flags, &rc, &internal_hairpin);
	if (unlikely(rc < 0))
		return process_result(ifp, NPF_RCT_FW4, rc, NPF_DECISION_BLOCK);

	/* SNAT forward (OUT), DNAT reply */
	if (!internal_hairpin) {
		npf_nat_t *nt = npf_session_get_nat(se);
		if (nt)
			rc = nat_do_subsequent(npc, m, se, nt, PFIL_OUT);
		else if (unlikely(npf_iscached(npc, NPC_ICMP_ERR)))
			rc = nat_do_icmp_err(npc, m, ifp, PFIL_OUT);
		else if (npf_active(nif_config, NPF_SNAT))
			rc = nat_try_initial(nif_config, npc, &se, m, ifp, PFIL_OUT);

		if (unlikely(rc < 0)) {
			if (rc == -NPF_RC_NAT_E2BIG) {
				rc = 0; /* TCP sends probes */

					/* too_big */
				if (in_ifp) {
					/*
					 * Generate any ICMP or ICMPv6 "too big" errors.
					 * Only IPv4 ICMP 'Too Big' for the moment.
					 */
					IPSTAT_INC_IFP(ifp, IPSTATS_MIB_FRAGFAILS);
					icmp_error_out(in_ifp, *m,
						       ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
						       htons(ifp->if_mtu), ifp);
				}
			}
			return process_stats(ifp, *m, se, rl, npc, rc, NPF_DECISION_BLOCK);
		}
	}

	/*
	 * If "passing" session found - skip the ruleset inspection.
	 * Similarly, session backwards NAT packets, and secondary
	 * sessions (i.e. ALG created) skip the firewall.
	 */
	if (se && (npf_session_is_pass(se, &rl) ||
		   npf_session_is_nat_pinhole(se, PFIL_OUT) ||
		   npf_session_is_child(se))) {
		if (unlikely(internal_hairpin))
			rl = NULL;	/* avoid running fw stats and rprocs */
		return process_pass(ifp, *m, se, rl, npc, rc);
	}

	/* update session ptr */
	if (se) {
		struct pktmbuf_mdata *mdata = pktmbuf_mdata(*m);
		mdata->md_session = se;
		pktmbuf_mdata_set(*m, PKT_MDATA_SESSION);
	} else
		pktmbuf_mdata_clear(*m, PKT_MDATA_SESSION);

	/* ALLOWS OUTPUT FIREWALL TO PROCESS */
	return NPF_DECISION_UNMATCHED;
}
