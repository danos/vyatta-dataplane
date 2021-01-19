/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdint.h>
#include <stdio.h>

#include "compiler.h"
#include "control.h"
#include "if_var.h"
#include "npf/npf.h"
#include "npf/npf_apm.h"
#include "npf/alg/alg_npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/npf_apm.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_cache.h"
#include "npf/npf_rc.h"
#include "npf/npf_event.h"
#include "npf/npf_if.h"
#include "npf/npf_if_feat.h"
#include "npf/npf_nat.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_session.h"
#include "npf/npf_state.h"
#include "npf/npf_vrf.h"
#include "npf/npf_timeouts.h"
#include "npf/zones/npf_zone_public.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/rproc/npf_ext_session_limit.h"
#include "npf_shim.h"
#include "npf/rproc/npf_ext_log.h"
#include "npf/nat/nat_pool_public.h"
#include "pktmbuf_internal.h"
#include "urcu.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "ip_icmp.h"

struct npf_ruleset;

/*
 * This is used for NPF configuration rulesets which are used
 * on a global basis (e.g. not per-interface).
 */
struct npf_config *npf_global_config __hot_data;

/*
 * Optimized version of npf_hook_track() which does not do session tracking.
 */
npf_result_t
npf_hook_notrack(const npf_ruleset_t *rlset, struct rte_mbuf **m,
		 struct ifnet *ifp, int dir, uint16_t npf_flags,
		 uint16_t eth_type, int *rcp)
{
	npf_cache_t npc, *n = NULL;
	uint32_t tag_val = 0;
	bool tag_set = false;
	npf_rule_t *rl;
	npf_rproc_result_t rproc_result = {
		.decision = NPF_DECISION_UNMATCHED,
	};

	if (npf_ruleset_uses_cache(rlset)) {
		int rc = 0;

		/*
		 * Use the global per-core cache if the packet has been
		 * reassembled, else use a local cache
		 *
		 * Note that both branches will clear any cached tag
		 */
		if (pktmbuf_mdata_exists(*m, PKT_MDATA_DEFRAG)) {
			n = npf_get_cache(&npf_flags, *m, eth_type, &rc);
			if (!n) {
				if (rcp)
					*rcp = rc;
				goto result;
			}
		} else {
			n = &npc;
			/* Initialize packet information cache.	 */
			npf_cache_init(n);

			/* Cache everything. drop if junk. */
			rc = npf_cache_all(n, *m, eth_type);
			if (unlikely(rc < 0)) {
				if (rcp)
					*rcp = rc;
				goto result;
			}
		}
	}

	rl = npf_ruleset_inspect(n, *m, rlset, NULL, ifp, dir);

	rproc_result.decision = npf_rule_decision(rl);

	if (rproc_result.decision != NPF_DECISION_UNMATCHED) {
		/* Log any matched rule immediately */
		if (unlikely(npf_rule_has_rproc_logger(rl)))
			npf_log_pkt(n, *m, rl, dir);

		tag_val = npf_rule_rproc_tag(rl, &tag_set);

		/* Traffic matched the rule, so perform actions */
		npf_rproc_action(n, m, dir, rl, NULL, &rproc_result);

		/*
		 * Account the packet unless the decision is BLOCK_UNACCOUNTED.
		 *
		 * In that case, convert the decision to BLOCK
		 * and proceed to drop the traffic.
		 */
		if (rproc_result.decision != NPF_DECISION_BLOCK_UNACCOUNTED)
			npf_add_pkt(rl, rte_pktmbuf_pkt_len(*m));
		else
			rproc_result.decision = NPF_DECISION_BLOCK;
	}

result:
	return (npf_result_t) {
		.decision = rproc_result.decision,
		.tag_set = tag_set,
		.flags = npf_flags,
		.tag = tag_val,
		.icmp_param_prob = rproc_result.icmp_param_prob,
		.icmp_dst_unreach = rproc_result.icmp_dst_unreach,
	};
}

/*
 * Search firewall ruleset and return a decision for this packet.
 */
static npf_decision_t
npf_apply_firewall(const struct npf_ruleset *rs,
		   npf_session_t *se, npf_cache_t *npc,
		   const struct ifnet *ifp, struct rte_mbuf *nbuf,
		   int dir, npf_rule_t **rl,
		   uint16_t npf_flag, bool reverse_stateful)
{
	bool have_ruleset = (rs != NULL);
	npf_decision_t decision;

	*rl = npf_ruleset_inspect(npc, nbuf, rs, se, ifp, dir);

	/* Get the initial decision */
	decision = npf_rule_decision(*rl);

	/* We have a definitive match on a pass rule */
	if (decision == NPF_DECISION_PASS)
		return decision;

	/* Log any matched non-pass rule immediately */
	if (unlikely(npf_rule_has_rproc_logger(*rl)))
		npf_log_pkt(npc, nbuf, *rl, dir);

	/*
	 * We are either:  NPF_DECISION_BLOCK or NPF_DECISION_UNMATCHED.
	 *
	 * Decide about any overrides here.  First, FROM_US packets
	 * always get a pass, then unmatched.
	 */

	if (npf_flag & NPF_FLAG_FROM_US) {
		*rl = NULL;
		return NPF_DECISION_PASS;
	}

	if (!*rl) {
		if (npf_flag & NPF_FLAG_ERR_SESSION) {
			/*
			 * An ICMP error for a stateful session.
			 */
			decision = NPF_DECISION_PASS;
		} else if (npf_iscached(npc, NPC_NDP)) {
			/*
			 * Allow IPv6 NDP if not explicitly blocked.
			 */
			decision = NPF_DECISION_PASS;
		} else if (reverse_stateful) {
			/*
			 * Stateful rule in opposite direction, block.
			 * This handles the case where a stateful rule is
			 * configured in one direction and allows
			 * only established packets through.
			 */
			decision = NPF_DECISION_BLOCK;
		} else if (have_ruleset) {
			/*
			 * Regular unmatched packet
			 */
			decision = NPF_DECISION_UNMATCHED;
		} else {
			/*
			 * Default. No ruleset for this interface
			 */
			decision = NPF_DECISION_PASS;
		}
	}

	return decision;
}

static inline void
npf_shim_rproc(npf_cache_t *npc, struct rte_mbuf **nbuf,
		int dir, npf_rule_t *rl,
		npf_session_t *se, npf_decision_t *decision)
{
	if (!npf_rule_has_rproc_actions(rl))
		return;

	npf_rproc_result_t rproc_result = {
		.decision = *decision,
	};

	npf_rproc_action(npc, nbuf, dir, rl, se, &rproc_result);
	*decision = rproc_result.decision;
}

/*
 * Processor entry point given packet, interface, direction
 * and configuration set.
 *
 * Packets passed in here must not be fragments.
 */
npf_result_t
npf_hook_track(struct ifnet *in_ifp, struct rte_mbuf **m,
	       struct npf_if *nif, int dir, uint16_t npf_flags,
	       uint16_t eth_type)
{
	struct npf_config *fw_config = NULL;
	npf_session_t *se = NULL;
	npf_rule_t *rl = NULL;
	npf_decision_t decision = NPF_DECISION_UNMATCHED;
	npf_action_t action = NPF_ACTION_NORMAL;
	enum npf_ruleset_type rlset_type = NPF_RS_TYPE_COUNT;
	const npf_ruleset_t *rlset;
	bool internal_hairpin = false;
	bool too_big = false;
	struct npf_config *nif_config = npf_if_conf(nif);
	struct ifnet *ifp = nif->nif_ifp;
	int rc = NPF_RC_UNMATCHED;

	/*
	 * Parse the packet, note this also clears any cached tag.
	 *
	 * If Firewall or NAT are enabled, we will never see a fragment,
	 * however if we get here due to DPI, we may.  That is fine as
	 * the subsequent logic should simply pass those fragments.
	 */
	npf_cache_t *npc = npf_get_cache(&npf_flags, *m, eth_type, &rc);

	if (unlikely(!npc)) {
		decision = NPF_DECISION_BLOCK;
		goto result;
	}

	/*
	 * Order of operations: INFW -> DNAT -> RT_LU -> SNAT -> OUTFW
	 */

	/*
	 * Try to find (and validate) an existing session, or failing that
	 * try to create a 'parent' tuple based session.
	 */
	se = npf_session_inspect_or_create(npc, *m, ifp, dir, &npf_flags,
					   &rc, &internal_hairpin);
	if (unlikely(rc < 0)) {
		decision = NPF_DECISION_BLOCK;
		goto result;
	}

	/* SNAT forward (OUT), DNAT reply */
	if (dir == PFIL_OUT && !internal_hairpin) {
		npf_nat_t *nt = npf_session_get_nat(se);
		if (nt) {
			rc = nat_do_subsequent(npc, m, se, nt, dir);
		    snat_result:
			if (unlikely(rc < 0)) {
				if (rc == -NPF_RC_NAT_E2BIG) {
					too_big = true;
					rc = 0; /* TCP sends probes */
				}
				decision = NPF_DECISION_BLOCK;
				goto stats;
			}
		} else if (unlikely(npf_iscached(npc, NPC_ICMP_ERR))) {
			rc = nat_do_icmp_err(npc, m, ifp, dir);
			goto snat_result;
		} else if (unlikely(npf_active(nif_config, NPF_SNAT))) {
			rc = nat_try_initial(nif_config, npc, &se, m, ifp, dir);
			goto snat_result;
		}
	}

	/*
	 * If "passing" session found - skip the ruleset inspection.
	 * Similarly, session backwards NAT packets, and secondary
	 * sessions (i.e. ALG created) skip the firewall.
	 */
	if (se && (npf_session_is_pass(se, &rl) ||
		   npf_session_is_nat_pinhole(se, dir) ||
		   npf_session_is_child(se))) {
		if (unlikely(internal_hairpin))
			rl = NULL;	/* avoid running fw stats and rprocs */
		decision = NPF_DECISION_PASS;
		goto pass;
	}

	/*
	 * Determine the ruleset type and any reverse ruleset,
	 * allowing for possible stateful ZBF pass session.
	 */
	bool reverse_stateful;

	if (dir == PFIL_IN) {
		fw_config = nif_config;

		unsigned long fw_active
			= fw_config ? fw_config->nc_active_flags : 0;

		rlset_type = NPF_RS_FW_IN;
		reverse_stateful = fw_active & NPF_FW_STATE_OUT;
	} else {
		fw_config = nif_config;

		unsigned long fw_active
			= fw_config ? fw_config->nc_active_flags : 0;

		rlset_type = NPF_RS_FW_OUT;
		reverse_stateful = fw_active & NPF_FW_STATE_IN;

		if (unlikely((npf_flags & NPF_FLAG_FROM_ZONE) ||
			     npf_nif_zone(nif))) {
			if (npf_zone_hook(in_ifp, nif, npf_flags, &fw_config,
					  &decision, &rlset_type,
					  &reverse_stateful))
				goto done;
		}
	}

	/* Inspect FW ruleset */
	rlset = npf_get_ruleset(fw_config, rlset_type);

	decision = npf_apply_firewall(rlset, se, npc, ifp, *m, dir, &rl,
				      npf_flags, reverse_stateful);
	switch (decision) {
	case NPF_DECISION_PASS:
		break;
	case NPF_DECISION_UNMATCHED:
		goto done;
	case NPF_DECISION_BLOCK:
		goto stats;
	default:	/* Hush up gcc */
		break;
	}

	/*
	 * Establish a "pass" session, if required. Just proceed, if session
	 * creation fails (e.g. due to unsupported protocol).
	 */
	if (rl && npf_rule_stateful(rl)) {
		if (!se) {
			se = npf_session_establish(npc, *m, ifp, dir, &rc);
			if (unlikely(rc < 0)) {
				decision = NPF_DECISION_BLOCK;
				goto stats;
			}
		}
		npf_session_add_fw_rule(se, rl);
	}

pass:
	/* Log any firewall matched rule now */
	if (unlikely(npf_rule_has_rproc_logger(rl)))
		npf_log_pkt(npc, *m, rl, dir);

	/* DNAT forward (IN), SNAT reply */
	if (dir == PFIL_IN && !internal_hairpin) {
		npf_nat_t *nt = npf_session_get_nat(se);
		if (nt) {
			/*
			 * If destined for local, bypass DNAT.  The session is
			 * only marked as local when the first packet passes
			 * through npf_local_fw.
			 */
			if (unlikely(npf_session_is_local_zone_nat(se))) {
				action = NPF_ACTION_TO_LOCAL;
				goto stats;
			}

			rc = nat_do_subsequent(npc, m, se, nt, dir);
		    dnat_result:
			if (unlikely(rc < 0)) {
				decision = NPF_DECISION_BLOCK;
				goto stats;
			}
		} else if (unlikely(npf_iscached(npc, NPC_ICMP_ERR))) {
			rc = nat_do_icmp_err(npc, m, ifp, dir);
			goto dnat_result;
		} else if (unlikely(npf_active(nif_config, NPF_DNAT))) {
			rc = nat_try_initial(nif_config, npc, &se, m, ifp, dir);
			goto dnat_result;
		}
	}

	/* ALGs may need/want to inspect. */
	if (npf_session_uses_alg(se))
		npf_alg_inspect(se, npc, *m, ifp, dir);

stats:
	/* Stats and rule procedures. */
	if (rl) {
		if (!se || !npf_session_is_pass(se, NULL) ||
		    npf_session_forward_dir(se, dir))
			npf_add_pkt(rl, rte_pktmbuf_pkt_len(*m));
		npf_shim_rproc(npc, m, dir, rl, se, &decision);
	}

done:
	if (se) {
		if (decision != NPF_DECISION_BLOCK) {
			/* N.B. se may be consumed */
			rc = npf_session_activate(se, ifp, npc, *m);
			if (rc == 0) {
				/* Attach the session to the packet */
				struct pktmbuf_mdata *mdata = pktmbuf_mdata(*m);
				mdata->md_session = se;
				pktmbuf_mdata_set(*m, PKT_MDATA_SESSION);

				/* Save session stats. */
				npf_save_stats(se, dir,
					       rte_pktmbuf_pkt_len(*m));
			} else {
				if (rc != -NPF_RC_ENOSTR)
					decision = NPF_DECISION_BLOCK;
			}
		} else if (!npf_session_is_active(se)) {
			npf_session_destroy(se);
		} else if (rc < 0) {
			pktmbuf_mdata_clear(*m, PKT_MDATA_SESSION);
			npf_session_expire(se);
		}
	}

result:
	/*
	 * Can jump here blocking the packet due to failing to cache the
	 * packet, or errors returned trying to create or lookup a session.
	 */
	if (in_ifp && unlikely(too_big)) {
		/*
		 * Generate any ICMP or ICMPv6 "too big" errors.
		 * Only IPv4 ICMP 'Too Big' for the moment.
		 */
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_FRAGFAILS);
		icmp_error_out(in_ifp, *m,
			       ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			       htons(ifp->if_mtu), ifp);
	}

	/* Increment return code counter */
	npf_rc_inc(ifp, ETH2RCT(eth_type), PFIL2RC(dir), rc, decision);

	return (npf_result_t) {
		.decision = decision,
		.action = action,
		.flags = npf_flags,
	};
}

void
npf_init(void)
{
	npf_event_init();
	npf_if_feat_init();
	npf_if_init();
	npf_alg_init();
	npf_apm_init();
	npf_rule_group_init();
	npf_attach_point_init();
	npf_config_init();
	pmf_arlg_init();
	npf_state_tcp_init();
	npf_ruleset_gc_init();
	npf_state_stats_create();
	nat_pool_init();

	int rc = npf_attpt_item_set_up(NPF_ATTACH_TYPE_GLOBAL, "",
				       &npf_global_config, NULL);
	if (rc != 0)
		RTE_LOG(ERR, DATAPLANE, "failed to register global rulesets "
			"with NPF\n");
	else
		npf_gbl_attach_point_init();
}

void npf_cleanup(void)
{
	npf_alg_uninit();
	npf_apm_uninit();
	npf_if_cleanup();
	npf_state_stats_destroy();
	nat_pool_uninit();
}

static int
npf_local_dnat(struct rte_mbuf **m, npf_cache_t *npc, npf_session_t *se)
{
	npf_nat_t *nt = npf_session_get_nat(se);

	if (nt) {
		int error = nat_do_subsequent(npc, m, se, nt, PFIL_IN);
		if (error)
			return -EINVAL;
	}
	return 0;
}

/*
 * Run local firewall rules.
 *
 * returns true if the packet should be discarded.
 */
bool npf_local_fw(struct ifnet *ifp, struct rte_mbuf **m, uint16_t ether_type)
{
	struct npf_if *nif = rcu_dereference(ifp->if_npf);
	bool rv = false;
	npf_result_t result = { .decision = NPF_DECISION_UNMATCHED };
	int rc = NPF_RC_UNMATCHED;
	bool rc_inc = false;	/* set true to increment rc counts */

	/*
	 * If there is no npf config on the input interface then jump straight
	 * to check the global CPP firewall
	 */
	if (!nif)
		goto global_fw;

	const struct npf_config *npf_config = npf_if_conf(nif);

	npf_cache_t npc;

	npf_cache_init(&npc);

	rc = npf_cache_all(&npc, *m, ether_type);
	if (rc < 0) {
		rc_inc = true;
		rv = true;	/* discard */
		goto end;
	}

	/* Find the session */
	npf_session_t *se = npf_session_find_cached(*m);

	/* Validate the session */
	if (se && npf_session_get_if_index(se) != ifp->if_index)
		se = NULL;

	/* If "passing" session found - skip the zones ruleset inspection */
	npf_rule_t *rl = NULL;
	if (se) {
		rc_inc = true;

		if ((npf_session_is_pass(se, &rl) ||
		     npf_session_is_nat_pinhole(se, PFIL_IN) ||
		     npf_session_is_child(se))) {
			rc = NPF_RC_PASS;
			goto skip_local_zone;
		}
	}

	/*
	 * Local zone firewall
	 */
	if (unlikely(npf_zone_local_is_set() &&
		     !npf_iscached(&npc, NPC_IPFRAG))) {

		rc_inc = true;
		if (npf_local_zone_hook(ifp, m, &npc, se, nif)) {
			rc = NPF_RC_BLOCK;
			rv = true;	/* discard */
			goto end;
		}
	}

skip_local_zone:

	/* Log any firewall matched rule now */
	if (unlikely(npf_rule_has_rproc_logger(rl)))
		npf_log_pkt(&npc, *m, rl, PFIL_IN);

	/*
	 * Do we need to DNAT?  Either we bypassed DNAT in npf_hook_track, or
	 * we undid DNAT above.
	 */
	if (se && (npf_session_is_local_zone_nat(se) ||
		   npf_active(npf_config, NPF_DNAT)) &&
	    !pktmbuf_mdata_exists(*m, PKT_MDATA_DNAT)) {

		rc_inc = true;
		if (npf_local_dnat(m, &npc, se)) {
			rc = NPF_RC_BLOCK;
			rv = true;
			goto end;
		}
	}

	/*
	 * Local firewall is done post-DNAT
	 */
	if (npf_active(npf_config, NPF_LOCAL)) {

		rc_inc = true;
		result = npf_hook_notrack(npf_get_ruleset(npf_config,
					  NPF_RS_LOCAL), m, ifp, PFIL_IN, 0,
					  ether_type, &rc);

		if (result.decision == NPF_DECISION_BLOCK) {
			rv = true;	/* discard */
			goto end;
		} else if (result.decision == NPF_DECISION_PASS) {
			rc = NPF_RC_PASS;
			rv = false;	/* retain */
			goto end;
		}

		/* No match, so try the global firewall rules. */
	}

global_fw:
	if (npf_active(npf_global_config, NPF_LOCAL)) {

		rc_inc = true;
		result = npf_hook_notrack(npf_get_ruleset(npf_global_config,
					  NPF_RS_LOCAL), m, ifp, PFIL_IN, 0,
					  ether_type, &rc);

		if (result.decision == NPF_DECISION_BLOCK) {
			rv = true;	/* discard */
		} else if (result.decision == NPF_DECISION_PASS) {
			rc = NPF_RC_PASS;
			rv = false;	/* retain */
		}
	}

end:
	/* Increment return code counter? */
	if (rc_inc)
		npf_rc_inc(ifp, NPF_RCT_LOC, NPF_RC_IN, rc, result.decision);

	return rv;
}

bool npf_originate_fw(struct ifnet *ifp, uint16_t npf_flags,
		struct rte_mbuf **m, uint16_t ether_type)
{
	struct npf_if *nif = rcu_dereference(ifp->if_npf);
	const struct npf_config *npf_config = npf_if_conf(nif);
	bool rv = false;
	npf_result_t result = { .decision = NPF_DECISION_UNMATCHED };
	int rc = NPF_RC_UNMATCHED;
	bool rc_inc = false;

	/*
	 * Local zone firewall will be done in fw_out processing
	 */

	if (npf_active(npf_config, NPF_ORIGINATE)) {

		rc_inc = true;
		result = npf_hook_notrack(npf_get_ruleset(npf_config,
				NPF_RS_ORIGINATE), m, ifp, PFIL_OUT, npf_flags,
					  ether_type, &rc);

		if (result.decision == NPF_DECISION_BLOCK) {
			rv = true;	/* discard */
			goto end;
		} else if (result.decision == NPF_DECISION_PASS) {
			rc = NPF_RC_PASS;
			rv = false;	/* retain */
			goto end;
		}
	}

	/* No match, so try the global firewall rules. */
	if (npf_active(npf_global_config, NPF_ORIGINATE)) {

		rc_inc = true;
		result = npf_hook_notrack(npf_get_ruleset(npf_global_config,
				NPF_RS_ORIGINATE), m, ifp, PFIL_OUT, npf_flags,
					  ether_type, &rc);

		if (result.decision == NPF_DECISION_BLOCK) {
			rv = true;	/* discard */
		} else if (result.decision == NPF_DECISION_PASS) {
			rc = NPF_RC_PASS;
			rv = false;	/* retain */
		}
	}

end:
	/* Increment return code counter? */
	if (rc_inc)
		npf_rc_inc(ifp, NPF_RCT_LOC, NPF_RC_OUT, rc, result.decision);

	return rv;
}

/*
 * Clear all sessions and reset the npf configuration back to what it
 * would be without any configuration.
 */
void npf_reset_config(enum cont_src_en cont_src)
{
	if (cont_src != CONT_SRC_MAIN)
		return;

	npf_cfg_detach_all();
	npf_cfg_all_group_delete();
	npf_cfg_commit_all();
	npf_addrgrp_tbl_destroy();
	npf_state_set_tcp_strict(false);
	npf_reset_session_log();
	npf_sess_limit_inst_destroy();
	npf_timeout_reset();
	npf_alg_reset(true);
	npf_zone_inst_destroy();
}

void npf_print_state_stats(json_writer_t *json)
{
	npf_state_stats_json(json);
}

/*
 * Pass-through to write NAT json for a dataplane session
 */
int npf_json_nat_session(json_writer_t *json, void *data)
{
	npf_session_t *se = data;

	return npf_session_json_nat(json, se);
}

/* Shim routine for determining whether this NPF session is natted */
bool npf_feature_is_nat(void *data)
{
	npf_session_t *se = data;

	return npf_session_get_nat(se) ? true : false;
}
