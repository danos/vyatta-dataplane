/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */


#include <rte_branch_prediction.h>
#include "urcu.h"
#include "if_var.h"

#include "vplane_log.h"
#include "npf/npf.h"
#include "npf/npf_cmd.h"
#include "npf/npf_nat.h"
#include "npf/npf_cache.h"
#include "npf/npf_if.h"
#include "npf/npf_rc.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_session.h"
#include "npf/rproc/npf_ext_log.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"

#include "npf/zones/npf_zone_public.h"
#include "npf/zones/npf_zone_private.h"

#ifndef NZONEFW

/*
 * Return true if a local zone is assigned
 */
bool npf_zone_local_is_set(void)
{
	return local_zone != NULL;
}

/*
 * Called by npf_hook_track in direction PFIL_OUT if destination interface is
 * in a zone.
 *
 * Gets the zone config and returns true if both source and destination
 * interfaces are in a zone and there are rules between the two zones,
 * else sets decision to PASS or BLOCK and returns false.
 *
 * Packets from the router itself are marked with flag NPF_FLAG_FROM_US, and
 * are never blocked.
 *
 * Packets from tunnels, or kernel forwarded packets, will have an unknown
 * input interface, and hence no 'from' zone.  These will be blocked.
 */
static bool npf_get_zone_config(struct ifnet *in_ifp,
				const struct npf_zone *to_zone,
				uint16_t npf_flags, npf_decision_t *decision,
				struct npf_config **npf_config)
{
	const struct npf_zone *from_zone = NULL;

	if (npf_flags & NPF_FLAG_FROM_US) {
		if (npf_flags & NPF_FLAG_FROM_LOCAL)
			from_zone = npf_zone_local();

		if (!from_zone) {
			*decision = NPF_DECISION_PASS;
			return false;
		}
	} else if (in_ifp)
		from_zone = npf_if_zone(in_ifp);

	if (!from_zone) {
		*decision = NPF_DECISION_BLOCK;
		return false;
	}

	if (from_zone == to_zone) {
		*decision = NPF_DECISION_PASS;
		return false;
	}

	/*
	 * Make stateful ZBF work like stateful IBF, namely that a block
	 * rule can not affect the stateful return traffic.  Otherwise
	 * stateful return traffic is allowed to pass.
	 */
	if (npf_flags & NPF_FLAG_IN_SESSION) {
		*decision = NPF_DECISION_PASS;
		return false;
	}

	/* Get the zone configuration */
	*npf_config = npf_zone_config(from_zone, to_zone);

	if (!*npf_config) {
		/* no configuration between the two zones. */
		if (npf_flags & NPF_FLAG_FROM_LOCAL)
			*decision = NPF_DECISION_PASS;
		else
			*decision = NPF_DECISION_BLOCK;
		return false;
	}

	return true;
}

/*
 * Zone firewall output hook
 */
bool
npf_zone_hook(struct ifnet *in_ifp, struct npf_if *nif, uint16_t npf_flags,
	      struct npf_config **fw_config, npf_decision_t *decision,
	      enum npf_ruleset_type *rlset_type, bool *reverse_stateful)
{
	struct npf_zone *to_zone = npf_nif_zone(nif);

	if (likely(!to_zone)) {

		/*
		 * Block zone to non-zone; NB from-us sometimes looks
		 * like from zone
		 */
		if (unlikely((npf_flags & NPF_FLAG_FROM_ZONE) &&
			     !(npf_flags & NPF_FLAG_FROM_US))) {
			*decision = NPF_DECISION_BLOCK;
			return true;
		}
	} else {
		/* Get the zones configuration */
		if (!npf_get_zone_config(in_ifp, to_zone, npf_flags,
					 decision, fw_config))
			return true;

		*rlset_type = NPF_RS_ZONE;
		*reverse_stateful = false;
	}

	return false;
}

/*
 * Local zone firewall.  For packets delivered *to* the router.  Bypass DNAT
 * in fw-in node if session has SE_LOCAL flag set
 */
static npf_decision_t
npf_local_zone_fw(struct ifnet *ifp, struct rte_mbuf **m,
		  npf_cache_t *npc, struct npf_config *zone_config,
		  npf_session_t *se)
{
	npf_decision_t decision = NPF_DECISION_PASS;
	npf_rule_t *rl;
	int error = 0;

	const npf_ruleset_t *rlset;

	rlset = npf_get_ruleset(zone_config, NPF_RS_ZONE);

	rl = npf_ruleset_inspect(npc, *m, rlset, se, NULL, PFIL_OUT);
	decision = npf_rule_decision(rl);

	/* Log any firewall matched rule now */
	if (unlikely(npf_rule_has_rproc_logger(rl)))
		npf_log_pkt(npc, *m, rl, PFIL_IN);

	/*
	 * Establish a "pass" session, if required. Just proceed, if session
	 * creation fails (e.g. due to unsupported protocol).
	 */
	if (rl && npf_rule_stateful(rl) && decision == NPF_DECISION_PASS) {
		if (!se) {
			se = npf_session_establish(npc, *m, ifp, PFIL_IN,
						   &error);
			if (unlikely(error)) {
				decision = NPF_DECISION_BLOCK;
				goto stats;
			}
		}
		npf_session_add_fw_rule(se, rl);
	}

stats:
	npf_add_pkt(rl, rte_pktmbuf_pkt_len(*m));

	if (se && ifp) {
		if (decision != NPF_DECISION_BLOCK) {
			/* N.B. se may be consumed */
			error = npf_session_activate(se, ifp, npc, *m);
			if (error == 0) {
				/* Attach the session to the packet */
				struct pktmbuf_mdata *mdata = pktmbuf_mdata(*m);
				mdata->md_session = se;
				pktmbuf_mdata_set(*m, PKT_MDATA_SESSION);
			} else {
				if (error != -NPF_RC_ENOSTR)
					decision = NPF_DECISION_BLOCK;
			}
		} else if (!npf_session_is_active(se)) {
			npf_session_destroy(se);
		} else if (error) {
			pktmbuf_mdata_clear(*m, PKT_MDATA_SESSION);
			npf_session_expire(se);
		}
	}
	return decision;
}

/*
 * Local zones hook.  Return true to discard.
 */
bool
npf_local_zone_hook(struct ifnet *ifp, struct rte_mbuf **m,
		    struct npf_cache *npc, struct npf_session *se,
		    struct npf_if *nif)
{
	struct npf_zone *local_zone = npf_zone_local();

	if (!local_zone)
		return false;

	struct npf_zone *from_zone = npf_nif_zone(nif);

	if (from_zone) {
		struct npf_config *zone_config;
		npf_decision_t decision;

		zone_config = npf_zone_config(from_zone, local_zone);
		if (!zone_config)
			return true;	/* discard */

		/*
		 * Do we need to un-DNAT before zones rulesets?
		 */
		if (se && pktmbuf_mdata_exists(*m, PKT_MDATA_DNAT)) {
			if (npf_local_undnat(m, npc, se))
				return true;	/* discard */

			/*
			 * Mark session such that subsequent packets
			 * will bypass DNAT and route lookup, and be
			 * sent direct to ipv4-local node after
			 * ipv4-fw-in node.
			 */
			npf_session_set_local_zone_nat(se);
		}
		decision = npf_local_zone_fw(ifp, m, npc, zone_config,
					     se);

		if (decision != NPF_DECISION_PASS)
			return true;	/* discard */
	}

	return false;
}

/*
 * Zone show command
 */
int npf_zone_show(FILE *fp, int argc, char **argv)
{
	const char *zone = NULL, *policy = NULL;
	uint8_t flags = NPF_ZONES_SHOW_ALL;
	char *endp;

	if (argc >= 1 && strcmp(argv[0], "all") != 0)
		zone = argv[0];

	if (argc >= 2 && strcmp(argv[1], "all") != 0)
		policy = argv[1];

	if (argc >= 3) {
		flags = strtoul(argv[2], &endp, 10);
		if (*endp) {
			npf_cmd_err(fp, "invalid flags");
			return -1;
		}
	}

	json_writer_t *json = jsonw_new(fp);

	if (json == NULL) {
		RTE_LOG(ERR, DATAPLANE, "failed to create json stream\n");
		return -1;
	}

	npf_zone_show_private(json, zone, policy, flags);
	jsonw_destroy(&json);
	return 0;
}

int
npf_zone_cfg_add(FILE *f, int argc, char **argv)
{
	if (argc < 1) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	if (npf_zone_cfg(argv[0]) < 0) {
		npf_cmd_err(f, "error adding zone %s", argv[0]);
		return -1;
	}
	return 0;
}

int
npf_zone_cfg_remove(FILE *f, int argc, char **argv)
{
	if (argc < 1) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	if (npf_zone_uncfg(argv[0]) < 0) {
		npf_cmd_err(f, "error deleting zone %s", argv[0]);
		return -1;
	}
	return 0;
}

int
npf_zone_cfg_local(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	bool set = strcmp(argv[1], "set") == 0;

	if (npf_zone_local_set(argv[0], set) < 0) {
		npf_cmd_err(f, "error setting %s as local zone", argv[0]);
		return -1;
	}
	return 0;
}

int
npf_zone_cfg_policy_add(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	if (npf_zone_policy_add(argv[0], argv[1])) {
		npf_cmd_err(f, "Failed to add policy %s to zone %s",
			    argv[1], argv[0]);
		return -1;
	}
	return 0;
}

int
npf_zone_cfg_policy_remove(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	if (npf_zone_policy_del(argv[0], argv[1]) < 0) {
		npf_cmd_err(f, "Failed to remove policy %s from zone %s",
			    argv[1], argv[0]);
		return -1;
	}
	return 0;
}

int
npf_zone_cfg_intf_add(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	if (npf_zone_intf_add(argv[0], argv[1]) < 0) {
		npf_cmd_err(f, "Failed to add interface %s to zone %s",
			    argv[1], argv[0]);
		return -1;
	}
	return 0;
}

int
npf_zone_cfg_intf_remove(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	if (npf_zone_intf_del(argv[0], argv[1]) < 0) {
		npf_cmd_err(f, "Failed to remove interface %s from zone %s",
			    argv[1], argv[0]);
		return -1;
	}
	return 0;
}

void
npf_zone_inst_destroy(void)
{
	npf_zone_inst_destroy_private();
}

struct npf_zone *npf_zone_zif2zone(const struct npf_zone_intf *zif)
{
	return npf_zone_zif2zone_private(zif);
}

/*
 * Indirect callback for dataplane DP_EVT_IF_INDEX_SET event.  Should be
 * called under niif_lock.
 */
int npf_zone_if_index_set(struct ifnet *ifp)
{
	struct npf_zone_intf *zif;
	int rc = 0;

	/*
	 * If this interface is in a zone, then reference the associated
	 * zone interface structure.
	 */
	zif = npf_zone_ifname2zif(ifp->if_name);
	if (zif) {
		rc = npf_if_zone_assign(ifp, zif, false);
		if (!rc)
			npf_zone_intf_get(zif);
	}
	return rc;
}

/*
 * Indirect callback for dataplane DP_EVT_IF_INDEX_UNSET event.  This is
 * necessary for when an interface is deleted before zones config is removed.
 * See also npf_zone_intf_del.
 */
int npf_zone_if_index_unset(struct ifnet *ifp)
{
	struct npf_zone_intf *zif = npf_if_zone_intf(ifp);
	int rc = 0;

	/*
	 * If associated with a zone, then disassociate.
	 */
	if (zif) {
		/* Clear pointer from npf_if_internal to zone intf */
		rc = npf_if_zone_assign(ifp, NULL, false);
		if (!rc)
			npf_zone_intf_put(&zif);
	}
	return rc;
}

#endif /* NZONEFW */
