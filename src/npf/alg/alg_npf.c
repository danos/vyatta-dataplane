/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include "util.h"
#include "vplane_log.h"
#include "vrf_internal.h"

#include "npf/npf_cmd.h"
#include "npf/npf_nat.h"
#include "npf/npf_rc.h"
#include "npf/npf_session.h"
#include "npf/npf_vrf.h"

#include "npf/alg/alg_npf.h"
#include "npf/alg/alg.h"
#include "npf/alg/alg_session.h"
#include "npf/alg/alg_ftp.h"
#include "npf/alg/alg_tftp.h"
#include "npf/alg/alg_rpc.h"
#include "npf/alg/alg_sip.h"

/*
 * One-time ALG initialisation function.  Initialises and starts a single
 * global garbage collection timer.
 */
void npf_alg_init(void)
{
	npf_alg_timer_init();
	npf_alg_timer_reset();
}

/*
 * Stop ALG.  Stops the garbage collection timer.
 */
void npf_alg_uninit(void)
{
	npf_alg_timer_uninit();
}

/*
 * Destroy a per-vrf ALG instance
 */
void npf_alg_destroy_instance(struct npf_alg_instance *ai)
{
	if (!ai)
		return;

	if (ai->ai_tftp)
		npf_alg_tftp_destroy_instance(ai->ai_tftp);

	if (ai->ai_ftp)
		npf_alg_ftp_destroy_instance(ai->ai_ftp);

	if (ai->ai_sip)
		npf_alg_sip_destroy_instance(ai->ai_sip);

	if (ai->ai_rpc)
		npf_alg_rpc_destroy_instance(ai->ai_rpc);

	ai->ai_tftp = NULL;
	ai->ai_ftp = NULL;
	ai->ai_sip = NULL;
	ai->ai_rpc = NULL;

	/* apt instance will be destroyed when last reference is removed */
	alg_apt_instance_put(ai->ai_apt);
	ai->ai_apt = NULL;

	free(ai);
}

/* Take reference on an alg application instance */
struct npf_alg *npf_alg_get(struct npf_alg *alg)
{
	if (alg)
		rte_atomic32_inc(&alg->na_refcnt);

	return alg;
}

/* Release reference on an alg application instance */
void npf_alg_put(struct npf_alg *alg)
{
	if (alg && rte_atomic32_dec_and_test(&alg->na_refcnt))
		npf_alg_destroy_alg(alg);
}

/*
 * ALG session init.
 *
 * If this is a child/data flow, then the session will have been created
 * because a tuple (pinhole) was matched.  In these cases, the tuple will be
 * cached in 'npc'.  We get here when a session lookup does not find a
 * session, and when npf_alg_session calls npf_session_establish.
 *
 * If not a child/data flow (i.e. no tuple found in cache) then check if the
 * new session matches an known protocol and destination port.  This
 * identifies ALG parent/control flows.
 */
int npf_alg_session_init(struct npf_session *se, struct npf_cache *npc, int di)
{
	const struct npf_alg *alg;
	struct apt_tuple *nt;
	int rc = 0;

	/* Ensure we have an instance struct for the VRF */
	vrfid_t vrfid = npf_session_get_vrfid(se);
	struct npf_alg_instance *ai = vrf_get_npf_alg_rcu(vrfid);
	if (!ai)
		return 0;

	/*
	 * Expected flow?  First look for tuple in cache (data flow).  Then
	 * lookup protocol and destination port in ALG tuple database (control
	 * flow).
	 */
	nt = alg_lookup_npc(ai, npc, npf_session_get_if_index(se));
	if (!nt)
		return 0;

	/* Get the specific ALG (sip, ftp etc.) data from the tuple  */
	alg = apt_tuple_get_client_handle(nt);

	if (!alg || !alg->na_enabled)
		return 0;

	/* Allocate and attach ALG data to the session */
	rc = npf_alg_session_set_alg(se, alg);
	if (rc)
		return rc;

	switch (alg->na_id) {
	case NPF_ALG_ID_FTP:
		rc = ftp_alg_session_init(se, npc, nt, di);
		break;
	case NPF_ALG_ID_TFTP:
		rc = tftp_alg_session_init(se, npc, nt, di);
		break;
	case NPF_ALG_ID_RPC:
		rc = rpc_alg_session_init(se, nt);
		break;
	case NPF_ALG_ID_SIP:
		rc = sip_alg_session_init(se, npc, nt, di);
		break;
	};

	if (rc && net_ratelimit()) {
		char buf[64];

		RTE_LOG(ERR, FIREWALL, "NPF ALG: %s: session init: %s\n",
			npf_alg_id2name(alg->na_id),
			strerror_r(-rc, buf, sizeof(buf)));
	}

	return rc;
}

/*
 * Bypass CGNAT out if packet matches ALG tuple or SNAT session.  Called
 * *only* from the CGNAT output pipeline node.
 */
bool npf_alg_bypass_cgnat(const struct ifnet *ifp, struct rte_mbuf *m)
{
	npf_cache_t npc_local, *npc;
	npf_session_t *se;
	bool sforw = false;

	/* Initialize local npf packet cache. */
	npc = &npc_local;
	npf_cache_init(npc);

	/* Cache packet */
	if (unlikely(!npf_cache_all_nogpr(npc, m, htons(RTE_ETHER_TYPE_IPV4))))
		return false;

	if (npf_iscached(npc, NPC_ICMP_ERR))
		return false;

	/* Does pkt match an ALG session? */
	se = npf_session_find(m, PFIL_OUT, ifp, &sforw, NULL);
	if (se && npf_session_get_alg_ptr(se))
		return true;

	/*
	 * Does pkt match an ALG tuple?
	 *
	 * Note that this does *not* set the NPC_ALG_TLUP cache flag or set
	 * npc_tuple, since it may not be the correct type of tuple when
	 * fw_out first does a lookup.
	 */
	if (alg_lookup_every_table(ifp, npc) != NULL)
		return true;

	return false;
}

/*
 * npf_alg_session.  Lookup ALG tuple database, and create an ALG secondary
 * session if packet matches an expected ALG secondary flow.
 *
 * The tuple will contain a pointer to the parent session, which is then
 * linked to the secondary flow child session.
 */
struct npf_session *
npf_alg_session(struct npf_cache *npc, struct rte_mbuf *nbuf,
		const struct ifnet *ifp, const int di, int *error)
{
	struct apt_tuple *nt;
	struct npf_session *se;
	bool do_drop;

	/* Ensure we have an instance struct for the VRF */
	struct npf_alg_instance *ai = vrf_get_npf_alg_rcu(ifp->if_vrfid);
	if (!ai)
		return NULL;

	/*
	 * Search the 'all' ht for an exact match, then the any_sport for a
	 * wildcarded sport
	 */
	nt = alg_search_all_then_any_sport(ai, npc, ifp->if_index);
	if (!nt)
		return NULL;

	/*
	 * Verify the tuple, then expire it so that no other packets find
	 * it. (Note, some tuple are *not* expired here)
	 *
	 * There is one race we are concerned with:
	 *
	 * - Possible receipt of both a forward and reverse packet.
	 *
	 * This race is problematic.  We could wind up with two session
	 * handles, one containing the forward sentry and one containing its
	 * backward sentry. We cannot allow that.  So detect and drop on the
	 * basis of tuple expiration.
	 *
	 * Regardless, expire all tuples for this match.
	 */
	do_drop = apt_tuple_verify_and_expire(ai->ai_apt, nt);

	/* Decide whether we need to drop the racing packet(s).  */
	if (do_drop) {
		*error = -NPF_RC_ALG_EEXIST;
		return NULL;
	}

	/*
	 * Add the tuple to the npc, since establish will call session init.
	 * session_init will init the ALG portion of the handle and link to
	 * parent.
	 *
	 * Note, we are adding an expired tuple to the cache without taking a
	 * reference on it.  This relies on the tuple sticking around until at
	 * least the second garbage collection run after this point.
	 */
	npc->npc_info |= NPC_ALG_TLUP;
	npf_cache_set_tuple(npc, (void *)nt);

	/*
	 * Create the tuple derived session if possible.  Any session returned
	 * will be a child already linked to its parent.
	 *
	 * This is as a consequence of the type of tuples used for child
	 * sessions being distinct to those used for parent sessions, and in
	 * the above we only search said child tuples.
	 */
	se = npf_session_establish(npc, nbuf, ifp, di, error);

	return se;
}

/*
 * ALG inspect for (mostly) non-NATd pkts
 */
void
npf_alg_inspect(struct npf_session *se,	struct npf_cache *npc,
		struct rte_mbuf *nbuf, int di, struct npf_session_alg *sa)
{
	assert(sa);

	/* Is inspection enabled? */
	if (!sa->sa_inspect || !sa->sa_alg)
		return;

	struct npf_alg *alg = (struct npf_alg *)sa->sa_alg;

	/* Call inspect function */
	switch (alg->na_id) {
	case NPF_ALG_ID_FTP:
		/*
		 * Active ftp requires a reverse pinhole in order to detect
		 * data flow from server that might otherwise be blocked.
		 *
		 * Passive ftp requires a forwards 'any src port' pinhole.
		 * This is necessary because we do not know what source port
		 * the client will use for the data flow.
		 */
		if (!npf_iscached(npc, NPC_NATTED))
			ftp_alg_inspect(se, npc, nbuf, alg);
		break;

	case NPF_ALG_ID_TFTP:
		/*
		 * tftp requires a forwards 'any src port' pinhole.  This is
		 * necessary because we do not know what source port the
		 * client will use for the data flow.
		 */
		if (!npf_iscached(npc, NPC_NATTED))
			tftp_alg_inspect(se, npc, nbuf, alg);
		break;

	case NPF_ALG_ID_RPC:
		if (!npf_iscached(npc, NPC_NATTED))
			rpc_alg_inspect(se, npc, nbuf, alg);
		break;

	case NPF_ALG_ID_SIP:
		/*
		 * SIP is the exception here.  It wants to see some NATd pkts
		 * as well.  SIP will only create tuples (pinholes) after
		 * inspecting both Invite Request pkt and 200 Response pkt (or
		 * one with SDP msg).
		 */
		sip_alg_inspect(se, npc, nbuf, alg, di);
		break;
	};
}

/*
 * Associate nat struct with an ALG.  Called for the first packet in a NAT
 * flow.
 *
 * This determines if we associate an ALG with the session nat structure,
 * which in turn determines if npf_alg_nat sees further packets for this
 * session.
 */
void npf_alg_nat_inspect(struct npf_nat *nat, struct npf_session_alg *sa)
{
	struct npf_alg *alg = (struct npf_alg *)sa->sa_alg;
	if (!alg)
		return;

	/* Return if *not* a control session (except rpc) */
	switch (alg->na_id) {
	case NPF_ALG_ID_FTP:
		if (!ftp_alg_cntl_session(sa))
			return;
		break;

	case NPF_ALG_ID_TFTP:
		if (!tftp_alg_cntl_session(sa))
			return;
		break;

	case NPF_ALG_ID_RPC:
		/* Nothing to check */
		break;

	case NPF_ALG_ID_SIP:
		if (!sip_alg_cntl_session(sa))
			return;
		break;
	};

	/*
	 * Associate nat struct with alg.  Set 'nat->nt_alg = alg' and take a
	 * reference on alg.
	 */
	npf_nat_setalg(nat, alg);
}

/*
 * ALG inspect for NATd packets.
 *
 * Look for data flow port info in the packet payload, and creates NAT
 * mappings and tuples (pinholes) if found.  Some ALGs (notably SIP) require
 * to inspect multiple control packets before pinholes can be created, and
 * store state locally during this time (e.g. SIP invite request hash
 * table). Called *before* the layer 3 and layer 4 headers are translated.
 */
int
npf_alg_nat(struct npf_session *se, struct npf_cache *npc,
	    struct rte_mbuf *nbuf, struct npf_nat *nat,
	    const struct npf_alg *alg, const int di)
{
	int rc = 0;

	switch (alg->na_id) {
	case NPF_ALG_ID_FTP:
		rc = ftp_alg_nat(se, npc, nbuf, nat, di);
		break;
	case NPF_ALG_ID_TFTP:
		rc = tftp_alg_nat(se, npc, nbuf, nat, alg, di);
		break;
	case NPF_ALG_ID_RPC:
		rc = rpc_alg_nat(se, npc, nbuf, nat, alg, di);
		break;
	case NPF_ALG_ID_SIP:
		rc = sip_alg_nat(se, npc, nbuf, nat, alg, di);
		break;
	};
	return rc;
}

/*
 * An ALG session is being expired.
 */
void
npf_alg_session_expire(struct npf_session *se, struct npf_session_alg *sa)
{
	assert(sa);
	const struct npf_alg *alg = sa->sa_alg;

	if (!alg)
		return;

	/* Expire any tuples created by this session */
	alg_expire_session_tuples(alg, se);

	/* SIP may also need to expire any unresolved Invites */
	if (alg->na_id == NPF_ALG_ID_SIP)
		sip_alg_session_expire(se);
}


/*
 * npf_alg_session_destroy.  Called when an ALG session is being destroyed.
 *
 * npf_session_destroy (which calls this function) is called under two
 * distinct circumstances:
 *
 * 1. The session was never activated (i.e. never added to the session table),
 * in which case 'sa' will be NULL and this function will not be called, and
 *
 * 2. The dataplane session has expired and been removed from the session
 * table, in which case this function is called from an RCU callback
 * (sf_rcu_destroy).
 */
void npf_alg_session_destroy(struct npf_session *se, struct npf_session_alg *sa)
{
	const struct npf_alg *alg = sa->sa_alg;

	if (!alg) {
		npf_session_set_alg_ptr(se, NULL);
		free(sa);
		return;
	}

	switch (alg->na_id) {
	case NPF_ALG_ID_FTP:
		/*
		 * ftp stores an SNAT mapping in the session private data
		 * (sa_private).  This needs to be released if it was not used
		 * by a tuple.
		 */
		ftp_alg_session_destroy(se);
		break;
	case NPF_ALG_ID_TFTP:
		/* Nothing to do */
		break;
	case NPF_ALG_ID_RPC:
		/*
		 * rpc stores rpc request info in the session private data.
		 * This needs to be freed.
		 */
		rpc_alg_session_destroy(se);
		break;
	case NPF_ALG_ID_SIP:
		/*
		 * sip stores a list of unresolved SIP Request call IDs in the
		 * session private data.  Each call ID may have an entry in
		 * the 'invite' hash table.  These need to be expired, and the
		 * call ID info freed.
		 */
		sip_alg_session_destroy(se);
		break;
	};

	/* Delete any tuples (pinholes) created by this session */
	alg_destroy_session_tuples(alg, se);

	sa->sa_alg = NULL;
	npf_alg_put((struct npf_alg *)alg);

	/* NULL the ALG session ptr in the session and free it */
	npf_session_set_alg_ptr(se, NULL);
	free(sa);
}

/*
 * Reset an alg. Re-installs the default config.
 */
void npf_alg_reset(void)
{
	struct vrf *vrf;
	vrfid_t vrfid;

	VRF_FOREACH(vrf, vrfid)
		alg_reset_instance(vrf, vrf_get_npf_alg_rcu(vrfid));
}

/*
 * npf_alg_cfg
 */
int
npf_alg_cfg(FILE *f, int argc, char **argv)
{
	uint32_t ext_vrfid;

	if (argc < 3) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	/* id is always first arg here */
	ext_vrfid = strtoul(argv[0], NULL, 10);

	/* icmp is deprecated, ignore it */
	if (strcmp(argv[2], "icmp") == 0)
		return 0;

	/* pptp is deprecated, ignore it */
	if (strcmp(argv[2], "pptp") == 0)
		return 0;

	/* rsh is deprecated, ignore it */
	if (strcmp(argv[2], "rsh") == 0)
		return 0;

	/*
	 * Note that ALGs are enabled by default, so the CLI will only
	 * allow a 'disable' to come first.  (A first cmd of 'enable' is
	 * a bug)
	 */
	if (strcmp(argv[1], "enable") == 0) {
		if (npf_alg_state_set(ext_vrfid, argv[2],
					NPF_ALG_CONFIG_ENABLE) < 0) {
			npf_cmd_err(f, "failed to enable alg %s", argv[1]);
			return -1;
		}
		return 0;
	}
	if (strcmp(argv[1], "disable") == 0) {
		if (npf_alg_state_set(ext_vrfid, argv[2],
				      NPF_ALG_CONFIG_DISABLE) < 0) {
			npf_cmd_err(f, "failed to disable alg %s", argv[1]);
			return -1;
		}
		return 0;
	}

	if (argc < 5) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	/*
	 * On a 'delete', we dec the VRF ref count twice.
	 */
	if (strcmp(argv[1], "set") == 0) {
		if (npf_alg_config(ext_vrfid, argv[2], NPF_ALG_CONFIG_SET,
				   argc-3, &argv[3]) < 0) {
			npf_cmd_err(f, "failed to set alg %s config", argv[2]);
			return -1;
		}
		return 0;
	}
	if (strcmp(argv[1], "delete") == 0) {
		if (npf_alg_config(ext_vrfid, argv[2], NPF_ALG_CONFIG_DELETE,
				   argc-3, &argv[3]) < 0) {
			npf_cmd_err(f, "failed to delete alg %s config",
				    argv[2]);
			return -1;
		}
		return 0;
	}

	npf_cmd_err(f, "%s: %s", npf_cmd_str_unknown, argv[0]);
	return -1;
}

struct npf_alg_child_json_ctx {
	json_writer_t	*json;
	struct session	*s;
};

/*
 * Add per-child json for a parent session
 */
static void npf_alg_child_session_json(struct session *child, void *data)
{
	struct npf_alg_child_json_ctx *ctx = data;
	json_writer_t *json = ctx->json;
	struct session *parent = NULL;

	/*
	 * The walk function also calls the callback for the parent session
	 * and grandchild sessions, so we skip them here.  We are only
	 * interested in children.
	 */
	if (child == ctx->s)
		return;

	if (child->se_link)
		parent = child->se_link->sl_parent;

	/* Only return children, not grandchildren */
	if (!parent || parent != ctx->s)
		return;

	jsonw_start_object(json);
	jsonw_uint_field(json, "id", child->se_id);
	jsonw_end_object(json);
}

/*
 * Add ALG info to session json
 */
int npf_alg_session_json(struct json_writer *json, struct npf_session *se,
			 struct npf_session_alg *sa)
{
	struct npf_session *parent;
	struct npf_session *base_parent;
	struct npf_alg *alg;

	assert(sa);
	alg = (struct npf_alg *)sa->sa_alg;

	if (!alg)
		return 0;

	/* Will return NULL if this is a parent */
	parent = npf_session_get_parent(se);

	/* If this is the base parent then base_parent will equal se */
	base_parent = (struct npf_session *)npf_session_get_base_parent(se);

	jsonw_name(json, "alg");
	jsonw_start_object(json);

	jsonw_string_field(json, "name", npf_alg_id2name(alg->na_id));

	if (parent)
		jsonw_uint_field(json, "parent",
				 npf_session_get_id(parent));

	if (base_parent != se && base_parent != parent) {
		jsonw_uint_field(json, "base_parent",
				 npf_session_get_id(base_parent));

		/* Is base parent the grandparent? */
		bool bp_is_gp;

		bp_is_gp = (npf_session_get_parent(parent) == base_parent);
		jsonw_bool_field(json, "bp_is_gp", bp_is_gp);
	}

	/* Walk children */
	jsonw_name(json, "children");
	jsonw_start_array(json);

	struct npf_alg_child_json_ctx ctx = {
		.json = json,
		.s = npf_session_get_dp_session(se),
	};

	session_link_walk(npf_session_get_dp_session(se), false,
			  npf_alg_child_session_json, &ctx);

	jsonw_end_array(json);

	/*
	 * ALG-specific session json
	 */
	if (alg->na_id == NPF_ALG_ID_SIP)
		sip_alg_session_json(json, se);

	jsonw_end_object(json);
	return 0;
}

/*
 * Dump contents of alg tuple tables
 */
void npf_alg_dump(FILE *fp, vrfid_t vrfid)
{
	json_writer_t *json;
	struct npf_alg_instance *ai;
	struct vrf *vrf;

	json = jsonw_new(fp);
	jsonw_name(json, "alg");
	jsonw_start_object(json);

	jsonw_name(json, "instances");
	jsonw_start_array(json);

	if (vrfid == VRF_INVALID_ID) { /* All vrfs... */
		VRF_FOREACH(vrf, vrfid) {
			ai = vrf_get_npf_alg(vrf);
			if (ai)
				alg_dump(ai, vrfid, json);
		}
	} else {
		ai = vrf_get_npf_alg(get_vrf(vrfid));
		if (ai)
			alg_dump(ai, vrfid, json);
	}
	jsonw_end_array(json);

	jsonw_end_object(json);
	jsonw_destroy(&json);
}

/*
 * Returns the name of the ALG a session is associated with, or NULL if
 * it is not associated with an ALG.
 */
const char *npf_alg_name(struct npf_session *se)
{
	struct npf_alg *alg = npf_alg_session_get_alg(se);

	if (alg)
		return npf_alg_id2name(alg->na_id);

	return NULL;
}

