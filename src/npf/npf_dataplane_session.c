/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_mbuf.h>
#include "compiler.h"
#include "if_var.h"

#include "session/session.h"
#include "session/session_feature.h"

#include "npf/npf_if.h"
#include "npf/npf_cache.h"
#include "npf/npf_rc.h"
#include "npf/npf_session.h"
#include "npf/npf_nat.h"
#include "npf/npf_nat64.h"
#include "npf/npf_state.h"
#include "npf/npf_dataplane_session.h"

/* Initial session creation timeout - can be virtually anything */
#define INITIAL_TIMEOUT 5

static int nat_session_establish(npf_cache_t *npc, struct rte_mbuf *nbuf,
		npf_nat_t *nt, const struct ifnet *ifp,
		uint32_t timeout, struct session **ss, bool *created)
{
	const void *saddr = NULL;
	const void *daddr = NULL;
	uint16_t sid = 0;
	uint16_t did = 0;
	uint16_t flags;
	struct sentry_packet sp_forw, sp_tmp, sp_back;
	int rc;

	npf_nat_get_original_tuple(nt, npc, &saddr, &sid, &daddr, &did);

	if (npf_iscached(npc, NPC_IP6))
		flags = SENTRY_IPv6;
	else
		flags = SENTRY_IPv4;

	rc = session_init_sentry_packet(&sp_forw, ifp->if_index, flags,
			npf_cache_ipproto(npc), ifp->if_vrfid, sid, saddr,
			did, daddr);
	if (rc)
		return rc;

	/* Packet has already been natted, so create backward sentry from it. */
	rc = sentry_packet_from_mbuf(nbuf, ifp->if_index, &sp_tmp);
	if (rc)
		return rc;

	sentry_packet_reverse(&sp_tmp, &sp_back);

	rc = session_create_from_sentry_packets(nbuf, &sp_forw, &sp_back,
			ifp, timeout, ss, created);
	if (rc)
		return rc;

	/* Mark this session as containing NAT */
	if (npf_nat_type(nt) == NPF_NATOUT)
		session_set_snat(*ss);
	else
		session_set_dnat(*ss);

	return 0;
}

/* Feature operations */
static void dps_feature_expire(struct session *s __unused,
		uint32_t if_index __unused,
		enum session_feature_type type __unused,
		void *data)
{
	npf_session_t *se = data;

	npf_session_expire(se);
}

static void dps_feature_destroy(struct session *s __unused,
		uint32_t if_index __unused,
		enum session_feature_type type __unused, void *data)
{
	npf_session_t *se = data;

	npf_session_destroy(se);
}

static void dps_feature_json(json_writer_t *json, struct session_feature *sf)
{
	npf_session_t *se = sf->sf_data;

	npf_session_feature_json(json, se);
}

static void dps_feature_log(enum session_log_event event, struct session *s,
			    struct session_feature *sf)
{
	npf_session_feature_log(event, s, sf);
}

/* Callbacks for the npf_session_t */
static const struct session_feature_ops ops = {
	.expired = dps_feature_expire,
	.destroy = dps_feature_destroy,
	.json = dps_feature_json,
	.log = dps_feature_log,
};

/*
 * Create a dataplane session and add the npf session as a feature.  Returns 0
 * for success or -NPF_RC_DP_SESS_ESTB for failure.
 */
int npf_dataplane_session_establish(npf_session_t *se, npf_cache_t *npc,
		struct rte_mbuf *nbuf, const struct ifnet *ifp)
{

	npf_nat_t *nt = npf_session_get_nat(se);
	struct session *s = NULL;
	bool created;
	uint32_t timeout;
	int rc;

	/*
	 * sessions must be created with a non-zero initial timeout,
	 * note we update the timeout immediately after session creation.
	 */
	timeout = INITIAL_TIMEOUT;

	if (nt)
		rc = nat_session_establish(npc, nbuf, nt, ifp, timeout,
				&s, &created);
	else
		rc = session_establish(nbuf, ifp, timeout, &s, &created);

	if (rc) {
		npf_session_destroy(se);
		return -NPF_RC_DP_SESS_ESTB;
	}

	/* Get a custom session timeout, if configured */
	timeout = npf_state_get_custom_timeout(ifp->if_vrfid, npc, nbuf);
	if (timeout)
		session_set_custom_timeout(s, timeout);

	/* Cache dataplane session on npf session */
	npf_session_set_dp_session(se, s);

	/* Update the dataplane state/timeout */
	npf_session_update_state(se);

	/* Now add the npf session as a feature datum */
	rc = session_feature_add(s, ifp->if_index, SESSION_FEATURE_NPF, se);
	if (rc) {
		npf_session_destroy(se);
		goto bad;
	}

	/*
	 * If this is an ALG secondary session, link,
	 * and mark it as such.
	 */
	if (npf_session_is_child(se)) {
		npf_session_t *parent = npf_session_get_parent(se);

		rc = session_link(npf_session_get_dp_session(parent), s);
		if (rc)
			goto bad;

		/* Mark both the parent and child as alg sessions */
		session_set_alg(npf_session_get_dp_session(parent));
		session_set_alg(s);
	}

	/*
	 * If this is a nat64 or nat46 session, link, and mark it as such.
	 */
	if (npf_session_is_nat64(se)) {
		struct npf_nat64 *n64 = npf_session_get_nat64(se);
		/*
		 * If this session is a NAT64 peer session, link dataplane
		 * sessions.
		 */
		if (npf_nat64_has_peer(n64)) {
			rc = npf_nat64_session_link(
				npf_nat64_get_peer(n64), se);
			if (rc)
				goto bad;
		}

		if (npf_nat64_session_is_nat64(se))
			session_set_nat64(s);
		else
			session_set_nat46(s);
	}
	assert(rc == 0);
	return 0;
bad:
	if (created)
		session_expire(s, nbuf);
	return -NPF_RC_DP_SESS_ESTB;
}

static void __attribute__((constructor)) npf_dataplane_session_init(void)
{
	session_feature_register(SESSION_FEATURE_NPF, &ops);
}
