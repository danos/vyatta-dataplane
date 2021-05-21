/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <values.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include "util.h"
#include "json_writer.h"
#include "soft_ticks.h"
#include "in_cksum.h"

#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/nat/nat_pool_event.h"
#include "npf/nat/nat_pool_public.h"

#include "npf/cgnat/alg/alg.h"
#include "npf/cgnat/alg/alg_rc.h"
#include "npf/cgnat/alg/alg_pinhole.h"
#include "npf/cgnat/alg/alg_pptp.h"
#include "npf/cgnat/alg/alg_session.h"

/*
 * ALG PPTP Session (sub-session) context
 *
 * Mapping info is saved to session when the PPTP_OUT_CALL_REQ msg is seen,
 * and then used to create pinhole when subsequent PPTP_OUT_CALL_REPLY msg is
 * seen.
 */
struct cgn_alg_pptp_session {
	/* Must always be first */
	struct cgn_alg_sess_ctx	aps_as;
	struct cgn_map		aps_cmi;

	/*
	 * Call ID in outbound TCP control/parent pkts is translated from
	 * aps_orig_call_id to aps_trans_call_id
	 *
	 * Peer call ID in inbound TCP control/parent pkts is translated from
	 * aps_trans_call_id to aps_orig_call_id
	 *
	 * Call ID in inbound GRE data/child pkts is translated from
	 * aps_trans_call_id to aps_orig_call_id.  (outbound GRE pkts require
	 * no payload translation)
	 *
	 * aps_orig_call_id and aps_trans_call_id are set when the outbound
	 * PPTP_OUT_CALL_REQ TCP ctrl msg is seen.
	 *
	 * aps_peer_call_id is set when the subsequent inbound
	 * PPTP_OUT_CALL_REPLY TCP ctrl msg is seen.
	 */
	uint16_t	aps_orig_call_id;	/* client inside call ID */
	uint16_t	aps_trans_call_id;	/* client outside call ID */
	uint16_t	aps_peer_call_id;	/* server call ID */
};

static_assert(offsetof(struct cgn_alg_pptp_session, aps_as) == 0,
	      "cgn_alg_pptp_session: aps_as not first");

#define aps_cse		aps_as.as_cse
#define aps_vrfid	aps_as.as_vrfid
#define aps_proto	aps_as.as_proto
#define aps_min_payload	aps_as.as_min_payload


/*
 * Initialise PPTP child session (enhanced GRE)
 */
static void
cgn_alg_pptp_child_sess_init(struct alg_pinhole *ap,
			     struct cgn_alg_pptp_session *aps)
{
	struct cgn_alg_pptp_session *parent_aps;
	struct cgn_alg_sess_ctx *parent_as;
	struct cgn_session *parent_cse;

	parent_cse = alg_pinhole_cse(ap);
	parent_as = cgn_session_alg_get(parent_cse);
	parent_aps = caa_container_of(parent_as, struct cgn_alg_pptp_session,
				      aps_as);

	/*
	 * aps_orig_call_id and aps_trans_call_id are setup in the parent
	 * session when the PPTP_OUT_CALL_REQ msg is inspected.
	 *
	 * aps_peer_call_id is setup in the parent session when the
	 * PPTP_OUT_CALL_REPLY msg is inspected.
	 */
	aps->aps_orig_call_id = parent_aps->aps_orig_call_id;
	aps->aps_trans_call_id = parent_aps->aps_trans_call_id;
	aps->aps_peer_call_id = parent_aps->aps_peer_call_id;
}

/*
 * A new CGNAT 5-tuple session has just been created.
 *
 * If 'te' is set then it is a child session, else it is a parent session.
 */
struct cgn_alg_sess_ctx *
cgn_alg_pptp_sess_init(struct cgn_session *cse, struct alg_pinhole *ap)
{
	struct cgn_alg_pptp_session *aps;

	aps = zmalloc_aligned(sizeof(*aps));
	if (!aps)
		return NULL;

	struct cgn_alg_sess_ctx *as = &aps->aps_as;

	/* Set 'inspect' if this is parent flow (!ap) */
	cgn_alg_common_session_init(as, cse, !ap);

	if (ap)
		/* Child flow */
		cgn_alg_pptp_child_sess_init(ap, aps);

	return as;
}

void cgn_alg_pptp_sess_uninit(struct cgn_alg_sess_ctx *as)
{
	struct cgn_alg_pptp_session *aps;

	aps = caa_container_of(as, struct cgn_alg_pptp_session, aps_as);

	/* free any unused GRE session mapping */
	if (aps && aps->aps_cmi.cmi_reserved)
		cgn_map_put(&aps->aps_cmi, aps->aps_vrfid);
}

/*
 * Init PPTP child (GRE) sub-session
 *
 * Adjust the sub-session sentry.  The ID/port needs to change to match the
 * translation ID.
 */
int cgn_alg_pptp_child_sess2_init(struct cgn_alg_sess_ctx *as,
				  struct cgn_sess2 *s2)
{
	struct cgn_alg_pptp_session *aps;

	aps = caa_container_of(as, struct cgn_alg_pptp_session, aps_as);

	cgn_sess2_set_sentry_id(s2, CGN_DIR_OUT, aps->aps_peer_call_id);
	cgn_sess2_set_sentry_id(s2, CGN_DIR_IN, aps->aps_trans_call_id);

	return 0;
}

/*
 * Write json for ALG PPTP session info
 */
void cgn_alg_show_pptp_session(json_writer_t *json,
			      struct cgn_alg_sess_ctx *as)
{
	struct cgn_alg_pptp_session *aps;

	aps = caa_container_of(as, struct cgn_alg_pptp_session, aps_as);
	(void)aps;

	jsonw_name(json, "pptp");
	jsonw_start_object(json);

	jsonw_uint_field(json, "orig_call_id", ntohs(aps->aps_orig_call_id));
	jsonw_uint_field(json, "trans_call_id", ntohs(aps->aps_trans_call_id));
	jsonw_uint_field(json, "peer_call_id", ntohs(aps->aps_peer_call_id));

	cgn_map_json(json, "mapping", &aps->aps_cmi);

	jsonw_end_object(json);
}
