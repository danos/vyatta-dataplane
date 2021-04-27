/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <values.h>

#include "json_writer.h"
#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_sess2.h"

#include "npf/cgnat/alg/alg_public.h"
#include "npf/cgnat/alg/alg_pinhole.h"
#include "npf/cgnat/alg/alg_session.h"


/*
 * Min and max payload lengths:
 *
 *		Min	Max
 * ftp		11	255
 * sip		200	8000
 * rpc		28	256
 *
 * The minimum payload length helps to determine if we should inspect the
 * packet or not.  For example, there is no point in passing the FTP TCP
 * handshake pkts to the FTP ALG inspection function.
 *
 * However, the minimums specified here may be 'minimum minimums'.  In other
 * words, once an ALG parses a pkt further it may then determine that the pkt
 * still does not meet the min pkt size requirement.
 */
uint cgn_alg_payload_min[CGN_ALG_MAX] = {
	[CGN_ALG_NONE] = 0,
	[CGN_ALG_FTP] = 11,
	[CGN_ALG_PPTP] = 16,
	[CGN_ALG_SIP] = 200,
};

/*
 * Set the inspect flag in the ALG session data and in the main CGNAT session.
 * We mirror it in the main session to avoid packets having to dereference the
 * ALG session data pointer unnecessarily.
 *
 * 'as_inspect' will be true for control sessions and false for data sessions.
 * Some control sessions will subsequently set 'as_inspect' to false when they
 * no longer need to inspect packet payloads.
 */
void cgn_alg_set_inspect(struct cgn_alg_sess_ctx *as, bool val)
{
	as->as_inspect = val;
	cgn_session_set_alg_inspect(as->as_cse, val);
}

/*
 * Called by the individual ALGs after the ALG session context has been
 * created in order to initialise common objects that need to be initialised
 * *before* the ALG-specific initialisation.
 *
 * cgn_alg_session_init
 *     cgn_alg_parent_session_init
 *         (specific alg session init))
 *             (this function)
 */
void cgn_alg_common_session_init(struct cgn_alg_sess_ctx *as,
				 struct cgn_session *cse, bool inspect)
{
	as->as_cse = cse;
	as->as_vrfid = cgn_session_vrfid(as->as_cse);
	cgn_alg_set_inspect(as, inspect);

	/* Save pointer to alg ctx in main cgnat session */
	cgn_session_alg_set(cse, as);
}

/*
 * A new CGNAT ALG control session has just been created.
 */
static struct cgn_alg_sess_ctx *
cgn_alg_parent_session_init(struct cgn_session *cse __unused,
			    enum nat_proto proto,
			    enum cgn_alg_id alg_id)
{
	struct cgn_alg_sess_ctx *as = NULL;

	switch (alg_id) {
	case CGN_ALG_FTP:
		break;

	case CGN_ALG_PPTP:
		break;

	case CGN_ALG_SIP:
		break;

	case CGN_ALG_NONE:
		break;
	}

	if (!as)
		return NULL;

	/*
	 * Initialise remainder of common session context.  Initialisation
	 * that need to occur before the ALG-specific initialisation should be
	 * done in cgn_alg_common_session_init.
	 */
	as->as_alg_id = alg_id;
	as->as_proto = proto;
	as->as_min_payload = cgn_alg_payload_min[alg_id];

	return as;
}

/*
 * A new CGNAT ALG data session has just been created.
 */
static struct cgn_alg_sess_ctx *
cgn_alg_child_session_init(struct cgn_session *child_cse, enum nat_proto proto,
			   struct alg_pinhole *ap)
{
	struct cgn_alg_sess_ctx *as = NULL;
	enum cgn_alg_id alg_id = alg_pinhole_alg_id(ap);

	switch (alg_id) {
	case CGN_ALG_FTP:
		break;

	case CGN_ALG_PPTP:
		break;

	case CGN_ALG_SIP:
		break;

	case CGN_ALG_NONE:
		break;
	}

	if (!as)
		return NULL;

	as->as_alg_id = alg_id;
	as->as_proto = proto;

	cgn_session_alg_set(child_cse, as);

	return as;
}

/*
 * A new CGNAT session has just been created for an ALG flow.
 *
 * An ALG flow is identified by either:
 *
 * 1. the destination port matching a well-known port value (ftp, sip etc), or
 * 2. the packet matching an ALG pinhole tuple.
 *
 * #1 is a parent/control flow.  #2 is a child/data flow.
 *
 * There is some back and forth between the common ALG code and specific ALG
 * code in order to initialise the ALG session context in the required order,
 * e.g.:
 *
 * cgn_alg_session_init
 *     cgn_alg_parent_session_init
 *         (specific alg session init))
 *             cgn_alg_common_session_init
 */
int cgn_alg_session_init(struct cgn_packet *cpk, struct cgn_session *cse,
			 enum cgn_dir dir)
{
	struct cgn_alg_sess_ctx *as = NULL;

	assert(cpk->cpk_alg_id);

	if (!cpk->cpk_alg_pinhole)
		/* Control (Parent) flow */
		as = cgn_alg_parent_session_init(cse, cpk->cpk_proto,
						 cpk->cpk_alg_id);
	else
		/* Data (Child) flow */
		as = cgn_alg_child_session_init(cse, cpk->cpk_proto,
						cpk->cpk_alg_pinhole);

	assert(as);
	if (!as)
		return -CGN_ALG_ERR_SESS;

	/* Set convenience flag in CGNAT session */
	if (!cpk->cpk_alg_pinhole)
		cgn_session_set_alg_parent(cse, true);
	else
		cgn_session_set_alg_child(cse, true);

	/* Store the address and port of the public host */
	if (dir == CGN_DIR_OUT) {
		as->as_dst_addr = cpk->cpk_daddr;
		as->as_dst_port = cpk->cpk_did;
	} else {
		as->as_dst_addr = cpk->cpk_saddr;
		as->as_dst_port = cpk->cpk_sid;
	}

	return 0;
}

/*
 * A CGNAT session has just been expired. Undo cgn_alg_session_init.
 *
 * Note that the session 'expired' flag will have already been set so the
 * session will no longer be findable by pkts in the session table.
 */
void cgn_alg_session_uninit(struct cgn_session *cse __unused,
			    struct cgn_alg_sess_ctx *as)
{
	switch (as->as_alg_id) {
	case CGN_ALG_FTP:
		break;

	case CGN_ALG_PPTP:
		break;

	case CGN_ALG_SIP:
		break;

	case CGN_ALG_NONE:
		break;
	}
}
