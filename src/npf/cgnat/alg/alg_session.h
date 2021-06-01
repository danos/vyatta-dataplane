/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef ALG_SESSION_H
#define ALG_SESSION_H

#include <stdint.h>
#include <urcu/list.h>

#include "vrf.h"
#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_dir.h"
#include "npf/nat/nat_proto.h"
#include "npf/cgnat/alg/alg_defs.h"

struct cgn_session;

/*
 * ALG session context.  This is embedded at the start of every specific ALG
 * session context, e.g. 'struct cgn_alg_ftp_session'.
 */
struct cgn_alg_sess_ctx {
	/* Back pointer to CGNAT main session */
	struct cgn_session	*as_cse;

	/*
	 * Do not rely on as_parent pointer or as_children list to determine
	 * if a session is a parent or child session.
	 */
	bool			as_is_child;

	/* ftp, pptp or sip */
	enum cgn_alg_id		as_alg_id;

	/* as_vrfid and as_proto are used for CGNAT mapping allocation */
	enum nat_proto		as_proto;
	vrfid_t			as_vrfid;

	/* Outbound dest addr and port */
	uint32_t		as_dst_addr;
	uint16_t		as_dst_port;

	/*
	 * as_inspect is set true while we need to examine and/or translate a
	 * packet payload. Only ever set for the parent 'control' session.
	 * Some ALGs such as FTP will set as_inspect to false one the data
	 * flow info has been identified.  Others such as SIP always have
	 * as_inspect enabled.
	 *
	 * Mirrored by cs_alg_inspect in main CGNAT session.
	 */
	bool			as_inspect;

	/*
	 * Each ALG will have its own minimum payload requirement.  This
	 * ensures that, for example, the ftp ALG does not unnecessarily
	 * inspect the TCP handchake pkts.
	 */
	uint16_t		as_min_payload;

	/* Session link - Used by algs to link sessions */
	struct cgn_alg_sess_ctx	*as_parent;
	struct cds_list_head	as_children;
	struct cds_list_head	as_link;
	rte_spinlock_t		as_lock;
};

/**
 * Initialise the common parts of the ALG session context.  'inspect' is set
 * true for control or parent sessions.
 *
 * @param as Pointer to ALG session context
 * @param cse Pointer to main (3-tuple) session
 * @param inspect True for parent sessions, false for child sessions
 */
void cgn_alg_common_session_init(struct cgn_alg_sess_ctx *as,
				 struct cgn_session *cse, bool inspect);

/**
 * Set the inspect flag in the ALG session data and in the main CGNAT session.
 * We mirror it in the main session to avoid packets having to dereference the
 * ALG session data pointer unnecessarily.
 *
 * @param as Pointer to ALG session context
 * @param val New value
 */
void cgn_alg_set_inspect(struct cgn_alg_sess_ctx *as, bool val);

#endif /* ALG_SESSION_H */
