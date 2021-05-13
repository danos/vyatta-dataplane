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
#include "npf/cgnat/alg/alg.h"
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

/* Forward references */
static void cgn_alg_session_link(struct cgn_alg_sess_ctx *p_as,
				struct cgn_alg_sess_ctx *c_as);
static void cgn_alg_session_unlink_child(struct cgn_alg_sess_ctx *as);
static void cgn_alg_session_expire_children(struct cgn_alg_sess_ctx *as);


static bool cgn_alg_session_is_parent(struct cgn_alg_sess_ctx *as)
{
	/* as_parent is NULL for parent session and non-NULL for child session */
	return as->as_parent == NULL;
}

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

	CDS_INIT_LIST_HEAD(&as->as_children);
	CDS_INIT_LIST_HEAD(&as->as_link);
	as->as_parent = NULL;
	rte_spinlock_init(&as->as_lock);
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
	struct cgn_session *parent_cse = alg_pinhole_cse(ap);
	struct cgn_alg_sess_ctx *as = NULL;
	enum cgn_alg_id alg_id = alg_pinhole_alg_id(ap);

	assert(parent_cse);

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

	cgn_alg_session_link(cgn_session_alg_get(parent_cse), as);

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
	/* Expire all pinholes matching this session */
	(void)alg_pinhole_tbl_expire_by_session(cse);

	/* If this is a parent session, then expire all children */
	cgn_alg_session_expire_children(as);

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

	/* If this is a child session, then unlink from parent */
	cgn_alg_session_unlink_child(as);
}

/*
 * Sub-session init.  Currently only called when the CGNAT main session is an
 * ALG child sessions.
 */
int cgn_alg_sess2_init(struct cgn_packet *cpk __unused, struct cgn_sess2 *s2)
{
	struct cgn_session *cse = cgn_sess2_session(s2);
	struct cgn_alg_sess_ctx *as;
	int rc = 0;

	as = cgn_session_alg_get(cse);
	if (!as)
		return -1;

	/* Placeholder for hooks into individual ALGs */

	return rc;
}

/*
 * Link a child session to its parent
 */
static void cgn_alg_session_link(struct cgn_alg_sess_ctx *p_as,
				 struct cgn_alg_sess_ctx *c_as)
{
	struct cgn_session *p_cse, *c_cse;

	assert(p_as);
	assert(c_as);
	assert(p_as->as_cse);
	assert(c_as->as_cse);

	p_cse = p_as->as_cse;
	c_cse = c_as->as_cse;

	/* Lock parent while we link child session to it */
	assert(!rte_spinlock_is_locked(&p_as->as_lock));
	rte_spinlock_lock(&p_as->as_lock);

	/* Add child to parents list, and refcnt child */
	cds_list_add_tail(&c_as->as_link, &p_as->as_children);
	(void)cgn_session_get(c_cse);

	/* Add parent pointer to child session, and refcnt parent */
	c_as->as_parent = p_as;
	(void)cgn_session_get(p_cse);

	rte_spinlock_unlock(&p_as->as_lock);
}

/*
 * Unlink a child session from its parent.
 */
static void cgn_alg_session_unlink(struct cgn_alg_sess_ctx *c_as,
				   struct cgn_session *c_cse,
				   struct cgn_alg_sess_ctx *p_as __unused,
				   struct cgn_session *p_cse)
{
	assert(rte_spinlock_is_locked(&p_as->as_lock));

	/* Remove child from parent list and release reference on child */
	cds_list_del_init(&c_as->as_link);
	cgn_session_put(c_cse);

	/* Remove parent pointer from child and release reference on parent */
	c_as->as_parent = NULL;
	cgn_session_put(p_cse);
}

/*
 * Unlink a child session from its parent.  Called if the child session is
 * expired before the parent session.
 */
static void cgn_alg_session_unlink_child(struct cgn_alg_sess_ctx *as)
{
	struct cgn_session *p_cse, *c_cse;
	struct cgn_alg_sess_ctx *p_as;

	p_as = rcu_dereference(as->as_parent);
	if (!p_as)
		return;

	p_cse = p_as->as_cse;
	c_cse = as->as_cse;

	assert(p_as);
	assert(c_cse);

	/* Lock parent session */
	assert(!rte_spinlock_is_locked(&as->as_lock));
	rte_spinlock_lock(&p_as->as_lock);

	/* Was as_parent cleared while waiting for lock? */
	if (!rcu_dereference(as->as_parent)) {
		rte_spinlock_unlock(&p_as->as_lock);
		return;
	}

	cgn_alg_session_unlink(as, c_cse, p_as, p_cse);

	rte_spinlock_unlock(&p_as->as_lock);
}

/*
 * Unlink all child sessions from a parent session, and expire them.
 *
 * Called if the parent session is expired before the child sessions.
 */
static void cgn_alg_session_expire_children(struct cgn_alg_sess_ctx *as)
{
	struct cgn_alg_sess_ctx *c_as, *tmp;

	if (rcu_dereference(as->as_parent))
		/* Not a parent session */
		return;

	assert(!rte_spinlock_is_locked(&as->as_lock));
	rte_spinlock_lock(&as->as_lock);

	cds_list_for_each_entry_safe(c_as, tmp, &as->as_children, as_link) {
		cgn_alg_session_unlink(c_as, c_as->as_cse, as, as->as_cse);
		cgn_session_expire_one(c_as->as_cse);
	}

	rte_spinlock_unlock(&as->as_lock);
}

/*
 * Write json for session ALG info
 */
void cgn_alg_show_session(json_writer_t *json, struct cgn_sess_fltr *fltr __unused,
			  struct cgn_alg_sess_ctx *as)
{
	char str[INET_ADDRSTRLEN];
	bool is_parent;

	if (!as)
		return;

	is_parent = cgn_alg_session_is_parent(as);

	jsonw_name(json, "alg");
	jsonw_start_object(json);

	jsonw_string_field(json, "name", cgn_alg_id_name(as->as_alg_id));

	jsonw_string_field(json, "dst_addr",
			   inet_ntop(AF_INET, &as->as_dst_addr,
				     str, sizeof(str)));
	jsonw_uint_field(json, "dst_port", ntohs(as->as_dst_port));

	/*
	 * Show parent or child specific fields, including IDs of linked
	 * sessions
	 */
	if (is_parent) {
		struct cgn_alg_sess_ctx *c_as;

		jsonw_name(json, "children");
		jsonw_start_array(json);

		cds_list_for_each_entry(c_as, &as->as_children, as_link)
			jsonw_uint(json, cgn_session_id(c_as->as_cse));

		jsonw_end_array(json);

		jsonw_bool_field(json, "inspect", as->as_inspect);
		jsonw_uint_field(json, "min_payload", as->as_min_payload);
	} else {
		uint32_t p_id = 0;

		if (as->as_parent)
			p_id = cgn_session_id(as->as_parent->as_cse);

		jsonw_uint_field(json, "parent", p_id);
	}

	/* ALG specific json */
	switch (as->as_alg_id) {
	case CGN_ALG_NONE:
		break;
	case CGN_ALG_FTP:
		break;
	case CGN_ALG_PPTP:
		break;
	case CGN_ALG_SIP:
		break;
	};

	/*
	 * Show pinholes created by this session.  Only parent sessions might
	 * have created pinholes.
	 */
	if (is_parent)
		cgn_show_pinholes_by_session(json, as);

	jsonw_end_object(json);
}
