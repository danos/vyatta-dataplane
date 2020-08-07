/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_log.h>
#include <stdlib.h>

#include "npf/npf_state.h"
#include "npf/npf_timeouts.h"
#include "npf/npf_vrf.h"
#include "urcu.h"
#include "vplane_log.h"

static void timeout_init(struct npf_timeout *to)
{
	enum npf_proto_idx proto;

	to->to_set_count                  = 0;
	to->to_tcp[NPF_TCPS_NONE]         = 0;
		/* Unsynchronised states. */
	to->to_tcp[NPF_TCPS_SYN_SENT]     = 30;
	to->to_tcp[NPF_TCPS_SIMSYN_SENT]  = 30;
	to->to_tcp[NPF_TCPS_SYN_RECEIVED] = 60;
		/* Established: 24 hours. */
	to->to_tcp[NPF_TCPS_ESTABLISHED]  = 60 * 60 * 24;
		/* FIN seen: 4 minutes (2 * MSL). */
	to->to_tcp[NPF_TCPS_FIN_SENT]     = 60 * 2 * 2;
	to->to_tcp[NPF_TCPS_FIN_RECEIVED] = 60 * 2 * 2;
		/* Half-closed cases: 6 hours. */
	to->to_tcp[NPF_TCPS_CLOSE_WAIT]   = 60 * 60 * 6;
	to->to_tcp[NPF_TCPS_FIN_WAIT]     = 60 * 60 * 6;
		/* Full close cases: 30 sec and 2 * MSL. */
	to->to_tcp[NPF_TCPS_CLOSING]      = 30;
	to->to_tcp[NPF_TCPS_LAST_ACK]     = 30;
	to->to_tcp[NPF_TCPS_TIME_WAIT]    = 60 * 2 * 2;
	to->to_tcp[NPF_TCPS_RST_RECEIVED] = 10;
	to->to_tcp[NPF_TCPS_CLOSED]       = 0;

	for (proto = NPF_PROTO_IDX_FIRST; proto <= NPF_PROTO_IDX_LAST;
	     proto++) {
		if (proto == NPF_PROTO_IDX_TCP)
			continue;
		to->to[proto][SESSION_STATE_NONE]		= 0;
		to->to[proto][SESSION_STATE_NEW]		= 30;
		to->to[proto][SESSION_STATE_ESTABLISHED]	= 60;
		to->to[proto][SESSION_STATE_CLOSED]		= 0;
	}
}

/* Take reference on timeout structure */
struct npf_timeout *npf_timeout_ref_get(struct npf_timeout *to)
{
	if (to)
		rte_atomic32_inc(&to->to_refcnt);
	return to;
}

/* Release reference on timeout structure */
void npf_timeout_ref_put(struct npf_timeout *to)
{
	if (to && rte_atomic32_dec_and_test(&to->to_refcnt))
		free(to);
}

/* Set a state timeout */
int npf_timeout_set(vrfid_t vrfid, enum npf_timeout_action action,
		uint8_t proto_idx, uint8_t state, uint32_t tout)
{
	struct npf_timeout *to;
	struct vrf *vrf;

	/*
	 * We can race with VRF creation, so manage VRF reference counts
	 * to maintain state
	 */
	vrf = vrf_find_or_create(vrfid);
	if (!vrf)
		return -EINVAL;
	to = vrf_get_npf_timeout_rcu(vrfid);
	if (!to)
		return -EINVAL;


	/* Manage ref count */
	switch (action) {
	case TIMEOUT_SET:
		vrf_find_or_create(vrfid); /* Inc on set */
		to->to_set_count++;
		break;
	case TIMEOUT_DEL:
		vrf_delete_by_ptr(vrf);   /* Dec on reset */
		to->to_set_count--;
		break;
	};

	if (proto_idx == NPF_PROTO_IDX_TCP)
		to->to_tcp[state] = tout;
	else
		to->to[proto_idx][state] = tout;

	/* Always release initial reference */
	vrf_delete_by_ptr(vrf);
	return 0;
}

/* Get a state timeout */
uint32_t npf_timeout_get(const npf_state_t *nst, uint8_t proto_idx,
		uint32_t custom)
{
	if (npf_state_is_steady(nst, proto_idx) && custom)
		return custom;

	if (proto_idx == NPF_PROTO_IDX_TCP)
		return nst->nst_to->to_tcp[nst->nst_state];

	return nst->nst_to->to[proto_idx][nst->nst_state];
}

static void timeout_reset(struct vrf *vrf, struct npf_timeout *to)
{
	uint32_t count;

	if (!to)
		return;

	/* 'to' may get deleted */
	count = to->to_set_count;
	timeout_init(to);

	while (count--)
		vrf_delete_by_ptr(vrf);
}

/* Reset all VRF timeouts to initial values */
void npf_timeout_reset(void)
{
	struct vrf *vrf;
	vrfid_t vrfid;

	VRF_FOREACH(vrf, vrfid)
		timeout_reset(vrf, vrf_get_npf_timeout_rcu(vrfid));
}

/* Create a timeout instance */
struct npf_timeout *npf_timeout_create_instance(void)
{
	struct npf_timeout *to;

	to = zmalloc_aligned(sizeof(struct npf_timeout));
	if (to) {
		timeout_init(to);
		rte_atomic32_init(&to->to_refcnt);
		npf_timeout_ref_get(to);
	}
	return to;
}

/* Destroy the timeout */
void npf_timeout_destroy_instance(struct npf_timeout *to)
{
	npf_timeout_ref_put(to);
}
