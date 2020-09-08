/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 2009-2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef NPF_STATE_H
#define NPF_STATE_H

#include <assert.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>

#include "npf/npf_cache.h"
#include "npf/npf_ruleset.h"
#include "util.h"
#include "vrf_internal.h"
#include "dp_session.h"

struct rte_mbuf;
struct npf_pack_session_state;

/* Forward Declarations */
typedef struct npf_cache npf_cache_t;

/*
 * NPF TCP states.  Note: these states are different from the TCP FSM
 * states of RFC 793.  The packet filter is a man-in-the-middle.
 */
typedef enum {
	NPF_TCPS_NONE = 0,
	NPF_TCPS_SYN_SENT,
	NPF_TCPS_SIMSYN_SENT,
	NPF_TCPS_SYN_RECEIVED,
	NPF_TCPS_ESTABLISHED,
	NPF_TCPS_FIN_SENT,
	NPF_TCPS_FIN_RECEIVED,
	NPF_TCPS_CLOSE_WAIT,
	NPF_TCPS_FIN_WAIT,
	NPF_TCPS_CLOSING,
	NPF_TCPS_LAST_ACK,
	NPF_TCPS_TIME_WAIT,
	NPF_TCPS_RST_RECEIVED,
	NPF_TCPS_CLOSED,
} TCP_STATES;

#define NPF_TCPS_FIRST		NPF_TCPS_NONE
#define NPF_TCPS_LAST		NPF_TCPS_CLOSED
#define NPF_TCP_NSTATES		(NPF_TCPS_LAST + 1)

/*
 * NPF_TCPS_OK is used to denote that *no* state change should take place.
 * It *must* be greater than NPF_TCPS_LAST.
 */
#define NPF_TCPS_OK		NPF_TCP_NSTATES
#define NPF_TCPS_ERR		(NPF_TCP_NSTATES + 1)


/* State statistics struct */
struct npf_state_stats {
	uint32_t ss_tcp_ct[NPF_TCP_NSTATES];
	uint32_t ss_ct[NPF_PROTO_IDX_COUNT][SESSION_STATE_SIZE];
	uint32_t ss_nat_cnt; /* used only for session_summary */
};

#define	NPF_FLOW_FORW		0
#define	NPF_FLOW_BACK		1

typedef struct {
	uint32_t	nst_end;
	uint32_t	nst_maxend;
	uint32_t	nst_maxwin;
	uint8_t		nst_wscale;
	uint8_t		nst_pad[3];
} npf_tcpstate_t;

static_assert(sizeof(npf_tcpstate_t) == 16, "npf_tcpstate_t != 16");

typedef struct {
	rte_spinlock_t		nst_lock;
	uint8_t			nst_state;
	uint8_t			nst_pad[3];
	npf_tcpstate_t		nst_tcpst[2];
	struct npf_timeout	*nst_to;
} npf_state_t;

static_assert(sizeof(npf_state_t) == 48, "npf_state_t != 48");

static inline bool
npf_state_tcp_state_is_valid(uint8_t state)
{
	assert(NPF_TCPS_FIRST == 0);
	return state <= NPF_TCPS_LAST;
}

static inline bool
npf_state_is_valid(uint8_t proto_idx, uint8_t state)
{
	if (proto_idx == NPF_PROTO_IDX_TCP)
		return npf_state_tcp_state_is_valid(state);
	else
		return dp_session_state_is_valid(state);
}

/*
 * Get generic state.  Non-TCP protocols already use generic state.
 * Convert TCP state to generic state.
 */
static inline enum dp_session_state
npf_state_get_generic_state(uint8_t proto_idx, uint8_t state)
{
	if (proto_idx != NPF_PROTO_IDX_TCP) {
		if (dp_session_state_is_valid(state))
			return (enum dp_session_state)state;
		else
			return SESSION_STATE_NONE;
	}

	switch (state) {
	case NPF_TCPS_NONE:
		return SESSION_STATE_NONE;
	case NPF_TCPS_SYN_SENT:
	case NPF_TCPS_SIMSYN_SENT:
	case NPF_TCPS_SYN_RECEIVED:
		return SESSION_STATE_NEW;
	case NPF_TCPS_ESTABLISHED:
		return SESSION_STATE_ESTABLISHED;
	case NPF_TCPS_FIN_SENT:
	case NPF_TCPS_FIN_RECEIVED:
	case NPF_TCPS_CLOSE_WAIT:
	case NPF_TCPS_FIN_WAIT:
	case NPF_TCPS_CLOSING:
	case NPF_TCPS_LAST_ACK:
	case NPF_TCPS_TIME_WAIT:
	case NPF_TCPS_RST_RECEIVED:
		return SESSION_STATE_TERMINATING;
	case NPF_TCPS_CLOSED:
		return SESSION_STATE_CLOSED;
	};
	return SESSION_STATE_CLOSED;
}

static inline bool npf_state_is_established(uint8_t proto, uint8_t state)
{
	if (proto == IPPROTO_TCP)
		return state == NPF_TCPS_ESTABLISHED;
	return state == SESSION_STATE_ESTABLISHED;
}

static inline bool npf_state_is_closing(uint8_t proto, uint8_t state)
{
	if (proto == IPPROTO_TCP)
		return state > NPF_TCPS_ESTABLISHED;
	return state > SESSION_STATE_ESTABLISHED;
}

void npf_state_stats_create(void);
void npf_state_stats_destroy(void);
bool npf_state_init(vrfid_t vrfid, uint8_t proto_idx, npf_state_t *nst);
void npf_state_destroy(npf_state_t *nst, uint8_t proto_idx);
int npf_state_inspect(const npf_cache_t *npc, struct rte_mbuf *nbuf,
		      npf_state_t *nst, bool forw);
void npf_state_update_session_state(struct session *s, uint8_t proto_idx,
		const npf_state_t *nst);
void npf_state_set_closed_state(npf_state_t *nst, bool lock, uint8_t proto_idx);
const char *npf_state_get_state_name(uint8_t state, uint8_t proto_idx);
bool npf_state_is_steady(const npf_state_t *nst, const uint8_t proto_idx);
bool npf_tcp_state_is_closed(const npf_state_t *nst, const uint8_t proto_idx);
enum dp_session_state npf_map_str_to_generic_state(const char *state);
uint8_t npf_map_str_to_tcp_state(const char *state);
uint32_t npf_state_get_custom_timeout(vrfid_t vrfid, npf_cache_t *npc,
				      struct rte_mbuf *nbuf);
void npf_state_stats_json(json_writer_t *json);
#ifdef _NPF_TESTING
void npf_state_dump(const npf_state_t *nst);
#endif

void npf_session_state_change(npf_state_t *nst, uint8_t old_state,
			      uint8_t new_state, uint8_t proto_idx);

void npf_state_set_icmp_strict(bool value);

/* npf_state_tcp.c */

void npf_state_tcp_init(void);

/*
 * npf_state_tcp returns either:
 *  1. the new TCP state,
 *  2. NPF_TCPS_OK, if no state change is required, or
 *  3. '*error' < 0 if the packet should be discarded
 */
uint8_t npf_state_tcp(const npf_cache_t *npc, struct rte_mbuf *nbuf,
		      npf_state_t *nst, int di, int *error);
uint32_t npf_state_get_tcp_seq(int di, npf_state_t *nst);

void npf_state_set_tcp_strict(bool value);

int npf_state_npf_pack_update(npf_state_t *nst,
			      struct npf_pack_session_state *pst,
			      uint8_t state, uint8_t proto_idx);

#endif  /* NPF_STATE_H */
