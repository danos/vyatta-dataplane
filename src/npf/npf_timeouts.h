/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_TIMEOUTS_H
#define NPF_TIMEOUTS_H

#include <rte_atomic.h>
#include <stdint.h>

#include "npf/npf_state.h"
#include "npf/npf_cache.h"
#include "urcu.h"
#include "util.h"

struct session;

/*
 * Struct for a timeout instance.
 *
 * to_set_count indicates how many timeouts have been cfgd.  For each timeout
 * configured, we also take a reference on the vrf.
 */
struct npf_timeout {
	rte_atomic32_t	to_refcnt;
	uint32_t	to_set_count;
	uint32_t	to_tcp[NPF_TCP_NSTATES];
	uint32_t	to[NPF_PROTO_IDX_COUNT][SESSION_STATE_SIZE];
};

enum npf_timeout_action {
	TIMEOUT_SET = 0x01,
	TIMEOUT_DEL = 0x02,
};

/* Protos */
int npf_gen_timeout_set(struct npf_timeout *to, enum npf_proto_idx proto_idx,
			enum dp_session_state state, uint32_t tout);
int npf_tcp_timeout_set(struct npf_timeout *to, enum tcp_session_state state,
			uint32_t tout);
uint32_t npf_gen_timeout_get(const npf_state_t *nst,
			     enum dp_session_state state,
			     enum npf_proto_idx proto_idx,
			     const struct session *s);
uint32_t npf_tcp_timeout_get(const npf_state_t *nst,
			     enum tcp_session_state tcp_state,
			     const struct session *s);
void npf_timeout_reset(void);
struct npf_timeout *npf_timeout_create_instance(void);
void npf_timeout_destroy_instance(struct npf_timeout *to);
struct npf_timeout *npf_timeout_ref_get(struct npf_timeout *to);
void npf_timeout_ref_put(struct npf_timeout *to);

#endif  /* NPF_TIMEOUTS_H */
