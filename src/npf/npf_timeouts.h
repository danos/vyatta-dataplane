/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
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
	uint32_t	to[NPF_PROTO_IDX_COUNT][NPF_ANY_SESSION_NSTATES];
};

enum npf_timeout_action {
	TIMEOUT_SET = 0x01,
	TIMEOUT_DEL = 0x02,
};

/* Protos */
int npf_timeout_set(vrfid_t vrfid, enum npf_timeout_action action,
		uint8_t proto_idx, uint8_t state, uint32_t tout);
uint32_t npf_timeout_get(const npf_state_t *nst, uint8_t proto_idx,
		uint32_t custom);
void npf_timeout_reset(void);
struct npf_timeout *npf_timeout_create_instance(void);
void npf_timeout_destroy_instance(struct npf_timeout *to);
struct npf_timeout *npf_timeout_ref_get(struct npf_timeout *to);
void npf_timeout_ref_put(struct npf_timeout *to);

#endif  /* NPF_TIMEOUTS_H */
