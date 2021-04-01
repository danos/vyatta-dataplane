/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_SESSION_H_
#define _ALG_SESSION_H_

/*
 * Private to the npf ALGs
 */

#include <stdint.h>
#include "npf/alg/alg_rpc_msg.h"
#include "npf/alg/alg_sip_session.h"

struct npf_session;
struct npf_nat;
struct npf_alg;

/**
 * RPC ALG session private data
 *
 * RPC stores the parsed request info until it sees the RPC response.
 * Re-transmssions of the request may occur, in which case the pointer is
 * simply replaced.
 */
struct rpc_alg_session {
	/* Interesting params parsed from an RPC Request msg */
	struct rpc_request	sar_request;
};

/**
 * ALG session context.
 *
 * Pointed-to in 'struct npf_session' by 's_alg'.  Accessed from the npf
 * session via npf_session_get_alg_ptr and npf_session_set_alg_ptr
 *
 * sa_alg  ALG instance handle
 * sa_private  Private data specific to each ALG
 * sa_flags  Flags specific to each ALG
 * sa_inspect  Enables inspection for (mostly) non-NATd pkts
 */
struct npf_session_alg {
	const struct npf_alg	*sa_alg;
	void			*sa_private;
	uint32_t		sa_flags;
	bool			sa_inspect;

	/* rtp and tftp ALGs do not have session data */
	union {
		struct rpc_alg_session	sa_rpc;
		struct sip_alg_session	sa_sip;
	};
};

/* Masks for flag subsets within each ALG */
#define ALG_MASK_CNTL_FLOW	0x000F
#define ALG_MASK_DATA_FLOW	0x00F0

void npf_alg_session_set_private(struct npf_session *se, void *data);
void *npf_alg_session_get_private(const struct npf_session *se);
void *npf_alg_session_get_and_set_private(const npf_session_t *se, void *data);

int npf_alg_session_test_flag(const struct npf_session *se, uint32_t flag);
void npf_alg_session_set_flag(struct npf_session *se, uint32_t flag);
uint32_t npf_alg_session_get_flags(const struct npf_session *se);
bool npf_alg_cntl_session(struct npf_session *se);
bool npf_alg_data_session(struct npf_session *se);
void npf_alg_session_set_inspect(struct npf_session *se, bool v);
int npf_alg_session_set_alg(struct npf_session *se, const struct npf_alg *alg);
void npf_alg_session_clear_alg(struct npf_session *se,
			       struct npf_session_alg *sa);
struct npf_alg *npf_alg_session_get_alg(const struct npf_session *se);
struct npf_nat *npf_alg_parent_nat(struct npf_session *se);

#endif
