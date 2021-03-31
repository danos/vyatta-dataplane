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

struct npf_alg;

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
};

/* Masks for flag subsets within each ALG */
#define ALG_MASK_CNTL_FLOW	0x000F
#define ALG_MASK_DATA_FLOW	0x00F0

#endif
