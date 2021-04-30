/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <values.h>

#include "compiler.h"
#include "util.h"

#include "npf/cgnat/alg/alg_rc.h"


/* Return code and error counters. */
struct alg_rc_t *alg_rc;

uint64_t alg_rc_read(enum cgn_dir dir, enum alg_rc_en rc)
{
	uint64_t sum;
	uint i;

	if (rc >= ALG_RC_SZ || dir >= CGN_DIR_SZ || !alg_rc)
		return 0UL;

	sum = 0UL;
	FOREACH_DP_LCORE(i)
		sum += alg_rc[i].dir[dir].count[rc];

	return sum;
}

void alg_rc_clear(enum cgn_dir dir, enum alg_rc_en rc)
{
	uint i;

	if (rc >= ALG_RC_SZ || dir >= CGN_DIR_SZ || !alg_rc)
		return;

	FOREACH_DP_LCORE(i)
		alg_rc[i].dir[dir].count[rc] = 0UL;
}

/*
 * Init CGNAT ALG global per-core return code counters
 */
void alg_rc_init(void)
{
	if (alg_rc)
		return;

	alg_rc = zmalloc_aligned((get_lcore_max() + 1) * sizeof(*alg_rc));
}

void alg_rc_uninit(void)
{
	free(alg_rc);
	alg_rc = NULL;
}
