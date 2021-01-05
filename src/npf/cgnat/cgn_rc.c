/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <values.h>
#include <rte_atomic.h>

#include "compiler.h"
#include "util.h"

#include "npf/cgnat/cgn_rc.h"

/* Return code and error counters. */
struct cgn_rc_t *cgn_rc;

uint64_t cgn_rc_read(enum cgn_dir dir, enum cgn_rc_en rc)
{
	uint64_t sum;
	uint i;

	if (rc >= CGN_RC_SZ || dir >= CGN_DIR_SZ || !cgn_rc)
		return 0UL;

	sum = 0UL;
	FOREACH_DP_LCORE(i)
		sum += cgn_rc[i].dir[dir].count[rc];

	return sum;
}

void cgn_rc_clear(enum cgn_dir dir, enum cgn_rc_en rc)
{
	uint i;

	if (rc >= CGN_RC_SZ || dir >= CGN_DIR_SZ || !cgn_rc)
		return;

	FOREACH_DP_LCORE(i)
		cgn_rc[i].dir[dir].count[rc] = 0UL;
}

/*
 * Init cgnat global per-core return code counters
 */
void cgn_rc_init(void)
{
	if (cgn_rc)
		return;

	cgn_rc = zmalloc_aligned((get_lcore_max() + 1) * sizeof(*cgn_rc));
}

void cgn_rc_uninit(void)
{
	free(cgn_rc);
	cgn_rc = NULL;
}
