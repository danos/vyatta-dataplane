/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * npf return code counters
 */

#include <json_writer.h>

#include "util.h"
#include "npf/npf_rc.h"

/*
 * Create npf counters.  A set of counters is created per npf interface.
 */
struct npf_rc_counts *npf_rc_counts_create(void)
{
	struct npf_rc_counts *rcc;

	assert(PFIL2RC(PFIL_IN) == NPF_RC_IN);
	assert(PFIL2RC(PFIL_OUT) == NPF_RC_OUT);

	rcc = zmalloc_aligned((get_lcore_max() + 1) *
			      sizeof(struct npf_rc_counts));

	return rcc;
}

void npf_rc_counts_destroy(struct npf_rc_counts **rcc)
{
	if (*rcc) {
		free(*rcc);
		*rcc = NULL;
	}
}
