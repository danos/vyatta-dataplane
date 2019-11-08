/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <rte_atomic.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/rproc/npf_rproc.h"

/* Constructor */
static int
npf_ctrdef_ctor(npf_rule_t *rl __unused, const char *params, void **handle)
{
	if (params)
		*handle = NULL;

	return 0;
}

/* Destructor */
static void
npf_ctrdef_dtor(void *handle)
{
	free(handle);
}

/* Generate the json output */
static void
npf_ctrdef_json(json_writer_t *json __unused,
		npf_rule_t *rl __unused,
		const char *params __unused,
		void *handle)
{
	if (!handle)
		return;
}

/* Clear state values */
static void
npf_ctrdef_clear(void *handle)
{
	if (!handle)
		return;
}

/* Counter Definition RPROC ops. */
const npf_rproc_ops_t npf_ctrdef_ops = {
	.ro_name	= "ctr_def",
	.ro_type	= NPF_RPROC_TYPE_HANDLE,
	.ro_id		= NPF_RPROC_ID_CTR_DEF,
	.ro_bidir	= false,
	.ro_ctor	= npf_ctrdef_ctor,
	.ro_dtor	= npf_ctrdef_dtor,
	.ro_json	= npf_ctrdef_json,
	.ro_clear_stats	= npf_ctrdef_clear,
};
