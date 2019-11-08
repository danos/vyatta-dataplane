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

struct rte_mbuf;
struct npf_cache;

/* Constructor */
static int
npf_ctrref_ctor(npf_rule_t *rl __unused, const char *params, void **handle)
{
	if (params)
		*handle = NULL;

	return 0;
}

/* Destructor */
static void
npf_ctrref_dtor(void *handle)
{
	free(handle);
}

/* Packet processing */
static bool
npf_ctrref_action(struct npf_cache *npc __unused,
		  struct rte_mbuf **nbuf __unused,
		  void *handle, npf_session_t *se __unused,
		  npf_rproc_result_t *result __unused)
{
	if (handle)
		return true;

	return true; // continue rproc processing
}

/* Generate the json output */
static void
npf_ctrref_json(json_writer_t *json __unused,
		npf_rule_t *rl __unused,
		const char *params __unused,
		void *handle)
{
	if (!handle)
		return;
}

/* Clear state values */
static void
npf_ctrref_clear(void *handle)
{
	if (!handle)
		return;
}

/* Counter Reference RPROC ops. */
const npf_rproc_ops_t npf_ctrref_ops = {
	.ro_name	= "ctr_ref",
	.ro_type	= NPF_RPROC_TYPE_ACTION,
	.ro_id		= NPF_RPROC_ID_CTR_REF,
	.ro_bidir	= false,
	.ro_ctor	= npf_ctrref_ctor,
	.ro_dtor	= npf_ctrref_dtor,
	.ro_action	= npf_ctrref_action,
	.ro_json	= npf_ctrref_json,
	.ro_clear_stats	= npf_ctrref_clear,
};
