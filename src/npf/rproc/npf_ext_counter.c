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

struct ifnet;
struct rte_mbuf;
struct npf_cache;

/*
 * While multicore safe, this is using atomic operations, and so is
 * not operating at the max possible rate, however it may be good
 * enough for now.
 *
 * This should possibly be replaced with similar logic to that used by
 * the internal rule counters, those counters then being deleted.
 *
 * However that is a memory vs speed tradeoff.
 */
struct rule_ctr {
	rte_atomic64_t	rc_hits;
};

/* Allocate a counter block */
static int
npf_counter_ctor(npf_rule_t *rl __unused, const char *params __unused,
		 void **handle)
{
	/* Memory to store the counter. */
	struct rule_ctr *rule_ctr =
		zmalloc_aligned(sizeof(struct rule_ctr));

	if (!rule_ctr)
		return -ENOMEM;

	rte_atomic64_init(&rule_ctr->rc_hits);

	*handle = rule_ctr;

	return 0;
}

/* Free the counter block */
static void
npf_counter_dtor(void *handle)
{
	free(handle);
}

/* Count it */
static bool
npf_counter_action(struct npf_cache *npc __unused,
		   struct rte_mbuf **nbuf __unused,
		   void *handle, npf_session_t *se __unused,
		   npf_rproc_result_t *result __unused)
{
	struct rule_ctr *rule_ctr = handle;

	rte_atomic64_inc(&rule_ctr->rc_hits);

	return true; // continue rproc processing
}

/* Generate the json output */
static void
npf_counter_json(json_writer_t *json,
		 npf_rule_t *rl __unused,
		 const char *params __unused,
		 void *handle)
{
	if (!handle)
		return;

	struct rule_ctr *rule_ctr = handle;

	uint64_t hits = rte_atomic64_read(&rule_ctr->rc_hits);

	jsonw_uint_field(json, "hits", hits);
}

/* Clear the counter block values */
static void
npf_counter_clear(void *handle)
{
	if (!handle)
		return;

	struct rule_ctr *rule_ctr = handle;

	rte_atomic64_clear(&rule_ctr->rc_hits);
}

/* Counter RPROC ops. */
const npf_rproc_ops_t npf_counter_ops = {
	.ro_name	= "ctr",
	.ro_type	= NPF_RPROC_TYPE_ACTION,
	.ro_id		= NPF_RPROC_ID_COUNTER,
	.ro_bidir	= false,
	.ro_ctor	= npf_counter_ctor,
	.ro_dtor	= npf_counter_dtor,
	.ro_action	= npf_counter_action,
	.ro_json	= npf_counter_json,
	.ro_clear_stats	= npf_counter_clear,
};
