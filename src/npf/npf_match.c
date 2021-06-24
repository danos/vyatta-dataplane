/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Abstraction for a packet matching utility. Used to provide the ability
 * to use different packet matching algorithms depending on the ruleset
 * type.
 *
 * If no callback table is registered, the abstraction uses grouper2 by default
 */
#include "npf_match.h"
#include "npf_grouper.h"

static npf_match_cb_tbl * npf_match_cbs[NPF_RS_TYPE_COUNT];

int npf_match_init(enum npf_ruleset_type rs_type, int af, const char *name,
		   uint32_t max_rules, npf_match_ctx_t **ctx)
{
	npf_match_cb_tbl *tbl;

	tbl = npf_match_cbs[rs_type];
	if (tbl)
		return tbl->npf_match_init_cb(af, name, max_rules, ctx);

	return npf_grouper_init(af, (g2_config_t **)ctx);
}

int npf_match_add_rule(enum npf_ruleset_type rs_type,
		       int af, npf_match_ctx_t *ctx,
		       uint32_t rule_no, uint8_t *match_addr, uint8_t *mask,
		       void *match_ctx)
{
	npf_match_cb_tbl *tbl;

	tbl = npf_match_cbs[rs_type];
	if (tbl)
		return tbl->npf_match_add_rule_cb(af, ctx, rule_no,
						  match_addr, mask, match_ctx);

	return npf_grouper_add_rule(af, (g2_config_t *)ctx, rule_no,
				    match_addr, mask, match_ctx);
}

int npf_match_build(enum npf_ruleset_type rs_type,
		    int af, npf_match_ctx_t **ctx)
{
	npf_match_cb_tbl *tbl;

	tbl = npf_match_cbs[rs_type];
	if (tbl)
		return tbl->npf_match_build_cb(af, ctx);

	return npf_grouper_build((g2_config_t **)ctx);
}

int npf_match_classify(enum npf_ruleset_type rs_type,
		       int af, npf_match_ctx_t *ctx,
		       npf_cache_t *npc, struct npf_match_cb_data *data,
		       npf_rule_t **rl)
{
	npf_match_cb_tbl *tbl;

	tbl = npf_match_cbs[rs_type];
	if (tbl)
		return tbl->npf_match_classify_cb(af, ctx, npc, data, rl);

	return npf_grouper_match(af, (g2_config_t *)ctx, npc, data, rl);
}

int npf_match_destroy(enum npf_ruleset_type rs_type,
		      int af, npf_match_ctx_t **ctx)
{
	npf_match_cb_tbl *tbl;

	tbl = npf_match_cbs[rs_type];
	if (tbl)
		return tbl->npf_match_destroy_cb(af, ctx);

	return npf_grouper_destroy((g2_config_t **)ctx);
}
