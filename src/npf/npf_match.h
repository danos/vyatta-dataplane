/*
 * Copyright (c) 2019-2021 AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Abstraction for a packet matching utility. Used to provide the ability
 * to use different packet matching algorithms depending on the ruleset
 * type.
 */
#ifndef NPF_MATCH_H
#define NPF_MATCH_H

#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_cache.h"

typedef struct npf_match_ctx npf_match_ctx_t;

struct npf_match_cb_data {
	npf_cache_t *npc;
	struct rte_mbuf *mbuf;
	const struct ifnet *ifp;
	int dir;
	npf_session_t *se;
	npf_rule_group_t *rg;
};

typedef	int (*npf_match_init_cb_t)(int af, const char *name,
				   uint32_t max_rules,
				   npf_match_ctx_t **ctx);
typedef int (*npf_match_add_rule_cb_t)(int af, npf_match_ctx_t *ctx,
				       uint32_t rule_no,
				       uint8_t *match_addr, uint8_t *mask,
				       void *match_ctx);
typedef	int (*npf_match_build_cb_t)(int af, npf_match_ctx_t **ctx);
typedef	int (*npf_match_classify_cb_t)(int af, npf_match_ctx_t *ctx,
				       npf_cache_t *npc,
				       struct npf_match_cb_data *data,
				       npf_rule_t **rl);
typedef int (*npf_match_destroy_cb_t)(int af, npf_match_ctx_t **ctx);


typedef struct npf_match_cb_tbl {
	npf_match_init_cb_t      npf_match_init_cb;
	npf_match_add_rule_cb_t  npf_match_add_rule_cb;
	npf_match_build_cb_t     npf_match_build_cb;
	npf_match_classify_cb_t  npf_match_classify_cb;
	npf_match_destroy_cb_t   npf_match_destroy_cb;
} npf_match_cb_tbl;

int npf_match_init(enum npf_ruleset_type rs_type,
		   int af, const char *name,
		   uint32_t max_rules, npf_match_ctx_t **ctx);

int npf_match_add_rule(enum npf_ruleset_type rs_type,
		       int af, npf_match_ctx_t *ctx, uint32_t rule_no,
		       uint8_t *match_addr, uint8_t *mask,
		       void *match_ctx);

int npf_match_build(enum npf_ruleset_type rs_type,
		    int af, npf_match_ctx_t **ctx);

int npf_match_classify(enum npf_ruleset_type rs_type,
		       int af, npf_match_ctx_t *ctx,
		       npf_cache_t *npc, struct npf_match_cb_data *data,
		       npf_rule_t **rl);

int npf_match_destroy(enum npf_ruleset_type rs_type,
		      int af, npf_match_ctx_t **ctx);

#endif
