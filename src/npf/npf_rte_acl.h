/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_RTE_ACL_H
#define NPF_RTE_ACL_H

#include <rte_acl.h>
#include "npf_cache.h"
#include "npf_match.h"

int npf_rte_acl_init(int af, const char *name, uint32_t max_rules,
		     npf_match_ctx_t **m_ctx);

int npf_rte_acl_start_transaction(int af, npf_match_ctx_t *m_ctx);

int npf_rte_acl_commit_transaction(int af, npf_match_ctx_t *m_ctx);

int npf_rte_acl_add_rule(int af, npf_match_ctx_t *m_ctx,
			 uint32_t rule_no,
			 uint8_t *match_add, uint8_t *mask,
			 void *match_ctx);

int npf_rte_acl_del_rule(int af, npf_match_ctx_t *m_ctx, uint32_t rule_no,
			 uint8_t *match_addr, uint8_t *mask);

int npf_rte_acl_match(int af, npf_match_ctx_t *m_ctx, npf_cache_t *npc,
		      struct npf_match_cb_data *data, uint32_t *rule_no);

int npf_rte_acl_destroy(int af, npf_match_ctx_t **m_ctx);

#endif
