/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_RTE_ACL_H
#define NPF_RTE_ACL_H

#include <rte_acl.h>
#include <json_writer.h>
#include "npf_cache.h"
#include "npf_match.h"

/* get priority associated with rule */
typedef int (*npf_rte_acl_prio_map_cb_t)(void *userdata,
					 uint32_t rule_no,
					 uint32_t *priority);

int npf_rte_acl_setup(void);

int npf_rte_acl_teardown(void);

int npf_rte_acl_init(int af, const char *name, uint32_t max_rules,
		     npf_match_ctx_t **m_ctx);

int npf_rte_acl_start_transaction(int af, npf_match_ctx_t *m_ctx);

int npf_rte_acl_commit_transaction(int af, npf_match_ctx_t *m_ctx);

int npf_rte_acl_add_rule(int af, npf_match_ctx_t *m_ctx,
			 uint32_t rule_no, uint32_t priority,
			 uint8_t *match_add, uint8_t *mask,
			 void *match_ctx);

int npf_rte_acl_del_rule(int af, npf_match_ctx_t *m_ctx, uint32_t rule_no,
			 uint32_t priority, uint8_t *match_addr, uint8_t *mask);

int npf_rte_acl_match(int af, npf_match_ctx_t *m_ctx, npf_cache_t *npc,
		      struct npf_match_cb_data *data,
		      npf_rte_acl_prio_map_cb_t prio_map_cb,
		      void *prio_map_userdata,
		      uint32_t *rule_no);

int npf_rte_acl_destroy(int af, npf_match_ctx_t **m_ctx);

size_t npf_rte_acl_rule_size(int af);

void npf_rte_acl_dump(npf_match_ctx_t *ctx, json_writer_t *wr);

#endif
