/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_GROUPER_H
#define NPF_GROUPER_H

/* Forward declarations */
typedef struct npf_rule npf_rule_t;

#include <rte_mbuf.h>
#include "grouper2.h"

int npf_grouper_init(int af, g2_config_t **g_ctx);

int npf_grouper_add_rule(int af, g2_config_t *g_ctx, uint32_t rule_no,
			 uint8_t *match_add, uint8_t *mask,
			 void *match_ctx);

int npf_grouper_build(g2_config_t **g_ctx);

int npf_grouper_match(int af, g2_config_t *g_ctx, npf_cache_t *npc,
		      void *data, npf_rule_t **rl);

int npf_grouper_destroy(g2_config_t **g_ctx);

#endif
