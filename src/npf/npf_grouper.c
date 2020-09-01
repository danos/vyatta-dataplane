/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "npf_grouper.h"
#include "grouper2.h"
#include "npf_rule_gen.h"

/*
 * Packet matching callback functions which use the grouper2 API
 */

int npf_grouper_init(int af, g2_config_t **g_ctx)
{
	if (af == AF_INET)
		*g_ctx = g2_init(NPC_GPR_SIZE_v4);
	else
		*g_ctx = g2_init(NPC_GPR_SIZE_v6);

	if (!*g_ctx)
		return -ENOMEM;

	return 0;
}

int npf_grouper_add_rule(int af, g2_config_t *g_ctx, uint32_t rule_no,
			 uint8_t *match_addr, uint8_t *mask,
			 void *match_ctx)
{
	if (!g2_create_rule(g_ctx, rule_no, match_ctx))
		return -ENOMEM;

	if (!g2_add(g_ctx, 0,
		    (af == AF_INET ? NPC_GPR_SIZE_v4 : NPC_GPR_SIZE_v6),
		    match_addr, mask))
		return -EINVAL;

	return 0;
}

int npf_grouper_build(g2_config_t **g_ctx)
{
	g2_optimize(g_ctx);

	return 0;
}

int npf_grouper_match(int af, g2_config_t *g_ctx, npf_cache_t *npc,
		      void *data, npf_rule_t **rl)
{
	uint8_t *pkt;

	if (unlikely(!npc))
		return 0;

	pkt = (uint8_t *)npc->npc_grouper;
	if (af == AF_INET)
		*rl = g2_eval4(g_ctx, pkt, data);
	else
		*rl = g2_eval6(g_ctx, pkt, data);
	if (*rl)
		return 1;

	return 0;
}

int npf_grouper_destroy(g2_config_t **g_ctx)
{
	/* Release groupers */
	g2_destroy(g_ctx);

	return 0;
}
