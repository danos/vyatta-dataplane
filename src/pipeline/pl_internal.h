/*
 * pl_internal.h
 *
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PL_INTERNAL_H
#define PL_INTERNAL_H

#include "compiler.h"
#include "json_writer.h"
#include "util.h"

extern int g_stats_enabled __hot_data;
extern uint64_t *g_pl_node_stats;

static ALWAYS_INLINE int
pl_node_stats_id(int node_id, unsigned int lcore_id)
{
	return RTE_MAX_LCORE * node_id + lcore_id;
}

static ALWAYS_INLINE void
pl_inc_node_stat(int node_id)
{
	if (unlikely(g_stats_enabled))
		++(*(g_pl_node_stats +
		     pl_node_stats_id(node_id, dp_lcore_id())));
}

void pl_graph_validate(void);

uint64_t pl_get_node_stats(int id);

void pl_show_plugin_state(json_writer_t *json, const char *plugin_name);
#endif /* PL_INTERNAL_H */
