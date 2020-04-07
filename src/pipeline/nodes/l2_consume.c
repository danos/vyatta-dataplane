/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <linux/if.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "compiler.h"
#include "ether.h"
#include "if_var.h"
#include "if/macvlan.h"
#include "main.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "util.h"

struct pl_node;

/*
 * Term drop feature instance is global, so we can store it in a global var.
 */
uint16_t l2_consume_features;

static inline struct pl_node *l2_consume_feat_list_to_node(void)
{
	/* our imaginary node */
	return (struct pl_node *)&l2_consume_features;
}

static inline uint16_t *
drop_node_to_l2_consume_feat_list(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (uint16_t *)node;
}

ALWAYS_INLINE unsigned int
l2_consume_process_common(struct pl_packet *pkt, void *context __unused,
			 enum pl_mode mode)
{
	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_l2_consume_features(
			    pkt, l2_consume_feat_list_to_node()))
			return L2_CONSUME_FINISH;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_l2_consume_no_dyn_features(
			    pkt, l2_consume_feat_list_to_node()))
			return L2_CONSUME_FINISH;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    l2_consume_node_ptr,
			    l2_consume_feat_list_to_node(),
			    pkt))
			return L2_CONSUME_FINISH;
		break;
	}

	return L2_CONSUME_ACCEPT;
}

ALWAYS_INLINE unsigned int
l2_consume_process(struct pl_packet *p, void *context)
{
	return l2_consume_process_common(p, context, PL_MODE_REGULAR);
}

static int
l2_consume_feat_change(struct pl_node *node,
		      struct pl_feature_registration *feat,
		      enum pl_node_feat_action action)
{
	uint16_t *feature_list = drop_node_to_l2_consume_feat_list(node);

	return pl_node_feat_change_u16(feature_list, feat, action);
}

ALWAYS_INLINE bool
l2_consume_feat_iterate(struct pl_node *node, bool first,
		       unsigned int *feature_id, void **context,
		       void **storage_ctx __unused)
{
	uint16_t *feature_list = drop_node_to_l2_consume_feat_list(node);

	/* No support for instance context at the moment */
	return pl_node_feat_iterate_u16(feature_list, first,
					feature_id, context);
}

static struct pl_node *
l2_consume_node_lookup(const char *name)
{
	if (strcmp(name, "all") == 0)
		return l2_consume_feat_list_to_node();

	return NULL;
}

/* Register Node */
PL_REGISTER_NODE(l2_consume_node) = {
	.name = "vyatta:l2-consume",
	.type = PL_PROC,
	.handler = l2_consume_process,
	.feat_change = l2_consume_feat_change,
	.feat_iterate = l2_consume_feat_iterate,
	.lookup_by_name = l2_consume_node_lookup,
	.num_next = L2_CONSUME_NUM,
	.next = {
		[L2_CONSUME_ACCEPT] = "term-noop",
		[L2_CONSUME_FINISH] = "term-finish",
	}
};

struct pl_node_registration *const l2_consume_node_ptr =
	&l2_consume_node;
