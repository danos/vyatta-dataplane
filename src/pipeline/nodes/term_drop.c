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
uint16_t term_drop_features;

static inline struct pl_node *term_drop_feat_list_to_node(void)
{
	/* our imaginary node */
	return (struct pl_node *)&term_drop_features;
}

static inline uint16_t *
drop_node_to_term_drop_feat_list(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (uint16_t *)node;
}

ALWAYS_INLINE unsigned int
term_drop_process_common(struct pl_packet *pkt, void *context __unused,
			 enum pl_mode mode)
{
	/*
	 * As this is a feature run once it is decided that the packet is
	 * to be dropped the features can not change that decision. It will
	 * still be dropped. The feature return value can not change that
	 * so don't check it.
	 */
	switch (mode) {
	case PL_MODE_FUSED:
		pipeline_fused_term_drop_features(
			pkt, term_drop_feat_list_to_node());
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		pipeline_fused_term_drop_no_dyn_features(
			pkt, term_drop_feat_list_to_node());
		break;
	case PL_MODE_REGULAR:
		pl_node_invoke_enabled_features(term_drop_node_ptr,
						term_drop_feat_list_to_node(),
						pkt);
		break;
	}

	rte_pktmbuf_free(pkt->mbuf);
	pkt->mbuf = NULL;

	return TERM_DROP_ACCEPT;
}

ALWAYS_INLINE unsigned int
term_drop_process(struct pl_packet *p, void *context)
{
	return term_drop_process_common(p, context, PL_MODE_REGULAR);
}

static int
term_drop_feat_change(struct pl_node *node,
		      struct pl_feature_registration *feat,
		      enum pl_node_feat_action action)
{
	uint16_t *feature_list = drop_node_to_term_drop_feat_list(node);

	return pl_node_feat_change_u16(feature_list, feat, action);
}

ALWAYS_INLINE bool
term_drop_feat_iterate(struct pl_node *node, bool first,
		       unsigned int *feature_id, void **context,
		       void **storage_ctx __unused)
{
	uint16_t *feature_list = drop_node_to_term_drop_feat_list(node);

	/* No support for instance context at the moment */
	return pl_node_feat_iterate_u16(feature_list, first,
					feature_id, context);
}

static struct pl_node *
term_drop_node_lookup(const char *name)
{
	if (strcmp(name, "all") == 0)
		return term_drop_feat_list_to_node();

	return NULL;
}

/* Register Node */
PL_REGISTER_NODE(term_drop_node) = {
	.name = "vyatta:term-drop",
	.type = PL_PROC,
	.handler = term_drop_process,
	.feat_change = term_drop_feat_change,
	.feat_iterate = term_drop_feat_iterate,
	.lookup_by_name = term_drop_node_lookup,
	.num_next = TERM_DROP_NUM,
	.next = {
		[TERM_DROP_ACCEPT] = "term-finish",
	}
};

struct pl_node_registration *const term_drop_node_ptr =
	&term_drop_node;
