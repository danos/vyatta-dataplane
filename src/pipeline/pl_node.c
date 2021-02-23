/*
 * pl_node.c
 *
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "ether.h"
#include "pl_common.h"
#include "pl_internal.h"
#include "pl_node.h"
#include "urcu.h"
#include "pl_fused_gen.h"

struct pl_node;

/* for now need a place to hang callback funcs and not on node */
static pl_storage_delete *g_pl_storage_func[PL_NODE_STORE_MAX] __hot_data;
/* used to track the number of registered storage count */
static int g_pl_storage_ct;
/* count of the instances of dynamic features enabled */
static uint32_t dyn_feat_inst_count;
/* enable packet counter per node */
int g_stats_enabled __hot_data;
/* packet counter per node */
uint64_t *g_pl_node_stats __hot_data;

ALWAYS_INLINE void
pl_release_storage(struct pl_packet *p)
{
	int i;

	for (i = 0; i < p->max_data_used; ++i) {
		if (!p->data[i])
			continue;
		if (g_pl_storage_func[i])
			g_pl_storage_func[i](p->data[i]);
	}
}

void
pl_register_storage(struct pl_node_storage *storage)
{
	if (g_pl_storage_ct < PL_NODE_STORE_MAX && !storage->disable) {
		storage->id = g_pl_storage_ct++;
		g_pl_storage_func[storage->id] = storage->release;
	}
}

int
pl_node_add_feature_by_inst(struct pl_feature_registration *feat, void *node)
{
	int ret;

	if (!feat->feature_point_node->feat_change)
		return -ENOTSUP;

	ret = feat->feature_point_node->feat_change(
		node, feat, PL_NODE_FEAT_ADD);

	if (ret == 0 && feat->dynamic) {
		if (uatomic_add_return(&dyn_feat_inst_count, 1) == 1)
			set_packet_input_func(ether_input);
	}

	return ret;
}

static int
pl_node_add_feature_all_inst(struct pl_feature_registration *feat)
{
	int ret;

	if (!feat->feature_point_node->feat_change_all)
		return -ENOTSUP;

	ret = feat->feature_point_node->feat_change_all(feat, PL_NODE_FEAT_ADD);

	if (ret == 0 && feat->dynamic) {
		if (uatomic_add_return(&dyn_feat_inst_count, 1) == 1)
			set_packet_input_func(ether_input);
	}

	return ret;
}

int
pl_node_remove_feature_by_inst(struct pl_feature_registration *feat, void *node)
{
	int ret;

	if (!feat->feature_point_node->feat_change)
		return -ENOTSUP;

	ret = feat->feature_point_node->feat_change(
		node, feat, PL_NODE_FEAT_REM);

	if (ret == 0 && feat->dynamic) {
		if (uatomic_add_return(&dyn_feat_inst_count, -1) == 0)
			set_packet_input_func(NULL);
	}

	return ret;
}

static int
pl_node_remove_feature_all_inst(struct pl_feature_registration *feat)
{
	int ret;

	if (!feat->feature_point_node->feat_change_all)
		return -ENOTSUP;

	ret = feat->feature_point_node->feat_change_all(feat, PL_NODE_FEAT_REM);

	if (ret == 0 && feat->dynamic) {
		if (uatomic_add_return(&dyn_feat_inst_count, -1) == 0)
			set_packet_input_func(NULL);
	}

	return ret;
}

int
pl_node_add_feature(struct pl_feature_registration *feat,
		    const char *node_inst_name)
{
	struct pl_node *node;

	if (!feat->feature_point_node->lookup_by_name)
		return -ENOTSUP;
	node = feat->feature_point_node->lookup_by_name(node_inst_name);
	if (!node)
		return -ENODEV;

	return pl_node_add_feature_by_inst(feat, node);
}

int
pl_node_remove_feature(struct pl_feature_registration *feat,
		       const char *node_inst_name)
{
	struct pl_node *node;

	if (!feat->feature_point_node->lookup_by_name)
		return -ENOTSUP;
	node = feat->feature_point_node->lookup_by_name(node_inst_name);
	if (!node)
		return -ENODEV;

	return pl_node_remove_feature_by_inst(feat, node);
}

bool
pl_node_is_feature_enabled_by_inst(struct pl_feature_registration *feat,
				   void *node)
{
	pl_node_feat_iterate *iter_fn;
	unsigned int feature_id;
	void *context;
	bool more;
	void *storage_ctx;

	iter_fn = feat->feature_point_node->feat_iterate;
	if (!iter_fn)
		return false;

	for (more = iter_fn(node, true, &feature_id, &context, &storage_ctx);
	     more;
	     more = iter_fn(node, false, &feature_id, &context, &storage_ctx))
		if (feature_id == feat->id)
			return true;

	return false;
}

bool
pl_node_is_feature_enabled(struct pl_feature_registration *feat,
			   const char *node_inst_name)
{
	struct pl_node *node;

	if (!feat->feature_point_node->lookup_by_name)
		return false;
	node = feat->feature_point_node->lookup_by_name(node_inst_name);
	if (!node)
		return false;

	return pl_node_is_feature_enabled_by_inst(feat, node);
}

ALWAYS_INLINE bool
pl_node_invoke_feature(struct pl_node_registration *node_reg,
		       unsigned int feature, struct pl_packet *pkt,
		       void *storage_ctx)
{
	assert(feature < node_reg->max_feature_reg_idx);
	return pl_graph_walk(node_reg->feature_regs[feature]->node,
			     pkt, storage_ctx);
}

ALWAYS_INLINE bool
pl_node_invoke_feature_by_type(struct pl_node_registration *node_reg,
			       uint32_t feature_type, struct pl_packet *pkt)
{
	unsigned int feature_id;

	if (!node_reg->feat_type_find)
		return true;

	feature_id = node_reg->feat_type_find(feature_type);
	/* The case features are enabled globally not per instance */
	return pl_node_invoke_feature(node_reg, feature_id, pkt, NULL);
}

/*
 * Invoke all the enabled features for a node
 *
 * Returns false if packet was consumed, true otherwise.
 */
bool
pl_node_invoke_enabled_features(
	struct pl_node_registration *node_reg, struct pl_node *node,
	struct pl_packet *pkt)
{
	pl_node_feat_iterate *iter_fn;
	unsigned int feature_id;
	void *context;
	bool more;
	void *storage_ctx;

	iter_fn = node_reg->feat_iterate;
	if (!iter_fn)
		return true;

	for (more = iter_fn(node, true, &feature_id, &context, &storage_ctx);
	     more;
	     more = iter_fn(node, false, &feature_id, &context, &storage_ctx)) {
		if (!pl_node_invoke_feature(node_reg, feature_id,
					    pkt, storage_ctx))
			return false;
	}

	return true;
}

/*
 * Iterate all the enabled features for a node.
 *
 * The features are iterated in the same order they are visited in the
 * pipeline. If the callback function returns false the walk is
 * aborted.
 *
 * Returns false if the walk aborted or true otherwise.
 */
bool
pl_node_iter_features(struct pl_node_registration *node_reg,
		      void *node, pl_user_feat_iterate_fn callback,
		      void *user_context)
{
	pl_node_feat_iterate *iter_fn;
	unsigned int feature_id;
	void *context;
	bool more;
	void *storage_ctx;

	iter_fn = node_reg->feat_iterate;
	if (!iter_fn)
		return false;

	for (more = iter_fn(node, true, &feature_id, &context, &storage_ctx);
	     more;
	     more = iter_fn(node, false, &feature_id, &context, &storage_ctx)) {
		assert(feature_id < node_reg->max_feature_reg_idx);
		if (!callback(node_reg->feature_regs[feature_id],
			      user_context))
			return false;
	}

	return true;
}

/*
 * Walk the graph with a packet
 *
 * This would ideally walk nodes rather than node registrations, but
 * we don't create nodes yet.
 *
 * Returns false if packet was consumed, true otherwise.
 */
bool
pl_graph_walk(struct pl_node_registration *node_reg,
	      struct pl_packet *pkt,
	      void *storage_ctx)
{
	int resp;

	while (true) {
		pl_inc_node_stat(node_reg->node_decl_id);
		resp = node_reg->handler(pkt, storage_ctx);

		switch (node_reg->type) {
		case PL_OUTPUT:
			return false;
		case PL_CONTINUE:
			return true;
		case PL_PROC:
			break;
		}

		assert(resp < node_reg->num_next);
		node_reg = node_reg->next_nodes[resp];
		storage_ctx = NULL;
	}

	return true;
}

int
pl_node_feat_change_u16(uint16_t *bitmask,
			struct pl_feature_registration *feat,
			enum pl_node_feat_action action)
{
	switch (action) {
	case PL_NODE_FEAT_ADD:
		if (feat->id > sizeof(*bitmask) * CHAR_BIT)
			return -ENOSPC;
		uatomic_or(bitmask, 1 << (feat->id - 1));
		return 0;
	case PL_NODE_FEAT_REM:
		if (feat->id > sizeof(*bitmask) * CHAR_BIT)
			return -ENOSPC;
		uatomic_and(bitmask, ~(1 << (feat->id - 1)));
		return 0;
	default:
		return -EINVAL;
	}
}

ALWAYS_INLINE bool
pl_node_feat_iterate_u16(const uint16_t *bitmask, bool first,
			 unsigned int *feature_id, void **context)
{
	uint16_t *features_ctx = (uint16_t *)context;
	int lowest_bit_set;
	uint16_t features;

	if (first)
		features = CMM_ACCESS_ONCE(*bitmask);
	else
		features = *features_ctx;

	lowest_bit_set = ffs(features);
	if (likely(!lowest_bit_set))
		return false;
	*feature_id = lowest_bit_set;
	*features_ctx = features & ~(1u << (*feature_id - 1));
	return true;
}

int
pl_node_feat_change_u8(uint8_t *bitmask,
			struct pl_feature_registration *feat,
			enum pl_node_feat_action action)
{
	switch (action) {
	case PL_NODE_FEAT_ADD:
		if (feat->id > sizeof(*bitmask) * CHAR_BIT)
			return -ENOSPC;
		uatomic_or(bitmask, 1 << (feat->id - 1));
		return 0;
	case PL_NODE_FEAT_REM:
		if (feat->id > sizeof(*bitmask) * CHAR_BIT)
			return -ENOSPC;
		uatomic_and(bitmask, ~(1 << (feat->id - 1)));
		return 0;
	default:
		return -EINVAL;
	}
}

ALWAYS_INLINE bool
pl_node_feat_iterate_u8(const uint8_t *bitmask, bool first,
			 unsigned int *feature_id, void **context)
{
	uint8_t *features_ctx = (uint8_t *)context;
	int lowest_bit_set;
	uint8_t features;

	if (first)
		features = CMM_ACCESS_ONCE(*bitmask);
	else
		features = *features_ctx;

	lowest_bit_set = ffs(features);
	if (likely(!lowest_bit_set))
		return false;
	*feature_id = lowest_bit_set;
	*features_ctx = features & ~(1u << (*feature_id - 1));
	return true;
}

uint64_t
pl_get_node_stats(int id)
{
	unsigned int i;
	uint64_t ct = 0;

	for (i = 0; i <= get_lcore_max(); ++i)
		ct +=  *(g_pl_node_stats + pl_node_stats_id(id, i));
	return ct;
}

static int
pl_node_enable_global_case_feature(struct pl_feature_registration *pl_feat)
{

	if (!pl_feat->feature_point_node->feat_type_find)
		return -ENOTSUP;

	if (!pl_feat->feature_point_node->feat_type_insert ||
	    !pl_feat->feature_point_node->feat_type_remove)
		return -ENOTSUP;

	if (pl_feat->feature_point_node->feat_type_insert(
		    pl_feat->feature_point_node,
		    pl_feat,
		    pl_feat->feat_type) != 0)
		return -EINVAL;

	if (uatomic_add_return(&dyn_feat_inst_count, 1) == 1)
		set_packet_input_func(ether_input);

	return 0;
}

int pl_node_enable_global_feature(struct pl_feature_registration *pl_feat)
{
	if (!pl_feat)
		return -EINVAL;

	if (pl_feat->feature_point_node->feat_type_find)
		return pl_node_enable_global_case_feature(pl_feat);

	return pl_node_add_feature_all_inst(pl_feat);
}

static int
pl_node_disable_global_case_feature(struct pl_feature_registration *pl_feat)
{
	if (!pl_feat)
		return -EINVAL;

	if (!pl_feat->feature_point_node->feat_type_find)
		return -ENOTSUP;

	if (!pl_feat->feature_point_node->feat_type_insert ||
	    !pl_feat->feature_point_node->feat_type_remove)
		return -ENOTSUP;

	if (pl_feat->feature_point_node->feat_type_remove(
		    pl_feat->feature_point_node,
		    pl_feat,
		    pl_feat->feat_type) != 0)
		return -EINVAL;

	if (uatomic_add_return(&dyn_feat_inst_count, -1) == 0)
		set_packet_input_func(NULL);

	return 0;
}

int pl_node_disable_global_feature(struct pl_feature_registration *pl_feat)
{
	if (!pl_feat)
		return -EINVAL;

	if (pl_feat->feature_point_node->feat_type_find)
		return pl_node_disable_global_case_feature(pl_feat);

	return pl_node_remove_feature_all_inst(pl_feat);
}

int pl_node_register_storage(struct pl_feature_registration *feat,
			     const char *node_inst_name,
			     void *context)
{
	struct pl_node *node;

	if (!feat->feature_point_node->feat_reg_context)
		return -ENOTSUP;

	node = feat->feature_point_node->lookup_by_name(node_inst_name);
	if (!node)
		return -ENODEV;

	return feat->feature_point_node->feat_reg_context(node, feat,
							  context);
}

int pl_node_unregister_storage(struct pl_feature_registration *feat,
			       const char *node_inst_name)
{
	struct pl_node *node;

	if (!feat->feature_point_node->feat_unreg_context)
		return -ENOTSUP;

	node = feat->feature_point_node->lookup_by_name(node_inst_name);
	if (!node)
		return -ENODEV;

	return feat->feature_point_node->feat_unreg_context(node, feat);
}

void *pl_node_get_storage(struct pl_feature_registration *feat,
			  const char *node_inst_name)
{
	struct pl_node *node;

	if (!feat->feature_point_node->feat_get_context)
		return NULL;

	node = feat->feature_point_node->lookup_by_name(node_inst_name);
	if (!node)
		return NULL;

	return feat->feature_point_node->feat_get_context(node, feat);
}
