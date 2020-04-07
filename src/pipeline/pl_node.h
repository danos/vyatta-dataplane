/*
 * pl_node.h
 *
 *
 * Copyright (c) 2017,2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PL_NODE_H
#define PL_NODE_H

#include "compiler.h"
#include "pl_common.h"
#include "pl_fused_gen.h"

typedef bool (*pl_user_feat_iterate_fn)(
	struct pl_feature_registration *feat_reg, void *context);

/* Meta data stuff */
void
pl_release_storage(struct pl_packet *);


static ALWAYS_INLINE void
pl_get_node_data(struct pl_packet *p, uint8_t id, void **data)
{
	*data = p->data[id];
}


static ALWAYS_INLINE void
pl_set_node_data(struct pl_packet *p, uint8_t id, void *data)
{
	uint8_t unused_id;

	if (id >= p->max_data_used) {
		for (unused_id = p->max_data_used; unused_id < id;
		     unused_id++)
			p->data[unused_id] = NULL;
		p->max_data_used = id + 1;
	}
	p->data[id] = data;
}

int
pl_node_add_feature_by_inst(struct pl_feature_registration *feat, void *node);

int
pl_node_remove_feature_by_inst(struct pl_feature_registration *feat,
			       void *node);

int
pl_node_add_feature(struct pl_feature_registration *feat,
		    const char *node_inst_name);

int
pl_node_remove_feature(struct pl_feature_registration *feat,
		       const char *node_inst_name);

bool
pl_node_is_feature_enabled(struct pl_feature_registration *feat, void *node);

bool
pl_node_invoke_feature(struct pl_node_registration *node_reg,
		       unsigned int feature, struct pl_packet *pkt,
		       void *storage_ctx);

bool
pl_node_invoke_feature_by_type(struct pl_node_registration *node_reg,
			       uint32_t feature_type, struct pl_packet *pkt);

bool
pl_node_invoke_enabled_features(
	struct pl_node_registration *node_reg, struct pl_node *node,
	struct pl_packet *pkt);

bool
pl_node_iter_features(struct pl_node_registration *node_reg,
		      void *node, pl_user_feat_iterate_fn callback,
		      void *context);

bool
pl_graph_walk(struct pl_node_registration *node_reg,
	      struct pl_packet *pkt,
	      void *storage_ctx);

int
pl_node_feat_change_u16(uint16_t *bitmask,
			struct pl_feature_registration *feat,
			enum pl_node_feat_action action);

bool
pl_node_feat_iterate_u16(const uint16_t *bitmask, bool first,
			 unsigned int *feature_id, void **context);

int
pl_node_feat_change_u8(uint8_t *bitmask,
		       struct pl_feature_registration *feat,
		       enum pl_node_feat_action action);

bool
pl_node_feat_iterate_u8(const uint8_t *bitmask, bool first,
			unsigned int *feature_id, void **context);

int pl_node_enable_global_feature(struct pl_feature_registration *pl_feat);
int pl_node_disable_global_feature(struct pl_feature_registration *pl_feat);

uint32_t
pl_feat_point_node_get_max_features(enum pl_feature_point_id feat_point);

int pl_node_register_storage(struct pl_feature_registration *feat,
			     const char *node_inst_name,
			     void *context);
int pl_node_unregister_storage(struct pl_feature_registration *feat,
			       const char *node_inst_name);
void *pl_node_get_storage(struct pl_feature_registration *feat,
			  const char *node_inst_name);

#endif /* PL_NODE_H */
