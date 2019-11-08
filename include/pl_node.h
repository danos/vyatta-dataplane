/*
 * pl_node.h
 *
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PL_NODE_H
#define PL_NODE_H

#include "compiler.h"
#include "pl_common.h"

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
		       unsigned int feature, struct pl_packet *pkt);

bool
pl_node_invoke_enabled_features(
	struct pl_node_registration *node_reg, struct pl_node *node,
	struct pl_packet *pkt);

bool
pl_node_iter_features(struct pl_node_registration *node_reg,
		      void *node, pl_user_feat_iterate_fn callback,
		      void *context);

bool
pl_graph_walk(struct pl_node_registration *node_reg, struct pl_packet *pkt);

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

#endif /* PL_NODE_H */
