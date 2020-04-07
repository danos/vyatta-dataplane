/*
 * l2_output.c
 *
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

static inline struct pl_node *ifp_to_l2_output_node(struct ifnet *ifp)
{
	/* our imaginary node */
	return (struct pl_node *)ifp;
}

static inline struct ifnet *l2_output_node_to_ifp(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct ifnet *)node;
}

ALWAYS_INLINE unsigned int
l2_output_process_common(struct pl_packet *pkt, void *context __unused,
			 enum pl_mode mode)
{
	struct ifnet *out_ifp = pkt->out_ifp;

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_l2_output_features(
			    pkt, ifp_to_l2_output_node(out_ifp)))
			return L2_OUTPUT_DROP;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_l2_output_no_dyn_features(
			    pkt, ifp_to_l2_output_node(out_ifp)))
			return L2_OUTPUT_DROP;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    l2_output_node_ptr,
			    ifp_to_l2_output_node(out_ifp),
			    pkt))
			return L2_OUTPUT_DROP;
		break;
	}

	return L2_OUTPUT_ACCEPT;
}

ALWAYS_INLINE unsigned int
l2_output_process(struct pl_packet *p, void *context)
{
	return l2_output_process_common(p, context, PL_MODE_REGULAR);
}

static int
l2_output_feat_change(struct pl_node *node,
		      struct pl_feature_registration *feat,
		      enum pl_node_feat_action action)
{
	struct ifnet *ifp = l2_output_node_to_ifp(node);

	return pl_node_feat_change_u16(&ifp->l2_output_features, feat, action);
}

static int
l2_output_feat_change_all(struct pl_feature_registration *feat,
			  enum pl_node_feat_action action)
{
	return if_node_instance_feat_change_all(feat, action,
						l2_output_feat_change);
}

ALWAYS_INLINE bool
l2_output_feat_iterate(struct pl_node *node, bool first,
		       unsigned int *feature_id, void **context,
		       void **storage_ctx)
{
	bool ret;
	struct ifnet *ifp = l2_output_node_to_ifp(node);

	ret = pl_node_feat_iterate_u16(&ifp->l2_output_features, first,
				       feature_id, context);
	if (ret)
		*storage_ctx = if_node_instance_get_storage_internal(
			ifp,
			PL_FEATURE_POINT_L2_OUTPUT_ID,
			*feature_id);

	return ret;
}

static struct pl_node *
l2_output_node_lookup(const char *name)
{
	struct ifnet *ifp = dp_ifnet_byifname(name);
	return ifp ? ifp_to_l2_output_node(ifp) : NULL;
}

/* Register Node */
PL_REGISTER_NODE(l2_output_node) = {
	.name = "vyatta:l2-output",
	.type = PL_PROC,
	.handler = l2_output_process,
	.feat_change = l2_output_feat_change,
	.feat_change_all = l2_output_feat_change_all,
	.feat_iterate = l2_output_feat_iterate,
	.lookup_by_name = l2_output_node_lookup,
	.feat_reg_context = if_node_instance_register_storage,
	.feat_unreg_context = if_node_instance_unregister_storage,
	.feat_setup_cleanup_cb = if_node_instance_set_cleanup_cb,
	.num_next = L2_OUTPUT_NUM,
	.next = {
		[L2_OUTPUT_ACCEPT] = "term-noop",
		[L2_OUTPUT_DROP] = "term-drop",
	}
};

struct pl_node_registration *const l2_output_node_ptr =
	&l2_output_node;
