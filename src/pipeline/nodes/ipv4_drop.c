/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
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
 * Ipv4 drop feature instance is global, so we can store it in a global var.
 */
uint16_t ipv4_drop_features;

static inline struct pl_node *ipv4_drop_feat_list_to_node(void)
{
	/* our imaginary node */
	return (struct pl_node *)&ipv4_drop_features;
}

static inline uint16_t *
drop_node_to_ipv4_drop_feat_list(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (uint16_t *)node;
}

ALWAYS_INLINE unsigned int
ipv4_drop_process_common(struct pl_packet *pkt, void *context __unused,
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
		pipeline_fused_ipv4_drop_features(
			pkt, ipv4_drop_feat_list_to_node());
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		pipeline_fused_ipv4_drop_no_dyn_features(
			pkt, ipv4_drop_feat_list_to_node());
		break;
	case PL_MODE_REGULAR:
		(void)pl_node_invoke_enabled_features(ipv4_drop_node_ptr,
						      ipv4_drop_feat_list_to_node(), pkt);
		break;
	}

	if (pkt->in_ifp)
		IPSTAT_INC_IFP(pkt->in_ifp, IPSTATS_MIB_INDISCARDS);

	rte_pktmbuf_free(pkt->mbuf);
	pkt->mbuf = NULL;

	return IPV4_DROP_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_drop_process(struct pl_packet *p, void *context)
{
	return ipv4_drop_process_common(p, context, PL_MODE_REGULAR);
}

static int
ipv4_drop_feat_change(struct pl_node *node,
		      struct pl_feature_registration *feat,
		      enum pl_node_feat_action action)
{
	uint16_t *feature_list = drop_node_to_ipv4_drop_feat_list(node);

	return pl_node_feat_change_u16(feature_list, feat, action);
}

ALWAYS_INLINE bool
ipv4_drop_feat_iterate(struct pl_node *node, bool first,
		       unsigned int *feature_id, void **context,
		       void **storage_ctx __unused)
{
	uint16_t *feature_list = drop_node_to_ipv4_drop_feat_list(node);

	/* No support for instance context at the moment */
	return pl_node_feat_iterate_u16(feature_list, first,
					feature_id, context);
}

static struct pl_node *
ipv4_drop_node_lookup(const char *name)
{
	if (strcmp(name, "all") == 0)
		return ipv4_drop_feat_list_to_node();

	return NULL;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_drop_node) = {
	.name = "vyatta:ipv4-drop",
	.type = PL_PROC,
	.handler = ipv4_drop_process,
	.feat_change = ipv4_drop_feat_change,
	.feat_iterate = ipv4_drop_feat_iterate,
	.lookup_by_name = ipv4_drop_node_lookup,
	.num_next = IPV4_DROP_NUM,
	.next = {
		[IPV4_DROP_ACCEPT] = "term-finish",
	}
};

struct pl_node_registration *const ipv4_drop_node_ptr =
	&ipv4_drop_node;

/*
 * show features ipv4_drop
 */
static int cmd_pl_show_feat_ipv4_drop(struct pl_command *cmd)
{
	json_writer_t *wr;

	wr = jsonw_new(cmd->fp);
	if (!wr)
		return 0;

	jsonw_name(wr, "features");
	jsonw_start_object(wr);

	jsonw_name(wr, "global");
	jsonw_start_array(wr);
	pl_node_iter_features(ipv4_drop_node_ptr, &ipv4_drop_features,
			      pl_print_feats, wr);
	jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}

PL_REGISTER_OPCMD(pl_show_feat_ipv4_drop) = {
	.cmd = "show features ipv4_drop",
	.handler = cmd_pl_show_feat_ipv4_drop,
};
