/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <linux/if.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "if_var.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"

struct pl_node;

static inline struct pl_node *ifp_to_ipv4_out_spath_node(struct ifnet *ifp)
{
	/* our imaginary node */
	return (struct pl_node *)ifp;
}

static inline struct ifnet *ipv4_out_spath_node_to_ifp(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct ifnet *)node;
}

ALWAYS_INLINE unsigned int
ipv4_out_spath_process_common(struct pl_packet *pkt, void *context __unused,
			      enum pl_mode mode)
{
	struct ifnet *out_ifp = pkt->out_ifp;

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv4_out_spath_features(
			    pkt, ifp_to_ipv4_out_spath_node(out_ifp)))
			return IPV4_OUT_SPATH_FINISH;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv4_out_spath_no_dyn_features(
			pkt, ifp_to_ipv4_out_spath_node(out_ifp)))
			return IPV4_OUT_SPATH_FINISH;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    ipv4_out_spath_node_ptr,
			    ifp_to_ipv4_out_spath_node(out_ifp),
			    pkt))
			return IPV4_OUT_SPATH_FINISH;
		break;
	}
	return IPV4_OUT_SPATH_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_out_spath_process(struct pl_packet *p, void *context)
{
	return ipv4_out_spath_process_common(p, context, PL_MODE_REGULAR);
}

static int
ipv4_out_spath_feat_change(struct pl_node *node,
		      struct pl_feature_registration *feat,
		      enum pl_node_feat_action action)
{
	struct ifnet *ifp = ipv4_out_spath_node_to_ifp(node);

	return pl_node_feat_change_u16(&ifp->ip_out_spath_features, feat,
				       action);
}

static int
ipv4_out_spath_feat_change_all(struct pl_feature_registration *feat,
			       enum pl_node_feat_action action)
{
	return if_node_instance_feat_change_all(feat, action,
						ipv4_out_spath_feat_change);
}

ALWAYS_INLINE bool
ipv4_out_spath_feat_iterate(struct pl_node *node, bool first,
			    unsigned int *feature_id, void **context,
			    void **storage_ctx __unused)
{
	struct ifnet *ifp = ipv4_out_spath_node_to_ifp(node);
	bool ret;

	ret = pl_node_feat_iterate_u16(&ifp->ip_out_spath_features, first,
				       feature_id, context);

	return ret;
}

static struct pl_node *
ipv4_out_spath_node_lookup(const char *name)
{
	struct ifnet *ifp = dp_ifnet_byifname(name);
	return ifp ? ifp_to_ipv4_out_spath_node(ifp) : NULL;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_out_spath_node) = {
	.name = "vyatta:ipv4-out-spath",
	.type = PL_PROC,
	.handler = ipv4_out_spath_process,
	.feat_change = ipv4_out_spath_feat_change,
	.feat_change_all = ipv4_out_spath_feat_change_all,
	.feat_iterate = ipv4_out_spath_feat_iterate,
	.lookup_by_name = ipv4_out_spath_node_lookup,
	.num_next = IPV4_OUT_SPATH_NUM,
	.next = {
		[IPV4_OUT_SPATH_ACCEPT] = "term-noop",
		[IPV4_OUT_SPATH_FINISH] = "term-finish",
	}
};

struct pl_node_registration *const ipv4_out_spath_node_ptr =
	&ipv4_out_spath_node;

/*
 * show features ipv4_out_spath [interface <ifname>]
 */
static int cmd_pl_show_feat_ipv4_out_spath(struct pl_command *cmd)
{
	return if_node_instance_feat_print(cmd, ipv4_out_spath_node_ptr);
}

PL_REGISTER_OPCMD(pl_show_feat_ipv4_out_spath) = {
	.cmd = "show features ipv4_out_spath",
	.handler = cmd_pl_show_feat_ipv4_out_spath,
};
