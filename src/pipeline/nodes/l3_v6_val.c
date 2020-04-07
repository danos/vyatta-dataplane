/*
 * l3_v4_val.c
 *
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/snmp.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdio.h>

#include "compat.h"
#include "compiler.h"
#include "if_var.h"
#include "ip6_funcs.h"
#include "npf/npf.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "route_v6.h"
#include "snmp_mib.h"
#include "util.h"
#include "vrf_internal.h"

struct pl_node;

static inline struct pl_node *ifp_to_ipv6_val_node(struct ifnet *ifp)
{
	/* our imaginary node */
	return (struct pl_node *)ifp;
}

static inline struct ifnet *ipv6_val_node_to_ifp(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct ifnet *)node;
}

ALWAYS_INLINE unsigned int
ipv6_validate_process_common(struct pl_packet *pkt, void *context __unused,
			     enum pl_mode mode)
{
	struct ip6_hdr *ip6 = ip6hdr(pkt->mbuf);
	struct ifnet *ifp = pkt->in_ifp;
	vrfid_t vrf_id = if_vrfid(ifp);

	IP6STAT_INC_VRF(vrf_get_rcu_fast(vrf_id), IPSTATS_MIB_INPKTS);

	if (unlikely(!ip6_validate_packet_and_count(pkt->mbuf, ip6, ifp)))
		return IPV6_VAL_DROP;

	pktmbuf_set_vrf(pkt->mbuf, vrf_id);
	pkt->l3_hdr = ip6;
	pkt->tblid = RT_TABLE_MAIN;
	pkt->npf_flags = NPF_FLAG_CACHE_EMPTY;

	/* Lookahead in route table */
	rt6_prefetch_fast(pkt->mbuf, &ip6->ip6_dst);

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv6_validate_features(
			    pkt, ifp_to_ipv6_val_node(ifp)))
			return IPV6_VAL_CONSUME;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv6_validate_no_dyn_features(
			    pkt, ifp_to_ipv6_val_node(ifp)))
			return IPV6_VAL_CONSUME;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    ipv6_validate_node_ptr,
			    ifp_to_ipv6_val_node(ifp),
			    pkt))
			return IPV6_VAL_CONSUME;
		break;
	}

	return IPV6_VAL_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv6_validate_process(struct pl_packet *p, void *context)
{
	return ipv6_validate_process_common(p, context, PL_MODE_REGULAR);
}

static int
ipv6_validate_feat_change(struct pl_node *node,
			  struct pl_feature_registration *feat,
			  enum pl_node_feat_action action)
{
	struct ifnet *ifp = ipv6_val_node_to_ifp(node);

	return pl_node_feat_change_u16(&ifp->ip6_in_features, feat, action);
}

static int
ipv6_validate_feat_change_all(struct pl_feature_registration *feat,
			      enum pl_node_feat_action action)
{
	return if_node_instance_feat_change_all(feat, action,
						ipv6_validate_feat_change);
}

ALWAYS_INLINE bool
ipv6_validate_feat_iterate(struct pl_node *node, bool first,
			   unsigned int *feature_id, void **context,
			   void **storage_ctx)
{
	struct ifnet *ifp = ipv6_val_node_to_ifp(node);
	bool ret;

	ret = pl_node_feat_iterate_u16(&ifp->ip6_in_features, first,
				       feature_id, context);
	if (ret)
		*storage_ctx = if_node_instance_get_storage_internal(
			ifp,
			PL_FEATURE_POINT_IPV6_VALIDATE_ID,
			*feature_id);

	return ret;
}

static struct pl_node *
ipv6_validate_node_lookup(const char *name)
{
	struct ifnet *ifp = dp_ifnet_byifname(name);
	return ifp ? ifp_to_ipv6_val_node(ifp) : NULL;
}

/* Register Node */
PL_REGISTER_NODE(ipv6_validate_node) = {
	.name = "vyatta:ipv6-validate",
	.type = PL_PROC,
	.handler = ipv6_validate_process,
	.feat_change = ipv6_validate_feat_change,
	.feat_change_all = ipv6_validate_feat_change_all,
	.feat_iterate = ipv6_validate_feat_iterate,
	.lookup_by_name = ipv6_validate_node_lookup,
	.feat_reg_context = if_node_instance_register_storage,
	.feat_unreg_context = if_node_instance_unregister_storage,
	.feat_get_context = if_node_instance_get_storage,
	.feat_setup_cleanup_cb = if_node_instance_set_cleanup_cb,
	.num_next = IPV6_VAL_NUM,
	.next = {
		[IPV6_VAL_ACCEPT]  = "ipv6-route-lookup",
		[IPV6_VAL_DROP]    = "ipv6-drop",
		[IPV6_VAL_CONSUME] = "term-finish",
	}
};

struct pl_node_registration *const ipv6_validate_node_ptr =
	&ipv6_validate_node;
