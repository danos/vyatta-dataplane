/*
 * l2_vlan_mod.c
 * *
 * Copyright (c) 2019-2021, AT&T Intellectual Property. All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "compiler.h"
#include "if_var.h"
#include "ether.h"
#include "util.h"
#include "ether.h"
#include "fal_plugin.h"
#include "vlan_modify.h"

#include "pl_common.h"
#include "pl_node.h"
#include "../pl_fused.h"
#include "pl_nodes_common.h"

static struct rte_mbuf *vlan_modify_ingress(struct ifnet *ifp,
					    struct rte_mbuf *m)
{
	struct rte_mbuf *ret;
	struct vlan_mod_ft_cls_action *action;
	uint16_t vlan;

	vlan = vlan_mod_get_vlan(m, ifp, VLAN_MOD_DIR_INGRESS);
	if (vlan == 0)
		return m;
	action = vlan_modify_get_action(ifp, vlan,
					VLAN_MOD_DIR_INGRESS);
	if (!action)
		return m;

	switch (action->data.vlan.action) {
	case VLAN_MOD_FILTER_ACT_VLAN_POP:
		ret = vlan_mod_tag_pop(ifp, &m,
				       VLAN_MOD_DIR_INGRESS);
		break;
	case VLAN_MOD_FILTER_ACT_VLAN_PUSH:
		ret =  vlan_mod_tag_push(ifp, &m, action,
					 VLAN_MOD_DIR_INGRESS);
		break;
	case VLAN_MOD_FILTER_ACT_VLAN_MOD:
		ret =  vlan_mod_tag_modify(ifp, &m, action,
					   VLAN_MOD_DIR_INGRESS);
		break;
	default:
		ret = NULL;
	}

	return ret;
}

ALWAYS_INLINE unsigned int
vlan_modify_in_check_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *ret;

	ret  = vlan_modify_ingress(pkt->in_ifp, pkt->mbuf);
	if (ret) {
		pkt->mbuf = ret;
		return VLAN_MOD_IN_ACCEPT;
	}
	return VLAN_MOD_IN_DROP;
}

static struct rte_mbuf *
vlan_modify_egress(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct rte_mbuf *ret;
	struct vlan_mod_ft_cls_action *action;
	uint16_t vlan;

	vlan = vlan_mod_get_vlan(m, ifp, VLAN_MOD_DIR_EGRESS);
	if (vlan == 0)
		return m;
	action = vlan_modify_get_action(ifp, vlan, VLAN_MOD_DIR_EGRESS);
	if (!action)
		return m;

	switch (action->data.vlan.action) {
	case VLAN_MOD_FILTER_ACT_VLAN_POP:
		ret = vlan_mod_tag_pop(ifp, &m, VLAN_MOD_DIR_EGRESS);
		break;
	case VLAN_MOD_FILTER_ACT_VLAN_PUSH:
		ret =  vlan_mod_tag_push(ifp, &m, action, VLAN_MOD_DIR_EGRESS);
		break;
	case VLAN_MOD_FILTER_ACT_VLAN_MOD:
		ret = vlan_mod_tag_modify(ifp, &m, action, VLAN_MOD_DIR_EGRESS);
		break;
	default:
		ret = NULL;
	}

	return ret;
}

ALWAYS_INLINE unsigned int
vlan_modify_out_check_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *ret;

	ret  = vlan_modify_egress(pkt->out_ifp, pkt->mbuf);
	if (ret) {
		pkt->mbuf = ret;
		return VLAN_MOD_OUT_ACCEPT;
	}
	return VLAN_MOD_OUT_DROP;
}

/* Register Node */
PL_REGISTER_NODE(vlan_mod_in_node) = {
	.name = "vyatta:vlan-modify-in",
	.type = PL_PROC,
	.handler = vlan_modify_in_check_process,
	.num_next = VLAN_MOD_IN_NUM,
	.next = {
		[VLAN_MOD_IN_ACCEPT]  = "term-noop",
		[VLAN_MOD_IN_DROP]   = "term-drop",
	}
};

PL_REGISTER_FEATURE(vlan_mod_in_feat) = {
	.name = "vyatta:vlan-modify-in",
	.node_name = "vlan-modify-in",
	.feature_point = "ether-lookup",
	.id = PL_ETHER_LOOKUP_FUSED_FEAT_VLAN_MOD_INGRESS,
	.visit_after = "portmonitor-in",
};

/* Register Node */
PL_REGISTER_NODE(vlan_mod_out_node) = {
	.name = "vyatta:vlan-modify-out",
	.type = PL_PROC,
	.handler = vlan_modify_out_check_process,
	.num_next = VLAN_MOD_OUT_NUM,
	.next = {
		[VLAN_MOD_OUT_ACCEPT]  = "term-noop",
		[VLAN_MOD_OUT_DROP]   = "term-drop",
	}
};

PL_REGISTER_FEATURE(vlan_mod_out_feat) = {
	.name = "vyatta:vlan-modify-out",
	.node_name = "vlan-modify-out",
	.feature_point = "l2-output",
	.id = PL_L2_OUTPUT_FUSED_FEAT_VLAN_MOD_EGRESS,
};
