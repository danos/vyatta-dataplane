/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <stdio.h>
#include <urcu.h>

#include "util.h"
#include "vrf_internal.h"
#include "if_var.h"
#include "pl_node.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "vplane_log.h"
#include "if_feat.h"
#include "npf/npf_if_feat.h"

/*
 * Enable or disable ACL feature
 */
static void npf_if_feat_enable_acl_in(struct ifnet *ifp, bool enable)
{
	/* IP input. Attached to ipv[46]_validate */
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_acl_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_acl_in_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_acl_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_acl_in_feat, ifp);
	}
}

static void npf_if_feat_enable_acl_out(struct ifnet *ifp, bool enable)
{
	/* IP (post fragment) output. Attached to ipv[46]_encap */
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_acl_out_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_acl_out_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_acl_out_spath_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_acl_out_spath_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_acl_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_acl_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_acl_out_spath_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_acl_out_spath_feat, ifp);
	}
}

/*
 * Enable or disable defrag feature
 */
static void npf_if_feat_enable_defrag(struct ifnet *ifp, bool enable)
{
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_defrag_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_defrag_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_defrag_out_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_defrag_out_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_defrag_out_spath_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_defrag_out_spath_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_defrag_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_defrag_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_defrag_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_defrag_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_defrag_out_spath_feat,
					       ifp);
		pl_node_remove_feature_by_inst(&ipv6_defrag_out_spath_feat,
					       ifp);
	}
}

/*
 * Enable or disable fw feature
 */
static void npf_if_feat_enable_fw(struct ifnet *ifp, bool enable)
{
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_fw_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_fw_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_fw_out_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_fw_out_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_fw_out_spath_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_fw_out_spath_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_fw_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_fw_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_fw_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_fw_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_fw_out_spath_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_fw_out_spath_feat, ifp);
	}
}

/*
 * Enable or disable fw originate feature
 */
static void npf_if_feat_enable_fw_orig(struct ifnet *ifp, bool enable)
{
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_fw_orig_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_fw_orig_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_fw_orig_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_fw_orig_feat, ifp);
	}
}

/*
 * Enable or disable pbr feature
 */
static void npf_if_feat_enable_pbr(struct ifnet *ifp, bool enable)
{
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_pbr_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_pbr_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_pbr_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_pbr_feat, ifp);
	}
}

/*
 * Enable or disable nptv6 feature
 */
static void npf_if_feat_enable_nptv6(struct ifnet *ifp, bool enable)
{
	if (enable) {
		pl_node_add_feature_by_inst(&nptv6_in_feat, ifp);
		pl_node_add_feature_by_inst(&nptv6_out_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&nptv6_in_feat, ifp);
		pl_node_remove_feature_by_inst(&nptv6_out_feat, ifp);
	}
}

/*
 * Enable or disable cgnat feature
 */
static void npf_if_feat_enable_cgnat(struct ifnet *ifp, bool enable)
{
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_cgnat_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_cgnat_out_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_cgnat_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_cgnat_out_feat, ifp);
	}
}

/*
 * Enable or disable nat64 feature
 */
static void npf_if_feat_enable_nat64(struct ifnet *ifp, bool enable)
{
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_nat46_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_nat46_out_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_nat64_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_nat64_out_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_nat46_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_nat46_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_nat64_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_nat64_out_feat, ifp);
	}
}

void npf_if_feat_init(void)
{
	if_feat_init(npf_if_feat_enable_acl_in, "acl-in", IF_FEAT_ACL_IN);
	if_feat_init(npf_if_feat_enable_acl_out, "acl-out", IF_FEAT_ACL_OUT);
	if_feat_init(npf_if_feat_enable_defrag, "defrag", IF_FEAT_DEFRAG);
	if_feat_init(npf_if_feat_enable_fw, "firewall", IF_FEAT_FW);
	if_feat_init(npf_if_feat_enable_fw_orig, "fw-orig", IF_FEAT_FW_ORIG);
	if_feat_init(npf_if_feat_enable_pbr, "pbr", IF_FEAT_PBR);
	if_feat_init(npf_if_feat_enable_nptv6, "nptv6", IF_FEAT_NPTV6);
	if_feat_init(npf_if_feat_enable_cgnat, "cgnat", IF_FEAT_CGNAT);
	if_feat_init(npf_if_feat_enable_nat64, "nat64", IF_FEAT_NAT64);
	if_feat_init(NULL, "dpi", IF_FEAT_DPI);
}
