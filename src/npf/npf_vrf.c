/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_branch_prediction.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <urcu.h>

#include "util.h"
#include "vrf_internal.h"
#include "vplane_log.h"
#include "dp_event.h"

#include "npf/config/npf_attach_point.h"
#include "npf/alg/alg_npf.h"
#include "npf/npf_timeouts.h"
#include "npf/npf_if.h"
#include "npf/npf_vrf.h"
#include "npf_shim.h"

/*
 * Ideally we would have a per-vrf set of ruleset counters in order to handle
 * rulesets such as nat64 and zones, where firewall pipeline features are
 * added to all interface when just one interface has such a ruleset.
 *
 * However we use a single global set of ruleset counters for nat64, zones
 * etc. for two reasons:
 *
 *   1. npf does not cleanly handle vrfs being deleted (specifically, the
 *      vrf ids changing of interfaces with attached rulesets)
 *   2. routing between vrfs
 */
static uint32_t npf_rs_count[NPF_RS_TYPE_COUNT];

struct npf_config *vrf_get_npf_conf_rcu(vrfid_t vrf_id)
{
	struct vrf *vrf = get_vrf(vrf_id);
	return vrf ? rcu_dereference(vrf->v_npf) : NULL;
}

void vrf_set_npf_timeout(struct vrf *vrf, struct npf_timeout *to)
{
	rcu_assign_pointer(vrf->v_to, to);
}

struct npf_timeout *vrf_get_npf_timeout(struct vrf *vrf)
{
	return vrf ? vrf->v_to : NULL;
}

struct npf_timeout *vrf_get_npf_timeout_rcu(vrfid_t vrf_id)
{
	struct vrf *vrf = get_vrf(vrf_id);
	return vrf ? rcu_dereference(vrf->v_to) : NULL;
}

void vrf_set_npf_alg(struct vrf *vrf, struct npf_alg_instance *ai)
{
	rcu_assign_pointer(vrf->v_ai, ai);
}

struct npf_alg_instance *vrf_get_npf_alg(struct vrf *vrf)
{
	return vrf ? vrf->v_ai : NULL;
}

struct npf_alg_instance *vrf_get_npf_alg_rcu(vrfid_t vrf_id)
{
	struct vrf *vrf = get_vrf(vrf_id);
	return vrf ? rcu_dereference(vrf->v_ai) : NULL;
}

/*
 * Invoked via a DP_EVT_VRF_CREATE event
 */
void npf_vrf_create(struct vrf *vrf)
{
	struct npf_alg_instance *ai;
	struct npf_timeout *to;
	uint32_t ext_vrfid;
	char vrfid_str[32];

	if (vrf->v_id == VRF_INVALID_ID)
		return;

	ext_vrfid = dp_vrf_get_external_id(vrf->v_id);
	snprintf(vrfid_str, sizeof(vrfid_str), "%u", ext_vrfid);

	int rc = npf_attpt_item_set_up(NPF_ATTACH_TYPE_VRF, vrfid_str,
				       &vrf->v_npf, NULL);
	if (rc != 0) {
		RTE_LOG(ERR, FIREWALL, "failed to register per-vrf "
					"rulesets with NPF - %d\n", -rc);
	}

	/* ALG Instance */
	ai = npf_alg_create_instance(ext_vrfid);
	if (ai)
		vrf_set_npf_alg(vrf, ai);
	else
		RTE_LOG(ERR, FIREWALL, "failed to create per-vrf "
					"NPF ALG instance\n");

	/* Timeout instance */
	to = npf_timeout_create_instance();
	if (to)
		vrf_set_npf_timeout(vrf, to);
	else
		RTE_LOG(ERR, FIREWALL, "failed to create per-vrf "
					"NPF timeout instance\n");
}

/*
 * Invoked via a DP_EVT_VRF_DELETE event
 */
void npf_vrf_delete(struct vrf *vrf)
{
	if (vrf->v_id == VRF_INVALID_ID)
		return;

	char vrfid_str[32];
	snprintf(vrfid_str, sizeof(vrfid_str), "%u",
		 dp_vrf_get_external_id(vrf->v_id));
	int rc = npf_attpt_item_set_down(NPF_ATTACH_TYPE_VRF, vrfid_str);
	if (rc != 0) {
		RTE_LOG(ERR, FIREWALL, "failed to detach per-vrf "
					"rulesets from NPF - %d\n", -rc);
	}
}

/*
 * Called from vrf_destroy, which is an RCU callback scheduled from
 * vrf_delete_by_ptr.
 */
void npf_vrf_destroy(struct vrf *vrf)
{
	if (vrf->v_id == VRF_INVALID_ID)
		return;

	/* ALG instance */
	npf_alg_destroy_instance(vrf->v_ai);
	vrf->v_ai = NULL;

	/* Timeout instance */
	npf_timeout_destroy_instance(vrf->v_to);
	vrf->v_to = NULL;
}

/*
 * Increment global ruleset count
 */
void npf_gbl_rs_count_incr(enum npf_ruleset_type rs_type)
{
	if (rs_type >= NPF_RS_TYPE_COUNT)
		return;

	assert(npf_rs_count[rs_type] < UINT_MAX);
	if (npf_rs_count[rs_type] == UINT_MAX) {
		RTE_LOG(ERR, DATAPLANE,
			"Cannot increment %s global ruleset count above max\n",
			npf_get_ruleset_type_name(rs_type));
		return;
	}

	/*
	 * Increment interface feature ref counts for this ruleset type for
	 * all interfaces when the ruleset count changes from 0 to 1 if it is
	 * a 'global' type.
	 */
	if (npf_rs_count[rs_type]++ == 0) {
		enum npf_rs_flag rfl;

		/* Are features applied for all interfaces? */
		rfl = npf_get_ruleset_type_flags(rs_type);

		if ((rfl & NPF_RS_FLAG_FEAT_GBL) != 0) {
			enum if_feat_flag ffl;

			/* Add niif reference for all interfaces */
			npf_if_reference_all();

			/* Enable features for all interfaces */
			ffl = npf_get_ruleset_type_feat_flags(rs_type);
			if_feat_all_refcnt_incr(ffl);
		}
	}
}

/*
 * Decrement global ruleset count
 */
void npf_gbl_rs_count_decr(enum npf_ruleset_type rs_type)
{
	if (rs_type >= NPF_RS_TYPE_COUNT)
		return;

	assert(npf_rs_count[rs_type] > 0);
	if (npf_rs_count[rs_type] == 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Cannot decrement %s global ruleset count below zero\n",
			npf_get_ruleset_type_name(rs_type));
		return;
	}

	/*
	 * Decrement interface feature ref counts for this ruleset type for
	 * all interfaces when the ruleset count changes from 1 to 0 if it is
	 * a 'global' type.
	 */
	if (--npf_rs_count[rs_type] == 0) {
		enum npf_rs_flag rfl;

		/* Are features applied for all interfaces? */
		rfl = npf_get_ruleset_type_flags(rs_type);

		if ((rfl & NPF_RS_FLAG_FEAT_GBL) != 0) {
			enum if_feat_flag ffl;

			/* Disable features for all interfaces */
			ffl = npf_get_ruleset_type_feat_flags(rs_type);
			if_feat_all_refcnt_decr(ffl);

			/* Remove niif reference for all interfaces */
			npf_if_release_all();
		}
	}
}

/*
 * Indirect callback for DP_EVT_IF_INDEX_SET event
 *
 * Check if any ruleset global counts are greater than zero.  If so, enable
 * those features on the interface and return true.
 *
 * Typically this is used when rulesets such as nat64 or zones require
 * features to be enabled for all interfaces and not just the interfaces with
 * the nat64/zone configuration.  In these situations the npf_rs_count[] for
 * the relevant ruleset will be greater than 0.
 *
 * Typically this function will be useful for when interfaces (such as vlan
 * interfaces) are created after bootup.
 */
void npf_vrf_if_index_set(struct ifnet *ifp)
{
	enum npf_ruleset_type rs_type;

	for (rs_type = 0; rs_type < NPF_RS_TYPE_COUNT; rs_type++) {
		enum npf_rs_flag rfl;

		rfl = npf_get_ruleset_type_flags(rs_type);

		/* Is global ruleset count > 0? */
		if (npf_rs_count[rs_type] > 0 &&
		    (rfl & NPF_RS_FLAG_FEAT_GBL) != 0) {
			enum if_feat_flag ffl;

			/* Enable features on interface */
			ffl = npf_get_ruleset_type_feat_flags(rs_type);
			if_feat_intf_multi_refcnt_incr(ifp, ffl);

			/* Create npf interface structure */
			npf_if_reference_one(ifp, NULL);
		}
	}
}

/*
 * Indirect callback for DP_EVT_IF_INDEX_UNSET event.
 *
 * Check if we need to remove any features that were added globally.
 */
void npf_vrf_if_index_unset(struct ifnet *ifp)
{
	enum npf_ruleset_type rs_type;

	/*
	 * If a ruleset type requires features to be enabled for all
	 * interfaces, then disable the relevant features for this deleted
	 * interface.
	 */
	for (rs_type = 0; rs_type < NPF_RS_TYPE_COUNT; rs_type++) {
		enum npf_rs_flag rfl;

		rfl = npf_get_ruleset_type_flags(rs_type);

		if (npf_rs_count[rs_type] > 0 &&
		    (rfl & NPF_RS_FLAG_FEAT_GBL) != 0) {
			enum if_feat_flag ffl;

			/* Disable features on interface */
			ffl = npf_get_ruleset_type_feat_flags(rs_type);
			if_feat_intf_multi_refcnt_decr(ifp, ffl);

			/* Release reference on npf interface structure */
			npf_if_release_one(ifp, NULL);
		}
	}
}
