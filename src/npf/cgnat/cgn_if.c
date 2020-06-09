/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_if.c - CGNAT interface functions
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <urcu/list.h>
#include <rte_branch_prediction.h>

#include "compiler.h"
#include "if_var.h"
#include "urcu.h"
#include "util.h"

#include "pl_node.h"
#include "pipeline/nodes/pl_nodes_common.h"

#include "if_feat.h"
#include "npf/npf_addrgrp.h"

#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_policy.h"


/*
 * Per-interface CGNAT data
 *
 * ci_feat_enabled is used to indicate whether this interface has enabled or
 * disabled the cgnat pipeline feature.
 *
 * ci_refcnt is incremented when a policy is added to the policy list or when
 * ci_feat_enabled changes to true.
 */
struct cgn_intf {
	struct ifnet		*ci_ifp;
	struct cds_list_head	ci_policy_list;
	uint			ci_policy_count;
	uint32_t		ci_index;	/* Session key index */
	bool			ci_feat_enabled;
	rte_atomic16_t		ci_refcnt;
	struct rcu_head		ci_rcu_head;
};

/*
 * Kernel ifindex is a signed int with range -1 - 0x7FFFFFFF.  The dataplane
 * ifindex is a uint32_t.  CGN_IF_INDEX_BASE is simply set to a large
 * round-ish number greater than 0x80000001 such that is does not look like a
 * random number if the show output.
 *
 * ci_index is either set to ifp->if_index or (CGN_IF_INDEX_BASE + vrf ID)
 */
#define CGN_IF_INDEX_BASE 2220000000


/*
 * Get index value to be used in session key
 */
uint32_t cgn_if_key_index(const struct ifnet *ifp)
{
	assert(ifp->if_cgn);
	if (likely(ifp->if_cgn))
		return ifp->if_cgn->ci_index;
	return ifp->if_index;
}

static struct cgn_intf *cgn_if_get(struct ifnet *ifp)
{
	if (ifp != NULL)
		return ifp->if_cgn;
	return NULL;
}

static void cgn_if_set(struct ifnet *ifp, struct cgn_intf *ci)
{
	if (ifp != NULL)
		rcu_assign_pointer(ifp->if_cgn, ci);
}

static void cgn_if_clear(struct ifnet *ifp)
{
	if (ifp != NULL)
		rcu_assign_pointer(ifp->if_cgn, NULL);
}

struct ifnet *cgn_if_get_ifp(struct cgn_intf *ci)
{
	if (likely(ci != NULL))
		return ci->ci_ifp;
	return NULL;
}

/* Take reference on ci */
static struct cgn_intf *cgn_ci_get(struct cgn_intf *ci)
{
	if (ci)
		rte_atomic16_inc(&ci->ci_refcnt);
	return ci;
}

static void cgn_ci_rcu_free(struct rcu_head *head)
{
	struct cgn_intf *ci = caa_container_of(head, struct cgn_intf,
					       ci_rcu_head);
	free(ci);
}

/* Release reference on ci */
static void cgn_ci_put(struct cgn_intf *ci)
{
	if (ci && rte_atomic16_dec_and_test(&ci->ci_refcnt)) {
		/* Clear cgnat handle on interface */
		cgn_if_clear(ci->ci_ifp);

		rcu_assign_pointer(ci->ci_ifp, NULL);

		/* Schedule rcu free */
		call_rcu(&ci->ci_rcu_head, cgn_ci_rcu_free);
	}
}

struct cds_list_head *cgn_if_get_policy_list(struct ifnet *ifp)
{
	struct cgn_intf *ci = cgn_if_get(ifp);

	if (likely(ci != NULL))
		return &ci->ci_policy_list;
	return NULL;
}

/*
 * Called when a CGNAT policy is attached to an interface
 */
static struct cgn_intf *cgn_if_create(struct ifnet *ifp)
{
	struct cgn_intf *ci;

	ci = zmalloc_aligned(sizeof(*ci));
	if (!ci)
		return NULL;

	CDS_INIT_LIST_HEAD(&ci->ci_policy_list);
	rte_atomic16_set(&ci->ci_refcnt, 0);

	rcu_assign_pointer(ci->ci_ifp, ifp);

	/* ci_index defaults to base + vrf ID */
	ci->ci_index = CGN_IF_INDEX_BASE + ifp->if_vrfid;

	/* Set cgnat handle on interface */
	cgn_if_set(ifp, ci);

	return ci;
}

/*
 * Enable or disable CGNAT pipeline feature node on an interface
 */
void cgn_if_feat_enable(struct ifnet *ifp, bool enable)
{
	if (enable) {
		pl_node_add_feature_by_inst(&ipv4_cgnat_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_cgnat_out_feat, ifp);
		if_feat_refcnt_incr(ifp, IF_FEAT_DEFRAG);
	} else {
		pl_node_remove_feature_by_inst(&ipv4_cgnat_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_cgnat_out_feat, ifp);
		if_feat_refcnt_decr(ifp, IF_FEAT_DEFRAG);
	}
}

/*
 * Insert a policy into list in order or priority, lowest value first.
 */
static void cgn_if_list_insert(struct cgn_policy *cp, struct cgn_intf *ci)
{
	struct cds_list_head *pos, *newp = &cp->cp_list_node;
	struct cds_list_head *policy_list = &ci->ci_policy_list;
	struct cgn_policy *p;

	if (cds_list_empty(policy_list)) {
		cds_list_add_rcu(newp, policy_list);
		goto end;
	}

	for (pos = policy_list->next; pos != policy_list; pos = pos->next) {

		p = caa_container_of(pos, struct cgn_policy, cp_list_node);

		if (cp->cp_priority < p->cp_priority) {
			/*
			 * Insert newp/cp before pos/p
			 */
			newp->prev = pos->prev;
			newp->next = pos;

			rcu_assign_pointer(pos->prev->next, newp);
			rcu_assign_pointer(pos->prev, newp);
			goto end;
		}
	}
	if (pos == policy_list)
		cds_list_add_tail_rcu(newp, policy_list);

end:
	/* Store back pointer to cgn intf struct */
	cp->cp_ci = ci;

	ci->ci_policy_count++;

	/* Take reference on ci while this policy is in the list */
	(void)cgn_ci_get(ci);
}

/*
 * Remove a policy from an interface list
 */
static void cgn_if_list_remove(struct cgn_policy *cp, struct cgn_intf *ci)
{
	/* Remove policy from the policy list */
	cds_list_del_rcu(&cp->cp_list_node);

	/* Disassociate the node from the list */
	CDS_INIT_LIST_HEAD(&cp->cp_list_node);

	/* Clear back pointer */
	cp->cp_ci = NULL;

	ci->ci_policy_count--;

	/* Assert that list state and list count agree */
	assert(cds_list_empty(&ci->ci_policy_list) ==
	       (ci->ci_policy_count == 0));

	/* If cgn_intf is empty then disable feature node. */
	if (cds_list_empty(&ci->ci_policy_list)) {

		if (ci->ci_feat_enabled) {
			/* Decrement cgnat feature count in interface */
			cgn_if_feat_enable(ci->ci_ifp, false);
			ci->ci_feat_enabled = false;

			/* Release reference on ci held by ci_feat_enabled */
			cgn_ci_put(ci);
		}
	}

	/* Release reference on ci that was held while policy was in list */
	cgn_ci_put(ci);
}

/*
 * Called via config.
 */
int cgn_if_add_policy(struct ifnet *ifp, struct cgn_policy *cp)
{
	struct cgn_intf *ci;

	/* Already in list? */
	if (cgn_if_find_policy_by_name(ifp, cp->cp_name))
		return 0;

	ci = cgn_if_get(ifp);
	if (!ci) {
		ci = cgn_if_create(ifp);
		if (!ci)
			return -ENOMEM;
	}

	/* Has this interface incremented the feature count? */
	if (!ci->ci_feat_enabled) {
		/* Increment cgnat feature count in interface */
		cgn_if_feat_enable(ifp, true);
		ci->ci_feat_enabled = true;

		/* Take reference on ci */
		(void)cgn_ci_get(ci);
	}

	/* Add policy to cgn_intf list */
	cgn_if_list_insert(cp, ci);

	/* Take reference on policy */
	cgn_policy_get(cp);

	return 0;
}

int cgn_if_del_policy(struct ifnet *ifp, struct cgn_policy *cp)
{
	struct cgn_intf *ci;

	if (!cgn_if_find_policy_by_name(ifp, cp->cp_name))
		return 0;

	ci = cgn_if_get(ifp);
	if (!ci)
		return -ENOENT;

	/* Remove policy from list. */
	cgn_if_list_remove(cp, ci);

	/* Release reference on policy */
	cgn_policy_put(cp);

	return 0;
}

/*
 * Look for cgnat policy by name on interface cgnat policy list
 */
struct cgn_policy *
cgn_if_find_policy_by_name(struct ifnet *ifp, const char *name)
{
	struct cds_list_head *policy_list;
	struct cgn_policy *cp;

	/* Get cgnat policy list from interface */
	policy_list = cgn_if_get_policy_list(ifp);
	if (!policy_list)
		return NULL;

	cds_list_for_each_entry_rcu(cp, policy_list, cp_list_node) {
		if (!strcmp(cp->cp_name, name))
			return cp;
	}

	return NULL;
}

/*
 * Lookup source address in policy list on an interface.
 *
 * This is the main cgnat lookup function for determining if a packet is to be
 * nat'd.  addr is in network byte order.
 */
struct cgn_policy *
cgn_if_find_policy_by_addr(struct ifnet *ifp, uint32_t addr)
{
	struct cds_list_head *policy_list;
	struct cgn_policy *cp;

	/* Get cgnat policy list from interface */
	policy_list = cgn_if_get_policy_list(ifp);
	if (!policy_list)
		return NULL;

	cds_list_for_each_entry_rcu(cp, policy_list, cp_list_node) {
		/*
		 * Is subscriber address in the match address-group?
		 */
		if (npf_addrgrp_lookup_v4_by_handle(cp->cp_match_ag,
						    addr) == 0)
			return cp;
	}
	return NULL;
}

/*
 * Show one cgnat interface
 */
static void cgn_if_show_intf_walk(struct ifnet *ifp, void *arg)
{
	json_writer_t *json = arg;
	struct cgn_intf *ci = ifp->if_cgn;

	if (!ci)
		return;

	jsonw_start_object(json);

	jsonw_string_field(json, "name", ifp->if_name);
	jsonw_uint_field(json, "vrf_id",
			 dp_vrf_get_external_id(ifp->if_vrfid));
	jsonw_uint_field(json, "ifindex", ifp->if_index);

	jsonw_uint_field(json, "session_index", ci->ci_index);
	jsonw_uint_field(json, "policy_count", ci->ci_policy_count);
	jsonw_bool_field(json, "feat_enabled", ci->ci_feat_enabled);
	jsonw_uint_field(json, "refcnt", rte_atomic16_read(&ci->ci_refcnt));

	jsonw_end_object(json);
}

/*
 * Show all cgnat interfaces
 */
static void cgn_if_show_intf(FILE *f)
{
	json_writer_t *json;

	json = jsonw_new(f);
	if (!json)
		return;
	jsonw_pretty(json, true);

	jsonw_name(json, "cgnat_interfaces");
	jsonw_start_array(json);

	dp_ifnet_walk(cgn_if_show_intf_walk, json);

	jsonw_end_array(json);
	jsonw_destroy(&json);
}

/* cgn-op show interface */
void cgn_show_interface(FILE *f, int argc __unused, char **argv __unused)
{
	cgn_if_show_intf(f);
}

/*
 * Callback for dataplane DP_EVT_IF_INDEX_UNSET event.
 */
void cgn_if_disable(struct ifnet *ifp)
{
	if (!cgn_if_get(ifp))
		return;

	/* Delete CGNAT Policies */
	cgn_policy_if_disable(ifp);
}
