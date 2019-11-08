/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
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

#include "compiler.h"
#include "if_var.h"
#include "util.h"

#include "pl_node.h"
#include "pipeline/nodes/pl_nodes_common.h"

#include "if_feat.h"
#include "npf/npf_if.h"

#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_policy.h"


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
static void
cgn_if_list_insert(struct cgn_policy *cp, struct cds_list_head *head)
{
	struct cds_list_head *pos, *newp = &cp->cp_list_node;
	struct cgn_policy *p;

	if (cds_list_empty(head)) {
		cds_list_add_rcu(newp, head);
		return;
	}

	for (pos = head->next; pos != head; pos = pos->next) {

		p = caa_container_of(pos, struct cgn_policy, cp_list_node);

		if (cp->cp_priority < p->cp_priority) {
			/*
			 * Insert newp/cp before pos/p
			 */
			newp->prev = pos->prev;
			newp->next = pos;

			rcu_assign_pointer(pos->prev->next, newp);
			rcu_assign_pointer(pos->prev, newp);
			return;
		}
	}
	if (pos == head)
		cds_list_add_tail_rcu(newp, head);
}

/*
 * Called via config.  May be called via command replay if interface was not
 * available at config time.
 *
 * Note that its possible the npf niif may not be available at this time.
 */
int cgn_if_add_policy(struct ifnet *ifp, struct cgn_policy *cp)
{
	struct cgn_intf *ci;

	/* Already in list? */
	if (cgn_if_find_policy_by_name(ifp, cp->cp_name))
		return 0;

	ci = npf_if_get_cgn(ifp);
	if (!ci) {
		ci = zmalloc_aligned(sizeof(*ci));
		if (!ci)
			return -1;

		ci->ci_ifp = ifp;
		CDS_INIT_LIST_HEAD(&ci->ci_policy_list);

		if (npf_if_set_cgn(ifp, ci) < 0) {
			free(ci);
			return -1;
		}
		cgn_if_feat_enable(ifp, true);
	}

	/* Add policy to cgn_intf list */
	cgn_if_list_insert(cp, &ci->ci_policy_list);
	cp->cp_ci = ci;

	cgn_policy_get(cp);

	return 0;
}

/*
 * Garbage collect the cgn interface structure.
 *
 * This is called after one or more policies are removed from the interface
 * policy list.  This can be either when a policy is unconfigured, or when an
 * interface is deleted.
 */
void cgn_if_gc_intf(struct ifnet *ifp, bool if_unset)
{
	struct cgn_intf *ci = npf_if_get_cgn(ifp);

	if (!ci)
		return;

	/*
	 * If cgn_intf is empty ... clear ptr in niif struct, free cgn_intf,
	 * and disable cgnat pipeline node.
	 */
	if (cds_list_empty(&ci->ci_policy_list)) {
		/*
		 * Do not lock npf niif if called from npf_if_disable_with_name
		 * since niif is already locked.
		 */
		npf_if_clear_cgn(ifp, !if_unset);
		free(ci);

		cgn_if_feat_enable(ifp, false);
	}
}

int cgn_if_del_policy(struct ifnet *ifp, struct cgn_policy *cp)
{
	struct cgn_intf *ci;

	if (!cgn_if_find_policy_by_name(ifp, cp->cp_name))
		return 0;

	ci = npf_if_get_cgn(ifp);
	if (!ci)
		return -1;

	/* Remove cp from cgn_intf list */
	cds_list_del_rcu(&cp->cp_list_node);
	cp->cp_ci = NULL;
	cgn_policy_put(cp);

	return 0;
}

/*
 * Look for cgnat policy by name on interface cgnat policy list
 */
struct cgn_policy *
cgn_if_find_policy_by_name(struct ifnet *ifp, const char *name)
{
	struct cgn_intf *ci;
	struct cgn_policy *cp;

	ci = npf_if_get_cgn(ifp);
	if (!ci)
		return NULL;

	cds_list_for_each_entry_rcu(cp, &ci->ci_policy_list, cp_list_node) {
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
	struct cgn_intf *ci;
	struct cgn_policy *cp;

	/* Get cgnat interface structure. */
	ci = npf_if_get_cgn(ifp);
	if (!ci)
		return NULL;

	cds_list_for_each_entry_rcu(cp, &ci->ci_policy_list, cp_list_node) {
		if (cp->cp_prefix == (addr & cp->cp_mask))
			return cp;
	}

	return NULL;
}

/*
 * Called from npf callbacks for DP_EVT_IF_INDEX_SET and DP_EVT_IF_INDEX_UNSET
 * events.
 */
void cgn_nif_index_set(struct ifnet *ifp __unused)
{
	/* Nothing to do */
}

/*
 * Called via npf index unset.
 */
void cgn_nif_index_unset(struct ifnet *ifp)
{
	struct cgn_policy *cp, *tmp;
	struct cgn_intf *ci;

	ci = npf_if_get_cgn(ifp);
	if (!ci)
		return;

	/* Delete CGNAT Policies */
	cds_list_for_each_entry_safe(cp, tmp, &ci->ci_policy_list,
				     cp_list_node)
		cgn_policy_if_index_unset(ifp, cp);

	/* If policy list is now empty, then free cgn intf */
	cgn_if_gc_intf(ifp, true);

}
