/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_IF_H_
#define _CGN_IF_H_

struct ifnet;
struct cgn_policy;

struct cgn_intf {
	struct ifnet		*ci_ifp;
	struct cds_list_head	ci_policy_list;
};

void cgn_if_feat_enable(struct ifnet *ifp, bool enable);

int cgn_if_add_policy(struct ifnet *ifp, struct cgn_policy *cp);
int cgn_if_del_policy(struct ifnet *ifp, struct cgn_policy *cp);

/* Garbage collect the cgn interface structure */
void cgn_if_gc_intf(struct ifnet *ifp, bool if_unset);

/*
 * Called from npf callbacks for DP_EVT_IF_INDEX_SET and DP_EVT_IF_INDEX_UNSET
 * events.
 */
void cgn_nif_index_set(struct ifnet *ifp);
void cgn_nif_index_unset(struct ifnet *ifp);

struct cgn_policy *cgn_if_find_policy_by_name(struct ifnet *ifp,
					      const char *name);
struct cgn_policy *cgn_if_find_policy_by_addr(struct ifnet *ifp,
					      uint32_t addr);

/* npf/npf_if.c */
struct cgn_intf *npf_if_get_cgn(struct ifnet *ifp);
int npf_if_set_cgn(struct ifnet *ifp, struct cgn_intf *cgn);
int npf_if_clear_cgn(struct ifnet *ifp, bool lock);

#endif
