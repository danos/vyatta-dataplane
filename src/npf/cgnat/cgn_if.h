/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_IF_H_
#define _CGN_IF_H_

struct ifnet;
struct cgn_policy;
struct cgn_intf;

uint32_t cgn_if_key_index(const struct ifnet *ifp);
struct ifnet *cgn_if_get_ifp(struct cgn_intf *ci);
struct cds_list_head *cgn_if_get_policy_list(struct ifnet *ifp);
void cgn_if_feat_enable(struct ifnet *ifp, bool enable);

int cgn_if_add_policy(struct ifnet *ifp, struct cgn_policy *cp);
int cgn_if_del_policy(struct ifnet *ifp, struct cgn_policy *cp);

void cgn_show_interface(FILE *f, int argc, char **argv);

/* Called from DP_EVT_IF_INDEX_UNSET event */
void cgn_if_disable(struct ifnet *ifp);

struct cgn_policy *cgn_if_find_policy_by_name(struct ifnet *ifp,
					      const char *name);
struct cgn_policy *cgn_if_find_policy_by_addr(struct ifnet *ifp,
					      uint32_t addr);

#endif /* CGN_IF_H */
