/*-
 * Copyright (c) 2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * VLAN interfaces
 */

#ifndef	VLAN_IF_H
#define	VLAN_IF_H

struct ifnet;
struct nlattr;

struct ifnet *
vlan_if_create(struct ifnet *ifp, uint16_t vid,
	       const char *ifname, int ifindex, uint16_t vlan_proto);
struct ifnet *
vlan_if_change(struct ifnet *ifp, uint16_t vid, struct ifnet *vifp,
	       uint16_t vlan_proto);
void
vlan_if_delete(struct ifnet *ifp);

struct ifnet *vlan_nl_create(struct ifnet *parent_ifp,
			     const char *ifname, int ifindex,
			     struct nlattr *lb);
void vlan_nl_modify(struct ifnet *ifp,
		    struct nlattr *tb[],
		    char const *kind, struct nlattr *kdata,
		    enum cont_src_en cont_src);

#endif /* VLAN_IF_H */
