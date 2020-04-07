/*
 * Copyright (c) 2017,2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "nh.h"

ALWAYS_INLINE struct ifnet *
dp_nh4_get_ifp(const struct next_hop *next_hop)
{
	if (next_hop->flags & (RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT))
		return rcu_dereference(next_hop->u.lle->ifp);

	return rcu_dereference(next_hop->u.ifp);
}

ALWAYS_INLINE struct ifnet *
dp_nh6_get_ifp(const struct next_hop_v6 *next_hop)
{
	if (next_hop->flags & (RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT))
		return next_hop->u.lle->ifp;
	return next_hop->u.ifp;
}

ALWAYS_INLINE void
nh4_set_ifp(struct next_hop *next_hop, struct ifnet *ifp)
{
	if (next_hop->flags & (RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT)) {
		rte_panic("Can't set interface for NH with linked arp");
		return;
	}

	rcu_assign_pointer(next_hop->u.ifp, ifp);
}

ALWAYS_INLINE void
nh6_set_ifp(struct next_hop_v6 *next_hop, struct ifnet *ifp)
{
	if (next_hop->flags & (RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT)) {
		rte_panic("Can't set interface for NH6 with linked neigh");
		return;
	}
	next_hop->u.ifp = ifp;
}

ALWAYS_INLINE const struct in_addr *
dp_nh4_get_addr(const struct next_hop *next_hop)
{
	return (struct in_addr *)&next_hop->gateway;
}

ALWAYS_INLINE const struct in6_addr *
dp_nh6_get_addr(const struct next_hop_v6 *next_hop)
{
	return &next_hop->gateway;
}
