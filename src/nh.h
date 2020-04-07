/*
 * Common nexthop and nexthop_u processing
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NH_H
#define NH_H

#include "compiler.h"
#include "if_llatbl.h"
#include "netinet6/route_v6.h"
#include "route.h"

enum nh_fwd_ret {
	NH_FWD_FAILURE = -1,
	NH_FWD_SUCCESS = 0,
	NH_FWD_RESWITCH_IPv4 = 2,
	NH_FWD_RESWITCH_IPv6 = 3,
	NH_FWD_RESWITCH_MPLS = 4,
	NH_FWD_SLOWPATH,
	NH_FWD_IPv4,
	NH_FWD_IPv6,
};

enum nh_type {
	NH_TYPE_V4GW, /* struct next_hop  */
	NH_TYPE_V6GW, /* struct next_hop_v6 */
};

union next_hop_v4_or_v6_ptr {
	struct next_hop *v4;
	struct next_hop_v6 *v6;
};

#define NH_STRING_MAX 100

/*
 * funcs for manipulating abstract nh and nh set structs
 */

/* accessors */
static inline const union next_hop_outlabels *
nh_get_labels(enum nh_type nh_type, union next_hop_v4_or_v6_ptr nh)
{
	if (nh_type == NH_TYPE_V6GW)
		return &nh.v6->outlabels;

	assert(nh_type == NH_TYPE_V4GW);
	return &nh.v4->outlabels;
}

static inline uint32_t
nh_get_flags(enum nh_type nh_type, union next_hop_v4_or_v6_ptr nh)
{
	if (nh_type == NH_TYPE_V6GW)
		return nh.v6->flags;

	assert(nh_type == NH_TYPE_V4GW);
	return nh.v4->flags;
}

void
nh4_set_ifp(struct next_hop *next_hop, struct ifnet *ifp);

static ALWAYS_INLINE bool
nh4_is_neigh_created(const struct next_hop *next_hop)
{
	return next_hop->flags & RTF_NEIGH_CREATED;
}

static ALWAYS_INLINE bool
nh4_is_neigh_present(const struct next_hop *next_hop)
{
	return next_hop->flags & RTF_NEIGH_PRESENT;
}

static ALWAYS_INLINE struct llentry *
nh4_get_lle(const struct next_hop *next_hop)
{
	if (next_hop->flags & (RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT))
		return rcu_dereference(next_hop->u.lle);

	return NULL;
}

void
nh6_set_ifp(struct next_hop_v6 *next_hop, struct ifnet *ifp);

static ALWAYS_INLINE bool
nh6_is_neigh_created(const struct next_hop_v6 *next_hop)
{
	return next_hop->flags & RTF_NEIGH_CREATED;
}

static ALWAYS_INLINE bool
nh6_is_neigh_present(const struct next_hop_v6 *next_hop)
{
	return next_hop->flags & RTF_NEIGH_PRESENT;
}

static ALWAYS_INLINE struct llentry *
nh6_get_lle(const struct next_hop_v6 *next_hop)
{
	if (next_hop->flags & (RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT))
		return next_hop->u.lle;

	return NULL;
}

static ALWAYS_INLINE struct ifnet *
nh_get_if(enum nh_type nh_type, union next_hop_v4_or_v6_ptr nh)
{
	if (nh_type == NH_TYPE_V6GW)
		return dp_nh6_get_ifp(nh.v6);

	assert(nh_type == NH_TYPE_V4GW);
	return dp_nh4_get_ifp(nh.v4);
}

static inline union next_hop_v4_or_v6_ptr
nh_select(enum nh_type nh_type, uint16_t nh_idx,
	  const struct rte_mbuf *m, uint16_t ether_type)
{
	union next_hop_v4_or_v6_ptr nh;

	if (nh_type == NH_TYPE_V6GW)
		nh.v6 = nexthop6_select(nh_idx, m, ether_type);
	else {
		assert(nh_type == NH_TYPE_V4GW);
		nh.v4 = nexthop_select(nh_idx, m, ether_type);
	}
	return nh;
}

#endif /* NH_H */
