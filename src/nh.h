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
	struct next_hop *v6;
};

#define NH_STRING_MAX 100

static inline union next_hop_v4_or_v6_ptr
nh_select(enum nh_type nh_type, uint16_t nh_idx,
	  const struct rte_mbuf *m, uint16_t ether_type)
{
	union next_hop_v4_or_v6_ptr nh;

	if (nh_type == NH_TYPE_V6GW)
		nh.v6 = nexthop6_select(AF_INET6, nh_idx, m, ether_type);
	else {
		assert(nh_type == NH_TYPE_V4GW);
		nh.v4 = nexthop_select(AF_INET, nh_idx, m, ether_type);
	}
	return nh;
}

#endif /* NH_H */
