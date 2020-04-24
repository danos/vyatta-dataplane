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

#define NH_STRING_MAX 100

#endif /* NH_H */
