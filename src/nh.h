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


enum nh_type {
	NH_TYPE_V4GW, /* struct next_hop  */
	NH_TYPE_V6GW, /* struct next_hop_v6 */
};

#endif /* NH_H */
