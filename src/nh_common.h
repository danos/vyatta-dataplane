/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NH_COMMON_H
#define NH_COMMON_H

#include <netinet/in.h>
#include <netinet/in.h>

struct ifnet;
struct llentry;

/* Output information associated with a single nexthop */
struct next_hop {
	union {
		struct ifnet *ifp;     /* target interface */
		struct llentry *lle;   /* lle entry to use when sending */
	} u;
	uint32_t      flags;   /* routing flags */
	union next_hop_outlabels outlabels;
	union {
		in_addr_t       gateway4; /* nexthop IPv4 address */
		struct in6_addr gateway6; /* nexthop IPv6 address */
	};
};

#endif /* NH_COMMON_H */
