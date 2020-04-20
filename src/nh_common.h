/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NH_COMMON_H
#define NH_COMMON_H

#include <netinet/in.h>
#include <netinet/in.h>

#include "fal_plugin.h"
#include "pd_show.h"
#include "urcu.h"

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

/*
 * This is the nexthop information result of route lookup - allows for
 * multiple nexthops in the case of ECMP
 */
struct next_hop_u {
	struct next_hop      *siblings;	/* array of next_hop */
	uint8_t              nsiblings;	/* # of next_hops */
	uint8_t              proto;	/* routing protocol */
	uint16_t             padding;
	uint32_t             index;
	struct next_hop      hop0;      /* optimization for non-ECMP */
	uint32_t             refcount;	/* # of LPM's referring */
	enum pd_obj_state    pd_state;
	struct cds_lfht_node nh_node;
	fal_object_t         nhg_fal_obj;   /* FAL handle for next_hop_group */
	fal_object_t         *nh_fal_obj; /* Per-nh FAL handles */
	struct rcu_head      rcu;
} __rte_cache_aligned;

/*
 * key for hashing an array of NHs. Size is the number of NHs in the array.
 */
struct nexthop_hash_key {
	const struct next_hop *nh;
	size_t		       size;
	uint8_t		       proto;
};

#endif /* NH_COMMON_H */
