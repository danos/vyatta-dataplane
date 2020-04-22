/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NH_COMMON_H
#define NH_COMMON_H

#include <netinet/in.h>
#include <rte_fbk_hash.h>

#include "compiler.h"
#include "fal_plugin.h"
#include "pd_show.h"
#include "route_flags.h"
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

/*

 * The nexthop in LPM is 22 bits but dpdk hash tables currently have a
 * limit of 2^20 entries.
 */
#define NEXTHOP_HASH_TBL_SIZE RTE_FBK_HASH_ENTRIES_MAX
#define NEXTHOP_HASH_TBL_MIN  (UINT8_MAX + 1)

struct nexthop_table {
	uint32_t in_use;  /* # of entries used */
	uint32_t rover;   /* next free slot to look at */
	struct next_hop_u *entry[NEXTHOP_HASH_TBL_SIZE]; /* array of entries */
	uint32_t neigh_present;
	uint32_t neigh_created;
};

void nh_set_ifp(struct next_hop *next_hop, struct ifnet *ifp);

/*
 * Per AF hash function for a nexthop.
 */
typedef int (nh_common_hash_fn)(const struct nexthop_hash_key *key,
				unsigned long seed);

/*
 * Per AF function to compare nexthops
 */
typedef int (nh_common_cmp_fn)(struct cds_lfht_node *node, const void *key);

/*
 * get the hash table used to track NHs and if a new can be reused.
 */
typedef struct cds_lfht *(nh_common_get_hash_tbl_fn)(void);

/*
 * Get the table that the NHs are stored in.
 */
typedef struct nexthop_table *(nh_common_get_nh_tbl_fn)(void);

/*
 * Structure to hold all the function pointers required to do the
 * NH processing that differs between address families.
 */
struct nh_common {
	nh_common_hash_fn *nh_hash;
	nh_common_cmp_fn *nh_compare;
	nh_common_get_hash_tbl_fn *nh_get_hash_tbl;
	nh_common_get_nh_tbl_fn *nh_get_nh_tbl;
};

/*
 * Register AF specific behaviour for processing NHs.
 */
void nh_common_register(int family, struct nh_common *nh_common);

#endif /* NH_COMMON_H */
