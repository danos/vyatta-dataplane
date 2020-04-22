/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_debug.h>

#include "if_llatbl.h"
#include "nh_common.h"
#include "vplane_debug.h"

/*
 * use entry 0 for AF_INET
 * use entry 1 for AF_INET6
 */
struct nh_common nh_common_af[2];

void nh_common_register(int family, struct nh_common *nh_common)
{
	if (family == AF_INET) {
		nh_common_af[0] = *nh_common;
		return;
	}

	if (family == AF_INET6) {
		nh_common_af[1] = *nh_common;
		return;
	}

	rte_panic("Invalid family %d for nh registration\n", family);
}

static int af_family_to_family(int af_family)
{
	if (af_family == AF_INET)
		return 0;
	if (af_family == AF_INET6)
		return 1;

	return -1;
}

static struct cds_lfht *nh_common_get_hash_table(int af_family)
{
	int family = af_family_to_family(af_family);
	if (family < 0)
		return NULL;

	if (nh_common_af[family].nh_get_hash_tbl)
		return nh_common_af[family].nh_get_hash_tbl();

	return NULL;
}

static nh_common_hash_fn *nh_common_get_hash_fn(int af_family)
{
	int family = af_family_to_family(af_family);
	if (family < 0)
		return NULL;

	if (nh_common_af[family].nh_hash)
		return nh_common_af[family].nh_hash;

	return NULL;
}

static nh_common_cmp_fn *nh_common_get_hash_cmp_fn(int af_family)
{
	int family = af_family_to_family(af_family);
	if (family < 0)
		return NULL;

	if (nh_common_af[family].nh_compare)
		return nh_common_af[family].nh_compare;

	return NULL;
}

ALWAYS_INLINE struct ifnet *
dp_nh_get_ifp(const struct next_hop *next_hop)
{
	if (next_hop->flags & (RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT))
		return rcu_dereference(next_hop->u.lle->ifp);

	return rcu_dereference(next_hop->u.ifp);
}

ALWAYS_INLINE struct ifnet *
dp_nh4_get_ifp(const struct next_hop *next_hop)
{
	return dp_nh_get_ifp(next_hop);
}

ALWAYS_INLINE struct ifnet *
dp_nh6_get_ifp(const struct next_hop *next_hop)
{
	return dp_nh_get_ifp(next_hop);
}

ALWAYS_INLINE void
nh_set_ifp(struct next_hop *next_hop, struct ifnet *ifp)
{
	if (next_hop->flags & (RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT)) {
		rte_panic("Can't set interface for NH with linked neigh");
		return;
	}

	rcu_assign_pointer(next_hop->u.ifp, ifp);
}

struct next_hop_u *nexthop_lookup(int family,
				  const struct nexthop_hash_key *key)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct cds_lfht *hash_tbl = nh_common_get_hash_table(family);
	nh_common_hash_fn *hash_fn = nh_common_get_hash_fn(family);
	nh_common_cmp_fn *cmp_fn = nh_common_get_hash_cmp_fn(family);

	if (!hash_tbl || !hash_fn || !cmp_fn)
		return NULL;

	cds_lfht_lookup(hash_tbl,
			hash_fn(key, 0),
			cmp_fn, key, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct next_hop_u, nh_node);
	else
		return NULL;
}

/* Reuse existing next hop entry */
struct next_hop_u *nexthop_reuse(int family,
				 const struct nexthop_hash_key *key,
				 uint32_t *slot)
{
	struct next_hop_u *nu;
	int index;

	nu = nexthop_lookup(family, key);
	if (!nu)
		return NULL;

	index = nu->index;

	*slot = index;
	++nu->refcount;

	DP_DEBUG(ROUTE, DEBUG, ROUTE,
		 "%s nexthop reuse: nexthop %d, refs %u\n",
		 family == AF_INET ? "IPv4" : "IPv6",
		 index, nu->refcount);

	return nu;
}

int
nexthop_hash_insert(int family, struct next_hop_u *nu,
		    const struct nexthop_hash_key *key)
{
	struct cds_lfht_node *ret_node;
	unsigned long hash;
	struct cds_lfht *hash_tbl = nh_common_get_hash_table(family);
	nh_common_hash_fn *hash_fn = nh_common_get_hash_fn(family);
	nh_common_cmp_fn *cmp_fn = nh_common_get_hash_cmp_fn(family);

	cds_lfht_node_init(&nu->nh_node);
	hash = hash_fn(key, 0);

	ret_node = cds_lfht_add_unique(hash_tbl, hash,
				       cmp_fn, key,
				       &nu->nh_node);

	return (ret_node != &nu->nh_node) ? EEXIST : 0;
}

struct next_hop_u *nexthop_alloc(int size)
{
	struct next_hop_u *nextu;

	nextu = calloc(1, sizeof(*nextu));
	if (unlikely(!nextu)) {
		RTE_LOG(ERR, ROUTE, "can't alloc next_hop_u\n");
		return NULL;
	}

	nextu->nh_fal_obj = calloc(size, sizeof(*nextu->nh_fal_obj));
	if (!nextu->nh_fal_obj) {
		free(nextu);
		return NULL;
	}

	if (size == 1) {
		/* Optimize for non-ECMP case by staying in cache line */
		nextu->siblings = &nextu->hop0;
	} else {
		nextu->siblings = calloc(1, size * sizeof(struct next_hop));
		if (unlikely(nextu->siblings == NULL)) {
			free(nextu->nh_fal_obj);
			free(nextu);
			return NULL;
		}
	}
	nextu->nsiblings = size;
	return nextu;
}
