/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_debug.h>

#include "ecmp.h"
#include "fal.h"
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

static struct nexthop_table *nh_common_get_nh_table(int af_family)
{
	int family = af_family_to_family(af_family);
	if (family < 0)
		return NULL;

	if (nh_common_af[family].nh_get_nh_tbl)
		return nh_common_af[family].nh_get_nh_tbl();

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

static struct next_hop_list *nexthop_lookup(int family,
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
		return caa_container_of(node, struct next_hop_list, nh_node);
	else
		return NULL;
}

/* Reuse existing next hop entry */
static struct next_hop_list *nexthop_reuse(int family,
					   const struct nexthop_hash_key *key,
					   uint32_t *slot)
{
	struct next_hop_list *nhl;
	int index;

	nhl = nexthop_lookup(family, key);
	if (!nhl)
		return NULL;

	index = nhl->index;

	*slot = index;
	++nhl->refcount;

	DP_DEBUG(ROUTE, DEBUG, ROUTE,
		 "%s nexthop reuse: nexthop %d, refs %u\n",
		 family == AF_INET ? "IPv4" : "IPv6",
		 index, nhl->refcount);

	return nhl;
}

static int nexthop_hash_insert(int family, struct next_hop_list *nhl,
			       const struct nexthop_hash_key *key)
{
	struct cds_lfht_node *ret_node;
	unsigned long hash;
	struct cds_lfht *hash_tbl = nh_common_get_hash_table(family);
	nh_common_hash_fn *hash_fn = nh_common_get_hash_fn(family);
	nh_common_cmp_fn *cmp_fn = nh_common_get_hash_cmp_fn(family);

	cds_lfht_node_init(&nhl->nh_node);
	hash = hash_fn(key, 0);

	ret_node = cds_lfht_add_unique(hash_tbl, hash,
				       cmp_fn, key,
				       &nhl->nh_node);

	return (ret_node != &nhl->nh_node) ? EEXIST : 0;
}

struct next_hop_list *nexthop_alloc(int size)
{
	struct next_hop_list *nextl;

	nextl = calloc(1, sizeof(*nextl));
	if (unlikely(!nextl)) {
		RTE_LOG(ERR, ROUTE, "can't alloc next_hop_list\n");
		return NULL;
	}

	nextl->nh_fal_obj = calloc(size, sizeof(*nextl->nh_fal_obj));
	if (!nextl->nh_fal_obj) {
		free(nextl);
		return NULL;
	}

	if (size == 1) {
		/* Optimize for non-ECMP case by staying in cache line */
		nextl->siblings = &nextl->hop0;
	} else {
		nextl->siblings = calloc(1, size * sizeof(struct next_hop));
		if (unlikely(nextl->siblings == NULL)) {
			free(nextl->nh_fal_obj);
			free(nextl);
			return NULL;
		}
	}
	nextl->nsiblings = size;
	return nextl;
}

void __nexthop_destroy(struct next_hop_list *nextl)
{
	unsigned int i;

	for (i = 0; i < nextl->nsiblings; i++)
		nh_outlabels_destroy(&nextl->siblings[i].outlabels);
	if (nextl->siblings != &nextl->hop0)
		free(nextl->siblings);

	free(nextl->nh_fal_obj);
	free(nextl);
}

/* Callback from RCU after all other threads are done. */
void nexthop_destroy(struct rcu_head *head)
{
	struct next_hop_list *nextl
		= caa_container_of(head, struct next_hop_list, rcu);

	__nexthop_destroy(nextl);
}

/* Lookup (or create) nexthop based on hop information */
int nexthop_new(int family, const struct next_hop *nh, uint16_t size,
		uint8_t proto, uint32_t *slot)
{
	struct nexthop_hash_key key = {
				.nh = nh, .size = size, .proto = proto };
	struct next_hop_list *nextl;
	uint32_t rover;
	uint32_t nh_iter;
	int ret;
	struct nexthop_table *nh_table = nh_common_get_nh_table(family);

	if (!nh_table) {
		RTE_LOG(ERR, ROUTE, "Invalid family %d for new nexthop\n",
			family);
			return -EINVAL;
	}

	rover = nh_table->rover;
	nextl = nexthop_reuse(family, &key, slot);
	if (nextl)
		return 0;

	if (unlikely(nh_table->in_use == NEXTHOP_HASH_TBL_SIZE)) {
		RTE_LOG(ERR, ROUTE, "IPv%d next hop table full\n",
			family == AF_INET ? 4 : 6);
		return -ENOSPC;
	}

	nextl = nexthop_alloc(size);
	if (!nextl) {
		RTE_LOG(ERR, ROUTE, "IPv%d next hop table alloc failed\n",
			family == AF_INET ? 4 : 6);
		return -ENOMEM;
	}

	nextl->nsiblings = size;
	nextl->refcount = 1;
	nextl->index = rover;
	nextl->proto = proto;
	if (size == 1)
		nextl->hop0 = *nh;
	else
		memcpy(nextl->siblings, nh, size * sizeof(struct next_hop));

	if (unlikely(nexthop_hash_insert(family, nextl, &key))) {
		__nexthop_destroy(nextl);
		return -ENOMEM;
	}

	ret = fal_ip_new_next_hops(nextl->nsiblings, nextl->siblings,
				    &nextl->nhg_fal_obj,
				    nextl->nh_fal_obj);
	if (ret < 0 && ret != -EOPNOTSUPP)
		RTE_LOG(ERR, ROUTE,
			"FAL IPv4 next-hop-group create failed: %s\n",
			strerror(-ret));
	nextl->pd_state = fal_state_to_pd_state(ret);

	nh_iter = rover;
	do {
		nh_iter++;
		if (nh_iter >= NEXTHOP_HASH_TBL_SIZE)
			nh_iter = 0;
	} while ((rcu_dereference(nh_table->entry[nh_iter]) != NULL) &&
		 likely(nh_iter != rover));

	nh_table->rover = nh_iter;
	*slot = rover;
	nh_table->in_use++;

	rcu_assign_pointer(nh_table->entry[rover], nextl);

	return 0;
}

struct next_hop *
nexthop_create(struct ifnet *ifp, struct ip_addr *gw, uint32_t flags,
	       uint16_t num_labels, label_t *labels)
{
	struct next_hop *next = malloc(sizeof(struct next_hop));

	if (next) {
		/* Copying the v6 addr guarantees all bits are copied */
		next->gateway = *gw;
		next->flags = flags;
		nh_set_ifp(next, ifp);

		if (!nh_outlabels_set(&next->outlabels, num_labels,
					   labels)) {
			RTE_LOG(ERR, ROUTE,
				"Failed to set outlabels for nexthop with %u labels\n",
				num_labels);
			free(next);
			return NULL;
		}
	}
	return next;
}

void nexthop_put(int family, uint32_t idx)
{
	struct next_hop_list *nextl;
	struct nexthop_table *nh_table = nh_common_get_nh_table(family);
	struct cds_lfht *hash_tbl = nh_common_get_hash_table(family);

	if (!nh_table) {
		RTE_LOG(ERR, ROUTE, "Invalid family %d for nexthop put\n",
			family);
		return;
	}

	nextl = rcu_dereference(nh_table->entry[idx]);
	if (--nextl->refcount == 0) {
		struct next_hop *array = nextl->siblings;
		int ret;
		int i;

		nh_table->entry[idx] = NULL;
		--nh_table->in_use;

		for (i = 0; i < nextl->nsiblings; i++) {
			struct next_hop *nh = array + i;

			if (nh_is_neigh_present(nh))
				nh_table->neigh_present--;
			if (nh_is_neigh_created(nh))
				nh_table->neigh_created--;
		}

		if (fal_state_is_obj_present(nextl->pd_state)) {
			ret = fal_ip_del_next_hops(nextl->nhg_fal_obj,
						   nextl->nsiblings,
						   nextl->nh_fal_obj);
			if (ret < 0) {
				RTE_LOG(ERR, ROUTE,
					"FAL IPv%d next-hop-group delete failed: %s\n",
					family == AF_INET ? 4 : 6,
					strerror(-ret));
			}
		}

		cds_lfht_del(hash_tbl, &nextl->nh_node);
		call_rcu(&nextl->rcu, nexthop_destroy);
	}
}

/*
 * Create an array of next_hops based on the hops in the next_hop_list.
 */
struct next_hop *
next_hop_list_copy_next_hops(struct next_hop_list *nhl, int *size)
{
	struct next_hop *next, *n;
	struct next_hop *array = rcu_dereference(nhl->siblings);
	int i;

	*size = nhl->nsiblings;
	n = next = calloc(sizeof(struct next_hop), *size);
	if (!next)
		return NULL;

	for (i = 0; i < nhl->nsiblings; i++) {
		struct next_hop *nhl_next = array + i;

		memcpy(n, nhl_next, sizeof(struct next_hop));
		nh_outlabels_copy(&nhl_next->outlabels, &n->outlabels);
		n++;
	}
	return next;
}

int
nexthop_hash_del_add(int family,
		     struct next_hop_list *old_nhl,
		     struct next_hop_list *new_nhl)
{
	struct nexthop_hash_key key = {.nh = new_nhl->siblings,
				       .size = new_nhl->nsiblings,
				       .proto = new_nhl->proto };
	struct cds_lfht *hash_tbl = nh_common_get_hash_table(family);

	if (!hash_tbl) {
		RTE_LOG(ERR, ROUTE, "Invalid family %d for nh hash del add\n",
			family);
		return -EINVAL;
	}

	int rc;

	/* Remove old one */
	rc = cds_lfht_del(hash_tbl, &old_nhl->nh_node);
	assert(rc == 0);
	if (rc != 0)
		return rc;

	/* add new one */
	return nexthop_hash_insert(family, new_nhl, &key);
}

bool nh_is_connected(const struct next_hop *nh)
{
	if (nh->flags & (RTF_BLACKHOLE | RTF_REJECT |
			 RTF_SLOWPATH | RTF_GATEWAY |
			 RTF_LOCAL | RTF_NOROUTE))
		return false;

	return true;
}

bool nh_is_local(const struct next_hop *nh)
{
	if (nh->flags & RTF_LOCAL)
		return true;

	return false;
}

bool nh_is_gw(const struct next_hop *nh)
{
	if (nh->flags & RTF_GATEWAY)
		return true;

	return false;
}

void nh_set_neigh_present(int family,
			  struct next_hop *next_hop,
			  struct llentry *lle)
{
	struct nexthop_table *nh_table = nh_common_get_nh_table(family);

	if (!nh_table) {
		RTE_LOG(ERR, ROUTE,
			"Invalid family %d for set neigh present\n",
			family);
		return;
	}

	assert((next_hop->flags & RTF_NEIGH_PRESENT) == 0);
	next_hop->flags |= RTF_NEIGH_PRESENT;
	next_hop->u.lle = lle;
	nh_table->neigh_present++;
}

void nh_clear_neigh_present(int family,
			    struct next_hop *next_hop)
{
	struct nexthop_table *nh_table = nh_common_get_nh_table(family);

	if (!nh_table) {
		RTE_LOG(ERR, ROUTE,
			"Invalid family %d for clear neigh present\n",
			family);
		return;
	}

	assert(next_hop->flags & RTF_NEIGH_PRESENT);
	next_hop->flags &= ~RTF_NEIGH_PRESENT;
	next_hop->u.ifp = next_hop->u.lle->ifp;
	nh_table->neigh_present--;
}

void nh_set_neigh_created(int family,
			  struct next_hop *next_hop,
			  struct llentry *lle)
{
	struct nexthop_table *nh_table = nh_common_get_nh_table(family);

	if (!nh_table) {
		RTE_LOG(ERR, ROUTE,
			"Invalid family %d for set neigh created\n",
			family);
		return;
	}

	assert((next_hop->flags & RTF_NEIGH_CREATED) == 0);
	next_hop->flags |= RTF_NEIGH_CREATED;
	next_hop->u.lle = lle;
	nh_table->neigh_created++;
}

void nh_clear_neigh_created(int family,
			    struct next_hop *next_hop)
{
	struct nexthop_table *nh_table = nh_common_get_nh_table(family);

	if (!nh_table) {
		RTE_LOG(ERR, ROUTE,
			"Invalid family %d for clear neigh created\n",
			family);
		return;
	}
	assert(next_hop->flags & RTF_NEIGH_CREATED);
	next_hop->flags &= ~RTF_NEIGH_CREATED;
	next_hop->u.ifp = next_hop->u.lle->ifp;
	nh_table->neigh_created--;
}

int next_hop_list_nc_count(const struct next_hop_list *nhl)
{
	int count = 0;
	int i;
	struct next_hop *array = rcu_dereference(nhl->siblings);

	for (i = 0; i < nhl->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (nh_is_neigh_created(next))
			count++;
	}
	return count;
}

struct next_hop *next_hop_list_find_path_using_ifp(struct next_hop_list *nhl,
						   struct ifnet *ifp,
						   int *sibling)
{
	uint32_t i;
	struct next_hop *array = rcu_dereference(nhl->siblings);

	for (i = 0; i < nhl->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (dp_nh_get_ifp(next) == ifp) {
			*sibling = i;
			return next;
		}
	}
	return NULL;
}

bool next_hop_list_is_any_connected(const struct next_hop_list *nhl)
{
	uint32_t i;
	struct next_hop *array = rcu_dereference(nhl->siblings);

	for (i = 0; i < nhl->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (nh_is_connected(next))
			return true;
	}
	return false;
}

ALWAYS_INLINE struct next_hop *nexthop_mp_select(struct next_hop *next,
						 uint32_t size,
						 uint32_t hash)
{
	uint16_t path;

	if (ecmp_max_path && ecmp_max_path < size)
		size = ecmp_max_path;

	path = ecmp_lookup(size, hash);
	if (unlikely(next[path].flags & RTF_DEAD)) {
		/* retry to find a good path */
		for (path = 0; path < size; path++) {
			if (!(next[path].flags & RTF_DEAD))
				break;
		}

		if (path == size)
			return NULL;
	}
	return next + path;
}

ALWAYS_INLINE struct next_hop *nexthop_select(int family, uint32_t nh_idx,
					      const struct rte_mbuf *m,
					      uint16_t ether_type)
{
	struct next_hop_list *nextl;
	struct next_hop *next;
	uint32_t size;
	struct nexthop_table *nh_table = nh_common_get_nh_table(family);

	nextl = rcu_dereference(nh_table->entry[nh_idx]);
	if (unlikely(!nextl))
		return NULL;

	size = nextl->nsiblings;
	next = nextl->siblings;

	if (likely(size == 1))
		return next;

	return nexthop_mp_select(next, size, ecmp_mbuf_hash(m, ether_type));
}

/*
 * This is kept for backwards compatibility.
 */
ALWAYS_INLINE const struct in_addr *
dp_nh4_get_addr(const struct next_hop *next_hop)
{
	return &next_hop->gateway.address.ip_v4;
}

/*
 * This is kept for backwards compatibility.
 */
ALWAYS_INLINE const struct in6_addr *
dp_nh6_get_addr(const struct next_hop *next_hop)
{
	return &next_hop->gateway.address.ip_v6;
}
