/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <urcu/list.h>
#include <rte_debug.h>

#include "ecmp.h"
#include "fal.h"
#include "if_llatbl.h"
#include "ip_route.h"
#include "nh_common.h"
#include "urcu.h"
#include "vplane_debug.h"

static struct cds_lfht *next_hop_intf_hash;

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

static int next_hop_list_backup_count(const struct next_hop_list *nhl)
{
	int count = 0;
	int i;
	struct next_hop *array = rcu_dereference(nhl->siblings);

	for (i = 0; i < nhl->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (next->flags & RTF_BACKUP)
			count++;
	}
	return count;
}

static int next_hop_list_primary_count(const struct next_hop_list *nhl)
{
	int backups = next_hop_list_backup_count(nhl);

	if (backups)
		return nhl->nsiblings - backups;

	return 0;
}

static int next_hop_list_num_primaries_usable(struct next_hop_list *nextl)
{
	struct next_hop *array;
	int i, count = 0;
	bool backup = false;

	array = nextl->siblings;
	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (next->flags & RTF_BACKUP) {
			backup = true;
			continue;
		}
		if (next->flags & RTF_UNUSABLE)
			continue;
		count++;
	}

	if (backup)
		return count;

	/* No backups, therefore no primaries */
	return 0;
}

static void next_hop_map_use_backups(struct next_hop_list *nextl)
{
	int i, j;
	int backups = nextl->nsiblings - nextl->primaries;
	int slots[backups];
	struct next_hop *array;

	/* find the slots that we need to loop over */
	j = 0;
	array = nextl->siblings;
	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (next->flags & RTF_BACKUP) {
			slots[j] = i;
			j++;
		}
	}

	j = 0;
	for (i = 0; i < nextl->nh_map->count; i++) {
		CMM_STORE_SHARED(nextl->nh_map->index[i], slots[j]);
		j++;
		if (j >= backups)
			j = 0;
	}
}

/*
 * Called to update a map when a path has become unusable.
 */
static void next_hop_list_update_map(struct next_hop_list *nextl, int index)
{
	struct next_hop *array;
	int i, j = 0;
	int new_index = 0;
	int usable = next_hop_list_num_primaries_usable(nextl);

	if (usable == 0) {
		next_hop_map_use_backups(nextl);
		return;
	}

	/*
	 * Update with the smaller set of primaries that are usable
	 * The one at index is now unusable
	 */
	assert(nextl->siblings[index].flags & RTF_UNUSABLE);
	array = nextl->siblings;
	for (i = 0; i < nextl->nh_map->count; i++) {
		if (nextl->nh_map->index[i] == index) {
			/* Was using the now unusable path */

			for (j = 0; j < nextl->nsiblings; j++) {
				if (array[new_index].flags & (RTF_BACKUP |
							      RTF_UNUSABLE)) {
					new_index++;
					if (new_index >= nextl->nsiblings)
						new_index = 0;
					continue;
				}
				CMM_STORE_SHARED(nextl->nh_map->index[i],
						 new_index);
				new_index++;
				if (new_index >= nextl->nsiblings)
					new_index = 0;
				break;
			}
		}
	}
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
	if (nextl->nh_map)
		free(nextl->nh_map);

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

/*
 * Structure to store in the top level interface hash. Part of the 2 level
 * hash to allow lookups of all the NHs using an interface/gateway pair.
 */
struct next_hop_intf_entry {
	uint32_t ifindex;
	struct cds_lfht_node intf_hash_tbl_node;
	struct cds_lfht *gw_hash_tbl;
	struct rcu_head rcu;
};

static void next_hop_intf_entry_free(struct rcu_head *head)
{
	struct next_hop_intf_entry *if_entry
		= caa_container_of(head, struct next_hop_intf_entry, rcu);

	free(if_entry);
}

static int next_hop_intf_hash_cmp_fn(struct cds_lfht_node *node,
				     const void *key)
{
	struct next_hop_intf_entry *entry;
	uint32_t *ifindex =  (uint32_t *)key;

	entry = caa_container_of(node, struct next_hop_intf_entry,
				 intf_hash_tbl_node);

	if (entry->ifindex == *ifindex)
		return 1;

	return 0;
}

/*
 * Return the hash table that hold next_hops for the given interface.
 */
static struct next_hop_intf_entry *
next_hop_intf_hash_lookup(const struct ifnet *ifp)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (!next_hop_intf_hash)
		return NULL;

	cds_lfht_lookup(next_hop_intf_hash, ifp->if_index,
			next_hop_intf_hash_cmp_fn, &ifp->if_index, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct next_hop_intf_entry,
					intf_hash_tbl_node);
	else
		return NULL;
}


#define NH_INTF_HASH_TBL_MIN_SIZE 8
#define NH_INTF_HASH_TBL_MAX_SIZE 1024

static int next_hop_intf_hash_init(void)
{
	if (next_hop_intf_hash)
		return 0;

	next_hop_intf_hash = cds_lfht_new(NH_INTF_HASH_TBL_MIN_SIZE,
					  NH_INTF_HASH_TBL_MIN_SIZE,
					  NH_INTF_HASH_TBL_MAX_SIZE,
					  CDS_LFHT_AUTO_RESIZE,
					  NULL);
	if (!next_hop_intf_hash)
		return -ENOMEM;
	return 0;
}

static struct next_hop_intf_entry *
next_hop_intf_hash_add(const struct next_hop *next)
{
	struct next_hop_intf_entry *entry;
	struct ifnet *ifp = dp_nh_get_ifp(next);
	struct cds_lfht_node *ret_node;
	unsigned long hash;

	if (next_hop_intf_hash_init())
		return NULL;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return NULL;

	entry->ifindex = ifp->if_index;
	entry->gw_hash_tbl = cds_lfht_new(NH_INTF_HASH_TBL_MIN_SIZE,
					  NH_INTF_HASH_TBL_MIN_SIZE,
					  NH_INTF_HASH_TBL_MAX_SIZE,
					  CDS_LFHT_AUTO_RESIZE,
					  NULL);
	if (!entry->gw_hash_tbl) {
		free(entry);
		return NULL;
	}

	cds_lfht_node_init(&entry->intf_hash_tbl_node);
	hash = ifp->if_index;

	ret_node = cds_lfht_add_unique(next_hop_intf_hash, hash,
				       next_hop_intf_hash_cmp_fn,
				       &entry->ifindex,
				       &entry->intf_hash_tbl_node);

	if (ret_node != &entry->intf_hash_tbl_node) {
		/* This entry exists - this should not happen */
		cds_lfht_destroy(entry->gw_hash_tbl, NULL);
		free(entry);
		return caa_container_of(ret_node,
					struct next_hop_intf_entry,
					intf_hash_tbl_node);
	}

	return entry;
}

/*
 * Structure to store in the 2nd level hash. Part of the 2 level
 * hash to allow lookups of all the NHs using an interface/gateway pair.
 */
struct next_hop_gw_entry {
	struct ip_addr addr;
	struct cds_lfht_node gw_hash_tbl_node;
	struct cds_list_head intf_gw_nh_list;
	struct rcu_head rcu;
};

static unsigned long next_hop_gw_hash_fn(const struct ip_addr *key)
{
	int words = 1; /* for key->type */

	if (key->type == AF_INET)
		words += sizeof(struct in_addr) / 4;
	else if (key->type == AF_INET6)
		words += sizeof(struct in6_addr) / 4;
	return rte_jhash_32b((uint32_t *)key, words, 0);
}

static int next_hop_gw_hash_cmp_fn(struct cds_lfht_node *node,
				   const void *key)
{
	struct next_hop_gw_entry *gw_entry;
	const struct ip_addr *addr = key;

	gw_entry = caa_container_of(node, struct next_hop_gw_entry,
				    gw_hash_tbl_node);

	if (dp_addr_eq(addr, &gw_entry->addr))
		return 1;

	return 0;
}

static struct next_hop_gw_entry *
next_hop_gw_hash_lookup(struct cds_lfht *gw_hash_tbl,
			const struct ip_addr *gw)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(gw_hash_tbl,
			next_hop_gw_hash_fn(gw),
			next_hop_gw_hash_cmp_fn, gw, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct next_hop_gw_entry,
					gw_hash_tbl_node);
	else
		return NULL;
}

static struct next_hop_gw_entry *
next_hop_gw_hash_add(struct cds_lfht *gw_hash_tbl,
		     const struct ip_addr *gw)
{
	struct cds_lfht_node *ret_node;
	struct next_hop_gw_entry *gw_entry;

	gw_entry = malloc(sizeof(*gw_entry));
	if (!gw_entry)
		return NULL;

	gw_entry->addr = *gw;
	CDS_INIT_LIST_HEAD(&gw_entry->intf_gw_nh_list);

	ret_node = cds_lfht_add_unique(gw_hash_tbl,
				       next_hop_gw_hash_fn(&gw_entry->addr),
				       next_hop_gw_hash_cmp_fn, &gw_entry->addr,
				       &gw_entry->gw_hash_tbl_node);

	if (ret_node != &gw_entry->gw_hash_tbl_node) {
		/* This entry exists - this should not happen */
		free(gw_entry);
		return caa_container_of(ret_node,
					struct next_hop_gw_entry,
					gw_hash_tbl_node);
	}

	return gw_entry;
}

typedef void (next_hop_usability_change_cb)(struct next_hop *next);

static void next_hop_usability_check_update_cb(struct next_hop *next)
{
	struct next_hop_list *nextl = next->nhl;
	int rc;

	rc = fal_ip_upd_next_hop_unusable(nextl->nh_fal_obj,
					  next - nextl->siblings);
	if (rc < 0 && (rc != -EOPNOTSUPP)) {
		struct ifnet *ifp = dp_nh_get_ifp(next);
		char b[INET6_ADDRSTRLEN];

		RTE_LOG(ERR, ROUTE,
			"FAL Unable to mark next hop unusable %s %s (%s)\n",
			ifp ? ifp->if_name : "no interface",
			inet_ntop(next->gateway.type,
				  &next->gateway.address,
				  b, sizeof(b)),
			strerror(-rc));
	}
	next_hop_list_update_map(nextl, next - nextl->siblings);
}

static void
next_hop_intf_gw_list_mark_path_unusable(struct cds_list_head *list_head)
{
	struct cds_list_head *list_entry, *next;
	struct next_hop *nh;

	cds_list_for_each_safe(list_entry, next, list_head) {
		nh = cds_list_entry(list_entry, struct next_hop,
				    if_gw_list_entry);
		CMM_STORE_SHARED(nh->flags, nh->flags | RTF_UNUSABLE);
		next_hop_usability_check_update_cb(nh);
	}
}

void next_hop_mark_path_state(enum dp_rt_path_state state,
			      const struct dp_rt_path_unusable_key *key)
{
	struct ifnet *ifp = dp_ifnet_byifindex(key->ifindex);
	struct next_hop_intf_entry *intf_entry;
	struct next_hop_gw_entry *gw_entry;
	struct cds_lfht_iter iter;

	if (state != DP_RT_PATH_UNUSABLE)
		return;
	intf_entry = next_hop_intf_hash_lookup(ifp);
	if (!intf_entry)
		return;

	if (key->type == DP_RT_PATH_UNUSABLE_KEY_INTF) {
		cds_lfht_for_each_entry(intf_entry->gw_hash_tbl,
					&iter, gw_entry, gw_hash_tbl_node) {
			/* All NHs using this interface are unusable */
			next_hop_intf_gw_list_mark_path_unusable(
				&gw_entry->intf_gw_nh_list);
		}
	} else if (key->type == DP_RT_PATH_UNUSABLE_KEY_INTF_NEXTHOP) {
		gw_entry = next_hop_gw_hash_lookup(intf_entry->gw_hash_tbl,
						   &key->nexthop);
		if (!gw_entry)
			return;
		next_hop_intf_gw_list_mark_path_unusable(
			&gw_entry->intf_gw_nh_list);
	}
}

static void
next_hop_list_check_usability(struct next_hop_list *nextl,
			      next_hop_usability_change_cb change_cb)
{
	int backups = next_hop_list_backup_count(nextl);
	int primaries = nextl->nsiblings - backups;
	struct next_hop *array;
	enum dp_rt_path_state state;
	struct dp_rt_path_unusable_key key;
	int i;
	struct ifnet *ifp;

	if (!backups) {
		nextl->primaries = 0;
		return;
	}

	nextl->primaries = primaries;

	array = nextl->siblings;
	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *next = array + i;

		ifp = dp_nh_get_ifp(next);
		if (!ifp)
			continue;
		key.ifindex = ifp->if_index;
		if (nh_is_gw(next)) {
			key.type = DP_RT_PATH_UNUSABLE_KEY_INTF_NEXTHOP;
			key.nexthop = next->gateway;
		} else {
			key.type = DP_RT_PATH_UNUSABLE_KEY_INTF;
		}

		state = dp_rt_signal_check_paths_state(&key);

		if (state == DP_RT_PATH_UNUSABLE) {
			if (!(next->flags & RTF_UNUSABLE)) {
				next->flags |= RTF_UNUSABLE;
				if (change_cb)
					change_cb(next);
			}
		}
	}
}

static int next_hop_track_protected_nh(struct next_hop *next)
{
	struct next_hop_intf_entry *if_entry;
	struct next_hop_gw_entry *gw_entry;
	struct ifnet *ifp = dp_nh_get_ifp(next);

	if (!ifp || next->flags & RTF_BACKUP)
		return 0;

	if_entry = next_hop_intf_hash_lookup(ifp);
	if (!if_entry) {
		if_entry = next_hop_intf_hash_add(next);
		if (!if_entry) {
			RTE_LOG(ERR, ROUTE,
				"Failed to add protected NH to intf hash %d\n",
				ifp->if_index);
			return -1;
		}
	}

	gw_entry = next_hop_gw_hash_lookup(if_entry->gw_hash_tbl,
					   &next->gateway);
	if (!gw_entry) {
		gw_entry = next_hop_gw_hash_add(if_entry->gw_hash_tbl,
						&next->gateway);
		if (!gw_entry) {
			RTE_LOG(ERR, ROUTE,
				"Failed to add protected NH to gw hash %d\n",
				ifp->if_index);
			return -1;
		}
	}

	cds_list_add_rcu(&next->if_gw_list_entry, &gw_entry->intf_gw_nh_list);

	return 0;
}

static void next_hop_gw_entry_free(struct rcu_head *head)
{
	struct next_hop_gw_entry *gw_entry
		= caa_container_of(head, struct next_hop_gw_entry, rcu);

	free(gw_entry);
}

static int next_hop_untrack_protected_nh(struct next_hop *next)
{
	struct next_hop_intf_entry *if_entry;
	struct next_hop_gw_entry *gw_entry;
	struct ifnet *ifp = dp_nh_get_ifp(next);
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (!ifp || next->flags & RTF_BACKUP)
		return 0;

	if_entry = next_hop_intf_hash_lookup(ifp);
	if (!if_entry)
		return 0;

	gw_entry = next_hop_gw_hash_lookup(if_entry->gw_hash_tbl,
					   &next->gateway);
	if (!gw_entry)
		return 0;

	cds_list_del_rcu(&next->if_gw_list_entry);

	/* Delete the list if it is empty - no more with matching addr. */
	if (cds_list_empty(&gw_entry->intf_gw_nh_list)) {
		cds_lfht_del(if_entry->gw_hash_tbl,
			     &gw_entry->gw_hash_tbl_node);
		call_rcu(&gw_entry->rcu, next_hop_gw_entry_free);

	}

	/* Delete the 2nd level hash table if empty - no more on interface */
	cds_lfht_first(if_entry->gw_hash_tbl, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		cds_lfht_destroy(if_entry->gw_hash_tbl, NULL);
		cds_lfht_del(next_hop_intf_hash,
			     &if_entry->intf_hash_tbl_node);
		call_rcu(&if_entry->rcu, next_hop_intf_entry_free);
	}

	/* Delete the 1st level hash table if empty - no more protected nhs. */
	cds_lfht_first(next_hop_intf_hash, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		cds_lfht_destroy(next_hop_intf_hash, NULL);
		next_hop_intf_hash = NULL;
	}

	return 0;
}

static void next_hop_list_track_protected_nh(struct next_hop_list *nextl)
{
	int i;
	struct next_hop *array;

	if (nextl->primaries) {

		array = nextl->siblings;
		for (i = 0; i < nextl->nsiblings; i++) {
			struct next_hop *next = array + i;

			(void)next_hop_track_protected_nh(next);
		}
	}

	/*
	 * Now we need to recheck the usability to catch the case where
	 * the next_hop became unusable after installed in the fal but
	 * before it was installed in the hash table
	 */
	next_hop_list_check_usability(nextl,
				      next_hop_usability_check_update_cb);
}

static void next_hop_list_untrack_protected_nh(struct next_hop_list *nextl)
{
	int i;
	struct next_hop *array;

	if (nextl->primaries) {

		array = nextl->siblings;
		for (i = 0; i < nextl->nsiblings; i++) {
			struct next_hop *next = array + i;

			(void)next_hop_untrack_protected_nh(next);
		}
	}
}

/*
 * When building a new next_hop_list to swap into the forwarding state
 * we need to make sure that the lists at the end of the 2 stage hash
 * contain the new entry not the old one.
 */
static void next_hop_fixup_protected_tracking(struct next_hop_list *old,
					      struct next_hop_list *new)
{
	struct next_hop *old_array;
	struct next_hop *new_array;
	struct ifnet *ifp;
	struct next_hop_intf_entry *intf_entry;
	struct next_hop_gw_entry *gw_entry;
	int i;

	ASSERT_MASTER();

	if (!new->primaries)
		return;

	old_array = old->siblings;
	new_array = new->siblings;
	for (i = 0; i < new->nsiblings; i++) {
		struct next_hop *next_old = old_array + i;
		struct next_hop *next_new = new_array + i;

		ifp = dp_nh_get_ifp(next_old);
		if (!ifp)
			continue;

		intf_entry = next_hop_intf_hash_lookup(ifp);
		if (!intf_entry)
			return;

		gw_entry = next_hop_gw_hash_lookup(intf_entry->gw_hash_tbl,
						   &next_old->gateway);
		if (!gw_entry)
			return;
		/*
		 * Take the old entry out of the list, then add the new
		 * one.
		 */
		cds_list_del_rcu(&next_old->if_gw_list_entry);
		cds_list_add_rcu(&next_new->if_gw_list_entry,
				 &gw_entry->intf_gw_nh_list);
	}
}
/*
 * Create the nh_map for the list. Only use the map if there are backup paths.
 * We use (#primary_paths * (#primary_paths -1)) as the initial size of the map
 * as this gives us fairness on the first cutover of a path. This is limited
 * to a max of 64 entries to make sure it stays in a cache line.
 */
static int next_hop_list_init_map(struct next_hop_list *nextl)
{
	int num_entries;
	int primary_num = 0;
	int i, j = 0;
	struct next_hop *array;
	int primaries;

	/*
	 * Check usability of NHs before we build the map as we do not
	 * want unusable ones in there.
	 */
	next_hop_list_check_usability(nextl, NULL);

	if (nextl->primaries == 0)
		return 0;

	nextl->nh_map = malloc_aligned(sizeof(*nextl->nh_map));
	if (!nextl->nh_map)
		return -ENOMEM;

	/*
	 * Use the amount of usable primaries to work out the size so
	 * we still get fairness after another one goes down.
	 */
	primaries = next_hop_list_num_primaries_usable(nextl);
	if (primaries > 1)
		num_entries = primaries * (primaries - 1);
	else
		num_entries = 1;

	if (num_entries > NH_MAP_MAX_ENTRIES)
		num_entries = NH_MAP_MAX_ENTRIES;

	if (primaries) {
		nextl->nh_map->count = num_entries;
	} else {
		/*
		 * Set the count here as the func to use backup can be called
		 * due to a cutover and it will not change the count.
		 */
		nextl->nh_map->count = nextl->nsiblings - nextl->primaries;
		next_hop_map_use_backups(nextl);
		return 0;
	}

	array = nextl->siblings;
	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (next->flags & RTF_BACKUP)
			continue;

		for (j = 0; j < primaries; j++)
			nextl->nh_map->index[j * primaries + primary_num] = i;
		primary_num++;
	}
	return 0;
}

static void next_hop_list_setup_back_ptrs(struct next_hop_list *nextl)
{
	int i;
	struct next_hop *array;

	array = nextl->siblings;
	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *next = array + i;

		next->nhl = nextl;
	}
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
	next_hop_list_setup_back_ptrs(nextl);

	if (next_hop_list_init_map(nextl)) {
		__nexthop_destroy(nextl);
		return -ENOMEM;
	}

	if (unlikely(nexthop_hash_insert(family, nextl, &key))) {
		__nexthop_destroy(nextl);
		return -ENOMEM;
	}

	nextl->primaries = next_hop_list_primary_count(nextl);

	ret = fal_ip_new_next_hops(nextl->nsiblings, nextl->siblings,
				   &nextl->nhg_fal_obj,
				   nextl->nh_fal_obj);
	if (ret < 0 && ret != -EOPNOTSUPP)
		RTE_LOG(ERR, ROUTE,
			"FAL IPv4 next-hop-group create failed: %s\n",
			strerror(-ret));
	nextl->pd_state = fal_state_to_pd_state(ret);

	next_hop_list_track_protected_nh(nextl);

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

		next_hop_list_untrack_protected_nh(nextl);

		cds_lfht_del(hash_tbl, &nextl->nh_node);
		call_rcu(&nextl->rcu, nexthop_destroy);
	}
}

int next_hop_copy(struct next_hop *old, struct next_hop *new)
{
	bool success;

	new->u = old->u;
	new->flags = old->flags;
	new->gateway = old->gateway;
	success = nh_outlabels_copy(&old->outlabels, &new->outlabels);

	if (success)
		return 0;

	return -ENOMEM;
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

		if (next_hop_copy(nhl_next, n) < 0)
			goto fail;
		n++;
	}
	return next;

fail:
	/* Copy of a nh failed so cleanup */
	n = next;
	for (i = 0; i < nhl->nsiblings; i++)
		nh_outlabels_destroy(&n->outlabels);
	free(next);
	return NULL;
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

ALWAYS_INLINE struct next_hop *
nexthop_mp_select(const struct next_hop_list *nextl,
		  struct next_hop *next,
		  uint32_t size,
		  uint32_t hash)
{
	uint16_t path;
	int index;

	if (nextl->nh_map) {
		index = hash % nextl->nh_map->count;
		return next + (nextl->nh_map->index[index]);
	}

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

	return nexthop_mp_select(nextl, next, size,
				 ecmp_mbuf_hash(m, ether_type));
}

struct next_hop_list *
next_hop_list_create_copy_start(int family __unused,
				struct next_hop_list *old)
{
	struct next_hop_list *new_nextl;

	new_nextl = nexthop_alloc(old->nsiblings);
	if (!new_nextl)
		return NULL;

	if (old->nh_map) {
		new_nextl->nh_map = malloc(sizeof(*new_nextl->nh_map));
		if (!new_nextl->nh_map) {
			__nexthop_destroy(new_nextl);
			return NULL;
		}
	}

	new_nextl->proto = old->proto;
	new_nextl->primaries = old->primaries;
	new_nextl->index = old->index;
	new_nextl->refcount = old->refcount;

	return new_nextl;
}

int
next_hop_list_create_copy_finish(int family,
				 struct next_hop_list *old,
				 struct next_hop_list *new,
				 uint32_t old_idx)
{
	int rc;
	struct nexthop_table *nh_table = nh_common_get_nh_table(family);

	rc = nexthop_hash_del_add(family, old, new);
	if (rc < 0) {
		__nexthop_destroy(new);
		return rc;
	}

	if (old->nh_map)
		memcpy(new->nh_map, old->nh_map, sizeof(*new->nh_map));

	next_hop_list_setup_back_ptrs(new);

	/*
	 * It's safe to copy over the FAL objects without
	 * notifications as there are no FAL-visible changes to the
	 * object - it maintains its own linkage to the neighbour
	 */
	new->nhg_fal_obj = old->nhg_fal_obj;
	memcpy(new->nh_fal_obj, old->nh_fal_obj,
	       new->nsiblings * sizeof(*new->nh_fal_obj));
	new->pd_state = old->pd_state;

	assert(nh_table->entry[old_idx] == old);
	rcu_xchg_pointer(&nh_table->entry[old_idx], new);

	next_hop_fixup_protected_tracking(old, new);
	/*
	 * Now we need to recheck the usability to catch the case where
	 * a next_hop became unusable and was some way through processing
	 * an update to the old map as we were updating it here.
	 */
	next_hop_list_check_usability(new,
				      next_hop_usability_check_update_cb);

	call_rcu(&old->rcu, nexthop_destroy);

	return 0;
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

void nexthop_map_display(const struct next_hop_list *nextl,
			 json_writer_t *jsonw)
{
	int i;

	if (!nextl->nh_map)
		return;

	jsonw_uint_field(jsonw, "nh_map_count", nextl->nh_map->count);
	jsonw_name(jsonw, "nh_map");
	jsonw_start_array(jsonw);
	for (i = 0; i < nextl->nh_map->count; i++)
		jsonw_uint(jsonw, nextl->nh_map->index[i]);
	jsonw_end_array(jsonw);
}
