/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <assert.h>
#include <czmq.h>
#include <errno.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_rwlock.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "json_writer.h"
#include "npf/npf.h"
#include "npf_addrgrp.h"
#include "npf_cidr_util.h"
#include "npf_ptree.h"
#include "npf_tblset.h"
#include "urcu.h"
#include "util.h"

struct ptree_node;
struct ptree_table;

/*
 * NPF Address Groups
 *
 * When the user configures an address resource-group for use with Firewall
 * rules etc., then an address-group is created.
 *
 * Up to 1024 address-groups may be created.  Management of the address-groups
 * is done via the tableset utility (npf_tblset.c).
 *
 * Lookup of an address by the forwarding threads occurs via the npf 'grouper'
 * (ruleset bytecode), and a Patricia Tree (npf_ptree.c).  The Patricia Tree
 * implementation is optimised for use with address-groups in that
 * address-groups only want to know "is this address a member of this group?".
 *
 * In order to keep the Patricia Tree implementation small and fast, the
 * address-group management layer hides some of the configuration details from
 * the Patricia Tree by using zlists to store what the user actually
 * configured.  This is necessary for two reasons:
 *
 * 1. Multiple masks for the same prefix.  To maintain backwards compatibility
 *    we need to allow multiple mask lengths for the same prefix, however the
 *    Patricia Tree implementation only allows unique keys.  The address-group
 *    stores the multiple masks in a short array, but only programs the
 *    Patricia Tree with the shortest mask.

 * 2. Address ranges.  In order to allow address ranges, we store the range in
 *    the address-group, and use that to create the smallest set of prefixes
 *    to program into the Patricia Tree (using npf_cidr_util.c).
 *
 * Up to 7 masks are allowed per prefix.  This is purely arbitrary (we could
 * allow more.  The structure union would let us have 28 'for free').
 *
 * It should be noted that having the same prefix multiple masks could be
 * considered a misconfiguration, so we should consider transitioning the
 * users config away from that.
 *
 * We do not allow address ranges to overlap with either other address range
 * entries or with prefixes.
 *
 * Changes to an address-groups ptree are protected by a read-write lock.
 *
 *
 * g_addrgrp_table[]
 *      |
 *      v
 * Address Group 1                                        ptree
 * +---------+                                           +---------+
 * | ag_tree |------------------------------------------>|         |
 * +---------+       +---------+                         |         |
 * | ag_list |------>| prefix  |                         |         |
 * +---------+       +---------+                         +---------+
 *      |            | prefix  |
 *      |            +---------+
 *      |            | prefix  |
 *      |            +---------+       +---------+
 *      |            | range   |------>| prefix  |
 *      |            | pfx_list|       +---------+
 *      |            +---------+       | prefix  |
 *      v                              +---------+
 *  Address Group 2
 * +---------+
 * | ag_tree |
 * +---------+
 * | ag_list |
 * +---------+
 */


/* Single, global, address-group "table of tables" (tableset) */
static struct npf_tbl *g_addrgrp_table;

/*
 * Start off with space for 32 tables.  Allow re-sizing to up to 1024 tables.
 */
#define NPF_ADDRGRP_SZ     32
#define NPF_ADDRGRP_SZ_MAX 1024
#define NPF_ADDRGRP_CTL    TS_TBL_RESIZE

/*
 * Allow two types of entry in the address-group lists:
 *
 * 1. Prefix and mask, with up to 7 different masks per prefix.
 * 2. Address range
 */
enum {
	NPF_ADDRGRP_TYPE_PREFIX = 0,
	NPF_ADDRGRP_TYPE_RANGE = 1,
};

/*
 * Max masks per prefix, e.g. 10.0.0.0/16 and 10.0.0.0/24 would result in one
 * entry with two mask lengths.  Only the shortest mask is added to the tree.
 * Multiple masks are required for backwards compatibility with previous
 * tableset implementation.
 *
 * We also allow both the following two entries be added via the cli:
 * 10.0.0.1/32 and 10.0.0.1.  This will result in one entry in the dataplane,
 * with two mask lengths 32 and 255 (NPF_NO_NETMASK).
 */
#define NPF_ADDRGRP_MASKS_MAX 7

/*
 * address-group union member for prefix entries
 *
 * If multiple prefixes have the same prefix, but different mask lengths, then
 * we store the mask lengths in order of shortest to longest.  The shortest
 * mask is the only mask programmed into the ptree.
 */
struct ag_prefix {
	uint8_t    nmasks;
	uint8_t    mask[NPF_ADDRGRP_MASKS_MAX];
};

/*
 * address-group union member for range entries
 */
struct ag_range {
	/* A set of prefixes is derived from the range */
	zlist_t    *pfx_list;
};

/*
 * address-group entry.  May be a prefix (plus one or more mask lengths), or
 * an address range.
 *
 * Addresses are stored in *network* byte order.
 */
struct npf_addrgrp_entry {
	struct npf_addrgrp *ae_ag;

	union {
		struct ag_range  range;
		struct ag_prefix prefix;
	} u;

	uint8_t             ae_type:1;
	uint8_t             ae_af:1;
	/* true if prefix entry and in ptree */
	uint8_t             ae_ptree:1;

	/*
	 * One address for prefix entries, two addresses for range entries.
	 * Must be last.
	 *
	 * Note, this is aligned to a 4-byte boundary whereas the structure is
	 * aligned to 8 bytes, hence we allow for one uint32_t here and take
	 * account of this in the malloc.
	 */
	uint32_t ae_addrs[1];
};

/* prefix entry */
#define ap_nmasks u.prefix.nmasks
#define ap_mask   u.prefix.mask

/* range entry */
#define ar_list  u.range.pfx_list

/*
 * address-group
 *
 * Each address-group is an entry in the global tableset, g_addrgrp_table
 * ("table of tables").
 *
 * A zlist is used to manage the address-group entries.  Entries from the list
 * are filtered and optimized to a minimal set of prefixes, which are then
 * added to the ptrees.
 *
 * Each list entry may be either a prefix or range.
 */
struct npf_addrgrp {
	char               *ag_name;
	int                 ag_tid;  /* Index of ag in tableset */
	rte_rwlock_t        ag_lock;
	bool                ag_any[AG_MAX];  /* 0.0.0.0/0 or ::/0 */
	zlist_t            *ag_list[AG_MAX];
	struct ptree_table *ag_tree[AG_MAX];
};

#define AG_KLEN_IPv4 4
#define AG_KLEN_IPv6 16

#define AG_ALEN2AF(_alen) ((_alen) == 4 ? AG_IPv4 : AG_IPv6)
#define AG_AF2ALEN(_af)   ((_af) == AG_IPv4 ? AG_KLEN_IPv4 : AG_KLEN_IPv6)
#define AG_AF2INET(_af)   ((_af) == AG_IPv4 ? AF_INET : AF_INET6)

/*
 * We store NPF_NO_NETMASK (255) in the prefix list to allow for the user to
 * add, for example, both 10.0.0.1 and 10.0.0.1/32.  Only one from the list is
 * ever added to the ptree at any one time. However we must still use the
 * correct mask value when adding and removing host entries from the ptree.
 */
static inline uint8_t ag_ptree_mask(enum npf_addrgrp_af af, uint8_t mask)
{
	uint8_t max_mask = (af == AG_IPv4) ? 32 : 128;
	return MIN(mask, max_mask);
}

/*
 * Accessor to range start addr in address-group entry zero length word array
 */
static inline uint8_t *ar_start(struct npf_addrgrp_entry *ae)
{
	return (uint8_t *)ae->ae_addrs;
}

/*
 * Accessor to range end addr in address-group entry zero length word array.
 *
 * There are only ever two addresses in this space, so adding the
 * address-length to the start pointer gets us the second address.
 */
static inline uint8_t *ar_end(struct npf_addrgrp_entry *ae)
{
	return (uint8_t *)(ae->ae_addrs) + AG_AF2ALEN(ae->ae_af);
}

/*
 * Accessor to prefix addr in address-group entry zero length word array
 */
static inline uint8_t *ap_prefix(struct npf_addrgrp_entry *ae)
{
	return (uint8_t *)ae->ae_addrs;
}

/*
 * Get the address-group for an address family and table ID
 */
struct npf_addrgrp *npf_addrgrp_tid_lookup(int tid)
{
	struct npf_tbl *table;

	table = rcu_dereference(g_addrgrp_table);
	if (unlikely(!table))
		return NULL;

	/*
	 * Table ID to address-group.  This does an rcu_dereference of
	 * g_addrgrp_table[tid].
	 */
	return npf_tbl_id_lookup(table, tid);
}

/*
 * Lookup an address in an address-group.  Called from forwarding thread.
 */
int
npf_addrgrp_lookup(enum npf_addrgrp_af af, struct npf_addrgrp *ag,
		   npf_addr_t *addr)
{
	struct ptree_node *pn;

	if (unlikely(!ag))
		return -EINVAL;

	assert(af == AG_IPv4 || af == AG_IPv6);

	/* If 0.0.0.0/0 (or ::/0) then we always match */
	if (ag->ag_any[af])
		return 0;

	rte_rwlock_read_lock(&ag->ag_lock);

	pn = ptree_shortest_match(ag->ag_tree[af], addr->s6_addr);

	rte_rwlock_read_unlock(&ag->ag_lock);

	return (pn != NULL) ? 0 : -ENOENT;
}

int npf_addrgrp_lookup_v4(struct npf_addrgrp *ag, uint32_t addr)
{
	struct ptree_node *pn;

	if (unlikely(!ag))
		return -EINVAL;

	/* If 0.0.0.0/0 then we always match */
	if (ag->ag_any[AG_IPv4])
		return 0;

	rte_rwlock_read_lock(&ag->ag_lock);

	pn = ptree_shortest_match(ag->ag_tree[AG_IPv4], (uint8_t *)&addr);

	rte_rwlock_read_unlock(&ag->ag_lock);

	return (pn != NULL) ? 0 : -ENOENT;
}

int npf_addrgrp_lookup_v6(struct npf_addrgrp *ag, uint8_t *addr)
{
	struct ptree_node *pn;

	if (unlikely(!ag))
		return -EINVAL;

	/* If 0.0.0.0/0 then we always match */
	if (ag->ag_any[AG_IPv6])
		return 0;

	rte_rwlock_read_lock(&ag->ag_lock);

	pn = ptree_shortest_match(ag->ag_tree[AG_IPv6], addr);

	rte_rwlock_read_unlock(&ag->ag_lock);

	return (pn != NULL) ? 0 : -ENOENT;
}

/*
 * Create an address-group tableset
 */
static int
npf_addrgrp_tbl_create(void)
{
	struct npf_tbl *table;

	if (!g_addrgrp_table) {
		table = npf_tbl_create(0, NPF_ADDRGRP_SZ, NPF_ADDRGRP_SZ_MAX,
				       sizeof(struct npf_addrgrp),
				       NPF_ADDRGRP_CTL);

		if (!table)
			return -1;

		rcu_assign_pointer(g_addrgrp_table, table);
	}
	return 0;
}

static int _npf_addrgrp_destroy(struct npf_addrgrp *ag);
static void npf_addrgrp_data_destroy(struct npf_addrgrp *ag);

/*
 * Callback for each address-group in the tableset
 */
static int
npf_addrgrp_destroy_cb(const char *name __unused, uint id __unused, void *data,
		       void *ctx __unused)
{
	struct npf_addrgrp *ag = data;

	/* Destroy address group */
	return _npf_addrgrp_destroy(ag);
}

/*
 * Destroy address-group tableset
 */
int
npf_addrgrp_tbl_destroy(void)
{
	struct npf_tbl *table;

	if (!g_addrgrp_table)
		return -EINVAL;

	if (npf_tbl_size(g_addrgrp_table) > 0)
		npf_tbl_walk(g_addrgrp_table, npf_addrgrp_destroy_cb, NULL);

	if (npf_tbl_size(g_addrgrp_table) != 0)
		return -EEXIST;

	table = g_addrgrp_table;
	g_addrgrp_table = NULL;

	npf_tbl_destroy(table);

	return 0;
}

/*
 * Return number of tables in the address-group tableset
 */
uint npf_addrgrp_ntables(void)
{
	return npf_tbl_size(g_addrgrp_table);
}

/*
 * Lookup an address-group by name in the tableset
 */
struct npf_addrgrp *npf_addrgrp_lookup_name(const char *name)
{
	return npf_tbl_name_lookup(g_addrgrp_table, name);
}

/*
 * Returns number of entries in an address-group
 */
int npf_addrgrp_nentries(const char *name)
{
	struct npf_addrgrp *ag;

	ag = npf_tbl_name_lookup(g_addrgrp_table, name);
	if (!ag)
		return 0;

	return zlist_size(ag->ag_list[AG_IPv4]) +
		zlist_size(ag->ag_list[AG_IPv6]);
}

/*
 * Is this a valid address-group table ID?  Called by the bytecode
 * verification function, so check the table ID is valid *and* a table exists.
 */
bool
npf_addrgrp_tid_valid(uint32_t tid)
{
	struct npf_tbl *table;

	table = rcu_dereference(g_addrgrp_table);
	if (!table)
		return false;

	if (!npf_tbl_id_lookup(table, tid))
		return false;

	return true;
}

const char *
npf_addrgrp_tid2name(uint32_t tid)
{
	struct npf_tbl *table;

	table = rcu_dereference(g_addrgrp_table);
	if (!table)
		return NULL;

	return npf_tbl_id2name(table, tid);
}

/*
 * Name to table ID
 */
int npf_addrgrp_name2tid(const char *name, uint32_t *tid)
{
	struct npf_tbl *table;
	int id;

	table = rcu_dereference(g_addrgrp_table);
	if (!table)
		return -1;

	id = npf_tbl_name2id(table, name);
	if (id < 0)
		return id;

	*tid = (uint32_t)id;
	return 0;
}

/*
 * Get an address-groups table ID
 */
int npf_addrgrp_get_tid(struct npf_addrgrp *ag)
{
	if (ag)
		return ag->ag_tid;
	return -ENOENT;
}

char *npf_addrgrp_handle2name(struct npf_addrgrp *ag)
{
	return ag ? ag->ag_name : NULL;
}

/*
 * Create an address-group, and insert it into address-group tableset
 */
struct npf_addrgrp *npf_addrgrp_create(const char *name)
{
	struct npf_addrgrp *ag;
	int rc;

	/* Create address-group tableset */
	rc = npf_addrgrp_tbl_create();
	if (rc < 0)
		return NULL;

	/* Is name already in address-group tableset? */
	if (npf_tbl_name_lookup(g_addrgrp_table, name) != NULL)
		return NULL;

	/* Create address-group */
	ag = npf_tbl_entry_create(g_addrgrp_table, name);
	if (!ag)
		return NULL;

	/* Initialize address-group data */
	rte_rwlock_init(&ag->ag_lock);

	/* Create mgmgt list */
	ag->ag_list[AG_IPv4] = zlist_new();
	ag->ag_list[AG_IPv6] = zlist_new();

	if (!ag->ag_list[AG_IPv4] || !ag->ag_list[AG_IPv6])
		goto error;

	/* Create address trees */
	ag->ag_tree[AG_IPv4] = ptree_table_create(AG_KLEN_IPv4);
	ag->ag_tree[AG_IPv6] = ptree_table_create(AG_KLEN_IPv6);

	if (!ag->ag_tree[AG_IPv4] || !ag->ag_tree[AG_IPv6])
		goto error;

	ag->ag_name = strdup(name);

	/* Add entry to tableset */
	ag->ag_tid = npf_tbl_entry_insert(g_addrgrp_table, ag);

	if (ag->ag_tid < 0)
		goto error;

	return ag;

error:
	/* free address group lists and trees */
	npf_addrgrp_data_destroy(ag);

	/* free (uninserted) tableset entry */
	npf_tbl_entry_destroy(ag);

	return NULL;
}

/*
 * Destroy the address-group specific data of an address-group
 *
 * zlist_destroy takes care of freeing each list entry through either the
 * callback function, npf_addrgrp_entry_free, or free (in no callback
 * specified).
 */
static void
npf_addrgrp_data_destroy(struct npf_addrgrp *ag)
{
	/*
	 * The zlist free function callbacks will take care of removing
	 * corresponding ptree table entries.
	 */
	if (ag->ag_list[AG_IPv4])
		zlist_destroy(&ag->ag_list[AG_IPv4]);

	assert(ptree_get_table_leaf_count(ag->ag_tree[AG_IPv4]) == 0);

	if (ag->ag_list[AG_IPv6])
		zlist_destroy(&ag->ag_list[AG_IPv6]);

	assert(ptree_get_table_leaf_count(ag->ag_tree[AG_IPv6]) == 0);

	rte_rwlock_write_lock(&ag->ag_lock);

	if (ag->ag_tree[AG_IPv4])
		ptree_table_destroy(ag->ag_tree[AG_IPv4]);

	if (ag->ag_tree[AG_IPv6])
		ptree_table_destroy(ag->ag_tree[AG_IPv6]);

	rte_rwlock_write_unlock(&ag->ag_lock);

	if (ag->ag_name)
		free(ag->ag_name);
}

static int
_npf_addrgrp_destroy(struct npf_addrgrp *ag)
{
	if (!ag)
		return -EINVAL;

	/* free lists and trees */
	npf_addrgrp_data_destroy(ag);

	/* Remove addr table from tableset and destroy it */
	return npf_tbl_entry_remove(g_addrgrp_table, ag);
}

/*
 * Remove an address-group from tableset, and destroy it.
 */
int
npf_addrgrp_destroy(const char *name)
{
	struct npf_addrgrp *ag;

	if (!g_addrgrp_table)
		return -EINVAL;

	/* Is name in addr group tableset? */
	ag = npf_tbl_name_lookup(g_addrgrp_table, name);
	if (!ag)
		return -ENOENT;

	return _npf_addrgrp_destroy(ag);
}

/*
 * Lookup a mask in the list of masks for a prefix entry.  Return index of
 * mask in mask table if found, else < 0 if not found.
 */
static int
npf_addrgrp_prefix_mask_lookup(struct npf_addrgrp_entry *ae, uint8_t mask)
{
	uint i;

	if (ae->ae_type != NPF_ADDRGRP_TYPE_PREFIX)
		return -EINVAL;

	for (i = 0; i < ae->ap_nmasks; i++) {
		if (mask == ae->ap_mask[i])
			return i;
		if (mask > ae->ap_mask[i])
			break;
	}
	return -ENOENT;
}

/*
 * Insert a mask into list of masks for a prefix entry.  Masks are maintained
 * in order of shortest to longest.
 */
static int
npf_addrgrp_prefix_mask_insert(struct npf_addrgrp_entry *ae, uint8_t mask)
{
	struct npf_addrgrp *ag = ae->ae_ag;
	uint i, j;

	if (ae->ae_type != NPF_ADDRGRP_TYPE_PREFIX)
		return -EINVAL;

	if (ae->ap_nmasks == NPF_ADDRGRP_MASKS_MAX)
		return -ENOSPC;

	/* Find insert point */
	for (i = 0; i < ae->ap_nmasks; i++) {
		if (mask == ae->ap_mask[i])
			return -EEXIST;

		if (mask < ae->ap_mask[i])
			break;
	}

	/* The easy case - Insert at end */
	if (i == ae->ap_nmasks) {
		ae->ap_mask[i] = mask;
		ae->ap_nmasks++;
		return 0;
	}

	/*
	 * Insert at start or middle by shuffling all masks above insert point
	 * up one place.
	 */
	for (j = ae->ap_nmasks; j > i; j--)
		ae->ap_mask[j] = ae->ap_mask[j-1];

	ae->ap_mask[i] = mask;
	ae->ap_nmasks++;

	/*
	 * If we inserted at the start, then that means there is a new
	 * shortest mask.
	 */
	if (i == 0 && ae->ap_nmasks > 1) {
		/*
		 * Change tree entry mask.  Cleanest way of doing this is by
		 * first removing current ptree entry, and re-adding it with
		 * the different mask.
		 */
		rte_rwlock_write_lock(&ag->ag_lock);

		ptree_remove(ag->ag_tree[ae->ae_af], ap_prefix(ae),
			     ag_ptree_mask(ae->ae_af, ae->ap_mask[1]));

		ptree_insert(ag->ag_tree[ae->ae_af], ap_prefix(ae),
			     ag_ptree_mask(ae->ae_af, ae->ap_mask[0]));

		rte_rwlock_write_unlock(&ag->ag_lock);
	}
	return 0;
}

/*
 * Remove mask from list of masks for a prefix entry.
 */
static int
npf_addrgrp_prefix_mask_remove(struct npf_addrgrp_entry *ae, uint8_t mask)
{
	struct npf_addrgrp *ag = ae->ae_ag;
	int i, j;

	if (ae->ae_type != NPF_ADDRGRP_TYPE_PREFIX)
		return -EINVAL;

	if (ae->ap_nmasks == 0)
		return -ENOENT;

	/* Find mask */
	for (i = 0; i < ae->ap_nmasks; i++) {
		if (mask == ae->ap_mask[i])
			break;
	}

	if (i == ae->ap_nmasks)
		return -ENOENT;

	/*
	 * If we are removing the first mask, then that means there is a
	 * new shortest mask.
	 */
	if (i == 0 && ae->ap_nmasks > 1) {
		/*
		 * Change tree entry mask.  Cleanest way of doing this is by
		 * first removing current ptree entry, and re-adding it with
		 * the different mask.
		 */
		rte_rwlock_write_lock(&ag->ag_lock);

		ptree_remove(ag->ag_tree[ae->ae_af], ap_prefix(ae),
			     ag_ptree_mask(ae->ae_af, ae->ap_mask[0]));

		ptree_insert(ag->ag_tree[ae->ae_af], ap_prefix(ae),
			     ag_ptree_mask(ae->ae_af, ae->ap_mask[1]));

		rte_rwlock_write_unlock(&ag->ag_lock);
	}

	/*
	 * Remove mask by shuffling all masks above it down one place
	 */
	for (j = i; j < ae->ap_nmasks - 1; j++)
		ae->ap_mask[j] = ae->ap_mask[j+1];

	ae->ap_nmasks--;
	return 0;
}

/*
 * Compare two addresses
 */
static int
npf_addrgrp_addr_cmp(uint8_t *addr1, uint8_t *addr2, uint8_t alen)
{
	int i;

	/*
	 * Addresses are in network byte order, so most-significant byte is in
	 * low memory.
	 */
	for (i = 0; i < alen; i++) {
		if (addr1[i] > addr2[i])
			return 1;
		else if (addr1[i] < addr2[i])
			return -1;
	}
	return 0;
}

/*
 * Compare two address-groups.  Used by zlist_sort.
 */
static int
npf_addrgrp_cmp(void *item1, void *item2)
{
	struct npf_addrgrp_entry *ae1 = item1;
	struct npf_addrgrp_entry *ae2 = item2;
	uint8_t *addr1, *addr2;
	int rc;

	assert(ae1);
	assert(ae2);

	/*
	 * Range and prefix entries cannot overlap, so just compare prefix
	 * address and/or range start address.
	 */
	if (ae1->ae_type == NPF_ADDRGRP_TYPE_PREFIX)
		addr1 = ap_prefix(ae1);
	else
		addr1 = ar_start(ae1);

	if (ae2->ae_type == NPF_ADDRGRP_TYPE_PREFIX)
		addr2 = ap_prefix(ae2);
	else
		addr2 = ar_start(ae2);

	rc = npf_addrgrp_addr_cmp(addr1, addr2,	AG_AF2ALEN(ae1->ae_af));
	if (rc != 0)
		return rc;

	return 0;
}

/*
 * Does address range x1-x2 overlap with address range y1-y2?
 *
 * Easiest way to visualize this is to consider the check for the ranges that
 * do *not* overlap.
 *
 *       dont_overlap = (x2 <  y1 || x1 >  y2)
 * thus:
 *       overlap      = (x2 >= y1 && x1 <= y2)
 */
static bool
npf_addrgrp_range_overlap(uint8_t *x1, uint8_t *x2,
			  uint8_t *y1, uint8_t *y2,
			  uint8_t alen)
{
	int c1, c2;

	c1 = npf_addrgrp_addr_cmp(x2, y1, alen);
	c2 = npf_addrgrp_addr_cmp(x1, y2, alen);

	return c1 >= 0 && c2 <= 0;
}

/*
 * Set host bits.  Address in network byte order.
 */
static void set_host_bits(uint8_t *a, int alen, int mask)
{
	int i, b;

	/* Start at least significant byte */
	for (i = alen - 1, b = alen*8 - mask; i >= 0 && b > 7; i--, b -= 8)
		a[i] = 0xff;

	/* partial byte */
	if (b)
		a[i] = a[i] | ~(0xFF << b);
}

/*
 * Given a prefix and mask, determine the equivalent address range
 */
static void
npf_addrgrp_prefix_to_range(uint8_t *prefix, uint8_t mask, uint8_t alen,
			    uint8_t *start, uint8_t *end)
{
	memcpy(start, prefix, alen);
	memcpy(end, prefix, alen);
	set_host_bits(end, alen, mask);
}

/*
 * Lookup a prefix entry in an address-group list.  Returns first entry (range
 * or prefix) that matches with the given prefix.
 */
static struct npf_addrgrp_entry *
npf_addrgrp_list_prefix_lookup(struct npf_addrgrp *ag, uint8_t *addr,
			       uint8_t mask, uint8_t alen)
{
	zlist_t *list = ag->ag_list[AG_ALEN2AF(alen)];
	struct npf_addrgrp_entry *ae;

	for (ae = zlist_first(list); ae != NULL; ae = zlist_next(list)) {
		if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX) {
			/*
			 * Compare given prefix with entry prefix.
			 */
			if (npf_addrgrp_addr_cmp(ap_prefix(ae),
						 addr, alen) == 0)
				return ae;
		} else {
			/*
			 * Compare given prefix with entry range.  To do this
			 * we convert the prefix and mask to an equivalent
			 * range, then check they don't overlap.
			 */
			uint8_t y1[alen], y2[alen];

			npf_addrgrp_prefix_to_range(addr, mask, alen, y1, y2);

			if (npf_addrgrp_range_overlap(y1, y2, ar_start(ae),
						      ar_end(ae), alen))
				return ae;
		}
	}
	return NULL;
}

/*
 * Lookup an range entry in an address-group list.  Returns first entry (range
 * or prefix) that overlaps with the given range.
 */
static struct npf_addrgrp_entry *
npf_addrgrp_list_range_lookup(struct npf_addrgrp *ag, uint8_t *start,
			      uint8_t *end, uint8_t alen)
{
	zlist_t *list = ag->ag_list[AG_ALEN2AF(alen)];
	struct npf_addrgrp_entry *ae;

	for (ae = zlist_first(list); ae != NULL; ae = zlist_next(list)) {

		if (ae->ae_type == NPF_ADDRGRP_TYPE_RANGE) {
			/*
			 * Does the given prefix/range overlap with this entry
			 * range?
			 */
			if (npf_addrgrp_range_overlap(start, end,
						      ar_start(ae),
						      ar_end(ae), alen))
				return ae;
		} else {
			uint8_t y1[alen], y2[alen];
			int i;

			/*
			 * Prefix entry.  Get the equivalent address range for
			 * each mask off this prefix entry.
			 */
			for (i = 0; i < ae->ap_nmasks; i++) {

				npf_addrgrp_prefix_to_range(ap_prefix(ae),
							    ae->ap_mask[i],
							    alen, y1, y2);

				if (npf_addrgrp_range_overlap(start, end,
							      y1, y2, alen))
					return ae;
			}
		}
	}
	return NULL;
}

/*
 * Lookup an address range entry *exact* match in an address-group list.
 */
static struct npf_addrgrp_entry *
npf_addrgrp_list_range_lookup_exact(struct npf_addrgrp *ag, uint8_t *start,
				    uint8_t *end, uint8_t alen)
{
	zlist_t *list = ag->ag_list[AG_ALEN2AF(alen)];
	struct npf_addrgrp_entry *ae;
	int c1, c2;

	for (ae = zlist_first(list); ae != NULL; ae = zlist_next(list)) {
		if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX) {
			c1 = npf_addrgrp_addr_cmp(ap_prefix(ae), start, alen);
			c2 = npf_addrgrp_addr_cmp(ap_prefix(ae), end, alen);

			/*
			 * If this prefix entry falls within the range, then
			 * no point looking any further for a match since we
			 * know overlapping entries are not allowed.
			 */
			if (c1 >= 0 && c2 <= 0)
				return NULL;
		} else {
			c1 = npf_addrgrp_addr_cmp(start, ar_start(ae), alen);
			if (c1 != 0)
				continue;

			c2 = npf_addrgrp_addr_cmp(end, ar_end(ae), alen);
			if (c2 != 0)
				continue;

			return ae;
		}
	}
	return NULL;
}

/*
 * Callback function for zlist_destroy and zlist_remove.
 *
 * Note, there is some recursion here.  The zlist_destroy for range entries
 * will end up calling back here with the ar_list prefix entries.
 */
static void npf_addrgrp_entry_free(void *item)
{
	int rc;

	if (item == NULL)
		return;

	struct npf_addrgrp_entry *ae = item;
	struct npf_addrgrp *ag = ae->ae_ag;

	if (ae->ae_type == NPF_ADDRGRP_TYPE_RANGE)
		zlist_destroy(&ae->ar_list);

	if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX && ae->ae_ptree) {
		/*
		 * Remove prefix from ptree
		 */
		rte_rwlock_write_lock(&ag->ag_lock);

		rc = ptree_remove(ag->ag_tree[ae->ae_af], ap_prefix(ae),
				  ag_ptree_mask(ae->ae_af, ae->ap_mask[0]));
		if (rc == 0)
			ae->ae_ptree = 0;

		rte_rwlock_write_unlock(&ag->ag_lock);
	}

	free(ae);
}

/*
 * A prefix and mask may be representing either a single host, single prefix,
 * or part of a host range.  For a single host prefix we return 1.  For a
 * prefix we return the number of addresses less the all-ones and all-zeros.
 * If the prefix is representing a host range then we do *not* want to
 * subtract the all ones/zeros addresses.
 */
static uint64_t
npf_addrgrp_useable_addrs(uint8_t masklen, uint8_t alen, bool count_all)
{
	uint8_t max = alen*8;
	uint64_t naddrs;

	if (masklen > max)
		masklen = max;

	naddrs = UINT64_C(1) << (max - masklen);

	/* Conditionally subtract all zeros and all ones addresses */
	if (!count_all && naddrs > 2)
		naddrs -= 2;

	return naddrs;
}

/*
 * Prefix entries can exist in two different lists. Either in the main
 * access-group list, or in a range entries derived prefix list.
 */
static struct npf_addrgrp_entry *
npf_addrgrp_prefix_insert_list(zlist_t *list, zlist_free_fn free_fn,
			       uint8_t *addr, uint8_t alen,
			       uint8_t mask, struct npf_addrgrp *ag)
{
	struct npf_addrgrp_entry *ae;

	/*
	 * We already have 1 word for ae_addrs[] in the struct definition, so
	 * subtract that from the size we allocate.
	 */
	ae = zmalloc_aligned(sizeof(*ae) + alen - sizeof(ae->ae_addrs));
	if (!ae)
		return NULL;

	ae->ae_type = NPF_ADDRGRP_TYPE_PREFIX;
	ae->ae_ag = ag;
	ae->ae_af = AG_ALEN2AF(alen);

	memcpy(ap_prefix(ae), addr, alen);
	ae->ap_nmasks = 1;
	ae->ap_mask[0] = mask;

	if (zlist_append(list, ae) != 0) {
		free(ae);
		return NULL;
	}
	if (free_fn)
		zlist_freefn(list, ae, free_fn, true);

	/* Maintain the list in order */
	zlist_sort(list, npf_addrgrp_cmp);

	return ae;
}

/*
 * Return true if any hosts bits are set
 */
static bool
host_bits_set(uint8_t *addr, uint8_t alen, uint8_t mask)
{
	int i, b;
	uint8_t *a = addr;

	if (mask == alen*8)
		return false;

	/*
	 * Start at least significant byte
	 */
	for (i = alen - 1, b = alen*8 - mask; i >= 0 && b > 7; i--, b -= 8)
		if (a[i] != 0)
			return true;

	/* partial byte */
	if (b && (a[i] & ~(0xFF << b)) != 0)
		return true;

	return false;
}

/*
 * Return true if address is zero
 */
static bool
is_addr_zero(uint8_t *addr, uint8_t alen)
{
	uint i;

	for (i = 0; i < alen; i++)
		if (addr[i] != 0)
			return false;

	return true;
}

/*
 * Insert an address into an address group.  Address should be in network byte
 * order.
 *
 * Some effort is made to prevent duplicate/redundant entries.  Ranges are not
 * allowed to overlap with other ranges.
 *
 * The same prefix with multiple mask lengths is allowed to an extent in order
 * to be backwards compatible.
 *
 * However we do *not* check that every address covered by a prefix/mask is
 * not already covered by an existing entry, for example we allow the following:
 *
 *     1. 10.0.0.2 - 10.0.0.4
 *     2. 10.0.0.8/32
 *     3. 10.0.0.0/16
 *
 * When entry #3 is entered, it would be impractical to check all addresses
 * covered by the /16 mask.
 *
 * mask will be NPF_NO_NETMASK (255) if no mask was specified in the user
 * command.  We store this address and mask as just another in address and
 * mask value.  (The multiple-mask mechanism allows for both 10.0.0.1/32 and
 * 10.0.0.1 to be entered via the cli.)
 */
int npf_addrgrp_prefix_insert(const char *name, npf_addr_t *addr,
			      uint8_t alen, uint8_t mask)
{
	struct npf_addrgrp_entry *ae;
	struct npf_addrgrp *ag;
	enum npf_addrgrp_af af;
	bool new = false;
	int rc;

	if (alen != AG_KLEN_IPv4 && alen != AG_KLEN_IPv6)
		return -EINVAL;

	if (mask == 0) {
		/*
		 * Special case of zero length prefix mask.  if mask is 0 then
		 * addr must also be zero.
		 */
		if (!is_addr_zero(addr->s6_addr, alen))
			return -EINVAL;
	} else {
		/*
		 * If mask is NPF_NO_NETMASK then change to 32 or 128 for host
		 * bits check
		 */
		uint8_t mm = MIN(mask, alen * 8);

		/*
		 * check no host bits are set
		 */
		if (host_bits_set(addr->s6_addr, alen, mm))
			return -EINVAL;
	}

	/* Create an address-group if one doesn't already exist */
	ag = npf_addrgrp_lookup_name(name);
	if (!ag) {
		ag = npf_addrgrp_create(name);
		if (!ag)
			return -EINVAL;
		new = true;
	}
	af = AG_ALEN2AF(alen);

	/* Only one 0.0.0.0/0 (or ::/0) allowed */
	if (mask == 0 && ag->ag_any[af])
		return -EEXIST;

	/*
	 * Does the new prefix match/overlap with an existing prefix list
	 * entry or list range entry?  This examines the address-group *list*.
	 */
	ae = npf_addrgrp_list_prefix_lookup(ag, addr->s6_addr, mask, alen);
	if (ae) {
		assert(!new);

		if (ae->ae_type == NPF_ADDRGRP_TYPE_RANGE)
			return -EEXIST;

		int midx = npf_addrgrp_prefix_mask_lookup(ae, mask);

		if (midx >= 0)
			return -EEXIST;

		/* Add mask to existing entry */
		return npf_addrgrp_prefix_mask_insert(ae, mask);
	}


	zlist_t *list = ag->ag_list[af];

	ae = npf_addrgrp_prefix_insert_list(list, npf_addrgrp_entry_free,
					    addr->s6_addr, alen, mask, ag);
	if (!ae) {
		if (new)
			_npf_addrgrp_destroy(ag);
		return -ENOMEM;
	}

	/*
	 * Special case of 0.0.0.0/0 (or ::/0).  We just set a boolean, and do
	 * not add to the ptree.
	 */
	if (mask == 0) {
		ag->ag_any[af] = true;
		return 0;
	}

	/*
	 * Add prefix to ptree
	 */
	rte_rwlock_write_lock(&ag->ag_lock);

	rc = ptree_insert(ag->ag_tree[af], addr->s6_addr,
			  ag_ptree_mask(af, mask));
	if (rc == 0)
		ae->ae_ptree = 1;

	rte_rwlock_write_unlock(&ag->ag_lock);

	assert(rc == 0);

	if (rc < 0 && new)
		_npf_addrgrp_destroy(ag);

	return rc;
}

/*
 * reverse address.  The CIDR utils use host-byte order, and address-groups
 * use network byte order.
 */
static inline void reverse_addr(uint8_t *dst, uint8_t *src, int len)
{
	int i;

	for (i = 0; i < len; i++)
		dst[i] = src[len - i - 1];
}

/*
 * Callback context for npf_cidr_tree_walk
 */
struct npf_addgrp_cidr_walk_ctx {
	struct npf_addrgrp       *ag;
	zlist_t                  *list;
	zlist_free_fn            *free_fn;
};

/*
 * Callback for npf_cidr_tree_dump.  Used to program the ptree with a set of
 * prefixes derived from an address group range.
 *
 * pfx is in host byte order (so needs reversed).  ctx is parent range entry.
 */
static int
npf_addrgrp_range_pfx_insert(uint8_t *pfx, int alen, int mask, void *data)
{
	struct npf_addgrp_cidr_walk_ctx *ctx = data;
	uint8_t addr[alen];

	/* host order to network order */
	reverse_addr(addr, pfx, alen);

	/* Add a prefix entry to the range entries prefix list */
	struct npf_addrgrp_entry *ap;

	ap = npf_addrgrp_prefix_insert_list(ctx->list, ctx->free_fn,
					    addr, alen, mask, ctx->ag);
	if (!ap)
		return -ENOMEM;

	return 0;
}

/*
 * Add the prefix list of a new address range entry to the ptree
 */
static void
npf_addrgrp_range_pfx_list_ptree_insert(struct npf_addrgrp *ag,
					struct npf_addrgrp_entry *ae)
{
	struct npf_addrgrp_entry *ap;
	struct ptree_table *tree = ag->ag_tree[ae->ae_af];
	int rc;

	rte_rwlock_write_lock(&ag->ag_lock);

	for (ap = zlist_first(ae->ar_list); ap != NULL;
	     ap = zlist_next(ae->ar_list)) {
		rc = ptree_insert(tree, ap_prefix(ap),
				  ag_ptree_mask(ae->ae_af, ap->ap_mask[0]));
		if (rc == 0)
			ap->ae_ptree = 1;
	}

	rte_rwlock_write_unlock(&ag->ag_lock);
}

static struct npf_addrgrp_entry *
npf_addrgrp_range_insert_list(zlist_t *list, uint8_t *start,
			      uint8_t *end, uint8_t alen,
			      struct npf_addrgrp *ag)
{
	struct npf_addrgrp_entry *ae;

	/*
	 * We already have 1 word for ae_addrs[] in the struct definition, so
	 * subtract that from the size we allocate.
	 */
	ae = zmalloc_aligned(sizeof(*ae) + 2*alen - sizeof(ae->ae_addrs));
	if (!ae)
		return NULL;

	ae->ae_type = NPF_ADDRGRP_TYPE_RANGE;
	ae->ae_ag = ag;
	ae->ae_af = AG_ALEN2AF(alen);

	memcpy(ar_start(ae), start, alen);
	memcpy(ar_end(ae), end, alen);

	ae->ar_list = zlist_new();
	if (!ae->ar_list) {
		free(ae);
		return NULL;
	}

	if (zlist_append(list, ae) != 0) {
		zlist_destroy(&ae->ar_list);
		free(ae);
		return NULL;
	}
	zlist_freefn(list, ae, npf_addrgrp_entry_free, true);

	/* Maintain the list in order */
	zlist_sort(list, npf_addrgrp_cmp);

	return ae;
}

/*
 * Does an entry exist in a list?
 *
 * Only used when updating the list of prefixes belonging to an address range
 * entry.  This differs from the requirements for zlist_sort and zlist_remove
 * (which use the zlist compare function) in that we want to check the first
 * mask value.
 *
 * In these cases we want to detect that, for example, 10.0.0.16/32 has
 * changed to 10.0.0.16/29 when comparing two lists for old and new address
 * ranges.
 *
 * That being said, we might as well make this also work for other entries.
 */
static bool
npf_addrgrp_zlist_exists(zlist_t *list, struct npf_addrgrp_entry *ae)
{
	struct npf_addrgrp_entry *itr;
	uint8_t *addr1, *addr2;
	uint8_t alen = AG_AF2ALEN(ae->ae_af);

	if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX)
		addr1 = ap_prefix(ae);
	else
		addr1 = ar_start(ae);

	for (itr = zlist_first(list); itr != NULL; itr = zlist_next(list)) {
		if (ae->ae_type != itr->ae_type)
			continue;

		if (itr->ae_type == NPF_ADDRGRP_TYPE_PREFIX)
			addr2 = ap_prefix(itr);
		else
			addr2 = ar_start(itr);

		if (npf_addrgrp_addr_cmp(addr1, addr2, alen) != 0)
			continue;

		/*
		 * Only return true for prefix entries if address matches
		 * *and* first mask value matches.
		 */
		if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX) {
			if (ae->ap_nmasks > 0 && itr->ap_nmasks > 0 &&
			    ae->ap_mask[0] == itr->ap_mask[0])
				return true;
			return false;
		}

		/*
		 * return true for range entries if start address matches
		 */
		return true;
	}
	return false;
}

/*
 * Update an address range when the end address changes
 *
 * At this point we have two address-range entries in the group list - ae and
 * cur_ae.  However only cur_ae's prefixes exist in the ptree.
 *
 * We want to add/remove from the ptree as little as possible, so we update
 * the cur_ae prefix list and then swap them over.  Note that we must delete
 * entries before we add entries, since there ptree has no mechanism for
 * changing the mask length of an entry.
 */
static void
npf_addrgrp_range_update(struct npf_addrgrp *ag,
			 struct npf_addrgrp_entry *cur_ae,
			 struct npf_addrgrp_entry *ae,
			 uint8_t alen)
{
	struct npf_addrgrp_entry *cur, *new;
	zlist_t *cur_list, *new_list;
	uint8_t af = AG_ALEN2AF(alen);
	int rc;

	cur_list = cur_ae->ar_list;
	new_list = ae->ar_list;

	/* For each prefix in current list ... */
	for (cur = zlist_first(cur_list); cur != NULL;
	     cur = zlist_next(cur_list)) {

		/* .. if not in new list .. */
		if (!npf_addrgrp_zlist_exists(new_list, cur))
			/* ... remove pfx entry from cur list and ptree */
			zlist_remove(cur_list, cur);
	}

	/* For each prefix in new list ... */
	for (new = zlist_first(new_list); new != NULL;
	     new = zlist_next(new_list)) {

		/* .. if not in old list .. */
		if (!npf_addrgrp_zlist_exists(cur_list, new)) {
			struct npf_addrgrp_entry *tmp;

			/* .. create new pfx entry in current list */
			tmp = npf_addrgrp_prefix_insert_list(
				cur_list, npf_addrgrp_entry_free,
				ap_prefix(new), alen, new->ap_mask[0], ag);

			/* .. add to ptree */
			rc = ptree_insert(ag->ag_tree[af], ap_prefix(tmp),
					  ag_ptree_mask(af, tmp->ap_mask[0]));
			if (rc == 0)
				tmp->ae_ptree = 1;
		}
	}

	/* Swap lists */
	ae->ar_list = cur_list;
	cur_ae->ar_list = new_list;

	/* The new range entry is no longer required */
	zlist_remove(ag->ag_list[af], cur_ae);
}

/*
 * Insert an address range into an address group.  Addresses should be in
 * network byte order.
 */
int npf_addrgrp_range_insert(const char *name, npf_addr_t *start,
			     npf_addr_t *end, uint8_t alen)
{
	struct npf_addrgrp_entry *ae, *cur_ae = NULL;
	struct npf_addrgrp *ag;
	bool new = false;

	if (alen != AG_KLEN_IPv4 && alen != AG_KLEN_IPv6)
		return -EINVAL;

	/* end address must be greater than start address */
	if (npf_addrgrp_addr_cmp(start->s6_addr, end->s6_addr, alen) >= 0)
		return -EINVAL;

	/* Create an address-group if one doesn't already exist */
	ag = npf_addrgrp_lookup_name(name);
	if (!ag) {
		ag = npf_addrgrp_create(name);
		if (!ag)
			return -EINVAL;
		new = true;
	}

	/*
	 * Does the new range overlap with an existing prefix entry or range
	 * entry?
	 *
	 * Address ranges are identified in the config by their start address,
	 * so if the start address is the same but the end address is
	 * different then this is a special case that we must treat
	 * differently such that we update the existing entry.
	 */
	ae = npf_addrgrp_list_range_lookup(ag, start->s6_addr, end->s6_addr,
					   alen);
	if (ae) {
		/*
		 * If the address we hace found is a prefix entry, or is a
		 * range entry with a different start address, then we have an
		 * overlapping entry.
		 */
		if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX ||
		    npf_addrgrp_addr_cmp(start->s6_addr, ar_start(ae),
					 alen) != 0)
			return -EEXIST;

		/*
		 * An address range end address has changed.  We resolve this
		 * in a somewhat roundabout fashion.  First we create a new
		 * range entry, along with a list of derived prefixes.  We
		 * then compare the prefix lists of the current abd new range
		 * entries to determine which prefixes to add or delete from
		 * the ptree.
		 */
		cur_ae = ae;
	}

	zlist_t *list = ag->ag_list[AG_ALEN2AF(alen)];

	ae = npf_addrgrp_range_insert_list(list, start->s6_addr, end->s6_addr,
					   alen, ag);
	if (!ae) {
		if (new)
			_npf_addrgrp_destroy(ag);
		return -ENOMEM;
	}

	/*
	 * Convert range to minimal set of CIDR notation blocks, and add to
	 * ptree
	 */
	struct cidr_tree cidr;
	uint8_t a1[alen], a2[alen];

	npf_cidr_tree_init(&cidr, alen);

	reverse_addr(a1, ar_start(ae), alen);
	reverse_addr(a2, ar_end(ae), alen);
	npf_cidr_save_range(&cidr, a1, a2);

	struct npf_addgrp_cidr_walk_ctx ctx = {
		.ag      = ag,
		.list    = ae->ar_list,
		.free_fn = npf_addrgrp_entry_free,
	};

	/* Derive prefix list from address range */
	npf_cidr_tree_walk(&cidr, alen, npf_addrgrp_range_pfx_insert, &ctx);
	npf_cidr_tree_free(&cidr);

	if (!cur_ae)
		/*
		 * New range entry.  Add address range prefix list to ptree
		 */
		npf_addrgrp_range_pfx_list_ptree_insert(ag, ae);
	else
		npf_addrgrp_range_update(ag, cur_ae, ae, alen);

	return 0;
}

/*
 * Remove a prefix from an address group.  Address should be in network byte
 * order.  mask will be NPF_NO_NETMASK if no mask was specified in the
 * command.
 */
int npf_addrgrp_prefix_remove(const char *name, npf_addr_t *addr,
			      uint8_t alen, uint8_t mask)
{
	struct npf_addrgrp *ag;
	struct npf_addrgrp_entry *ae;
	int rc;

	if (alen != AG_KLEN_IPv4 && alen != AG_KLEN_IPv6)
		return -EINVAL;

	if (mask == 0) {
		/*
		 * Special case of zero length prefix mask.  if mask is 0 then
		 * addr must also be zero.
		 */
		if (!is_addr_zero(addr->s6_addr, alen))
			return -EINVAL;
	} else {
		/*
		 * If mask is NPF_NO_NETMASK then change to 32 or 128 for host
		 * bits check
		 */
		uint8_t tmp = MIN(mask, alen * 8);

		/*
		 * check no host bits are set
		 */
		if (host_bits_set(addr->s6_addr, alen, tmp))
			return -EINVAL;
	}

	/* Lookup address-group */
	ag = npf_addrgrp_lookup_name(name);
	if (!ag)
		return -EINVAL;

	/* Does the prefix already exist? */
	ae = npf_addrgrp_list_prefix_lookup(ag, addr->s6_addr, mask, alen);
	if (!ae)
		return -ENOENT;

	/*
	 * Check if exact match.  If ae is a prefix this it must be an
	 * exact match for the prefix, but not necessarily the mask.
	 */
	if (ae->ae_type != NPF_ADDRGRP_TYPE_PREFIX)
		return -EINVAL;

	rc = npf_addrgrp_prefix_mask_remove(ae, mask);
	if (rc < 0)
		return rc;

	if (ae->ap_nmasks > 0)
		return 0;

	if (mask == 0)
		ag->ag_any[AG_ALEN2AF(alen)] = false;

	/*
	 * zlist_remove calls npf_addrgrp_entry_free to free the entry,
	 * which will remove the prefix from the ptree
	 */
	zlist_remove(ag->ag_list[AG_ALEN2AF(alen)], ae);

	return 0;
}

/*
 * Remove an address range from an address group.  Addresses should be in
 * network byte order.
 */
int npf_addrgrp_range_remove(const char *name, npf_addr_t *start,
			     npf_addr_t *end, uint8_t alen)
{
	struct npf_addrgrp *ag;
	struct npf_addrgrp_entry *ae;

	if (alen != AG_KLEN_IPv4 && alen != AG_KLEN_IPv6)
		return -EINVAL;

	/* Lookup address-group */
	ag = npf_addrgrp_lookup_name(name);
	if (!ag)
		return -EINVAL;

	/* Does the address range already exist? */
	ae = npf_addrgrp_list_range_lookup_exact(ag, start->s6_addr,
						 end->s6_addr, alen);
	if (!ae)
		return -ENOENT;

	/*
	 * zlist_remove calls npf_addrgrp_entry_free to free the entry,
	 * which will remove the range prefixes from the ptree
	 */
	zlist_remove(ag->ag_list[AG_ALEN2AF(alen)], ae);

	return 0;
}

/********************************************************************
 * Address group list walk
 *******************************************************************/

/*
 * Walk address-group tree
 */
int
npf_addrgrp_tree_walk(enum npf_addrgrp_af af, int tid,
		      pt_walk_cb *cb, void *ctx)
{
	struct npf_addrgrp *ag;

	ag = npf_addrgrp_tid_lookup(tid);
	if (!ag)
		return -EINVAL;

	if (af != AG_IPv4 && af != AG_IPv6)
		return -EINVAL;

	if (ptree_get_table_leaf_count(ag->ag_tree[af]) == 0)
		return 0;

	return ptree_walk(ag->ag_tree[af], PT_UP, cb, ctx);
}

/*
 * Walk IPv4 address group list, and callback for each list entry providing:
 * start address, end address and number of useable addresses (range).
 *
 * Start and end address are returned in host byte order.
 */
int
npf_addrgrp_ipv4_range_walk(int tid, ag_ipv4_range_cb *cb, void *ctx)
{
	struct npf_addrgrp_entry *ae;
	struct npf_addrgrp *ag;
	zlist_t *list;
	uint8_t alen = AG_AF2ALEN(AG_IPv4);

	ag = npf_addrgrp_tid_lookup(tid);
	if (!ag)
		return -EINVAL;

	list = ag->ag_list[AG_IPv4];

	/* For each entry in address-group list */
	for (ae = zlist_first(list); ae != NULL; ae = zlist_next(list)) {
		uint32_t mask, start = 0, stop = 0;
		uint64_t range = UINT64_C(0);
		uint32_t *tmp;
		int rc;

		if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX) {
			/*
			 * Prefix entry. Note it does not count all-zeros
			 * or all-ones addresses if mask is neither 31 nor 32.
			 */
			tmp = (uint32_t *)ap_prefix(ae);
			start = ntohl(*tmp);

			range = npf_addrgrp_useable_addrs(ae->ap_mask[0], alen,
							  false);
			mask = npf_prefix_to_net_mask4(ae->ap_mask[0]);
			start &= mask;
			if (ae->ap_mask[0] < 31)
				start++; /* skip host-zeros */
			stop = start + range - 1;
		} else if (ae->ae_type == NPF_ADDRGRP_TYPE_RANGE) {
			/*
			 * Range entry.  Start and end addresses are simple
			 * gotten from the range entry itself.  Number of
			 * useable addresses is determined from the set of
			 * prefixes we are using to represent this range, but
			 * this time we *do* count the all-ones and all-zeros
			 * addresses.
			 */
			struct npf_addrgrp_entry *ap;

			for (ap = zlist_first(ae->ar_list); ap != NULL;
			     ap = zlist_next(ae->ar_list))
				range += npf_addrgrp_useable_addrs(
					ap->ap_mask[0], alen, true);

			tmp = (uint32_t *)ar_start(ae);
			start = ntohl(*tmp);

			tmp = (uint32_t *)ar_end(ae);
			stop = ntohl(*tmp);
		}

		rc = (*cb)(start, stop, (uint32_t)range, ctx);
		if (rc)
			return rc;
	}
	return 0;
}

/*
 * Determine how many addresses are included in a table
 */
uint64_t
npf_addrgrp_naddrs(enum npf_addrgrp_af af, int tid)
{
	struct npf_addrgrp_entry *ae;
	struct npf_addrgrp_entry *ap;
	struct npf_addrgrp *ag;
	zlist_t *list;
	uint64_t naddrs = 0;
	uint8_t alen = AG_AF2ALEN(af);

	ag = npf_addrgrp_tid_lookup(tid);
	assert(ag != NULL);
	if (!ag)
		return 0;

	if (af != AG_IPv4 && af != AG_IPv6)
		return 0;

	list = ag->ag_list[af];

	for (ae = zlist_first(list); ae != NULL; ae = zlist_next(list)) {
		if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX)
			naddrs += npf_addrgrp_useable_addrs(ae->ap_mask[0],
							    alen, false);
		else {
			for (ap = zlist_first(ae->ar_list); ap != NULL;
			     ap = zlist_next(ae->ar_list)) {
				naddrs += npf_addrgrp_useable_addrs(
					ap->ap_mask[0], alen, true);
			}
		}
	}

	return naddrs;
}


/********************************************************************
 * Address group show
 *******************************************************************/

static void npf_addrgrp_jsonw_list(json_writer_t *json, zlist_t *list,
				   const char *name,
				   struct npf_show_ag_ctl *ctl);

/*
 * Write json for an address-group prefix object.  This same object is used in
 * three places: list entries, range prefixes, and tree entries.
 */
static void
npf_addrgrp_jsonw_prefix(json_writer_t *json, enum npf_addrgrp_af af,
			 uint8_t *prefix, uint8_t mask)
{
	char str[INET6_ADDRSTRLEN];

	inet_ntop(AG_AF2INET(af), prefix, str, sizeof(str));

	jsonw_start_object(json);

	jsonw_uint_field(json,   "type", NPF_ADDRGRP_TYPE_PREFIX);
	jsonw_string_field(json, "prefix", str);

	/*
	 * NPF_NO_NETMASK indicates that the user entered a host address
	 * rather than a prefix and mask.
	 */
	if (mask != NPF_NO_NETMASK)
		jsonw_uint_field(json, "mask", mask);

	jsonw_end_object(json);
}

/*
 * Write json for an address-group list entry.  Mutually recursive with
 * npf_addrgrp_jsonw_list().
 */
static void
npf_addrgrp_jsonw_list_entry(json_writer_t *json, struct npf_addrgrp_entry *ae,
			     struct npf_show_ag_ctl *ctl)
{
	char str1[INET6_ADDRSTRLEN];
	char str2[INET6_ADDRSTRLEN];
	int i;

	if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX) {
		for (i = 0; i < ae->ap_nmasks; i++)
			npf_addrgrp_jsonw_prefix(json, ae->ae_af,
						 ap_prefix(ae),
						 ae->ap_mask[i]);
	} else if (ae->ae_type == NPF_ADDRGRP_TYPE_RANGE) {
		inet_ntop(AG_AF2INET(ae->ae_af), ar_start(ae),
			  str1, sizeof(str1));
		inet_ntop(AG_AF2INET(ae->ae_af), ar_end(ae),
			  str2, sizeof(str2));

		jsonw_start_object(json);
		jsonw_uint_field(json, "type", NPF_ADDRGRP_TYPE_RANGE);

		jsonw_string_field(json, "start", str1);
		jsonw_string_field(json, "end", str2);

		if (ctl->range_pfxs)
			npf_addrgrp_jsonw_list(json, ae->ar_list,
					       "range-prefixes", ctl);

		jsonw_end_object(json);
	}
}

/*
 * Write json array for an address-group list.
 */
static void
npf_addrgrp_jsonw_list(json_writer_t *json, zlist_t *list, const char *name,
		       struct npf_show_ag_ctl *ctl)
{
	struct npf_addrgrp_entry *ae;

	jsonw_name(json, name);
	jsonw_start_array(json);

	for (ae = zlist_first(list); ae != NULL;
	     ae = zlist_next(list))
		npf_addrgrp_jsonw_list_entry(json, ae, ctl);

	jsonw_end_array(json);
}

/*
 * ptree walk callback function
 */
static int
npf_addrgrp_jsonw_tree_cb(struct ptree_node *n, void *data)
{
	json_writer_t *json = data;

	npf_addrgrp_jsonw_prefix(json, AG_ALEN2AF(ptree_get_keylen(n)),
				 ptree_get_key(n),
				 ptree_get_mask(n));

	return 0;
}

/*
 * Write json array for and address-group tree
 */
static void
npf_addrgrp_jsonw_tree(json_writer_t *json, struct npf_addrgrp *ag,
		       enum npf_addrgrp_af af)
{
	jsonw_name(json, "tree");
	jsonw_start_array(json);

	/*
	 * Address group entry 0.0.0.0/0 is a special case that is not
	 * actually entered into the tree, so we emulate a suitable entry
	 * for the show command.
	 */
	if (ag->ag_any[af]) {
		uint32_t addr[4] = {0, 0, 0, 0};
		npf_addrgrp_jsonw_prefix(json, af, (uint8_t *)addr, 0);
	}

	npf_addrgrp_tree_walk(af, ag->ag_tid,
			      npf_addrgrp_jsonw_tree_cb, json);

	jsonw_end_array(json);
}

/*
 * Write json for an address-group
 */
static void
npf_addrgrp_jsonw(json_writer_t *json, struct npf_addrgrp *ag,
		  struct npf_show_ag_ctl *ctl)
{
	assert(AG_IPv6 > AG_IPv4);

	int af;

	jsonw_name(json, "address-group");
	jsonw_start_object(json);

	jsonw_string_field(json, "name", ag->ag_name);
	jsonw_uint_field(json, "id", ag->ag_tid);

	for (af = AG_IPv4; af <= AG_IPv6; af++) {
		if (!ctl->af[af])
			continue;

		jsonw_name(json, af == AG_IPv4 ? "ipv4" : "ipv6");
		jsonw_start_object(json);

		if (ctl->list)
			npf_addrgrp_jsonw_list(json, ag->ag_list[af],
					       "list-entries", ctl);

		if (ctl->tree)
			npf_addrgrp_jsonw_tree(json, ag, af);

		jsonw_end_object(json);
	}
	jsonw_end_object(json);
}

/*
 * Callback for each address-group in the global table.
 */
static int
npf_addrgrp_show_json_cb(const char *name __unused, uint id __unused,
				void *data, void *ctx)
{
	struct npf_addrgrp *ag = data;
	struct npf_show_ag_ctl *ctl = ctx;

	/*
	 * Table walk is either looking for the first address-group
	 * (ctl->tid == 0), or the next address-group equal to or greater
	 * than ctl->tid.
	 */
	if (ctl->tid > 0 && ag->ag_tid < ctl->tid)
		return 0;

	rte_rwlock_read_lock(&ag->ag_lock);

	npf_addrgrp_jsonw(ctl->json, ag, ctl);

	rte_rwlock_read_unlock(&ag->ag_lock);

	/* stop the walk when we find a suitable address-group */
	return 1;
}

/*
 * Fetch the json representation of an address-group
 *
 * Return an empty address-group object if address-group is not found
 */
void
npf_addrgrp_show_json(FILE *fp, struct npf_show_ag_ctl *ctl)
{
	struct npf_addrgrp *ag = NULL;
	json_writer_t *json;

	if (!g_addrgrp_table || npf_tbl_size(g_addrgrp_table) == 0)
		return;

	ctl->json = json = jsonw_new(fp);
	if (!json)
		return;

	if (ctl->name) {
		ag = npf_addrgrp_lookup_name(ctl->name);
		if (!ag)
			goto end_ag;
	}

	if (ag) {
		rte_rwlock_read_lock(&ag->ag_lock);

		/* Show one address-group */
		npf_addrgrp_jsonw(json, ag, ctl);

		rte_rwlock_read_unlock(&ag->ag_lock);
	} else
		/* Show address-group with ID equal or greater than ctl->tid */
		npf_tbl_walk(g_addrgrp_table, npf_addrgrp_show_json_cb, ctl);

end_ag:
	jsonw_destroy(&json);
}


/*
 * Populate the optimal CIDR subblock tree
 */
static void
npf_addrgrp_get_optimal(zlist_t *list, struct cidr_tree *cidr, int alen)
{
	struct npf_addrgrp_entry *ae;
	uint8_t a1[alen];

	for (ae = zlist_first(list); ae != NULL; ae = zlist_next(list)) {

		if (ae->ae_type == NPF_ADDRGRP_TYPE_PREFIX) {
			reverse_addr(a1, ap_prefix(ae), alen);
			npf_cidr_save_prefix(cidr, a1, ae->ap_mask[0]);
		} else {
			if (zlist_size(ae->ar_list) > 0)
				npf_addrgrp_get_optimal(ae->ar_list, cidr,
							alen);
		}
	}
}

static int
npf_addrgrp_show_json_opt_cb(uint8_t *pfx, int alen, int mask, void *ctx)
{
	json_writer_t *json = ctx;
	uint8_t addr[alen];

	/*
	 * Addresses returned in the CIDR walk are in host-byte order, and the
	 * address group addresses are stored in network-byte order
	 */
	reverse_addr(addr, pfx, alen);

	npf_addrgrp_jsonw_prefix(json, AG_ALEN2AF(alen), addr, mask);

	return 0;
}

static int
_npf_addrgrp_show_json_opt(int id, void *data, void *ctx)
{
	struct npf_addrgrp *ag = data;
	struct npf_show_ag_ctl *ctl = ctx;
	json_writer_t *json = ctl->json;

	jsonw_name(json, "address-group");
	jsonw_start_object(json);

	jsonw_string_field(json, "name", ag->ag_name);
	jsonw_uint_field(json, "id", id);

	/* Can only be IPv4 *or* IPv6 */
	jsonw_name(json, ctl->af[AG_IPv4] ? "ipv4" : "ipv6");
	jsonw_start_object(json);

	jsonw_name(json, "tree");
	jsonw_start_array(json);

	struct cidr_tree cidr;
	int alen = ctl->af[AG_IPv4] ? 4 : 16;
	zlist_t *list = ag->ag_list[ctl->af[AG_IPv4] ? AG_IPv4 : AG_IPv6];

	npf_cidr_tree_init(&cidr, alen);

	if (zlist_size(list) > 0)
		npf_addrgrp_get_optimal(list, &cidr, alen);

	npf_cidr_tree_walk(&cidr, alen, npf_addrgrp_show_json_opt_cb, json);

	npf_cidr_tree_free(&cidr);

	jsonw_end_array(json);
	jsonw_end_object(json);
	jsonw_end_object(json);

	return 0;
}

/*
 * Show list of optimal address-group tree entries, i.e. the minimal set of
 * prefixes and masks to provide same coverage as the user has configured.
 */
void
npf_addrgrp_show_json_opt(FILE *fp, struct npf_show_ag_ctl *ctl)
{
	struct npf_addrgrp *ag = NULL;
	json_writer_t *json;

	if (!g_addrgrp_table || npf_tbl_size(g_addrgrp_table) == 0)
		return;

	ctl->json = json = jsonw_new(fp);
	if (!json)
		return;

	if (ctl->name)
		ag = npf_addrgrp_lookup_name(ctl->name);
	if (!ag)
		goto end_ag;

	rte_rwlock_read_lock(&ag->ag_lock);

	/* Show one address-group */
	_npf_addrgrp_show_json_opt(ag->ag_tid, ag, ctl);

	rte_rwlock_read_unlock(&ag->ag_lock);

end_ag:
	jsonw_destroy(&json);
}
