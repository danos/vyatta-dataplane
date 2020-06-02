/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file nat_pool.c - nat public address pool
 *
 * Address pools are stored in a hash table for lookup by configuration.
 */

#include <errno.h>
#include <malloc.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <dpdk/rte_jhash.h>

#include "compiler.h"
#include "if_var.h"
#include "urcu.h"
#include "util.h"

#include "npf/npf_addr.h"
#include "npf/npf_addrgrp.h"

#include "npf/nat/nat_cmd_cfg.h"
#include "npf/nat/nat_pool_event.h"
#include "npf/nat/nat_pool.h"
#include "npf/cgnat/cgn_log.h"

/*
 * NAT pool.  Each pool contains:
 *
 *   1. one or more address ranges and/or prefixes (host order),
 *   2. a port range
 *   3. method for allocating address and ports
 *   4. state required to manage the allocation
 *
 * nat_pool.c handles:
 *
 *   1. nat pool configuration
 *   2. nat pool table management (name based lookup; master thread only)
 *
 * nat pool entries are stored in a hash table for lookup during
 * config.
 *
 * nat pool entries are referenced by zero or more nat policies.
 */

/*
 * NAT pool hash table.  Pool name is used for the hash.  Used for
 * configuration only.
 */
#define NP_HT_INIT		2
#define NP_HT_MIN		4
#define NP_HT_MAX		32

static struct cds_lfht *nat_pool_ht;

#define NP_PORT_AUTO_START	1024
#define NP_PORT_AUTO_STOP	65535

/* Ports per block */
#define NP_DEF_PORT_BLOCK_SZ	512
#define NP_MIN_PORT_BLOCK_SZ	64
#define NP_MAX_PORT_BLOCK_SZ	4096

/* Max blocks per user */
#define NP_DEF_MBPU		8
#define NP_MIN_MBPU		1
#define NP_MAX_MBPU		32


/*
 * NAT pool configuration
 */
struct nat_pool_cfg {
	char			np_name[NAT_POOL_NAME_MAX];
	enum nat_pool_type	np_type;

	/* Config for address allocation */
	enum nat_addr_pooling	np_ap;
	enum nat_addr_allcn	np_aa;

	/* Config for port blocks */
	uint16_t		np_block_sz; /* Port block size */
	uint16_t		np_mbpu;     /* max blocks per user */

	/* Config for port allocation */
	uint16_t		np_port_start;
	uint16_t		np_port_end;
	enum nat_port_allcn	np_pa;

	/* Logging control */
	bool			np_log_pba;  /* Log port-block alloc/release */

	uint8_t			np_nranges;	/* number of addr ranges */
	struct nat_pool_range	np_range[NAT_POOL_MAX_RANGES];

	/* Address group name */
	const char		*np_blacklist_name;
};

struct match {
	const char *name;
};

/* NAT pool threshold, time, and timer */
static int32_t np_threshold_cfg;  /* configured percent */
static uint32_t np_threshold_time;

/* Forward references */
static void np_threshold_timer_expiry(
		struct rte_timer *timer __unused,
		void *arg);
static void nat_pool_client_counts(struct nat_pool *np, uint32_t *nusers,
				   uint64_t *naddrs);
static void nat_pool_destroy(struct nat_pool *np, bool rcu_free);

/* Get pool name */
char *nat_pool_name(struct nat_pool *np)
{
	if (np)
		return np->np_name;
	return NULL;
}

bool nat_pool_type_is_cgnat(struct nat_pool *np)
{
	return np && np->np_type == NPT_CGNAT;
}

/* Log port-block alloc and release? */
bool nat_pool_log_pba(struct nat_pool *np)
{
	return !np || np->np_log_pba;
}

/* Is this a blacklisted address? */
bool
nat_pool_is_blacklist_addr(struct nat_pool *np, uint32_t addr)
{
	return np->np_blacklist &&
		npf_addrgrp_lookup_v4_by_handle(np->np_blacklist, addr) == 0;
}

/*
 * Check if an address in in a NAT pool.  'addr' is in network-byte order.
 */
bool nat_pool_is_pool_addr(const struct nat_pool *np, uint32_t addr)
{
	if (!np || !np->np_ranges || !np->np_ranges->nr_ag)
		return false;

	/* Is addr in one of this pools address ranges? */
	if (npf_addrgrp_lookup_v4_by_handle(np->np_ranges->nr_ag, addr) == 0)
		return true;

	return false;
}

/* Is NAT pool active? */
bool nat_pool_is_active(struct nat_pool *np)
{
	return np && !!(np->np_flags & NP_ACTIVE);
}

/*
 * Mark a pool as active.
 */
void nat_pool_set_active(struct nat_pool *np)
{
	uint16_t exp = np->np_flags & ~NP_ACTIVE;

	/* Must ensure this happens only once */
	if (rte_atomic16_cmpset((uint16_t *) &np->np_flags, exp,
				(exp | NP_ACTIVE))) {
		/* Notify event */
		nat_pool_event(NP_EVT_ACTIVE, np);
	}
}

/*
 * Mark a pool as inactive.
 */
void nat_pool_clear_active(struct nat_pool *np)
{
	uint16_t exp = np->np_flags | NP_ACTIVE;

	/* Must ensure this happens only once */
	if (rte_atomic16_cmpset((uint16_t *) &np->np_flags, exp,
				(exp & ~NP_ACTIVE))) {
		/* Notify event */
		nat_pool_event(NP_EVT_INACTIVE, np);
	}
}

/*
 * rte_jhash reads from memory in 4-byte chunks.  If the length of 'name' is
 * not a multiple of 4 bytes then it may try and read memory that is not
 * mapped.  Issue was detected by valgrind.
 */
static ulong nat_pool_hash(const char *name)
{
	int len = strlen(name);
	char __name[RTE_ALIGN(len, 4)] __rte_aligned(sizeof(uint32_t));

	memcpy(__name, name, len);
	return rte_jhash(__name, len, 0);
}

/*
 * nat pool hash table match function
 */
static int nat_pool_match(struct cds_lfht_node *node, const void *key)
{
	struct nat_pool *np = caa_container_of(node, struct nat_pool, np_node);
	const struct match *m = key;

	if ((np->np_flags & NP_ACTIVE) == 0)
		return 0; /* no match */

	if (strcmp(np->np_name, m->name) != 0)
		return 0; /* no match */

	return 1; /* match */
}

/*
 * nat pool hash table lookup
 */
struct nat_pool *nat_pool_lookup(const char *name)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct match m = { .name = name };
	ulong hash;

	if (!nat_pool_ht)
		return NULL;

	hash = nat_pool_hash(name);
	cds_lfht_lookup(nat_pool_ht, hash, nat_pool_match, &m, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct nat_pool, np_node);

	return NULL;
}

/* Clear address hints */
void nat_pool_clear_addr_hints(struct nat_pool *np)
{
	struct nat_pool_ranges *nr = np->np_ranges;
	uint i;

	if (!nr)
		return;

	for (i = NAT_PROTO_FIRST; i <= NAT_PROTO_LAST; i++)
		rte_atomic32_set(&nr->nr_addr_hint[i], 0);
}

/*
 * Create an address-group from a NAT pool range set.
 */
static struct npf_addrgrp *
nat_pool_ranges_to_addrgrp(struct nat_pool_ranges *nr, const char *np_name)
{
	char ag_name[NAT_POOL_NAME_MAX + 5];
	struct npf_addrgrp *ag;
	uint32_t addr1, addr2;
	uint i;
	int rc;

	/*
	 * The data model prevents address-group names from starting with an
	 * underscore, so we are guaranteed that the name used for the
	 * address-group is unique.
	 */
	snprintf(ag_name, sizeof(ag_name), "_%s_AG", np_name);

	/* Create address group and add to table set */
	ag = npf_addrgrp_cfg_add(ag_name);
	if (!ag)
		return NULL;

	for (i = 0; i < nr->nr_nranges; i++) {
		struct nat_pool_range *pr = &nr->nr_range[i];

		/* Pool addresses are in host order */
		addr1 = htonl(pr->pr_addr_start);
		addr2 = htonl(pr->pr_addr_stop);

		if (addr1 == addr2)
			rc = npf_addrgrp_prefix_insert(ag_name,
						      (npf_addr_t *)&addr1,
						       4, 32);
		else
			rc = npf_addrgrp_range_insert(ag_name,
						      (npf_addr_t *)&addr1,
						      (npf_addr_t *)&addr2,
						      4);

		if (rc < 0) {
			npf_addrgrp_cfg_delete(ag_name);
			return NULL;
		}
	}

	/*
	 * Take a reference on the address-group and then remove the addr-grp
	 * from the table set.
	 *
	 * After this the address-group is hidden in that it cannot be found
	 * in the table set.  The only thing keeping it in existence is the
	 * reference held by the NAT pool ranges structure.
	 */
	npf_addrgrp_get(ag);
	npf_addrgrp_cfg_delete(ag_name);

	return ag;
}

/*
 * Convert prefix or subnet to address range .  Given a NAT pool address range
 * in prefix format, determine the first and last addresses in the range.
 *
 * Users will typically use a prefix address range to assign a small number of
 * addresses out of a larger /24 subnet.  Several CGNAT policies may be
 * configured, each with adjoining address prefixes.  In these cases we do
 * *not* want to lose the first and last address in the prefix range.
 * Exceptions are when the first address is .0 or the last address is .255.
 *
 * If the user has specified a subnet address range then we do not use the
 * first and last addresses.
 */
static void
nat_pool_prefix_setup_addr_start_stop(struct nat_pool_range *pr)
{
	if (pr->pr_mask == 32) {
		pr->pr_addr_start = pr->pr_prefix;
		pr->pr_addr_stop = pr->pr_prefix;
		return;
	}

	uint32_t first, last, mask;

	first = pr->pr_prefix;
	mask = 0xFFFFFFFFUL << (32 - pr->pr_mask);
	last = (first | ~mask);
	first = (first & mask);

	if (pr->pr_mask < 31) {
		/*
		 * Only use the first or last address if configured to do so,
		 * and they do not result in the last byte being 0 or 255.
		 */
		if (pr->pr_type == NPA_SUBNET || (first & 0xFF) == 0)
			first += 1;

		if (pr->pr_type == NPA_SUBNET || (last & 0xFF) == 255)
			last -= 1;
	}

	pr->pr_addr_start = first;
	pr->pr_addr_stop = last;
}

/*
 * Create a NAT address pool range structure from configuration
 */
static struct nat_pool_ranges *
nat_pool_create_ranges(struct nat_pool_cfg *cfg, int *error)
{
	struct nat_pool_ranges *nr;
	uint i;

	/* Must contain at least one prefix or address range */
	if (cfg->np_nranges == 0) {
		*error = -EINVAL;
		return NULL;
	}

	nr = zmalloc_aligned(sizeof(*nr));
	if (!nr) {
		*error = -ENOMEM;
		return NULL;
	}

	nr->nr_nranges = cfg->np_nranges;

	/* Copy address ranges */
	for (i = 0; i < cfg->np_nranges; i++) {
		struct nat_pool_range *pr = &nr->nr_range[i];

		memcpy(pr, &cfg->np_range[i], sizeof(*pr));

		/* Convert prefix or subnet to address range */
		if (pr->pr_type == NPA_PREFIX || pr->pr_type == NPA_SUBNET)
			nat_pool_prefix_setup_addr_start_stop(pr);

		pr->pr_naddrs = pr->pr_addr_stop - pr->pr_addr_start + 1;
		nr->nr_naddrs += pr->pr_naddrs;
		pr->pr_range = i;
		pr->pr_shared = cfg->np_range[i].pr_shared;

		/* Copy range name */
		strcpy(pr->pr_name, cfg->np_range[i].pr_name);
	}

	for (i = NAT_PROTO_FIRST; i <= NAT_PROTO_LAST; i++)
		rte_atomic32_set(&nr->nr_addr_hint[i], 0);

	/*
	 * Create a 'hidden' address-group from the set of address ranges.
	 * This is used to quickly test if an address in in a NAT pool, for
	 * example when ICMP Echo Requests are received on the outside
	 * interface.
	 */
	nr->nr_ag = nat_pool_ranges_to_addrgrp(nr, cfg->np_name);
	assert(nr->nr_ag);

	return nr;
}

static void nat_pool_rcu_free_ranges(struct rcu_head *head)
{
	struct nat_pool_ranges *nr;

	nr = caa_container_of(head, struct nat_pool_ranges, nr_rcu_head);
	free(nr);
}

/*
 * If the parent pool structure is being freed then this function will be
 * called from an rcu_callback, in which case we free 'nr' immediately.
 *
 * If the ranges of an existing pool are just being re-configured, then we
 * want to rcu-free 'nr'.  (This will occur after we rcu_xchg_pointer the
 * np_ranges pointer in the NAT pool.)
 */
static void nat_pool_free_ranges(struct nat_pool_ranges *nr, bool rcu_free)
{
	struct npf_addrgrp *ag;

	if (!nr)
		return;

	/* Release reference on ranges address-group */
	ag = rcu_xchg_pointer(&nr->nr_ag, NULL);
	if (ag)
		npf_addrgrp_put(ag);

	if (rcu_free)
		call_rcu(&nr->nr_rcu_head, nat_pool_rcu_free_ranges);
	else
		free(nr);
}

/*
 * Update the address ranges of an existing nat pool.  Currently we just allow
 * ranges to be added.
 *
 * If this is successful, it frees the old ranges structure.  If unsuccessful,
 * then the caller should free the new ranges structure.
 */
static int
nat_pool_update_ranges(struct nat_pool *np, struct nat_pool_ranges *new)
{
	struct nat_pool_ranges *old = np->np_ranges;
	bool destructive_change = false;
	uint i, j;

	if (!old) {
		rcu_assign_pointer(np->np_ranges, new);
		return 0;
	}

	/*
	 * Check that existing ranges are present.  Addresses may be added to
	 * a range without affecting current operation.
	 *
	 * If addresses are removed from a range then we use the brute force
	 * approach and de-activate the pool (which clears sessions and
	 * mappings)
	 */
	for (i = 0; i < old->nr_nranges; i++) {
		/* Loop through 'new' ranges to find matching range name */
		for (j = 0; j < new->nr_nranges; j++) {
			if (!strcmp(new->nr_range[j].pr_name,
				     old->nr_range[i].pr_name)) {
				/* Found match.  Has it changed? */
				if (new->nr_range[j].pr_type !=
				    old->nr_range[i].pr_type ||
				    new->nr_range[j].pr_addr_start >
				    old->nr_range[i].pr_addr_start ||
				    new->nr_range[j].pr_addr_stop <
				    old->nr_range[i].pr_addr_stop)
					destructive_change = true;

				/* Go to next 'old' range */
				break;
			}
		}

		/* Is a range missing from new config? */
		if (j == new->nr_nranges)
			destructive_change = true;
	}

	if (destructive_change)
		nat_pool_clear_active(np);

	old = rcu_xchg_pointer(&np->np_ranges, new);

	/* rcu-free old np_ranges */
	nat_pool_free_ranges(old, true);

	return 0;
}

/*
 * Create a nat pool
 */
static struct nat_pool *nat_pool_create(struct nat_pool_cfg *cfg, int *error)
{
	struct nat_pool *np;

	np = zmalloc_aligned(sizeof(*np));
	if (!np) {
		*error = -ENOMEM;
		return NULL;
	}

	/* Alloc address range structure */
	np->np_ranges = nat_pool_create_ranges(cfg, error);

	if (!np->np_ranges) {
		*error = -ENOMEM;
		goto error;
	}

	strcpy(np->np_name, cfg->np_name);

	/* Copy items from config */
	np->np_type	= cfg->np_type;
	np->np_ap	= cfg->np_ap;
	np->np_aa	= cfg->np_aa;
	np->np_block_sz	= cfg->np_block_sz;
	np->np_mbpu	= cfg->np_mbpu;
	np->np_port_start = cfg->np_port_start;
	np->np_port_end	= cfg->np_port_end;
	np->np_pa	= cfg->np_pa;
	np->np_log_pba	= cfg->np_log_pba;
	np->np_blacklist = NULL;

	if (cfg->np_blacklist_name) {
		/* We store a pointer the address group */
		np->np_blacklist =
			npf_addrgrp_lookup_name(cfg->np_blacklist_name);

		/* Take reference on ag since we are storing ptr */
		if (np->np_blacklist)
			npf_addrgrp_get(np->np_blacklist);
	}

	/* Initialize non-config items */
	rte_atomic32_init(&np->np_refcnt);
	rte_atomic32_init(&np->np_map_active);
	rte_atomic64_init(&np->np_map_reqs);
	rte_atomic64_init(&np->np_map_fails);

	rte_atomic32_init(&np->np_pb_active);
	rte_atomic64_init(&np->np_pb_allocs);
	rte_atomic64_init(&np->np_pb_freed);
	rte_atomic64_init(&np->np_pb_limit);

	/* State derived from config */
	np->np_nports = np->np_port_end - np->np_port_start + 1;

	return np;
error:
	nat_pool_destroy(np, false);
	return NULL;
}

/* Free a nat pool */
static void nat_pool_free(struct nat_pool *np)
{
	nat_pool_free_ranges(np->np_ranges, false);
	np->np_ranges = NULL;

	free(np);
}

/* Schedule freeing nat pool */
static void nat_pool_rcu_free(struct rcu_head *head)
{
	struct nat_pool *np = caa_container_of(head, struct nat_pool,
					       np_rcu_head);
	nat_pool_free(np);
}

/*
 * Insert nat pool into hash table
 */
static int nat_pool_insert(struct nat_pool *np)
{
	struct cds_lfht_node *node;
	struct match m = { .name = np->np_name };
	ulong hash;

	if (!nat_pool_ht)
		return -ENOENT;

	hash = nat_pool_hash(np->np_name);
	node = cds_lfht_add_unique(nat_pool_ht, hash, nat_pool_match, &m,
				   &np->np_node);

	/*
	 * This should never happen as entries are only added by master thread
	 */
	if (node != &np->np_node)
		return -EEXIST;

	/* Takes reference on the pool */
	nat_pool_get(np);

	/* Notify event */
	nat_pool_event(NP_EVT_CREATE, np);

	return 0;
}

/*
 * Delete nat pool from hash table
 */
static int nat_pool_delete(struct nat_pool *np)
{
	int rc;

	if (!nat_pool_ht)
		return -ENOENT;

	rc = cds_lfht_del(nat_pool_ht, &np->np_node);
	if (rc < 0)
		return rc;

	/* Notify event */
	nat_pool_event(NP_EVT_DELETE, np);

	/* Release reference on pool */
	nat_pool_put(np);

	return 0;
}

static void nat_pool_destroy(struct nat_pool *np, bool rcu_free)
{
	struct npf_addrgrp *ag;

	assert(rte_atomic32_read(&np->np_refcnt) == 0);

	/* Release reference on blacklist address-group */
	ag = rcu_xchg_pointer(&np->np_blacklist, NULL);
	if (ag)
		npf_addrgrp_put(ag);

	if (rcu_free)
		call_rcu(&np->np_rcu_head, nat_pool_rcu_free);
	else
		nat_pool_free(np);
}

/*
 * Take reference on a nat pool.
 */
struct nat_pool *nat_pool_get(struct nat_pool *np)
{
	rte_atomic32_inc(&np->np_refcnt);
	return np;
}

/*
 * Release reference on a nat pool.
 */
void nat_pool_put(struct nat_pool *np)
{
	assert(np);
	if (np && rte_atomic32_dec_and_test(&np->np_refcnt))
		nat_pool_destroy(np, true);
}

/*
 * Walk all nat pools
 */
int nat_pool_walk(nat_poolwalk_cb cb, void *data)
{
	struct cds_lfht_iter iter;
	struct nat_pool *np;
	int rc;

	if (!nat_pool_ht)
		return -ENOENT;

	cds_lfht_for_each_entry(nat_pool_ht, &iter, np, np_node) {
		rc = cb(np, data);
		if (rc)
			return rc;
	}
	return 0;
}

/*
 * Get the range index that an address is in.  Returns -1 if address is not in
 * any range.  'addr' is in host-byte order.
 */
int nat_pool_addr_range(struct nat_pool *np, uint32_t addr)
{
	struct nat_pool_ranges *nr = np->np_ranges;
	uint range;

	for (range = 0; range < nr->nr_nranges; range++) {
		if (addr >= nr->nr_range[range].pr_addr_start &&
		    addr <= nr->nr_range[range].pr_addr_stop)
			return (int)range;
	}
	return -1;
}

/*
 * Get next address in pool after the given address.  If the given addr is 0
 * then the first address in the first range is returned.
 */
uint32_t nat_pool_next_addr(struct nat_pool *np, uint32_t addr,
			    struct nat_pool_range **prp)
{
	struct nat_pool_ranges *nr = np->np_ranges;
	uint range;
	int rc;

	if (addr == 0) {
		/* Return first address in first range */
		if (likely(prp != NULL))
			*prp = &nr->nr_range[0];
		return nr->nr_range[0].pr_addr_start;
	}

	/* Find the range that addr is in */
	rc = nat_pool_addr_range(np, addr);

	/*
	 * If the ranges in the pool have changed, then return the
	 * first address in the first range
	 */
	if (rc < 0) {
		if (likely(prp != NULL))
			*prp = &nr->nr_range[0];
		return nr->nr_range[0].pr_addr_start;
	}

	range = (uint)rc;

	if (++addr > nr->nr_range[range].pr_addr_stop) {
		/* Try next range */
		if (++range >= nr->nr_nranges)
			range = 0;
		addr = nr->nr_range[range].pr_addr_start;
	}
	if (likely(prp != NULL))
		*prp = &nr->nr_range[range];
	return addr;
}

static const char *nat_pool_range_type_str(enum nat_pool_range_type type)
{
	switch (type) {
	case NPA_PREFIX:
		return "prefix";
	case NPA_RANGE:
		return "range";
	case NPA_SUBNET:
		return "subnet";
	};
	return "unknown";
}

/*
 * NAT pool range string
 */
static char *nat_pool_range_str(struct nat_pool_range *pr)
{
	static char str[70];
	uint32_t addr;
	char str1[20], str2[20];

	addr = htonl(pr->pr_addr_start);
	inet_ntop(AF_INET, &addr, str1, sizeof(str1));

	addr = htonl(pr->pr_addr_stop);
	inet_ntop(AF_INET, &addr, str2, sizeof(str2));

	snprintf(str, sizeof(str), "%s - %s", str1, str2);

	return str;
}

/*
 * NAT pool prefix or subnet string
 */
static char *nat_pool_prefix_str(struct nat_pool_range *pr)
{
	static char str[30];
	char str1[20];
	uint32_t addr;

	addr = htonl(pr->pr_prefix);
	inet_ntop(AF_INET, &addr, str1, sizeof(str1));
	snprintf(str, sizeof(str), "%s/%u", str1, pr->pr_mask);
	return str;
}

/*
 * json for address pool ranges
 */
static void
nat_pool_jsonw_ranges(json_writer_t *json, struct nat_pool *np)
{
	struct nat_pool_ranges *nr = rcu_dereference(np->np_ranges);
	uint i;

	jsonw_uint_field(json, "naddrs", nr->nr_naddrs);
	jsonw_uint_field(json, "used", rte_atomic32_read(&nr->nr_used));

	jsonw_name(json, "address_ranges");
	jsonw_start_array(json);

	for (i = 0; i < nr->nr_nranges; i++) {
		struct nat_pool_range *pr = &nr->nr_range[i];

		jsonw_start_object(json);
		jsonw_string_field(json, "name", pr->pr_name);
		jsonw_string_field(json, "type",
				   nat_pool_range_type_str(pr->pr_type));

		/* Display the address range for all types */
		jsonw_string_field(json, "range", nat_pool_range_str(pr));

		jsonw_uint_field(json, "naddrs", pr->pr_naddrs);

		if (pr->pr_type == NPA_PREFIX)
			jsonw_string_field(json, "prefix",
					   nat_pool_prefix_str(pr));
		else if (pr->pr_type == NPA_SUBNET)
			jsonw_string_field(json, "subnet",
					   nat_pool_prefix_str(pr));

		jsonw_end_object(json);
	}
	jsonw_end_array(json);

	/*
	 * Add json for hidden NAT pool address-group.
	 *
	 * We use the generic address group code to format the json for this
	 * hidden group. The per address-group json is normally an object
	 * within an array.  We dont have the array here, so need to name the
	 * json object.
	 */
	struct npf_addrgrp *ag = rcu_dereference(nr->nr_ag);
	if (ag) {
		struct npf_show_ag_ctl ctl = { 0 };
		ctl.af[AG_IPv4] = true;
		ctl.detail = true;

		jsonw_name(json, "address-group");
		npf_addrgrp_jsonw_one(json, ag, &ctl);
	}
}

/*
 * json for address pool mapping stats
 */
static void
nat_pool_jsonw_mappings(json_writer_t *json, struct nat_pool *np)
{
	jsonw_name(json, "map_stats");
	jsonw_start_object(json);

	jsonw_uint_field(json, "active", rte_atomic32_read(&np->np_map_active));
	jsonw_uint_field(json, "reqs", rte_atomic64_read(&np->np_map_reqs));
	jsonw_uint_field(json, "fails", rte_atomic64_read(&np->np_map_fails));

	jsonw_end_object(json);
}

/*
 * json for port-block allocation stats
 */
static void
nat_pool_jsonw_pba(json_writer_t *json, struct nat_pool *np)
{
	jsonw_name(json, "block_stats");
	jsonw_start_object(json);

	jsonw_uint_field(json, "active", rte_atomic32_read(&np->np_pb_active));
	jsonw_uint_field(json, "total", rte_atomic64_read(&np->np_pb_allocs));
	jsonw_uint_field(json, "failures", rte_atomic64_read(&np->np_pb_fails));
	jsonw_uint_field(json, "freed", rte_atomic64_read(&np->np_pb_freed));
	jsonw_uint_field(json, "subs_limit",
			 rte_atomic64_read(&np->np_pb_limit));

	jsonw_end_object(json);
}

static const char *nat_pool_type_str(enum nat_pool_type pt)
{
	switch (pt) {
	case NPT_CGNAT:
		return "cgnat";
	};
	return "unknown";
}

static const char *nat_pool_addr_pooling_str(enum nat_addr_pooling ap)
{
	switch (ap) {
	case NAT_AP_PAIRED:
		return "paired";
	case NAT_AP_ARBITRARY:
		return "arbitrary";
	};
	return "unknown";
}

static const char *nat_pool_addr_allcn_str(enum nat_addr_allcn aa)
{
	switch (aa) {
	case NAT_AA_ROUND_ROBIN:
		return "round-robin";
	case NAT_AA_SEQUENTIAL:
		return "sequential";
	};
	return "unknown";
}

static const char *nat_pool_port_allcn_str(enum nat_port_allcn pa)
{
	switch (pa) {
	case NAT_PA_RANDOM:
		return "random";
	case NAT_PA_SEQUENTIAL:
		return "sequential";
	};
	return "unknown";
}

/*
 * json for one nat pool
 */
static void
nat_pool_jsonw_one(json_writer_t *json, struct nat_pool *np)
{
	const char *name;
	int i;

	jsonw_start_object(json);

	jsonw_string_field(json, "name", np->np_name);
	jsonw_bool_field(json, "active", (np->np_flags & NP_ACTIVE) != 0);
	jsonw_string_field(json, "type", nat_pool_type_str(np->np_type));

	nat_pool_jsonw_ranges(json, np);

	jsonw_string_field(json, "addr_pooling",
			   nat_pool_addr_pooling_str(np->np_ap));
	jsonw_string_field(json, "addr_allocn",
			 nat_pool_addr_allcn_str(np->np_aa));

	jsonw_uint_field(json, "port_start", np->np_port_start);
	jsonw_uint_field(json, "port_end", np->np_port_end);
	jsonw_uint_field(json, "nports", np->np_nports);
	jsonw_string_field(json, "port_allocn",
			   nat_pool_port_allcn_str(np->np_pa));

	jsonw_uint_field(json, "block_sz", np->np_block_sz);
	jsonw_uint_field(json, "mbpu", np->np_mbpu);

	/* Number of users (eg cgnat policies) sharing this pool */
	uint32_t nusers = 0;
	uint64_t nuser_addrs = 0UL;

	nat_pool_client_counts(np, &nusers, &nuser_addrs);

	jsonw_uint_field(json, "nusers", nusers);

	/* Total private addresses sharing this pool */
	jsonw_uint_field(json, "nuser_addrs", nuser_addrs);

	nat_pool_jsonw_mappings(json, np);
	nat_pool_jsonw_pba(json, np);

	name = npf_addrgrp_handle2name(np->np_blacklist);
	if (name)
		jsonw_string_field(json, "blacklist", name);

	jsonw_bool_field(json, "log_pba", np->np_log_pba); /* deprecated */
	jsonw_bool_field(json, "log_all", false);	/* deprecated */

	/* Are all nat pool addrs in-use? */
	jsonw_bool_field(json, "full", np->np_full);

	jsonw_name(json, "current");
	jsonw_start_object(json);

	for (i = NAT_PROTO_FIRST; i <= NAT_PROTO_LAST; i++) {
		static char str[16];
		uint32_t addr;

		addr = nat_pool_hint(np, i);
		addr = htonl(addr);
		inet_ntop(AF_INET, &addr, str, sizeof(str));
		jsonw_string_field(json, nat_proto_lc_str(i), str);
	}
	jsonw_end_object(json);
	jsonw_end_object(json);
}

/*
 * json for all nat pools
 */
static void
nat_pool_jsonw(FILE *f)
{
	struct cds_lfht_iter iter;
	json_writer_t *json;
	struct nat_pool *np;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "pools");
	jsonw_start_array(json);

	if (nat_pool_ht) {
		cds_lfht_for_each_entry(nat_pool_ht, &iter, np, np_node)
			nat_pool_jsonw_one(json, np);
	}

	jsonw_end_array(json);
	jsonw_destroy(&json);
}

/*
 * nat_pool_show
 */
void nat_pool_show(FILE *f, int argc __unused, char **argv __unused)
{
	nat_pool_jsonw(f);
}

/*
 * Parse comma separated list of address range options: "a=yes,b=no" etc.
 */
static int
nat_pool_cfg_parse_range_opts(char *opts, struct nat_pool_range *pr)
{
	char *sep;
	char *item, *value;

	/* Address range option defaults */
	pr->pr_shared = true;

	if (!opts)
		return 0;

	/* First item */
	item = opts;

	/* NULL terminate the first "item=value" if necessary */
	sep = strstr(opts, ",");
	if (sep) {
		*sep = '\0';
		opts = sep + 1;
	} else
		opts = NULL;

	while (true) {
		/* item=value */
		sep = strstr(item, "=");
		if (!sep)
			return -EINVAL;

		*sep = '\0';
		value = sep + 1;

		/* Sharing of addresses in this range */
		if (!strcmp(item, "shared")) {
			if (!strcmp(value, "no"))
				pr->pr_shared = false;
		}

		if (!opts)
			break;

		/* Next option ... */
		item = opts;

		sep = strstr(opts, ",");
		if (sep) {
			*sep = '\0';
			opts = sep + 1;
		} else
			opts = NULL;
	}

	return 0;
}

/*
 * Parse address and mask.  'item' is either "prefix" or "subnet".
 *
 * Value is of format "RANGE2/10.1.1.0/24"
 */
static int
nat_pool_cfg_parse_prefix(char *item, char *value, struct nat_pool_range *pr)
{
	npf_netmask_t mask;
	sa_family_t fam;
	npf_addr_t addr;
	char *sep, *prefix, *opts = NULL;
	bool negate;
	int rc;

	if (!strcmp(item, "prefix"))
		pr->pr_type = NPA_PREFIX;
	else if (!strcmp(item, "subnet"))
		pr->pr_type = NPA_SUBNET;
	else
		return -EINVAL;

	sep = strstr(value, "/");
	if (sep) {
		*sep = '\0';

		/* Copy range name */
		strncpy(pr->pr_name, value, sizeof(pr->pr_name));
		pr->pr_name[NAT_POOL_NAME_MAX - 1] = '\0';

		/* Pointer to prefix string */
		prefix = sep + 1;
	} else
		return -EINVAL;

	/* Remember where the options start.  These will be parsed later */
	sep = strstr(prefix, ",");
	if (sep) {
		*sep = '\0';
		opts = sep + 1;
	}

	/* Parse prefix string */
	rc = npf_parse_ip_addr(prefix, &fam, &addr, &mask, &negate);
	if (rc < 0)
		return -EINVAL;

	pr->pr_prefix = NPF_ADDR_TO_UINT32(&addr);
	pr->pr_mask = MIN(mask, 32);

	rc = nat_pool_cfg_parse_range_opts(opts, pr);

	return rc;
}

/*
 * Parse address range.
 *
 * Value is of format "RANGE1/1.1.1.1-1.1.1.4"
 *
 * optional per-range config is as follows:
 *                   "RANGE1/1.1.1.1-1.1.1.4,shared=yes"
 */
static int
nat_pool_cfg_parse_addr_range(char *item __unused, char *value,
			      struct nat_pool_range *pr)
{
	npf_netmask_t mask;
	sa_family_t fam;
	npf_addr_t addr;
	bool negate;
	char *sep, *range, *opts = NULL;
	int rc;

	pr->pr_type = NPA_RANGE;

	sep = strstr(value, "/");
	if (sep) {
		*sep = '\0';

		/* Copy range name */
		strncpy(pr->pr_name, value, sizeof(pr->pr_name));
		pr->pr_name[NAT_POOL_NAME_MAX - 1] = '\0';

		/* Pointer to address range string */
		range = sep + 1;
	} else
		return -EINVAL;

	/* Remember where the options start.  These will be parsed later */
	sep = strstr(range, ",");
	if (sep) {
		*sep = '\0';
		opts = sep + 1;
	}

	/* Parse address range string */
	sep = strstr(range, "-");
	if (!sep)
		return -EINVAL;
	*sep = '\0';

	char *first = range, *last = sep + 1;

	rc = npf_parse_ip_addr(first, &fam, &addr, &mask, &negate);
	if (rc < 0)
		return -EINVAL;

	pr->pr_addr_start = NPF_ADDR_TO_UINT32(&addr);

	rc = npf_parse_ip_addr(last, &fam, &addr, &mask,
			       &negate);
	if (rc < 0)
		return -EINVAL;

	pr->pr_addr_stop = NPF_ADDR_TO_UINT32(&addr);

	rc = nat_pool_cfg_parse_range_opts(opts, pr);

	return rc;
}

/*
 * Parse port range.
 */
static int
nat_pool_cfg_parse_port_range(char *item __unused, char *value,
			      struct nat_pool_cfg *cfg)
{
	char *sep, *start = NULL, *stop = NULL;

	/*
	 * port-range=automatic
	 * port-range=2000
	 * port-range=2000-2020
	 */
	if (!strcmp(value, "automatic")) {
		cfg->np_port_start = NP_PORT_AUTO_START;
		cfg->np_port_end = NP_PORT_AUTO_STOP;
		return 0;
	}

	start = value;
	sep = strstr(value, "-");
	if (sep) {
		*sep = '\0';
		stop = sep + 1;
	}

	char *tmp;
	ulong n = 0;

	n = strtoul(start, &tmp, 10);
	if (*tmp != '\0' || n > USHRT_MAX)
		return -EINVAL;

	cfg->np_port_start = n;
	cfg->np_port_end = n;

	if (stop) {
		n = strtoul(stop, &tmp, 10);
		if (*tmp != '\0' || n > USHRT_MAX)
			return -EINVAL;
		cfg->np_port_end = n;
	}

	if (cfg->np_port_end < cfg->np_port_start)
		return -EINVAL;

	return 0;
}

/*
 * Parse port allocation method.  port-alloc=random|sequential
 */
static int
nat_pool_cfg_parse_pa(char *item __unused, char *value,
		      struct nat_pool_cfg *cfg)
{
	if (!strcmp(value, "random"))
		cfg->np_pa = NAT_PA_RANDOM;
	else
		cfg->np_pa = NAT_PA_SEQUENTIAL;
	return 0;
}

/*
 * Parse port-block size.  block-size=512
 */
static int
nat_pool_cfg_parse_block_sz(char *item __unused, char *value,
			    struct nat_pool_cfg *cfg)
{
	char *p;
	ulong n = 0;

	n = strtoul(value, &p, 10);
	if (*p != '\0' || n > USHRT_MAX)
		return -EINVAL;

	if (n < NP_MIN_PORT_BLOCK_SZ || n > NP_MAX_PORT_BLOCK_SZ)
		return -EINVAL;

	/* Must be multiple of 64 */
	if ((n & 0x3F) != 0)
		return -EINVAL;

	cfg->np_block_sz = n;
	return 0;
}

/*
 * Parse max-blocks-per-subscriber.  max-blocks=8
 */
static int
nat_pool_cfg_parse_mbpu(char *item __unused, char *value,
			struct nat_pool_cfg *cfg)
{
	char *p;
	ulong n = 0;

	n = strtoul(value, &p, 10);
	if (*p != '\0' || n > USHRT_MAX)
		return -1;

	if (n >= NP_MIN_MBPU && n <= NP_MAX_MBPU)
		cfg->np_mbpu = n;
	return 0;
}

/*
 * Parse address-pooling method.  addr-pooling=arbitrary | paired
 */
static int
nat_pool_cfg_parse_ap(char *item __unused, char *value,
		      struct nat_pool_cfg *cfg)
{
	if (!strcmp(value, "arbitrary"))
		cfg->np_ap = NAT_AP_ARBITRARY;
	else
		cfg->np_ap = NAT_AP_PAIRED;
	return 0;
}

/*
 * Parse address-allocation methd.  addr-alloc=sequential | round-robin
 */
static int
nat_pool_cfg_parse_aa(char *item __unused, char *value,
		      struct nat_pool_cfg *cfg)
{
	if (!strcmp(value, "sequential"))
		cfg->np_aa = NAT_AA_SEQUENTIAL;
	else
		cfg->np_aa = NAT_AA_ROUND_ROBIN;
	return 0;
}

/*
 * Parse blacklist name.  blacklist=<name>
 */
static int
nat_pool_cfg_parse_blacklist(char *item __unused, char *value,
			     struct nat_pool_cfg *cfg)
{
	if (!npf_addrgrp_lookup_name(value))
		return -EINVAL;

	cfg->np_blacklist_name = value;

	return 0;
}

static int
nat_pool_cfg_parse_type(char *item __unused, char *value,
			struct nat_pool_cfg *cfg)
{
	if (!strcasecmp(value, "cgnat"))
		cfg->np_type = NPT_CGNAT;
	else
		return -EINVAL;

	return 0;
}

static int
nat_pool_cfg_parse_log_pba(char *item __unused, char *value,
			     struct nat_pool_cfg *cfg)
{
	if (!strcasecmp(value, "yes"))
		cfg->np_log_pba = true;
	else
		cfg->np_log_pba = false;

	return 0;
}

/*
 * Parse nat pool config to structure, cfg.
 */
static int nat_pool_cfg_parse(FILE *f __unused, int argc, char **argv,
			      struct nat_pool_cfg *cfg)
{
	int rc = 0;

	/* argv and argc point to first option */
	while (argc) {
		char *sep, *item, *value;

		sep = strstr(argv[0], "=");
		if (!sep)
			goto next;

		*sep = '\0';
		item = argv[0];
		value = sep+1;

		if (!strcmp(item, "prefix") || !strcmp(item, "subnet")) {

			if (cfg->np_nranges >= NAT_POOL_MAX_RANGES) {
				rc = -EINVAL;
				goto error;
			}

			rc = nat_pool_cfg_parse_prefix(
				item, value, &cfg->np_range[cfg->np_nranges]);
			if (rc < 0)
				goto error;
			cfg->np_nranges++;

		} else if (!strcmp(item, "address-range")) {

			if (cfg->np_nranges >= NAT_POOL_MAX_RANGES) {
				rc = -EINVAL;
				goto error;
			}

			rc = nat_pool_cfg_parse_addr_range(
				item, value, &cfg->np_range[cfg->np_nranges]);
			if (rc < 0)
				goto error;

			cfg->np_nranges++;

		} else if (!strcmp(item, "type"))
			rc = nat_pool_cfg_parse_type(item, value, cfg);

		else if (!strcmp(item, "log-pba"))
			rc = nat_pool_cfg_parse_log_pba(item, value, cfg);

		else if (!strcmp(item, "port-range"))
			rc = nat_pool_cfg_parse_port_range(item, value, cfg);

		else if (!strcmp(item, "port-alloc"))
			rc = nat_pool_cfg_parse_pa(item, value, cfg);

		else if (!strcmp(item, "block-size"))
			rc = nat_pool_cfg_parse_block_sz(item, value, cfg);

		else if (!strcmp(item, "max-blocks"))
			rc = nat_pool_cfg_parse_mbpu(item, value, cfg);

		else if (!strcmp(item, "addr-pooling"))
			rc = nat_pool_cfg_parse_ap(item, value, cfg);

		else if (!strcmp(item, "addr-alloc"))
			rc = nat_pool_cfg_parse_aa(item, value, cfg);

		else if (!strcmp(item, "blacklist"))
			rc = nat_pool_cfg_parse_blacklist(item, value, cfg);

		if (rc)
			goto error;

 next:
		argc--;
		argv++;
	}

error:
	return rc;
}

/*
 * Create or update a nat pool
 *
 * nat-ut pool add POOL1 type=cgnat
 *                       address-range=RANGE1/1.1.1.11-1.1.1.20
 *                       prefix=RANGE2/1.1.1.192/26
 *                       block-size=4096 max-blocks=32 log-pba=yes
 */
int nat_pool_cfg_add(FILE *f, int argc, char **argv)
{
	struct nat_pool *np;
	int rc = 0;

	/* Items are parsed and stored in cfg */
	struct nat_pool_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));

	if (argc < 4)
		return -EINVAL;

	strncpy(cfg.np_name, argv[3], sizeof(cfg.np_name));
	cfg.np_name[NAT_POOL_NAME_MAX - 1] = '\0';
	argc -= 4;
	argv += 4;

	np = nat_pool_lookup(cfg.np_name);

	/* Setup defaults */
	if (np) {
		cfg.np_type	= np->np_type;
		cfg.np_ap	= np->np_ap;
		cfg.np_aa	= np->np_aa;
		cfg.np_block_sz	= np->np_block_sz;
		cfg.np_mbpu	= np->np_mbpu;
		cfg.np_port_start = np->np_port_start;
		cfg.np_port_end	= np->np_port_end;
		cfg.np_pa	= np->np_pa;
		cfg.np_log_pba	= np->np_log_pba;
		cfg.np_nranges	 = 0;

		cfg.np_blacklist_name =
			npf_addrgrp_handle2name(np->np_blacklist);

	} else {
		cfg.np_type	= NPT_CGNAT;
		cfg.np_ap	= NAT_AP_PAIRED;
		cfg.np_aa	= NAT_AA_ROUND_ROBIN;
		cfg.np_block_sz	= NP_DEF_PORT_BLOCK_SZ;
		cfg.np_mbpu	= NP_DEF_MBPU;
		cfg.np_port_start = NP_PORT_AUTO_START;
		cfg.np_port_end	= NP_PORT_AUTO_STOP;
		cfg.np_pa	= NAT_PA_SEQUENTIAL;
		cfg.np_log_pba	= true;
		cfg.np_nranges	 = 0;
		cfg.np_blacklist_name = NULL;
	}

	rc = nat_pool_cfg_parse(f, argc, argv, &cfg);
	if (rc < 0)
		goto error;

	if (np) {
		/* Update existing nat pool */
		bool destructive_change = false;

		/* Some changes are disallowed on an active pool */
		if (np->np_type != cfg.np_type ||
		    np->np_block_sz != cfg.np_block_sz ||
		    np->np_ap != cfg.np_ap ||
		    np->np_aa != cfg.np_aa ||
		    np->np_port_start != cfg.np_port_start ||
		    np->np_port_end != cfg.np_port_end)
			destructive_change = true;

		/* Mark NAT pool as inactive (clears all mappings.) */
		if (destructive_change)
			nat_pool_clear_active(np);

		/*
		 * Update the address ranges of an existing nat pool.  If
		 * addresses or ranges may be added without tearing down
		 * mappings.  If addresses or ranges are removed then the nat
		 * pool is de-activated.
		 */
		if (cfg.np_nranges > 0) {
			struct nat_pool_ranges *nr;

			nr = nat_pool_create_ranges(&cfg, &rc);
			if (!nr)
				goto error;

			/* This will free existing range struct if successful */
			rc = nat_pool_update_ranges(np, nr);
			if (rc < 0) {
				nat_pool_free_ranges(nr, false);
				goto error;
			}
		}

		np->np_ap	= cfg.np_ap;
		np->np_aa	= cfg.np_aa;
		np->np_block_sz = cfg.np_block_sz;
		np->np_mbpu	= cfg.np_mbpu;
		np->np_port_start = cfg.np_port_start;
		np->np_port_end = cfg.np_port_end;
		np->np_pa	= cfg.np_pa;
		np->np_log_pba	= cfg.np_log_pba;

		/* Has blacklist address-group changed? */
		const char *name = npf_addrgrp_handle2name(np->np_blacklist);

		npf_addrgrp_update_handle(name, cfg.np_blacklist_name,
					  &np->np_blacklist);

		/* State derived from config */
		np->np_nports = np->np_port_end - np->np_port_start + 1;

		/* Mark pool as active.  This is a noop if already active. */
		nat_pool_set_active(np);
	} else {
		/* Create new nat pool and copy addresses from addr_array */
		np = nat_pool_create(&cfg, &rc);

		if (!np) {
			rc = -ENOMEM;
			goto error;
		}

		/* Insert pool into hash table and take reference */
		rc = nat_pool_insert(np);
		if (rc < 0) {
			nat_pool_destroy(np, false);
			goto error;
		}

		/* Mark pool as active */
		nat_pool_set_active(np);
	}
	rc = 0;

	/* Set pool's warning threshold */
	np_threshold_set(np, NULL);

error:
	return rc;
}

/*
 * nat pool config delete
 */
int nat_pool_cfg_delete(FILE *f __unused, int argc, char **argv)
{
	const char *name;
	struct nat_pool *np;

	if (argc < 4)
		return -EINVAL;

	name = argv[3];

	np = nat_pool_lookup(name);
	if (!np)
		return 0;

	/* De-activate pool */
	nat_pool_clear_active(np);

	/* Delete pool from table and release reference */
	nat_pool_delete(np);

	return 0;
}

/*
 * One-time initialization.  Called from npf_init.
 */
void nat_pool_init(void)
{
	nat_pool_ht = cds_lfht_new(NP_HT_INIT, NP_HT_MIN, NP_HT_MAX,
				   CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
				   NULL);
}

/*
 * Called from npf_cleanup.
 */
void nat_pool_uninit(void)
{
	dp_ht_destroy_deferred(nat_pool_ht);
	nat_pool_ht = NULL;
}

/*
 * Generate NAT pool threshold log
 * and restart timer if required.
 */
static void np_threshold_log(
	struct nat_pool *np,
	int32_t val, int32_t max)
{
	cgn_log_resource_pool(
		CGN_RESOURCE_THRESHOLD, np, val, max);

	if (np_threshold_time)
		rte_timer_reset(&np->np_threshold_timer,
			np_threshold_time * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(),
			np_threshold_timer_expiry, np);
}

/*
 * Warn if over the configured nat pool threshold
 */
static void np_threshold_check(struct nat_pool *np, int32_t val)
{
	if (np->np_threshold &&
	    np->np_threshold_been_below &&
	    (val >= np->np_threshold) &&
	    (!rte_timer_pending(&np->np_threshold_timer))) {

		np->np_threshold_been_below = false;
		np_threshold_log(np, val, np->np_ranges->nr_naddrs);
	}
}

/*
 * Set NAT pool threshold for one NAT pool
 *
 * threshold is in percent; interval is in seconds.
 */
int np_threshold_set(struct nat_pool *np, void *arg __unused)
{
	rte_timer_stop(&np->np_threshold_timer);
	np->np_threshold =
		(np->np_ranges->nr_naddrs * np_threshold_cfg + 99) / 100;
	np->np_threshold_been_below = true;

	/* Warn if over configured threshold */
	int32_t val = rte_atomic32_read(&np->np_ranges->nr_used);
	np_threshold_check(np, val);

	return 0;
}

/*
 * Set NAT pool threshold for all NAT pools
 *
 * threshold is in percent; interval is in seconds.
 */
void np_threshold_set_all(int32_t threshold, uint32_t interval)
{
	np_threshold_cfg = threshold;
	np_threshold_time = interval;
	nat_pool_walk(np_threshold_set, NULL);
}

/*
 * Handle NAT pool threshold timer expiry.
 */
static void np_threshold_timer_expiry(
	struct rte_timer *timer __unused,
	void *arg)
{
	struct nat_pool *np = arg;

	int32_t val = rte_atomic32_read(&np->np_ranges->nr_used);

	if (np->np_threshold &&
		(val >= np->np_threshold)) {

		np_threshold_log(np, val, np->np_ranges->nr_naddrs);
	}
}

/*
 * Increment the threshold counter when taking a NAT pool entry.
 * Generate a log if over the threshold.
 */
void np_threshold_get(struct nat_pool *np)
{
	int32_t val = rte_atomic32_add_return(&np->np_ranges->nr_used, 1);

	/* Warn if over configured threshold */
	np_threshold_check(np, val);
}

/*
 * Decrement the threshold counter when returning a NAT pool entry
 */
void np_threshold_put(struct nat_pool *np)
{
	int32_t val = rte_atomic32_sub_return(&np->np_ranges->nr_used, 1);

	if (val < np->np_threshold)
		np->np_threshold_been_below = true;
}

/**************************************************************************
 * NAT Pool to Client API
 **************************************************************************/

/*
 * Fixed size array for holding client operations pointers.
 */
static struct np_client_ops *np_client_ops[NP_CLIENT_MAX_OPS];

/* Register client ops */
bool nat_pool_client_register(const struct np_client_ops *ops)
{
	uint32_t i;

	/* Add client to first free space */
	for (i = 0; i < ARRAY_SIZE(np_client_ops); i++) {
		if (!rcu_cmpxchg_pointer(&np_client_ops[i], NULL,
					(struct np_client_ops *)ops))
			return true;
	}
	return false;
}

/* Unregister client ops */
void nat_pool_client_unregister(const struct np_client_ops *op)
{
	struct np_client_ops *ops = (struct np_client_ops *) op;
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(np_client_ops); i++) {
		if (rcu_cmpxchg_pointer(&np_client_ops[i], ops, NULL) == ops)
			return;
	}
}

/*
 * Get the number of users and addresses using this NAT pool.
 *
 * For example, if two CGNAT policies were using this pool then nusers would
 * be two.
 *
 * naddrs is a count of all the possible source addresses for all the users
 * that may use this pool. naddrs can be compared with the number of addresses
 * in the pool to give a private-public address contention ratio.
 */
static void nat_pool_client_counts(struct nat_pool *np, uint32_t *nusers,
				   uint64_t *naddrs)
{
	struct np_client_ops *ops;
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(np_client_ops); i++) {
		ops = rcu_dereference(np_client_ops[i]);
		if (ops)
			ops->np_client_counts(np, nusers, naddrs);
	}
}
