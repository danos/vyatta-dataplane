/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
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
	char			*np_name;
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
	char			*np_blacklist_name;
};

struct match {
	const char *name;
};

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

/*
 * Increment number of users of this pool.  Typically this is a count of the
 * number of subscribers addresses in policies or rules that use this pool.
 */
void nat_pool_incr_nusers(struct nat_pool *np, uint32_t naddrs)
{
	if (np) {
		np->np_nusers++;
		np->np_nuser_addrs += naddrs;
	}
}

void nat_pool_decr_nusers(struct nat_pool *np, uint32_t naddrs)
{
	if (np) {
		np->np_nusers--;
		np->np_nuser_addrs -= naddrs;
	}
}

/* Is this a blacklisted address? */
bool
nat_pool_is_blacklist_addr(struct nat_pool *np, uint32_t addr)
{
	return np->np_blacklist != NULL &&
		npf_addrgrp_lookup_v4(np->np_blacklist, addr) == 0;
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
	char __name[len] __rte_aligned(sizeof(uint32_t));

	memcpy(__name, name, len + 1);
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
		memcpy(&nr->nr_range[i], &cfg->np_range[i],
		       sizeof(struct nat_pool_range));

		nr->nr_naddrs += (nr->nr_range[i].pr_addr_stop -
				  nr->nr_range[i].pr_addr_start + 1);
		nr->nr_range[i].pr_range = i;

		if (cfg->np_range[i].pr_name)
			nr->nr_range[i].pr_name =
				strdup(cfg->np_range[i].pr_name);
	}

	for (i = NAT_PROTO_FIRST; i <= NAT_PROTO_LAST; i++)
		rte_atomic32_set(&nr->nr_addr_hint[i], 0);

	return nr;
}

static void nat_pool_free_ranges(struct nat_pool_ranges *ranges)
{
	uint i;

	if (!ranges)
		return;

	for (i = 0; i < ranges->nr_nranges; i++)
		free(ranges->nr_range[i].pr_name);

	free(ranges);
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
	nat_pool_free_ranges(old);

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
		free(np);
		return NULL;
	}

	np->np_name = strdup(cfg->np_name);

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

	if (cfg->np_blacklist_name)
		np->np_blacklist =
			npf_addrgrp_lookup_name(cfg->np_blacklist_name);

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
}

/* Free a nat pool */
static void nat_pool_free(struct nat_pool *np)
{
	if (np->np_name)
		free(np->np_name);

	nat_pool_free_ranges(np->np_ranges);
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

static void nat_pool_destroy(struct nat_pool *np)
{
	call_rcu(&np->np_rcu_head, nat_pool_rcu_free);
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
		nat_pool_destroy(np);
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
 * any range.
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
 * Get next address in pool after the given address
 */
uint32_t nat_pool_next_addr(struct nat_pool *np, uint32_t addr)
{
	struct nat_pool_ranges *nr = np->np_ranges;
	uint range;
	int rc;

	if (addr == 0)
		/* Return first address */
		return nr->nr_range[0].pr_addr_start;

	/* Find the range that addr is in */
	rc = nat_pool_addr_range(np, addr);

	/*
	 * If the ranges in the pool have changed, then return the
	 * first address
	 */
	if (rc < 0)
		return nr->nr_range[0].pr_addr_start;

	range = (uint)rc;

	if (++addr > nr->nr_range[range].pr_addr_stop) {
		/* Try next range */
		if (++range >= nr->nr_nranges)
			range = 0;
		addr = nr->nr_range[range].pr_addr_start;
	}
	return addr;
}

/*
 * NAT pool range string
 */
static char *nat_pool_range_str(struct nat_pool_range *pr)
{
	static char str[40];
	uint32_t addr;

	if (true || pr->pr_type == NPA_RANGE) {
		char str1[20], str2[20];

		addr = htonl(pr->pr_addr_start);
		inet_ntop(AF_INET, &addr, str1, sizeof(str1));

		addr = htonl(pr->pr_addr_stop);
		inet_ntop(AF_INET, &addr, str2, sizeof(str2));

		snprintf(str, sizeof(str), "%s-%s", str1, str2);
	} else {
		char str1[20];

		addr = htonl(pr->pr_prefix);
		inet_ntop(AF_INET, &addr, str1, sizeof(str1));
		snprintf(str, sizeof(str), "%s/%u", str1, pr->pr_mask);
	}
	return str;
}

/*
 * json for address pool ranges
 */
static void
nat_pool_jsonw_ranges(json_writer_t *json, struct nat_pool *np)
{
	struct nat_pool_ranges *nr = np->np_ranges;
	uint i;

	jsonw_uint_field(json, "naddrs", nr->nr_naddrs);

	jsonw_name(json, "address_ranges");
	jsonw_start_array(json);

	for (i = 0; i < nr->nr_nranges; i++) {
		jsonw_start_object(json);
		jsonw_string_field(json, "name", nr->nr_range[i].pr_name);
		jsonw_string_field(json, "range",
				   nat_pool_range_str(&nr->nr_range[i]));
		jsonw_uint_field(json, "naddrs", nr->nr_range[i].pr_naddrs);
		jsonw_end_object(json);
	}
	jsonw_end_array(json);
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
	jsonw_uint_field(json, "nusers", np->np_nusers);

	/* Total private addresses sharing this pool */
	jsonw_uint_field(json, "nuser_addrs", np->np_nuser_addrs);

	nat_pool_jsonw_mappings(json, np);
	nat_pool_jsonw_pba(json, np);

	if (np->np_blacklist) {
		char *name = npf_addrgrp_handle2name(np->np_blacklist);
		jsonw_string_field(json, "blacklist",
				   name ? name : "(unknown)");
	}

	jsonw_bool_field(json, "log_pba", np->np_log_pba);
	jsonw_bool_field(json, "log_all", np->np_full);

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
 * Parse address and mask.  'item' is either "prefix" or "address-mask".
 *
 * Value is of format "RANGE2/10.1.1.0/24"
 */
static int
nat_pool_cfg_parse_prefix(char *item, char *value, struct nat_pool_range *pr)
{
	npf_netmask_t mask;
	sa_family_t fam;
	npf_addr_t addr;
	char *sep;
	bool negate;
	int rc;

	if (!strcmp(item, "prefix"))
		pr->pr_type = NPA_PREFIX;
	else
		return -EINVAL;

	sep = strstr(value, "/");
	if (sep) {
		*sep = '\0';
		pr->pr_name = value;
		value = sep+1;
	} else
		return -EINVAL;

	rc = npf_parse_ip_addr(value, &fam, &addr, &mask, &negate);
	if (rc < 0)
		return -EINVAL;

	pr->pr_prefix = NPF_ADDR_TO_UINT32(&addr);
	pr->pr_mask = MIN(mask, 32);

	/* Convert prefix to address range */
	if (pr->pr_mask == 32) {
		pr->pr_addr_start = pr->pr_prefix;
		pr->pr_addr_stop = pr->pr_prefix;
	} else {
		uint32_t first, last, mask;

		first = pr->pr_prefix;
		mask = 0xFFFFFFFFUL << (32 - pr->pr_mask);
		last = (first | ~mask);
		first = (first & mask);

		if (pr->pr_mask < 31) {
			/* Do not use first or last address */
			first += 1;
			last -= 1;
		}

		pr->pr_addr_start = first;
		pr->pr_addr_stop = last;
	}
	return 0;
}

/*
 * Parse address range.
 *
 * Value is of format "RANGE1/1.1.1.1-1.1.1.4"
 */
static int
nat_pool_cfg_parse_addr_range(char *item __unused, char *value,
			      struct nat_pool_range *pr)
{
	npf_netmask_t mask;
	sa_family_t fam;
	npf_addr_t addr;
	bool negate;
	char *sep;
	int rc;

	pr->pr_type = NPA_RANGE;

	sep = strstr(value, "/");
	if (sep) {
		*sep = '\0';
		pr->pr_name = value;
		value = sep+1;
	} else
		return -EINVAL;

	sep = strstr(value, "-");
	if (!sep)
		return -EINVAL;
	*sep = '\0';

	char *first = value, *last = sep+1;

	rc = npf_parse_ip_addr(first, &fam, &addr, &mask, &negate);
	if (rc < 0)
		return -EINVAL;

	pr->pr_addr_start = NPF_ADDR_TO_UINT32(&addr);

	rc = npf_parse_ip_addr(last, &fam, &addr, &mask,
			       &negate);
	if (rc < 0)
		return -EINVAL;

	pr->pr_addr_stop = NPF_ADDR_TO_UINT32(&addr);
	pr->pr_naddrs = pr->pr_addr_stop - pr->pr_addr_start + 1;

	return 0;
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

		if (!strcmp(item, "prefix")) {

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
 */
int nat_pool_cfg_add(FILE *f, int argc, char **argv)
{
	struct nat_pool *cur;
	int rc = 0;

	/* Items are parsed and stored in cfg */
	struct nat_pool_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));

	if (argc < 4)
		return -EINVAL;

	cfg.np_name = argv[3];
	argc -= 4;
	argv += 4;

	cur = nat_pool_lookup(cfg.np_name);

	/* Setup defaults */
	if (cur) {
		cfg.np_type	= cur->np_type;
		cfg.np_ap	= cur->np_ap;
		cfg.np_aa	= cur->np_aa;
		cfg.np_block_sz	= cur->np_block_sz;
		cfg.np_mbpu	= cur->np_mbpu;
		cfg.np_port_start = cur->np_port_start;
		cfg.np_port_end	= cur->np_port_end;
		cfg.np_pa	= cur->np_pa;
		cfg.np_log_pba	= cur->np_log_pba;
		cfg.np_nranges	 = 0;
		cfg.np_blacklist_name = NULL;

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
	}

	rc = nat_pool_cfg_parse(f, argc, argv, &cfg);
	if (rc < 0)
		goto error;

	if (cur) {
		/* Update existing nat pool */
		bool destructive_change = false;

		/* Some changes are disallowed on an active pool */
		if (cur->np_type != cfg.np_type ||
		    cur->np_block_sz != cfg.np_block_sz ||
		    cur->np_ap != cfg.np_ap ||
		    cur->np_aa != cfg.np_aa ||
		    cur->np_port_start != cfg.np_port_start ||
		    cur->np_port_end != cfg.np_port_end)
			destructive_change = true;

		/* Mark NAT pool as inactive (clears all mappings.) */
		if (destructive_change)
			nat_pool_clear_active(cur);

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
			rc = nat_pool_update_ranges(cur, nr);
			if (rc < 0) {
				nat_pool_free_ranges(nr);
				goto error;
			}
		}

		cur->np_ap	= cfg.np_ap;
		cur->np_aa	= cfg.np_aa;
		cur->np_block_sz = cfg.np_block_sz;
		cur->np_mbpu	= cfg.np_mbpu;
		cur->np_port_start = cfg.np_port_start;
		cur->np_port_end = cfg.np_port_end;
		cur->np_pa	= cfg.np_pa;
		cur->np_log_pba	= cfg.np_log_pba;

		if (cfg.np_blacklist_name)
			cur->np_blacklist =
				npf_addrgrp_lookup_name(cfg.np_blacklist_name);
		else
			cur->np_blacklist = NULL;

		/* State derived from config */
		cur->np_nports = cur->np_port_end - cur->np_port_start + 1;

		/* Mark pool as active.  This is a noop if already active. */
		nat_pool_set_active(cur);
	} else {
		/* Create new nat pool and copy addresses from addr_array */
		struct nat_pool *np = nat_pool_create(&cfg, &rc);

		if (!np) {
			rc = -ENOMEM;
			goto error;
		}

		/* Insert pool into hash table and take reference */
		rc = nat_pool_insert(np);
		if (rc < 0) {
			nat_pool_free(np);
			goto error;
		}

		/* Mark pool as active */
		nat_pool_set_active(np);
	}
	rc = 0;

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
