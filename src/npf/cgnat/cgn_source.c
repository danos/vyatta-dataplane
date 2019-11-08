/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_source.c - cgnat hash table of subscriber addresses.
 *
 * Hash table of cgnat subscriber addresses (i.e. private source addrs).
 * Addresses are stored in host byte-order.
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <dpdk/rte_jhash.h>
#include <urcu/list.h>

#include "compiler.h"
#include "if_var.h"
#include "urcu.h"
#include "util.h"
#include "soft_ticks.h"

#include "npf/nat/nat_proto.h"
#include "npf/nat/nat_pool.h"

#include "npf/cgnat/cgn.h"
#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_cmd_cfg.h"
#include "npf/cgnat/cgn_errno.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_log.h"


/* source GC Timer */
static struct rte_timer cgn_src_timer;

/* source hash table */
static struct cds_lfht *cgn_src_ht;

struct src_match {
	uint32_t addr;
	vrfid_t  vrfid;
};

static rte_atomic32_t cgn_src_used;
static int32_t cgn_src_max = CGN_SRC_TABLE_MAX;
static bool cgn_src_table_full;

/*
 * Update stats in source from a session.  Called periodically from the
 * session gc routine, and when a session is destroyed.
 */
void cgn_source_update_stats(struct cgn_source *src,
			     uint64_t pkts_out, uint64_t bytes_out,
			     uint64_t pkts_in, uint64_t bytes_in)
{
	assert(src);
	if (src) {
		src->sr_pkts_out += pkts_out;
		src->sr_bytes_out += bytes_out;
		src->sr_pkts_in += pkts_in;
		src->sr_bytes_in += bytes_in;
	}
}

struct cgn_source *cgn_source_get(struct cgn_source *src)
{
	rte_atomic32_inc(&src->sr_refcnt);
	return src;
}

void cgn_source_put(struct cgn_source *src)
{
	assert(src);
	rte_atomic32_dec(&src->sr_refcnt);
}

void cgn_source_stats_sess_created(struct cgn_source *src)
{
	if (src)
		rte_atomic32_inc(&src->sr_sess_created);
}

void cgn_source_stats_sess_destroyed(struct cgn_source *src)
{
	if (src)
		rte_atomic32_inc(&src->sr_sess_destroyed);
}

struct nat_pool *cgn_source_get_pool(struct cgn_source *src)
{
	if (src && src->sr_policy)
		return src->sr_policy->cp_pool;

	return NULL;
}

/*
 * Add port block to source list
 */
int
cgn_source_add_block(struct cgn_source *src, uint8_t proto,
		     struct apm_port_block *pb, struct nat_pool *np)
{
	assert(rte_spinlock_is_locked(&src->sr_lock));

	cds_list_add_tail(apm_block_get_list_node(pb), &src->sr_block_list);

	src->sr_block_count++;

	/* Take reference on source */
	cgn_source_get(src);

	/* Set active_block for the requested protocol */
	src->sr_active_block[proto] = pb;

	/*
	 * Set active_block for other protocols, if they are not already set.
	 */
	uint8_t p;
	for (p = NAT_PROTO_FIRST; p < NAT_PROTO_COUNT; p++)
		if (p != proto && src->sr_active_block[p] == NULL)
			src->sr_active_block[p] = pb;

	/*
	 * If this is the first port-block assigned to this subscriber, then
	 * remember the address
	 */
	if (src->sr_paired_addr == 0) {
		struct apm *apm = apm_block_get_apm(pb);
		if (apm)
			src->sr_paired_addr = apm->apm_addr;
	}

	if (nat_pool_log_pba(np))
		apm_log_block_alloc(pb, src->sr_addr);

	return 0;
}

/*
 * cgn_session_destroy -> cgn_map_put
 */
int
cgn_source_del_block(struct cgn_source *src, struct apm_port_block *pb,
		     struct nat_pool *np)
{
	assert(!rte_spinlock_is_locked(&src->sr_lock));
	rte_spinlock_lock(&src->sr_lock);

	/*
	 * Was src destroyed while we waited for lock?  This should never
	 * happen in normal operation as only the master thread destroys
	 * sessions, and hence calls cgn_map_put and cgn_source_del_block.
	 */
	if ((src->sr_flags & SF_DEAD) != 0) {
		rte_spinlock_unlock(&src->sr_lock);
		return -1;
	}

	if (nat_pool_log_pba(np))
		apm_log_block_release(pb, src->sr_addr);

	cds_list_del_rcu(apm_block_get_list_node(pb));
	src->sr_block_count--;

	/* Release reference on source */
	cgn_source_put(src);

	uint8_t p;
	for (p = NAT_PROTO_FIRST; p < NAT_PROTO_COUNT; p++)
		if (pb == src->sr_active_block[p])
			src->sr_active_block[p] = NULL;

	/* Had the mbpu limit been previously reached? */
	if (src->sr_mbpu_full &&
	    src->sr_block_count < nat_pool_get_mbpu(np)) {
		cgn_log_subscriber_mbpu_avail(src->sr_addr,
					      src->sr_block_count,
					      nat_pool_get_mbpu(np));
		src->sr_mbpu_full = false;
	}

	rte_spinlock_unlock(&src->sr_lock);

	return 0;
}

/*
 * Is there space in the source table?
 */
static bool cgn_src_slot_get(void)
{
	if (rte_atomic32_add_return(&cgn_src_used, 1) <= cgn_src_max)
		return true;

	rte_atomic32_dec(&cgn_src_used);

	if (!cgn_src_table_full)
		RTE_LOG(ERR, CGNAT, "SUBSCRIBER_TABLE_FULL count=%u/%u\n",
			rte_atomic32_read(&cgn_src_used), cgn_src_max);

	/*
	 * Mark src table as full.  This is reset in the gc when the src count
	 * reduces.
	 */
	cgn_src_table_full = true;

	return false;
}

static void cgn_src_slot_put(void)
{
	rte_atomic32_dec(&cgn_src_used);
}

/* Get subscriber hash table used and max counts */
int32_t cgn_source_get_used(void)
{
	return rte_atomic32_read(&cgn_src_used);
}

int32_t cgn_source_get_max(void)
{
	return cgn_src_max;
}

static struct cgn_source *
cgn_source_create(struct cgn_policy *cp, uint32_t addr, vrfid_t vrfid,
		  int *error)
{
	struct cgn_source *src;
	uint8_t proto;

	if (!cgn_src_slot_get()) {
		*error = -CGN_SRC_ENOSPC;
		return NULL;
	}

	src = zmalloc_aligned(sizeof(*src));
	if (!src) {
		*error = -CGN_SRC_ENOMEM;
		cgn_src_slot_put();
		return NULL;
	}

	src->sr_addr = addr;
	src->sr_vrfid = vrfid;
	rte_spinlock_init(&src->sr_lock);
	rte_atomic32_set(&src->sr_refcnt, 0);
	src->sr_start_time = soft_ticks;

	/* Take reference on policy */
	src->sr_policy = cgn_policy_get(cp);

	cgn_policy_inc_source_count(src->sr_policy);

	CDS_INIT_LIST_HEAD(&src->sr_block_list);
	src->sr_block_count = 0;

	for (proto = NAT_PROTO_FIRST; proto < NAT_PROTO_COUNT; proto++)
		src->sr_active_block[proto] = NULL;

	return src;
}

static void cgn_source_rcu_free(struct rcu_head *head)
{
	struct cgn_source *src = caa_container_of(head, struct cgn_source,
						  sr_rcu_head);
	free(src);
}

static void cgn_source_stats_periodic(struct cgn_source *src);

/*
 * Called from garbage collection
 */
static void cgn_source_destroy(struct cgn_source *src)
{
	assert(rte_spinlock_is_locked(&src->sr_lock));
	assert((src->sr_flags & SF_DEAD) == 0);

	/* Mark as invalid for anyone doing a lookup or acquiring lock */
	src->sr_flags |= SF_DEAD;

	/* Update stats in policy */
	cgn_source_stats_periodic(src);

	if (!src->sr_policy || src->sr_policy->cp_log_subs)
		cgn_log_subscriber_end(
			src->sr_addr, src->sr_start_time, soft_ticks,
			src->sr_pkts_out_tot, src->sr_bytes_out_tot,
			src->sr_pkts_in_tot, src->sr_bytes_in_tot,
			src->sr_sess_created_tot);

	cgn_policy_dec_source_count(src->sr_policy);

	/* Release reference on policy */
	cgn_policy_put(src->sr_policy);
	src->sr_policy = NULL;

	/* Delete from hash table */
	cds_lfht_del(cgn_src_ht, &src->sr_node);

	/* Release slot */
	cgn_src_slot_put();

	/* Schedule rcu free */
	call_rcu(&src->sr_rcu_head, cgn_source_rcu_free);
}

static ulong
cgn_source_hash(uint32_t addr, vrfid_t vrfid)
{
	return rte_jhash_1word(addr, vrfid);
}

/*
 * cgnat source hash table match function
 */
static int cgn_source_match(struct cds_lfht_node *node, const void *key)
{
	struct cgn_source *src = caa_container_of(node, struct cgn_source,
						  sr_node);
	const struct src_match *m = key;

	/* Never return an expired or dead entry. */
	if (src->sr_flags & (SF_DEAD | SF_EXPIRED))
		return 0; /* no match */

	if (src->sr_addr != m->addr)
		return 0; /* no match */

	if (src->sr_vrfid != m->vrfid)
		return 0; /* no match */

	return 1; /* match */
}

/*
 * cgnat source hash table match function for expired entries
 */
static int cgn_source_match_expd(struct cds_lfht_node *node, const void *key)
{
	struct cgn_source *src = caa_container_of(node, struct cgn_source,
						  sr_node);
	const struct src_match *m = key;

	if ((src->sr_flags & (SF_DEAD | SF_EXPIRED)) != SF_EXPIRED)
		return 0; /* no match */

	if (src->sr_addr != m->addr)
		return 0; /* no match */

	if (src->sr_vrfid != m->vrfid)
		return 0; /* no match */

	return 1; /* match */
}

/*
 * Hash table lookup.  Do not match on expired sources.
 */
struct cgn_source *cgn_source_lookup(uint32_t addr, vrfid_t vrfid)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct src_match m = { .addr = addr, .vrfid = vrfid };
	ulong hash;

	assert(cgn_src_ht != NULL);
	if (!cgn_src_ht)
		return NULL;

	hash = cgn_source_hash(addr, vrfid);
	cds_lfht_lookup(cgn_src_ht, hash, cgn_source_match, &m, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct cgn_source, sr_node);

	return NULL;
}

/*
 * Hash table lookup for expired entries. Used by the show commands only.
 */
static struct cgn_source *cgn_source_lookup_expd(uint32_t addr, vrfid_t vrfid)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct src_match m = { .addr = addr, .vrfid = vrfid };
	ulong hash;

	assert(cgn_src_ht != NULL);
	if (!cgn_src_ht)
		return NULL;

	hash = cgn_source_hash(addr, vrfid);
	cds_lfht_lookup(cgn_src_ht, hash, cgn_source_match_expd, &m, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct cgn_source, sr_node);

	return NULL;
}

/*
 * Insert
 */
static int
cgn_source_insert(struct cgn_source **srcp)
{
	struct cgn_source *src = *srcp;
	struct cds_lfht_node *node;
	ulong hash;

	if (!src)
		return 0;

	struct src_match m = { .addr = src->sr_addr,
			       .vrfid = src->sr_vrfid };

	hash = cgn_source_hash(src->sr_addr, src->sr_vrfid);
	node = cds_lfht_add_unique(cgn_src_ht, hash, cgn_source_match, &m,
				   &src->sr_node);

	/* Did we loose race to add this address? */
	if (node != &src->sr_node) {

		/* Yes.  Free src and return entry that beat us. */
		free(src);
		*srcp = caa_container_of(node, struct cgn_source, sr_node);

		return 0;
	}

	if (!src->sr_policy || src->sr_policy->cp_log_subs)
		cgn_log_subscriber_start(src->sr_addr);

	return 0;
}

static struct cgn_source *
cgn_source_create_and_insert(struct cgn_policy *cp, uint32_t addr,
			     vrfid_t vrfid, int *error)
{
	struct cgn_source *src;

	src = cgn_source_create(cp, addr, vrfid, error);
	if (src)
		cgn_source_insert(&src);

	return src;
}

/*
 * Find or create a src structure, then lock it.
 *
 * addr is in host byte-order.
 */
struct cgn_source *
cgn_source_find_and_lock(struct cgn_policy *cp, uint32_t addr, vrfid_t vrfid,
			 int *error)
{
	struct cgn_source *src;

	/* Find or create source */
	src = cgn_source_lookup(addr, vrfid);
	if (!src) {
		src = cgn_source_create_and_insert(cp, addr, vrfid, error);
		if (!src)
			return NULL;
	}

	/*
	 * Lock source since we will try and allocate a port from the sources
	 * active port-block.  Check the source is still valid after acquiring
	 * lock.
	 */
	rte_spinlock_lock(&src->sr_lock);

	/*
	 * Has src been deleted while waiting for lock?
	 */
	if (src->sr_flags & SF_DEAD) {
		rte_spinlock_unlock(&src->sr_lock);
		*error = -CGN_SRC_ENOENT;
		return NULL;
	}

	/* Return a locked src */
	return src;
}

/*
 * jsonw subscriber port-block list
 */
static void
cgn_source_jsonw_port_blocks(json_writer_t *json, struct cgn_source *src)
{
	struct apm_port_block *pb;

	pb = src->sr_active_block[NAT_PROTO_TCP];
	jsonw_uint_field(json, "tcp_active_block", apm_block_get_block(pb));

	pb = src->sr_active_block[NAT_PROTO_UDP];
	jsonw_uint_field(json, "udp_active_block", apm_block_get_block(pb));

	pb = src->sr_active_block[NAT_PROTO_OTHER];
	jsonw_uint_field(json, "other_active_block", apm_block_get_block(pb));

	jsonw_name(json, "port_blocks");
	jsonw_start_array(json);

	apm_source_port_block_list_jsonw(json, &src->sr_block_list);

	jsonw_end_array(json);
}

struct cgn_source_fltr {
	bool		sf_all;
	uint32_t	sf_addr;	/* host byte-order */
	uint32_t	sf_mask;
	bool		sf_detail;
	uint32_t	sf_start;
	uint32_t	sf_count;
};

/* Convert a count to a per-second rate */
static uint cgn_count2rate(uint count, uint interval)
{
	uint rate = 0;

	if (count > 0) {
		if (count < interval)
			rate = 1;
		else
			rate = count / interval;
	}
	return rate;
}

/*
 * cgn_source_jsonw_one
 */
static void
cgn_source_jsonw_one(json_writer_t *json, uint detail __unused,
		     struct cgn_source *src)
{
	char addr_str[16];
	uint32_t addr;

	jsonw_start_object(json);

	addr = htonl(src->sr_addr);
	inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
	jsonw_string_field(json, "address", addr_str);
	jsonw_uint_field(json, "flags", src->sr_flags);

	addr = htonl(src->sr_paired_addr);
	inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
	jsonw_string_field(json, "paired_addr", addr_str);

	/* Number of blocks used by this subscriber */
	jsonw_uint_field(json, "block_count", src->sr_block_count);

	uint ports_used[NAT_PROTO_COUNT] = {0};
	uint nports = 0;

	apm_source_block_list_get_counts(&src->sr_block_list,
					 &nports, ports_used);

	jsonw_uint_field(json, "port_count", nports);
	jsonw_uint_field(json, "tcp_ports_used", ports_used[NAT_PROTO_TCP]);
	jsonw_uint_field(json, "udp_ports_used", ports_used[NAT_PROTO_UDP]);
	jsonw_uint_field(json, "other_ports_used", ports_used[NAT_PROTO_OTHER]);

	if (detail)
		cgn_source_jsonw_port_blocks(json, src);

	jsonw_uint_field(json, "start_time",
			 cgn_ticks2timestamp(src->sr_start_time));
	jsonw_uint_field(json, "duration",
			 cgn_start2duration(src->sr_start_time));
	jsonw_uint_field(json, "map_reqs", src->sr_map_reqs);
	jsonw_uint_field(json, "map_fails", src->sr_map_fails);
	jsonw_uint_field(json, "map_active",
			 rte_atomic32_read(&src->sr_map_active));
	jsonw_uint_field(json, "refcnt", rte_atomic32_read(&src->sr_refcnt));

	/* Stats from completed sessions */
	uint64_t pkts, bytes;

	pkts = src->sr_pkts_out + src->sr_pkts_out_tot;
	bytes = src->sr_bytes_out + src->sr_bytes_out_tot;

	jsonw_uint_field(json, "out_pkts", pkts);
	jsonw_uint_field(json, "out_bytes", bytes);

	pkts = src->sr_pkts_in + src->sr_pkts_in_tot;
	bytes = src->sr_bytes_in + src->sr_bytes_in_tot;

	jsonw_uint_field(json, "in_pkts", pkts);
	jsonw_uint_field(json, "in_bytes", bytes);

	/* Sessions stats */
	uint32_t sess_crtd, sess_dstrd;

	sess_crtd = rte_atomic32_read(&src->sr_sess_created);
	sess_dstrd = rte_atomic32_read(&src->sr_sess_destroyed);

	jsonw_uint_field(json, "sess_crtd",
			 src->sr_sess_created_tot + sess_crtd);
	jsonw_uint_field(json, "sess_dstrd",
			 src->sr_sess_destroyed_tot + sess_dstrd);

	/*
	 * Session rates.  We start at the last value recorded, and work
	 * backwards from there.
	 */
	uint i = src->sr_sess_rate_cur, n;
	uint rate_max = 0, rate_20s, rate_1m = 0, rate_5m = 0;

	if (i == 0)
		i = CGN_SESS_RATE_CNTRS - 1;
	else
		i -= 1;

	rate_20s = src->sr_sess_rate[i];

	for (n = 0; n < CGN_SESS_RATE_CNTRS; n++) {
		if ((n * CGN_SRC_GC_INTERVAL) < 60)
			rate_1m += src->sr_sess_rate[i];

		rate_5m += src->sr_sess_rate[i];

		/* Decrement i */
		if (i == 0)
			i = CGN_SESS_RATE_CNTRS - 1;
		else
			i -= 1;
	}

	/* Convert to sessions per second */
	uint ivals_per_min = 60 / CGN_SRC_GC_INTERVAL;

	rate_max = cgn_count2rate(src->sr_sess_rate_max, CGN_SRC_GC_INTERVAL);

	rate_20s = cgn_count2rate(rate_20s, CGN_SRC_GC_INTERVAL);
	rate_1m = cgn_count2rate(rate_1m,
				 CGN_SRC_GC_INTERVAL * ivals_per_min);
	rate_5m = cgn_count2rate(rate_5m,
				 CGN_SRC_GC_INTERVAL * ivals_per_min * 5);

	jsonw_uint_field(json, "sess_rate_20s", rate_20s);
	jsonw_uint_field(json, "sess_rate_1m", rate_1m);
	jsonw_uint_field(json, "sess_rate_5m", rate_5m);

	jsonw_uint_field(json, "sess_rate_max", rate_max);
	jsonw_uint_field(json, "sess_rate_max_tm",
			 cgn_ticks2timestamp(src->sr_sess_rate_max_time));

	jsonw_end_object(json);
}

/*
 * cgn_source_jsonw
 */
static void
cgn_source_jsonw(FILE *f, struct cgn_source_fltr *fltr)
{
	bool detail = fltr->sf_detail;
	struct cds_lfht_iter iter;
	struct cgn_source *src;
	json_writer_t *json;
	uint i = 1, count = 0;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "subscribers");
	jsonw_start_array(json);

	/*
	 * If a host mask is specified in filter, then just lookup address.
	 * Show expired and non-expired entries matching the address.
	 */
	if (fltr->sf_mask == 0xffffffff) {
		src = cgn_source_lookup(fltr->sf_addr, VRF_DEFAULT_ID);
		if (src)
			cgn_source_jsonw_one(json, detail, src);

		src = cgn_source_lookup_expd(fltr->sf_addr, VRF_DEFAULT_ID);
		if (src)
			cgn_source_jsonw_one(json, detail, src);
		goto end;
	}


	cds_lfht_for_each_entry(cgn_src_ht, &iter, src, sr_node) {
		if (fltr->sf_mask &&
		    (src->sr_addr & fltr->sf_mask) != fltr->sf_addr)
			continue;

		if (fltr->sf_count && i++ < fltr->sf_start)
			continue;

		cgn_source_jsonw_one(json, detail, src);

		if (fltr->sf_count && ++count >= fltr->sf_count)
			break;
	}

end:
	jsonw_end_array(json);
	jsonw_destroy(&json);
}

static void __attribute__((format(printf, 2, 3))) cmd_err(FILE *f,
		const char *format, ...)
{
	char str[100];
	va_list ap;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	RTE_LOG(DEBUG, CGNAT, "%s\n", str);

	if (f) {
		json_writer_t *json = jsonw_new(f);
		if (json) {
			jsonw_string_field(json, "__error", str);
			jsonw_destroy(&json);
		}
	}
}

/*
 * cgn_source_show
 *
 * cgn-op show subscriber [address 100.64.0.0/30] [detail]
 */
void cgn_source_show(FILE *f, int argc, char **argv)
{
	struct cgn_source_fltr fltr = { 0 };

	fltr.sf_all = true;

	/* Remove "cgn-op show subscriber" */
	argc -= 3;
	argv += 3;

	while (argc > 0) {
		if (!strcmp(argv[0], "address") && argc >= 2) {
			npf_addr_t npf_addr;
			npf_netmask_t pl;
			sa_family_t fam;
			uint32_t addr;
			bool negate;
			ulong tmp;
			int rc;

			rc = npf_parse_ip_addr(argv[1], &fam, &npf_addr,
					       &pl, &negate);
			if (rc < 0)
				return;

			pl = MIN(32, pl);
			memcpy(&addr, &npf_addr, 4);
			fltr.sf_addr = ntohl(addr);

			tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
			fltr.sf_mask = tmp;
			fltr.sf_addr &= fltr.sf_mask;
			fltr.sf_all = false;

			argc -= 2;
			argv += 2;

		} else if (argc >= 1 && !strcmp(argv[0], "detail")) {
			fltr.sf_detail = true;
			argc -= 1;
			argv += 1;

		} else if (!strcmp(argv[0], "start") && argc >= 2) {
			int tmp;

			tmp = cgn_arg_to_int(argv[1]);
			if (tmp < 0)
				cmd_err(f, "invalid start: %s\n", argv[1]);

			fltr.sf_start = tmp;
			/* count is optional, so set default here */
			fltr.sf_count = UINT_MAX;
			fltr.sf_all = false;

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "count") && argc >= 2) {
			int tmp;

			tmp = cgn_arg_to_int(argv[1]);
			if (tmp < 0)
				cmd_err(f, "invalid count: %s\n", argv[1]);

			/* count of 0 means show all */
			if (tmp > 0)
				fltr.sf_count = tmp;
			else
				fltr.sf_count = UINT_MAX;

			argc -= 2;
			argv += 2;

		} else {
			/* Unknown option */
			argc -= 1;
			argv += 1;
		}
	}

	cgn_source_jsonw(f, &fltr);
}

/*
 * Return json list of addresses in uint format, host-byte order
 *
 * cgn-op list subscribers [prefix 100.64.0.0/30]
 */
void cgn_source_list(FILE *f, int argc, char **argv)
{
	uint32_t fltr_addr = 0, mask = 0;
	int rc;

	argc -= 3;
	argv += 3;

	if (argc >= 2 && !strcmp(argv[0], "prefix")) {
		npf_addr_t npf_addr;
		npf_netmask_t pl;
		sa_family_t fam;
		bool negate;
		ulong tmp;

		rc = npf_parse_ip_addr(argv[1], &fam, &npf_addr, &pl, &negate);
		if (rc < 0)
			return;

		pl = MIN(32, pl);
		memcpy(&fltr_addr, &npf_addr, 4);
		fltr_addr = ntohl(fltr_addr);
		tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
		mask = tmp;
	}

	struct cds_lfht_iter iter;
	struct cgn_source *src;
	json_writer_t *json;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "subscribers");
	jsonw_start_array(json);

	cds_lfht_for_each_entry(cgn_src_ht, &iter, src, sr_node) {
		if (mask != 0 && (src->sr_addr & mask) != fltr_addr)
			continue;

		jsonw_uint(json, src->sr_addr);
	}

	jsonw_end_array(json);
	jsonw_destroy(&json);

}

/*
 * Called from master thread in garbage collection interval, and from
 * cgn_source_destroy.
 */
static void
cgn_source_stats_periodic(struct cgn_source *src)
{
	assert(rte_spinlock_is_locked(&src->sr_lock));

	/*
	 * Sessions created and destroyed
	 */
	uint32_t sess_crtd, sess_dstd;

	sess_crtd = rte_atomic32_exchange(
		(volatile uint32_t *)&src->sr_sess_created.cnt, 0);
	sess_dstd = rte_atomic32_exchange(
		(volatile uint32_t *)&src->sr_sess_destroyed.cnt, 0);

	src->sr_sess_created_tot += sess_crtd;
	src->sr_sess_destroyed_tot += sess_dstd;

	src->sr_sess_rate[src->sr_sess_rate_cur] = sess_crtd;

	if (++src->sr_sess_rate_cur >= CGN_SESS_RATE_CNTRS)
		src->sr_sess_rate_cur = 0;

	if (sess_crtd > src->sr_sess_rate_max) {
		src->sr_sess_rate_max = sess_crtd;
		src->sr_sess_rate_max_time = soft_ticks;
	}

	/*
	 * Packets and byte counts
	 */
	src->sr_pkts_out_tot += src->sr_pkts_out;
	src->sr_bytes_out_tot += src->sr_bytes_out;
	src->sr_pkts_in_tot += src->sr_pkts_in;
	src->sr_bytes_in_tot += src->sr_bytes_in;

	/* Update stats in policy */
	cgn_policy_update_stats(src->sr_policy,
				src->sr_pkts_out, src->sr_bytes_out,
				src->sr_pkts_in, src->sr_bytes_in,
				sess_crtd, sess_dstd);

	src->sr_pkts_out = 0UL;
	src->sr_bytes_out = 0UL;
	src->sr_pkts_in = 0UL;
	src->sr_bytes_in = 0UL;
}

/*
 * Garbage collector per-entry inspection function
 */
static void cgn_source_gc_inspect(struct cgn_source *src)
{
	assert(!rte_spinlock_is_locked(&src->sr_lock));
	rte_spinlock_lock(&src->sr_lock);

	cgn_source_stats_periodic(src);

	/*
	 * Wait until all references on the entry have been removed.  There
	 * will be one reference for each port-block used by this source.
	 */
	if (rte_atomic32_read(&src->sr_refcnt) > 0) {
		src->sr_gc_pass = 0;
		src->sr_flags &= ~(SF_EXPIRED | SF_DEAD);
		goto unlock;
	}

	/*
	 * Once all references are released:
	 *  1st pass: Nothing happens
	 *  2nd pass: Marked as SF_EXPIRED (no longer findable in ht)
	 *  3rd pass: Marked as SF_DEAD (src destroyed, then rcu-freed)
	 */

	if (src->sr_gc_pass++ < CGN_SRC_GC_COUNT) {
		/*
		 * Mark source as expired 1 full gc pass before it is removed
		 * from the hash table destroyed.  Expired sources are no
		 * longer findable in the table.
		 */
		if (src->sr_gc_pass == CGN_SRC_GC_COUNT)
			src->sr_flags |= SF_EXPIRED;

		goto unlock;
	}

	cgn_source_destroy(src);

unlock:
	rte_spinlock_unlock(&src->sr_lock);
}

static void cgn_source_gc_walk(void)
{
	struct cds_lfht_iter iter;
	struct cgn_source *src;

	if (!cgn_src_ht)
		return;

	cds_lfht_for_each_entry(cgn_src_ht, &iter, src, sr_node)
		cgn_source_gc_inspect(src);

	/* Is table still full? */
	if (cgn_src_table_full &&
	    rte_atomic32_read(&cgn_src_used) < cgn_src_max) {

		RTE_LOG(ERR, CGNAT, "SUBSCRIBER_TABLE_AVAILABLE count=%u/%u\n",
			rte_atomic32_read(&cgn_src_used), cgn_src_max);

		cgn_src_table_full = false;
	}
}

static void cgn_source_gc(struct rte_timer *timer __unused, void *arg __unused)
{
	/* Walk the source table */
	cgn_source_gc_walk();

	/* Restart timer if dataplane still running */
	if (running)
		rte_timer_reset(&cgn_src_timer,
				CGN_SRC_GC_INTERVAL * rte_get_timer_hz(),
				SINGLE, rte_get_master_lcore(), cgn_source_gc,
				NULL);
}

/*
 * Unit-test only.
 */
void cgn_source_cleanup(void)
{
	rte_timer_stop(&cgn_src_timer);
	cgn_source_gc_walk();
	cgn_source_gc_walk(); /* SF_EXPIRED */
	cgn_source_gc_walk(); /* SF_DEAD */
}

void cgn_source_init(void)
{
	if (cgn_src_ht)
		return;

	cgn_src_ht = cds_lfht_new(CGN_SOURCE_HT_INIT, CGN_SOURCE_HT_MIN,
				  CGN_SOURCE_HT_MAX,
				  CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
				  NULL);

	rte_timer_init(&cgn_src_timer);
	rte_timer_reset(&cgn_src_timer,
			(CGN_SRC_GC_INTERVAL + 5) * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), cgn_source_gc,
			NULL);
}


void cgn_source_uninit(void)
{
	uint i;

	if (!cgn_src_ht)
		return;

	rte_timer_stop(&cgn_src_timer);

	for (i = 0; i <= CGN_SRC_GC_COUNT; i++)
		cgn_source_gc_walk();

	dp_ht_destroy_deferred(cgn_src_ht);
	cgn_src_ht = NULL;
}
