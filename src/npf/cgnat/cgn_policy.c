/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_policy.c - cgnat policy
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <dpdk/rte_jhash.h>

#include "compiler.h"
#include "if_var.h"
#include "util.h"

#include "npf/npf_addrgrp.h"
#include "npf/nat/nat_pool_public.h"

#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_cmd_cfg.h"
#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_time.h"


/*
 * CG-NAT policy hash table.  Policy name is used for the hash.  Used for
 * configuration only.
 */
#define CP_HT_INIT		8
#define CP_HT_MIN		16
#define CP_HT_MAX		128

#define CGN_POLICY_LOG_SESS_PERIOD_MIN	300
#define CGN_POLICY_LOG_SESS_PERIOD_MAX	86400

static struct cds_lfht *cgn_policy_ht;

struct match {
	const char *name;
};

static void cgn_policy_destroy(struct cgn_policy *cp, bool rcu_free);
static void cgn_policy_free_sess_rate(struct cgn_policy *cp);

/*
 * Record destination?  i.e. create nested 2-tuple session.
 *
 * This is determined from either a per-policy configuration
 * (cp_log_sess_all), of from an address-group of subscriber addresses and/or
 * prefixes (cp_log_sess_ag).
 */
bool cgn_policy_record_dest(struct cgn_policy *cp, uint32_t addr)
{
	if (cp->cp_log_sess_all)
		return true;

	if (cp->cp_log_sess_ag)
		return npf_addrgrp_lookup_v4_by_handle(
			cp->cp_log_sess_ag, addr) == 0;

	return false;
}

static ulong cgn_policy_hash(const char *name)
{
	return rte_jhash(name, strlen(name), 0);
}

/*
 * cgnat policy hash table match function
 */
static int cgn_policy_match(struct cds_lfht_node *node, const void *key)
{
	struct cgn_policy *cp = caa_container_of(node, struct cgn_policy,
						 cp_table_node);
	const struct match *m = key;

	if (strcmp(cp->cp_name, m->name) != 0)
		return 0; /* no match */

	return 1; /* match */
}

/*
 * cgnat policy hash table lookup
 */
struct cgn_policy *cgn_policy_lookup(const char *name)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct match m = { .name = name };
	ulong hash;

	if (!cgn_policy_ht)
		return NULL;

	hash = cgn_policy_hash(name);
	cds_lfht_lookup(cgn_policy_ht, hash, cgn_policy_match, &m, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct cgn_policy, cp_table_node);

	return NULL;
}

/*
 * Insert cgnat policy into hash table
 */
static int cgn_policy_insert(struct cgn_policy *cp)
{
	struct cds_lfht_node *node;
	struct match m = { .name = cp->cp_name };
	ulong hash;

	if (!cgn_policy_ht)
		return -ENOENT;

	hash = cgn_policy_hash(cp->cp_name);
	node = cds_lfht_add_unique(cgn_policy_ht, hash, cgn_policy_match, &m,
				   &cp->cp_table_node);

	/*
	 * This should never happen as entries are only added by main thread
	 */
	if (node != &cp->cp_table_node)
		return -EEXIST;

	/* Take reference on policy */
	cgn_policy_get(cp);

	return 0;
}

/*
 * Delete nat policy from hash table
 */
static int cgn_policy_delete(struct cgn_policy *cp)
{
	int rc = -ENOENT;

	if (cgn_policy_ht) {
		rc = cds_lfht_del(cgn_policy_ht, &cp->cp_table_node);
		cgn_policy_put(cp);
	}

	return rc;
}

struct nat_pool *cgn_policy_get_pool(struct cgn_policy *cp)
{
	/*
	 * NAT pool may be temporarily inactive if it is being reconfigured.
	 */
	if (cp && nat_pool_is_active(cp->cp_pool))
		return cp->cp_pool;

	return NULL;
}

const char *cgn_policy_get_name(struct cgn_policy *cp)
{
	if (cp)
		return cp->cp_name;
	return NULL;
}

/*
 * Get the number of addresses that a cgnat policy might match, i.e. the
 * number of subscribers covered by this policy.
 */
static uint32_t cgn_policy_naddrs(struct cgn_policy *cp)
{
	uint32_t naddrs = 0;

	if (cp->cp_match_ag)
		naddrs += npf_addrgrp_naddrs_by_handle(AG_IPv4,
						       cp->cp_match_ag, true);

	return naddrs;
}

/*
 * Attach policy to nat pool
 */
static int
cgn_policy_attach_pool(struct cgn_policy *cp, const char *pool_name)
{
	struct nat_pool *np;

	np = nat_pool_lookup(pool_name);
	if (!np)
		return -ENOENT;

	/* Take reference on pool */
	cp->cp_pool = nat_pool_get(np);

	return 0;
}

static void
cgn_policy_detach_pool(struct cgn_policy *cp)
{
	if (!cp->cp_pool)
		return;

	nat_pool_put(cp->cp_pool);
	cp->cp_pool = NULL;
}

/*
 * Create cgnat policy
 */
static struct cgn_policy *cgn_policy_create(struct cgn_policy_cfg *cpc)
{
	size_t sz;
	int rc;

	/*
	 * Policy name and match address-group must be configured.
	 */
	if (strlen(cpc->cp_name) == 0 || !cpc->cp_match_ag_name)
		return NULL;

	sz = sizeof(struct cgn_policy);

	struct cgn_policy *cp = zmalloc_aligned(sz);
	if (!cp)
		return NULL;

	strncpy(cp->cp_name, cpc->cp_name, sizeof(cp->cp_name));
	rte_atomic32_set(&cp->cp_refcnt, 0);
	cp->cp_match_ag = NULL;
	CDS_INIT_LIST_HEAD(&cp->cp_list_node);
	cp->cp_priority = cpc->cp_priority;

	cp->cp_map_type = cpc->cp_map_type;
	cp->cp_fltr_type = cpc->cp_fltr_type;
	cp->cp_trans_type = cpc->cp_trans_type;
	cp->cp_log_sess_all = cpc->cp_log_sess_all;
	cp->cp_log_sess_start = cpc->cp_log_sess_start;
	cp->cp_log_sess_end = cpc->cp_log_sess_end;
	cp->cp_log_sess_periodic = cpc->cp_log_sess_periodic;
	cp->cp_log_subs = cpc->cp_log_subs;
	cp->cp_log_sess_ag = NULL;

	CDS_INIT_LIST_HEAD(&cp->cp_sess_rate_list);
	cp->cp_sess_rate_count = 0;

	/* Is a log address-group specified? */
	if (cpc->cp_log_sess_name) {
		/* We store a pointer the address group */
		cp->cp_log_sess_ag =
			npf_addrgrp_lookup_name(cpc->cp_log_sess_name);

		if (!cp->cp_log_sess_ag)
			goto error;

		/* Take reference on ag since we are storing ptr */
		npf_addrgrp_get(cp->cp_log_sess_ag);
	}

	if (cp->cp_log_sess_all ||
	    cp->cp_map_type == CGN_MAP_EDM || cp->cp_fltr_type == CGN_FLTR_EDF)
		cp->cp_sess2_enabled = true;

	/* Match address-group */
	if (cpc->cp_match_ag_name) {
		/* We store a pointer the address group */
		cp->cp_match_ag =
			npf_addrgrp_lookup_name(cpc->cp_match_ag_name);

		if (!cp->cp_match_ag)
			/* Should never happen */
			goto error;

		/*
		 * We take reference on the match address-group *only* because
		 * we are storing a pointer to the address-group instead of a
		 * table ID.
		 */
		npf_addrgrp_get(cp->cp_match_ag);
	}

	/*
	 * Find cgnat pool.  Takes a reference on the cgnat pool if found.
	 */
	rc = cgn_policy_attach_pool(cp, cpc->cp_pool_name);
	if (rc < 0)
		goto error;

	return cp;

error:
	cgn_policy_destroy(cp, false);
	return NULL;
}

static void cgn_policy_free(struct cgn_policy *cp)
{
	cgn_policy_free_sess_rate(cp);
	free(cp);
}

static void cgn_policy_rcu_free(struct rcu_head *head)
{
	struct cgn_policy *cp = caa_container_of(head, struct cgn_policy,
						 cp_rcu_head);
	cgn_policy_free(cp);
}

/*
 * cgn_policy_destroy
 */
static void cgn_policy_destroy(struct cgn_policy *cp, bool rcu_free)
{
	struct npf_addrgrp *ag;

	/*
	 * Only detach from pool when all references on the policy have been
	 * removed.
	 */
	cgn_policy_detach_pool(cp);

	/* Release reference on match address-group */
	ag = rcu_xchg_pointer(&cp->cp_match_ag, NULL);
	if (ag)
		npf_addrgrp_put(ag);

	/* Release reference on session lof address-group */
	ag = rcu_xchg_pointer(&cp->cp_log_sess_ag, NULL);
	if (ag)
		npf_addrgrp_put(ag);

	if (rcu_free)
		call_rcu(&cp->cp_rcu_head, cgn_policy_rcu_free);
	else
		cgn_policy_free(cp);
}

/*
 * cgn_policy_put - Take reference on cgnat policy
 */
struct cgn_policy *cgn_policy_get(struct cgn_policy *cp)
{
	rte_atomic32_inc(&cp->cp_refcnt);
	return cp;
}

/*
 * cgn_policy_put - Release reference on cgnat policy
 */
void cgn_policy_put(struct cgn_policy *cp)
{
	if (cp && rte_atomic32_dec_and_test(&cp->cp_refcnt))
		cgn_policy_destroy(cp, true);
}

void cgn_policy_inc_source_count(struct cgn_policy *cp)
{
	if (cp)
		rte_atomic32_inc(&cp->cp_source_count);
}

void cgn_policy_dec_source_count(struct cgn_policy *cp)
{
	if (cp)
		rte_atomic32_dec(&cp->cp_source_count);
}

/*
 * Update policy stats from a source.  Called periodically, and when a source
 * is destroyed.
 */
void cgn_policy_update_stats(struct cgn_policy *cp,
			     uint64_t pkts_out, uint64_t bytes_out,
			     uint64_t pkts_in, uint64_t bytes_in,
			     uint64_t unk_pkts_in,
			     uint64_t sess_created, uint64_t sess_destroyed,
			     uint64_t sess2_created, uint64_t sess2_destroyed)
{
	if (!cp)
		return;

	cp->cp_pkts[CGN_DIR_OUT] += pkts_out;
	cp->cp_bytes[CGN_DIR_OUT] += bytes_out;
	cp->cp_pkts[CGN_DIR_IN] += pkts_in;
	cp->cp_bytes[CGN_DIR_IN] += bytes_in;
	cp->cp_unk_pkts_in += unk_pkts_in;

	cp->cp_sess_created += sess_created;
	cp->cp_sess_destroyed += sess_destroyed;
	cp->cp_sess2_created += sess2_created;
	cp->cp_sess2_destroyed += sess2_destroyed;
}

/*
 * Create a new subscriber max session rate entry
 */
static struct cgn_policy_sess_rate *
cgn_policy_sess_rate_create(uint32_t subs_addr, uint32_t sess_rate_max,
			    uint64_t sess_rate_max_time)
{
	struct cgn_policy_sess_rate *new;
	struct cds_list_head *node;

	new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	node = &new->ps_list_node;
	CDS_INIT_LIST_HEAD(node);
	new->ps_subs_addr = subs_addr;
	new->ps_sess_rate_max = sess_rate_max;
	new->ps_sess_rate_max_time = sess_rate_max_time;

	return new;
}

/*
 * Update the list of subscribers with the highest 1 minute average session
 * rates
 */
void cgn_policy_update_sess_rate(struct cgn_policy *cp,
				 uint32_t subs_addr,
				 uint32_t sess_rate_max,
				 uint64_t sess_rate_max_time)
{
	struct cgn_policy_sess_rate *cur, *tail, *new = NULL;

	if (!cp)
		return;

	/*
	 * If the list is full *and* sess_rate_max is less than the last value
	 * in the list then there is nothing to do.
	 */
	if (cp->cp_sess_rate_count >= CGN_POLICY_SESS_RATE_MAX) {
		tail = caa_container_of(cp->cp_sess_rate_list.prev,
					struct cgn_policy_sess_rate,
					ps_list_node);
		if (sess_rate_max < tail->ps_sess_rate_max)
			return;
	}

	struct cds_list_head *node, *next, *new_node;

	/*
	 * Iterate through list looking for correct place to insert
	 */
	cds_list_for_each_safe(node, next, &cp->cp_sess_rate_list) {
		cur = caa_container_of(node, struct cgn_policy_sess_rate,
				       ps_list_node);

		/*
		 * Insert before 'cur' if rates are greater or equal
		 */
		if (!new && sess_rate_max >= cur->ps_sess_rate_max) {

			/* Are we updating the same subscriber? */
			if (subs_addr == cur->ps_subs_addr) {
				cur->ps_sess_rate_max = sess_rate_max;
				cur->ps_sess_rate_max_time = sess_rate_max_time;
				return;
			}

			/* Insert a new node before current node */
			new = cgn_policy_sess_rate_create(subs_addr,
							  sess_rate_max,
							  sess_rate_max_time);
			if (!new)
				return;

			new_node = &new->ps_list_node;
			new_node->next = node;
			new_node->prev = node->prev;
			node->prev = new_node;
			new_node->prev->next = new_node;
			cp->cp_sess_rate_count++;

			/*
			 * Calling 'continue' here means the next 'cur' will
			 * be the list node *after* the one we have just
			 * inserted (since we are using the 'safe' form of the
			 * loop).
			 */
			continue;
		}

		/*
		 * If we have already added a new node, then check if there
		 * already is an entry for this subscriber lower down in the
		 * list.
		 */
		if (new && new->ps_subs_addr == cur->ps_subs_addr) {
			cds_list_del(&cur->ps_list_node);
			free(cur);
			cp->cp_sess_rate_count--;
			return;
		}
	}

	/*
	 * If a new node was added, and we have exceeded the max then delete
	 * the last node in list
	 */
	if (new && cp->cp_sess_rate_count > CGN_POLICY_SESS_RATE_MAX) {
		node = cp->cp_sess_rate_list.prev;
		tail = caa_container_of(node, struct cgn_policy_sess_rate,
				       ps_list_node);

		cds_list_del(node);
		free(tail);
		cp->cp_sess_rate_count--;
	}

	/*
	 * If a new node was *not* added, and there is space at the end of the
	 * list, then create and add a new node.
	 */
	if (!new && cp->cp_sess_rate_count < CGN_POLICY_SESS_RATE_MAX) {
		/* Insert new entry at tail */
		new = cgn_policy_sess_rate_create(subs_addr,
						  sess_rate_max,
						  sess_rate_max_time);
		if (!new)
			return;

		cds_list_add_tail(&new->ps_list_node, &cp->cp_sess_rate_list);
		cp->cp_sess_rate_count++;
	}
}

/*
 * Free session rate list
 */
static void cgn_policy_free_sess_rate(struct cgn_policy *cp)
{
	struct cgn_policy_sess_rate *node, *next;

	cds_list_for_each_entry_safe(node, next, &cp->cp_sess_rate_list,
				     ps_list_node) {
		cds_list_del(&node->ps_list_node);
		cp->cp_sess_rate_count--;
		free(node);
	}
}

struct cgn_policy_stats {
	uint64_t	ps_sess_created;
	uint64_t	ps_sess_destroyed;
	uint64_t	ps_sess2_created;
	uint64_t	ps_sess2_destroyed;
	uint64_t	ps_pkts[CGN_DIR_SZ];
	uint64_t	ps_bytes[CGN_DIR_SZ];
	uint64_t	ps_unk_pkts_in;
};

/*
 * Sum the stats for all policies on one interface
 */
static void cgn_policy_jsonw_summary_cb(struct ifnet *ifp, void *arg)
{
	struct cgn_policy_stats *ps = arg;
	struct cds_list_head *policy_list;
	struct cgn_policy *cp;

	policy_list = cgn_if_get_policy_list(ifp);
	if (!policy_list)
		return;

	cds_list_for_each_entry(cp, policy_list, cp_list_node) {
		ps->ps_sess_created += cp->cp_sess_created;
		ps->ps_sess_destroyed += cp->cp_sess_destroyed;
		ps->ps_sess2_created += cp->cp_sess2_created;
		ps->ps_sess2_destroyed += cp->cp_sess2_destroyed;
		ps->ps_pkts[CGN_DIR_OUT] += cp->cp_pkts[CGN_DIR_OUT];
		ps->ps_bytes[CGN_DIR_OUT] += cp->cp_bytes[CGN_DIR_OUT];
		ps->ps_pkts[CGN_DIR_IN] += cp->cp_pkts[CGN_DIR_IN];
		ps->ps_bytes[CGN_DIR_IN] += cp->cp_bytes[CGN_DIR_IN];
		ps->ps_unk_pkts_in += cp->cp_unk_pkts_in;
	}
}

/*
 * Sum the stats for all policies on all interfaces
 */
void cgn_policy_jsonw_summary(json_writer_t *json)
{
	struct cgn_policy_stats ps = {0};

	/* For each interface */
	dp_ifnet_walk(cgn_policy_jsonw_summary_cb, &ps);

	jsonw_uint_field(json, "sess_created", ps.ps_sess_created);
	jsonw_uint_field(json, "sess_destroyed", ps.ps_sess_destroyed);
	jsonw_uint_field(json, "sess2_created", ps.ps_sess2_created);
	jsonw_uint_field(json, "sess2_destroyed", ps.ps_sess2_destroyed);
	jsonw_uint_field(json, "pkts_out", ps.ps_pkts[CGN_DIR_OUT]);
	jsonw_uint_field(json, "bytes_out", ps.ps_bytes[CGN_DIR_OUT]);
	jsonw_uint_field(json, "pkts_in", ps.ps_pkts[CGN_DIR_IN]);
	jsonw_uint_field(json, "bytes_in", ps.ps_bytes[CGN_DIR_IN]);
	jsonw_uint_field(json, "unk_pkts_in", ps.ps_unk_pkts_in);
}


struct cgn_policy_show_ctx {
	json_writer_t	*json;
};

/*
 * cgn_policy_jsonw_one
 */
static void
cgn_policy_jsonw_one(json_writer_t *json, struct cgn_policy *cp)
{
	char ad_str[16];
	const char *name;
	struct ifnet *ifp;

	ifp = cgn_if_get_ifp(cp->cp_ci);

	jsonw_start_object(json);

	jsonw_string_field(json, "name", cp->cp_name);

	name = npf_addrgrp_handle2name(cp->cp_match_ag);
	jsonw_string_field(json, "match_group",
			   name ? name : "(unknown)");

	if (ifp)
		jsonw_string_field(json, "interface", ifp->if_name);
	else
		jsonw_string_field(json, "interface", "");

	jsonw_uint_field(json, "priority", cp->cp_priority);

	jsonw_uint_field(json, "naddrs", cgn_policy_naddrs(cp));
	if (cp->cp_pool)
		jsonw_string_field(json, "pool", nat_pool_name(cp->cp_pool));
	else
		jsonw_string_field(json, "pool", "");

	jsonw_uint_field(json, "refcnt", rte_atomic32_read(&cp->cp_refcnt));

	jsonw_uint_field(json, "source_count",
			 rte_atomic32_read(&cp->cp_source_count));

	jsonw_uint_field(json, "sess_created", cp->cp_sess_created);
	jsonw_uint_field(json, "sess_destroyed", cp->cp_sess_destroyed);
	jsonw_uint_field(json, "sess2_created", cp->cp_sess2_created);
	jsonw_uint_field(json, "sess2_destroyed", cp->cp_sess2_destroyed);

	jsonw_uint_field(json, "out_pkts", cp->cp_pkts[CGN_DIR_OUT]);
	jsonw_uint_field(json, "out_bytes", cp->cp_bytes[CGN_DIR_OUT]);

	jsonw_uint_field(json, "in_pkts", cp->cp_pkts[CGN_DIR_IN]);
	jsonw_uint_field(json, "in_bytes", cp->cp_bytes[CGN_DIR_IN]);

	jsonw_uint_field(json, "unk_pkts_in", cp->cp_unk_pkts_in);

	jsonw_bool_field(json, "snat_alg_bypass", cgn_snat_alg_bypass_gbl);

	jsonw_bool_field(json, "record_dest", cp->cp_sess2_enabled);
	jsonw_bool_field(json, "log_sess_all", cp->cp_log_sess_all);

	name = npf_addrgrp_handle2name(cp->cp_log_sess_ag);
	if (name)
		jsonw_string_field(json, "log_sess_group", name);

	jsonw_bool_field(json, "log_sess_start", cp->cp_log_sess_start);
	jsonw_bool_field(json, "log_sess_end", cp->cp_log_sess_end);
	jsonw_uint_field(json, "log_sess_periodic", cp->cp_log_sess_periodic);

	/* List of subscribers with highest 1 minute session rates */
	jsonw_name(json, "subs_sess_rates");
	jsonw_start_array(json);

	struct cgn_policy_sess_rate *node;
	uint i = 0;

	cds_list_for_each_entry(node, &cp->cp_sess_rate_list, ps_list_node) {
		jsonw_start_object(json);

		uint32_t addr = htonl(node->ps_subs_addr);
		inet_ntop(AF_INET, &addr, ad_str, sizeof(ad_str));
		jsonw_string_field(json, "subscriber", ad_str);
		jsonw_uint_field(json, "max_sess_rate", node->ps_sess_rate_max);
		jsonw_uint_field(
			json, "time",
			cgn_ticks2timestamp(node->ps_sess_rate_max_time));

		jsonw_end_object(json);
		i++;
	}

	/* Fill empty slots something */
	for (; i < CGN_POLICY_SESS_RATE_MAX; i++) {
		jsonw_start_object(json);
		jsonw_string_field(json, "subscriber", "None");
		jsonw_uint_field(json, "max_sess_rate", 0);
		jsonw_uint_field(json, "time", 0);
		jsonw_end_object(json);
	}
	jsonw_end_array(json); /* subs_sess_rates array */

	jsonw_end_object(json);
}

/*
 * cgn_policy_jsonw_intf
 */
static void cgn_policy_jsonw_intf(struct ifnet *ifp, void *arg)
{
	struct cgn_policy_show_ctx *ctx = arg;
	struct cds_list_head *policy_list;
	struct cgn_policy *cp;

	policy_list = cgn_if_get_policy_list(ifp);
	if (!policy_list)
		return;

	cds_list_for_each_entry(cp, policy_list, cp_list_node) {
		cgn_policy_jsonw_one(ctx->json, cp);
	}
}

/*
 * Show policies that are not attached to an interface
 */
static void cgn_policy_jsonw_unattached(json_writer_t *json)
{
	struct cds_lfht_iter iter;
	struct cgn_policy *cp;

	if (!cgn_policy_ht)
		return;

	cds_lfht_for_each_entry(cgn_policy_ht, &iter, cp, cp_table_node) {
		if (cp->cp_ci == NULL)
			cgn_policy_jsonw_one(json, cp);
	}
}

/*
 * cgn_policy_jsonw
 */
static void
cgn_policy_jsonw(FILE *f, char *name)
{
	struct cgn_policy_show_ctx ctx;

	ctx.json = jsonw_new(f);
	if (!ctx.json)
		return;

	jsonw_name(ctx.json, "policies");
	jsonw_start_array(ctx.json);

	if (name) {
		struct cgn_policy *cp;

		cp = cgn_policy_lookup(name);
		if (cp)
			cgn_policy_jsonw_one(ctx.json, cp);
	} else {
		/* Show policies attached to interfaces first */
		dp_ifnet_walk(cgn_policy_jsonw_intf, &ctx);

		/* Show unattached policies */
		cgn_policy_jsonw_unattached(ctx.json);
	}

	jsonw_end_array(ctx.json);
	jsonw_destroy(&ctx.json);
}

/*
 * cgn_policy_show
 */
void cgn_policy_show(FILE *f, int argc __unused, char **argv __unused)
{
	char *name = NULL;

	/* Remove "cgn-op show policy" */
	argc -= 3;
	argv += 3;

	if (argc >= 1)
		name = argv[0];

	cgn_policy_jsonw(f, name);
}

/*
 * cgn-op clear policy <name> statistics
 */
void cgn_policy_clear(int argc, char **argv)
{
	struct cgn_policy *cp;

	/* Remove "cgn-op clear policy" */
	argc -= 3;
	argv += 3;

	if (argc < 2)
		return;

	cp = cgn_policy_lookup(argv[0]);
	if (!cp)
		return;

	if (!strcmp(argv[1], "statistics")) {
		cp->cp_pkts[CGN_DIR_OUT] = 0UL;
		cp->cp_bytes[CGN_DIR_OUT] = 0UL;
		cp->cp_pkts[CGN_DIR_IN] = 0UL;
		cp->cp_bytes[CGN_DIR_IN] = 0UL;
		cp->cp_unk_pkts_in = 0UL;

		cgn_policy_free_sess_rate(cp);
	}
}

static int
cgn_policy_cfg_parse_pool(const char *value, struct cgn_policy_cfg *cgn)
{
	cgn->cp_pool_name = value;

	return 0;
}

/* Match address-group name */
static int
cgn_policy_cfg_parse_match(const char *value, struct cgn_policy_cfg *cgn)
{
	cgn->cp_match_ag_name = value;

	return 0;
}

/*
 * map-type=eim
 * map-type=edm
 */
static int
cgn_policy_cfg_parse_map(char *value, struct cgn_policy_cfg *cgn)
{
	if (!strcmp(value, "edm"))
		cgn->cp_map_type = CGN_MAP_EDM;
	else
		cgn->cp_map_type = CGN_MAP_EIM;
	return 0;
}

/*
 * fltr-type=eif
 * fltr-type=edf
 */
static int
cgn_policy_cfg_parse_fltr(char *value, struct cgn_policy_cfg *cgn)
{
	if (!strcmp(value, "edf"))
		cgn->cp_fltr_type = CGN_FLTR_EDF;
	else
		cgn->cp_fltr_type = CGN_FLTR_EIF;
	return 0;
}

/*
 * trans-type=napt44-dyn
 * trans-type=napt44-det
 */
static int
cgn_policy_cfg_parse_trans(char *value, struct cgn_policy_cfg *cgn)
{
	if (!strcmp(value, "napt-det"))
		cgn->cp_trans_type = CGN_TRANS_NAPT44_DETERMINISTIC;
	else
		cgn->cp_trans_type = CGN_TRANS_NAPT44_DYNAMIC;
	return 0;
}

static int
cgn_policy_cfg_parse_log_sess(char *item, char *value,
			      struct cgn_policy_cfg *cgn)
{
	if (!strcmp(item, "log-sess-all")) {
		cgn->cp_log_sess_all = !strcasecmp(value, "yes");

	} else if (!strcmp(item, "log-sess-group")) {
		/* address-group? */
		cgn->cp_log_sess_name = value;

	} else if (!strcmp(item, "log-sess-creation")) {
		cgn->cp_log_sess_start = !strcasecmp(value, "yes");

	} else if (!strcmp(item, "log-sess-deletion")) {
		cgn->cp_log_sess_end = !strcasecmp(value, "yes");

	} else if (!strcmp(item, "log-sess-periodic")) {
		int tmp;

		tmp = cgn_arg_to_int(value);
		if (tmp != 0 && (tmp < CGN_POLICY_LOG_SESS_PERIOD_MIN ||
				 tmp > CGN_POLICY_LOG_SESS_PERIOD_MAX))
			return -EINVAL;

		/* Store number of gc intervals instead of seconds */
		cgn->cp_log_sess_periodic =
			(uint16_t)(tmp / CGN_SESS_GC_INTERVAL);
	}

	return 0;
}

static int
cgn_policy_cfg_parse_log_subs(char *item __unused, char *value,
			      struct cgn_policy_cfg *cgn)
{
	cgn->cp_log_subs = !strcasecmp(value, "yes");
	return 0;
}

static int
cgn_policy_cfg_parse_priority(char *value, struct cgn_policy_cfg *cfg)
{
	int tmp;

	tmp = cgn_arg_to_int(value);
	if (tmp < 1 || tmp > 9999)
		return -1;

	cfg->cp_priority = tmp;
	return 0;
}

/*
 * cgn_policy_cfg_add
 *
 * cgn policy add POLICY1 pri=10 src-addr=100.64.0.0/12 pool=POOL1
 */
int cgn_policy_cfg_add(FILE * f __unused, int argc, char **argv)
{
	struct cgn_policy *cp;
	const char *name;
	char *c, *item, *value;
	int i, rc = 0;

	if (argc < 4)
		return -EINVAL;

	name = argv[3];
	argc -= 4;
	argv += 4;

	cp = cgn_policy_lookup(name);

	/* Setup defaults */
	struct cgn_policy_cfg cfg;

	if (cp) {
		/* Copy name string from existing policy */
		strcpy(cfg.cp_name, cp->cp_name);

		cfg.cp_priority = cp->cp_priority;

		cfg.cp_match_ag_name =
			npf_addrgrp_handle2name(cp->cp_match_ag);

		cfg.cp_pool_name = nat_pool_name(cp->cp_pool);
		cfg.cp_map_type = cp->cp_map_type;
		cfg.cp_fltr_type = cp->cp_fltr_type;
		cfg.cp_trans_type = cp->cp_trans_type;
		cfg.cp_log_sess_all = cp->cp_log_sess_all;

		cfg.cp_log_sess_name =
			npf_addrgrp_handle2name(cp->cp_log_sess_ag);

		cfg.cp_log_sess_start = cp->cp_log_sess_start;
		cfg.cp_log_sess_end = cp->cp_log_sess_end;
		cfg.cp_log_sess_periodic = cp->cp_log_sess_periodic;
		cfg.cp_log_subs = cp->cp_log_subs;
	} else {
		/*
		 * We are copying name string from argv, so ensure it is NULL
		 * terminated
		 */
		strncpy(cfg.cp_name, name, sizeof(cfg.cp_name));
		cfg.cp_name[NAT_POLICY_NAME_MAX - 1] = '\0';

		cfg.cp_priority = 0;
		cfg.cp_match_ag_name = NULL;
		cfg.cp_pool_name = NULL;
		cfg.cp_map_type = CGN_MAP_EIM;
		cfg.cp_fltr_type = CGN_FLTR_EIF;
		cfg.cp_trans_type = CGN_TRANS_NAPT44_DYNAMIC;
		cfg.cp_log_sess_all = false;
		cfg.cp_log_sess_name = NULL;
		cfg.cp_log_sess_start = true;
		cfg.cp_log_sess_end = true;
		cfg.cp_log_sess_periodic = 0;
		cfg.cp_log_subs = true;
	};

	/*
	 * Parse item/value pairs.  We ignore any we do not understand.
	 */
	for (i = 0; i < argc; i++) {
		c = strchr(argv[i], '=');
		if (!c)
			continue;

		item = argv[i];
		*c = '\0';
		value = c + 1;
		rc = 0;

		/* Pool name */
		if (!strcmp(item, "pool")) {
			rc = cgn_policy_cfg_parse_pool(value, &cfg);

		/* Match address-group */
		} else if (!strcmp(item, "match-ag")) {
			rc = cgn_policy_cfg_parse_match(value, &cfg);

		/* Priority */
		} else if (!strcmp(item, "priority")) {
			rc = cgn_policy_cfg_parse_priority(value, &cfg);

		/* Config for logging a session */
		} else if (!strncmp(item, "log-sess", 7)) {
			rc = cgn_policy_cfg_parse_log_sess(item, value, &cfg);

		/* Log subscriber start/end */
		} else if (!strcmp(item, "log-subs")) {
			rc = cgn_policy_cfg_parse_log_subs(item, value, &cfg);

		} else if (!strcmp(item, "map-type")) {
			rc = cgn_policy_cfg_parse_map(value, &cfg);

		} else if (!strcmp(item, "fltr-type")) {
			rc = cgn_policy_cfg_parse_fltr(value, &cfg);

		} else if (!strcmp(item, "trans-type")) {
			rc = cgn_policy_cfg_parse_trans(value, &cfg);

		}

		if (rc < 0)
			goto err_out;
	}

	if (cfg.cp_priority < 1 || cfg.cp_priority > 9999)
		goto err_out;

	if (!cp) {
		cp = cgn_policy_create(&cfg);
		if (!cp)
			goto err_out;

		/* Insert into table */
		rc = cgn_policy_insert(cp);
		if (rc < 0)
			goto err_out;

		/* Inform source database that a new policy has been added */
		cgn_source_policy_added(cp);
	} else {
		/* Update existing policy */

		/* Has pool changed? */
		char *pool_name = nat_pool_name(cp->cp_pool);

		if (cfg.cp_pool_name != pool_name) {
			if (!nat_pool_lookup(cfg.cp_pool_name))
				return -ENOENT;

			cgn_policy_detach_pool(cp);
			cgn_policy_attach_pool(cp, cfg.cp_pool_name);
		}

		/*
		 * Has the match address-group changed?
		 */
		name = npf_addrgrp_handle2name(cp->cp_match_ag);

		npf_addrgrp_update_handle(name, cfg.cp_match_ag_name,
					  &cp->cp_match_ag);

		cp->cp_priority = cfg.cp_priority;

		cp->cp_map_type = cfg.cp_map_type;
		cp->cp_fltr_type = cfg.cp_fltr_type;
		cp->cp_trans_type = cfg.cp_trans_type;
		cp->cp_log_sess_all = cfg.cp_log_sess_all;
		cp->cp_log_sess_start = cfg.cp_log_sess_start;
		cp->cp_log_sess_end = cfg.cp_log_sess_end;
		cp->cp_log_sess_periodic = cfg.cp_log_sess_periodic;
		cp->cp_log_subs = cfg.cp_log_subs;

		/*
		 * Has the session log address-group changed?
		 */
		name = npf_addrgrp_handle2name(cp->cp_log_sess_ag);

		npf_addrgrp_update_handle(name, cfg.cp_log_sess_name,
					  &cp->cp_log_sess_ag);

		if (cp->cp_log_sess_all ||
		    cp->cp_map_type == CGN_MAP_EDM ||
		    cp->cp_fltr_type == CGN_FLTR_EDF)
			cp->cp_sess2_enabled = true;
	}

	return 0;

err_out:
	return -1;
}

/*
 * cgn_policy_cfg_delete
 *
 * cgn policy delete POLICY1
 */
int cgn_policy_cfg_delete(FILE *f __unused, int argc, char **argv)
{
	struct cgn_policy *cp;
	const char *name;

	if (argc < 4)
		return -EINVAL;

	name = argv[3];

	cp = cgn_policy_lookup(name);
	if (!cp)
		return -EEXIST;

	/* Remove from table and release reference. */
	cgn_policy_delete(cp);

	/* The interface list *may* still hold a reference on the policy */

	return 0;
}

/*
 * The interface that this policy is attached to is going away.
 */
void cgn_policy_if_disable(struct ifnet *ifp)
{
	struct cds_list_head *policy_list;
	struct cgn_policy *cp, *tmp;

	/* Get cgnat policy list from interface */
	policy_list = cgn_if_get_policy_list(ifp);
	if (!policy_list)
		return;

	cds_list_for_each_entry_safe(cp, tmp, policy_list, cp_list_node) {
		/* Clear sessions related to this policy */
		cgn_session_expire_policy(true, cp);

		/* Remove policy from cgn interface list */
		cgn_if_del_policy(ifp, cp);

		/* Remove from hash table and release reference. */
		cgn_policy_delete(cp);
	}
}

/*
 * Return the number of CGNAT policies and subscriber addresses using this NAT
 * pool.
 */
static void cgn_np_client_counts(struct nat_pool *np, uint32_t *nusers,
				 uint64_t *naddrs)
{
	struct cds_lfht_iter iter;
	struct cgn_policy *cp;

	if (!cgn_policy_ht)
		return;

	cds_lfht_for_each_entry(cgn_policy_ht, &iter, cp, cp_table_node) {
		if (cp->cp_pool == np) {
			*nusers += 1;
			*naddrs += cgn_policy_naddrs(cp);
		}
	}
}

/* NAT pool client api handlers */
static const struct np_client_ops cgn_np_client_ops = {
	.np_client_counts = cgn_np_client_counts,
};

/*
 * One-time initialization.  Called from cgn_init.
 */
void cgn_policy_init(void)
{
	if (cgn_policy_ht)
		return;

	cgn_policy_ht =	cds_lfht_new(CP_HT_INIT, CP_HT_MIN, CP_HT_MAX,
				     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
				     NULL);

	nat_pool_client_register(&cgn_np_client_ops);
}

/*
 * Called from cgn_uninit.
 */
void cgn_policy_uninit(void)
{
	if (cgn_policy_ht) {
		dp_ht_destroy_deferred(cgn_policy_ht);
		cgn_policy_ht = NULL;

		nat_pool_client_unregister(&cgn_np_client_ops);
	}
}
