/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
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

/*
 * Record destination?  i.e. create nested 2-tuple session.
 */
bool cgn_policy_record_dest(struct cgn_policy *cp, uint32_t addr, int dir)
{
	if (dir != CGN_DIR_OUT)
		return false;

	if (cp->cp_log_sess_all)
		return true;

	if (cp->cp_log_sess_ag)
		return npf_addrgrp_lookup_v4(cp->cp_log_sess_ag, addr) == 0;

	return false;
}

/*
 * Compare two policies.  Returns -1, 0, or 1 is p1 is less than, equal, or
 * greater than p2.
 */
int cgn_policy_cmp(struct cgn_policy *p1, struct cgn_policy *p2)
{
	return strcmp(p1->cp_name, p2->cp_name);
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
	 * This should never happen as entries are only added by master thread
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

/*
 * Attach policy to nat pool
 */
static int
cgn_policy_attach_pool(struct cgn_policy *cp, const char *pool_name)
{
	struct nat_pool *np;
	uint32_t naddrs;

	np = nat_pool_lookup(pool_name);
	if (!np)
		return -ENOENT;

	naddrs = npf_prefix_to_useable_naddrs4(cp->cp_prefix_len);

	/* Take reference on pool */
	cp->cp_pool = nat_pool_get(np);
	nat_pool_incr_nusers(np, naddrs);

	return 0;
}

static void
cgn_policy_detach_pool(struct cgn_policy *cp)
{
	uint32_t naddrs;

	if (!cp->cp_pool)
		return;

	naddrs = npf_prefix_to_useable_naddrs4(cp->cp_prefix_len);
	nat_pool_decr_nusers(cp->cp_pool, naddrs);
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
	 * name source prefix prefix must be configured.
	 */
	if (!cpc->cp_name || cpc->cp_prefix == 0)
		return NULL;

	sz = sizeof(struct cgn_policy);

	struct cgn_policy *cp = zmalloc_aligned(sz);
	if (!cp)
		return NULL;

	cp->cp_name = strdup(cpc->cp_name);

	rte_atomic32_set(&cp->cp_refcnt, 0);

	cp->cp_prefix = cpc->cp_prefix;
	cp->cp_prefix_len = cpc->cp_prefix_len;
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

	if (cpc->cp_log_sess_name) {
		cp->cp_log_sess_ag =
			npf_addrgrp_lookup_name(cpc->cp_log_sess_name);
	}

	if (cp->cp_log_sess_all ||
	    cp->cp_map_type == CGN_MAP_EDM || cp->cp_fltr_type == CGN_FLTR_EDF)
		cp->cp_sess2_enabled = true;

	unsigned long mask;

	mask = (0xFFFFFFFF << (32 - cp->cp_prefix_len)) & 0xFFFFFFFF;
	cp->cp_mask = mask;
	cp->cp_mask = htonl(cp->cp_mask);

	/*
	 * Find cgnat pool.  Takes a reference on the cgnat pool if found.
	 */
	rc = cgn_policy_attach_pool(cp, cpc->cp_pool_name);
	if (rc < 0) {
		free(cp);
		return NULL;
	}

	return cp;
}

static void cgn_policy_rcu_free(struct rcu_head *head)
{
	struct cgn_policy *cp = caa_container_of(head, struct cgn_policy,
						 cp_rcu_head);
	free(cp->cp_name);
	cp->cp_name = NULL;

	free(cp);
}

/*
 * cgn_policy_destroy
 */
static void cgn_policy_destroy(struct cgn_policy *cp)
{
	/*
	 * Only detach from pool when all references on the policy have been
	 * removed.
	 */
	cgn_policy_detach_pool(cp);

	call_rcu(&cp->cp_rcu_head, cgn_policy_rcu_free);
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
		cgn_policy_destroy(cp);
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
			     uint64_t sess_created, uint64_t sess_destroyed)
{
	if (!cp)
		return;

	cp->cp_pkts[CGN_DIR_OUT] += pkts_out;
	cp->cp_bytes[CGN_DIR_OUT] += bytes_out;
	cp->cp_pkts[CGN_DIR_IN] += pkts_in;
	cp->cp_bytes[CGN_DIR_IN] += bytes_in;

	cp->cp_sess_created += sess_created;
	cp->cp_sess_destroyed += sess_destroyed;
}

struct cgn_policy_stats {
	uint64_t	ps_sess_created;
	uint64_t	ps_sess_destroyed;
	uint64_t	ps_pkts[CGN_DIR_SZ];
	uint64_t	ps_bytes[CGN_DIR_SZ];
};

/*
 * Sum the stats for all policies on one interface
 */
static void cgn_policy_jsonw_summary_cb(struct ifnet *ifp, void *arg)
{
	struct cgn_policy_stats *ps = arg;
	struct cgn_policy *cp;
	struct cgn_intf *ci;

	ci = npf_if_get_cgn(ifp);
	if (!ci)
		return;

	cds_list_for_each_entry(cp, &ci->ci_policy_list, cp_list_node) {
		ps->ps_sess_created += cp->cp_sess_created;
		ps->ps_sess_destroyed += cp->cp_sess_destroyed;
		ps->ps_pkts[CGN_DIR_OUT] += cp->cp_pkts[CGN_DIR_OUT];
		ps->ps_bytes[CGN_DIR_OUT] += cp->cp_bytes[CGN_DIR_OUT];
		ps->ps_pkts[CGN_DIR_IN] += cp->cp_pkts[CGN_DIR_IN];
		ps->ps_bytes[CGN_DIR_IN] += cp->cp_bytes[CGN_DIR_IN];
	}
}

/*
 * Sum the stats for all policies on all interfaces
 */
void cgn_policy_jsonw_summary(json_writer_t *json)
{
	struct cgn_policy_stats ps = {0};

	/* For each interface */
	ifnet_walk(cgn_policy_jsonw_summary_cb, &ps);

	jsonw_uint_field(json, "sess_created", ps.ps_sess_created);
	jsonw_uint_field(json, "sess_destroyed", ps.ps_sess_destroyed);
	jsonw_uint_field(json, "pkts_out", ps.ps_pkts[CGN_DIR_OUT]);
	jsonw_uint_field(json, "bytes_out", ps.ps_bytes[CGN_DIR_OUT]);
	jsonw_uint_field(json, "pkts_in", ps.ps_pkts[CGN_DIR_IN]);
	jsonw_uint_field(json, "bytes_in", ps.ps_bytes[CGN_DIR_IN]);
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
	char ad_str[16], pfx_str[24];
	uint32_t naddrs;

	inet_ntop(AF_INET, &cp->cp_prefix,
		  ad_str, sizeof(ad_str));
	snprintf(pfx_str, 24, "%s/%u", ad_str, cp->cp_prefix_len);
	naddrs = npf_prefix_to_useable_naddrs4(cp->cp_prefix_len);

	jsonw_start_object(json);

	jsonw_string_field(json, "name", cp->cp_name);
	jsonw_string_field(json, "prefix", pfx_str);
	if (cp->cp_ci && cp->cp_ci->ci_ifp)
		jsonw_string_field(json, "interface",
				   cp->cp_ci->ci_ifp->if_name);
	else
		jsonw_string_field(json, "interface", "");
	jsonw_uint_field(json, "priority", cp->cp_priority);

	jsonw_uint_field(json, "naddrs", naddrs);
	if (cp->cp_pool)
		jsonw_string_field(json, "pool", nat_pool_name(cp->cp_pool));
	else
		jsonw_string_field(json, "pool", "");

	jsonw_uint_field(json, "refcnt", rte_atomic32_read(&cp->cp_refcnt));

	jsonw_uint_field(json, "source_count",
			 rte_atomic32_read(&cp->cp_source_count));

	jsonw_uint_field(json, "sess_created", cp->cp_sess_created);
	jsonw_uint_field(json, "sess_destroyed", cp->cp_sess_destroyed);

	jsonw_uint_field(json, "out_pkts", cp->cp_pkts[CGN_DIR_OUT]);
	jsonw_uint_field(json, "out_bytes", cp->cp_bytes[CGN_DIR_OUT]);

	jsonw_uint_field(json, "in_pkts", cp->cp_pkts[CGN_DIR_IN]);
	jsonw_uint_field(json, "in_bytes", cp->cp_bytes[CGN_DIR_IN]);

	jsonw_bool_field(json, "record_dest", cp->cp_sess2_enabled);
	jsonw_bool_field(json, "log_sess_all", cp->cp_log_sess_all);

	char *lg_name = npf_addrgrp_handle2name(cp->cp_log_sess_ag);
	if (lg_name)
		jsonw_string_field(json, "log_sess_group", lg_name);

	jsonw_bool_field(json, "log_sess_start", cp->cp_log_sess_start);
	jsonw_bool_field(json, "log_sess_end", cp->cp_log_sess_end);
	jsonw_uint_field(json, "log_sess_periodic", cp->cp_log_sess_periodic);

	jsonw_end_object(json);
}

/*
 * cgn_policy_jsonw_intf
 */
static void cgn_policy_jsonw_intf(struct ifnet *ifp, void *arg)
{
	struct cgn_policy_show_ctx *ctx = arg;
	struct cgn_policy *cp;
	struct cgn_intf *ci;

	ci = npf_if_get_cgn(ifp);
	if (!ci)
		return;

	cds_list_for_each_entry(cp, &ci->ci_policy_list, cp_list_node) {
		cgn_policy_jsonw_one(ctx->json, cp);
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
		/* For each interface */
		ifnet_walk(cgn_policy_jsonw_intf, &ctx);
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

static int
cgn_policy_cfg_parse_src(char *value, struct cgn_policy_cfg *cgn)
{
	npf_netmask_t prefix_len = 0;
	npf_addr_t src_addr;
	sa_family_t fam;
	bool negate;

	int rc = npf_parse_ip_addr(value, &fam, &src_addr,
				   &prefix_len, &negate);
	if (rc)
		return -1;

	if (prefix_len == NPF_NO_NETMASK)
		prefix_len = 32;

	memcpy(&cgn->cp_prefix, &src_addr, 4);
	cgn->cp_prefix_len = prefix_len;

	return 0;
}

static int
cgn_policy_cfg_parse_pool(char *value, struct cgn_policy_cfg *cgn)
{
	cgn->cp_pool_name = value;

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
int cgn_policy_cfg_add(FILE *f, int argc, char **argv)
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
		cfg.cp_name = cp->cp_name;
		cfg.cp_priority = cp->cp_priority;
		cfg.cp_prefix = cp->cp_prefix;
		cfg.cp_prefix_len = cp->cp_prefix_len;
		cfg.cp_pool_name = nat_pool_name(cp->cp_pool);
		cfg.cp_map_type = cp->cp_map_type;
		cfg.cp_fltr_type = cp->cp_fltr_type;
		cfg.cp_trans_type = cp->cp_trans_type;
		cfg.cp_log_sess_all = cp->cp_log_sess_all;
		cfg.cp_log_sess_name = NULL;
		if (cp->cp_log_sess_ag)
			cfg.cp_log_sess_name =
				npf_addrgrp_handle2name(cp->cp_log_sess_ag);
		cfg.cp_log_sess_start = cp->cp_log_sess_start;
		cfg.cp_log_sess_end = cp->cp_log_sess_end;
		cfg.cp_log_sess_periodic = cp->cp_log_sess_periodic;
		cfg.cp_log_subs = cp->cp_log_subs;
	} else {
		cfg.cp_name = name;
		cfg.cp_priority = 0;
		cfg.cp_prefix = 0;
		cfg.cp_prefix_len = 0;
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

		/* Source prefix */
		if (!strcmp(item, "src-addr")) {
			rc = cgn_policy_cfg_parse_src(value, &cfg);

		/* Pool name */
		} else if (!strcmp(item, "pool")) {
			rc = cgn_policy_cfg_parse_pool(value, &cfg);

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
			goto usage;
	}

	if (cfg.cp_priority < 1 || cfg.cp_priority > 9999)
		goto usage;

	if (!cp) {
		cp = cgn_policy_create(&cfg);
		if (!cp)
			goto err_out;

		/* Insert into table */
		rc = cgn_policy_insert(cp);
		if (rc < 0)
			goto err_out;
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
		uint32_t mask;

		mask = (0xFFFFFFFF << (32 - cfg.cp_prefix_len)) & 0xFFFFFFFF;
		mask = htonl(mask);

		cp->cp_priority = cfg.cp_priority;
		cp->cp_prefix = cfg.cp_prefix;
		cp->cp_prefix_len = cfg.cp_prefix_len;
		cp->cp_mask = mask;

		cp->cp_map_type = cfg.cp_map_type;
		cp->cp_fltr_type = cfg.cp_fltr_type;
		cp->cp_trans_type = cfg.cp_trans_type;
		cp->cp_log_sess_all = cfg.cp_log_sess_all;
		cp->cp_log_sess_start = cfg.cp_log_sess_start;
		cp->cp_log_sess_end = cfg.cp_log_sess_end;
		cp->cp_log_sess_periodic = cfg.cp_log_sess_periodic;
		cp->cp_log_subs = cfg.cp_log_subs;

		if (cfg.cp_log_sess_name)
			cp->cp_log_sess_ag =
				npf_addrgrp_lookup_name(cfg.cp_log_sess_name);
		else
			cp->cp_log_sess_ag = NULL;

		if (cp->cp_log_sess_all ||
		    cp->cp_map_type == CGN_MAP_EDM ||
		    cp->cp_fltr_type == CGN_FLTR_EDF)
			cp->cp_sess2_enabled = true;
	}

	return 0;

usage:
	if (f)
		fprintf(f, "%s: policy add <name> pri=<pri> "
			"src-addr=<prefix/mask> pool=<name>", __func__);
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
void cgn_policy_if_index_unset(struct ifnet *ifp, struct cgn_policy *cp)
{
	/* Clear sessions related to this policy */
	cgn_session_expire_policy(true, cp);

	/* Remove policy from cgn interface list */
	cgn_if_del_policy(ifp, cp);

	/* Remove from table and release reference. */
	cgn_policy_delete(cp);
}

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
}

/*
 * Called from cgn_uninit.
 */
void cgn_policy_uninit(void)
{
	if (cgn_policy_ht) {
		dp_ht_destroy_deferred(cgn_policy_ht);
		cgn_policy_ht = NULL;
	}
}
