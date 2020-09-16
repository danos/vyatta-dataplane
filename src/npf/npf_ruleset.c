/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 2009-2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NPF ruleset module.
 */

#include <assert.h>
#include <czmq.h>
#include <errno.h>
#include <netinet/in.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "if_var.h"
#include "json_writer.h"
#include "npf/npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_config.h"
#include "npf/grouper2.h"
#include "npf/npf_disassemble.h"
#include "npf/npf_nat.h"
#include "npf/npf_ncode.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "npf_match.h"
#include "../ether.h"

struct npf_attpt_item;

#define NPF_RULE_HASH_MIN       1024      /* smallest hash table size */
#define NPF_RULE_HASH_MAX       32768     /* largest hash table size
					   * Pick a suitably large value to
					   * allow for large IPsec rulesets
					   */

#define SHOW_BUF_LEN		8192

/* For GC of rulesets */
static CDS_LIST_HEAD(ruleset_reap);
static struct rte_timer ruleset_gc_timer;
#define RULESET_GC_INTERVAL	30

struct npf_ruleset {
	struct cds_list_head	rs_reap;
	struct cds_list_head	rs_groups;
	enum npf_attach_type	rs_attach_type;
	const char		*rs_attach_point;
	enum npf_ruleset_type	rs_type;
	bool			rs_is_stateful;
	bool			rs_is_dead;
};

/* Rproc definitions */
struct npf_rproc {
	const char *config_arg;		/* arguments configured with */
	const npf_rproc_ops_t *ops;	/* functions */
	void *handle;			/* handle to pass to fns */
};

/*
 * This holds information for a group of NPF rules.
 */
struct npf_rule_group {
	/*
	 * Entries used when running on a packet are kept at the
	 * start, for cache coherency.
	 */
	struct cds_list_head rg_entry;	/* used in chaining rule groups */

	uint8_t rg_dir;			/* direction - IN, OUT, or both */

	npf_match_ctx_t *match_ctx_v4;
	npf_match_ctx_t *match_ctx_v6;

	struct cds_list_head rg_rules;	/* rules in this group */
	struct cds_lfht *rg_rules_ht;	/* hash tbl for rules in this group */


	/*
	 * The following are not used per-packet,
	 * or used infrequently - e.g. for logging.
	 */
	enum npf_rule_class rg_class;	/* class of this rule group */
	char *rg_name;			/* name of this rule group */

	npf_ruleset_t *rg_ruleset;	/* ruleset this group is in */
};

/* Struct containing rule generation and state data.  */
struct npf_rule_state {
	uint32_t			rs_hash;
	npf_rule_group_t		*rs_rule_group;
	char				*rs_config_line;
	zhashx_t			*rs_config_ht;	/* var=value hash */
	struct npf_rproc		*rs_rproc;	/* configured rprocs */
	uint8_t				rs_rproc_count;	/* active rprocs */
	struct npf_rule_grouper_info	rs_grouper_info;/* Grouper datum */
	rule_no_t			rs_rule_no;
};

/* npf_rule definition - read-only data.  */
struct npf_rule {
	struct cds_list_head		r_entry;
	struct cds_lfht_node		r_entry_ht;
	void				*r_ncode;	/* pointer to ncode */
	npf_natpolicy_t			*r_natp;	/* nat policy */
	struct npf_rule_stats		*r_stats;	/* rule stats */
	struct npf_rule_state		*r_state;	/* generation state */
	uint32_t			r_nc_size;	/* ncode size */
	rte_atomic32_t			r_refcnt;	/* Reference counter */
	uint8_t				r_pass:1;	/* rule bits */
	uint8_t				r_stateful:1;
	uint8_t				r_rproc_action:1;
	uint8_t				r_rproc_logger:1;
	uint8_t				r_rproc_match:1;
	uint8_t				r_rproc_handle:1;
};

npf_ruleset_t *
npf_ruleset_create(enum npf_ruleset_type ruleset_type,
		   enum npf_attach_type attach_type, const char *attach_point)
{
	npf_ruleset_t *ruleset;

	ruleset = calloc(1, sizeof(npf_ruleset_t));
	if (ruleset) {
		CDS_INIT_LIST_HEAD(&ruleset->rs_groups);
		CDS_INIT_LIST_HEAD(&ruleset->rs_reap);
		ruleset->rs_type = ruleset_type;
		ruleset->rs_attach_type = attach_type;
		ruleset->rs_attach_point = strdup(attach_point);

		if (!ruleset->rs_attach_point) {
			free(ruleset);
			return NULL;
		}
	}
	return ruleset;
}

static struct npf_rule_stats *
npf_rule_stats_get(struct npf_rule_stats *rl_stats)
{
	rte_atomic64_inc(&(rl_stats[0].refcnt));
	return rl_stats;
}

static void npf_rule_stats_put(struct npf_rule_stats *rl_stats)
{
	if (rte_atomic64_dec_and_test(&(rl_stats[0].refcnt)))
		free(rl_stats);
}

static struct npf_rule_stats *npf_rule_stats_alloc(void)
{
	/* Allocate stats with highest lcore id as an array indice */
	struct npf_rule_stats *rl_stats = zmalloc_aligned(
		sizeof(struct npf_rule_stats) * (get_lcore_max() + 1));

	if (!rl_stats)
		return NULL;

	return npf_rule_stats_get(rl_stats);
}

/* Allocate a rule and its subsystems */
static npf_rule_t *npf_alloc_rule(uint32_t ruleset_type_flags)
{
	npf_rule_t *rl;

	rl = zmalloc_aligned(sizeof(struct npf_rule));
	if (!rl)
		return NULL;

	CDS_INIT_LIST_HEAD(&rl->r_entry);
	cds_lfht_node_init(&rl->r_entry_ht);

	rte_atomic32_set(&rl->r_refcnt, 1);

	if (!(ruleset_type_flags & NPF_RS_FLAG_NO_STATS)) {
		rl->r_stats = npf_rule_stats_alloc();
		if (!rl->r_stats)
			goto bad_stats;
	}

	rl->r_state = zmalloc_aligned(sizeof(struct npf_rule_state));
	if (!rl->r_state)
		goto bad_state;

	rl->r_state->rs_rproc = zmalloc_aligned(
			sizeof(struct npf_rproc) * npf_rproc_max_rprocs());
	if (!rl->r_state->rs_rproc)
		goto bad_rproc;

	return rl;

bad_rproc:
	free(rl->r_state);
bad_state:
	if (rl->r_stats)
		npf_rule_stats_put(rl->r_stats);
bad_stats:
	free(rl);
	return NULL;
}

static void rule_free(npf_rule_t *rl)
{
	unsigned int i;

	/* Call the rproc destructors and free the config arg */
	for (i = 0; i < rl->r_state->rs_rproc_count; i++) {
		npf_destroy_rproc(rl->r_state->rs_rproc[i].ops,
				rl->r_state->rs_rproc[i].handle);
		free((char *)rl->r_state->rs_rproc[i].config_arg);
	}

	if (rl->r_natp)
		npf_nat_policy_put(rl->r_natp);

	zhashx_destroy(&rl->r_state->rs_config_ht);
	free(rl->r_state->rs_config_line);
	free(rl->r_state->rs_rproc);
	free(rl->r_state);
	if (rl->r_stats)
		npf_rule_stats_put(rl->r_stats);
	free(rl->r_ncode);
	free(rl);
}

npf_rule_t *npf_rule_get(npf_rule_t *rl)
{
	if (rl)
		rte_atomic32_inc(&rl->r_refcnt);
	return rl;
}

void npf_rule_put(npf_rule_t *rl)
{
	if (rl && rte_atomic32_dec_and_test(&rl->r_refcnt))
		rule_free(rl);
}

static void
npf_free_rules(npf_rule_group_t *rg)
{
	npf_rule_t *rl, *tmp_rl;
	struct cds_lfht_iter iter;

	if (rg->rg_rules_ht) {
		cds_lfht_for_each_entry(rg->rg_rules_ht, &iter, rl, r_entry_ht)
			cds_lfht_del(rg->rg_rules_ht, &rl->r_entry_ht);
		cds_lfht_destroy(rg->rg_rules_ht, NULL);
	}

	cds_list_for_each_entry_safe(rl, tmp_rl, &rg->rg_rules, r_entry) {
		/* Completely dissociate rule */
		rl->r_state->rs_rule_group = NULL;
		cds_list_del(&rl->r_entry);
		npf_rule_put(rl);
	}
}

void
npf_free_group(npf_rule_group_t *rg)
{
	/* Free the rules in this group */
	npf_free_rules(rg);

	/* Remove from the list of groups */
	cds_list_del_rcu(&rg->rg_entry);

	/* Release groupers */
	npf_match_destroy(rg->rg_ruleset->rs_type, AF_INET, &rg->match_ctx_v4);
	npf_match_destroy(rg->rg_ruleset->rs_type, AF_INET6, &rg->match_ctx_v6);

	free(rg->rg_name);
	free(rg);
}

static void
npf_free_groups(struct cds_list_head *groups)
{
	npf_rule_group_t *rg, *tmp_rg;

	cds_list_for_each_entry_safe(rg, tmp_rg, groups, rg_entry)
		npf_free_group(rg);
}

static void ruleset_free(npf_ruleset_t *rs)
{
	npf_free_groups(&rs->rs_groups);
	free((char *) rs->rs_attach_point);
	free(rs);
}

void
npf_ruleset_free(npf_ruleset_t *rs)
{
	if (rs)
		cds_list_add(&rs->rs_reap, &ruleset_reap);
}

/* GC for rulesets. Ensures no access at time of free. */
static void ruleset_gc(struct rte_timer *t __rte_unused, void *arg __unused)
{
	npf_ruleset_t *rs, *tmp_rs;

	cds_list_for_each_entry_safe(rs, tmp_rs, &ruleset_reap, rs_reap) {
		if (rs->rs_is_dead) {
			cds_list_del(&rs->rs_reap);
			ruleset_free(rs);
		} else
			rs->rs_is_dead = true;
	}
}

/*
 * Used by unit-tests
 */
int npf_flush_rulesets(void)
{
	ruleset_gc(NULL, NULL);
	ruleset_gc(NULL, NULL);
	return 0;
}

/* periodic timer for freeing stale rulesets.  */
void npf_ruleset_gc_init(void)
{
	rte_timer_init(&ruleset_gc_timer);
	rte_timer_reset(&ruleset_gc_timer,
			(RULESET_GC_INTERVAL * rte_get_timer_hz()),
			PERIODICAL, rte_get_master_lcore(), ruleset_gc, NULL);
}

/*
 * Get a rproc handle from a rule for logger
 */
void *
npf_rule_rproc_handle_for_logger(npf_rule_t *rl)
{
	if (!rl)
		return NULL;

	unsigned int i;
	unsigned int max = npf_rproc_max_rprocs();

	for (i = 0; i < max; i++) {
		const npf_rproc_ops_t *ops = rl->r_state->rs_rproc[i].ops;

		/* End of list? */
		if (!ops)
			break;

		if (ops->ro_logger)
			return rl->r_state->rs_rproc[i].handle;
	}
	return NULL;
}

/*
 * Get a rproc handle from a rule and rproc ID
 */
void *
npf_rule_rproc_handle_from_id(npf_rule_t *rl, enum npf_rproc_id id)
{
	if (!rl)
		return NULL;

	unsigned int i;
	unsigned int max = npf_rproc_max_rprocs();

	for (i = 0; i < max; i++) {
		const npf_rproc_ops_t *ops = rl->r_state->rs_rproc[i].ops;

		/* End of list? */
		if (!ops)
			break;

		if (ops->ro_id == id)
			return rl->r_state->rs_rproc[i].handle;
	}
	return NULL;
}

/*
 * Get a rproc tag from a rule.
 *
 * The tag is a special case in that the handle is the tag, so just cast
 * appropriately and return.
 */
uint32_t npf_rule_rproc_tag(npf_rule_t *rl, bool *tag_set)
{
	if (!rl)
		return 0;

	unsigned int i;
	unsigned int max = npf_rproc_max_rprocs();

	for (i = 0; i < max; i++) {
		const npf_rproc_ops_t *ops = rl->r_state->rs_rproc[i].ops;

		/* End of list? */
		if (!ops)
			break;

		if (ops->ro_id == NPF_RPROC_ID_TAG) {
			void *handle;

			if (tag_set)
				*tag_set = true;
			handle = rl->r_state->rs_rproc[i].handle;
			return (uint32_t)(uintptr_t)handle;
		}
	}
	return 0;
}

/*
 * Give any rprocs a chance to clear any statistics that they have gathered.
 */
static void rproc_clear_stats(npf_rule_t *rl)
{
	unsigned int i;
	unsigned int max = npf_rproc_max_rprocs();

	for (i = 0; i < max; i++) {
		const npf_rproc_ops_t *ops = rl->r_state->rs_rproc[i].ops;

		if (!ops)
			break;

		if (ops->ro_clear_stats)
			ops->ro_clear_stats(rl->r_state->rs_rproc[i].handle);
	}
}

static void rule_clear_stats(npf_rule_t *rl)
{
	unsigned int i;

	if (!rl->r_stats)
		return;

	FOREACH_DP_LCORE(i) {
		rl->r_stats[i].pkts_ct = 0;
		rl->r_stats[i].bytes_ct = 0;
	}

	rproc_clear_stats(rl);
}

void rule_sum_stats(const npf_rule_t *rl,
		    struct npf_rule_stats *rs)
{
	unsigned int i, nprot;

	memset(rs, '\0', sizeof(struct npf_rule_stats));

	if (!rl->r_stats)
		return;

	FOREACH_DP_LCORE(i) {
		rs->bytes_ct += rl->r_stats[i].bytes_ct;
		rs->pkts_ct += rl->r_stats[i].pkts_ct;
		for (nprot = NAT_PROTO_FIRST; nprot < NAT_PROTO_COUNT;
		     nprot++) {
			rs->map_ports[nprot] += rl->r_stats[i].map_ports[nprot];
		}
	}
}


void npf_rule_get_overall_used(npf_rule_t *rl, uint64_t used[],
		uint64_t *overall)
{
	struct npf_rule_stats rs;
	int nprot;

	*overall = npf_natpolicy_get_map_range(rl->r_natp);

	rule_sum_stats(rl, &rs);

	for (nprot = NAT_PROTO_FIRST; nprot < NAT_PROTO_COUNT; nprot++) {
		/*
		 * Note for DNAT ports are not taken from a pool,
		 * so 'used' is not limited by the total.
		 */
		used[nprot] = rs.map_ports[nprot];
	}
}

void npf_rule_update_map_stats(npf_rule_t *rl, int nr_maps, uint32_t map_flags,
			       uint8_t ip_prot)
{
	unsigned int id = dp_lcore_id();
	int ports = (map_flags & NPF_NAT_MAP_PORT) ? nr_maps : 0;
	enum nat_proto nprot = nat_proto_from_ipproto(ip_prot);

	if (rl && rl->r_stats)
		rl->r_stats[id].map_ports[nprot] += ports;
}

static void rule_ref_stats(npf_rule_t *old, npf_rule_t *new)
{
	/*
	 * Release the statistics block allocated initially for the new
	 * rule, and instead reference the statistics associated with the
	 * old rule.
	 */
	if (new->r_stats)
		npf_rule_stats_put(new->r_stats);

	if (old->r_stats)
		new->r_stats = npf_rule_stats_get(old->r_stats);
}

/*
 * Are two sets of bytecode identical?
 */
static bool
npf_ncode_equal(void *nc1, size_t nc1_size, void *nc2, size_t nc2_size)
{
	if (!nc1 && !nc2)
		return true;
	if (!nc1 || !nc2 || nc1_size != nc2_size)
		return false;
	return memcmp(nc1, nc2, nc1_size) == 0;
}

/*
 * Reference stats of the old rule by the new rule if the rule is materially
 * unchanged, i.e. if the ncode and action are unchanged.
 */
static void
npf_ref_stats_if_rule_unchanged(npf_rule_t *rl_old, npf_rule_t *rl_new)
{
	/* Is bytecode different? */
	if (!npf_ncode_equal(rl_old->r_ncode, rl_old->r_nc_size,
			    rl_new->r_ncode, rl_new->r_nc_size))
		return;

	/* Has action changed? */
	if (rl_old->r_pass != rl_new->r_pass)
		return;

	/* Rules are deemed unchanged, so reference the stats */
	rule_ref_stats(rl_old, rl_new);
}

static int npf_rg_rule_match(struct cds_lfht_node *node, const void *key)
{
	const uint32_t *rule_no = key;
	npf_rule_t *rl = caa_container_of(node, npf_rule_t, r_entry_ht);

	if (rl->r_state->rs_rule_no == *rule_no)
		return 1;

	return 0;
}

static npf_rule_t *
npf_find_rule(npf_rule_group_t *rg, npf_rule_t *match)
{
	npf_rule_t *rl;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (rg->rg_rules_ht) {
		cds_lfht_lookup(rg->rg_rules_ht, match->r_state->rs_rule_no,
				npf_rg_rule_match, &match->r_state->rs_rule_no,
				&iter);
		node = cds_lfht_iter_get_node(&iter);
		return node ? caa_container_of(node, npf_rule_t, r_entry_ht) :
			NULL;
	}

	cds_list_for_each_entry(rl, &rg->rg_rules, r_entry) {
		if (match->r_state->rs_rule_no == rl->r_state->rs_rule_no)
			return rl;
		else if (match->r_state->rs_rule_no < rl->r_state->rs_rule_no)
			return NULL;
	}
	return NULL;
}

static void
npf_ref_stats_group(npf_rule_group_t *rg_old, npf_rule_group_t *rg_new)
{
	npf_rule_t *rl_old, *rl_new;

	cds_list_for_each_entry(rl_new, &rg_new->rg_rules, r_entry) {
		rl_old = npf_find_rule(rg_old, rl_new);

		if (rl_old)
			npf_ref_stats_if_rule_unchanged(rl_old, rl_new);
	}
}

static npf_rule_group_t *
npf_find_rule_group(struct cds_list_head *from_groups, npf_rule_group_t *match)
{
	npf_rule_group_t *rg;

	cds_list_for_each_entry(rg, from_groups, rg_entry) {
		if ((match->rg_dir == rg->rg_dir) &&
		    (match->rg_class == rg->rg_class) &&
		    (strcmp(match->rg_name, rg->rg_name) == 0))
			return rg;
	}
	return NULL;
}

/*
 * References the byte/packet/map_ports statistics on rule
 * change. A rule is considered changed if the rule number changes
 * and/or the byte code changes. This leaves the following
 * behavior as a further enhancement:
 *
 * When a rule has a non-filter change, i.e. log the statistics
 * are still cleared.
 *
 * Finally, this is a list walk from the beginning--expensive on
 * large sets. Marking last match would improve performance, but
 * this is tricky in getting right when there's a number of rule
 * changes. Or moderately tricky--should be done once this technique
 * has been validated.
 */
void
npf_ref_stats(npf_ruleset_t *old, npf_ruleset_t *new)
{
	npf_rule_group_t *rg_old, *rg_new;
	uint32_t rs_type_flags;

	rs_type_flags = npf_get_ruleset_type_flags(old->rs_type);
	if (rs_type_flags & NPF_RS_FLAG_NO_STATS)
		return;

	cds_list_for_each_entry(rg_new, &new->rs_groups, rg_entry) {
		rg_old = npf_find_rule_group(&old->rs_groups, rg_new);

		if (rg_old)
			npf_ref_stats_group(rg_old, rg_new);
	}
}

void
npf_clear_stats(const npf_ruleset_t *ruleset, enum npf_rule_class group_class,
		const char *group_name, rule_no_t rule_no)
{
	npf_rule_group_t *rg;
	npf_rule_t *rl;

	uint32_t rs_type_flags;

	rs_type_flags = npf_get_ruleset_type_flags(ruleset->rs_type);
	if (rs_type_flags & NPF_RS_FLAG_NO_STATS)
		return;

	cds_list_for_each_entry(rg, &ruleset->rs_groups, rg_entry) {
		if (group_class == NPF_RULE_CLASS_COUNT ||
		    (group_class == rg->rg_class &&
		    (strcmp(group_name, rg->rg_name) == 0))) {

			cds_list_for_each_entry(rl, &rg->rg_rules, r_entry) {
				if (rule_no == 0 ||
				    rule_no == rl->r_state->rs_rule_no)
					rule_clear_stats(rl);
			}
		}
	}
}

void
npf_add_pkt(npf_rule_t *rl, uint64_t bytes)
{
	if (rl == NULL || rl->r_stats == NULL)
		return;

	unsigned int core = dp_lcore_id();

	rl->r_stats[core].pkts_ct++;
	rl->r_stats[core].bytes_ct += bytes;
}

const void *
npf_get_ncode(const npf_rule_t *rl)
{
	return rl->r_ncode;
}

rule_no_t
npf_rule_get_num(npf_rule_t *rl)
{
	return rl->r_state->rs_rule_no;
}

void
npf_rule_set_pass(npf_rule_t *rl, bool value)
{
	rl->r_pass = value;
}

int
npf_rule_get_attach_point(const npf_rule_t *rl,
			  enum npf_attach_type *attach_type,
			  const char **attach_point)
{
	npf_ruleset_t *ruleset = npf_ruleset(rl);

	if (!ruleset)
		return -ENOENT;

	*attach_type = ruleset->rs_attach_type;
	*attach_point = ruleset->rs_attach_point;

	return 0;
}

bool
npf_rule_get_pass(npf_rule_t *rl)
{
	return rl->r_pass ? true : false;
}

uint32_t
npf_rule_get_hash(npf_rule_t *rl)
{
	return rl->r_state->rs_hash;
}

const char *
npf_rule_get_name(npf_rule_t *rl)
{
	if (rl && rl->r_state->rs_rule_group)
		return rl->r_state->rs_rule_group->rg_name;
	return NULL;
}

/*
 * 0, PFIL_IN, PFIL_OUT or (PFIL_IN | PFIL_OUT)
 */
int
npf_rule_get_dir(const npf_rule_t *rl)
{
	if (rl && rl->r_state->rs_rule_group)
		return rl->r_state->rs_rule_group->rg_dir;
	return 0;
}

/*
 * Get interface pointer from rule attach point
 */
struct ifnet *
npf_rule_get_ifp(const npf_rule_t *rl)
{
	/*
	 * Lookup the rule attach point to get the interface name.
	 */
	enum npf_attach_type attach_type;
	const char *attach_point;

	if (npf_rule_get_attach_point(rl, &attach_type,
				      &attach_point) < 0 ||
	    attach_type != NPF_ATTACH_TYPE_INTERFACE)
		return NULL;

	return dp_ifnet_byifname(attach_point);
}

static npf_rule_t *
npf_get_rule_by_hash_ruleset(const npf_ruleset_t *ruleset, uint32_t hash)
{
	npf_rule_group_t *rg;
	npf_rule_t *rl;

	cds_list_for_each_entry_rcu(rg, &ruleset->rs_groups, rg_entry) {
		cds_list_for_each_entry_rcu(rl, &rg->rg_rules, r_entry) {
			if (rl->r_state->rs_hash == hash)
				return rl;
		}
	}

	return NULL;
}

static npf_rule_t *
npf_get_rule_by_hash_config(struct npf_config *npf_conf, uint32_t hash)
{
	enum npf_ruleset_type ruleset_type;
	const npf_ruleset_t *ruleset;
	npf_rule_t *rl;

	for (ruleset_type = 0; ruleset_type < NPF_RS_TYPE_COUNT;
	     ruleset_type++) {
		ruleset = npf_get_ruleset(npf_conf, ruleset_type);
		if (ruleset && ((npf_get_ruleset_type_flags(ruleset_type) &
		    NPF_RS_FLAG_NOTRACK) == 0)) {
			rl = npf_get_rule_by_hash_ruleset(ruleset, hash);
			if (rl)
				return rl;
		}
	}

	return NULL;
}

struct npf_get_rule_by_hash_info {
	uint32_t hash;
	npf_rule_t *rl;
};

static npf_attpt_walk_items_cb npf_get_rule_by_hash_cb;
static bool
npf_get_rule_by_hash_cb(struct npf_attpt_item *ap, void *ctx)
{
	struct npf_get_rule_by_hash_info *info = ctx;

	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	if (!npf_conf_p)
		return true;

	struct npf_config *npf_conf = *npf_conf_p;
	if (!npf_conf)
		return true;

	info->rl = npf_get_rule_by_hash_config(npf_conf, info->hash);
	if (info->rl)
		return false; /* cause walker to stop */
	else
		return true;
}

npf_rule_t *
npf_get_rule_by_hash(uint32_t hash)
{
	struct npf_get_rule_by_hash_info info = {
		.hash = hash,
		.rl = NULL
	};

	/* We only have NAT on interfaces */
	npf_attpt_item_walk_type(NPF_ATTACH_TYPE_INTERFACE,
				 npf_get_rule_by_hash_cb, &info);

	return info.rl;
}

static void
npf_get_rule_rprocs_string(npf_rule_t *rl, char *buf, size_t *used_buf_len,
			   const size_t total_buf_len, bool match,
			   const char *prefix)
{
	unsigned int i;
	bool first = true;
	unsigned int max = npf_rproc_max_rprocs();

	for (i = 0; i < max; i++) {
		const npf_rproc_ops_t *ops = rl->r_state->rs_rproc[i].ops;
		const char *config_args;

		if (!ops)
			break;

		if ((ops->ro_match != NULL) != match)
			continue;

		if (first) {
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%s %s", prefix, ops->ro_name);
			first = false;
		} else
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       ", %s", ops->ro_name);

		config_args = rl->r_state->rs_rproc[i].config_arg;
		if (config_args)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "(%s)", config_args);
	}
}

/*
 * Invoke any json callbacks.
 */
static void
npf_json_rule_rprocs(json_writer_t *json, npf_rule_t *rl)
{
	unsigned int i;
	unsigned int max = npf_rproc_max_rprocs();
	bool first = true;

	for (i = 0; i < max; i++) {
		const npf_rproc_ops_t *ops = rl->r_state->rs_rproc[i].ops;

		if (!ops)
			break;

		if (ops->ro_json) {
			if (first) {
				jsonw_name(json, "rprocs");
				jsonw_start_object(json);
				first = false;
			}

			/* Each rproc goes in its own object. */
			jsonw_name(json, ops->ro_name);
			jsonw_start_object(json);
			ops->ro_json(json, rl,
				     rl->r_state->rs_rproc[i].config_arg,
				     rl->r_state->rs_rproc[i].handle);
			jsonw_end_object(json);
		}
	}

	if (!first) {
		jsonw_end_object(json);
	}
}

static void
npf_json_grouper_info(struct npf_rule_grouper_info *info, json_writer_t *json)
{
	char buf[256];
	size_t used_buf_len;
	int i;

	if (info->g_family != AF_INET6) {
		buf[0] = '\0';
		used_buf_len = 0;
		for (i = 0; i < NPC_GPR_SIZE_v4; i++)
			buf_app_printf(buf, &used_buf_len, sizeof(buf),
				       "%02X ", info->g_v4_match[i]);
		buf[used_buf_len - 1] = '\0'; /* remove last space */
		jsonw_string_field(json, "grouper-v4-match", buf);

		buf[0] = '\0';
		used_buf_len = 0;
		for (i = 0; i < NPC_GPR_SIZE_v4; i++)
			buf_app_printf(buf, &used_buf_len, sizeof(buf),
				       "%02X ", info->g_v4_mask[i]);
		buf[used_buf_len - 1] = '\0'; /* remove last space */
		jsonw_string_field(json, "grouper-v4-mask", buf);
	}

	if (info->g_family != AF_INET) {
		buf[0] = '\0';
		used_buf_len = 0;
		for (i = 0; i < NPC_GPR_SIZE_v6; i++)
			buf_app_printf(buf, &used_buf_len, sizeof(buf),
				       "%02X ", info->g_v6_match[i]);
		buf[used_buf_len - 1] = '\0'; /* remove last space */
		jsonw_string_field(json, "grouper-v6-match", buf);

		buf[0] = '\0';
		used_buf_len = 0;
		for (i = 0; i < NPC_GPR_SIZE_v6; i++)
			buf_app_printf(buf, &used_buf_len, sizeof(buf),
				       "%02X ", info->g_v6_mask[i]);
		buf[used_buf_len - 1] = '\0'; /* remove last space */
		jsonw_string_field(json, "grouper-v6-mask", buf);
	}
}

static void
npf_json_rule(npf_rule_t *rl, bool is_nat, json_writer_t *json)
{
	char buf[SHOW_BUF_LEN];
	size_t used_buf_len = 0;
	const char *action;
	struct npf_rule_stats rs;

	snprintf(buf, sizeof(buf), "%u", rl->r_state->rs_rule_no);
	jsonw_name(json, buf);
	jsonw_start_object(json);

	if (rl->r_pass)
		action = "pass ";
	else
		action = "block ";
	jsonw_string_field(json, "action", action);

	jsonw_string_field(json, "config", rl->r_state->rs_config_line);

	/*
	 * build up the contents for "match"
	 */
	buf[0] = '\0';
	used_buf_len = 0;
	if (rl->r_stateful)
		buf_app_printf(buf, &used_buf_len, sizeof(buf), "stateful ");

	npf_get_rule_match_string(rl->r_state->rs_config_ht, buf, &used_buf_len,
				  sizeof(buf));

	npf_get_rule_rprocs_string(rl, buf, &used_buf_len, sizeof(buf), true,
				   "match");

	/*
	 * If overrunning the buffer, then indicate this.
	 */
	if (strlen(buf) == sizeof(buf) - 1)
		strcpy(buf + sizeof(buf) - 4, "...");
	jsonw_string_field(json, "match", buf);

	buf[0] = '\0';
	used_buf_len = 0;
	npf_get_rule_rprocs_string(rl, buf, &used_buf_len, sizeof(buf), false,
				   "apply");
	if (strlen(buf) == sizeof(buf) - 1)
		strcpy(buf + sizeof(buf) - 4, "...");
	jsonw_string_field(json, "operation", buf);

	/* Invoke any json callbacks. */
	npf_json_rule_rprocs(json, rl);

	/*
	 * For ACL we'll want a different form of stats, using an rproc.
	 * So for the moment, hide the existing set.
	 * We'll do something better in future.
	 */
	if (rl->r_state->rs_rule_group->rg_class != NPF_RULE_CLASS_ACL) {
		/* Send all stats to the CLI */
		rule_sum_stats(rl, &rs);
		jsonw_uint_field(json, "bytes", rs.bytes_ct);
		jsonw_uint_field(json, "packets", rs.pkts_ct);
	}

	if (rl->r_natp) {
		uint64_t total;
		uint64_t used[NAT_PROTO_COUNT];
		enum nat_proto nprot;

		npf_rule_get_overall_used(rl, used, &total);

		jsonw_uint_field(json, "total_ts", total);

		jsonw_name(json, "protocols");
		jsonw_start_array(json);

		for (nprot = NAT_PROTO_FIRST; nprot < NAT_PROTO_COUNT;
		     nprot++) {
			jsonw_start_object(json);
			jsonw_string_field(json, "protocol",
					   nat_proto_lc_str(nprot));
			jsonw_uint_field(json, "used_ts", used[nprot]);
			jsonw_end_object(json);
		}
		jsonw_end_array(json); /* protocols */

		buf[0] = '\0';
		used_buf_len = 0;
		npf_nat_get_map_string(rl->r_state->rs_config_ht, buf,
				&used_buf_len, sizeof(buf));
		jsonw_string_field(json, "map", buf);
	} else if (is_nat) {
		jsonw_string_field(json, "map", "exclude");
	}

	if (DP_DEBUG_ENABLED(NPF)) {
		npf_json_ncode(rl->r_ncode, rl->r_nc_size, json);
		npf_json_grouper_info(&rl->r_state->rs_grouper_info, json);
	}

	jsonw_end_object(json);
}

static void
npf_json_ruleset_group_info(npf_rule_group_t *rg, json_writer_t *json)
{
	const char *rg_name = rg->rg_name;

	if (!rg_name)
		jsonw_string_field(json, "name", "");
	else {
		const char *class_name = npf_get_rule_class_name(rg->rg_class);

		if (class_name)
			jsonw_string_field(json, "class", class_name);
		jsonw_string_field(json, "name", rg_name);
	}

	if (rg->rg_dir == PFIL_ALL)
		jsonw_string_field(json, "direction", "on");
	else
		jsonw_string_field(json, "direction",
				   (rg->rg_dir & PFIL_IN) ? "in" : "out");
}

/*
 * Give JSON for the rule group and the rules in the group
 */
static void
npf_json_ruleset_group(npf_rule_group_t *rg, json_writer_t *json)
{
	npf_rule_t *rl;

	jsonw_start_object(json);
	npf_json_ruleset_group_info(rg, json);

	jsonw_name(json, "rules");
	jsonw_start_object(json);

	bool is_nat = (rg->rg_class == NPF_RULE_CLASS_DNAT) ||
		      (rg->rg_class == NPF_RULE_CLASS_SNAT);
	cds_list_for_each_entry(rl, &rg->rg_rules, r_entry) {
		npf_json_rule(rl, is_nat, json);
	}

	jsonw_end_object(json);
	jsonw_end_object(json);
}

/*
 * Give JSON for all the groups of rules in a ruleset.
 */
int
npf_json_ruleset(const npf_ruleset_t *ruleset, json_writer_t *json)
{
	npf_rule_group_t *rg;

	jsonw_name(json, "groups");
	jsonw_start_array(json);

	cds_list_for_each_entry(rg, &ruleset->rs_groups, rg_entry) {
		npf_json_ruleset_group(rg, json);
	}

	jsonw_end_array(json);
	return 0;
}

npf_rule_group_t *
npf_rule_group_create(npf_ruleset_t *ruleset, enum npf_rule_class group_class,
		      const char *group, uint8_t dir)
{
	uint32_t rs_type_flags;
	npf_rule_group_t *rg = calloc(1, sizeof(npf_rule_group_t));

	if (!rg)
		return NULL;

	CDS_INIT_LIST_HEAD(&rg->rg_entry);
	CDS_INIT_LIST_HEAD(&rg->rg_rules);

	rs_type_flags = npf_get_ruleset_type_flags(ruleset->rs_type);
	if (rs_type_flags & NPF_RS_FLAG_HASH_TBL) {
		rg->rg_rules_ht = cds_lfht_new(NPF_RULE_HASH_MIN,
					       NPF_RULE_HASH_MIN,
					       NPF_RULE_HASH_MAX,
					       CDS_LFHT_AUTO_RESIZE,
					       NULL);
		if (!rg->rg_rules_ht) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Could not allocate hash table for rules\n");
			goto err;
		}
	}
	rg->rg_ruleset = ruleset;
	rg->rg_dir = dir;

	rg->rg_class = group_class;
	if (group) {
		rg->rg_name = strdup(group);
		if (!rg->rg_name)
			goto err;
	}

	/* Add group to ruleset, after the groups that are there. */
	cds_list_add_tail_rcu(&rg->rg_entry, &ruleset->rs_groups);

	return rg;

err:
	if (rg->rg_rules_ht)
		cds_lfht_destroy(rg->rg_rules_ht, NULL);
	free(rg);
	return NULL;
}

static uint32_t
npf_rule_hash(npf_rule_t *rl)
{
	npf_rule_group_t *rg = rl->r_state->rs_rule_group;
	uint32_t hash = 0;
	const char *rg_name = rg->rg_name;

	if (rg_name) {
		/*
		 * The jhash reads in 4 byte words, so make sure
		 * that it doesn't read off the end of allocated mem.
		 */
		char __rg_name[RTE_ALIGN(strlen(rg_name), 4)]
			__rte_aligned(sizeof(uint32_t));

		memcpy(__rg_name, rg_name, strlen(rg_name));
		hash = rte_jhash(__rg_name, strlen(rg_name), hash);
	}

	hash = rte_jhash_3words(rl->r_state->rs_rule_no, rl->r_nc_size,
			rg->rg_dir, hash);

	if (rl->r_ncode)
		hash = rte_jhash(rl->r_ncode, rl->r_nc_size, hash);

	return hash;
}

static int
npf_process_rule_rproc(npf_rule_t *rl, char *rproc_value,
		       enum npf_rproc_type ro_type)
{
	char *start_bracket = strchr(rproc_value, '(');
	char *end_bracket = strchr(rproc_value, ')');
	char *rproc_args = NULL;
	char *rproc_args_dup = NULL;
	unsigned int cnt = rl->r_state->rs_rproc_count;
	const npf_rproc_ops_t *ops;
	int ret;

	if (cnt >= npf_rproc_max_rprocs() - 1)	/* too many rprocs installed */
		return -ENOMEM;

	if (start_bracket && !end_bracket)
		return -EINVAL;

	if (start_bracket) {
		*start_bracket = '\0';
		rproc_args = start_bracket + 1;
	}

	ops = npf_find_rproc(rproc_value, ro_type);
	if (start_bracket)	/* put back bracket to retain the string */
		*start_bracket = '(';
	if (!ops)
		return -EINVAL;

	if (rproc_args) {	/* have a parameter to pass in to create? */
		*end_bracket = '\0';
		rproc_args_dup = strdup(rproc_args);
		*end_bracket = ')';	/* restore the end bracket */

		if (!rproc_args_dup)
			return -ENOMEM;
	}

	ret = npf_create_rproc(ops, rl, rproc_args_dup,
			       &rl->r_state->rs_rproc[cnt].handle);
	if (ret) {
		free(rproc_args_dup);
		return ret;
	}

	rl->r_state->rs_rproc[cnt].config_arg = rproc_args_dup;
	rl->r_state->rs_rproc[cnt].ops = ops;
	rl->r_state->rs_rproc_count++;

	assert((ops->ro_action != NULL) ==
	       (ops->ro_type == NPF_RPROC_TYPE_ACTION));
	assert((ops->ro_match != NULL) ==
	       (ops->ro_type == NPF_RPROC_TYPE_MATCH));
	assert((ops->ro_action == NULL && ops->ro_match == NULL) ==
	       (ops->ro_type == NPF_RPROC_TYPE_HANDLE));

	/*
	 * Optimize various rproc invocations by setting a
	 * bit to know whether these ops exist.
	 */
	if (ops->ro_logger)
		rl->r_rproc_logger = 1;

	if (ops->ro_type == NPF_RPROC_TYPE_ACTION)
		rl->r_rproc_action = 1;

	if (ops->ro_type == NPF_RPROC_TYPE_MATCH)
		rl->r_rproc_match = 1;

	if (ops->ro_type == NPF_RPROC_TYPE_HANDLE)
		rl->r_rproc_handle = 1;

	return 0;
}

static int
npf_process_rule_rprocs(npf_rule_t *rl, enum npf_rproc_type ro_type)
{
	const char *type_str = npf_rproc_type2string(ro_type);
	if (!type_str)
		return 0;

	char *rproc_entries = zhashx_lookup(rl->r_state->rs_config_ht,
					    type_str);
	char *rproc_entries_cpy;
	char *rproc;

	if (!rproc_entries)
		return 0;

	/* Make a copy, as the line is edited when parsed. */
	rproc_entries_cpy = strdupa(rproc_entries);

	while ((rproc = strsep(&rproc_entries_cpy, ";")) != NULL) {
		int ret = npf_process_rule_rproc(rl, rproc, ro_type);

		if (ret) {
			RTE_LOG(ERR, FIREWALL, "NPF: %s in rule: %s=%s\n",
				ret == -ENOMEM ? "out of memory" :
						 "unexpected value",
				type_str, rproc_entries);
			return ret;
		}
	}

	return 0;
}

static int
npf_add_rule_to_grouper(npf_rule_t *rl)
{
	struct npf_rule_grouper_info *info = &rl->r_state->rs_grouper_info;
	enum npf_ruleset_type rs_type =
		rl->r_state->rs_rule_group->rg_ruleset->rs_type;
	int err;

	/*
	 * Insert the grouper entries for this rule into the grouper
	 * associated with this group of rules.
	 */
	if (info->g_family != AF_INET6) {
		err = npf_match_add_rule(
			rs_type, AF_INET,
			rl->r_state->rs_rule_group->match_ctx_v4,
			rl->r_state->rs_rule_no, info->g_v4_match,
			info->g_v4_mask, rl);
		if (err)
			return err;
	}

	/*
	 * NAT64 might have a natpolicy, so always add IPv6 rule
	 */
	if (info->g_family != AF_INET) {
		err = npf_match_add_rule(
			rs_type, AF_INET6,
			rl->r_state->rs_rule_group->match_ctx_v6,
			rl->r_state->rs_rule_no, info->g_v6_match,
			info->g_v6_mask, rl);
		if (err)
			return err;
	}

	return 0;
}

#ifdef NPF_RULE_DEBUG
static void
grouper_rule_dump(struct npf_rule_grouper_info *info)
{
	int i;

	printf("Grouper info: family %s\n\n",
	       info->g_family == AF_INET ? "IPv4" :
	       (info->g_family == AF_INET6 ? "IPv6" : "Unspec"));

	if (info->g_family != AF_INET6) {
		printf("PR -SRC-ADDR-- -DST-ADDR-- S-PRT D-PRT\n");
		for (i = 0; i < NPC_GPR_SIZE_v4; i++)
			printf("%02X ", info->g_v4_match[i]);
		printf("\n");
		for (i = 0; i < NPC_GPR_SIZE_v4; i++)
			printf("%02X ", info->g_v4_mask[i]);
		printf("\n\n");
	}

	if (info->g_family != AF_INET) {
		printf("PR --------------------SRC-ADDR-------------------\n");
		for (i = 0; i < NPC_GPR_DADDR_OFF_v6; i++)
			printf("%02X ", info->g_v6_match[i]);
		printf("\n");
		for (i = 0; i < NPC_GPR_DADDR_OFF_v6; i++)
			printf("%02X ", info->g_v6_mask[i]);
		printf("\n");

		printf("   --------------------DST-ADDR------------------- "
		       "S-PRT D-PRT\n   ");
		for (i = NPC_GPR_DADDR_OFF_v6; i < NPC_GPR_SIZE_v6; i++)
			printf("%02X ", info->g_v6_match[i]);
		printf("\n   ");
		for (i = NPC_GPR_DADDR_OFF_v6; i < NPC_GPR_SIZE_v6; i++)
			printf("%02X ", info->g_v6_mask[i]);
		printf("\n");
	}
}
#endif /* NPF_RULE_DEBUG */

static int
npf_process_rule_config(npf_rule_t *rl)
{
	char *value;
	int ret;

	value = zhashx_lookup(rl->r_state->rs_config_ht, "action");
	if (value) {
		if (strcmp(value, "accept") == 0)
			rl->r_pass = 1;
		else if (strcmp(value, "drop") == 0)
			rl->r_pass = 0;
		else {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"action=%s\n", value);
			return -EINVAL;
		}
	} else {
		rl->r_pass = 1;	/* default is accept */
	}

	value = zhashx_lookup(rl->r_state->rs_config_ht, "stateful");
	if (value) {
		if (strcmp(value, "y") == 0)
			rl->r_stateful = 1;
		else if (strcmp(value, "n") == 0)
			rl->r_stateful = 0;
		else {
			RTE_LOG(ERR, FIREWALL, "NPF: unexpected value in rule: "
				"stateful=%s\n", value);
			return -EINVAL;
		}
	} else
		rl->r_stateful = 0;	/* default is stateless */

	enum npf_rproc_type ro_type;

	for (ro_type = NPF_RPROC_TYPE_FIRST;
	     ro_type <= NPF_RPROC_TYPE_LAST; ro_type++) {
		ret = npf_process_rule_rprocs(rl, ro_type);
		if (ret)
			return ret;
	}

	ret = npf_gen_ncode(rl->r_state->rs_config_ht, &rl->r_ncode,
			&rl->r_nc_size, rl->r_rproc_match,
			&rl->r_state->rs_grouper_info);
	if (ret)
		return ret;

#ifdef NPF_RULE_DEBUG
	printf("Attach Type: %s, Attach Name: %s, Group: %s, Rule Number: %u\n",
		npf_get_attach_type_name(
			rl->r_state->rs_rule_group->rg_ruleset->rs_attach_type),
		rl->r_state->rs_rule_group->rg_ruleset->rs_attach_point,
		rl->r_state->rs_rule_group->rg_name, rl->r_state->rs_rule_no);
	printf("Rule: %s\n", rl->r_state->rs_config_line);
	grouper_rule_dump(&rl->r_state->rs_grouper_info);
	printf("\n");
#endif /* NPF_RULE_DEBUG */

	ret = npf_process_nat_config(rl, rl->r_state->rs_config_ht);
	if (ret)
		return ret;

	ret = npf_add_rule_to_grouper(rl);
	if (ret)
		return ret;

	if (rl->r_stateful)
		npf_ruleset_set_stateful(rl->r_state->rs_rule_group, true);

	return 0;
}

static zhashx_t *npf_rule_config_ht_init(void)
{
	zhashx_t *config_ht;

	config_ht = zhashx_new();
	if (!config_ht)
		return NULL;

	zhashx_set_destructor(config_ht, (zhashx_destructor_fn *)zstr_free);
	zhashx_set_duplicator(config_ht, (zhashx_duplicator_fn *)strdup);

	return config_ht;
}

int
npf_make_rule(npf_rule_group_t *rg, uint32_t rule_no, const char *rule_line,
	      uint32_t ruleset_type_flags)
{
	struct cds_lfht_node *ret_node = NULL;
	npf_rule_t *rl;
	int ret;

	rl = npf_alloc_rule(ruleset_type_flags);
	if (!rl) {
		RTE_LOG(ERR, FIREWALL, "Error: rule allocation failed\n");
		return -ENOMEM;
	}

	rl->r_state->rs_config_line = strdup(rule_line);
	if (!rl->r_state->rs_config_line) {
		RTE_LOG(ERR, FIREWALL, "Error: rule line allocation failed\n");
		ret = -ENOMEM;
		goto error;
	}

	rl->r_state->rs_config_ht = npf_rule_config_ht_init();
	if (!rl->r_state->rs_config_ht) {
		RTE_LOG(ERR, FIREWALL, "Error: rule hash table allocation "
			"failed\n");
		ret = -ENOMEM;
		goto error;
	}

	/*
	 * Add a back reference to the group and insert in the rule into
	 * its group.
	 */
	rl->r_state->rs_rule_group = rg;
	cds_list_add_tail(&rl->r_entry, &rg->rg_rules);

	/*
	 * NB: this is truncated down to 16-bits, storing a rule as
	 * a 32-bit value will be removed when IPSEC change to store
	 * its rule number as 16-bit values.
	 */
	rl->r_state->rs_rule_no = rule_no;

	/*
	 * Add rule to hash table (if present) to enable faster lookups
	 */
	if (rg->rg_rules_ht) {
		ret_node = cds_lfht_add_unique(rg->rg_rules_ht,
					       rl->r_state->rs_rule_no,
					       npf_rg_rule_match,
					       &rl->r_state->rs_rule_no,
					       &rl->r_entry_ht);

		if (ret_node != &rl->r_entry_ht) {
			ret = -EEXIST;
			goto error;
		}
	}

	ret = npf_parse_rule_line(rl->r_state->rs_config_ht, rule_line);
	if (ret) {
		RTE_LOG(ERR, FIREWALL, "Error: parsing rule line: %s - %s\n",
			rule_line, strerror(-ret));
		goto error;
	}

	ret = npf_process_rule_config(rl);
	if (ret) {
		RTE_LOG(ERR, FIREWALL, "Error: processing config for rule "
			"line: %s - %s\n", rule_line, strerror(-ret));
		goto error;
	}

	rl->r_state->rs_hash = npf_rule_hash(rl);

	return 0;
error:
	cds_list_del(&rl->r_entry);
	if (rg->rg_rules_ht && ret_node == &rl->r_entry_ht)
		cds_lfht_del(rg->rg_rules_ht, &rl->r_entry_ht);
	npf_rule_put(rl);
	return ret;

}

/*
 * The rproc array on a rule is tightly packed,
 * as such it easy cheap to test if any rprocs are set.
 */
bool
npf_rule_has_rproc_actions(npf_rule_t *rl)
{
	return rl->r_rproc_action != 0;
}

ALWAYS_INLINE bool
npf_rule_has_rproc_logger(npf_rule_t *rl)
{
	return rl && rl->r_rproc_logger;
}

/*
 * Run the rule action procedures by executing each extension call.
 *
 * Note that 'result' pointer may be NULL.
 */
bool
npf_rproc_action(npf_cache_t *npc, struct rte_mbuf **nbuf,
		 int dir, npf_rule_t *rl,
		 npf_session_t *se, npf_rproc_result_t *result)
{
	unsigned int i;

	/* Only if any have an action */
	if (!rl->r_rproc_action)
		return true;

	bool backwards = (se && !npf_session_forward_dir(se, dir));
	bool rv = true;

	for (i = 0; i < rl->r_state->rs_rproc_count; i++) {
		const npf_rproc_ops_t *ops = rl->r_state->rs_rproc[i].ops;
		void *handle = rl->r_state->rs_rproc[i].handle;

		if (!ops->ro_action)
			continue;
		if (ops->ro_logger)
			continue;

		/* Maybe not interested in backwards session direction */
		if (backwards && !ops->ro_bidir)
			continue;
		if (!ops->ro_action(npc, nbuf, handle, se, result)) {
			rv = false;
			break;
		}
	}

	return rv;
}

/*
 * For each rproc which is enabled on a rule and supplied a match vector,
 * call it to see if the criteria match.  Each result is logically AND'ed
 * such that the rule can only match if all match vectors return true.
 */
bool
npf_rproc_match(npf_cache_t *npc, struct rte_mbuf *m, const npf_rule_t *rl,
		const struct ifnet *ifp, int dir, npf_session_t *se)
{
	unsigned int i;

	/* Only if any have a match */
	if (!rl->r_rproc_match)
		return true;

	for (i = 0; i < rl->r_state->rs_rproc_count; i++) {
		const npf_rproc_ops_t *ops = rl->r_state->rs_rproc[i].ops;
		void *handle = rl->r_state->rs_rproc[i].handle;

		if (!ops->ro_match)
			continue;

		if (!ops->ro_match(npc, m, ifp, dir, se, handle))
			return false;
	}

	return true;
}

int
npf_match_setup(npf_rule_group_t *rg, uint32_t max_rules)
{
	int err;
	enum npf_ruleset_type rs_type = rg->rg_ruleset->rs_type;

	DP_DEBUG(NPF, DEBUG, DATAPLANE, "Creating ruleset of size %d\n",
		 max_rules);

	err = npf_match_init(rs_type, AF_INET, rg->rg_name,
			     max_rules, &rg->match_ctx_v4);
	if (err)
		return err;

	err = npf_match_init(rs_type, AF_INET6, rg->rg_name,
			     max_rules, &rg->match_ctx_v6);
	if (err) {
		npf_match_destroy(rs_type, AF_INET, &rg->match_ctx_v4);
		return err;
	}

	return 0;
}

void
npf_match_optimize(npf_rule_group_t *rg)
{
	int err;
	enum npf_ruleset_type rs_type = rg->rg_ruleset->rs_type;

	err = npf_match_build(rs_type, AF_INET, &rg->match_ctx_v4);
	if (err)
		RTE_LOG(ERR, DATAPLANE, "Could not rebuild IPv4 grouper\n");

	err = npf_match_build(rs_type, AF_INET6, &rg->match_ctx_v6);
	if (err)
		RTE_LOG(ERR, DATAPLANE, "Could not rebuild IPv6 grouper\n");
}

static ALWAYS_INLINE
bool npf_rule_match(npf_cache_t *npc, struct rte_mbuf *nbuf,
		    const struct ifnet *ifp, int dir,
		    npf_session_t *se, const npf_rule_t *rl)
{
	/*
	 * Process the n-code, if any
	 * NB: 'match all' generates no ncode
	 */
	if (rl->r_ncode && npf_ncode_process(npc, rl, ifp, dir, se, nbuf))
		return false;

	return true;
}

bool
npf_rule_proc(const void *d, const void *r)
{
	const struct npf_match_cb_data *pd = d;
	const npf_rule_t *rl = r;

	return npf_rule_match(pd->npc, pd->mbuf, pd->ifp, pd->dir, pd->se, rl);
}

/*
 * Note, ifp is only used by the dpi rproc match function for session lookup
 * and creation.
 */
npf_rule_t *
npf_ruleset_inspect(npf_cache_t *npc, struct rte_mbuf *nbuf,
		    const npf_ruleset_t *ruleset, npf_session_t *se,
		    const struct ifnet *ifp, const int dir)
{
	npf_rule_group_t *rg = NULL;
	npf_rule_t *rl;
	int match;

	if (unlikely(ruleset == NULL))
		return NULL;

	struct npf_match_cb_data pd = {
		.npc = npc,
		.mbuf = nbuf,
		.ifp = ifp,
		.dir = dir,
		.se = se,
	};

	cds_list_for_each_entry_rcu(rg, &ruleset->rs_groups, rg_entry) {
		enum npf_ruleset_type rs_type = rg->rg_ruleset->rs_type;

		/* Match the direction. */
		if ((rg->rg_dir & dir) == 0)
			continue;

		/*
		 * update rule group in context. The current rule group
		 * being used is passed in the match context to enable
		 * easy search for the rule when a match is found
		 */
		pd.rg = rg;

		int af;
		void *match_ctx = NULL;

		if (!npc) {
			uint16_t et = ethhdr(nbuf)->ether_type;

			if (et == htons(RTE_ETHER_TYPE_IPV4)) {
				af = AF_INET;
				match_ctx = rg->match_ctx_v4;
			} else if (et == htons(RTE_ETHER_TYPE_IPV6)) {
				af = AF_INET6;
				match_ctx = rg->match_ctx_v6;
			}
		} else if (likely(npf_iscached(npc, NPC_GROUPER))) {
			if (likely(npf_iscached(npc, NPC_IP4))) {
				af = AF_INET;
				match_ctx = rg->match_ctx_v4;
			} else if (npf_iscached(npc, NPC_IP6)) {
				af = AF_INET6;
				match_ctx = rg->match_ctx_v6;
			}
		}

		if (match_ctx) {
			match = npf_match_classify(rs_type, af, match_ctx,
						   npc, &pd, &rl);
			if (match)
				return rl;
			continue;
		}

		/*
		 * Either grouper is not enabled, the grouper has been
		 * optimized out, or this is a packet for which we have no
		 * grouper support - so perform a slow search of the list.
		 */
		cds_list_for_each_entry_rcu(rl, &rg->rg_rules, r_entry) {
			if (unlikely(!npc))
				break;
			if (npf_rule_match(npc, nbuf, ifp, dir, se, rl))
				return rl;
		}
	}
	return NULL;
}

npf_decision_t
npf_rule_decision(npf_rule_t *rl)
{
	if (rl) {
		/* Match.  Either pass or block */
		if (rl->r_pass)
			return NPF_DECISION_PASS;
		else
			return NPF_DECISION_BLOCK;
	}
	return NPF_DECISION_UNMATCHED;
}

npf_ruleset_t *
npf_ruleset(const npf_rule_t *rl)
{
	if (rl && rl->r_state->rs_rule_group)
		return rl->r_state->rs_rule_group->rg_ruleset;

	return NULL;
}

void
npf_ruleset_set_stateful(npf_rule_group_t *rg, bool value)
{
	assert(rg->rg_ruleset != NULL);
	rg->rg_ruleset->rs_is_stateful = value;
}

bool
npf_ruleset_is_stateful(const npf_ruleset_t *ruleset)
{
	return ruleset ? ruleset->rs_is_stateful : false;
}

bool
npf_rule_stateful(const npf_rule_t *rl)
{
	return rl->r_stateful ? true : false;
}

enum npf_ruleset_type
npf_type_of_ruleset(const npf_ruleset_t *ruleset)
{
	return ruleset ? ruleset->rs_type : NPF_RS_TYPE_COUNT;
}

/*
 * returns true if the ruleset depends on the NPF cache
 * having been populated. Currently the only exception to this is
 * IPSec. The implementation should eventually move to a flag
 * that expresses the dependency on the cache as opposed to
 * specific ruleset types
 */
bool npf_ruleset_uses_cache(const npf_ruleset_t *ruleset)
{
	return (ruleset->rs_type != NPF_RS_IPSEC);
}

/* Update (as needed) all rules for a masquerade addr change */
void npf_ruleset_update_masquerade(const struct ifnet *ifp,
				   const npf_ruleset_t *rs)
{
	npf_rule_group_t *rg;
	npf_rule_t *rl;
	struct if_addr *ifa;
	struct sockaddr *sa;
	struct sockaddr_in *sin;
	npf_addr_t addr = IN6ADDR_ANY_INIT;

	/*
	 * Get the 'masquerade' addr from the interface.
	 * Use the first IPv4 addr found.
	 */
	cds_list_for_each_entry(ifa, &ifp->if_addrhead, ifa_link) {
		sa = (struct sockaddr *) &ifa->ifa_addr;
		if (sa->sa_family == AF_INET) {
			sin = satosin(sa);
			memcpy(&addr, &sin->sin_addr, 4);
			break;
		}
	}

	/* sanity, should never happen, but could... */
	if (IN6_IS_ADDR_UNSPECIFIED(&addr))
		return;

	/*
	 * For the SNAT rule group, run through each rule and
	 * send each rule to the nat engine to deal with the
	 * (possible) update.
	 */
	cds_list_for_each_entry(rg, &rs->rs_groups, rg_entry) {
		cds_list_for_each_entry(rl, &rg->rg_rules, r_entry)
			npf_natpolicy_update_masq(rl, &addr);
	}
}

void npf_rule_set_natpolicy(npf_rule_t *rl, npf_natpolicy_t *np)
{
	rcu_xchg_pointer(&rl->r_natp, np);
}

npf_natpolicy_t *npf_rule_get_natpolicy(const npf_rule_t *rl)
{
	return rcu_dereference(rl->r_natp);
}

const char *npf_ruleset_get_name(npf_rule_group_t *rg)
{
	if (rg)
		return rg->rg_name;
	return NULL;
}

/*
 * Walk all ruleset groups in a ruleset config
 *
 * Filter on group class and group name if 'sel' is set and sel->group_class
 * and sel->group_name are non default.
 */
void
npf_ruleset_group_walk(const npf_ruleset_t *ruleset,
		       struct ruleset_select *sel,
		       npf_rs_group_walk_cb *fn, void *ctx)
{
	npf_rule_group_t *rg;

	cds_list_for_each_entry(rg, &ruleset->rs_groups, rg_entry) {
		/* filter in group class */
		if (sel &&
		    sel->group_class != NPF_RULE_CLASS_COUNT &&
		    sel->group_class != rg->rg_class)
			continue;

		/* filter in group name */
		if (sel && sel->group_name &&
		    strcmp(sel->group_name, rg->rg_name) != 0)
			continue;

		if (!(fn)(rg, ctx))
			break;
	}
}

/*
 * Walk all rules in a ruleset group.
 *
 * Filter on rule number if 'sel' is set and sel->rule_no is not zero.
 */
void
npf_rules_walk(npf_rule_group_t *rg, struct ruleset_select *sel,
	       npf_rs_rules_walk_cb *fn, void *ctx)
{
	npf_rule_t *rl;

	cds_list_for_each_entry(rl, &rg->rg_rules, r_entry) {
		/* filter on rule number */
		if (sel && sel->rule_no != 0 && rl->r_state &&
		    sel->rule_no != rl->r_state->rs_rule_no)
			continue;

		if (!(fn)(rl, ctx))
			break;
	}
}

#ifdef _NPF_TESTING
void
npf_rulenc_dump(const npf_rule_t *rl)
{
	const uint32_t *op = rl->r_ncode;
	unsigned int n = r->rl_nc_size;

	while (n) {
		printf("\t> |0x%02x|\n", (uint32_t)*op);
		op++;
		n -= sizeof(*op);
	}
	printf("-> %s\n", rl->r_pass ? "pass" : "block");
}
#endif

npf_rule_t *npf_rule_group_find_rule(npf_rule_group_t *rg,
				     uint32_t rule_no)
{
	npf_rule_t *rl;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	if (rg->rg_rules_ht) {
		cds_lfht_lookup(rg->rg_rules_ht, rule_no, npf_rg_rule_match,
				&rule_no, &iter);
		node = cds_lfht_iter_get_node(&iter);
		rl = node ? caa_container_of(node, npf_rule_t, r_entry_ht) :
			NULL;
		return rl;
	}

	cds_list_for_each_entry(rl, &rg->rg_rules, r_entry) {
		if (rule_no == rl->r_state->rs_rule_no)
			return rl;
	}

	return NULL;
}
