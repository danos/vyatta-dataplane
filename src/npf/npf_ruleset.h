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

#ifndef NPF_RULESET_H
#define NPF_RULESET_H

typedef struct npf_ruleset      npf_ruleset_t;
typedef struct npf_rule_group   npf_rule_group_t;
typedef struct npf_rule         npf_rule_t;
typedef uint16_t                rule_no_t;

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "json_writer.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf.h"
#include "src/npf/nat/nat_proto.h"
#include "pktmbuf_internal.h"

/* Forward Declarations */
struct ifnet;
struct rte_mbuf;

typedef struct json_writer json_writer_t;
typedef struct npf_natpolicy npf_natpolicy_t;
typedef struct npf_session npf_session_t;
typedef struct npf_cache npf_cache_t;

/* npf_rproc_action results */
typedef struct {
	npf_decision_t	decision : 4;
	bool		icmp_param_prob : 1;
	bool		icmp_dst_unreach : 1;
	uint8_t		_unused : 2;
} npf_rproc_result_t;

/*
 * This structures primary use is in a per-core array, and so it is aligned
 * to 64-byte boundary to ensure that different cores access different cache
 * lines.
 */
struct npf_rule_stats {
	uint64_t	pkts_ct;
	uint64_t	bytes_ct;
	uint64_t	map_ports[NAT_PROTO_COUNT]; /* NAT mapped ports stats */
	rte_atomic64_t  refcnt;    /* only refcnt of index 0 is used */
	uint64_t	pad[2];
};

static_assert(sizeof(struct npf_rule_stats) == 64, "not size of cache line");

/**
 * Used to select rulesets on attachment points to perform actions on,
 * such as showing them, clearing statistics, dumping generation
 * information, and making rulesets dirty.
 *
 * If "attach_type" is NPF_ATTACH_TYPE_NONE then the actions is done for
 * all attach types.
 *
 * The field "rulesets" is a bit mask of the rulesets on the selected
 * attach types. This can be set to all-ones to match every rule.
 *
 * Examples:
 *   npf-op show -n fw:FW_IN1 -r 10 interface:dp0p1s1 fw-in fw-out
 *   npf-op show -n fw:FW_IN2 -r 10 all: fw-in fw-out
 */
struct ruleset_select {
	enum npf_attach_type	attach_type;
	const char		*attach_point;
	unsigned long		rulesets; /* bitmask of rulesets to act on */
	enum npf_rule_class	group_class;
	char			*group_name;
	rule_no_t		rule_no;
};

void rule_sum_stats(const npf_rule_t *rl,
		    struct npf_rule_stats *rs);

void npf_ruleset_gc_init(void);
npf_ruleset_t *npf_ruleset_create(enum npf_ruleset_type ruleset_type,
				  enum npf_attach_type attach_type,
				  const char *attach_point);
void npf_ruleset_update_masquerade(const struct ifnet *ifp,
				   const npf_ruleset_t *rs);
void npf_rule_set_natpolicy(npf_rule_t *rl, npf_natpolicy_t *np);
npf_natpolicy_t *npf_rule_get_natpolicy(const npf_rule_t *rl);
void npf_free_group(npf_rule_group_t *rg);
void npf_ruleset_free(npf_ruleset_t *ruleset);
void npf_ref_stats(npf_ruleset_t *old, npf_ruleset_t *new);
void npf_clear_stats(const npf_ruleset_t *ruleset,
		     enum npf_rule_class group_class, const char *group_name,
		     rule_no_t rule_no);
npf_rule_t *npf_rule_get(npf_rule_t *rl);
void npf_rule_put(npf_rule_t *rl);
void npf_add_pkt(npf_rule_t *rl, uint64_t bytes);
const void *npf_get_ncode(const npf_rule_t *rl);
void npf_rule_update_map_stats(npf_rule_t *rl, int n, uint32_t flags,
			       uint8_t ip_prot);
void npf_rule_get_overall_used(npf_rule_t *rl, uint64_t *used,
		uint64_t *overall);
rule_no_t npf_rule_get_num(npf_rule_t *rl);
void npf_rule_set_pass(npf_rule_t *rl, bool value);
int npf_rule_get_attach_point(const npf_rule_t *rl,
			      enum npf_attach_type *attach_type,
			      const char **attach_point);
bool npf_rule_get_pass(npf_rule_t *rl);
uint32_t npf_rule_get_hash(npf_rule_t *rl);
const char *npf_rule_get_name(npf_rule_t *rl);
int npf_rule_get_dir(const npf_rule_t *rl);
struct ifnet *npf_rule_get_ifp(const npf_rule_t *rl);
npf_rule_t *npf_get_rule_by_hash(uint32_t hash);
int npf_json_ruleset(const npf_ruleset_t *ruleset, json_writer_t *json);
npf_rule_group_t *npf_rule_group_create(npf_ruleset_t *ruleset,
					enum npf_rule_class group_class,
					const char *group, uint8_t dir);
int npf_make_rule(npf_rule_group_t *rg, uint32_t rule_no,
		  const char *rule_line, uint32_t ruleset_type_flags);
void *npf_rule_rproc_handle_for_logger(npf_rule_t *rl);
bool npf_rule_has_rproc_actions(npf_rule_t *rl);
bool npf_rule_has_rproc_logger(npf_rule_t *rl);
bool npf_rproc_action(npf_cache_t *npc, struct rte_mbuf **nbuf,
		      int dir, npf_rule_t *rl,
		      npf_session_t *se, npf_rproc_result_t *result);
bool npf_rproc_match(npf_cache_t *npc, struct rte_mbuf *m, const npf_rule_t *rl,
		     const struct ifnet *ifp, int dir, npf_session_t *se);
int npf_match_setup(npf_rule_group_t *rg, uint32_t max_rules);
void npf_match_optimize(npf_rule_group_t *rg);
bool npf_rule_proc(const void *d, const void *r);
npf_rule_t *npf_ruleset_inspect(npf_cache_t *npc, struct rte_mbuf *nbuf,
				const npf_ruleset_t *ruleset,
				npf_session_t *se, const struct ifnet *ifp,
				const int dir);
npf_decision_t npf_rule_decision(npf_rule_t *rl);
npf_ruleset_t *npf_ruleset(const npf_rule_t *rl);
void npf_ruleset_set_stateful(npf_rule_group_t *rg, bool value);
bool npf_ruleset_is_stateful(const npf_ruleset_t *ruleset);
bool npf_rule_stateful(const npf_rule_t *rl);
enum npf_ruleset_type npf_type_of_ruleset(const npf_ruleset_t *ruleset);

const char *npf_ruleset_get_name(npf_rule_group_t *rg);
bool npf_ruleset_uses_cache(const npf_ruleset_t *ruleset);

/*
 * Walk all ruleset groups in a ruleset config
 *
 * Filter on group class and group name if 'sel' is set and sel->group_class
 * and sel->group_name are non default.
 */
typedef bool (npf_rs_group_walk_cb)(npf_rule_group_t *rg, void *ctx);
void npf_ruleset_group_walk(const npf_ruleset_t *ruleset,
			    struct ruleset_select *sel,
			    npf_rs_group_walk_cb *fn, void *ctx);

/*
 * Walk all rules in a ruleset group.
 *
 * Filter on rule number if 'sel' is set and sel->rule_no is not zero.
 */
typedef bool (npf_rs_rules_walk_cb)(npf_rule_t *rl, void *ctx);
void npf_rules_walk(npf_rule_group_t *rg, struct ruleset_select *sel,
		    npf_rs_rules_walk_cb *fn, void *ctx);


#ifdef _NPF_TESTING
void npf_rulenc_dump(const npf_rule_t *rl);
#endif
int npf_flush_rulesets(void);

/*
 * Find a rule matching the rule number.
 *
 * Used by clients of rte-acl since there is no
 * facility to store and directly return the pointer
 * to the rule (as is done with grouper)
 */
npf_rule_t *npf_rule_group_find_rule(npf_rule_group_t *rg,
				     uint32_t rule_no);

#endif /* NPF_RULESET_H */
