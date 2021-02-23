/*-
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in
 *	 the documentation and/or other materials provided with the
 *	 distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *	 contributors may be used to endorse or promote products derived
 *	 from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <bsd/sys/tree.h>
#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_errno.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/arch.h>

#include "compiler.h"
#include "pd_show.h"
#include "lpm.h"
#include "util.h"
#include "route.h"

/** Auto-growth of tbl8 */
#define LPM_TBL8_INIT_GROUPS	256	/* power of 2 */
#define LPM_TBL8_INIT_ENTRIES	(LPM_TBL8_INIT_GROUPS * \
					 LPM_TBL8_GROUP_NUM_ENTRIES)
/** Rule structure. */
struct lpm_rule {
	uint32_t ip;	    /**< Rule IP address. */
	uint32_t next_hop;	/**< Rule next hop. */
	int16_t scope;	/**< Rule scope */
	uint16_t tracker_count;
	struct pd_obj_state_and_flags pd_state;
	RB_HEAD(lpm_tracker_tree, rt_tracker_info) tracker_head;
	RB_ENTRY(lpm_rule) link;
};

/** @internal LPM structure. */
struct lpm {
	/* LPM metadata. */
	uint32_t id;			/**< table id */
	unsigned int rule_count;        /**< num of rules **/
	struct cds_list_head lpm_rti_list;
	/**< LPM rules. */
	RB_HEAD(lpm_rules_tree, lpm_rule) rules[LPM_MAX_DEPTH];

	struct lpm_rule no_route_rule; /* For storing trackers */

	/* LPM Tables. */
	uint32_t tbl8_num_groups;		/* Number of slots */
	uint32_t tbl8_rover;			/* Next slot to check */

	struct lpm_tbl8_entry *tbl8;	/* Actual table */
	struct lpm_tbl8_entry tbldflt; /* depth == 0 */
	struct lpm_tbl24_entry tbl24[LPM_TBL24_NUM_ENTRIES]
			__rte_cache_aligned; /**< LPM tbl24 table. */
};

/*
 * Define static initialiser for tbl24 LPM entries that
 * abstract details like how the nh is stored.
 */
#define TBL24_ENTRY_W_NH_INITIALIZER(n_depth, nhop)	\
	{						\
		.valid = VALID,				\
		.ext_entry = 0,				\
		.depth = (n_depth),			\
		.next_hop = (nhop),			\
	}

#define MAX_DEPTH_TBL24 24

enum valid_flag {
	INVALID = 0,
	VALID
};

static void lpm_tracker_update(struct lpm *lpm, struct lpm_rule *old_rule,
			       uint32_t ip, uint8_t depth);

/* Macro to enable/disable run-time checks. */
#if defined(LIBLPM_DEBUG)
#define VERIFY_DEPTH(depth) do {				\
	if (depth >= LPM_MAX_DEPTH)				\
		rte_panic("LPM: Invalid depth (%u) at line %d\n", \
				(unsigned int)(depth), __LINE__);	\
} while (0)
#else
#define VERIFY_DEPTH(depth)
#endif

/* Comparison function for red-black tree nodes.
   "If the first argument is smaller than the second, the function
    returns a value smaller than zero.	If they are equal, the function
    returns zero.  Otherwise, it should return a value greater than zero."
*/
static inline int rules_cmp(const struct lpm_rule *r1,
			    const struct lpm_rule *r2)
{
	if (r1->ip < r2->ip)
		return -1;
	if (r1->ip > r2->ip)
		return 1;
	return r1->scope - r2->scope;
}

static inline int tracker_cmp(const struct rt_tracker_info *r1,
			      const struct rt_tracker_info *r2)
{
	return memcmp(&r1->dst_addr.address.ip_v4.s_addr,
		      &r2->dst_addr.address.ip_v4.s_addr,
		      sizeof(r1->dst_addr.address.ip_v4.s_addr));
}

/* Generate internal functions and make them static. */
RB_GENERATE_STATIC(lpm_rules_tree, lpm_rule, link, rules_cmp)
RB_GENERATE_STATIC(lpm_tracker_tree, rt_tracker_info, rti_tree_node,
		   tracker_cmp)

/*
 * Converts a given depth value to its corresponding mask value.
 *
 * depth  (IN)		: range = 1 - 32
 * mask	  (OUT)		: 32bit mask
 */
uint32_t __attribute__((pure))
lpm_depth_to_mask(uint8_t depth)
{
	VERIFY_DEPTH(depth);

	/* per C std. shift of 32 bits is undefined */
	if (depth == 0)
		return 0;

	return ~0u << (32 - depth);
}

/*
 * Converts given depth value to its corresponding range value.
 */
static inline uint32_t __attribute__((pure))
depth_to_range(uint8_t depth)
{
	VERIFY_DEPTH(depth);

	/*
	 * Calculate tbl24 range. (Note: 2^depth = 1 << depth)
	 */
	if (depth <= MAX_DEPTH_TBL24)
		return 1 << (MAX_DEPTH_TBL24 - depth);

	/* Else if depth is greater than 24 */
	return 1 << (32 - depth);
}

/*
 * Allocates memory for LPM object
 */
struct lpm *
lpm_create(uint32_t id)
{
	struct lpm *lpm = NULL;
	unsigned int depth;

	RTE_BUILD_BUG_ON(sizeof(struct lpm_tbl24_entry) != 4);
	RTE_BUILD_BUG_ON(sizeof(struct lpm_tbl8_entry) != 4);

	/* Allocate memory to store the LPM data structures. */
	lpm = malloc_huge_aligned(sizeof(*lpm));
	if (lpm == NULL) {
		RTE_LOG(ERR, LPM, "LPM memory allocation failed\n");
		goto exit;
	}

	/* Save user arguments. */
	lpm->id = id;

	/* Vyatta change to use red-black tree */
	for (depth = 0; depth < LPM_MAX_DEPTH; ++depth)
		RB_INIT(&lpm->rules[depth]);

	/* Vyatta change to dynamically grow tbl8 */
	lpm->tbl8_num_groups = LPM_TBL8_INIT_GROUPS;
	lpm->tbl8_rover = LPM_TBL8_INIT_GROUPS - 1;
	lpm->tbl8 = malloc_huge_aligned(LPM_TBL8_INIT_ENTRIES *
					sizeof(struct lpm_tbl8_entry));

	if (lpm->tbl8 == NULL) {
		free_huge(lpm, sizeof(*lpm));
		RTE_LOG(ERR, LPM, "LPM tbl8 group allocation failed\n");
		lpm = NULL;
		goto exit;
	}

	memset(&lpm->no_route_rule, 0, sizeof(lpm->no_route_rule));
	RB_INIT(&lpm->no_route_rule.tracker_head);
exit:
	return lpm;
}

uint32_t
lpm_get_id(struct lpm *lpm)
{
	return lpm->id;
}

/*
 * Deallocates memory for given LPM table.
 */
void
lpm_free(struct lpm *lpm)
{
	if (lpm == NULL)
		return;

	assert(lpm->no_route_rule.tracker_count == 0);
	free_huge(lpm->tbl8, (lpm->tbl8_num_groups *
			      LPM_TBL8_GROUP_NUM_ENTRIES *
			      sizeof(struct lpm_tbl8_entry)));
	free_huge(lpm, sizeof(*lpm));
}

/*
 * Finds a rule in rule table.
 */
static struct lpm_rule *
rule_find(struct lpm *lpm, uint32_t ip_masked, uint8_t depth, int16_t scope)
{
	struct lpm_rules_tree *head = &lpm->rules[depth];
	struct lpm_rule k = {
		.ip = ip_masked,
		.scope = scope,
	};

	return RB_FIND(lpm_rules_tree, head, &k);
}

static struct lpm_rule *
rule_find_next(struct lpm *lpm, uint32_t ip_masked, uint8_t depth,
	       int16_t scope)
{
	struct lpm_rules_tree *head = &lpm->rules[depth];
	struct lpm_rule k = {
		.ip = ip_masked,
		.scope = scope,
	};

	return RB_NFIND(lpm_rules_tree, head, &k);
}

/* Finds rule in table in scope order */
static struct lpm_rule *
rule_find_any(struct lpm *lpm, uint32_t ip_masked, uint8_t depth)
{
	struct lpm_rule *r;

	/*
	 * Search RB tree for entry after the masked_ip with max scope.
	 * If it finds an entry then get the prev entry, and if ip addr
	 * matches we have a match with highest scope.
	 * If it doesn't find an entry check the last value in the
	 * tree, and if the ip addr matches, we have the best match.
	 */
	r = rule_find_next(lpm, ip_masked, depth, 255);
	if (r)
		r = RB_PREV(lpm_rules_tree, &lpm->rules[depth], r);
	else
		r = RB_MAX(lpm_rules_tree, &lpm->rules[depth]);

	if (r && (r->ip != ip_masked))
		return NULL;

	return r;
}

/*
 * Adds a rule to the rule table.
 *
 * NOTE: The rule table is split into 32 groups. Each group contains rules that
 * apply to a specific prefix depth (i.e. group 1 contains rules that apply to
 * prefixes with a depth of 1 etc.).
 * NOTE: Valid range for depth parameter is 0 .. 32 inclusive.
 */
static struct lpm_rule *
rule_add(struct lpm *lpm, uint32_t ip_masked, uint8_t depth,
	 uint32_t next_hop, int16_t scope, bool *new)
{
	struct lpm_rules_tree *head = &lpm->rules[depth];
	struct lpm_rule *r, *old;

	/*
	 * NB: uses regular malloc to avoid chewing up precious
	 *  memory pool space for rules.
	 */
	r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	r->ip = ip_masked;
	r->next_hop = next_hop;
	r->scope = scope;
	r->tracker_count = 0;
	memset(&r->pd_state, 0, sizeof(r->pd_state));
	RB_INIT(&r->tracker_head);

	old = RB_INSERT(lpm_rules_tree, head, r);
	if (!old) {
		lpm->rule_count++;
		*new = true;
		return r;
	}
	/* collision with existing rule */
	free(r);
	*new = false;
	return old;
}

/*
 * Delete a rule from the rule table.
 * NOTE: Valid range for depth parameter is 1 .. 32 inclusive.
 */
static void
rule_delete(struct lpm *lpm, struct lpm_rule *r, uint8_t depth)
{
	struct lpm_rules_tree *head = &lpm->rules[depth];

	RB_REMOVE(lpm_rules_tree, head, r);
	lpm->rule_count--;
	/* Notify changes to the relevant trackers */
	lpm_tracker_update(lpm, r, r->ip, depth);
	assert(r->tracker_count == 0);
	assert(RB_EMPTY(&r->tracker_head));
	free(r);
}

/*
 * Dynamically increase size of tbl8
 */
static int
tbl8_grow(struct lpm *lpm)
{
	size_t old_size, new_size;
	struct lpm_tbl8_entry *new_tbl8;

	/* This should not happen,
	 * worst case is each /24 can point to one tbl8 */
	if (lpm->tbl8_num_groups >= LPM_TBL24_NUM_ENTRIES)
		rte_panic("LPM: tbl8 grow already at %u\n",
			  lpm->tbl8_num_groups);

	old_size = lpm->tbl8_num_groups;
	new_size = old_size << 1;
	new_tbl8 = malloc_huge_aligned(new_size *
				       LPM_TBL8_GROUP_NUM_ENTRIES *
				       sizeof(struct lpm_tbl8_entry));

	if (new_tbl8 == NULL) {
		RTE_LOG(ERR, LPM, "LPM tbl8 group expand allocation failed\n");
		return -ENOMEM;
	}

	memcpy(new_tbl8, lpm->tbl8,
	       old_size * LPM_TBL8_GROUP_NUM_ENTRIES
		   * sizeof(struct lpm_tbl8_entry));

	if (lpm->tbl8) {
		if (defer_rcu_huge(lpm->tbl8, old_size *
				   LPM_TBL8_GROUP_NUM_ENTRIES *
				   sizeof(struct lpm_tbl8_entry))) {
			RTE_LOG(ERR, LPM, "Failed to free LPM tbl8 group\n");
			return -1;
		}
	}

	/* swap in new table */
	rcu_assign_pointer(lpm->tbl8, new_tbl8);
	lpm->tbl8_num_groups = new_size;

	return 0;
}

/*
 * Find, clean and allocate a tbl8.
 */
static int32_t
tbl8_alloc(struct lpm *lpm)
{
	uint32_t tbl8_gindex; /* tbl8 group index. */
	struct lpm_tbl8_entry *tbl8_entry;

	/* Scan through tbl8 to find a free (i.e. INVALID) tbl8 group. */
	for (tbl8_gindex = (lpm->tbl8_rover + 1) & (lpm->tbl8_num_groups - 1);
	     tbl8_gindex != lpm->tbl8_rover;
	     tbl8_gindex = (tbl8_gindex + 1) & (lpm->tbl8_num_groups - 1)) {
		tbl8_entry = lpm->tbl8
			+ tbl8_gindex * LPM_TBL8_GROUP_NUM_ENTRIES;

		/* If a free tbl8 group is found clean it and set as VALID. */
		if (likely(!tbl8_entry->valid_group))
			goto found;
	}

	/* Out of space expand */
	tbl8_gindex = lpm->tbl8_num_groups;
	if (tbl8_grow(lpm) < 0)
		return -ENOSPC;

	tbl8_entry = lpm->tbl8
		+ tbl8_gindex * LPM_TBL8_GROUP_NUM_ENTRIES;
 found:
	memset(tbl8_entry, 0,
	       LPM_TBL8_GROUP_NUM_ENTRIES * sizeof(tbl8_entry[0]));

	tbl8_entry->valid_group = VALID;

	/* Remember last slot to start looking there */
	lpm->tbl8_rover = tbl8_gindex;

	/* Return group index for allocated tbl8 group. */
	return tbl8_gindex;
}

static inline void
tbl8_free(struct lpm *lpm, uint32_t tbl8_group_start)
{
	/* Set tbl8 group invalid*/
	lpm->tbl8[tbl8_group_start].valid_group = INVALID;
}

static void
add_depth_small(struct lpm *lpm, uint32_t ip, uint8_t depth,
		uint32_t next_hop)
{
	uint32_t tbl24_index, tbl24_range, tbl8_index, tbl8_group_end, i, j;
	struct lpm_tbl24_entry new_tbl24_entry =
		TBL24_ENTRY_W_NH_INITIALIZER(depth, next_hop);
	struct lpm_tbl8_entry new_tbl8_entry = {
		.valid_group = VALID,
		.valid = VALID,
		.depth = depth,
		.next_hop = next_hop,
	};

	/* Calculate the index into Table24. */
	tbl24_index = ip >> 8;
	tbl24_range = depth_to_range(depth);
	for (i = tbl24_index; i < (tbl24_index + tbl24_range); i++) {
		/*
		 * For invalid OR valid and non-extended tbl 24 entries set
		 * entry.
		 */
		if (!lpm->tbl24[i].valid || lpm->tbl24[i].ext_entry == 0) {
			if (!lpm->tbl24[i].valid ||
			    lpm->tbl24[i].depth <= depth)
				_CMM_STORE_SHARED(lpm->tbl24[i],
						  new_tbl24_entry);
			continue;
		}

		/* If tbl24 entry is valid and extended calculate the index
		 * into tbl8. */
		tbl8_index = lpm->tbl24[i].tbl8_gindex
			* LPM_TBL8_GROUP_NUM_ENTRIES;
		tbl8_group_end = tbl8_index + LPM_TBL8_GROUP_NUM_ENTRIES;
		for (j = tbl8_index; j < tbl8_group_end; j++) {
			if (!lpm->tbl8[j].valid ||
			    lpm->tbl8[j].depth <= depth) {
				/*
				 * Setting tbl8 entry in one go to avoid race
				 * conditions
				 */
				_CMM_STORE_SHARED(lpm->tbl8[j],
						  new_tbl8_entry);
			}
		}
	}
}

static int32_t
add_depth_big(struct lpm *lpm, uint32_t ip_masked, uint8_t depth,
	      uint32_t next_hop)
{
	uint32_t tbl24_index;
	int32_t tbl8_group_index, tbl8_group_start, tbl8_group_end, tbl8_index,
		tbl8_range, i;

	tbl24_index = (ip_masked >> 8);
	tbl8_range = depth_to_range(depth);

	if (!lpm->tbl24[tbl24_index].valid) {
		/* Search for a free tbl8 group. */
		tbl8_group_index = tbl8_alloc(lpm);

		/* Check tbl8 allocation was unsuccessful. */
		if (tbl8_group_index < 0)
			return tbl8_group_index;

		/* Find index into tbl8 and range. */
		tbl8_index = (tbl8_group_index *
				LPM_TBL8_GROUP_NUM_ENTRIES) +
				(ip_masked & 0xFF);

		/* Set tbl8 entry. */
		struct lpm_tbl8_entry new_tbl8_entry = {
			.valid_group = VALID,
			.valid = VALID,
			.depth = depth,
			.next_hop = next_hop,
		};

		for (i = tbl8_index; i < (tbl8_index + tbl8_range); i++)
			_CMM_STORE_SHARED(lpm->tbl8[i], new_tbl8_entry);

		/*
		 * In order to ensure there's no transient packet
		 * drop, ensure that the next store doesn't overtake
		 * previous stores.
		 */
		cmm_smp_wmc();

		/*
		 * Update tbl24 entry to point to new tbl8 entry. Note: The
		 * ext_flag and tbl8_index need to be updated simultaneously,
		 * so assign whole structure in one go
		 */
		struct lpm_tbl24_entry new_tbl24_entry = {
			.valid = VALID,
			.ext_entry = 1,
			.depth = 0,
			{ .tbl8_gindex = tbl8_group_index, }
		};

		_CMM_STORE_SHARED(lpm->tbl24[tbl24_index], new_tbl24_entry);
	}
	/* If valid entry but not extended calculate the index into Table8. */
	else if (lpm->tbl24[tbl24_index].ext_entry == 0) {
		/* Search for free tbl8 group. */
		tbl8_group_index = tbl8_alloc(lpm);

		if (tbl8_group_index < 0)
			return tbl8_group_index;

		tbl8_group_start = tbl8_group_index *
				LPM_TBL8_GROUP_NUM_ENTRIES;
		tbl8_group_end = tbl8_group_start +
				LPM_TBL8_GROUP_NUM_ENTRIES;

		/* Populate new tbl8 with tbl24 value. */
		struct lpm_tbl8_entry new_tbl8_entry = {
			.valid_group = VALID,
			.valid = VALID,
			.depth = lpm->tbl24[tbl24_index].depth,
			.next_hop = lpm_tbl24_get_next_hop_idx(
				&lpm->tbl24[tbl24_index]),
		};

		for (i = tbl8_group_start; i < tbl8_group_end; i++)
			_CMM_STORE_SHARED(lpm->tbl8[i], new_tbl8_entry);

		tbl8_index = tbl8_group_start + (ip_masked & 0xFF);

		/* Insert new specific rule into the tbl8 entry. */
		new_tbl8_entry.depth = depth;
		new_tbl8_entry.next_hop = next_hop;
		for (i = tbl8_index; i < tbl8_index + tbl8_range; i++)
			_CMM_STORE_SHARED(lpm->tbl8[i], new_tbl8_entry);

		/*
		 * Update tbl24 entry to point to new tbl8 entry. Note: The
		 * ext_flag and tbl8_index need to be updated simultaneously,
		 * so assign whole structure in one go.
		 */
		struct lpm_tbl24_entry new_tbl24_entry = {
				.valid = VALID,
				.ext_entry = 1,
				.depth = 0,
				{ .tbl8_gindex = tbl8_group_index, }
		};

		/*
		 * In order to ensure there's no transient packet
		 * drop, ensure that the next store doesn't overtake
		 * previous stores.
		 */
		cmm_smp_wmc();

		_CMM_STORE_SHARED(lpm->tbl24[tbl24_index], new_tbl24_entry);

	} else {
		/*
		 * If it is valid, extended entry calculate the index into tbl8.
		 */
		struct lpm_tbl8_entry new_tbl8_entry = {
			.valid_group = VALID,
			.valid = VALID,
			.depth = depth,
			.next_hop = next_hop,
		};

		tbl8_group_index = lpm->tbl24[tbl24_index].tbl8_gindex;
		tbl8_group_start = tbl8_group_index *
				LPM_TBL8_GROUP_NUM_ENTRIES;
		tbl8_index = tbl8_group_start + (ip_masked & 0xFF);

		for (i = tbl8_index; i < (tbl8_index + tbl8_range); i++) {
			if (!lpm->tbl8[i].valid ||
			    lpm->tbl8[i].depth <= depth) {
				/*
				 * Setting tbl8 entry in one go to avoid race
				 * condition
				 */
				_CMM_STORE_SHARED(lpm->tbl8[i],
						  new_tbl8_entry);
			}
		}
	}

	return 0;
}

static void add_default_route(struct lpm *lpm, uint32_t next_hop)
{
	struct lpm_tbl8_entry new_tbl_entry = {
		.next_hop = next_hop,
		.depth = 0,
		.valid = VALID,
		.valid_group = VALID,
	};

	_CMM_STORE_SHARED(lpm->tbldflt, new_tbl_entry);
}

static void del_default_route(struct lpm *lpm)
{
	struct lpm_tbl8_entry new_tbl_entry = {
		.next_hop = 0,
		.depth = 0,
		.valid = INVALID,
		.valid_group = INVALID,
	};

	_CMM_STORE_SHARED(lpm->tbldflt, new_tbl_entry);
}

/*
 * Add a route
 */
int
lpm_add(struct lpm *lpm, uint32_t ip, uint8_t depth,
	uint32_t next_hop, int16_t scope,
	struct pd_obj_state_and_flags **pd_state, uint32_t *old_next_hop,
	struct pd_obj_state_and_flags **old_pd_state)
{
	struct lpm_rule *rule_other_scope;
	struct lpm_rule *rule;
	uint32_t ip_masked;
	bool demoted = false;
	bool new;

	/* Check user arguments. */
	if ((lpm == NULL) || (depth >= LPM_MAX_DEPTH) || (pd_state == NULL))
		return -EINVAL;

	ip_masked = (ip & lpm_depth_to_mask(depth));

	rule_other_scope = rule_find_any(lpm, ip_masked, depth);

	/* Add the rule to the rule table. */
	rule = rule_add(lpm, ip_masked, depth, next_hop, scope, &new);

	/* If the is no space available for new rule return error. */
	if (rule == NULL)
		return -ENOSPC;

	if (!new)
		return LPM_ALREADY_EXISTS;
	/*
	 * If there's an existing rule for the prefix with a higher
	 * scope, then don't override it in the LPM.
	 */
	if (rule_other_scope && rule_other_scope->scope > scope) {
		/* Return the pd state for the rule we added */
		*pd_state = &rule->pd_state;
		return LPM_HIGHER_SCOPE_EXISTS;
	}

	if (depth == 0)
		add_default_route(lpm, next_hop);
	else if (depth <= MAX_DEPTH_TBL24)
		add_depth_small(lpm, ip_masked, depth, next_hop);
	else {
		/*
		 * If add fails due to exhaustion of tbl8 extensions delete
		 * rule that was added to rule table.
		 */
		int status = add_depth_big(lpm, ip_masked, depth, next_hop);
		if (status < 0) {
			rule_delete(lpm, rule, depth);
			return status;
		}
	}

	/* If we are demoting an existing rule then return details */
	if (rule_other_scope && rule_other_scope->scope < scope) {
		if (old_next_hop)
			*old_next_hop = rule_other_scope->next_hop;
		if (old_pd_state)
			*old_pd_state = &rule_other_scope->pd_state;
		demoted = true;
	}

	/* Return the pd state for the rule we added */
	*pd_state = &rule->pd_state;

	/* Notify changes to the relevant trackers */
	lpm_tracker_update(lpm, rule_other_scope, ip, depth);

	return demoted ? LPM_LOWER_SCOPE_EXISTS : LPM_SUCCESS;
}

/*
 * Find the previous rule when the current rule has already
 * been deleted.
 */
static struct lpm_rule *
find_previous_rule(struct lpm *lpm, uint32_t ip, uint8_t depth,
		   uint8_t *sub_rule_depth)
{
	struct lpm_rule *rule;
	uint32_t ip_masked;
	int prev_depth;

	for (prev_depth = depth; prev_depth >= 0; prev_depth--) {
		ip_masked = ip & lpm_depth_to_mask(prev_depth);
		rule = rule_find_any(lpm, ip_masked, prev_depth);
		if (rule) {
			*sub_rule_depth = prev_depth;
			return rule;
		}
	}

	return NULL;
}

static struct rt_tracker_info *
lpm_tracker_find_next(struct lpm_rule *rule,
		      uint32_t ip, uint8_t depth)
{
	struct rt_tracker_info key;
	uint32_t ip_masked;

	ip_masked = htonl(ip & lpm_depth_to_mask(depth));
	key.dst_addr.type = AF_INET;
	key.dst_addr.address.ip_v4.s_addr = ip_masked;

	return RB_NFIND(lpm_tracker_tree, &rule->tracker_head, &key);
}

static int
lpm_tracker_add_to_rule(struct lpm_rule *rule, uint8_t r_depth,
			struct rt_tracker_info *ti_info,
			bool route_found)
{
	if (rule->tracker_count >= UINT16_MAX)
		return -ENOMEM;

	ti_info->rule = (void *)rule;
	ti_info->r_depth = r_depth;
	ti_info->nhindex = rule->next_hop;
	ti_info->tracking = route_found;
	rule->tracker_count++;
	RB_INSERT(lpm_tracker_tree, &rule->tracker_head, ti_info);
	return 0;
}

int lpm_tracker_add(struct lpm *lpm, struct rt_tracker_info *ti_info)
{
	struct lpm_rule *rule;
	uint8_t r_depth = 0;
	int ret = 0;

	rule = find_previous_rule(lpm,
				  ntohl(ti_info->dst_addr.address.ip_v4.s_addr),
				  LPM_MAX_DEPTH - 1,
				  &r_depth);
	if (rule)
		ret = lpm_tracker_add_to_rule(rule, r_depth, ti_info, true);
	else
		ret = lpm_tracker_add_to_rule(&lpm->no_route_rule, 0, ti_info,
					      false);
	return ret;
}

void lpm_tracker_delete(struct rt_tracker_info *ti_info)
{
	struct lpm_rule *rule = ti_info->rule;

	RB_REMOVE(lpm_tracker_tree, &rule->tracker_head, ti_info);
	rule->tracker_count--;
}

static void
lpm_tracker_rule_changed(struct lpm *lpm, struct rt_tracker_info *ti_info,
			 uint8_t depth)
{
	int ret = 0;
	uint8_t new_depth = 0;
	struct lpm_rule *new_rule = NULL;
	struct lpm_rule *old_rule = (struct lpm_rule *)ti_info->rule;

	new_rule = find_previous_rule(
		lpm,
		ntohl(ti_info->dst_addr.address.ip_v4.s_addr),
		depth, &new_depth);

	if (new_rule == old_rule)
		/*
		 * Nothing changed:
		 */
		return;

	/* There is a change, clear state first */
	RB_REMOVE(lpm_tracker_tree, &old_rule->tracker_head, ti_info);

	old_rule->tracker_count--;

	if (!new_rule)
		/* Now try default */
		ret = lpm_tracker_add_to_rule(&lpm->no_route_rule, 0, ti_info,
					      false);
	else
		/* Try attaching to the new rule */
		ret = lpm_tracker_add_to_rule(new_rule, new_depth, ti_info,
					      true);

	if (ret < 0)
		RTE_LOG(ERR, LPM, "LPM failed to update tracker\n");

	ti_info->rti_cb_func(ti_info);
}

/*
 * When a new rule is added:
 *     - replacing an old one
 *           - update if it has tracker count
 *     - not replacing an old rule
 *           - see if cover has tracker count, if so update, go to the
 *             cover to see if there are any trackers that need to be
 *             moved
 */
static void
lpm_tracker_update(struct lpm *lpm, struct lpm_rule *old_rule,
		   uint32_t ip, uint8_t depth)
{
	uint8_t cover_depth = 0;
	struct lpm_rule *cover_rule;
	struct lpm_rule *tracker_rule;
	struct rt_tracker_info *ti_info, *ti_iter = NULL;
	uint32_t ip_masked;

	/*
	 * This should only be set under two conditions:
	 *
	 * 1. old rule is being deleted
	 * 2. old rule is being replaced by a higher scope rule
	 *
	 * As a result only the trackers attached to this rule
	 * should be walked
	 */
	if (old_rule) {
		if (old_rule->tracker_count == 0) {
			/*
			 * Nothing to do, don't even need to go
			 * to the cover
			 */
			return;
		}
		tracker_rule = old_rule;
	} else {
		/*
		 * New rule is added, go to its cover and walk all the trackers
		 * and see if any of them can be re-resolved
		 */
		if (depth == 0)
			goto try_default;

		cover_rule = find_previous_rule(lpm, ip, depth - 1,
						&cover_depth);
		if (!cover_rule || !cover_rule->tracker_count) {
			/* try default trackers */
			goto try_default;
		}
		tracker_rule = cover_rule;
	}

	/*
	 * walk the tree of trackers from the cover. We only need to check
	 * the trackers that have a dest within the given ip/depth.
	 */
	ti_info = lpm_tracker_find_next(tracker_rule, ip, depth);
	RB_FOREACH_FROM(ti_iter, lpm_tracker_tree, ti_info) {
		ip_masked = (ip & lpm_depth_to_mask(depth));
		if (ip_masked != ip)
			break;

		/* Tracker changed ?*/
		lpm_tracker_rule_changed(lpm, ti_iter, depth);
	}
	return;

try_default:
	/* Now see if there are any default trackers */
	if (lpm->no_route_rule.tracker_count) {

		ti_info = lpm_tracker_find_next(&lpm->no_route_rule, ip, depth);
		RB_FOREACH_FROM(ti_iter, lpm_tracker_tree, ti_info) {
			ip_masked = (ip & lpm_depth_to_mask(depth));
			if (ip_masked != ip)
				break;

			/* Tracker changed ?*/
			lpm_tracker_rule_changed(lpm, ti_iter, depth);
		}
		return;
	}
}

static void lpm_tracker_call_cbs(struct lpm_rule *rule)
{
	struct rt_tracker_info *ti_iter, *next;

	if (rule->tracker_count == 0)
		return;

	RB_FOREACH_SAFE(ti_iter, lpm_tracker_tree, &rule->tracker_head, next)
		ti_iter->rti_cb_func(ti_iter);
}

int lpm_tracker_get_cover_ip_and_depth(struct rt_tracker_info *ti_info,
				       uint32_t *ip,
				       uint8_t *depth)
{
	struct lpm_rule *rule;

	if (ti_info->rule) {
		rule = ti_info->rule;
		*ip = htonl(rule->ip);
		*depth = ti_info->r_depth;
		return ti_info->tracking &&
			rule->scope != LPM_SCOPE_PAN_DIMENSIONAL;
	}

	return 0;
}

/*
 * Find rule that covers the given rule.
 */
int
lpm_find_cover(struct lpm *lpm, uint32_t ip, uint8_t depth,
		   uint32_t *cover_ip, uint8_t *cover_depth,
		   uint32_t *cover_nh_idx)
{
	struct lpm_rule *rule;

	if (!cover_ip || !cover_depth)
		return -EINVAL;
	if (depth == 0)
		return -ENOENT;

	rule =  find_previous_rule(lpm, ip, depth - 1, cover_depth);
	if (!rule)
		return -ENOENT;

	*cover_ip = rule->ip;
	*cover_nh_idx = rule->next_hop;

	return 0;
}

static void
delete_depth_small(struct lpm *lpm, uint32_t ip_masked, uint8_t depth,
		   struct lpm_rule *sub_rule, uint8_t new_depth)
{
	uint32_t tbl24_range, tbl24_index, tbl8_group_index, tbl8_index, i, j;

	/* Calculate the range and index into Table24. */
	tbl24_range = depth_to_range(depth);
	tbl24_index = (ip_masked >> 8);

	/* Firstly check the sub_rule. */
	if (sub_rule == NULL || new_depth == 0) {
		/*
		 * If no replacement rule exists then invalidate entries
		 * associated with this rule.
		 */
		for (i = tbl24_index; i < (tbl24_index + tbl24_range); i++) {
			if (lpm->tbl24[i].ext_entry == 0) {
				if (lpm->tbl24[i].depth <= depth)
					CMM_ACCESS_ONCE(lpm->tbl24[i]).valid =
						INVALID;
			} else {
				/*
				 * If TBL24 entry is extended, then there has
				 * to be a rule with depth >= 25 in the
				 * associated TBL8 group.
				 */
				tbl8_group_index = lpm->tbl24[i].tbl8_gindex;
				tbl8_index = tbl8_group_index *
						LPM_TBL8_GROUP_NUM_ENTRIES;

				for (j = tbl8_index; j < (tbl8_index +
					LPM_TBL8_GROUP_NUM_ENTRIES); j++) {

					if (lpm->tbl8[j].valid &&
					    lpm->tbl8[j].depth <= depth)
						CMM_ACCESS_ONCE(
							lpm->tbl8[j]).valid =
							INVALID;
				}
			}
		}
	} else {
		/*
		 * If a replacement rule exists then modify entries
		 * associated with this rule.
		 */
		struct lpm_tbl24_entry new_tbl24_entry =
			TBL24_ENTRY_W_NH_INITIALIZER(
				new_depth,
				sub_rule->next_hop);

		struct lpm_tbl8_entry new_tbl8_entry = {
			.valid_group = VALID,
			.valid = VALID,
			.depth = new_depth,
			.next_hop = sub_rule->next_hop,
		};

		for (i = tbl24_index; i < (tbl24_index + tbl24_range); i++) {
			if (lpm->tbl24[i].ext_entry == 0) {
				if (lpm->tbl24[i].depth <= depth)
					_CMM_STORE_SHARED(lpm->tbl24[i],
							  new_tbl24_entry);
			} else {
				/*
				 * If TBL24 entry is extended, then there has
				 * to be a rule with depth >= 25 in the
				 * associated TBL8 group.
				 */
				tbl8_group_index = lpm->tbl24[i].tbl8_gindex;
				tbl8_index = tbl8_group_index *
						LPM_TBL8_GROUP_NUM_ENTRIES;

				for (j = tbl8_index; j < (tbl8_index +
					LPM_TBL8_GROUP_NUM_ENTRIES); j++) {
					if (!lpm->tbl8[j].valid ||
					    lpm->tbl8[j].depth <= depth)
						_CMM_STORE_SHARED(
							lpm->tbl8[j],
							new_tbl8_entry);
				}
			}
		}
	}
}

/*
 * Checks if table 8 group can be recycled.
 *
 * Return of -EEXIST means tbl8 is in use and thus can not be recycled.
 * Return of -EINVAL means tbl8 is empty and thus can be recycled
 * Return of value > -1 means tbl8 is in use but has all the same values and
 * thus can be recycled
 */
static int32_t
tbl8_recycle_check(const struct lpm_tbl8_entry *tbl8,
		   uint32_t tbl8_group_start)
{
	uint32_t tbl8_group_end, i;
	tbl8_group_end = tbl8_group_start + LPM_TBL8_GROUP_NUM_ENTRIES;

	/*
	 * Check the first entry of the given tbl8. If it is invalid we know
	 * this tbl8 does not contain any rule with a depth <= LPM_MAX_DEPTH
	 * (As they would affect all entries in a tbl8) and thus this table
	 * can not be recycled.
	 */
	if (tbl8[tbl8_group_start].valid) {
		/*
		 * If first entry is valid check if the depth is less than 24
		 * and if so check the rest of the entries to verify that they
		 * are all of this depth.
		 */
		if (tbl8[tbl8_group_start].depth <= MAX_DEPTH_TBL24) {
			for (i = (tbl8_group_start + 1); i < tbl8_group_end;
					i++) {

				if (tbl8[i].depth !=
						tbl8[tbl8_group_start].depth) {

					return -EEXIST;
				}
			}
			/* If all entries are the same return the tb8 index */
			return tbl8_group_start;
		}

		return -EEXIST;
	}
	/*
	 * If the first entry is invalid check if the rest of the entries in
	 * the tbl8 are invalid.
	 */
	for (i = (tbl8_group_start + 1); i < tbl8_group_end; i++) {
		if (tbl8[i].valid)
			return -EEXIST;
	}

	/* If no valid entries are found then return -EINVAL. */
	return -EINVAL;
}

static void
delete_depth_big(struct lpm *lpm, uint32_t ip_masked, uint8_t depth,
		 struct lpm_rule *sub_rule, uint8_t new_depth)
{
	uint32_t tbl24_index, tbl8_group_index, tbl8_group_start, tbl8_index,
			tbl8_range, i;
	int32_t tbl8_recycle_index;

	/*
	 * Calculate the index into tbl24 and range. Note: All depths larger
	 * than MAX_DEPTH_TBL24 are associated with only one tbl24 entry.
	 */
	tbl24_index = ip_masked >> 8;

	/* Calculate the index into tbl8 and range. */
	tbl8_group_index = lpm->tbl24[tbl24_index].tbl8_gindex;
	tbl8_group_start = tbl8_group_index * LPM_TBL8_GROUP_NUM_ENTRIES;
	tbl8_index = tbl8_group_start + (ip_masked & 0xFF);
	tbl8_range = depth_to_range(depth);

	if (sub_rule == NULL || new_depth == 0) {
		/*
		 * Loop through the range of entries on tbl8 for which the
		 * rule_to_delete must be removed or modified.
		 */
		for (i = tbl8_index; i < (tbl8_index + tbl8_range); i++) {
			if (lpm->tbl8[i].valid && lpm->tbl8[i].depth <= depth)
				CMM_ACCESS_ONCE(lpm->tbl8[i]).valid = INVALID;
		}
	} else {
		/* Set new tbl8 entry. */
		struct lpm_tbl8_entry new_tbl8_entry = {
			.valid_group = VALID,
			.valid = VALID,
			.depth = new_depth,
			.next_hop = sub_rule->next_hop,
		};

		/*
		 * Loop through the range of entries on tbl8 for which the
		 * rule_to_delete must be modified.
		 */
		for (i = tbl8_index; i < (tbl8_index + tbl8_range); i++) {
			if (!lpm->tbl8[i].valid || lpm->tbl8[i].depth <= depth)
				_CMM_STORE_SHARED(lpm->tbl8[i],
						  new_tbl8_entry);
		}
	}

	/*
	 * Check if there are any valid entries in this tbl8 group. If all
	 * tbl8 entries are invalid we can free the tbl8 and invalidate the
	 * associated tbl24 entry.
	 */

	tbl8_recycle_index = tbl8_recycle_check(lpm->tbl8, tbl8_group_start);
	if (tbl8_recycle_index == -EINVAL) {
		CMM_ACCESS_ONCE(lpm->tbl24[tbl24_index]).valid = INVALID;
		tbl8_free(lpm, tbl8_group_start);
	} else if (tbl8_recycle_index > -1) {
		/* Update tbl24 entry. */
		struct lpm_tbl24_entry new_tbl24_entry =
			TBL24_ENTRY_W_NH_INITIALIZER(
				lpm->tbl8[tbl8_recycle_index].depth,
				lpm->tbl8[tbl8_recycle_index].next_hop);

		/*
		 * Note: this should probably be done before updating
		 * the tbl8 entries to avoid a potential (very)
		 * transient packet drop, but it would require a
		 * little bit of thought and the potential to introduce
		 * bugs so isn't done at this point.
		 */
		_CMM_STORE_SHARED(lpm->tbl24[tbl24_index], new_tbl24_entry);
		tbl8_free(lpm, tbl8_group_start);
	}
}

/*
 * Find rule to replace the old rule, then delete the old rule from the
 * tree. Modify the lpm so that entries that used the old rule now use
 * the replacement one. If there is no rule to replace the old_rule we
 * return NULL and  invalidate the table entries associated with this rule.
 */
static int rule_replace(struct lpm *lpm, struct lpm_rule *old_rule,
			uint32_t ip, uint8_t depth,
			struct lpm_rule **new_rule)
{
	uint32_t ip_masked;
	struct lpm_rule *sub_rule, *higher_scope_rule;
	uint8_t sub_depth = 0;
	bool higher_scope_found = false;

	/* Find prev rule */
	sub_rule = RB_PREV(lpm_rules_tree, &lpm->rules[depth], old_rule);
	if (sub_rule) {
		/*
		 * If IP address the same then this is a good rule
		 * with a lower scope. Otherwise it is not, and we
		 * need to check a different depth.
		 */
		if (old_rule->ip != sub_rule->ip)
			sub_rule = NULL;
		else
			sub_depth = depth;
	}

	/*
	 * Find the next rule. If it is for the same IP address, then it
	 * is a higher scope, and therefore the rule we are deleting is
	 * not being used in the LPM, so we can delete the rule and are
	 * finished.
	 */
	higher_scope_rule = RB_NEXT(lpm_rules_tree,
				&lpm->rules[depth], old_rule);
	if (higher_scope_rule && old_rule->ip == higher_scope_rule->ip)
		higher_scope_found = true;

	/* Delete the old rule from the rule table. */
	rule_delete(lpm, old_rule, depth);
	if (higher_scope_found)
		return LPM_HIGHER_SCOPE_EXISTS;

	ip_masked = ip & lpm_depth_to_mask(depth);
	if (!sub_rule) {
		sub_rule = find_previous_rule(lpm, ip, depth, &sub_depth);
		*new_rule = NULL;
	} else {
		*new_rule = sub_rule;
	}

	/*
	 * If the input depth value is less than 25 use function
	 * delete_depth_small otherwise use delete_depth_big.
	 */
	if (depth == 0)
		del_default_route(lpm);
	else if (depth <= MAX_DEPTH_TBL24)
		delete_depth_small(lpm, ip_masked, depth, sub_rule, sub_depth);
	else
		delete_depth_big(lpm, ip_masked, depth, sub_rule, sub_depth);

	return 0;
}

/*
 * Deletes a rule
 */
int
lpm_delete(struct lpm *lpm, uint32_t ip, uint8_t depth,
	   uint32_t *next_hop, int16_t scope,
	   struct pd_obj_state_and_flags *pd_state,
	   uint32_t *new_next_hop,
	   struct pd_obj_state_and_flags **new_pd_state)
{
	struct lpm_rule *rule;
	struct lpm_rule *new_rule;
	uint32_t ip_masked;
	int rc;

	/*
	 * Check input arguments. Note: IP must be a positive integer of 32
	 * bits in length therefore it need not be checked.
	 */
	if ((lpm == NULL) || (depth >= LPM_MAX_DEPTH) || (pd_state == NULL))
		return -EINVAL;

	ip_masked = ip & lpm_depth_to_mask(depth);

	/*
	 * Find the input rule, that needs to be deleted, in the
	 * rule table.
	 */
	rule = rule_find(lpm, ip_masked, depth, scope);

	/*
	 * Check if rule_to_delete_index was found. If no rule was found the
	 * function rule_find returns -E_NO_TAILQ.
	 */
	if (rule == NULL)
		return -EINVAL;

	/*
	 * Return next hop so caller can avoid lookup.
	 */
	if (next_hop)
		*next_hop = rule->next_hop;

	*pd_state = rule->pd_state;

	/* Replace with next level up rule */
	rc = rule_replace(lpm, rule, ip, depth, &new_rule);

	if (rc == 0 && new_rule) {
		if (new_next_hop)
			*new_next_hop = new_rule->next_hop;
		if (new_pd_state)
			*new_pd_state = &new_rule->pd_state;
		return LPM_LOWER_SCOPE_EXISTS;
	}
	return rc;
}

/*
 * Delete all rules from the LPM table.
 */
void
lpm_delete_all(struct lpm *lpm, lpm_walk_func_t func, void *arg)
{
	uint8_t depth;

	/* Zero tbl24. */
	memset(lpm->tbl24, 0, sizeof(lpm->tbl24));

	/* Zero tbl8. */
	memset(lpm->tbl8, 0,
	       lpm->tbl8_num_groups * LPM_TBL8_GROUP_NUM_ENTRIES
		   * sizeof(struct lpm_tbl8_entry));
	lpm->tbl8_rover = lpm->tbl8_num_groups - 1;

	/* Delete all rules form the rules table. */
	for (depth = 0; depth < LPM_MAX_DEPTH; ++depth) {
		struct lpm_rules_tree *head = &lpm->rules[depth];
		struct lpm_rule *r, *n;
		struct lpm_walk_params params;

		RB_FOREACH_SAFE(r, lpm_rules_tree, head, n) {
			if (func) {
				params.ip = r->ip;
				params.depth = depth;
				params.scope = r->scope;
				params.next_hop = r->next_hop;

				func(lpm, &params, &r->pd_state, arg);
			}
			rule_delete(lpm, r, depth);
		}
	}
	del_default_route(lpm);
}

/*
 * Iterate over LPM rules
 */
uint32_t
lpm_walk(struct lpm *lpm, lpm_walk_func_t func,
		struct lpm_walk_arg *r_arg)
{
	uint8_t depth = r_arg->depth;
	uint32_t rule_cnt = 0;
	uint32_t ip_masked;
	bool len_match = true;
	struct lpm_walk_params params;

	for (; depth < LPM_MAX_DEPTH; depth++) {
		struct lpm_rule *r, *n;

		if (r_arg->get_next && len_match) {
			ip_masked = (r_arg->addr &
				     lpm_depth_to_mask(depth));
			n = rule_find_next(lpm, ip_masked, depth, 255);
		} else {
			struct lpm_rules_tree *head = &lpm->rules[depth];

			n = RB_MIN(lpm_rules_tree, head);
		}

		len_match = false;
		if (!n)
			continue;

		RB_FOREACH_FROM(r, lpm_rules_tree, n) {
			params.ip = r->ip;
			params.depth = depth;
			params.scope = r->scope;
			params.next_hop = r->next_hop;
			params.call_tracker_cbs = false;

			func(lpm, &params, &r->pd_state, r_arg->walk_arg);

			if (params.call_tracker_cbs)
				lpm_tracker_call_cbs(r);
			if (r_arg->is_segment && (++rule_cnt == r_arg->cnt))
				return rule_cnt;
		}

	}

	return 0;
}

/* Count usage of tbl8 */
unsigned
lpm_tbl8_count(const struct lpm *lpm)
{
	unsigned int i, count = 0;

	for (i = 0; i < lpm->tbl8_num_groups; i++) {
		const struct lpm_tbl8_entry *tbl8_entry
			= lpm->tbl8 + i * LPM_TBL8_GROUP_NUM_ENTRIES;
		if (tbl8_entry->valid_group)
			++count;
	}
	return count;
}

int
lpm_nexthop_lookup(struct lpm *lpm, uint32_t ip, uint8_t depth,
		   int16_t scope, uint32_t *next_hop)
{
	struct lpm_rule *r;
	uint32_t ip_masked;

	ip_masked = (ip & lpm_depth_to_mask(depth));
	r = rule_find(lpm, ip_masked, depth, scope);
	if (!r)
		return -ENOENT;

	*next_hop = r->next_hop;
	return 0;
}

int
lpm_lookup_exact(struct lpm *lpm, uint32_t ip, uint8_t depth,
		     uint32_t *next_hop)
{
	struct lpm_rule *r;
	uint32_t ip_masked;

	ip_masked = (ip & lpm_depth_to_mask(depth));
	r = rule_find_any(lpm, ip_masked, depth);
	if (!r)
		return -ENOENT;

	if (next_hop)
		*next_hop = r->next_hop;

	return 0;
}

static ALWAYS_INLINE int
lpm_lookup_default(const struct lpm *lpm, uint32_t *next_hop)
{
	struct lpm_tbl8_entry tbldflt  = CMM_ACCESS_ONCE(lpm->tbldflt);

	if (likely(tbldflt.valid)) {
		*next_hop = tbldflt.next_hop;
		return 0;
	}

	return -ENOENT;
}

ALWAYS_INLINE int
lpm_lookup(const struct lpm *lpm, uint32_t ip, uint32_t *next_hop)
{
	struct lpm_tbl24_entry tbl24;
	struct lpm_tbl8_entry tbl8;

	/* Copy tbl24 entry (to avoid conconcurrency issues) */
	tbl24 = CMM_ACCESS_ONCE(lpm->tbl24[ip >> 8]);

	/*
	 * Use the tbl24_index to access the required tbl24 entry then check if
	 * the tbl24 entry is INVALID, if so return -ENOENT.
	 */
	if (unlikely(!tbl24.valid))
		return lpm_lookup_default(lpm, next_hop);

	/*
	 * If tbl24 entry is valid check if it is NOT extended (i.e. it does
	 * not use a tbl8 extension) if so return the next hop.
	 */
	if (tbl24.ext_entry == 0) {
		*next_hop = lpm_tbl24_get_next_hop_idx(&tbl24);
		return 0; /* Lookup hit. */
	}

	/*
	 * If tbl24 entry is valid and extended calculate the index into the
	 * tbl8 entry.
	 */
	tbl8 = CMM_ACCESS_ONCE(
		lpm->tbl8[tbl24.tbl8_gindex * LPM_TBL8_GROUP_NUM_ENTRIES
			  + (ip & 0xFF)]);

	/* Check if the tbl8 entry is invalid and if so return -ENOENT. */
	if (unlikely(!tbl8.valid))
		return lpm_lookup_default(lpm, next_hop);

	/* If the tbl8 entry is valid return return the next_hop. */
	*next_hop = tbl8.next_hop;
	return 0; /* Lookup hit. */
}

/*
 * Do a subtree walk of the given rule.
 *
 * MUST hold the route_mutex;
 */
void lpm_subtree_walk(struct lpm *lpm,
			  uint32_t root_ip,
			  uint8_t root_depth,
			  void (*cb)(struct lpm *lpm, uint32_t ip,
				     uint8_t depth, uint32_t idx,
				     void *arg),
			  void *arg)
{
	uint8_t depth;

	/* For some strange reason the max depth is 33 */
	if (root_depth >= LPM_MAX_DEPTH - 1)
		return;
	for (depth = root_depth + 1; depth < LPM_MAX_DEPTH; depth++) {
		struct lpm_rule *r, *n;
		uint32_t masked_ip;

		n = rule_find_next(lpm, root_ip, depth, 0);

		RB_FOREACH_FROM(r, lpm_rules_tree, n) {
			masked_ip = r->ip & lpm_depth_to_mask(root_depth);
			if (masked_ip == root_ip)
				cb(lpm, r->ip, depth, r->next_hop, arg);
			else
				break;
		}
	}
}

unsigned
lpm_tbl8_free_count(const struct lpm *lpm)
{
	return lpm->tbl8_num_groups - lpm_tbl8_count(lpm);
}

bool
lpm_is_empty(const struct lpm *lpm)
{
	return lpm->rule_count == 0;
}

unsigned int
lpm_rule_count(const struct lpm *lpm)
{
	return lpm->rule_count;
}
