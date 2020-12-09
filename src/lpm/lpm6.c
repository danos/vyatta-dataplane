/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
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
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
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
#include <assert.h>
#include <bsd/sys/tree.h>
#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_prefetch.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "lpm6.h"
#include "rt_tracker.h"
#include "urcu.h"
#include "util.h"

#define LPM6_TBL8_GROUP_NUM_ENTRIES         256
#define LPM6_TBL8_INIT_GROUPS               256 /* power of 2 */
#define LPM6_TBL8_INIT_ENTRIES	       (LPM6_TBL8_INIT_GROUPS * \
						LPM6_TBL8_GROUP_NUM_ENTRIES)

#define LPM6_TBL24_NUM_ENTRIES        (1 << 24)

#define LPM6_TBL8_MAX_NUM_GROUPS      (1 << 21)

#define MAX_DEPTH_TBL24 24

#define ADD_FIRST_BYTE                            3
#define LOOKUP_FIRST_BYTE                         4
#define BYTE_SIZE                                 8
#define BYTES2_SIZE                              16

#define lpm6_tbl8_gindex next_hop

/** Flags for setting an entry as valid/invalid. */
enum valid_flag {
	INVALID = 0,
	VALID
};

/** Tbl entry structure. It is the same for both tbl24 and tbl8 */
struct lpm6_tbl_entry {
	uint32_t next_hop    :21;  /**< Next hop / next table to be checked. */
	uint32_t  depth      :8;   /**< Rule depth. */
	/* Flags. */
	uint32_t valid       :1;   /**< Validation flag. */
	uint32_t ext_entry   :1;   /**< External entry. */
	uint32_t valid_group :1;   /**< Group validation flag. */
};

/** Rules tbl entry structure. */
struct lpm6_rule {
	uint8_t ip[LPM6_IPV6_ADDR_SIZE]; /**< Rule IP address. */
	uint32_t next_hop;	/**< Rule next hop. */
	int16_t scope;		/**< Rule scope */
	uint16_t tracker_count;
	RB_ENTRY(lpm6_rule) link;
	struct pd_obj_state_and_flags pd_state;
	RB_HEAD(lpm6_tracker_tree, rt_tracker_info) tracker_head;
};

/** LPM6 structure. */
struct lpm6 {
	/* LPM metadata. */
	uint32_t id;			/**< table id */
	uint32_t number_tbl8s;           /**< Number of tbl8s to allocate. */
	uint32_t next_tbl8;              /**< Next tbl8 to be used. */
	unsigned int rule_count;         /**< num of rules **/

	RB_HEAD(lpm6_rules_tree, lpm6_rule) rules[LPM6_MAX_DEPTH+1];

	struct lpm6_rule no_route_rule; /* For storing trackers */

	/* LPM Tables. */
	struct lpm6_tbl_entry tbldflt
			__rte_cache_aligned; /* depth == 0 */
	struct lpm6_tbl_entry tbl24[LPM6_TBL24_NUM_ENTRIES]
			__rte_cache_aligned; /**< LPM tbl24 table. */
	struct lpm6_tbl_entry *tbl8;	/* Actual table */
};

static void
lpm6_tracker_update(struct lpm6 *lpm, struct lpm6_rule *old_rule,
		    const uint8_t *ip, uint8_t depth);

bool
lpm6_is_empty(const struct lpm6 *lpm)
{
	return lpm->rule_count == 0;
}

unsigned int
lpm6_rule_count(const struct lpm6 *lpm)
{
	return lpm->rule_count;
}

/* Comparison function for red-black tree nodes.
   "If the first argument is smaller than the second, the function
    returns a value smaller than zero.	If they are equal, the function
    returns zero.  Otherwise, it should return a value greater than zero."
*/
static inline int rules_cmp(const struct lpm6_rule *r1,
			    const struct lpm6_rule *r2)
{
	int rc = memcmp(r1->ip, r2->ip, LPM6_IPV6_ADDR_SIZE);

	return rc ? : r1->scope - r2->scope;
}

static inline int tracker_cmp(const struct rt_tracker_info *r1,
			      const struct rt_tracker_info *r2)
{
	return memcmp(&r1->dst_addr.address.ip_v6,
		      &r2->dst_addr.address.ip_v6, LPM6_IPV6_ADDR_SIZE);
}

#ifndef __clang_analyzer__
/* Generate internal functions and make them static. */
RB_GENERATE_STATIC(lpm6_rules_tree, lpm6_rule, link, rules_cmp)
RB_GENERATE_STATIC(lpm6_tracker_tree, rt_tracker_info, rti_tree_node,
		   tracker_cmp)
#endif /* __clang_analyzer__ */

/*
 * Takes an array of uint8_t (IPv6 address) and masks it using the depth.
 * It leaves untouched one bit per unit in the depth variable
 * and set the rest to 0.
 */
static inline void
mask_ip6(uint8_t *masked_ip, const uint8_t *ip, uint8_t depth)
{
	int16_t part_depth = depth;
	int i;

	/* Copy the IP and mask it to avoid modifying user's input data. */
	for (i = 0; i < LPM6_IPV6_ADDR_SIZE; i++) {
		if (part_depth < BYTE_SIZE && part_depth >= 0) {
			int16_t mask = (uint16_t)(~(UINT8_MAX >> part_depth));

			masked_ip[i] = ip[i] & mask;
		} else if (part_depth < 0) {
			masked_ip[i] = 0;
		} else {
			masked_ip[i] = ip[i];
		}
		part_depth -= BYTE_SIZE;
	}
}

/*
 * Allocates memory for LPM object
 */
struct lpm6 *
lpm6_create(uint32_t tableid)
{
	struct lpm6 *lpm = NULL;
	uint8_t depth;

	RTE_BUILD_BUG_ON(sizeof(struct lpm6_tbl_entry) != sizeof(uint32_t));

	/* Allocate memory to store the LPM data structures. */
	lpm = malloc_huge_aligned(sizeof(*lpm));

	if (lpm == NULL) {
		RTE_LOG(ERR, LPM, "LPM memory allocation failed\n");
		goto exit;
	}

	/* Vyatta change to use red-black tree */
	for (depth = 0; depth <= LPM6_MAX_DEPTH; ++depth)
		RB_INIT(&lpm->rules[depth]);

	lpm->id = tableid;
	lpm->number_tbl8s = LPM6_TBL8_INIT_GROUPS;
	lpm->next_tbl8 = LPM6_TBL8_INIT_GROUPS - 1;
	lpm->tbl8 = malloc_huge_aligned(LPM6_TBL8_INIT_ENTRIES *
					sizeof(struct lpm6_tbl_entry));

	if (lpm->tbl8 == NULL) {
		RTE_LOG(ERR, LPM, "LPM tbl8 group allocation failed\n");
		free_huge(lpm, sizeof(*lpm));
		lpm = NULL;
		goto exit;
	}

	memset(&lpm->no_route_rule, 0, sizeof(lpm->no_route_rule));
	RB_INIT(&lpm->no_route_rule.tracker_head);
exit:
	return lpm;
}

uint32_t
lpm6_get_id(struct lpm6 *lpm)
{
	return lpm->id;
}

/*
 * Deallocates memory for given LPM table.
 */
void
lpm6_free(struct lpm6 *lpm)
{
	/* Check user arguments. */
	if (lpm == NULL)
		return;

	free_huge(lpm->tbl8, (lpm->number_tbl8s *
			      LPM6_TBL8_GROUP_NUM_ENTRIES *
			      sizeof(struct lpm6_tbl_entry)));
	free_huge(lpm, sizeof(*lpm));
}

/*
 * Finds a rule in rule table.
 * NOTE: Valid range for depth parameter is 1 .. 128 inclusive.
 */
static struct lpm6_rule *
rule_find(struct lpm6 *lpm, const uint8_t *ip,
	  uint8_t depth, int16_t scope)
{
	struct lpm6_rules_tree *head = &lpm->rules[depth];
	struct lpm6_rule k;

	memcpy(k.ip, ip, LPM6_IPV6_ADDR_SIZE);
	k.scope = scope;

	return RB_FIND(lpm6_rules_tree, head, &k);
}

static struct lpm6_rule *
rule_find_next(struct lpm6 *lpm, const uint8_t *ip,
	       uint8_t depth, int16_t scope)
{
	struct lpm6_rules_tree *head = &lpm->rules[depth];
	struct lpm6_rule k;

	memcpy(k.ip, ip, LPM6_IPV6_ADDR_SIZE);
	k.scope = scope;

	return RB_NFIND(lpm6_rules_tree, head, &k);
}

/* Finds rule in table in scope order */
static struct lpm6_rule *
rule_find_any(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth)
{
	struct lpm6_rule *r;

	/*
	 * Search RB tree for entry after the ip with max scope.
	 * If it finds an entry then get the prev entry, and if ip addr
	 * matches we have a match with highest scope.
	 * If it doesn't find an entry check the last value in the
	 * tree, and if the ip addr matches, we have the best match.
	 */
	r = rule_find_next(lpm, ip, depth, 255);
	if (r)
		r = RB_PREV(lpm6_rules_tree, &lpm->rules[depth], r);
	else
		r = RB_MAX(lpm6_rules_tree, &lpm->rules[depth]);

	if (r && memcmp(ip, r->ip, LPM6_IPV6_ADDR_SIZE))
		return NULL;

	return r;
}

/*
 * Checks if a rule already exists in the rules table and updates
 * the nexthop if so. Otherwise it adds a new rule if enough space is available.
 */
static struct lpm6_rule *
rule_add(struct lpm6 *lpm, uint8_t *ip, uint32_t next_hop,
	 uint8_t depth, int16_t scope)
{
	struct lpm6_rules_tree *head = &lpm->rules[depth];
	struct lpm6_rule *r, *old;

	/*
	 * NB: uses regular malloc to avoid chewing up precious
	 *  memory pool space for rules.
	 */
	r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	memcpy(r->ip, ip, LPM6_IPV6_ADDR_SIZE);
	r->next_hop = next_hop;
	r->scope = scope;
	r->tracker_count = 0;
	memset(&r->pd_state, 0, sizeof(r->pd_state));
	RB_INIT(&r->tracker_head);

	old = RB_INSERT(lpm6_rules_tree, head, r);
	if (!old) {
		lpm->rule_count++;
		return r;
	}

	/* collision with existing rule */
	free(r);
	return old;
}

/*
 * Function that expands a rule across the data structure when a less-generic
 * one has been added before. It assures that every possible combination of bits
 * in the IP address returns a match.
 */
static void
expand_rule(struct lpm6 *lpm, uint32_t tbl8_gindex, uint8_t depth,
	    uint32_t next_hop)
{
	uint32_t tbl8_group_end, tbl8_gindex_next, j;

	tbl8_group_end = tbl8_gindex + LPM6_TBL8_GROUP_NUM_ENTRIES;

	struct lpm6_tbl_entry new_tbl8_entry = {
		.valid = VALID,
		.depth = depth,
		.next_hop = next_hop,
		.ext_entry = 0,
		.valid_group = VALID,
	};

	for (j = tbl8_gindex; j < tbl8_group_end; j++) {
		if (!lpm->tbl8[j].valid || (lpm->tbl8[j].ext_entry == 0
				&& lpm->tbl8[j].depth <= depth)) {

			_CMM_STORE_SHARED(lpm->tbl8[j], new_tbl8_entry);

		} else if (lpm->tbl8[j].ext_entry == 1) {

			tbl8_gindex_next = lpm->tbl8[j].lpm6_tbl8_gindex
					* LPM6_TBL8_GROUP_NUM_ENTRIES;
			expand_rule(lpm, tbl8_gindex_next, depth, next_hop);
		}
	}
}

/*
 * TBL8 managing routines
 */
static int
tbl8_grow(struct lpm6 *lpm)
{
	size_t old_size, new_size;
	struct lpm6_tbl_entry *new_tbl8;

	if (lpm->number_tbl8s >= LPM6_TBL8_MAX_NUM_GROUPS) {
		RTE_LOG(ERR, LPM, "LPM6: Unable to grow tbl8s, already at %u\n",
			lpm->number_tbl8s);
		return -ENOMEM;
	}

	old_size = lpm->number_tbl8s;
	new_size = old_size << 1;
	new_tbl8 = malloc_huge_aligned(new_size *
				       LPM6_TBL8_GROUP_NUM_ENTRIES *
				       sizeof(struct lpm6_tbl_entry));

	if (new_tbl8 == NULL) {
		RTE_LOG(ERR, LPM, "LPM6 tbl8 group expand allocation failed\n");
		return -ENOMEM;
	}

	memcpy(new_tbl8, lpm->tbl8,
	       old_size * LPM6_TBL8_GROUP_NUM_ENTRIES *
	       sizeof(struct lpm6_tbl_entry));

	if (defer_rcu_huge(lpm->tbl8, old_size *
			   LPM6_TBL8_GROUP_NUM_ENTRIES *
			   sizeof(struct lpm6_tbl_entry))) {
		RTE_LOG(ERR, LPM, "Failed to free v6 LPM tbl8 group\n");
		return -1;
	}

	/* swap in new table */
	rcu_assign_pointer(lpm->tbl8, new_tbl8);
	lpm->number_tbl8s = new_size;

	return 0;
}

uint32_t
lpm6_tbl8_used_count(const struct lpm6 *lpm)
{
	uint32_t i, count = 0;

	for (i = 0; i < lpm->number_tbl8s; i++) {
		const struct lpm6_tbl_entry *tbl8_entry
			= lpm->tbl8 + i * LPM6_TBL8_GROUP_NUM_ENTRIES;
		if (tbl8_entry->valid_group)
			++count;
	}
	return count;
}

uint32_t
lpm6_tbl8_unused_count(const struct lpm6 *lpm)
{
	return lpm->number_tbl8s - lpm6_tbl8_used_count(lpm);
}

static int32_t
tbl8_alloc(struct lpm6 *lpm)
{
	uint32_t tbl8_gindex; /* tbl8 group index. */
	struct lpm6_tbl_entry *tbl8_entry;

	/* Scan through tbl8 to find a free (i.e. INVALID) tbl8 group. */
	for (tbl8_gindex = (lpm->next_tbl8 + 1) & (lpm->number_tbl8s - 1);
	     tbl8_gindex != lpm->next_tbl8;
	     tbl8_gindex = (tbl8_gindex + 1) & (lpm->number_tbl8s - 1)) {
		tbl8_entry = lpm->tbl8
			+ tbl8_gindex * LPM6_TBL8_GROUP_NUM_ENTRIES;

		/* If a free tbl8 group is found clean it and set as VALID. */
		if (likely(!tbl8_entry->valid_group))
			goto found;
	}

	/* Out of space expand */
	tbl8_gindex = lpm->number_tbl8s;
	if (tbl8_grow(lpm) < 0)
		return -ENOSPC;

	tbl8_entry = lpm->tbl8
		+ tbl8_gindex * LPM6_TBL8_GROUP_NUM_ENTRIES;
found:
	memset(tbl8_entry, 0,
	       LPM6_TBL8_GROUP_NUM_ENTRIES * sizeof(tbl8_entry[0]));

	tbl8_entry->valid_group = VALID;

	/* Remember last slot to start looking there */
	lpm->next_tbl8 = tbl8_gindex;

	/* Return group index for allocated tbl8 group. */
	return tbl8_gindex;
}

static inline void
tbl8_free(struct lpm6 *lpm, uint32_t tbl8_group_start)
{
	/* Set tbl8 group invalid*/
	lpm->tbl8[tbl8_group_start].valid_group = INVALID;
}

struct lpm6_tbl_context {
	bool tbl8;
	uint32_t tbl_index;
};

static struct lpm6_tbl_entry *
tbl_entry_get(struct lpm6 *lpm, const struct lpm6_tbl_context *tbl_ctx)
{
	return tbl_ctx->tbl8 ? &lpm->tbl8[tbl_ctx->tbl_index] :
		&lpm->tbl24[tbl_ctx->tbl_index];
}

/*
 * Partially adds a new route to the data structure (tbl24+tbl8s).
 * It returns 0 on success, a negative number on failure, or 1 if
 * the process needs to be continued by calling the function again.
 */
static int
add_step(struct lpm6 *lpm, const struct lpm6_tbl_context *tbl_ctx,
	 struct lpm6_tbl_context *tbl_ctx_next, const uint8_t *ip,
	 uint8_t bytes, uint8_t first_byte, uint8_t depth,
	 uint32_t next_hop)
{
	uint32_t tbl_index, tbl_range, tbl8_group_start, tbl8_group_end, i;
	struct lpm6_tbl_entry *tbl;
	int32_t tbl8_gindex;
	int8_t bitshift;
	uint8_t bits_covered;

	/* Default route */
	if (depth == 0) {
		/*
		 * Update default tbl entry. Note: The ext_flag and tbl8_index
		 * need to be updated simultaneously, so assign whole structure
		 * in one go.
		 */
		struct lpm6_tbl_entry new_tbl_entry = {
			.next_hop = next_hop,
			.depth = depth,
			.valid = VALID,
			.ext_entry = 0,
			.valid_group = VALID,
		};

		_CMM_STORE_SHARED(lpm->tbldflt, new_tbl_entry);
		return 0;
	}

	/*
	 * Calculate index to the table based on the number and position
	 * of the bytes being inspected in this step.
	 */
	tbl_index = 0;
	for (i = first_byte; i < (uint32_t)(first_byte + bytes); i++) {
		uint32_t temp_i = i - 1; /* work around coverity issue */

		bitshift = (int8_t)((bytes - i)*BYTE_SIZE);

		if (bitshift < 0) bitshift = 0;
		tbl_index = tbl_index | ip[temp_i] << bitshift;
	}

	/* Number of bits covered in this step */
	bits_covered = (uint8_t)((bytes+first_byte-1)*BYTE_SIZE);

	/*
	 * If depth if smaller than this number (ie this is the last step)
	 * expand the rule across the relevant positions in the table.
	 */
	if (depth <= bits_covered) {
		tbl_range = 1 << (bits_covered - depth);
		tbl = tbl_entry_get(lpm, tbl_ctx);

		for (i = tbl_index; i < (tbl_index + tbl_range); i++) {
			if (!tbl[i].valid || (tbl[i].ext_entry == 0 &&
					tbl[i].depth <= depth)) {

				struct lpm6_tbl_entry new_tbl_entry = {
					.next_hop = next_hop,
					.depth = depth,
					.valid = VALID,
					.ext_entry = 0,
					.valid_group = VALID,
				};

				_CMM_STORE_SHARED(tbl[i], new_tbl_entry);

			} else if (tbl[i].ext_entry == 1) {

				/*
				 * If tbl entry is valid and extended calculate the index
				 * into next tbl8 and expand the rule across the data structure.
				 */
				tbl8_gindex = tbl[i].lpm6_tbl8_gindex *
						LPM6_TBL8_GROUP_NUM_ENTRIES;
				expand_rule(lpm, tbl8_gindex, depth, next_hop);
			}
		}

		return 0;
	}

	/*
	 * If this is not the last step just fill one position
	 * and calculate the index to the next table.
	 */
	/* If it's invalid a new tbl8 is needed */
	if (!tbl_entry_get(lpm, tbl_ctx)[tbl_index].valid) {
		tbl8_gindex = tbl8_alloc(lpm);
		if (tbl8_gindex < 0)
			return -ENOSPC;

		struct lpm6_tbl_entry new_tbl_entry = {
			.lpm6_tbl8_gindex = tbl8_gindex,
			.depth = 0,
			.valid = VALID,
			.ext_entry = 1,
			.valid_group = VALID,
		};

		_CMM_STORE_SHARED(
			tbl_entry_get(lpm, tbl_ctx)[tbl_index],
			new_tbl_entry);
	}
	/*
	 * If it's valid but not extended the rule that was stored *
	 * here needs to be moved to the next table.
	 */
	else if (tbl_entry_get(lpm, tbl_ctx)[tbl_index].ext_entry == 0) {
		tbl8_gindex = tbl8_alloc(lpm);
		if (tbl8_gindex < 0)
			return -ENOSPC;

		tbl8_group_start = tbl8_gindex *
			LPM6_TBL8_GROUP_NUM_ENTRIES;
		tbl8_group_end = tbl8_group_start +
			LPM6_TBL8_GROUP_NUM_ENTRIES;

		/*
		 * be careful to only retrieve this after the
		 * tbl8_alloc
		 */
		tbl = tbl_entry_get(lpm, tbl_ctx);

		/* Populate new tbl8 with tbl value. */
		for (i = tbl8_group_start; i < tbl8_group_end; i++) {
			lpm->tbl8[i].valid = VALID;
			lpm->tbl8[i].depth = tbl[tbl_index].depth;
			lpm->tbl8[i].next_hop = tbl[tbl_index].next_hop;
			lpm->tbl8[i].ext_entry = 0;
		}

		/*
		 * Update tbl entry to point to new tbl8 entry. Note: The
		 * ext_flag and tbl8_index need to be updated simultaneously,
		 * so assign whole structure in one go.
		 */
		struct lpm6_tbl_entry new_tbl_entry = {
			.lpm6_tbl8_gindex = tbl8_gindex,
			.depth = 0,
			.valid = VALID,
			.ext_entry = 1,
			.valid_group = VALID,
		};

		_CMM_STORE_SHARED(tbl[tbl_index], new_tbl_entry);
	}

	tbl_ctx_next->tbl8 = true;
	tbl_ctx_next->tbl_index =
		tbl_entry_get(lpm, tbl_ctx)[tbl_index].lpm6_tbl8_gindex *
		LPM6_TBL8_GROUP_NUM_ENTRIES;

	return 1;
}

/*
 * Add a route
 */
int
lpm6_add(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
	 uint32_t next_hop, int16_t scope,
	 struct pd_obj_state_and_flags **pd_state,
	 uint32_t *old_next_hop,
	 struct pd_obj_state_and_flags **old_pd_state)
{
	struct lpm6_rule *rule_other_scope;
	struct lpm6_tbl_context tbl_ctx;
	struct lpm6_tbl_context tbl_ctx_next;
	struct lpm6_rule *rule;
	int status;
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];
	int i;
	bool demoted = false;

	/* Check user arguments. */
	if ((lpm == NULL) || (depth > LPM6_MAX_DEPTH) || (pd_state == NULL))
		return -EINVAL;

	mask_ip6(masked_ip, ip, depth);

	rule_other_scope = rule_find_any(lpm, masked_ip, depth);

	/* Add the rule to the rule table. */
	rule = rule_add(lpm, masked_ip, next_hop, depth, scope);

	/* If there is no space available for new rule return error. */
	if (rule == NULL)
		return -ENOSPC;

	/*
	 * If there's an existing rule for the prefix with a higher
	 * scope, then don't override it in the LPM.
	 */
	if (rule_other_scope && rule_other_scope->scope > scope) {
		/* Return the pd state for the rule we added */
		*pd_state = &rule->pd_state;
		return LPM_HIGHER_SCOPE_EXISTS;
	}

	tbl_ctx.tbl8 = false;
	tbl_ctx.tbl_index = 0;

	status = add_step(lpm, &tbl_ctx, &tbl_ctx_next, masked_ip,
			  ADD_FIRST_BYTE, 1, depth, next_hop);
	if (status < 0) {
		lpm6_delete(lpm, masked_ip, depth, NULL, scope, NULL,
				NULL, NULL);
		return status;
	}

	/*
	 * Inspect one by one the rest of the bytes until
	 * the process is completed.
	 */
	for (i = ADD_FIRST_BYTE; i < LPM6_IPV6_ADDR_SIZE && status == 1; i++) {
		tbl_ctx = tbl_ctx_next;
		status = add_step(lpm, &tbl_ctx, &tbl_ctx_next,
				  masked_ip, 1, (uint8_t)(i+1), depth,
				  next_hop);
		if (status < 0) {
			lpm6_delete(lpm, masked_ip, depth, NULL, scope,
					NULL, NULL, NULL);
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
	lpm6_tracker_update(lpm, rule_other_scope, ip, depth);

	return demoted ? LPM_LOWER_SCOPE_EXISTS : LPM_SUCCESS;
}

/* Check for default route. */
static ALWAYS_INLINE int
lookup_tbldflt(const struct lpm6_tbl_entry *tbl, uint32_t *next_hop)
{
	struct lpm6_tbl_entry tbl_entry = CMM_ACCESS_ONCE(*tbl);

	if (tbl_entry.valid) {
		*next_hop = tbl_entry.next_hop;
		return 0;
	}
	return -ENOENT;
}

/*
 * Takes a pointer to a table entry and inspect one level.
 * The function returns 0 on lookup success, ENOENT if no match was found
 * or 1 if the process needs to be continued by calling the function again.
 */
static ALWAYS_INLINE int
lookup_step(const struct lpm6 *lpm, const struct lpm6_tbl_entry *tbl,
		const struct lpm6_tbl_entry **tbl_next, const uint8_t *ip,
		uint8_t first_byte, uint32_t *next_hop)
{
	struct lpm6_tbl_entry tbl_entry;

	/* Take the integer value from the pointer. */
	tbl_entry = CMM_ACCESS_ONCE(*tbl);

	/* If it is valid and extended we calculate the new pointer to return. */
	if (!tbl_entry.valid)
		return -ENOENT;
	if (tbl_entry.ext_entry) {
		uint32_t tbl8_index = ip[first_byte-1]
			+ tbl_entry.next_hop * LPM6_TBL8_GROUP_NUM_ENTRIES;

		*tbl_next = &lpm->tbl8[tbl8_index];
		return 1;
	}
	/* If not extended then we can have a match. */
	*next_hop = tbl_entry.next_hop;
	return 0;
}

/*
 * Prefetch an IP for later lookup
 */
void
lpm6_prefetch(struct lpm6 *lpm, const uint8_t *ip)
{
	struct lpm6_tbl_entry *tbl;
	uint32_t tbl24_index;

	tbl24_index = (ip[0] << BYTES2_SIZE) | (ip[1] << BYTE_SIZE) | ip[2];

	/* Calculate pointer to the first entry to be inspected */
	tbl = &lpm->tbl24[tbl24_index];

	rte_prefetch1(tbl);
}

/*
 * Looks up an IP
 */
ALWAYS_INLINE int
lpm6_lookup(const struct lpm6 *lpm, const uint8_t *ip,
		uint32_t *next_hop)
{
	const struct lpm6_tbl_entry *tbl;
	const struct lpm6_tbl_entry *tbl_next = NULL;
	int status;
	uint8_t first_byte;
	uint32_t tbl24_index;

	first_byte = LOOKUP_FIRST_BYTE;
	tbl24_index = (ip[0] << BYTES2_SIZE) | (ip[1] << BYTE_SIZE) | ip[2];

	/* Calculate pointer to the first entry to be inspected */
	tbl = &lpm->tbl24[tbl24_index];

	do {
		/* Continue inspecting following levels until success or failure */
		status = lookup_step(lpm, tbl, &tbl_next, ip, first_byte++, next_hop);
		tbl = tbl_next;
	} while (status == 1);

	/* If a more specific route was not found check for a default route. */
	if (status == -ENOENT) {
		status = lookup_tbldflt(&lpm->tbldflt, next_hop);
	}

	return status;
}

/*
 * Looks up an next-hop
 */
int
lpm6_nexthop_lookup(struct lpm6 *lpm, const uint8_t *ip,
			uint8_t depth, int16_t scope, uint32_t *next_hop)
{
	struct lpm6_rule *rule;
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];

	mask_ip6(masked_ip, ip, depth);

	rule = rule_find(lpm, masked_ip, depth, scope);
	if (!rule)
		return -ENOENT;

	*next_hop = rule->next_hop;
	return 0;
}

int
lpm6_lookup_exact(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
		      uint32_t *next_hop)
{
	struct lpm6_rule *r;
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];

	mask_ip6(masked_ip, ip, depth);

	r = rule_find_any(lpm, masked_ip, depth);
	if (!r)
		return -ENOENT;

	if (next_hop)
		*next_hop = r->next_hop;

	return 0;
}

/*
 * Delete a rule from the rule table.
 * NOTE: Valid range for depth parameter is 1 .. 128 inclusive.
 */
static void
rule_delete(struct lpm6 *lpm, struct lpm6_rule *r, uint8_t depth)
{
	struct lpm6_rules_tree *head = &lpm->rules[depth];

	RB_REMOVE(lpm6_rules_tree, head, r);
	lpm->rule_count--;
	/* Notify changes to relevant trackers */
	lpm6_tracker_update(lpm, r, r->ip, depth);
	assert(r->tracker_count == 0);
	free(r);
}

static struct lpm6_rule *
find_previous_rule(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
		   uint8_t *sub_rule_depth)
{
	struct lpm6_rule *rule;
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];
	int prev_depth;

	for (prev_depth = depth; prev_depth >= 0; prev_depth--) {
		mask_ip6(masked_ip, ip, prev_depth);
		rule = rule_find_any(lpm, masked_ip, prev_depth);
		if (rule) {
			*sub_rule_depth = prev_depth;
			return rule;
		}
	}

	return NULL;
}

/*
 * Find rule that covers the given rule.
 */
int
lpm6_find_cover(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
		    uint8_t *cover_ip, uint8_t *cover_depth,
		    uint32_t *cover_nh_idx)
{
	struct lpm6_rule *rule;

	if (!cover_ip || !cover_depth)
		return -EINVAL;
	if (depth == 0)
		return -ENOENT;

	rule =  find_previous_rule(lpm, ip, depth - 1, cover_depth);
	if (!rule)
		return -ENOENT;

	memcpy(cover_ip, rule->ip, LPM6_IPV6_ADDR_SIZE);
	*cover_nh_idx = rule->next_hop;

	return 0;
}

static inline uint32_t __attribute__((pure))
depth_to_range(uint8_t depth)
{
	int r;

	/*
	 * Calculate tbl24 range. (Note: 2^depth = 1 << depth)
	 */
	if (depth <= MAX_DEPTH_TBL24)
		return 1 << (MAX_DEPTH_TBL24 - depth);

	/*
	 * Else if depth is greater than 24,
	 * find the range across a single tbl8
	 */
	r = depth % 8;
	if (r == 0)
		return 1;

	return 1 << (8 - r);
}

static uint8_t step_count_to_depth(uint32_t i)
{
	return 24 + (i * 8);
}

/*
 * Checks if table 8 group can be recycled.
 *
 * Return of -EEXIST means tbl8 is in use and thus can not be recycled.
 * Return of -EINVAL means tbl8 is empty and thus can be recycled
 * Return of value > -1 means tbl8 is in use but has all the same values
 * (which are not extended) and thus can be recycled
 */
static int32_t
tbl8_recycle_check(const struct lpm6_tbl_entry *tbl8,
		   uint32_t tbl8_group_start,
		   uint8_t depth_prev_step)
{
	uint32_t tbl8_group_end, i;

	tbl8_group_end = tbl8_group_start + LPM6_TBL8_GROUP_NUM_ENTRIES;
	/*
	 * Check the first entry of the given tbl8. If it is invalid we know
	 * this tbl8 does not contain any rule with a depth < LPM_MAX_DEPTH
	 *  (As they would affect all entries in a tbl8) and thus this table
	 *  can not be recycled.
	 */
	if (tbl8[tbl8_group_start].valid) {
		/*
		 * If first entry is valid check that its depth is less
		 * than the previous (less specific) step.  If it is we
		 * can recycle only if all entries are the same.
		 */
		if (tbl8[tbl8_group_start].depth <= depth_prev_step) {
			for (i = tbl8_group_start; i < tbl8_group_end; i++) {
				if (tbl8[i].ext_entry)
					return -EEXIST;

				if (tbl8[i].depth !=
				    tbl8[tbl8_group_start].depth)
					return -EEXIST;
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

static void tbl8_recycle(struct lpm6 *lpm, const uint32_t indices[],
			int index_count)
{
	uint32_t i, j;
	int32_t recycle_index;
	uint32_t tbl8_group_start, tbl8_group_end;

	for (i = index_count - 1; index_count > 1 && i > 0; i--) {
		tbl8_group_start = indices[i] & ~0xff;
		recycle_index = tbl8_recycle_check(lpm->tbl8,
						   tbl8_group_start,
						   step_count_to_depth(i - 1));
		if (recycle_index == -EINVAL) {
			if (i == 1)
				CMM_ACCESS_ONCE(
					lpm->tbl24[indices[0]]).valid =
					INVALID;
			else
				CMM_ACCESS_ONCE(
					lpm->tbl8[indices[i-1]]).valid =
					INVALID;
			tbl8_free(lpm, tbl8_group_start);
		}  else if (recycle_index > -1) {
			/* All entries are the same, so can collapse */
			struct lpm6_tbl_entry collapse_entry = {
				.valid = VALID,
				.ext_entry = 0,
				.depth = lpm->tbl8[indices[i]].depth,
				.next_hop = lpm->tbl8[indices[i]].next_hop,
				.valid_group = VALID,
			};
			tbl8_group_end = tbl8_group_start +
				LPM6_TBL8_GROUP_NUM_ENTRIES;
			for (j = tbl8_group_start; j < tbl8_group_end; j++)
				lpm->tbl8[j].valid = INVALID;

			if (i == 1)
				CMM_STORE_SHARED(lpm->tbl24[indices[0]],
						 collapse_entry);
			else
				CMM_STORE_SHARED(lpm->tbl8[indices[i-1]],
						 collapse_entry);
			tbl8_free(lpm, tbl8_group_start);
		} else
			return;
	}
}

/*
 * Recursively walk the tbl8s that are extended, and invalidate entries
 * with a matching depth.
 */
static void
invalidate_ext_entries(struct lpm6 *lpm,
		       uint32_t tbl8_start, uint8_t depth)
{
	uint32_t tbl8_end = tbl8_start + LPM6_TBL8_GROUP_NUM_ENTRIES;
	uint32_t i;

	for (i = (tbl8_start); i < tbl8_end; i++) {
		if (lpm->tbl8[i].ext_entry)
			invalidate_ext_entries(lpm,
					       lpm->tbl8[i].next_hop *
					       LPM6_TBL8_GROUP_NUM_ENTRIES,
					       depth);
		else if (lpm->tbl8[i].depth == depth)
			CMM_ACCESS_ONCE(lpm->tbl8[i]).valid = INVALID;
	}
}

/*
 * Recursively walk the tbl8s that are extended, and modify entries
 * with a matching depth.
 */
static void
modify_ext_entries(struct lpm6 *lpm,
		   uint32_t tbl8_start, uint8_t old_depth, uint8_t new_depth,
		   uint32_t next_hop)
{
	uint32_t tbl8_end = tbl8_start + LPM6_TBL8_GROUP_NUM_ENTRIES;
	uint32_t i;

	struct lpm6_tbl_entry new_tbl_entry = {
		.valid = VALID,
		.ext_entry = 0,
		.depth = new_depth,
		.next_hop = next_hop,
		.valid_group = VALID,
	};

	for (i = (tbl8_start); i < tbl8_end; i++) {
		assert(lpm->tbl8[i].valid);
		if (lpm->tbl8[i].ext_entry) {
			modify_ext_entries(lpm,
					   lpm->tbl8[i].next_hop *
					   LPM6_TBL8_GROUP_NUM_ENTRIES,
					   old_depth, new_depth, next_hop);
		} else {
			if (lpm->tbl8[i].depth == old_depth)
				CMM_STORE_SHARED(lpm->tbl8[i], new_tbl_entry);
		}
	}
}

static void
delete_rule(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
	    struct lpm6_rule *sub_rule, uint8_t new_depth)
{
	uint8_t first_byte;
	uint32_t tbl24_index, tbl24_range;
	uint32_t tbl8_range, tbl8_index = 0;
	/*
	 * stack of indices to tables. First one is index into tbl24,
	 * following ones are the indices to the entry in each tbl8.
	 * Start of tbl8 found by (index & ~0xff)
	 */
	uint32_t indices[14] = { 0 };
	int index_count = 0;
	struct lpm6_tbl_entry *tbl;
	struct lpm6_tbl_entry tbl_entry;
	uint32_t i;
	uint32_t walked_depth = 24;

	/*
	 * Find the lpm entry for the prefix we are deleting, and store all
	 * the tables we traverse in the table stack.
	 */
	first_byte = LOOKUP_FIRST_BYTE;
	tbl24_index = (ip[0] << BYTES2_SIZE) | (ip[1] << BYTE_SIZE) | ip[2];
	indices[index_count++] = tbl24_index;

	/* Calculate pointer to the first entry to be inspected */
	tbl = &lpm->tbl24[tbl24_index];

	do {
		if (walked_depth >= depth)
			break;

		/* Continue inspecting levels until success or failure */
		tbl_entry = CMM_ACCESS_ONCE(*tbl);

		if (!tbl_entry.valid)
			return;

		if (tbl_entry.ext_entry) {
			/* find next tbl8 */
			tbl8_index = tbl_entry.next_hop *
				LPM6_TBL8_GROUP_NUM_ENTRIES +
				ip[first_byte-1];
			indices[index_count++] = tbl8_index;

			tbl = &lpm->tbl8[tbl8_index];
		} else {
			/* not extended, therefore a match */
			break;
		}
		first_byte++;
		walked_depth += 8;
	} while (true);

	if (sub_rule == NULL || new_depth == 0) {
		/*  - have no cover (or cover is default route)
		 *    - invalidate entry for this rule.
		 *    - if the entry is extended then invalidate all entries
		 *      down until we find the more specific entry. This will
		 *      be everything that is valid but with a depth > the
		 *      depth being removed.
		 */
		if (depth <= 24) {
			tbl24_range = depth_to_range(depth);

			/*
			 * Invalidate entries associated with this rule unless
			 * there is a more specific rule.
			 */
			for (i = tbl24_index;
			     i < (tbl24_index + tbl24_range); i++) {
				if (lpm->tbl24[i].ext_entry == 0) {
					if (lpm->tbl24[i].depth <= depth)
						CMM_ACCESS_ONCE(
							lpm->tbl24[i]).valid =
							INVALID;
				} else {
					/* Are extended */
					invalidate_ext_entries(
						lpm,
						lpm->tbl24[i].next_hop *
						LPM6_TBL8_GROUP_NUM_ENTRIES,
						depth);
				}
			}

		} else {
			/* depth is greater than 24. */
			tbl8_range = depth_to_range(depth);

			for (i = tbl8_index; i <
				     (tbl8_index + tbl8_range); i++) {
				if (lpm->tbl8[i].valid &&
				    lpm->tbl8[i].depth <= depth &&
				    !lpm->tbl8[i].ext_entry)
					CMM_ACCESS_ONCE(lpm->tbl8[i]).valid =
						INVALID;
				else if (lpm->tbl8[i].valid &&
					lpm->tbl8[i].ext_entry) {
					/*
					 * Walk the extended entries
					 * looking for entries of this depth to
					 * invalidate.
					 */
					invalidate_ext_entries(
						lpm,
						lpm->tbl8[i].next_hop *
						LPM6_TBL8_GROUP_NUM_ENTRIES,
						depth);
				}
			}
			tbl8_recycle(lpm, indices, index_count);
		}

	} else {
		/* We have a sub rule. */
		struct lpm6_tbl_entry new_tbl_entry = {
			.valid = VALID,
			.ext_entry = 0,
			.depth = new_depth,
			.next_hop = sub_rule->next_hop,
			.valid_group = VALID,
		};

		if (depth <= 24) {
			/*
			 * Removing something from the tbl24 which has a
			 * cover in the tbl24.
			 */
			tbl24_range = depth_to_range(depth);

			/*
			 * Loop through the tbl24 entries for this depth.
			 * Recursively look at extended entries searching
			 * for this depth, and set them to the cover instead.
			 */
			for (i = tbl24_index;
			     i < (tbl24_index + tbl24_range); i++) {
				if (lpm->tbl24[i].ext_entry == 0) {
					if (lpm->tbl24[i].depth <= depth)
						/* Replace with the cover */
						CMM_STORE_SHARED(lpm->tbl24[i],
								new_tbl_entry);
				} else {
					/* Are extended */
					modify_ext_entries(
						lpm,
						lpm->tbl24[i].next_hop *
						LPM6_TBL8_GROUP_NUM_ENTRIES,
						depth,
						new_depth,
						sub_rule->next_hop);
				}
			}
		} else {
			/*
			 * Removing someting from a tbl8 which has a cover
			 * somewhere, possibly in the same table, but possibly
			 * in a previous table.
			 */
			tbl8_range = depth_to_range(depth);

			for (i = tbl8_index;
			     i < (tbl8_index + tbl8_range); i++) {
				if (lpm->tbl8[i].valid &&
					lpm->tbl8[i].depth <= depth &&
					!lpm->tbl8[i].ext_entry)
					CMM_STORE_SHARED(lpm->tbl8[i],
							new_tbl_entry);
				else if (lpm->tbl8[i].valid &&
					lpm->tbl8[i].ext_entry) {
					/* Are extended */
					modify_ext_entries(
						lpm,
						lpm->tbl8[i].next_hop *
						LPM6_TBL8_GROUP_NUM_ENTRIES,
						depth,
						new_depth,
						sub_rule->next_hop);
				}
			}
			tbl8_recycle(lpm, indices, index_count);
		}
	}
}

/*
 * Find rule to replace the just deleted. If there is no rule to
 * replace the rule_to_delete we return NULL and invalidate the table
 * entries associated with this rule.
 */
static int rule_replace(struct lpm6 *lpm, struct lpm6_rule *old_rule,
			const uint8_t *ip, uint8_t depth,
			struct lpm6_rule **new_rule)
{
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];
	struct lpm6_rule *sub_rule, *higher_scope_rule;
	uint8_t sub_depth = 0;
	bool higher_scope_found = false;

	mask_ip6(masked_ip, ip, depth);

	/* Find prev rule */
	sub_rule = RB_PREV(lpm6_rules_tree, &lpm->rules[depth], old_rule);
	if (sub_rule) {
		/*
		 * If IP address the same then this is a good rule
		 * with a lower scope. Otherwise it is not, and we
		 * need to check a different depth.
		 */
		if (memcmp(old_rule->ip, sub_rule->ip, LPM6_IPV6_ADDR_SIZE))
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
	higher_scope_rule = RB_NEXT(lpm6_rules_tree,
				    &lpm->rules[depth], old_rule);
	if (higher_scope_rule &&
	    !memcmp(old_rule->ip, higher_scope_rule->ip, LPM6_IPV6_ADDR_SIZE))
		higher_scope_found = true;

	rule_delete(lpm, old_rule, depth);
	if (higher_scope_found)
		return LPM_HIGHER_SCOPE_EXISTS;

	if (!sub_rule) {
		sub_rule = find_previous_rule(lpm, ip, depth, &sub_depth);
		*new_rule = NULL;
	} else {
		*new_rule = sub_rule;
	}

	/* Remove from lpm - the rule is already gone from the RB tree */
	if (depth == 0)
		memset(&lpm->tbldflt, 0, sizeof(lpm->tbldflt));
	else
		delete_rule(lpm, masked_ip, depth, sub_rule, sub_depth);

	return LPM_SUCCESS;
}


/*
 * Deletes a rule
 */
int
lpm6_delete(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
	    uint32_t *next_hop, int16_t scope,
	    struct pd_obj_state_and_flags *pd_state,
	    uint32_t *new_next_hop,
	    struct pd_obj_state_and_flags **new_pd_state)
{
	struct lpm6_rule *rule_to_delete;
	struct lpm6_rule *new_rule = NULL;
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];
	int rc;

	/*
	 * Check input arguments.
	 */
	if (lpm == NULL || depth > LPM6_MAX_DEPTH)
		return -EINVAL;

	mask_ip6(masked_ip, ip, depth);

	/*
	 * Find the index of the input rule, that needs to be deleted, in the
	 * rule table.
	 */
	rule_to_delete = rule_find(lpm, masked_ip, depth, scope);
	if (rule_to_delete == NULL)
		return -ENOENT;

	if (pd_state)
		*pd_state = rule_to_delete->pd_state;

	if (next_hop)
		*next_hop = rule_to_delete->next_hop;

	/* Replace with next level up rule */
	rc = rule_replace(lpm, rule_to_delete, ip, depth, &new_rule);
	if (rc == 0 && new_rule) {
		if (new_next_hop)
			*new_next_hop = new_rule->next_hop;
		if (new_pd_state)
			*new_pd_state = &new_rule->pd_state;
		return LPM_LOWER_SCOPE_EXISTS;
	}
	return rc;
}

static void lpm6_tracker_call_cbs(struct lpm6_rule *rule)
{
	struct rt_tracker_info *ti_iter, *next;

	if (rule->tracker_count == 0)
		return;

	RB_FOREACH_SAFE(ti_iter, lpm6_tracker_tree, &rule->tracker_head, next)
		ti_iter->rti_cb_func(ti_iter);
}

/*
 * Delete all rules from the LPM table.
 */
void
lpm6_delete_all(struct lpm6 *lpm, lpm6_walk_func_t func, void *arg)
{
	uint8_t depth;

	/* Zero next tbl8 index. */
	lpm->next_tbl8 = 0;

	/* Zero default table entry */
	memset(&lpm->tbldflt, 0, sizeof(lpm->tbldflt));

	/* Zero tbl24. */
	memset(lpm->tbl24, 0, sizeof(lpm->tbl24));

	/* Zero tbl8. */
	memset(lpm->tbl8, 0, sizeof(lpm->tbl8[0]) *
			LPM6_TBL8_GROUP_NUM_ENTRIES * lpm->number_tbl8s);

	/* Delete all rules form the rules table. */
	for (depth = 0; depth <= LPM6_MAX_DEPTH; ++depth) {
		struct lpm6_rules_tree *head = &lpm->rules[depth];
		struct lpm6_rule *r, *n;
		struct lpm6_walk_params params;

		RB_FOREACH_SAFE(r, lpm6_rules_tree, head, n) {
			if (func) {
				memcpy(&params.prefix, r->ip,
				       LPM6_IPV6_ADDR_SIZE);
				params.pr_len = depth;
				params.scope = r->scope;
				params.next_hop = r->next_hop;
				func(&params, &r->pd_state, arg);
			}
			rule_delete(lpm, r, depth);
		}
	}
}

uint32_t
lpm6_walk(struct lpm6 *lpm, lpm6_walk_func_t func,
		struct lpm6_walk_arg *r_arg)
{
	uint8_t depth = r_arg->depth;
	uint32_t rule_cnt = 0;
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];
	bool len_match = true;

	for (; depth <= LPM6_MAX_DEPTH; ++depth) {
		struct lpm6_rule *r, *n;
		struct lpm6_walk_params params;

		if (r_arg->get_next && len_match) {
			mask_ip6(masked_ip, r_arg->addr.s6_addr, depth);
			n = rule_find_next(lpm, r_arg->addr.s6_addr, depth,
					   255);
		} else {
			struct lpm6_rules_tree *head = &lpm->rules[depth];

			n = RB_MIN(lpm6_rules_tree, head);
		}

		len_match = false;
		if (!n)
			continue;

		RB_FOREACH_FROM(r, lpm6_rules_tree, n) {
			memcpy(&params.prefix, r->ip, LPM6_IPV6_ADDR_SIZE);
			params.pr_len = depth;
			params.scope = r->scope;
			params.next_hop = r->next_hop;
			params.call_tracker_cbs = false;

			func(&params, &r->pd_state, r_arg->walk_arg);
			if (params.call_tracker_cbs)
				lpm6_tracker_call_cbs(r);

			if (r_arg->is_segment && (++rule_cnt == r_arg->cnt))
				return rule_cnt;
		}
	}

	return 0;
}

/*
 * Do a subtree walk of the given rule.
 *
 * MUST hold the route_mutex;
 */
void lpm6_subtree_walk(struct lpm6 *lpm,
			   const uint8_t *root_ip,
			   uint8_t root_depth,
			   void (*cb)(struct lpm6 *lpm, uint8_t *ip,
				      uint8_t depth, uint32_t idx,
				      void *arg),
			   void *arg)
{
	uint8_t depth;

	if (root_depth >= LPM6_MAX_DEPTH)
		return;
	for (depth = root_depth + 1; depth <= LPM6_MAX_DEPTH; depth++) {
		struct lpm6_rule *r, *n;
		uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];

		n = rule_find_next(lpm, root_ip, depth, 0);

		RB_FOREACH_FROM(r, lpm6_rules_tree, n) {
			mask_ip6(masked_ip, r->ip, root_depth);
			if (memcmp(masked_ip, root_ip, LPM6_IPV6_ADDR_SIZE))
				break;
			/*
			 * Have to take a copy of the IP addr as the callback
			 * might delete the rule, and in that case we would
			 * end up accessing freed memory if the ip pointer is
			 * passed into lpm6_delete.
			 */
			memcpy(masked_ip,  r->ip, LPM6_IPV6_ADDR_SIZE);
			cb(lpm, masked_ip, depth, r->next_hop, arg);
		}
	}
}

static struct rt_tracker_info *
lpm6_tracker_find_next(struct lpm6_rule *rule,
		       const uint8_t *ip, uint8_t depth)
{
	struct rt_tracker_info key;
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];

	mask_ip6(masked_ip, ip, depth);
	key.dst_addr.type = AF_INET6;
	memcpy(&key.dst_addr.address.ip_v6, &masked_ip,
	       sizeof(key.dst_addr.address.ip_v6));

	return RB_NFIND(lpm6_tracker_tree, &rule->tracker_head, &key);
}

static int
lpm6_tracker_add_to_rule(struct lpm6_rule *rule,
			 uint8_t depth,
			 struct rt_tracker_info *ti_info,
			 bool route_found)
{
	if (rule->tracker_count >= UINT16_MAX)
		return -ENOMEM;

	ti_info->tracking = route_found;
	ti_info->rule = rule;
	ti_info->r_depth = depth;
	ti_info->nhindex = rule->next_hop;
	rule->tracker_count++;
	RB_INSERT(lpm6_tracker_tree, &rule->tracker_head, ti_info);
	return 0;
}

int lpm6_tracker_add(struct lpm6 *lpm, struct rt_tracker_info *ti_info)
{
	struct lpm6_rule *rule;
	uint8_t r_depth = 0;
	int ret = 0;

	rule = find_previous_rule(lpm, ti_info->dst_addr.address.ip_v6.s6_addr,
				  LPM6_MAX_DEPTH, &r_depth);

	if (rule)
		ret = lpm6_tracker_add_to_rule(rule, r_depth, ti_info, true);
	else
		ret = lpm6_tracker_add_to_rule(&lpm->no_route_rule, 0, ti_info,
					       false);

	return ret;
}

void lpm6_tracker_delete(struct rt_tracker_info *ti_info)
{
	struct lpm6_rule *rule = ti_info->rule;

	RB_REMOVE(lpm6_tracker_tree, &rule->tracker_head, ti_info);
	rule->tracker_count--;
}

static void
lpm6_tracker_rule_changed(struct lpm6 *lpm6, struct rt_tracker_info *ti_info,
			  uint8_t depth)
{
	int ret = 0;
	uint8_t new_depth = 0;
	struct lpm6_rule *new_rule = NULL;
	struct lpm6_rule *old_rule = (struct lpm6_rule *)ti_info->rule;

	new_rule = find_previous_rule(
		lpm6,
		(const uint8_t *)&ti_info->dst_addr.address.ip_v6, depth,
		&new_depth);

	if (new_rule == old_rule)
		/*
		 * Nothing changed:
		 */
		return;

	/* There is a change, clear state first */
	RB_REMOVE(lpm6_tracker_tree, &old_rule->tracker_head, ti_info);

	old_rule->tracker_count--;

	if (!new_rule)
		/* Now try the no_route_rule */
		ret = lpm6_tracker_add_to_rule(&lpm6->no_route_rule, 0, ti_info,
					       false);
	else
		/* Try attaching to the new rule */
		ret = lpm6_tracker_add_to_rule(new_rule, new_depth, ti_info,
					       true);

	if (ret < 0)
		RTE_LOG(ERR, LPM, "LPM failed to update tracker\n");

	ti_info->rti_cb_func(ti_info);
}


/*
 * Called when a new rule is added or deleted:
 *     - replacing an old one
 *           - update if it has tracker count
 *     - not replacing an old rule
 *           - see if cover has tracker count, if so update, go to the
 *             cover to see if there are any trackers that need to be
 *             moved
 */
static void
lpm6_tracker_update(struct lpm6 *lpm, struct lpm6_rule *old_rule,
		    const uint8_t *ip, uint8_t depth)
{
	uint8_t cover_depth = 0;
	struct lpm6_rule *cover_rule;
	struct lpm6_rule *tracker_rule;
	struct rt_tracker_info *ti_info, *ti_iter = NULL;
	uint8_t masked_ip[LPM6_IPV6_ADDR_SIZE];

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
	ti_info = lpm6_tracker_find_next(tracker_rule, ip, depth);
	RB_FOREACH_FROM(ti_iter, lpm6_tracker_tree, ti_info) {
		mask_ip6(masked_ip,
			 (const uint8_t *)&ti_iter->dst_addr.address.ip_v6,
			 depth);
		if (memcmp(masked_ip, ip, LPM6_IPV6_ADDR_SIZE))
			break;

		/* Tracker changed ?*/
		lpm6_tracker_rule_changed(lpm, ti_iter, depth);
	}
	return;

try_default:
	/* Now see if there are any default trackers */
	if (lpm->no_route_rule.tracker_count) {

		ti_info = lpm6_tracker_find_next(&lpm->no_route_rule, ip,
						 depth);
		RB_FOREACH_FROM(ti_iter, lpm6_tracker_tree, ti_info) {
			mask_ip6(masked_ip,
				 (const uint8_t *)
				 &ti_iter->dst_addr.address.ip_v6,
				 depth);
			if (memcmp(masked_ip, ip, LPM6_IPV6_ADDR_SIZE))
				break;

			/* Tracker changed ? */
			lpm6_tracker_rule_changed(lpm, ti_iter, depth);
		}
		return;
	}
}

int lpm6_tracker_get_cover_ip_and_depth(struct rt_tracker_info *ti_info,
					uint8_t *ip,
					uint8_t *depth)
{
	struct lpm6_rule *rule;

	if (ti_info->rule) {
		rule = ti_info->rule;
		memcpy(ip, rule->ip, LPM6_IPV6_ADDR_SIZE);
		*depth = ti_info->r_depth;
		return ti_info->tracking &&
			rule->scope != LPM_SCOPE_PAN_DIMENSIONAL;
	}

	return 0;
}
