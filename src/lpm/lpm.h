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
 *  version: DPDK.L.1.2.1-3
 */

#ifndef LPM_H
#define LPM_H

/**
 * @file
 * Longest Prefix Match (LPM)
 */

#include <bsd/sys/tree.h>
#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "pd_show.h"
#include "urcu.h"
#include "rt_tracker.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Max number of characters in LPM name. */
#define LPM_NAMESIZE	32

/** Maximum depth value possible for IPv4 LPM. */
#define LPM_MAX_DEPTH 33

/** Total number of tbl24 entries. */
#define LPM_TBL24_NUM_ENTRIES (1 << 24)

/** Number of entries in a tbl8 group. */
#define LPM_TBL8_GROUP_NUM_ENTRIES 256

/** Tbl24 entry structure. */
struct lpm_tbl24_entry {
	/* Using single uint8_t to store 3 values. */
	uint8_t valid       :1; /**< Validation flag. */
	uint8_t ext_entry   :1; /**< external entry? */
	uint8_t depth	    :6;	/**< Rule depth. */
	/* Stores Next hop or group index (i.e. gindex)into tbl8. */
	union {
		uint32_t next_hop:24;
		uint32_t tbl8_gindex:24;
	} __attribute__ ((__packed__));
};

/** Tbl8 entry structure. */
struct lpm_tbl8_entry {
	uint32_t next_hop    :24;	/**< next hop. */
	uint32_t depth       :6;	/**< Rule depth. */
	uint32_t valid       :1;	/**< Validation flag. */
	uint32_t valid_group :1;	/**< Group validation flag. */
};

/** rule walk utility db. */
struct lpm_walk_arg {
	bool is_segment;
	bool get_next; /* or get first if false */
	void *walk_arg;
	uint32_t addr;
	uint32_t cnt;
	uint8_t depth;
};

/* A scope that is even lower than RT_SCOPE_UNIVERSE */
#define LPM_SCOPE_PAN_DIMENSIONAL -1

ALWAYS_INLINE uint32_t
lpm_tbl24_get_next_hop_idx(struct lpm_tbl24_entry *entry)
{
	return entry->next_hop;
}

static inline void
lpm_tbl24_set_next_hop_idx(struct lpm_tbl24_entry *entry,
			       uint32_t nexthop_idx)
{
	entry->next_hop = nexthop_idx;
}

/**
 * Create an LPM object.
 *
 * @param id
 *   LPM table id
 * @return
 *   Handle to LPM object on success, NULL otherwise.
 */
struct lpm *
lpm_create(uint32_t id);

/*
 * @param lpm
 *   LPM table to return the ID of.
 * @return
 *   Id of the given LPM table.
 */
uint32_t
lpm_get_id(struct lpm *lpm);

/**
 * Free an LPM object.
 *
 * @param lpm
 *   LPM object handle
 * @return
 *   None
 */
void
lpm_free(struct lpm *lpm);

/*
 * Rule was added/deleted from the table. If added it is in the forwarding
 * table. If deleted it was removed from the forwarding table.
 */
#define LPM_SUCCESS 0
/*
 * Rule was added/deleted, but a higher scope rule exists so the forwarding
 * table is not changed.
 */
#define LPM_HIGHER_SCOPE_EXISTS 1
/*
 * A rule was added/removed and it has a higher scope than an existing rule.
 * On an add the new rule has been added to the forwarding table, and the
 * previous rule has been demoted. On a delete a rule has been removed from
 * the forwarding table and the lower scope rule has been promoted to the
 * forwarding table.
 */
#define LPM_LOWER_SCOPE_EXISTS 2
/*
 * A new rule has been added, but it already existed, so no changes were made
 */
#define LPM_ALREADY_EXISTS 3

/**
 * Add a rule to the LPM table. If there is a lower scope rule that is
 * currently programed, demote it and install this rule.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP of the rule to be added to the LPM table
 * @param depth
 *   Depth of the rule to be added to the LPM table
 * @param next_hop
 *   Next hop of the rule to be added to the LPM table
 * @param scope
 *   Priority scope of this route rule
 * @param pd_state
 *   Enum to store the PD state of this lpm rule in. This is used to track
 *   the state over the life of this route.
 * @param old_next_hop
 *   Location to store the id of the NH the demoted rule was using. Only
 *   set when returning 2.
 * @param old_pd_state
 *   Enum to store the PD state of the demoted lpm rule in. This is used to
 *   track the state over the life of this route. Only set when returning 2.
 * @return
 *   LPM_SUCCESS
 *   LPM_HIGHER_SCOPE_EXISTS
 *   LPM_LOWER_SCOPE_EXISTS
 *   LPM_ALREADY_EXISTS
 *   negative value otherwise
 */
int
lpm_add(struct lpm *lpm, uint32_t ip, uint8_t depth,
	uint32_t next_hop, int16_t scope,
	struct pd_obj_state_and_flags **pd_state,
	uint32_t *old_next_hop,
	struct pd_obj_state_and_flags **old_pd_state);

/**
 * Delete a rule from the LPM table. If there is a lower scope version of this
 * rule then promote that into the forwarding table.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP of the rule to be deleted from the LPM table
 * @param depth
 *   Depth of the rule to be deleted from the LPM table
 * @param next_hop
 *   Location to store the id of the NH this rule was using
 * @param scope
 *   Priority scope of this route rule
 * @param pd_state
 *   Location to store the PD state of this rule in. As the rule for this
 *   route will be deleted we return the value stored in it.
 * @param new_next_hop
 *   Location to store the id of the NH the promoted rule is using. Only
 *   set when returning 2.
 * @param new_pd_state
 *   Enum to store the PD state of the promoted lpm rule in. This is used to
 *   track the state over the life of this route. Only set when returning 2.
 * @return
 *   LPM_SUCCESS
 *   LPM_HIGHER_SCOPE_EXISTS
 *   LPM_LOWER_SCOPE_EXISTS
 *   negative value otherwise
 */
int
lpm_delete(struct lpm *lpm, uint32_t ip, uint8_t depth,
	   uint32_t *next_hop, int16_t scope,
	   struct pd_obj_state_and_flags *pd_state,
	   uint32_t *new_next_hop,
	   struct pd_obj_state_and_flags **new_pd_state);

struct lpm_walk_params {
	uint32_t ip;
	uint8_t depth;
	int16_t scope;
	uint32_t next_hop;
};

/** iterator function for LPM rule */
typedef void (*lpm_walk_func_t)(struct lpm *lpm,
				struct lpm_walk_params *params,
				struct pd_obj_state_and_flags *pd_state,
				void *arg);

/**
 * Delete all rules from the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param func
 *   Optional callback for each entry
 */
void
lpm_delete_all(struct lpm *lpm, lpm_walk_func_t func, void *arg);

/**
 * Lookup an IP into the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP to be looked up in the LPM table
 * @param next_hop
 *   Next hop of the most specific rule found for IP (valid on lookup hit only)
 * @return
 *   -EINVAL for incorrect arguments, -ENOENT on lookup miss, 0 on lookup hit
 */
int
lpm_lookup(const struct lpm *lpm, uint32_t ip, uint32_t *next_hop);

/*
 * Lookup an IP in the LPM table and return exact match
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP to be looked up in the LPM table
 * @param depth
 *   Prefix length
 * @param scope
 *   Scope of the rule
 * @param next_hop
 *   Next hop of the best exact match (valid on lookup hit only)
 * @return
 *   -EINVAL for incorrect arguments, -ENOENT on lookup miss, 0 on lookup hit
 */
int
lpm_nexthop_lookup(struct lpm *lpm, uint32_t ip,
		   uint8_t depth, int16_t scope, uint32_t *next_hop);

/**
 * Lookup an IP in the LPM table and return exact match
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP to be looked up in the LPM table
 * @param depth
 *   Prefix length
 * @param next_hop
 *   Optional next hop of the best exact match (valid on lookup hit only)
 * @return
 *   -EINVAL for incorrect arguments, -ENOENT on lookup miss, 0 on lookup hit
 */
int
lpm_lookup_exact(struct lpm *lpm, uint32_t ip, uint8_t depth,
		     uint32_t *next_hop);

/**
 * Iterate over all rules in the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param func
 *   Callback to display
 * @param arg
 *   Argument passed to iterator
 */
uint32_t
lpm_walk(struct lpm *lpm, lpm_walk_func_t func,
		struct lpm_walk_arg *arg);

/**
 * Return the number of entries in the Tbl8 array
 *
 * @param lpm
 *   LPM object handle
 */
unsigned
lpm_tbl8_count(const struct lpm *lpm);

/**
 * Return the number of free entries in the Tbl8 array
 *
 * @param lpm
 *   LPM object handle
 */
unsigned
lpm_tbl8_free_count(const struct lpm *lpm);

/**
 * Return whether LPM has any rules or not
 *
 * @param lpm
 *   LPM object handle
 */
bool
lpm_is_empty(const struct lpm *lpm);

/**
 * Return the number of rules the LPM has.
 *
 * @param lpm
 *   LPM object handle
 */
unsigned int
lpm_rule_count(const struct lpm *lpm);

/*
 * Do a subtree walk of the given rule and call the given callback function
 * for each entry found.
 *
 * @param lpm
 *   LPM object handle
 * @param root_ip
 *   Ip address at the root of the subtree
 * @param root_depth
 *   Prefix length at the root of the subtree
 * @param cb
 *   Callback function for each rule found during the subtree walk. The cb
 *   function is passed the ip and depth and the next_hop index for the
 *   current entry in the subtree, plus the arg the user supplied.
 * @param arg
 *   Arg passed through to the callback function.l
 * @return
 *   None
 */
void lpm_subtree_walk(struct lpm *lpm,
			  uint32_t ip,
			  uint8_t depth,
			  void (*cb)(struct lpm *lpm, uint32_t ip,
				     uint8_t depth, uint32_t idx,
				     void *arg),
			  void *arg);

/*
 * Find the rule that covers the prefix defined by ip and depth.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP to be looked up in the LPM table
 * @param depth
 *   Prefix length
 * @param cover_ip
 *   Pointer to store the ip address of the cover
 * @param cover_depth
 *    Pointer to store the depth of the cover
 * @param cover_nh_idx
 *    Pointer to store the next hop index of the cover
 * @return
 *   -EINVAL for incorrect arguments, -ENOENT on lookup miss, 0 on lookup hit
 */
int
lpm_find_cover(struct lpm *lpm, uint32_t ip, uint8_t depth,
		   uint32_t *cover_ip, uint8_t *cover_depth,
		   uint32_t *cover_nh_idx);

/*
 * Converts a given depth value to its corresponding mask value.
 *
 * depth  (IN)		: range = 1 - 32
 * mask	  (OUT)		: 32bit mask
 */
uint32_t lpm_depth_to_mask(uint8_t depth);

int
lpm_tracker_add(struct lpm *lpm, struct rt_tracker_info *ti_info);

void
lpm_tracker_delete(struct rt_tracker_info *ti_info);

int lpm_tracker_get_cover_ip_and_depth(struct rt_tracker_info *ti_info,
				       uint32_t *ip,
				       uint8_t *depth);
#ifdef __cplusplus
}
#endif

#endif /* LPM_H */
