/*-
 *   Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
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
#ifndef LPM6_H
#define LPM6_H

#include <netinet/in.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>

#include "lpm/lpm.h"
#include "pd_show.h"

/**
 * @file
 * Longest Prefix Match for IPv6 (LPM6)
 */

#ifdef __cplusplus
extern "C" {
#endif

#define LOGTYPE_LPM6 RTE_LOGTYPE_USER5

#define LPM6_MAX_DEPTH               128
#define LPM6_IPV6_ADDR_SIZE           16
/** Max number of characters in LPM name. */
#define LPM6_NAMESIZE                 32

/** LPM structure. */
struct lpm6;

/** LPM configuration structure. */
struct lpm6_config {
	uint32_t max_rules;      /**< Max number of rules. */
	uint32_t number_tbl8s;   /**< Number of tbl8s to allocate. */
};

/** rule walk utility db. */
struct lpm6_walk_arg {
	bool is_segment;
	bool get_next;
	void *walk_arg;
	struct in6_addr addr;
	uint32_t cnt;
	uint8_t depth;
};

/**
 * Create an LPM object.
 *
 * @param id
 *   LPM table id
 * @return
 *   Handle to LPM object on success, NULL otherwise.
 */
struct lpm6 *
lpm6_create(uint32_t id);

/*
 * @param lpm
 *   LPM table to return the ID of.
 * @return
 *   Id of the given LPM table.
 */
uint32_t
lpm6_get_id(struct lpm6 *lpm);

/**
 * Free an LPM object.
 *
 * @param lpm
 *   LPM object handle
 * @return
 *   None
 */
void
lpm6_free(struct lpm6 *lpm);

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
 *   set when returning LPM_LOWER_SCOPE_EXISTS.
 * @param old_pd_state
 *   Enum to store the PD state of the demoted lpm rule in. This is used to
 *   track the state over the life of this route. Only set when returning
 *   LPM_LOWER_SCOPE_EXISTS.
 * @return
 *   LPM_SUCCESS
 *   LPM_HIGHER_SCOPE_EXISTS
 *   LPM_LOWER_SCOPE_EXISTS
 *   negative value otherwise
 */
int
lpm6_add(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
	 uint32_t next_hop, int16_t scope,
	 struct pd_obj_state_and_flags **pd_state,
	 uint32_t *old_next_hop,
	 struct pd_obj_state_and_flags **old_pd_state);

/**
 * Delete a rule from the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP of the rule to be deleted from the LPM table
 * @param depth
 *   Depth of the rule to be deleted from the LPM table
 * @param next_hop
 *   Next hop of the rule deleted
 * @param scope
 *   Priority scope of this route rule
 * @param pd_state
 *   Location to store the PD state of this rule in. As the rule for this
 *   route will be deleted we return the value stored in it.
 * @param new_next_hop
 *   Location to store the id of the NH the promoted rule is using. Only
 *   set when returning LPM_LOWER_SCOPE_EXISTS.
 * @param new_pd_state
 *   Enum to store the PD state of the promoted lpm rule in. This is used to
 *   track the state over the life of this route. Only set when returning
 *   LPM_LOWER_SCOPE_EXISTS
 * @return
 *   LPM_SUCCESS
 *   LPM_HIGHER_SCOPE_EXISTS
 *   LPM_LOWER_SCOPE_EXISTS
 *   negative value otherwise
 */
int
lpm6_delete(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
	    uint32_t *next_hop, int16_t scope,
	    struct pd_obj_state_and_flags *pd_state,
	    uint32_t *new_next_hop,
	    struct pd_obj_state_and_flags **new_pd_state);

struct lpm6_walk_params {
	uint8_t prefix[LPM6_IPV6_ADDR_SIZE];
	uint32_t pr_len;
	int16_t scope;
	uint32_t next_hop;
	/*
	 * Set this to true in the walker callback to have the callbacks of
	 * any trackers on this entry called after the walker callback func
	 * has been called.
	 */
	bool call_tracker_cbs;
};

/** iterator function for LPM rule */
typedef void (*lpm6_walk_func_t)(struct lpm6_walk_params *params,
				 struct pd_obj_state_and_flags *pd_state,
				 void *arg);

/**
 * Delete all rules from the LPM table.
 *
 * @param lpm
 *   LPM object handle
 */
void
lpm6_delete_all(struct lpm6 *lpm, lpm6_walk_func_t func, void *arg);

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
lpm6_lookup(const struct lpm6 *lpm, const uint8_t *ip,
		uint32_t *next_hop);

/**
 * Iterate over all rules in the LPM table.
 **/
uint32_t
lpm6_walk(struct lpm6 *lpm, lpm6_walk_func_t func,
		struct lpm6_walk_arg *arg);

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
lpm6_nexthop_lookup(struct lpm6 *lpm, const uint8_t *ip,
		    uint8_t depth, int16_t scope, uint32_t *next_hop);

/*
 * Lookup an IP in the LPM table and return exact match
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP to be looked up in the LPM table
 * @param depth
 *   Prefix length
 * @param next_hop
 *   Next hop of the best exact match (valid on lookup hit only)
 * @return
 *   -EINVAL for incorrect arguments, -ENOENT on lookup miss, 0 on lookup hit
 */
int
lpm6_lookup_exact(struct lpm6 *lpm, const uint8_t *ip,
		      uint8_t depth, uint32_t *next_hop);

void
lpm6_prefetch(struct lpm6 *lpm, const uint8_t *ip);

bool
lpm6_is_empty(const struct lpm6 *lpm);

unsigned int
lpm6_rule_count(const struct lpm6 *lpm);

uint32_t
lpm6_tbl8_used_count(const struct lpm6 *lpm);

uint32_t
lpm6_tbl8_unused_count(const struct lpm6 *lpm);

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
lpm6_find_cover(struct lpm6 *lpm, const uint8_t *ip, uint8_t depth,
		    uint8_t *cover_ip, uint8_t *cover_depth,
		    uint32_t *cover_nh_idx);

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
void lpm6_subtree_walk(struct lpm6 *lpm,
			   const uint8_t *ip,
			   uint8_t depth,
			   void (*cb)(struct lpm6 *lpm, uint8_t *ip,
				      uint8_t depth, uint32_t idx,
				      void *arg),
			   void *arg);


int lpm6_tracker_add(struct lpm6 *lpm, struct rt_tracker_info *ti_info);
void lpm6_tracker_delete(struct rt_tracker_info *ti_info);

int lpm6_tracker_get_cover_ip_and_depth(struct rt_tracker_info *ti_info,
					uint8_t *ip,
					uint8_t *depth);

#ifdef __cplusplus
}
#endif

#endif
