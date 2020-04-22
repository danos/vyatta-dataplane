/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <pthread.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_fbk_hash.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <stdbool.h>
#include <stdint.h>
/*
 * IPv6 route table
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "address.h"
#include "compat.h"
#include "control.h"
#include "dp_event.h"
#include "ecmp.h"
#include "fal.h"
#include "ip_forward.h"
#include "if_var.h"
#include "in6_var.h"
#include "ip6_funcs.h"
#include "json_writer.h"
#include "lpm/lpm6.h"
#include "netinet6/route_v6.h"
#include "netinet6/nd6_nbr.h"
#include "pktmbuf_internal.h"
#include "route_flags.h"
#include "route_v6.h"
#include "urcu.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "vrf_if.h"


/* Use <in6_addr, if index, flags> */
#define IPV6_NH_HASH_KEY_SIZE 6

/*
 *
 * Linux kernel does support IPv6 multipath, it has some
 * differences from IPv4.
 *
 * Each nexthop is added like a single route in the routing table.
 * All routes that have the same destination and scope but
 * not the same gateway shoudld be considered as ECMP routes.
 *
 * When link goes down route delete messages are sent on a
 * per route basis. No implicit action on link down is
 * necessary.
 *
 * addr   +----------+
 *   ---->|          |
 *        |  L P M 6 | idx +-----------+
 *        |          +---->| nexthop_u |
 *        |          |     +-----------+
 *        |          |     |           |
 *        +----------+     +-----------+
 *                         |nexthop_v6 |
 *                         |     0     |
 *                         +-----------+
 *                         |    ...    |
 *                         +-----------+
 *                         |nexthop_v6 |
 *                         | count - 1 |
 *                         +-----------+
 */

static struct cds_lfht *nexthop6_hash;

/* Nexthop entry table, could be per-namespace */
static struct nexthop_table nh6_tbl;

/* Well-known blackhole next_hop_u for failure cases */
static struct next_hop_u *nextu6_blackhole;

static pthread_mutex_t route6_mutex = PTHREAD_MUTEX_INITIALIZER;

/* track the state of routes for the show commands */
static uint32_t route6_sw_stats[PD_OBJ_STATE_LAST];
static uint32_t route6_hw_stats[PD_OBJ_STATE_LAST];

#define IN6ADDR_V4MAPPED_INIT { { { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0,0 } } }

static const struct reserved_route {
	struct in6_addr addr;
	int prefix_length;
	uint32_t flags;
	int scope;
} reserved_routes[] = {
	{
		.addr = IN6ADDR_ANY_INIT,
		.prefix_length = 0,
		.flags = RTF_NOROUTE | RTF_REJECT,
		.scope = LPM_SCOPE_PAN_DIMENSIONAL,
	},
	/*
	 * RFC 4291 - Unicast destination address sanity checks.
	 *    The following are not allowed: unspecified, loopback
	 * draft-itojun-v6ops-v4mapped-harmful-02:
	 *    Don't allow V4 mapped either.
	 */
	{
		.addr = IN6ADDR_ANY_INIT,
		.prefix_length = 128,
		.flags = RTF_BLACKHOLE,
		.scope = RT_SCOPE_HOST,
	},
	{
		.addr = IN6ADDR_LOOPBACK_INIT,
		.prefix_length = 128,
		.flags = RTF_BLACKHOLE,
		.scope = RT_SCOPE_HOST,
	},
	{
		.addr = IN6ADDR_V4MAPPED_INIT,
		.prefix_length = 96,
		.flags = RTF_BLACKHOLE,
		.scope = RT_SCOPE_HOST,
	},
};

static struct nexthop_table *route6_get_nh_table(void)
{
	return &nh6_tbl;
}


static struct cds_lfht *route6_get_nh_hash_table(void)
{
	return nexthop6_hash;
}

/*
 * Wrapper round the nexthop_new function. This one keeps track of the
 * failures and successes.
 */
static int
route_nexthop6_new(struct next_hop *nh, uint16_t size,
		   uint32_t *slot)
{
	int rc;

	rc = nexthop_new(AF_INET6, nh, size, RTPROT_UNSPEC, slot);
	if (rc >= 0)
		return rc;

	switch (rc) {
	case 0:
		break;
	case -ENOSPC:
		route6_sw_stats[PD_OBJ_STATE_NO_RESOURCE]++;
		break;
	default:
		route6_sw_stats[PD_OBJ_STATE_ERROR]++;
		break;
	}

	return rc;
}

/*
 * Wrapper around the lpm function. This one keeps track of the
 * failures and successes.
 */
static int
route_lpm6_add(vrfid_t vrf_id, struct lpm6 *lpm,
	       const struct in6_addr *ip, uint8_t depth, uint32_t next_hop,
	       int16_t scope, uint32_t tableid)
{
	int rc;
	struct pd_obj_state_and_flags *pd_state;
	struct pd_obj_state_and_flags *old_pd_state;
	uint32_t old_nh;
	bool demoted = false;
	struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);
	bool update_pd_state = true;

	rc = lpm6_add(lpm, ip->s6_addr, depth, next_hop, scope, &pd_state,
		      &old_nh, &old_pd_state);
	switch (rc) {
	case LPM_SUCCESS:
		/* Success */
		route6_sw_stats[PD_OBJ_STATE_FULL]++;
		break;
	case LPM_HIGHER_SCOPE_EXISTS:
		/*
		 * Success, but there is a higher scope rule, so this is
		 * not needed in the fal.
		 */
		route6_sw_stats[PD_OBJ_STATE_NOT_NEEDED]++;
		pd_state->state = PD_OBJ_STATE_NOT_NEEDED;
		return rc;
	case LPM_LOWER_SCOPE_EXISTS:
		/* Added, but lower scope route was demoted. */
		route6_sw_stats[PD_OBJ_STATE_NOT_NEEDED]++;
		demoted = true;
		break;
	case -ENOSPC:
		route6_sw_stats[PD_OBJ_STATE_NO_RESOURCE]++;
		return rc;
	default:
		route6_sw_stats[PD_OBJ_STATE_ERROR]++;
		return rc;
	}

	if (nextu->pd_state != PD_OBJ_STATE_FULL &&
	    nextu->pd_state != PD_OBJ_STATE_NOT_NEEDED) {
		pd_state->state = nextu->pd_state;
		nextu = nextu6_blackhole;
		update_pd_state = false;
	}

	if (demoted) {
		struct next_hop_u *nextu =
			rcu_dereference(nh6_tbl.entry[next_hop]);

		if (old_pd_state->created) {
			rc = fal_ip6_upd_route(vrf_id, ip, depth,
					       tableid,
					       nextu->siblings,
					       nextu->nsiblings,
					       nextu->nhg_fal_obj);
		} else {
			rc = fal_ip6_new_route(vrf_id, ip, depth,
					       tableid,
					       nextu->siblings,
					       nextu->nsiblings,
					       nextu->nhg_fal_obj);
		}
		if (update_pd_state)
			pd_state->state = fal_state_to_pd_state(rc);
		if (!rc || old_pd_state->created)
			pd_state->created = true;
		route6_hw_stats[old_pd_state->state]--;
		old_pd_state->state = PD_OBJ_STATE_NOT_NEEDED;
		route6_hw_stats[pd_state->state]++;
		/* Successfully added to SW, so return success. */
		return 0;
	}

	/*
	 * We have successfully added to the lpm, and now need to update the
	 * platform, if there is one.
	 */
	rc = fal_ip6_new_route(vrf_id, ip, depth, tableid,
			       nextu->siblings,
			       nextu->nsiblings,
			       nextu->nhg_fal_obj);
	if (update_pd_state)
		pd_state->state = fal_state_to_pd_state(rc);
	if (!rc)
		pd_state->created = true;
	route6_hw_stats[pd_state->state]++;

	/*
	 * If the SW worked, but the HW failed then return success. The
	 * user needs to use the show commands and the notification infra
	 * in this case.
	 */
	return 0;
}

static int
route_lpm6_delete(vrfid_t vrf_id, struct lpm6 *lpm,
		  const struct in6_addr *ip, uint8_t depth,
		  uint32_t *index, int16_t scope)
{
	int rc;
	struct pd_obj_state_and_flags pd_state;
	struct pd_obj_state_and_flags *new_pd_state;
	uint32_t new_nh;
	bool promoted = false;

	rc = lpm6_delete(lpm, ip->s6_addr, depth, index, scope, &pd_state,
			 &new_nh, &new_pd_state);
	switch (rc) {
	case LPM_SUCCESS:
		/* Success */
		route6_sw_stats[PD_OBJ_STATE_FULL]--;
		break;
	case LPM_HIGHER_SCOPE_EXISTS:
		/* Deleted, but was not programmed as higher scope exists */
		route6_sw_stats[PD_OBJ_STATE_NOT_NEEDED]--;
		return rc;
	case LPM_LOWER_SCOPE_EXISTS:
		/* Deleted, but lower scope was promoted so is now programmed */
		route6_sw_stats[PD_OBJ_STATE_NOT_NEEDED]--;
		promoted = true;
		break;
	default:
		/* Can happen when trying to delete an incomplete route */
		return rc;
	}

	if (promoted) {
		struct next_hop_u *nextu =
			rcu_dereference(nh6_tbl.entry[new_nh]);

		bool update_new_pd_state = true;

		if (nextu->pd_state != PD_OBJ_STATE_FULL &&
		    nextu->pd_state != PD_OBJ_STATE_NOT_NEEDED) {
			new_pd_state->state = nextu->pd_state;
			nextu = nextu6_blackhole;
			update_new_pd_state = false;
		}

		if (pd_state.created) {
			rc = fal_ip6_upd_route(vrf_id, ip, depth,
					       lpm6_get_id(lpm),
					       nextu->siblings,
					       nextu->nsiblings,
					       nextu->nhg_fal_obj);
		} else {
			rc = fal_ip6_new_route(vrf_id, ip, depth,
					       lpm6_get_id(lpm),
					       nextu->siblings,
					       nextu->nsiblings,
					       nextu->nhg_fal_obj);
		}
		if (update_new_pd_state)
			new_pd_state->state = fal_state_to_pd_state(rc);
		if (!rc || pd_state.created)
			new_pd_state->created = true;
		route6_hw_stats[pd_state.state]--;
		route6_hw_stats[new_pd_state->state]++;
		return 0;
	}

	/* successfully removed and no lower scope promoted */
	if (pd_state.created) {
		rc = fal_ip6_del_route(vrf_id, ip, depth, lpm6_get_id(lpm));
		switch (rc) {
		case 0:
			route6_hw_stats[pd_state.state]--;
			break;
		default:
			/* General failure */
			break;
		}
	} else
		route6_hw_stats[pd_state.state]--;

	/* Successfully deleted from SW, so return success. */
	return 0;
}

static int
route_lpm6_update(vrfid_t vrf_id __unused, struct lpm6 *lpm,
		  const struct in6_addr *ip, uint8_t depth,
		  uint32_t *old_nh,
		  uint32_t next_hop, int16_t scope,
		  uint32_t tableid)
{
	int rc;
	struct pd_obj_state_and_flags pd_state;
	struct pd_obj_state_and_flags *old_pd_state;
	struct pd_obj_state_and_flags *new_pd_state;
	uint32_t new_nh;
	uint32_t dummy_old_nh;
	bool update_new_pd_state = true;

	/*
	 * Remove an old entry from the lpm, and add a new one. lpm
	 * does not currently support make-before-break
	 */
	rc = lpm6_delete(lpm, ip->s6_addr, depth, old_nh,
			 scope, &pd_state, &new_nh,
			 &new_pd_state);
	switch (rc) {
	case LPM_SUCCESS:
		/* Success */
		route6_sw_stats[PD_OBJ_STATE_FULL]--;
		break;
	case LPM_HIGHER_SCOPE_EXISTS:
		route6_sw_stats[PD_OBJ_STATE_NOT_NEEDED]--;
		break;
	case LPM_LOWER_SCOPE_EXISTS:
		/* Deleted, but lower scope was promoted so is now programmed */
		route6_sw_stats[PD_OBJ_STATE_NOT_NEEDED]--;
		break;

	default:
		return rc;
	}

	/*
	 * This is a replace, so the old_nh was got from the delete above,
	 * so make sure we don't overwrite that value here
	 */
	rc = lpm6_add(lpm, ip->s6_addr, depth, next_hop, scope,
		      &new_pd_state, &dummy_old_nh, &old_pd_state);
	switch (rc) {
	case LPM_SUCCESS:
		/* Success */
		route6_sw_stats[PD_OBJ_STATE_FULL]++;
		break;
	case LPM_HIGHER_SCOPE_EXISTS:
		/*
		 * Success, but there is a higher scope rule, so this is
		 * not needed in the fal.
		 */
		route6_sw_stats[PD_OBJ_STATE_NOT_NEEDED]++;
		break;
	case LPM_LOWER_SCOPE_EXISTS:
		/* Added, but lower scope route was demoted. */
		route6_sw_stats[PD_OBJ_STATE_NOT_NEEDED]++;
		break;
	case -ENOSPC:
		route6_sw_stats[PD_OBJ_STATE_NO_RESOURCE]++;
		break;
	default:
		route6_sw_stats[PD_OBJ_STATE_ERROR]++;
	}

	struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);

	if (nextu->pd_state != PD_OBJ_STATE_FULL &&
	    nextu->pd_state != PD_OBJ_STATE_NOT_NEEDED) {
		new_pd_state->state = nextu->pd_state;
		nextu = nextu6_blackhole;
		update_new_pd_state = false;
	}

	if (pd_state.created) {
		rc = fal_ip6_upd_route(vrf_id, ip, depth, tableid,
				       nextu->siblings, nextu->nsiblings,
				       nextu->nhg_fal_obj);
	} else {
		rc = fal_ip6_new_route(vrf_id, ip, depth, tableid,
				       nextu->siblings, nextu->nsiblings,
				       nextu->nhg_fal_obj);
	}

	route6_hw_stats[pd_state.state]--;
	if (!rc || pd_state.created)
		new_pd_state->created = true;
	if (update_new_pd_state)
		new_pd_state->state = fal_state_to_pd_state(rc);
	route6_hw_stats[new_pd_state->state]++;
	/* Successfully added to SW, so return success. */
	return 0;
}

/* Dynamically grow LPM table if necessary.
 * Doesn't just use rte_realloc because want to be RCU safe.
 */
static int rt_lpm_v6_resize(struct route6_head *rt6_head, uint32_t id)
{
	struct lpm6 **new_tbl, **old_tbl;
	uint32_t old_id;

	if (id < rt6_head->rt6_rtm_max)
		return 0;

	new_tbl = malloc_huge_aligned((id + 1) * sizeof(struct lpm6 *));
	if (new_tbl == NULL) {
		RTE_LOG(ERR, ROUTE6,
			"Can't grow v6 LPM table\n");
		return -1;
	}

	/* Copy existing table */
	old_tbl = rt6_head->rt6_table;
	old_id = rt6_head->rt6_rtm_max;
	if (old_tbl)
		memcpy(new_tbl, old_tbl,
		       sizeof(struct lpm6 *) * rt6_head->rt6_rtm_max);

	rcu_set_pointer(&rt6_head->rt6_table, new_tbl);
	rt6_head->rt6_rtm_max = id + 1;

	if (old_tbl) {
		if (defer_rcu_huge(old_tbl,
				   (old_id * sizeof(struct lpm6 *)))) {
			RTE_LOG(ERR, LPM, "Failed to free old v6 LPM tbl\n");
			return -1;
		}
	}
	return 0;
}

static bool
rt6_lpm_is_empty(struct lpm6 *lpm)
{
	unsigned int rule_count = lpm6_rule_count(lpm);

	assert(rule_count >= ARRAY_SIZE(reserved_routes));
	return rule_count == ARRAY_SIZE(reserved_routes);
}

static bool
rt6_is_reserved(const uint8_t *addr, int prefix_length, int scope)
{
	unsigned int rt_idx;

	for (rt_idx = 0; rt_idx < ARRAY_SIZE(reserved_routes); rt_idx++) {
		if (prefix_length == reserved_routes[rt_idx].prefix_length &&
		    scope == reserved_routes[rt_idx].scope &&
		    !memcmp(addr, &reserved_routes[rt_idx].addr,
			    sizeof(reserved_routes[rt_idx].addr)))
			return true;
	}

	return false;
}

static bool
rt6_lpm_add_reserved_routes(struct lpm6 *lpm, struct vrf *vrf)
{
	char b[INET_ADDRSTRLEN];
	unsigned int rt_idx;

	if (vrf->v_id == VRF_INVALID_ID)
		return true;

	for (rt_idx = 0; rt_idx < ARRAY_SIZE(reserved_routes); rt_idx++) {
		const struct in6_addr *addr = &reserved_routes[rt_idx].addr;
		struct next_hop *nhop;
		uint32_t nh_idx;
		int err_code;

		nhop = nexthop6_create(NULL, &in6addr_any,
				       reserved_routes[rt_idx].flags,
				       0, NULL);
		if (!nhop)
			return false;

		err_code = route_nexthop6_new(nhop, 1, &nh_idx);
		if (err_code < 0) {
			RTE_LOG(ERR, ROUTE,
				"reserved route add %s/%u failed - cannot create nexthop: %s\n",
				inet_ntop(AF_INET6,
					  &addr, b,
					  sizeof(b)),
				reserved_routes[rt_idx].prefix_length,
				strerror(-err_code));
			free(nhop);
			return false;
		}

		err_code = route_lpm6_add(
			vrf->v_id,
			lpm,
			addr,
			reserved_routes[rt_idx].prefix_length,
			nh_idx, reserved_routes[rt_idx].scope,
			lpm6_get_id(lpm));
		if (err_code < 0) {
			RTE_LOG(ERR, ROUTE,
				"reserved route %s/%u idx %u add to LPM failed (%d)\n",
				inet_ntop(AF_INET6,
					  &addr,
					  b, sizeof(b)),
				reserved_routes[rt_idx].prefix_length,
				nh_idx, err_code);
		}
		free(nhop);
		if (err_code != 0) {
			nexthop6_put(nh_idx);
			return false;
		}
	}

	return true;
}

static bool
rt6_lpm_del_reserved_routes(struct lpm6 *lpm, struct vrf *vrf)
{
	char b[INET6_ADDRSTRLEN];
	unsigned int rt_idx;

	if (vrf->v_id == VRF_INVALID_ID)
		return true;

	for (rt_idx = 0; rt_idx < ARRAY_SIZE(reserved_routes); rt_idx++) {
		const struct in6_addr *addr = &reserved_routes[rt_idx].addr;
		uint32_t nh_idx;
		int err_code;

		err_code = route_lpm6_delete(
			vrf->v_id,
			lpm,
			addr,
			reserved_routes[rt_idx].prefix_length,
			&nh_idx,
			reserved_routes[rt_idx].scope);
		if (err_code < 0) {
			RTE_LOG(ERR, ROUTE,
				"reserved route add %s/%u idx %u failed (%d)\n",
				inet_ntop(AF_INET6,
					  &addr,
					  b, sizeof(b)),
				reserved_routes[rt_idx].prefix_length,
				nh_idx, err_code);
			return false;
		}
		nexthop6_put(nh_idx);
	}

	return true;
}

static struct lpm6 *rt6_create_lpm(uint32_t id, struct vrf *vrf)
{
	struct lpm6 *lpm;

	if (rt_lpm_v6_resize(&vrf->v_rt6_head, id) < 0)
		return NULL;

	lpm = lpm6_create(id);
	if (lpm == NULL) {
		RTE_LOG(NOTICE, ROUTE6,
			"Can't create LPM6 for vrf %u table %u\n",
			vrf->v_id, id);
		return NULL;
	}

	if (!rt6_lpm_add_reserved_routes(lpm, vrf)) {
		DP_LOG_W_VRF(ERR, ROUTE, vrf->v_id,
			     "Failed to add reserved v6 routes to table %u\n",
			     id);
		lpm6_free(lpm);
		return NULL;
	}

	rcu_assign_pointer(vrf->v_rt6_head.rt6_table[id], lpm);

	return lpm;
}

static struct lpm6 *rt6_get_lpm(struct route6_head *rt6_head, uint32_t id)
{
	if (unlikely(id >= rt6_head->rt6_rtm_max))
		return NULL;

	return rcu_dereference(rt6_head->rt6_table[id]);
}

/* Do lookahead into route table and get first prefix match table  */
void rt6_prefetch_fast(const struct rte_mbuf *m, const struct in6_addr *dst)
{
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	struct vrf *vrf = vrf_get_rcu_fast(vrfid);
	struct lpm6 *lpm;

	lpm = rcu_dereference(vrf->v_rt6_head.rt6_table[RT_TABLE_MAIN]);
	lpm6_prefetch(lpm, dst->s6_addr);
}

/* Do lookahead into route table and get first prefix match table  */
void rt6_prefetch(const struct rte_mbuf *m, const struct in6_addr *dst)
{
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	struct vrf *vrf = vrf_get_rcu(vrfid);
	struct lpm6 *lpm;

	if (!vrf)
		return;

	lpm = rcu_dereference(vrf->v_rt6_head.rt6_table[RT_TABLE_MAIN]);
	lpm6_prefetch(lpm, dst->s6_addr);
}

ALWAYS_INLINE
struct next_hop *nexthop6_select_internal(struct next_hop *next,
					  uint32_t size,
					  uint32_t hash)
{
	uint32_t path;

	if (ecmp_max_path && ecmp_max_path < size)
		size = ecmp_max_path;

	path = ecmp_lookup(size, hash);
	if (unlikely(next[path].flags & RTF_DEAD)) {
		/* retry to find a good path */
		for (path = 0; path < size; path++) {
			if (!(next[path].flags & RTF_DEAD))
				break;
		}

		if (path == size)
			return NULL;
	}
	return next + path;
}

ALWAYS_INLINE
struct next_hop *nexthop6_select(uint32_t index, const struct rte_mbuf *m,
				 uint16_t ether_type)
{
	struct next_hop_u *nextu;
	struct next_hop *next;
	uint32_t size;

	nextu = rcu_dereference(nh6_tbl.entry[index]);
	if (unlikely(!nextu))
		return NULL;
	size = nextu->nsiblings;
	next = nextu->siblings;
	if (likely(size == 1))
		return next;

	return nexthop6_select_internal(next, size,
					ecmp_mbuf_hash(m, ether_type));
}

int dp_nh6_lookup_by_index(uint32_t nhindex, uint32_t hash,
			struct in6_addr *nh, uint32_t *ifindex)
{
	const struct next_hop_u *nextu;
	struct next_hop *next;
	struct ifnet *ifp;
	uint32_t size;

	nextu = rcu_dereference(nh6_tbl.entry[nhindex]);
	if (nextu == NULL)
		return -1;

	next = nextu->siblings;
	if (!next)
		return -1;

	size = nextu->nsiblings;
	if (size > 1)
		next = nexthop6_select_internal(next, size, hash);

	if (next->flags & RTF_GATEWAY)
		*nh = next->gateway6;
	else
		*nh = in6addr_any;

	ifp = dp_nh_get_ifp(next);
	if (!ifp)
		return -1;

	*ifindex = ifp->if_index;
	return 0;
}

/* Check if route table exists */
bool rt6_valid_tblid(vrfid_t vrfid, uint32_t tbl_id)
{
	struct vrf *vrf = vrf_get_rcu(vrfid);

	if (!vrf)
		return false;

	return vrf->v_rt6_head.rt6_table[tbl_id] != NULL;
}

/*
 * Lookup nexthop based on destination address
 *
 * Returns RCU protected nexthop structure or NULL.
 */
ALWAYS_INLINE
struct next_hop *dp_rt6_lookup(const struct in6_addr *dst, uint32_t tbl_id,
			       const struct rte_mbuf *m)
{
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	struct vrf *vrf = vrf_get_rcu(vrfid);

	if (!vrf)
		return NULL;

	return rt6_lookup_fast(vrf, dst, tbl_id, m);
}

/*
 * Lookup nexthop based on destination address
 *
 * Returns RCU protected nexthop structure or NULL.
 */
ALWAYS_INLINE
struct next_hop *rt6_lookup_fast(struct vrf *vrf,
				 const struct in6_addr *dst,
				 uint32_t tbl_id,
				 const struct rte_mbuf *m)
{
	const struct lpm6 *lpm;
	struct next_hop *nh;
	uint32_t index = 0;

	lpm = rcu_dereference(vrf->v_rt6_head.rt6_table[tbl_id]);

	if (unlikely(lpm6_lookup(lpm, dst->s6_addr, &index) != 0))
		return NULL;

	nh = nexthop6_select(index, m, ETHER_TYPE_IPv6);
	if (nh && unlikely(nh->flags & RTF_NOROUTE))
		return NULL;
	return nh;
}

/*
 * Modifying a NH in non atomic way, so this must be atomically swapped
 * into the forwarding state when ready
 */
static void nh6_set_neigh_present(struct next_hop *next_hop,
				  struct llentry *lle)
{
	assert((next_hop->flags & RTF_NEIGH_PRESENT) == 0);
	next_hop->flags |= RTF_NEIGH_PRESENT;
	next_hop->u.lle = lle;
	nh6_tbl.neigh_present++;
}

static void nh6_clear_neigh_present(struct next_hop *next_hop)
{
	assert(next_hop->flags & RTF_NEIGH_PRESENT);
	next_hop->flags &= ~RTF_NEIGH_PRESENT;
	next_hop->u.ifp = next_hop->u.lle->ifp;
	nh6_tbl.neigh_present--;
}

static void nh6_set_neigh_created(struct next_hop *next_hop,
				  struct llentry *lle)
{
	assert((next_hop->flags & RTF_NEIGH_CREATED) == 0);
	next_hop->flags |= RTF_NEIGH_CREATED;
	next_hop->u.lle = lle;
	nh6_tbl.neigh_created++;
}

static void nh6_clear_neigh_created(struct next_hop *next_hop)
{
	assert(next_hop->flags & RTF_NEIGH_CREATED);
	next_hop->flags &= ~RTF_NEIGH_CREATED;
	next_hop->u.ifp = next_hop->u.lle->ifp;
	nh6_tbl.neigh_created--;
}

static bool nh6_is_connected(const struct next_hop *nh)
{
	if (nh->flags & (RTF_BLACKHOLE | RTF_REJECT |
			 RTF_SLOWPATH | RTF_GATEWAY |
			 RTF_LOCAL | RTF_NOROUTE))
		return false;

	return true;
}

static bool nh6_is_local(const struct next_hop *nh)
{
	if (nh->flags & RTF_LOCAL)
		return true;

	return false;
}

static bool nh6_is_gw(const struct next_hop *nh)
{
	if (nh->flags & RTF_GATEWAY)
		return true;

	return false;
}

static inline bool rt6_is_nh_local(int nhindex)
{
	struct next_hop_u *nextu;
	struct next_hop *next;

	nextu = rcu_dereference(nh6_tbl.entry[nhindex]);
	if (unlikely(!nextu))
		return false;

	next = rcu_dereference(nextu->siblings);
	if (next && next->flags & RTF_LOCAL)
		return true;

	return false;
}

inline bool is_local_ipv6(vrfid_t vrf_id, const struct in6_addr *dst)
{
	struct vrf *vrf = vrf_get_rcu(vrf_id);
	const struct lpm6 *lpm;
	uint32_t index = 0;

	if (unlikely(!vrf))
		return false;

	lpm = rcu_dereference(vrf->v_rt6_head.rt6_table[RT_TABLE_MAIN]);
	if (unlikely(lpm6_lookup(lpm, dst->s6_addr, &index) != 0))
		return false;

	return rt6_is_nh_local(index);
}

struct next_hop *
nexthop6_create(struct ifnet *ifp, const struct in6_addr *gw, uint32_t flags,
		uint16_t num_labels, label_t *labels)
{
	struct next_hop *next = malloc(sizeof(struct next_hop));

	if (next) {
		next->gateway6 = *gw;
		next->flags = flags;
		nh_set_ifp(next, ifp);
		if (!nh_outlabels_set(&next->outlabels, num_labels, labels)) {
			RTE_LOG(ERR, ROUTE,
				"Failed to set outlabels for nexthop with %u labels\n",
				num_labels);
			free(next);
			return NULL;
		}
	}
	return next;
}

/*
 * Create an array of next_hops based on the hops in the NHU.
 */
static struct next_hop *nexthop6_create_copy(struct next_hop_u *nhu,
					     int *size)
{
	struct next_hop *next, *n;
	struct next_hop *array = rcu_dereference(nhu->siblings);
	uint32_t i;

	*size = nhu->nsiblings;
	n = next = calloc(sizeof(struct next_hop), *size);
	if (!next)
		return NULL;

	for (i = 0; i < nhu->nsiblings; i++) {
		struct next_hop *nhu_next = array + i;

		memcpy(n, nhu_next, sizeof(struct next_hop));
		nh_outlabels_copy(&nhu_next->outlabels, &n->outlabels);
		n++;
	}
	return next;
}

/* Reuse existing next hop entry */
static int
nexthop6_hashfn(const struct nexthop_hash_key *key,
		unsigned long seed __rte_unused)
{
	size_t size = key->size;
	uint32_t hash_keys[size * IPV6_NH_HASH_KEY_SIZE];
	struct ifnet *ifp;
	uint16_t i, j = 0;

	for (i = 0; i < size; i++, j += IPV6_NH_HASH_KEY_SIZE) {
		memcpy(&hash_keys[j], &key->nh[i].gateway6,
		       sizeof(key->nh[i].gateway6));
		ifp = dp_nh_get_ifp(&key->nh[i]);
		hash_keys[j+4] = ifp ? ifp->if_index : 0;
		hash_keys[j+5] = key->nh[i].flags & NH_FLAGS_CMP_MASK;
	}

	return rte_jhash_32b(hash_keys, size * IPV6_NH_HASH_KEY_SIZE, 0);

}

static int nexthop6_cmpfn(struct cds_lfht_node *node, const void *key)
{
	const struct nexthop_hash_key *h_key = key;
	const struct next_hop_u *nu =
		caa_container_of(node, const struct next_hop_u, nh_node);
	uint16_t i;

	if (h_key->size != nu->nsiblings)
		return false;

	for (i = 0; i < h_key->size; i++) {
		if ((dp_nh_get_ifp(&nu->siblings[i]) !=
		     dp_nh_get_ifp(&h_key->nh[i])) ||
		    (!IN6_ARE_ADDR_EQUAL(&nu->siblings[i].gateway6,
					 &h_key->nh[i].gateway6)) ||
		    ((nu->siblings[i].flags & NH_FLAGS_CMP_MASK) !=
		     (h_key->nh[i].flags & NH_FLAGS_CMP_MASK)) ||
		      !nh_outlabels_cmpfn(&nu->siblings[i].outlabels,
					  &h_key->nh[i].outlabels))
			return false;
	}
	return true;
}

/*
 * Remove the old NH from the hash and add the new one. Can not
 * use a call to cds_lfht_add_replace() or any of the variants
 * as the key for the new NH may be very different in the case
 * where there are a different number of paths.
 */
static int
nexthop6_hash_del_add(struct next_hop_u *old_nu,
		      struct next_hop_u *new_nu)
{
	struct nexthop_hash_key key = {.nh = new_nu->siblings,
				       .size = new_nu->nsiblings,
				       .proto = 0};
	int rc;

	/* Remove old one */
	rc = cds_lfht_del(nexthop6_hash, &old_nu->nh_node);
	assert(rc == 0);
	if (rc != 0)
		return rc;

	/* add new one */
	return nexthop_hash_insert(AF_INET6, new_nu, &key);
}

static int nextu6_nc_count(const struct next_hop_u *nhu)
{
	int count = 0;
	uint32_t i;
	struct next_hop *array = rcu_dereference(nhu->siblings);

	for (i = 0; i < nhu->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (nh6_is_neigh_created(next))
			count++;
	}
	return count;
}

static struct next_hop *nextu6_find_path_using_ifp(struct next_hop_u *nhu,
						   struct ifnet *ifp,
						   int *sibling)
{
	uint32_t i;
	struct next_hop *array = rcu_dereference(nhu->siblings);

	for (i = 0; i < nhu->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (dp_nh_get_ifp(next) == ifp) {
			*sibling = i;
			return next;
		}
	}
	return NULL;
}

static bool nextu6_is_any_connected(const struct next_hop_u *nhu)
{
	uint32_t i;
	struct next_hop *array = rcu_dereference(nhu->siblings);

	for (i = 0; i < nhu->nsiblings; i++) {
		struct next_hop *next = array + i;

		if (nh6_is_connected(next))
			return true;
	}
	return false;
}

void nexthop6_put(uint32_t idx)
{
	struct next_hop_u *nextu = rcu_dereference(nh6_tbl.entry[idx]);

	if (--nextu->refcount == 0) {
		struct next_hop *array = nextu->siblings;
		uint32_t i;
		int ret;

		nh6_tbl.entry[idx] = NULL;
		--nh6_tbl.in_use;

		for (i = 0; i < nextu->nsiblings; i++) {
			struct next_hop *nh = array + i;

			if (nh6_is_neigh_present(nh))
				nh6_tbl.neigh_present--;
			if (nh6_is_neigh_created(nh))
				nh6_tbl.neigh_created--;
		}

		if (fal_state_is_obj_present(nextu->pd_state)) {
			ret = fal_ip6_del_next_hops(nextu->nhg_fal_obj,
						    nextu->nsiblings,
						    nextu->nh_fal_obj);
			if (ret < 0) {
				RTE_LOG(ERR, ROUTE,
					"FAL IPv6 next-hop-group delete failed: %s\n",
					strerror(-ret));
			}
		}

		cds_lfht_del(nexthop6_hash, &nextu->nh_node);
		call_rcu(&nextu->rcu, nexthop_destroy);
	}
}

int route_v6_init(struct vrf *vrf)
{
	struct lpm6 *lpm;

	lpm = rt6_create_lpm(RT_TABLE_MAIN, vrf);
	if (!lpm) {
		DP_LOG_W_VRF(ERR, ROUTE6, vrf->v_id,
			     "rte_route_v6_init: can't create ipv6 LPM\n");
		return -1;
	}

	return 0;
}

void route_v6_uninit(struct vrf *vrf, struct route6_head *rt6_head)
{
	uint32_t id;

	if (rt6_head == NULL)
		return;

	for (id = 0; id < rt6_head->rt6_rtm_max; id++) {
		struct lpm6 *lpm = rt6_head->rt6_table[id];

		if (lpm) {
			if (!lpm6_is_empty(lpm)) {
				if (!rt6_lpm_is_empty(lpm)) {
					RTE_LOG(ERR, ROUTE,
						"%s:non empty lpm vrf %u table %u\n",
						__func__, vrf->v_id, id);
					return;
				}
				rt6_lpm_del_reserved_routes(lpm, vrf);
			}
			lpm6_free(lpm);
		}
	}
	free_huge(rt6_head->rt6_table, (rt6_head->rt6_rtm_max *
					sizeof(struct lpm6 *)));
	rt6_head->rt6_table = NULL;
}

struct nh_common nh6_common = {
	.nh_hash = nexthop6_hashfn,
	.nh_compare = nexthop6_cmpfn,
	.nh_get_hash_tbl = route6_get_nh_hash_table,
	.nh_get_nh_tbl = route6_get_nh_table,
};

void nexthop_v6_tbl_init(void)
{
	struct next_hop nh_drop = {
		.flags = RTF_BLACKHOLE,
	};
	uint32_t idx;

	nexthop6_hash = cds_lfht_new(NEXTHOP_HASH_TBL_MIN,
				     NEXTHOP_HASH_TBL_MIN,
				     NEXTHOP_HASH_TBL_SIZE,
				     CDS_LFHT_AUTO_RESIZE,
				     NULL);
	if (nexthop6_hash == NULL)
		rte_panic("rte_route_v6_init: can't create nexthop6 hash\n");

	nh_common_register(AF_INET6, &nh6_common);

	/* reserve a drop nexthop */
	if (nexthop_new(AF_INET6, &nh_drop, 1, RTPROT_UNSPEC, &idx))
		rte_panic("%s: can't create drop nexthop\n", __func__);
	nextu6_blackhole =
		rcu_dereference(nh6_tbl.entry[idx]);
	if (!nextu6_blackhole)
		rte_panic("%s: can't create drop nexthop\n", __func__);
}

/* Add new route entry. */
struct subtree_walk_arg {
	struct vrf *vrf;
	uint32_t table_id;
	struct in6_addr ip;
	uint8_t depth;
	bool delete;
};

static void subtree_walk_route_cleanup_cb(struct lpm6 *lpm,
					  uint8_t *masked_ip,
					  uint8_t depth, uint32_t idx,
					  void *arg)
{
	struct subtree_walk_arg *changing = arg;
	struct next_hop_u *nextu = rcu_dereference(nh6_tbl.entry[idx]);
	uint8_t cover_ip[LPM6_IPV6_ADDR_SIZE];
	struct in6_addr inaddr;
	uint8_t cover_depth;
	uint32_t cover_nh_idx;
	int neigh_created = 0;

	if (!nextu)
		return;

	neigh_created = nextu6_nc_count(nextu);
	if (neigh_created == 0)
		return;

	/*
	 * If we're changing this route itself then remove the
	 * neigbour created route.
	 */
	if (!IN6_ARE_ADDR_EQUAL(masked_ip, &changing->ip) &&
	    depth != changing->depth) {
		/*
		 * Is the route we are about to delete the cover of
		 * this route
		 */
		if (lpm6_find_cover(lpm, masked_ip, depth,
				    (uint8_t *)&cover_ip, &cover_depth,
				    &cover_nh_idx)) {
			/*
			 * we must have a cover as this is a subtree
			 * walk
			 */
			assert(0);
			return;
		}

		/*
		 * If changing route is not the immediate cover return
		 * early.
		 */
		if (!IN6_ARE_ADDR_EQUAL(&changing->ip, &cover_ip) ||
		    changing->depth != cover_depth)
			return;
	}

	/*
	 * We created at least one of the paths in here. It is covered by the
	 * route we are about to delete. Delete this too. It will be recreated
	 * later if required. This is ok as packets using this route will
	 * still be forwarded, but with an arp lookup required until the
	 * entry is recreaetd with correct values.
	 */
	memcpy(&inaddr.s6_addr, masked_ip, sizeof(inaddr.s6_addr));
	route_lpm6_delete(changing->vrf->v_id, lpm,
			      &inaddr, 128,
			      &cover_nh_idx, RT_SCOPE_LINK);
	nexthop6_put(idx);
}

static unsigned int lle_routing_insert_neigh_cb(struct lltable *llt __unused,
						struct llentry *lle,
						void *arg __unused)
{
	pthread_mutex_unlock(&route6_mutex);
	routing6_insert_neigh_safe(lle, false);
	pthread_mutex_lock(&route6_mutex);
	return 0;
}

enum nh_change {
	NH_NO_CHANGE,
	NH_SET_NEIGH_CREATED,
	NH_CLEAR_NEIGH_CREATED,
	NH_SET_NEIGH_PRESENT,
	NH_CLEAR_NEIGH_PRESENT,
	NH_DELETE,
};

/*
 * Replace a NH. If valid then add the llentry. In not valid
 * then remove it.
 */
static uint32_t
route6_nh_replace(struct next_hop_u *nextu, uint32_t nh_idx,
		  struct llentry *lle, uint32_t *new_nextu_idx_for_del,
		  enum nh_change (*nh_processing_cb)(struct next_hop *next,
						     int sibling,
						     void *arg),
		  void *arg)
{

	struct next_hop_u *new_nextu = NULL;
	struct next_hop *old_array;
	struct next_hop *new_array = NULL;
	enum nh_change nh_change;
	bool any_change = false;
	uint32_t i;
	uint32_t deleted = 0;

	ASSERT_MASTER();

	/* walk all the NHs, copying as we go */
	old_array = rcu_dereference(nextu->siblings);

	new_nextu = nexthop_alloc(nextu->nsiblings);
	if (!new_nextu)
		return 0;

	new_nextu->index = nextu->index;
	new_nextu->refcount = nextu->refcount;
	new_array = rcu_dereference(new_nextu->siblings);

	for (i = 0; i < nextu->nsiblings; i++) {
		struct next_hop *next = old_array + i;
		struct next_hop *new_next = new_array + i - deleted;

		nh_change = nh_processing_cb(next, i, arg);

		/* Copy across old NH */
		memcpy(new_next, next, sizeof(struct next_hop));
		nh_outlabels_copy(&next->outlabels, &new_next->outlabels);

		switch (nh_change) {
		case NH_NO_CHANGE:
			break;
		case NH_SET_NEIGH_CREATED:
			any_change = true;
			nh6_set_neigh_created(new_next, lle);
			break;
		case NH_CLEAR_NEIGH_CREATED:
			any_change = true;
			nh6_clear_neigh_created(new_next);
			break;
		case NH_SET_NEIGH_PRESENT:
			any_change = true;
			nh6_set_neigh_present(new_next, lle);
			break;
		case NH_CLEAR_NEIGH_PRESENT:
			any_change = true;
			nh6_clear_neigh_present(new_next);
			break;
		case NH_DELETE:
			if (!new_nextu_idx_for_del) {
				__nexthop_destroy(new_nextu);
				return -1;
			}
			any_change = true;
			deleted++;
			break;
		}
	}

	/* Did we make any changes?  If not then we can return */
	if (!any_change) {
		__nexthop_destroy(new_nextu);
		return 0;
	}

	if (deleted) {
		/*
		 * We are deleting at least one nh - create a new
		 * nextu for caller to deal with.
		 */
		if (deleted != nextu->nsiblings &&
		    route_nexthop6_new(nextu->siblings, nextu->nsiblings,
				       new_nextu_idx_for_del) < 0)
			deleted = nextu->nsiblings;
		__nexthop_destroy(new_nextu);
		return deleted;
	}

	if (nexthop6_hash_del_add(nextu, new_nextu)) {
		__nexthop_destroy(new_nextu);
		RTE_LOG(ERR, ROUTE, "nh6 replace failed\n");
		return 0;
	}

	/*
	 * It's safe to copy over the FAL objects without
	 * notifications as there are no FAL-visible changes to the
	 * object - it maintains its own linkage to the neighbour
	 */
	new_nextu->nhg_fal_obj = nextu->nhg_fal_obj;
	memcpy(new_nextu->nh_fal_obj, nextu->nh_fal_obj,
	       new_nextu->nsiblings * sizeof(*new_nextu->nh_fal_obj));
	new_nextu->pd_state = nextu->pd_state;

	assert(nh6_tbl.entry[nh_idx] == nextu);
	rcu_xchg_pointer(&nh6_tbl.entry[nh_idx], new_nextu);

	call_rcu(&nextu->rcu, nexthop_destroy);
	return 0;
}

static void route6_change_process_nh(struct next_hop_u *nhu,
				     enum nh_change (*upd_neigh_present_cb)(
					     struct next_hop *next,
					     int sibling,
					     void *arg))
{
	const struct next_hop *array;
	int index;
	uint i;

	index = nhu->index;
	array = rcu_dereference(nhu->siblings);
	for (i = 0; i < nhu->nsiblings; i++) {
		const struct next_hop *next = array + i;
		const struct ifnet *ifp = dp_nh_get_ifp(next);

		if (!ifp)
			/* happens for local routes */
			continue;

		if (!nh6_is_gw(next))
			continue;

		/*
		 * Is there an lle on this interface with a
		 * matching address.
		 */
		struct llentry *lle = in6_lltable_find((struct ifnet *)ifp,
						       &next->gateway6);
		if (lle) {
			route6_nh_replace(nhu, nhu->index, lle, NULL,
					  upd_neigh_present_cb,
					  lle);
			/*
			 * Need to reread as may have been
			 * replaced by prev func, and will not
			 * then be found in hash table.
			 */
			nhu = rcu_dereference(nh6_tbl.entry[index]);
			if (!nhu)
				break;
		}
	}
}

static void
walk_nh6s_for_route6_change(enum nh_change (*upd_neigh_present_cb)(
				    struct next_hop *next,
				    int sibling,
				    void *arg))
{
	struct next_hop_u *nhu;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	ASSERT_MASTER();

	cds_lfht_for_each(nexthop6_hash, &iter, node) {
		nhu = caa_container_of(node, struct next_hop_u, nh_node);
		route6_change_process_nh(nhu, upd_neigh_present_cb);
	}
}

/*
 * On an arp add, should we set NEIGH_PRESENT from this NH.
 */
static enum nh_change
routing_neigh_add_gw_nh_replace_cb(struct next_hop *next,
				   int sibling __unused,
				   void *arg)
{
	struct llentry *lle = arg;
	struct in6_addr *ip = ll_ipv6_addr(lle);
	struct ifnet *ifp = rcu_dereference(lle->ifp);

	if (!nh6_is_gw(next) || !IN6_ARE_ADDR_EQUAL(&next->gateway6,
						    &ip->s6_addr))
		return NH_NO_CHANGE;
	if (dp_nh_get_ifp(next) != ifp)
		return NH_NO_CHANGE;
	if (nh6_is_local(next) || nh6_is_neigh_present(next))
		return NH_NO_CHANGE;

	return NH_SET_NEIGH_PRESENT;
}

/*
 * This entry has just been added.
 *
 * Invalidate any old arp links
 * Create new arp links as required.
 */
static void
route_change_link_neigh(struct vrf *vrf, struct lpm6 *lpm,
			uint32_t table_id,
			const uint8_t *ip, uint8_t depth,
			uint32_t next_hop, int16_t scope __unused)
{
	uint32_t i;
	const struct next_hop_u *nextu;
	const struct next_hop *array;
	struct subtree_walk_arg subtree_arg = {
		.vrf = vrf,
		.table_id = table_id,
		.depth = depth,
		.delete = false
	};
	uint8_t cover_ip[LPM6_IPV6_ADDR_SIZE];
	uint8_t cover_depth;
	uint32_t cover_idx;
	const struct next_hop_u *cover_nextu;

	/*
	 * If the entry we have just created is connected OR its
	 * cover is connected then there may be routes that are marked
	 * as NEIGH_CREATED that should no longer be. This can be due to
	 * the cover no longer being connected, or being connected out of
	 * a different interface.
	 * In this case do a subtree walk of the entry just added.
	 * Any NHs we find that are NEIGH_CREATED, that have this entry
	 * as the cover need to be checked to see if they are still accurate,
	 * and removed if not.
	 */
	nextu = rcu_dereference(nh6_tbl.entry[next_hop]);
	if (nextu6_is_any_connected(nextu)) {
		memcpy(&subtree_arg.ip, ip,
		       LPM6_IPV6_ADDR_SIZE);
		lpm6_subtree_walk(
			lpm, ip, depth,
			subtree_walk_route_cleanup_cb,
			&subtree_arg);
	} else if (lpm6_find_cover(lpm, ip, depth, (uint8_t *)&cover_ip,
				   &cover_depth, &cover_idx) == 0) {
		cover_nextu = rcu_dereference(nh6_tbl.entry[cover_idx]);
		if (nextu6_is_any_connected(cover_nextu)) {
			memcpy(&subtree_arg.ip, ip,
			       LPM6_IPV6_ADDR_SIZE);
			lpm6_subtree_walk(
				lpm, ip, depth,
				subtree_walk_route_cleanup_cb,
				&subtree_arg);
		}
	}

	/* Walk all the interface neigh entries to do /128 processing */
	array = rcu_dereference(nextu->siblings);
	for (i = 0; i < nextu->nsiblings; i++) {
		const struct next_hop *next = array + i;
		const struct ifnet *ifp = dp_nh_get_ifp(next);

		if (!ifp)
			/* happens for local routes */
			continue;

		lltable_walk(ifp->if_lltable6, lle_routing_insert_neigh_cb,
			     NULL);
	}

	/* Now do the GW processing */
	walk_nh6s_for_route6_change(routing_neigh_add_gw_nh_replace_cb);
}

/*
 * This entry is about to be deleted.
 *
 * Invalidate any old arp links
 */
static void
route_delete_unlink_neigh(struct vrf *vrf, struct lpm6 *lpm,
			  uint32_t table_id, const uint8_t *ip,
			  uint8_t depth)
{
	const struct next_hop_u *nextu;
	uint32_t nh_idx;
	struct subtree_walk_arg subtree_arg = {
		.vrf = vrf,
		.table_id = table_id,
		.depth = depth,
		.delete = true,
	};
	uint8_t cover_ip[LPM6_IPV6_ADDR_SIZE];
	uint8_t cover_depth;
	uint32_t cover_idx;

	/*
	 * If the entry being deleted is connected there may be routes that
	 * are NEIGH_CREATED that will not be  after this is deleted.
	 * This can be due to the new cover no longer being connected,
	 * or being connected out of a different interface.
	 *
	 * In this case do a subtree walk of the entry we are about
	 * to delete. Any NHs we find that are NEIGH_CREATED, that have this
	 * entry as the cover need to be checked to see if they are still
	 * accurate, and removed if not.
	 */
	if (lpm6_lookup_exact(lpm, ip, depth, &nh_idx))
		return;

	nextu = rcu_dereference(nh6_tbl.entry[nh_idx]);
	if (nextu6_is_any_connected(nextu)) {
		memcpy(&subtree_arg.ip, ip, LPM6_IPV6_ADDR_SIZE);
		subtree_walk_route_cleanup_cb(lpm, (uint8_t *)ip,
					      depth, nh_idx,
					      &subtree_arg);
		lpm6_subtree_walk(lpm, ip, depth,
				subtree_walk_route_cleanup_cb,
				&subtree_arg);
	} else if (lpm6_find_cover(lpm, ip, depth, cover_ip,
				   &cover_depth, &cover_idx) == 0) {
		const struct next_hop_u *cover_nextu;

		cover_nextu = rcu_dereference(
			nh6_tbl.entry[cover_idx]);
		if (nextu6_is_any_connected(cover_nextu)) {
			memcpy(&subtree_arg.ip, ip,
			       LPM6_IPV6_ADDR_SIZE);
			subtree_walk_route_cleanup_cb(lpm, (uint8_t *)ip,
						      depth, nh_idx,
						      &subtree_arg);
			lpm6_subtree_walk(lpm, ip, depth,
					  subtree_walk_route_cleanup_cb,
					  &subtree_arg);
		}
	}
}

/*
 * This route has just been deleted. Create new neigh links as required.
 */
static void
route_delete_relink_neigh(struct lpm6 *lpm, uint8_t *ip, uint8_t depth)
{
	const struct next_hop_u *nextu;
	uint8_t cover_ip[LPM6_IPV6_ADDR_SIZE];
	uint8_t cover_depth;
	uint32_t cover_nh_idx;
	const struct next_hop *array;
	uint32_t i;

	/*
	 * Find the cover of the entry just deleted. Walk all neighbours
	 * on that interface to see if there is work to do.
	 */
	if (lpm6_find_cover(lpm, ip, depth, (uint8_t *)&cover_ip,
				&cover_depth, &cover_nh_idx)) {
		return;
	}

	/* Walk all the interfaces neigh entries to do /128 processing */
	nextu = rcu_dereference(nh6_tbl.entry[cover_nh_idx]);
	array = rcu_dereference(nextu->siblings);
	for (i = 0; i < nextu->nsiblings; i++) {
		const struct next_hop *next = array + i;
		const struct ifnet *ifp = dp_nh_get_ifp(next);

		if (!ifp)
			/* happens for local routes */
			continue;
		if (nh6_is_connected(next))
			lltable_walk(ifp->if_lltable6,
				     lle_routing_insert_neigh_cb, NULL);
	}

	/* Now do the gateway processing */
	walk_nh6s_for_route6_change(routing_neigh_add_gw_nh_replace_cb);
}

static int rt6_delete(vrfid_t vrf_id, const struct in6_addr *dst,
		      uint8_t prefix_len, uint32_t id, uint16_t scope,
		      bool is_local)
{
	struct lpm6 *lpm;
	uint32_t id_in = id;
	uint32_t index;
	char b[INET6_ADDRSTRLEN];
	struct vrf *vrf = vrf_get_rcu(vrf_id);
	int err = 0;

	if (vrf == NULL)
		return -ENOENT;

	/* use main table for local route */
	if (id == RT_TABLE_LOCAL)
		id = RT_TABLE_MAIN;

	/*
	 * This is reserved for our own purposes so don't accept any
	 * deletes for it.
	 */
	if (id == RT_TABLE_UNSPEC)
		return -ENOENT;

	lpm = rt6_get_lpm(&vrf->v_rt6_head, id);
	if (lpm == NULL || rt6_lpm_is_empty(lpm))
		return -ENOENT;

	pthread_mutex_lock(&route6_mutex);
	if (unlikely(prefix_len == 128)) {
		/* Do not delete an existing local /128 if the deletion
		 * was for a non-local /128, and vice-versa
		 */
		err = lpm6_nexthop_lookup(lpm, dst->s6_addr, prefix_len,
					scope, &index);
		if (err == 0) {
			if (is_local != rt6_is_nh_local(index)) {
				err = -ENOENT;
				DP_DEBUG(ROUTE, INFO, ROUTE6,
					 "route %s/%u index %u unchanged\n",
					 inet_ntop(AF_INET6, dst, b, sizeof(b)),
					 prefix_len, index);
			} else {
				err = 0;
			}
		}
	}
	if (!err) {
		route_delete_unlink_neigh(vrf, lpm, id, dst->s6_addr,
					  prefix_len);
		err = route_lpm6_delete(vrf->v_id, lpm, dst, prefix_len,
					    &index, scope);
		if (err >= 0) {
			/* A delete now always gets rid of all NHs */
			nexthop6_put(index);
			route_delete_relink_neigh(lpm, (uint8_t *)dst,
						  prefix_len);
		}
	}
	pthread_mutex_unlock(&route6_mutex);

	if (err)
		/*
		 * Expected now we get all deletes from RIB and still act on
		 * link down and purge.
		 */
		return -ENOENT;

	DP_DEBUG_W_VRF(ROUTE, DEBUG, ROUTE6, vrf_id,
		"route delete %s/%u table %d scope %u\n",
		inet_ntop(AF_INET6, dst, b, sizeof(b)), prefix_len,
		id_in, scope);

	return err;
}

/* Add new route entry. */
static int rt6_insert(struct vrf *vrf, struct lpm6 *lpm,
		      uint32_t table_id,
		      const struct in6_addr *dst, uint8_t prefix_len,
		      int16_t scope, struct next_hop hops[],
		      size_t size, uint32_t *idx, bool replace)
{
	char b[INET6_ADDRSTRLEN];
	int err;
	uint32_t old_index;

	if (replace)
		if (unlikely(prefix_len == 128 && !(hops->flags & RTF_LOCAL) &&
			     rt6_is_nh_local(*idx))) {
			DP_DEBUG(ROUTE, DEBUG, ROUTE,
				 "Will not supercede local /128 for %s\n",
				 ip6_sprintf(dst));
			return 0;
		}

	/*
	 * If a /128 and not a GW then  we want to set the GW (but
	 * not the GW flag) so that we do not share with non /128
	 * routes.  This allows us to then link the arp entries
	 * without using the arp for a /128 entry when we should not.
	 */
	unsigned int i;

	if (prefix_len == 128)
		for (i = 0; i < size; i++) {
			if (hops[i].flags & RTF_GATEWAY)
				continue;

			hops[i].gateway6 = *dst;
		}

	err = route_nexthop6_new(hops, size, idx);
	if (unlikely(err < 0)) {
		RTE_LOG(ERR, ROUTE, "route add can't create nexthop: %s\n",
			strerror(-err));
		return err;
	}

	route_delete_unlink_neigh(vrf, lpm, table_id, dst->s6_addr, prefix_len);
	if (replace)
		err = route_lpm6_update(vrf->v_id, lpm, dst, prefix_len,
					&old_index, *idx, scope, table_id);
	else
		err = route_lpm6_add(vrf->v_id, lpm, dst, prefix_len, *idx,
				     scope, table_id);
	if (err < 0) {
		RTE_LOG(ERR, ROUTE, "route insert %s/%u scope %u failed (%d)\n",
			inet_ntop(AF_INET6, dst, b, sizeof(b)),
			prefix_len, scope, err);
		nexthop6_put(*idx);
	} else {
		if (replace)
			nexthop6_put(old_index);
		route_change_link_neigh(vrf, lpm, table_id, dst->s6_addr,
					prefix_len, *idx, scope);
		DP_DEBUG(ROUTE, INFO, ROUTE,
			 "route insert %s/%u index %u scope %u paths %lu\n",
			 inet_ntop(AF_INET6, dst, b, sizeof(b)),
			 prefix_len, *idx, scope, size);
	}

	return err;
}

/* Add, replace or append a new entry */
static int rt6_add(vrfid_t vrf_id, struct in6_addr *dst, uint32_t prefix_len,
		   uint32_t table, int16_t scope, struct next_hop hops[],
		   size_t size)
{
	struct lpm6 *lpm;
	struct vrf *vrf = NULL;
	int err_code;
	uint32_t nhindex;
	bool replace = false;

	/* use main table for local route */
	if (table == RT_TABLE_LOCAL)
		table = RT_TABLE_MAIN;

	/*
	 * This is reserved for our own purposes so don't accept any
	 * routes for it.
	 */
	if (table == RT_TABLE_UNSPEC)
		return -ENOENT;

	vrf = vrf_get_rcu(vrf_id);
	if (!vrf)
		return -ENOENT;
	lpm = rt6_get_lpm(&vrf->v_rt6_head, table);
	if (lpm == NULL) {
		lpm = rt6_create_lpm(table, vrf);
		if (lpm == NULL) {
			err_code = -ENOENT;
			goto err;
		}
	}

	pthread_mutex_lock(&route6_mutex);
	err_code = lpm6_nexthop_lookup(lpm, dst->s6_addr, prefix_len,
					scope, &nhindex);

	replace = err_code == 0 ? true : false;
	err_code = rt6_insert(vrf, lpm, table, dst, prefix_len,
			      scope, hops, size, &nhindex, replace);

	pthread_mutex_unlock(&route6_mutex);

	if (err_code < 0)
		goto err;

	return 0;

err:
	return err_code;
}

/* Gleaner for the next hop */
static void flush6_cleanup(const uint8_t *prefix __rte_unused,
			   uint32_t pr_len __rte_unused,
			   int16_t scope __rte_unused,
			   uint32_t next_hop,
			   struct pd_obj_state_and_flags pd_state __rte_unused,
			   void *arg __rte_unused)
{
	nexthop6_put(next_hop);
}

static void rt6_flush(struct vrf *vrf)
{
	unsigned int id;
	struct route6_head rt6_head = vrf->v_rt6_head;

	if (vrf->v_id == VRF_INVALID_ID)
		return;

	pthread_mutex_lock(&route6_mutex);
	for (id = 0; id < rt6_head. rt6_rtm_max; id++) {
		struct lpm6 *lpm = rt6_head.rt6_table[id];

		if (lpm != NULL && !rt6_lpm_is_empty(lpm)) {
			lpm6_delete_all(lpm, flush6_cleanup, NULL);
			if (!rt6_lpm_add_reserved_routes(lpm, vrf)) {
				DP_LOG_W_VRF(ERR, ROUTE, vrf->v_id,
					"Failed to replace v6 reserved routes %s\n",
					vrf->v_name);
			}
		}
	}
	pthread_mutex_unlock(&route6_mutex);
}

void rt6_flush_all(enum cont_src_en cont_src)
{
	vrfid_t vrf_id;
	struct vrf *vrf;

	if (cont_src == CONT_SRC_MAIN)
		VRF_FOREACH_KERNEL(vrf, vrf_id)
			rt6_flush(vrf);
	else
		VRF_FOREACH_UPLINK(vrf, vrf_id)
			rt6_flush(vrf);
}


void rt6_print_nexthop(json_writer_t *json, uint32_t next_hop,
		       enum rt_print_nexthop_verbosity v)
{
	const struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);
	const struct next_hop *array;
	unsigned int i, j;


	jsonw_uint_field(json, "nh_index", next_hop);
	if (unlikely(!nextu))
		return;
	array = rcu_dereference(nextu->siblings);
	jsonw_uint_field(json, "nh_refcount", nextu->refcount);
	if (v == RT_PRINT_NH_DETAIL &&
	    fal_state_is_obj_present(nextu->pd_state)) {
		/*
		 * name disambuigates between next-hop-group state
		 * and possible future route state given we don't have a
		 * separate JSON object for the two.
		 */
		jsonw_name(json, "nhg_platform_state");
		jsonw_start_object(json);
		fal_ip_dump_next_hop_group(nextu->nhg_fal_obj, json);
		jsonw_end_object(json);
	}
	jsonw_name(json, "next_hop");
	jsonw_start_array(json);
	for (i = 0; i < nextu->nsiblings; i++) {
		const struct next_hop *next = array + i;
		const struct ifnet *ifp;

		jsonw_start_object(json);
		if (next->flags & RTF_BLACKHOLE)
			jsonw_string_field(json, "state", "blackhole");
		else if (next->flags & RTF_REJECT ||
			 next->flags & RTF_NOROUTE)
			jsonw_string_field(json, "state", "unreachable");
		else if (next->flags & RTF_LOCAL)
			jsonw_string_field(json, "state", "local");
		else if (next->flags & RTF_SLOWPATH)
			jsonw_string_field(json, "state",
					   "non-dataplane interface");
		else if (next->flags & RTF_GATEWAY) {
			char b1[INET6_ADDRSTRLEN];
			const char *nhop;
			in_addr_t v4nhop;

			jsonw_string_field(json, "state", "gateway");

			if (IN6_IS_ADDR_V4MAPPED(&next->gateway6)) {
				v4nhop = V4MAPPED_IPV6_TO_IPV4(next->gateway6);
				nhop = inet_ntop(AF_INET, &v4nhop,
						 b1, sizeof(b1));
			} else {
				nhop = inet_ntop(AF_INET6, &next->gateway6,
						 b1, sizeof(b1));
			}
			jsonw_string_field(json, "via", nhop);
		} else
			jsonw_string_field(json, "state", "directly connected");

		if (next->flags & RTF_NEIGH_PRESENT)
			jsonw_bool_field(json, "neigh_present", true);
		if (next->flags & RTF_NEIGH_CREATED)
			jsonw_bool_field(json, "neigh_created", true);

		ifp = dp_nh_get_ifp(next);
		if (ifp && !(next->flags & RTF_DEAD))
			jsonw_string_field(json, "ifname", ifp->if_name);

		if (nh_outlabels_present(&next->outlabels)) {
			label_t label;

			jsonw_name(json, "labels");
			jsonw_start_array(json);

			NH_FOREACH_OUTLABEL_TOP(&next->outlabels, j, label)
				jsonw_uint(json, label);

			jsonw_end_array(json);
		}

		/*
		 * FAL may access hardware which may be slow or may otherwise
		 * increase the data returned greatly, so only output this
		 * information if requested.
		 */
		if (v == RT_PRINT_NH_DETAIL &&
		    fal_state_is_obj_present(nextu->pd_state)) {
			jsonw_name(json, "platform_state");
			jsonw_start_object(json);
			fal_ip_dump_next_hop(nextu->nh_fal_obj[i], json);
			jsonw_end_object(json);
		}

		jsonw_end_object(json);
	}
	jsonw_end_array(json);
}

static void __rt6_display(json_writer_t *json, const uint8_t *addr,
			  uint32_t prefix_len, int16_t scope,
			  const struct next_hop_u *nextu __unused,
			  uint32_t next_hop)
{
	char b1[INET6_ADDRSTRLEN];
	char buf[INET6_ADDRSTRLEN+20]; /* fudge for prefix */

	snprintf(buf, sizeof(buf), "%s/%u",
		 inet_ntop(AF_INET6, addr, b1, sizeof(b1)), prefix_len);

	jsonw_start_object(json);

	jsonw_string_field(json, "prefix", buf);
	jsonw_uint_field(json, "scope", scope);
	rt6_print_nexthop(json, next_hop, RT_PRINT_NH_BRIEF);

	jsonw_end_object(json);
}

/*
 * Walk FIB table.
 */
static void rt6_display(const uint8_t *addr, uint32_t prefix_len, int16_t scope,
			uint32_t next_hop,
			struct pd_obj_state_and_flags pd_state __rte_unused,
			void *arg)
{
	json_writer_t *json = arg;
	const struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);
	const struct next_hop *next;

	if (unlikely(!nextu))
		return;
	next = rcu_dereference(nextu->siblings);

	/* Filter local route being displayed */
	if (next->flags & RTF_LOCAL)
		return;

	/* Don't show if any paths are NEIGH_CREATED. */
	if (nextu6_nc_count(nextu))
		return;

	if (rt6_is_reserved(addr, prefix_len, scope))
		return;

	__rt6_display(json, addr, prefix_len, scope, nextu, next_hop);
}

static void rt6_display_all(const uint8_t *addr, uint32_t prefix_len,
			    int16_t scope, uint32_t next_hop,
			    struct pd_obj_state_and_flags pd_state __rte_unused,
			    void *arg)
{
	json_writer_t *json = arg;
	const struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);

	if (unlikely(!nextu))
		return;
	__rt6_display(json, addr, prefix_len, scope, nextu, next_hop);
}

static void rt6_local_display(
	const uint8_t *addr,
	uint32_t prefix_len,
	int16_t scope, uint32_t next_hop,
	struct pd_obj_state_and_flags pd_state __rte_unused,
	void *arg)
{
	FILE *f = arg;
	char b1[INET6_ADDRSTRLEN];
	const struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);
	const struct next_hop *next;

	if (unlikely(!nextu))
		return;
	next = rcu_dereference(nextu->siblings);
	if (next->flags & RTF_LOCAL &&
	    !rt6_is_reserved(addr, prefix_len, scope))
		fprintf(f, "\t%s\n", inet_ntop(AF_INET6, addr, b1, sizeof(b1)));
}

/* Route rule list (RB-tree) is not RCU safe */
static uint32_t
lpm6_walk_safe(struct lpm6 *lpm, lpm6_walk_func_t func,
		   struct lpm6_walk_arg *r_arg)
{
	uint32_t ret;

	pthread_mutex_lock(&route6_mutex);
	ret = lpm6_walk(lpm, func, r_arg);
	pthread_mutex_unlock(&route6_mutex);

	return ret;
}

static void
lpm6_walk_all_safe(struct lpm6 *lpm, lpm6_walk_func_t func,
		       void *arg)
{
	struct lpm6_walk_arg r_arg = {
		.is_segment = false,
		.walk_arg = arg,
	};

	pthread_mutex_lock(&route6_mutex);
	lpm6_walk(lpm, func, &r_arg);
	pthread_mutex_unlock(&route6_mutex);
}

struct rt6_vrf_lpm_walk_ctx {
	struct vrf *vrf;
	uint32_t table_id;
	void (*func)(struct vrf *vrf, uint32_t table_id,
		     const uint8_t *addr, uint32_t prefix_len,
		     int16_t scope, uint32_t next_hop,
		     struct pd_obj_state_and_flags pd_state, void *arg);
	void *arg;
};

static void rt6_vrf_lpm_walk_cb(const uint8_t *addr, uint32_t prefix_len,
				int16_t scope, uint32_t next_hop,
				struct pd_obj_state_and_flags pd_state,
				void *arg)
{
	const struct rt6_vrf_lpm_walk_ctx *ctx = arg;

	ctx->func(ctx->vrf, ctx->table_id, addr, prefix_len, scope, next_hop,
		  pd_state, ctx->arg);
}

static void rt6_lpm_walk_util(
	void (*func)(struct vrf *vrf, uint32_t table_id,
		     const uint8_t *addr, uint32_t prefix_len,
		     int16_t scope, uint32_t next_hop,
		     struct pd_obj_state_and_flags pd_state,
		     void *arg),
	void *arg)
{
	unsigned int id;
	vrfid_t vrf_id;
	struct vrf *vrf;

	VRF_FOREACH(vrf, vrf_id) {
		for (id = 1; id < vrf->v_rt6_head.rt6_rtm_max; id++) {
			struct lpm6 *lpm = vrf->v_rt6_head.rt6_table[id];
			struct rt6_vrf_lpm_walk_ctx ctx = {
				.vrf = vrf,
				.table_id = id,
				.func = func,
				.arg = arg,
			};

			if (lpm && !rt6_lpm_is_empty(lpm))
				lpm6_walk_all_safe(lpm, rt6_vrf_lpm_walk_cb,
						       &ctx);
		}
	}
}

static void rt6_if_dead(struct vrf *vrf, uint32_t table_id,
			const uint8_t *addr, uint32_t prefix_len,
			int16_t scope, uint32_t next_hop,
			struct pd_obj_state_and_flags pd_state __rte_unused,
			void *arg)
{
	struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);
	const struct ifnet *ifp = arg;
	unsigned int i, matches = 0;
	struct in6_addr inaddr;
	struct lpm6 *lpm;

	for (i = 0; i < nextu->nsiblings; i++) {
		struct next_hop *nh = nextu->siblings + i;

		if (dp_nh_get_ifp(nh) == ifp) {
			/* No longer check if connected, as kernel will not
			 * signal explicitly for flushing
			 */
			nh->flags |= RTF_DEAD;
			++matches;
		} else if (nh->flags & RTF_DEAD)
			++matches;
	}

	if (matches == 0)
		return;

	/*
	 * Delete the route as we can't have entries in the routing table
	 * that use interfaces that have been deleted. We will get another
	 * route event to bring us back to the correct state if we have
	 * thrown away some of the ecmp paths. This is similar to the v4
	 * behaviour.
	 */
	lpm = rcu_dereference(vrf->v_rt6_head.rt6_table[table_id]);
	memcpy(&inaddr.s6_addr, addr, sizeof(inaddr.s6_addr));
	route_lpm6_delete(vrf->v_id, lpm, &inaddr,
			      prefix_len, NULL, scope);
	nexthop6_put(next_hop);
}

static void rt6_if_clear_slowpath_flag(
	struct vrf *vrf __unused,
	uint32_t table_id __unused,
	const uint8_t *addr __unused,
	uint32_t prefix_len __unused,
	int16_t scope __unused,
	uint32_t next_hop,
	struct pd_obj_state_and_flags pd_state __rte_unused,
	void *arg)
{
	const struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);
	const struct ifnet *ifp = arg;
	unsigned int i;

	for (i = 0; i < nextu->nsiblings; i++) {
		struct next_hop *nh = nextu->siblings + i;

		if (dp_nh_get_ifp(nh) == ifp)
			nh->flags &= ~RTF_SLOWPATH;
	}
}

static void rt6_if_set_slowpath_flag(
	struct vrf *vrf __unused,
	uint32_t table_id __unused,
	const uint8_t *addr __unused,
	uint32_t prefix_len __unused,
	int16_t scope __unused, uint32_t next_hop,
	struct pd_obj_state_and_flags pd_state __rte_unused,
	void *arg)
{
	const struct next_hop_u *nextu =
		rcu_dereference(nh6_tbl.entry[next_hop]);
	const struct ifnet *ifp = arg;
	unsigned int i;

	for (i = 0; i < nextu->nsiblings; i++) {
		struct next_hop *nh = nextu->siblings + i;

		if (dp_nh_get_ifp(nh) == ifp)
			nh->flags |= RTF_SLOWPATH;
	}
}

/* Explicitly stop routes pointing to this interface punting to slowpath */
void rt6_if_handle_in_dataplane(struct ifnet *ifp)
{
	rt6_lpm_walk_util(rt6_if_clear_slowpath_flag, ifp);
}

/* Explicitly make routes pointing to this interface punt to slowpath */
void rt6_if_punt_to_slowpath(struct ifnet *ifp)
{
	rt6_lpm_walk_util(rt6_if_set_slowpath_flag, ifp);
}

static void rt6_if_delete(struct ifnet *ifp, uint32_t idx __unused)
{
	rt6_lpm_walk_util(rt6_if_dead, ifp);
}

static int rt6_walk(struct route6_head *rt6_head, json_writer_t *json,
		    uint32_t id, uint32_t cnt, enum rt_walk_type type)
{
	lpm6_walk_func_t cb = rt6_display;
	struct lpm6 *lpm = rt6_get_lpm(rt6_head, id);
	struct lpm6_walk_arg r_arg = {
		.is_segment = (cnt != UINT32_MAX),
		.walk_arg = json,
		.addr = IN6ADDR_ANY_INIT,
		.cnt = cnt,
	};

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE6, "Unknown route table\n");
		return 0;
	}

	if (type == RT_WALK_ALL)
		cb = rt6_display_all;

	if (lpm6_walk_safe(lpm, cb, &r_arg)) {
		jsonw_start_object(json);
		jsonw_string_field(json, "prefix", "more");
		jsonw_end_object(json);
	}
	return 0;
}

static int rt6_walk_next(struct route6_head *rt6_head, json_writer_t *json,
			 uint32_t id, const struct in6_addr *addr, uint8_t plen,
			 uint32_t cnt, enum rt_walk_type type)
{
	lpm6_walk_func_t cb = rt6_display;
	struct lpm6 *lpm = rt6_get_lpm(rt6_head, id);
	struct lpm6_walk_arg r_arg = {
		.is_segment = true,
		.get_next = true,
		.walk_arg = json,
		.addr = *addr,
		.cnt = cnt,
		.depth = plen,
	};

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE6, "Unknown route table\n");
		return 0;
	}

	if (type == RT_WALK_ALL)
		cb = rt6_display_all;

	if (lpm6_walk_safe(lpm, cb, &r_arg)) {
		jsonw_start_object(json);
		jsonw_string_field(json, "prefix", "more");
		jsonw_end_object(json);
	}
	return 0;
}

void rt6_local_show(struct route6_head *rt6_head, FILE *f)
{
	struct lpm6 *lpm = rt6_get_lpm(rt6_head, RT_TABLE_MAIN);

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE6, "Unknown route table\n");
		return;
	}

	lpm6_walk_all_safe(lpm, rt6_local_display, f);
}

static void rt6_summarize(const uint8_t *addr,
			  uint32_t prefix_len, int16_t scope,
			  uint32_t next_hop,
			  struct pd_obj_state_and_flags pd_state __rte_unused,
			  void *arg __rte_unused)
{
	const struct next_hop_u *nextu;
	const struct next_hop *nh;
	uint32_t *rt_used = arg;

	nextu = rcu_dereference(nh6_tbl.entry[next_hop]);
	if (unlikely(!nextu))
		return;

	nh = rcu_dereference(nextu->siblings);
	/* Filter local route being displayed */
	if (nh->flags & RTF_LOCAL)
		return;

	if (rt6_is_reserved(addr, prefix_len, scope))
		return;

	++rt_used[prefix_len];
}

static int rt6_stats(struct route6_head *rt6_head, json_writer_t *json,
		     uint32_t id)
{
	uint32_t depth;
	unsigned int total = 0;
	uint32_t rt_used[LPM6_MAX_DEPTH + 1] = { 0 };
	struct lpm6 *lpm = rt6_get_lpm(rt6_head, id);

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE6, "Unknown route table\n");
		return 0;
	}

	lpm6_walk_all_safe(lpm, rt6_summarize, rt_used);

	jsonw_name(json, "prefix");
	jsonw_start_object(json);
	for (depth = 0; depth <= LPM6_MAX_DEPTH; depth++) {
		total += rt_used[depth];
		if (rt_used[depth]) {
			char buf[20];

			snprintf(buf, sizeof(buf), "%u", depth);
			jsonw_uint_field(json, buf, rt_used[depth]);
		}

	}
	jsonw_end_object(json);

	jsonw_uint_field(json, "total", total);

	jsonw_name(json, "nexthop");
	jsonw_start_object(json);
	jsonw_uint_field(json, "used", nh6_tbl.in_use);
	jsonw_uint_field(json, "free", NEXTHOP_HASH_TBL_SIZE - nh6_tbl.in_use);
	jsonw_uint_field(json, "neigh_present", nh6_tbl.neigh_present);
	jsonw_uint_field(json, "neigh_created", nh6_tbl.neigh_created);
	jsonw_end_object(json);

	/*
	 * PLEASE NOTE: While the tbl8 stats are not used for the show cmds
	 * they are still used in the UT to assess correct purging of routes
	 * and its associated tbl8s
	 */
	jsonw_name(json, "tbl8s");
	jsonw_start_object(json);
	jsonw_uint_field(json, "used", lpm6_tbl8_used_count(lpm));
	jsonw_uint_field(json, "free", lpm6_tbl8_unused_count(lpm));
	jsonw_end_object(json);

	return 0;
}

static int rt6_show(struct route6_head *rt6_head, json_writer_t *json,
		    uint32_t tbl_id, const struct in6_addr *dst)
{
	struct lpm6 *lpm6 = rt6_get_lpm(rt6_head, tbl_id);
	char b1[INET6_ADDRSTRLEN];
	uint32_t next_hop;

	if (lpm6 == NULL) {
		RTE_LOG(ERR, ROUTE6, "Unknown route table\n");
		return 0;
	}

	jsonw_start_object(json);
	jsonw_string_field(json, "address",
			   inet_ntop(AF_INET6, dst, b1, sizeof(b1)));

	if (lpm6_lookup(lpm6, dst->s6_addr, &next_hop) != 0)
		jsonw_string_field(json, "state", "nomatch");
	else
		rt6_print_nexthop(json, next_hop, RT_PRINT_NH_DETAIL);
	jsonw_end_object(json);

	return 0;
}

static int rt6_show_exact(struct route6_head *rt6_head, json_writer_t *json,
			  uint32_t tbl_id, const struct in6_addr *dst,
			  uint8_t plen)
{
	struct lpm6 *lpm6 = rt6_get_lpm(rt6_head, tbl_id);
	char b2[INET6_ADDRSTRLEN + sizeof("/255")];
	char b1[INET6_ADDRSTRLEN];
	uint32_t next_hop;

	if (lpm6 == NULL) {
		RTE_LOG(ERR, ROUTE6, "Unknown route table\n");
		return 0;
	}

	jsonw_start_object(json);
	sprintf(b2, "%s/%u",
		inet_ntop(AF_INET6, dst, b1, sizeof(b1)), plen);
	jsonw_string_field(json, "prefix", b2);

	if (lpm6_lookup_exact(lpm6, dst->s6_addr, plen, &next_hop) != 0)
		jsonw_string_field(json, "state", "nomatch");
	else
		rt6_print_nexthop(json, next_hop, RT_PRINT_NH_DETAIL);
	jsonw_end_object(json);

	return 0;
}

int cmd_route6(FILE *f, int argc, char **argv)
{
	uint32_t tblid = RT_TABLE_MAIN;
	vrfid_t vrf_id = VRF_DEFAULT_ID;
	struct vrf *vrf;

	if (argc >= 3 && strcmp(argv[1], "vrf_id") == 0) {
		vrf_id = strtoul(argv[2], NULL, 10);
		argc -= 2;
		argv += 2;
	}

	if (argc > 1 && strcmp(argv[1], "table") == 0) {
		if (argc == 2) {
			fprintf(f, "missing table id\n");
			return -1;
		}

		const char *name = argv[2];
		char *endp;

		tblid = strtoul(name, &endp, 0);
		if (*name == '\0' || *endp != '\0') {
			fprintf(f, "invalid table id\n");
			return -1;
		}
		/* skip "table N" */
		argc -= 2;
		argv += 2;
	}

	if (vrf_is_vrf_table_id(tblid)) {
		if (vrf_lookup_by_tableid(tblid, &vrf_id, &tblid) < 0) {
			fprintf(f, "no vrf exists for table %u\n", tblid);
			return -1;
		}
		vrf = vrf_get_rcu(vrf_id);
	} else {
		vrf = dp_vrf_get_rcu_from_external(vrf_id);
	}

	if (vrf == NULL) {
		fprintf(f, "no vrf exists\n");
		return -1;
	}

	json_writer_t *json = jsonw_new(f);
	int err = -1;

	if (argc == 1 || strcmp(argv[1], "show") == 0 ||
	    strcmp(argv[1], "all") == 0) {
		enum rt_walk_type route_type = RT_WALK_RIB;

		if (argc > 1 && strcmp(argv[1], "all") == 0)
			route_type = RT_WALK_ALL;

		if (argc >= 6 && strcmp(argv[2], "get-next") == 0) {
			struct in6_addr addr;
			long plen;
			long cnt;

			if (inet_pton(AF_INET6, argv[3], &addr) == 0) {
				fprintf(f, "invalid address\n");
				goto error;
			}
			plen = strtol(argv[4], NULL, 10);
			if (plen < 0 || plen > 128) {
				fprintf(f, "invalid prefix length\n");
				goto error;
			}
			cnt = strtol(argv[5], NULL, 10);
			if (cnt < 0 || cnt > UINT32_MAX) {
				fprintf(f, "invalid count\n");
				goto error;
			}

			jsonw_name(json, "route6_show");
			jsonw_start_array(json);
			err = rt6_walk_next(&vrf->v_rt6_head, json, tblid,
					    &addr, plen, cnt, route_type);
			jsonw_end_array(json);
		} else {
			long cnt;

			if (argc > 2) {
				cnt = strtol(argv[2], NULL, 10);
				if (cnt < 0 || cnt > UINT32_MAX) {
					fprintf(f, "invalid count\n");
					goto error;
				}
			} else {
				cnt = UINT32_MAX;
			}

			jsonw_name(json, "route6_show");
			jsonw_start_array(json);
			err = rt6_walk(&vrf->v_rt6_head, json, tblid,
				       cnt, route_type);
			jsonw_end_array(json);
		}
	} else if (strcmp(argv[1], "summary") == 0) {
		jsonw_name(json, "route6_stats");
		jsonw_start_object(json);
		err = rt6_stats(&vrf->v_rt6_head, json, tblid);
		jsonw_end_object(json);
	} else if (strcmp(argv[1], "lookup") == 0) {
		struct in6_addr in6;
		long plen = -1;

		if (argc == 2) {
			fprintf(f, "missing address\n");
			goto error;
		}

		if (inet_pton(AF_INET6, argv[2], &in6) == 0) {
			RTE_LOG(ERR, ROUTE6, "invalid address\n");
			goto error;
		}

		if (argc > 3) {
			plen = strtol(argv[3], NULL, 10);
			if (plen < 0 || plen > 128) {
				fprintf(f, "invalid prefix length\n");
				goto error;
			}
		}

		jsonw_name(json, "route6_lookup");
		jsonw_start_array(json);
		if (plen >= 0)
			err = rt6_show_exact(&vrf->v_rt6_head, json, tblid,
					     &in6, plen);
		else
			err = rt6_show(&vrf->v_rt6_head, json, tblid, &in6);
		jsonw_end_array(json);
	} else if (strcmp(argv[1], "platform") == 0) {

		long cnt = UINT32_MAX;

		if (argc > 2) {
			cnt = strtol(argv[2], NULL, 10);
			if (cnt < 0 || cnt > UINT32_MAX) {
				fprintf(f, "invalid count\n");
				goto error;
			}
		}
		struct fal_attribute_t attr_list[] = {
			{ FAL_ROUTE_WALK_ATTR_VRFID,
			.value.u32 = vrf_id },
			{ FAL_ROUTE_WALK_ATTR_TABLEID,
			.value.u32 = tblid },
			{ FAL_ROUTE_WALK_ATTR_CNT,
			.value.u32 = cnt },
			{ FAL_ROUTE_WALK_ATTR_FAMILY,
			.value.u32 = FAL_IP_ADDR_FAMILY_IPV6 },
			{ FAL_ROUTE_WALK_ATTR_TYPE,
			.value.u32 = FAL_ROUTE_WALK_TYPE_ALL },
		};

		jsonw_name(json, "route6_platform_show");

		jsonw_start_array(json);

		err = fal_ip_walk_routes(rt_show_platform_routes,
					 RTE_DIM(attr_list),
					 attr_list, json);
		jsonw_end_array(json);

		/*TODO For scale, get_next from a prefix can be added */

	} else {
		fprintf(f,
			"Usage: route6 [vrf_id ID] [table N] [show]\n"
			"       route6 [vrf_id ID] [table N] all\n"
			"       route6 [vrf_id ID] [table N] summary\n"
			"       route6 [vrf_id ID] [table N] lookup ADDR <PREFIXLENGTH>\n"
			"       route6 [vrf_id ID] [table N] platform [cnt]\n");
	}

error:
	jsonw_destroy(&json);
	return err;
}

int handle_route6(vrfid_t vrf_id, uint16_t type, const struct rtmsg *rtm,
		  uint32_t table, const void *dest, const void *gateway,
		  unsigned int ifindex, uint8_t scope, struct nlattr *mpath,
		  uint32_t nl_flags, uint16_t num_labels, label_t *labels)
{
	uint32_t depth = rtm->rtm_dst_len;
	struct in6_addr dst = *(const struct in6_addr *)dest;
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);
	struct in6_addr gw = *(struct in6_addr *)gateway;
	struct next_hop *next;
	uint32_t size;
	uint32_t flags = 0;
	bool missing_ifp = false;
	bool exp_ifp = true;

	if (rtm->rtm_type != RTN_UNICAST  &&
	    rtm->rtm_type != RTN_LOCAL &&
	    rtm->rtm_type != RTN_BLACKHOLE &&
	    rtm->rtm_type != RTN_UNREACHABLE)
		return 0;

	if (rtm->rtm_family != AF_INET6)
		return 0;

	if (IN6_IS_ADDR_LOOPBACK(&dst))
		return 0;

	if (IN6_IS_ADDR_UNSPEC_LINKLOCAL(&dst))
		return 0;

	/*
	 * If LOCAL unicast then ensure we replace any connected
	 * /128 which may have preceded it unless it's linklocal
	 * which need not be unique.
	 * Also ignore any ff00::/8 summary routes for multicast.
	 */
	if (rtm->rtm_type == RTN_LOCAL) {
		if (!IN6_IS_ADDR_LINKLOCAL(&dst))
			nl_flags |= NLM_F_REPLACE;
	} else if (rtm->rtm_type == RTN_UNICAST &&
		   IN6_IS_ADDR_MULTICAST(&dst) && depth == 8) {
		return 0;
	}

	if (type == RTM_NEWROUTE) {
		if (rtm->rtm_type == RTN_BLACKHOLE) {
			flags |= RTF_BLACKHOLE;
			exp_ifp = false;
		} else if (rtm->rtm_type == RTN_UNREACHABLE) {
			flags |= RTF_REJECT;
			exp_ifp = false;
		} else if (rtm->rtm_type == RTN_LOCAL) {
			flags |= RTF_LOCAL;
			/* no need to store ifp for local routes */
			ifp = NULL;
			exp_ifp = false;
		} else if ((num_labels == 0) &&
			   (!ifp || is_lo(ifp))) {
			flags |= RTF_SLOWPATH;
		}

		if (num_labels > 0 && !is_lo(ifp))
			/* Output label rather than local label */
			flags |= RTF_OUTLABEL;

		if (!(nl_flags & NL_FLAG_ANY_ADDR))
			flags |= RTF_GATEWAY;

		if (mpath) {
			next = ecmp6_create(mpath, &size, &missing_ifp);
			if (missing_ifp)
				return -1;
		} else {
			if (exp_ifp && !ifp && !is_ignored_interface(ifindex))
				return -1;
			size = 1;
			next = nexthop6_create(ifp, &gw, flags, num_labels,
					labels);
		}

		if (unlikely(!next))
			return 0;

		rcu_read_unlock();
		rt6_add(vrf_id, &dst, depth, table, scope, next, size);
		rcu_read_lock();
		free(next);
	} else if (type == RTM_DELROUTE) {
		rt6_delete(vrf_id, &dst, depth, table, scope,
			   rtm->rtm_type == RTN_LOCAL);
	}

	return 0;
}

/*
 * Get egress interface for destination address.
 *
 * Must only be used on master thread.
 * Note for multipath routes, the first interface is always returned.
 */
struct ifnet *nhif_dst_lookup6(const struct vrf *vrf,
			       const struct in6_addr *dst,
			       bool *connected)
{
	struct ifnet *ifp;
	const struct next_hop_u *nextu;
	const struct next_hop *next;
	uint32_t nhindex;

	if (lpm6_lookup(vrf->v_rt6_head.rt6_table[RT_TABLE_MAIN],
			    dst->s6_addr, &nhindex) != 0)
		return NULL;

	nextu = nh6_tbl.entry[nhindex];
	if (nextu == NULL)
		return NULL;

	next = nextu->siblings;
	if (next == NULL)
		return NULL;

	ifp = dp_nh_get_ifp(next);
	if (ifp && connected)
		*connected = nh6_is_connected(next);

	return ifp;
}

static void
route6_create_neigh(struct vrf *vrf, struct lpm6 *lpm,
		    uint32_t table_id, struct in6_addr *ip,
		    struct llentry *lle)
{
	struct next_hop_u *nextu;
	uint32_t nh_idx;
	struct next_hop *nh;
	struct next_hop *cover_nh;
	struct ifnet *ifp = rcu_dereference(lle->ifp);
	int sibling;
	int size;

	if (lpm6_lookup(lpm, ip->s6_addr, &nh_idx) == 0) {
		nextu = rcu_dereference(nh6_tbl.entry[nh_idx]);

		/*
		 * Note that this does not support a connected with multiple
		 * paths that use the same ifp.
		 */
		cover_nh = nextu6_find_path_using_ifp(nextu, ifp, &sibling);
		if (cover_nh && nh6_is_connected(cover_nh)) {
			/*
			 * Have a connected cover so create a new entry for
			 * this. Will only be 1 NEIGH_CREATED path, but
			 * need to inherit other paths from the cover.
			 */
			nh = nexthop6_create_copy(nextu, &size);
			if (!nh)
				return;

			/*
			 * Set the correct NH to be NEIGH_CREATED. As this
			 * is copied from the cover nextu, the sibling gives
			 * the NH for the correct interface
			 */
			nh6_set_neigh_created(&nh[sibling], lle);
			/*
			 * This is a /128 we are creating, therefore not a GW.
			 * Set the GW (but not the flag) so that we do not
			 * share with non /128 routes such as the connected
			 * cover.
			 */
			nh[sibling].gateway6 = *ip;
			if (route_nexthop6_new(nh, size, &nh_idx) < 0) {
				free(nh);
				return;
			}
			route_lpm6_add(vrf->v_id, lpm, ip, 128,
				       nh_idx, RT_SCOPE_LINK, table_id);
			free(nh);
		}
	}
}

/*
 * On an arp del, should we clear NEIGH_PRESENT from this NH.
 */
static enum nh_change
routing_neigh_del_gw_nh_replace_cb(struct next_hop *next,
				   int sibling __unused,
				   void *arg)
{
	struct llentry *lle = arg;
	struct in6_addr *ip = ll_ipv6_addr(lle);
	struct ifnet *ifp = rcu_dereference(lle->ifp);

	if (!nh6_is_gw(next) || !IN6_ARE_ADDR_EQUAL(&next->gateway6,
						    &ip->s6_addr))
		return NH_NO_CHANGE;
	if (dp_nh_get_ifp(next) != ifp)
		return NH_NO_CHANGE;
	if (nh6_is_local(next) || !nh6_is_neigh_present(next))
		return NH_NO_CHANGE;

	return NH_CLEAR_NEIGH_PRESENT;
}

static void
walk_nhs_for_neigh_change(struct llentry *lle,
			  enum nh_change (*upd_neigh_present_cb)(
				  struct next_hop *next,
				  int sibling,
				  void *arg))
{
	struct next_hop_u *nhu;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	ASSERT_MASTER();

	cds_lfht_for_each(nexthop6_hash, &iter, node) {
		nhu = caa_container_of(node, struct next_hop_u, nh_node);
		route6_nh_replace(nhu, nhu->index, lle, NULL,
				  upd_neigh_present_cb, lle);
	}
}

struct neigh_add_nh_replace_arg {
	struct ifnet *ifp;
	bool count;
};

/*
 * On a neigh add, should we set this NH as NEIGH_PRESENT, OR NEIGH_CREATED
 *
 * Set to NEIGH_PRESENT in the case where the route existed already, but not
 * because of an neigh entry. If there are any NHs that are NEIGH_CREATED then
 * it only exists due to the neigh entry, so this hop can become NEIGH_CREATED
 * too.
 */
static enum nh_change routing_neigh_add_nh_replace_cb(struct next_hop *next,
						      int sibling __unused,
						      void *arg)
{
	struct neigh_add_nh_replace_arg *args = arg;

	if (!nh6_is_connected(next))
		return NH_NO_CHANGE;

	if (nh6_is_neigh_present(next) || nh6_is_neigh_created(next))
		return NH_NO_CHANGE;
	if (args->ifp != dp_nh_get_ifp(next))
		return NH_NO_CHANGE;

	if (args->count)
		return NH_SET_NEIGH_CREATED;

	return NH_SET_NEIGH_PRESENT;
}

/*
 * On a neigh del NEIGH_PRESENT from this NH.
 */
static enum nh_change routing_neigh_del_nh_replace_cb(struct next_hop *next,
						      int sibling __unused,
						      void *arg)
{
	struct ifnet *ifp = arg;

	if (!nh6_is_connected(next) || !nh6_is_neigh_present(next))
		return NH_NO_CHANGE;
	if (ifp != dp_nh_get_ifp(next))
		return NH_NO_CHANGE;

	return NH_CLEAR_NEIGH_PRESENT;
}

struct neigh_remove_purge_arg {
	int count; /* Count of number of NEIGH_CREATED in parent nextu */
	int sibling; /* Sibling that had the arp entry removed */
};

/*
 * Do we need to purge this NH. If the route was NEIGH_CREATED (any of the
 * paths were NEIGH_CREATED) and this path has had the neigh entry removed then
 * it either needs to be removed, or have NEIGH_CREATED removed.
 * If it is the last NEIGH_CREATED path then all paths to be removed.
 * If there will still be a NEIGH_CREATED path then this path should have
 * NEIGH_CREATED removed and revert back to inheriting from the cover.
 */
static enum nh_change
neigh_removal_nh_purge_cb(struct next_hop *next __unused,
						int sibling,
						void *arg)
{
	struct neigh_remove_purge_arg *args = arg;

	if (sibling == args->sibling) {
		if (args->count > 1)
			return NH_CLEAR_NEIGH_CREATED;
		else
			return NH_DELETE;
	}

	if (args->count > 1)
		return NH_NO_CHANGE;

	return NH_DELETE;
}

void routing6_insert_neigh_safe(struct llentry *lle, bool neigh_change)
{
	struct in6_addr *ip = ll_ipv6_addr(lle);
	struct vrf *vrf = get_vrf(if_vrfid(lle->ifp));
	struct lpm6 *lpm;
	struct next_hop_u *nextu;
	uint32_t nh_idx;
	struct ifnet *ifp = rcu_dereference(lle->ifp);
	struct next_hop *nh;
	int sibling;

	lpm = rcu_dereference(vrf->v_rt6_head.rt6_table[RT_TABLE_MAIN]);
	pthread_mutex_lock(&route6_mutex);
	if (lpm6_lookup_exact(lpm, ip->s6_addr, 128, &nh_idx) == 0) {
		/* We already have a /128 so add the shortcut if connected */
		nextu = rcu_dereference(nh6_tbl.entry[nh_idx]);

		/*
		 * Do we already have a nh for this interface?
		 * If so then we might need to modify it. As this is
		 * called when a route changes, we migh also need to
		 * modify the set of NHs, to reflect the ones the
		 * cover has.
		 */
		nh = nextu6_find_path_using_ifp(nextu, ifp, &sibling);
		if (nh) {
			struct neigh_add_nh_replace_arg arg = {
				.ifp = ifp,
				.count = nextu6_nc_count(nextu),
			};

			route6_nh_replace(nextu, nh_idx, lle, NULL,
					  routing_neigh_add_nh_replace_cb,
					  &arg);
		}

	} else {
		/* Have to create a /128. but only if cover is connected. */
		route6_create_neigh(vrf, lpm, RT_TABLE_MAIN, ip, lle);
	}
	pthread_mutex_unlock(&route6_mutex);

	/*
	 * If this is not a neigh change don't do this here as it will lead
	 * to something like an n squared issue as we call this func for all
	 * lle entries. The caller will do an equivalent after.
	 */
	if (neigh_change)
		/*
		 * Now walk the NHs using this interface that have the GW
		 * set as this IP address. For each of them add the link
		 * to the arp entry and mark as NEIGH_PRESENT.
		 */
		walk_nhs_for_neigh_change(lle,
					  routing_neigh_add_gw_nh_replace_cb);
}

void routing6_remove_neigh_safe(struct llentry *lle)
{
	struct in6_addr *ip = ll_ipv6_addr(lle);
	struct vrf *vrf = get_vrf(if_vrfid(lle->ifp));
	struct lpm6 *lpm;
	struct next_hop_u *nextu;
	uint32_t nh_idx;
	struct ifnet *ifp = rcu_dereference(lle->ifp);
	int sibling;
	struct next_hop *nh;

	lpm = rcu_dereference(vrf->v_rt6_head.rt6_table[RT_TABLE_MAIN]);
	pthread_mutex_lock(&route6_mutex);
	if (lpm6_lookup_exact(lpm, ip->s6_addr, 128, &nh_idx) == 0) {
		/* We have a /128 so unlink the arp (if there) */
		nextu = rcu_dereference(nh6_tbl.entry[nh_idx]);

		/* Do we already have a nh for this interface? */
		nh = nextu6_find_path_using_ifp(nextu, ifp, &sibling);
		if (nh && nh6_is_neigh_created(nh)) {
			/* Are we removing a path or the entire NH */
			if (nextu->nsiblings == 1) {
				route_lpm6_delete(vrf->v_id, lpm, ip, 128,
						      &nh_idx, RT_SCOPE_LINK);
				nexthop6_put(nh_idx);
			} else {
				struct neigh_remove_purge_arg args = {
					.count = nextu6_nc_count(nextu),
					.sibling = sibling,
				};
				uint32_t del;
				uint32_t new_nh_idx;

				del = route6_nh_replace(
					nextu, nh_idx, lle,
					&new_nh_idx,
					neigh_removal_nh_purge_cb,
					&args);
				/* Can not delete a subset of paths here */
				if (del == nextu->nsiblings) {
					route_lpm6_delete(vrf->v_id, lpm,
							      ip, 128, &nh_idx,
							      RT_SCOPE_LINK);
					nexthop6_put(nh_idx);
				}
			}
		} else {
			route6_nh_replace(nextu, nh_idx, NULL, NULL,
					  routing_neigh_del_nh_replace_cb, ifp);
		}
	}
	pthread_mutex_unlock(&route6_mutex);

	/*
	 * Now walk the NHs using this interface that have the GW
	 * set as this IP address. For each of them remove the link
	 * to the arp entry as it is going away
	 */
	walk_nhs_for_neigh_change(lle, routing_neigh_del_gw_nh_replace_cb);
}

uint32_t *route6_sw_stats_get(void)
{
	return route6_sw_stats;
}

uint32_t *route6_hw_stats_get(void)
{
	return route6_hw_stats;
}

struct rt6_show_subset {
	json_writer_t *json;
	enum pd_obj_state subset;
	vrfid_t vrf;
};

static void rt6_show_subset(struct vrf *vrf, uint32_t tableid,
			    const uint8_t *ip, uint32_t depth, int16_t scope,
			    uint32_t idx,
			    struct pd_obj_state_and_flags pd_state,
			    void *arg)
{
	struct rt6_show_subset *subset = arg;

	if (subset->vrf != vrf->v_id) {
		subset->vrf = vrf->v_id;
		jsonw_start_object(subset->json);
		jsonw_uint_field(subset->json, "vrf_id",
				 dp_vrf_get_external_id(vrf->v_id));
		jsonw_uint_field(subset->json, "table",
				 tableid);
		jsonw_end_object(subset->json);
	}

	if (subset->subset == pd_state.state)
		rt6_display_all(ip, depth, scope, idx, pd_state,
				subset->json);
}


int route6_get_pd_subset_data(json_writer_t *json,
			      enum pd_obj_state subset)
{
	struct rt6_show_subset arg = {
		.json = json,
		.subset = subset,
		.vrf = VRF_INVALID_ID,
	};
	rt6_lpm_walk_util(rt6_show_subset, &arg);

	return 0;
}

static const struct dp_event_ops route6_events = {
	.if_index_unset = rt6_if_delete,
	.vrf_delete = rt6_flush,
};

DP_STARTUP_EVENT_REGISTER(route6_events);
