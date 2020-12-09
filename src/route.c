/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <stdbool.h>
#include <stdint.h>
/*
 * IPv4 route table
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "compat.h"
#include "dp_event.h"
#include "ecmp.h"
#include "fal.h"
#include "ip_forward.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "json_writer.h"
#include "lcore_sched.h"
#include "lpm/lpm.h"	/* Use Vyatta modified version */
#include "mpls/mpls.h"
#include "mpls/mpls_label_table.h"
#include "pktmbuf_internal.h"
#include "pd_show.h"
#include "route.h"
#include "urcu.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"

struct rte_mbuf;

/* These are stored in a memory pool to allow for mapping
 * index/offset into pointer:
 *
 * addr   +----------+
 *   ---->|          |
 *        |  L P M   | idx +--------------+
 *        |          +---->| nexthop_list |
 *        |          |     +--------------+
 *        |          |     |              |
 *        +----------+     +--------------+
 *                         |  nexthop     |
 *                         |     0        |
 *                         +--------------+
 *                         |    ...       |
 *                         +--------------+
 *                         |  nexthop     |
 *                         | count - 1    |
 *                         +--------------+
 */

/* Nexthop entry table, could be per-namespace */
static struct nexthop_table nh_tbl __hot_data;

/* Index for next hop table */
static struct cds_lfht *nexthop_hash;

/* Well-known blackhole next_hop_list for failure cases */
static struct next_hop_list *nextl_blackhole;

static pthread_mutex_t route_mutex = PTHREAD_MUTEX_INITIALIZER;

static const struct reserved_route {
	in_addr_t addr;
	int prefix_length;
	uint32_t flags;
	int scope;
} reserved_routes[] = {
	{
		.addr = 0,
		.prefix_length = 0,
		.flags = RTF_NOROUTE | RTF_REJECT,
		.scope = LPM_SCOPE_PAN_DIMENSIONAL,
	},
	{
		.addr = 0x7f000000, /* loopback */
		.prefix_length = 8,
		.flags = RTF_BLACKHOLE,
		.scope = RT_SCOPE_HOST,
	},
	{
		.addr = INADDR_BROADCAST,
		.prefix_length = 32,
		.flags = RTF_BROADCAST | RTF_LOCAL,
		.scope = RT_SCOPE_HOST,
	},
};

/* track the state of routes for the show commands */
static uint32_t route_sw_stats[PD_OBJ_STATE_LAST];
static uint32_t route_hw_stats[PD_OBJ_STATE_LAST];

static struct nexthop_table *route_get_nh_table(void)
{
	return &nh_tbl;
}

static struct cds_lfht *route_get_nh_hash_table(void)
{
	return nexthop_hash;
}

/*
 * Wrapper round the nexthop_new function. This one keeps track of the
 * failures and successes.
 */
static int
route_nexthop_new(const struct next_hop *nh, uint16_t size, uint8_t proto,
		  uint32_t *slot)
{
	int rc;

	rc = nexthop_new(AF_INET, nh, size, proto, FAL_NHG_USE_IP, slot);
	if (rc >= 0)
		return rc;

	switch (rc) {
	case -ENOSPC:
		route_sw_stats[PD_OBJ_STATE_NO_RESOURCE]++;
		break;
	default:
		route_sw_stats[PD_OBJ_STATE_ERROR]++;
		break;
	}

	return rc;
}

/*
 * Wrapper round the lpm function. This one keeps track of the
 * failures and successes.
 */
static int
route_lpm_add(vrfid_t vrf_id, struct lpm *lpm, uint32_t ip,
	      uint8_t depth, uint32_t next_hop, int16_t scope)
{
	int rc;
	struct pd_obj_state_and_flags *pd_state;
	struct pd_obj_state_and_flags *old_pd_state;
	enum pd_obj_state nhl_pd_state;
	fal_object_t nhg_fal_obj;
	struct next_hop *hops;
	uint32_t old_nh;
	bool demoted = false;
	bool update_pd_state = true;
	size_t size;

	rc = lpm_add(lpm, ntohl(ip), depth, next_hop, scope, &pd_state,
			 &old_nh, &old_pd_state);
	switch (rc) {
	case LPM_SUCCESS:
		/* Success */
		route_sw_stats[PD_OBJ_STATE_FULL]++;
		break;
	case LPM_HIGHER_SCOPE_EXISTS:
		/*
		 * Success, but there is a higher scope rule, so this is
		 * not needed in the fal.
		 */
		route_sw_stats[PD_OBJ_STATE_NOT_NEEDED]++;
		pd_state->state = PD_OBJ_STATE_NOT_NEEDED;
		return rc;
	case LPM_LOWER_SCOPE_EXISTS:
		/* Added, but lower scope route was demoted. */
		demoted = true;
		route_sw_stats[PD_OBJ_STATE_NOT_NEEDED]++;
		break;
	case LPM_ALREADY_EXISTS:
		/* Added, but already existed. */
		return 0;
	case -ENOSPC:
		route_sw_stats[PD_OBJ_STATE_NO_RESOURCE]++;
		return rc;
	default:
		route_sw_stats[PD_OBJ_STATE_ERROR]++;
		return rc;
	}

	size = next_hop_list_get_fal_nhs(AF_INET, next_hop, &hops);
	nhg_fal_obj = next_hop_list_get_fal_obj(
		AF_INET, next_hop, &nhl_pd_state);

	if (nhl_pd_state != PD_OBJ_STATE_FULL &&
	    nhl_pd_state != PD_OBJ_STATE_NOT_NEEDED) {
		pd_state->state = nhl_pd_state;
		update_pd_state = false;
	}

	if (demoted) {
		if (old_pd_state->created) {
			rc = fal_ip4_upd_route(vrf_id, ip, depth,
					       lpm_get_id(lpm),
					       hops, size, nhg_fal_obj);
		} else {
			rc = fal_ip4_new_route(vrf_id, ip, depth,
					       lpm_get_id(lpm),
					       hops, size, nhg_fal_obj);
		}
		if (update_pd_state)
			pd_state->state = fal_state_to_pd_state(rc);
		if (!rc || old_pd_state->created)
			pd_state->created = true;
		route_hw_stats[old_pd_state->state]--;
		old_pd_state->state = PD_OBJ_STATE_NOT_NEEDED;
		route_hw_stats[pd_state->state]++;
		/* Successfully added to SW, so return success. */
		return 0;
	}

	/*
	 * We have successfully added to the lpm, and now need to update the
	 * platform, if there is one.
	 */
	rc = fal_ip4_new_route(vrf_id, ip, depth, lpm_get_id(lpm),
			       hops, size, nhg_fal_obj);
	if (update_pd_state)
		pd_state->state = fal_state_to_pd_state(rc);
	if (!rc)
		pd_state->created = true;
	route_hw_stats[pd_state->state]++;

	/*
	 * If the SW worked, but the HW failed then return success. The
	 * user needs to use the show commands and the notification infra
	 * in this case.
	 */
	return 0;
}

static int
route_lpm_update(vrfid_t vrf_id, struct lpm *lpm,
		 uint32_t ip, uint8_t depth,
		 uint32_t *old_nh,
		 uint32_t next_hop, int16_t scope)
{
	int rc;
	struct pd_obj_state_and_flags pd_state;
	struct pd_obj_state_and_flags *old_pd_state;
	struct pd_obj_state_and_flags *new_pd_state;
	uint32_t new_nh;
	uint32_t dummy_old_nh;
	bool update_new_pd_state = true;
	enum pd_obj_state nhl_pd_state;
	fal_object_t nhg_fal_obj;
	struct next_hop *hops;
	size_t size;

	/*
	 * Remove an old entry from the lpm, and add a new one. lpm
	 * does not currently support make-before-break
	 */
	rc = lpm_delete(lpm, ntohl(ip), depth, old_nh,
			scope, &pd_state, &new_nh,
			&new_pd_state);
	switch (rc) {
	case LPM_SUCCESS:
		/* Success */
		route_sw_stats[PD_OBJ_STATE_FULL]--;
		break;
	case LPM_HIGHER_SCOPE_EXISTS:
		route_sw_stats[PD_OBJ_STATE_NOT_NEEDED]--;
		break;
	case LPM_LOWER_SCOPE_EXISTS:
		/* Deleted, but lower scope was promoted so is now programmed */
		route_sw_stats[PD_OBJ_STATE_NOT_NEEDED]--;
		break;

	default:
		return rc;
	}

	/*
	 * This is a replace, so the old_nh was got from the delete above,
	 * so make sure we don't overwrite that value here
	 */
	rc = lpm_add(lpm, ntohl(ip), depth, next_hop, scope,
		     &new_pd_state, &dummy_old_nh, &old_pd_state);
	switch (rc) {
	case LPM_SUCCESS:
		/* Success */
		route_sw_stats[PD_OBJ_STATE_FULL]++;
		break;
	case LPM_HIGHER_SCOPE_EXISTS:
		/*
		 * Success, but there is a higher scope rule, so this is
		 * not needed in the fal.
		 */
		route_sw_stats[PD_OBJ_STATE_NOT_NEEDED]++;
		break;
	case LPM_LOWER_SCOPE_EXISTS:
		/* Added, but lower scope route was demoted. */
		route_sw_stats[PD_OBJ_STATE_NOT_NEEDED]++;
		break;
	case -ENOSPC:
		route_sw_stats[PD_OBJ_STATE_NO_RESOURCE]++;
		break;
	default:
		route_sw_stats[PD_OBJ_STATE_ERROR]++;
	}

	size = next_hop_list_get_fal_nhs(AF_INET, next_hop, &hops);
	nhg_fal_obj = next_hop_list_get_fal_obj(
		AF_INET, next_hop, &nhl_pd_state);

	if (nhl_pd_state != PD_OBJ_STATE_FULL &&
	    nhl_pd_state != PD_OBJ_STATE_NOT_NEEDED) {
		new_pd_state->state = nhl_pd_state;
		update_new_pd_state = false;
	}

	if (pd_state.created) {
		rc = fal_ip4_upd_route(vrf_id, ip, depth, lpm_get_id(lpm),
				       hops, size, nhg_fal_obj);
	} else {
		rc = fal_ip4_new_route(vrf_id, ip, depth, lpm_get_id(lpm),
				       hops, size, nhg_fal_obj);
	}

	route_hw_stats[pd_state.state]--;
	if (!rc || pd_state.created)
		new_pd_state->created = true;
	if (update_new_pd_state)
		new_pd_state->state = fal_state_to_pd_state(rc);
	route_hw_stats[new_pd_state->state]++;
	/* Successfully added to SW, so return success. */
	return 0;
}

static int
route_lpm_delete(vrfid_t vrf_id, struct lpm *lpm, uint32_t ip,
		 uint8_t depth, uint32_t *next_hop, int16_t scope)

{
	int rc;
	struct pd_obj_state_and_flags pd_state;
	struct pd_obj_state_and_flags *new_pd_state;
	uint32_t new_nh;
	bool promoted = false;

	rc = lpm_delete(lpm, ntohl(ip), depth, next_hop, scope, &pd_state,
			    &new_nh, &new_pd_state);
	switch (rc) {
	case LPM_SUCCESS:
		/* Success */
		route_sw_stats[PD_OBJ_STATE_FULL]--;
		break;
	case LPM_HIGHER_SCOPE_EXISTS:
		/* Deleted, but was not programmed as higher scope exists */
		route_sw_stats[PD_OBJ_STATE_NOT_NEEDED]--;
		assert(pd_state.state == PD_OBJ_STATE_NOT_NEEDED);
		return rc;
	case LPM_LOWER_SCOPE_EXISTS:
		/* Deleted, but lower scope was promoted so is now programmed */
		route_sw_stats[PD_OBJ_STATE_NOT_NEEDED]--;
		promoted = true;
		break;
	default:
		/* Can happen when trying to delete an incomplete route */
		return rc;
	}

	if (promoted) {
		bool update_new_pd_state = true;
		enum pd_obj_state nhl_pd_state;
		fal_object_t nhg_fal_obj;
		struct next_hop *hops;
		size_t size;

		size = next_hop_list_get_fal_nhs(AF_INET, new_nh, &hops);
		nhg_fal_obj = next_hop_list_get_fal_obj(
			AF_INET, new_nh, &nhl_pd_state);

		if (nhl_pd_state != PD_OBJ_STATE_FULL &&
		    nhl_pd_state != PD_OBJ_STATE_NOT_NEEDED) {
			new_pd_state->state = nhl_pd_state;
			update_new_pd_state = false;
		}

		if (pd_state.created) {
			rc = fal_ip4_upd_route(vrf_id, ip, depth,
					       lpm_get_id(lpm),
					       hops, size, nhg_fal_obj);
		} else {
			rc = fal_ip4_new_route(vrf_id, ip, depth,
					       lpm_get_id(lpm),
					       hops, size, nhg_fal_obj);
		}
		if (update_new_pd_state)
			new_pd_state->state = fal_state_to_pd_state(rc);
		if (!rc || pd_state.created)
			new_pd_state->created = true;
		route_hw_stats[pd_state.state]--;
		route_hw_stats[new_pd_state->state]++;
		return 0;
	}

	/* successfully removed and no lower scope promoted */
	if (pd_state.created) {
		rc = fal_ip4_del_route(vrf_id, ip, depth, lpm_get_id(lpm));
		switch (rc) {
		case 0:
			route_hw_stats[pd_state.state]--;
			break;
		default:
			/* General failure */
			break;
		}
	} else
		route_hw_stats[pd_state.state]--;

	/* Successfully deleted from SW, so return success. */
	return 0;
}

/* Dynamically grow LPM table if necessary.
 */
static int rt_lpm_resize(struct route_head *rt_head, uint32_t id)
{
	struct lpm **new_tbl, **old_tbl;
	uint32_t old_id;

	if (id < rt_head->rt_rtm_max)
		return 0;

	new_tbl = malloc_huge_aligned((id + 1) * sizeof(struct lpm *));
	if (new_tbl == NULL) {
		RTE_LOG(ERR, ROUTE,
			"Can't grow LPM table to %u entries\n", id);
		return -1;
	}

	/* Copy existing table */
	old_tbl = rt_head->rt_table;
	old_id = rt_head->rt_rtm_max;
	if (old_tbl)
		memcpy(new_tbl, old_tbl,
		       sizeof(struct lpm *) * rt_head->rt_rtm_max);

	rcu_set_pointer(&rt_head->rt_table, new_tbl);
	rt_head->rt_rtm_max = id + 1;

	if (old_tbl) {
		if (defer_rcu_huge(old_tbl,
				   (old_id * sizeof(struct lpm *)))) {
			RTE_LOG(ERR, LPM, "Failed to free old LPM tbl\n");
			return -1;
		}
	}
	return 0;
}

static bool
rt_lpm_is_empty(struct lpm *lpm)
{
	assert(lpm_rule_count(lpm) >= ARRAY_SIZE(reserved_routes));
	return lpm_rule_count(lpm) == ARRAY_SIZE(reserved_routes);
}

static bool
rt_is_reserved(in_addr_t addr, int prefix_length, int scope)
{
	unsigned int rt_idx;

	for (rt_idx = 0; rt_idx < ARRAY_SIZE(reserved_routes); rt_idx++) {
		if (addr == reserved_routes[rt_idx].addr &&
		    prefix_length == reserved_routes[rt_idx].prefix_length &&
		    scope == reserved_routes[rt_idx].scope)
			return true;
	}

	return false;
}

static bool
rt_lpm_add_reserved_routes(struct lpm *lpm, struct vrf *vrf)
{
	char b[INET_ADDRSTRLEN];
	unsigned int rt_idx;
	struct ip_addr addr_any = {
		.type = AF_INET,
		.address.ip_v4.s_addr = INADDR_ANY,
	};

	if (vrf->v_id == VRF_INVALID_ID)
		return true;

	for (rt_idx = 0; rt_idx < ARRAY_SIZE(reserved_routes); rt_idx++) {
		in_addr_t addr = htonl(reserved_routes[rt_idx].addr);
		struct next_hop *nhop;
		uint32_t nh_idx;
		int err_code;

		nhop = nexthop_create(NULL, &addr_any,
				      reserved_routes[rt_idx].flags,
				      0, NULL);
		if (!nhop)
			return false;

		err_code = route_nexthop_new(nhop, 1, RTPROT_UNSPEC, &nh_idx);
		if (err_code < 0) {
			RTE_LOG(ERR, ROUTE,
				"reserved route add %s/%u failed - cannot create nexthop: %s\n",
				inet_ntop(AF_INET,
					  &addr, b,
					  sizeof(b)),
				reserved_routes[rt_idx].prefix_length,
				strerror(-err_code));
			free(nhop);
			return false;
		}

		err_code = route_lpm_add(
			vrf->v_id,
			lpm,
			addr,
			reserved_routes[rt_idx].prefix_length,
			nh_idx, reserved_routes[rt_idx].scope);
		if (err_code < 0) {
			RTE_LOG(ERR, ROUTE,
				"reserved route %s/%u idx %u add to LPM failed (%d)\n",
				inet_ntop(AF_INET,
					  &addr,
					  b, sizeof(b)),
				reserved_routes[rt_idx].prefix_length,
				nh_idx, err_code);
		}
		free(nhop);
		if (err_code != 0) {
			nexthop_put(AF_INET, nh_idx);
			return false;
		}
	}

	return true;
}

static bool
rt_lpm_del_reserved_routes(struct lpm *lpm, struct vrf *vrf)
{
	char b[INET_ADDRSTRLEN];
	unsigned int rt_idx;

	if (vrf->v_id == VRF_INVALID_ID)
		return true;

	for (rt_idx = 0; rt_idx < ARRAY_SIZE(reserved_routes); rt_idx++) {
		in_addr_t addr = htonl(reserved_routes[rt_idx].addr);
		uint32_t nh_idx;
		int err_code;

		err_code = route_lpm_delete(
			vrf->v_id,
			lpm,
			addr,
			reserved_routes[rt_idx].prefix_length,
			&nh_idx,
			reserved_routes[rt_idx].scope);
		if (err_code < 0) {
			RTE_LOG(ERR, ROUTE,
				"reserved route add %s/%u idx %u failed (%d)\n",
				inet_ntop(AF_INET,
					  &addr,
					  b, sizeof(b)),
				reserved_routes[rt_idx].prefix_length,
				nh_idx, err_code);
			return false;
		}
		nexthop_put(AF_INET, nh_idx);
	}

	return true;
}

/* Create a new LPM table for route table id */
static struct lpm *rt_create_lpm(uint32_t id, struct vrf *vrf)
{
	struct lpm *lpm;

	if (rt_lpm_resize(&vrf->v_rt4_head, id) < 0)
		return NULL;

	lpm = lpm_create(id);
	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE, "Can't create LPM for vrf %u table %u\n",
			vrf->v_id, id);
		return NULL;
	}

	if (!rt_lpm_add_reserved_routes(lpm, vrf)) {
		DP_LOG_W_VRF(ERR, ROUTE, vrf->v_id,
			     "Failed to add reserved routes to table %u\n",
			     id);
		lpm_free(lpm);
		return NULL;
	}

	rcu_assign_pointer(vrf->v_rt4_head.rt_table[id], lpm);

	return lpm;
}

static struct lpm *rt_get_lpm(struct route_head *rt_head, uint32_t id)
{
	if (unlikely(id >= rt_head->rt_rtm_max))
		return NULL;

	return rcu_dereference(rt_head->rt_table[id]);
}

struct next_hop *nexthop_get(uint32_t nh_idx, uint8_t *size)
{
	struct next_hop_list *nextl;

	nextl = rcu_dereference(nh_tbl.entry[nh_idx]);
	*size = nextl->nsiblings;
	return nextl->siblings;
}

/* Check if route table exists */
bool rt_valid_tblid(vrfid_t vrfid, uint32_t tbl_id)
{
	struct vrf *vrf = vrf_get_rcu(vrfid);

	if (!vrf)
		return false;

	return vrf->v_rt4_head.rt_table[tbl_id] != NULL;
}

/*
 * Lookup nexthop based on destination address
 *
 * Returns RCU protected nexthop structure or NULL.
 */
ALWAYS_INLINE __hot_func
struct next_hop *dp_rt_lookup(in_addr_t dst, uint32_t tbl_id,
			      const struct rte_mbuf *m)
{
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	struct vrf *vrf = vrf_get_rcu(vrfid);

	if (!vrf)
		return NULL;

	return rt_lookup_fast(vrf, dst, tbl_id, m);
}

/*
 * Lookup nexthop based on destination address
 *
 * Assumes both the VRF ID is valid and the VRF exists.
 *
 * Returns RCU protected nexthop structure or NULL.
 */
ALWAYS_INLINE
struct next_hop *rt_lookup_fast(struct vrf *vrf, in_addr_t dst,
				uint32_t tblid,
				const struct rte_mbuf *m)
{
	struct next_hop *nh;
	struct lpm *lpm;
	uint32_t idx;

	lpm = rcu_dereference(vrf->v_rt4_head.rt_table[tblid]);

	if (unlikely(lpm_lookup(lpm, ntohl(dst), &idx) != 0))
		return NULL;

	nh = nexthop_select(AF_INET, idx, m, RTE_ETHER_TYPE_IPV4);
	if (nh && unlikely(nh->flags & RTF_NOROUTE))
		return NULL;
	return nh;
}

inline bool is_local_ipv4(vrfid_t vrf_id, in_addr_t dst)
{
	struct vrf *vrf = vrf_get_rcu(vrf_id);
	struct next_hop_list *nextl;
	struct next_hop *next;
	struct lpm *lpm;
	uint32_t idx;

	if (!vrf)
		return false;

	lpm = rcu_dereference(vrf->v_rt4_head.rt_table[RT_TABLE_MAIN]);

	if (unlikely(lpm_lookup(lpm, ntohl(dst), &idx) != 0))
		return false;

	nextl = rcu_dereference(nh_tbl.entry[idx]);
	if (unlikely(!nextl))
		return false;

	next = rcu_dereference(nextl->siblings);
	if (next->flags & RTF_LOCAL)
		return true;

	return false;
}

static int
nexthop_hashfn(const struct nexthop_hash_key *key,
	       unsigned long seed __rte_unused)
{
	size_t size = key->size;
	uint32_t hash_keys[size * 3 + 1];
	struct ifnet *ifp;
	uint16_t i, j = 0;

	for (i = 0; i < size; i++, j += 3) {
		hash_keys[j] = key->nh[i].gateway.address.ip_v4.s_addr;
		ifp = dp_nh_get_ifp(&key->nh[i]);
		hash_keys[j+1] = ifp ? ifp->if_index : 0;
		hash_keys[j+2] = key->nh[i].flags & NH_FLAGS_CMP_MASK;
	}

	hash_keys[size * 3] = key->use;

	return rte_jhash_32b(hash_keys, size * 3 + 1, 0);
}

static int nexthop_cmpfn(struct cds_lfht_node *node, const void *key)
{
	const struct nexthop_hash_key *h_key = key;
	const struct next_hop_list *nl =
		caa_container_of(node, const struct next_hop_list, nh_node);
	uint16_t i;

	if (h_key->size != nl->nsiblings ||
	    h_key->use != nl->use || h_key->proto != nl->proto)
		return false;

	for (i = 0; i < h_key->size; i++) {
		if ((dp_nh_get_ifp(&nl->siblings[i]) !=
		     dp_nh_get_ifp(&h_key->nh[i])) ||
		    ((nl->siblings[i].flags & NH_FLAGS_CMP_MASK) !=
		     (h_key->nh[i].flags & NH_FLAGS_CMP_MASK)) ||
		    (nl->siblings[i].gateway.address.ip_v4.s_addr !=
		     h_key->nh[i].gateway.address.ip_v4.s_addr) ||
		    !nh_outlabels_cmpfn(&nl->siblings[i].outlabels,
					&h_key->nh[i].outlabels))
			return false;
	}
	return true;
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
static int
route_nh_replace(int family, struct next_hop_list *nextl,
		 uint32_t nh_idx, struct llentry *lle,
		 uint32_t *new_nextl_idx_for_del,
		 enum nh_change (*nh_processing_cb)(struct next_hop *next,
						    int sibling,
						    void *arg),
		 void *arg)
{
	struct next_hop_list *new_nextl = NULL;
	struct next_hop *old_array;
	struct next_hop *new_array = NULL;
	enum nh_change nh_change;
	bool any_change = false;
	int i;
	int deleted = 0;

	ASSERT_MAIN();

	/* walk all the NHs, copying as we go */
	old_array = rcu_dereference(nextl->siblings);
	new_nextl = next_hop_list_create_copy_start(AF_INET, nextl);
	if (!new_nextl)
		return 0;

	new_array = rcu_dereference(new_nextl->siblings);

	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *next = old_array + i;
		struct next_hop *new_next = new_array + i - deleted;

		nh_change = nh_processing_cb(next, i, arg);

		/* Copy across old NH */
		if (next_hop_copy(next, new_next) < 0) {
			__nexthop_destroy(new_nextl);
			return 0;
		}

		switch (nh_change) {
		case NH_NO_CHANGE:
			break;
		case NH_SET_NEIGH_CREATED:
			any_change = true;
			nh_set_neigh_created(family, new_next, lle);
			break;
		case NH_CLEAR_NEIGH_CREATED:
			any_change = true;
			nh_clear_neigh_created(family, new_next);
			break;
		case NH_SET_NEIGH_PRESENT:
			any_change = true;
			nh_set_neigh_present(family, new_next, lle);
			break;
		case NH_CLEAR_NEIGH_PRESENT:
			any_change = true;
			nh_clear_neigh_present(family, new_next);
			break;
		case NH_DELETE:
			if (!new_nextl_idx_for_del) {
				__nexthop_destroy(new_nextl);
				return -1;
			}
			any_change = true;
			deleted++;
			break;
		}
	}

	/* Did we make any changes?  If not then we can return */
	if (!any_change) {
		__nexthop_destroy(new_nextl);
		return 0;
	}

	if (deleted) {
		/*
		 * We are deleting at least one nh - create a new
		 * next_hop_list for caller to deal with.
		 */
		if (deleted != nextl->nsiblings &&
		    route_nexthop_new(nextl->siblings, nextl->nsiblings,
				      nextl->proto, new_nextl_idx_for_del) < 0)
			deleted = nextl->nsiblings;
		__nexthop_destroy(new_nextl);
		return deleted;
	}

	if (next_hop_list_create_copy_finish(AF_INET, nextl, new_nextl,
					     nh_idx) < 0)
		RTE_LOG(ERR, ROUTE, "nh replace failed\n");

	return 0;
}

struct subtree_walk_arg {
	uint32_t ip;
	uint8_t depth;
	bool delete;
	struct vrf *vrf;
};

static void subtree_walk_route_cleanup_cb(struct lpm *lpm,
					  uint32_t masked_ip,
					  uint8_t depth, uint32_t idx,
					  void *arg)
{
	struct subtree_walk_arg *changing = arg;
	struct next_hop_list *nextl = rcu_dereference(nh_tbl.entry[idx]);
	uint32_t cover_ip;
	uint8_t cover_depth;
	uint32_t cover_nh_idx;
	int neigh_created = 0;
	int ret;

	if (!nextl)
		return;

	neigh_created = next_hop_list_nc_count(nextl);
	if (neigh_created == 0)
		return;

	/*
	 * If we're changing this route itself then remove the
	 * neigbour created route.
	 */
	if (masked_ip != changing->ip && depth != changing->depth) {
		/*
		 * Is the route we are about to delete the cover of
		 * this route
		 */
		if (lpm_find_cover(lpm, masked_ip, depth, &cover_ip,
				   &cover_depth, &cover_nh_idx)) {
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
		if (changing->ip != cover_ip ||
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
	ret = route_lpm_delete(changing->vrf->v_id,
				   lpm, htonl(masked_ip), 32, &cover_nh_idx,
				   RT_SCOPE_LINK);
	if (ret < 0) {
		char b[INET_ADDRSTRLEN];
		in_addr_t dst = htonl(masked_ip);

		DP_LOG_W_VRF(
			ERR, ROUTE, changing->vrf->v_id,
			"route delete %s/32 failed (%d)\n",
			inet_ntop(AF_INET, &dst, b, sizeof(b)),
			ret);
	}

	nexthop_put(AF_INET, idx);
}

static unsigned int lle_routing_insert_arp_cb(struct lltable *llt __unused,
					  struct llentry *lle,
					  void *arg __unused)
{
	pthread_mutex_unlock(&route_mutex);
	routing_insert_arp_safe(lle, false);
	pthread_mutex_lock(&route_mutex);
	return 0;
}


static void route_change_process_nh(struct next_hop_list *nhl,
				    enum nh_change (*upd_neigh_present_cb)(
					    struct next_hop *next,
					    int sibling,
					    void *arg))
{
	const struct next_hop *array;
	int index;
	int i;


	index = nhl->index;
	array = rcu_dereference(nhl->siblings);
	for (i = 0; i < nhl->nsiblings; i++) {
		const struct next_hop *next = array + i;
		const struct ifnet *ifp = dp_nh_get_ifp(next);

		if (!ifp)
			/* happens for local routes */
			continue;

		if (!nh_is_gw(next))
			continue;

		/*
		 * Is there an lle on this interface with a
		 * matching address.
		 */
		struct llentry *lle = in_lltable_find(
			(struct ifnet *)ifp,
			next->gateway.address.ip_v4.s_addr);
		if (lle) {
			route_nh_replace(AF_INET, nhl, nhl->index, lle, NULL,
					 upd_neigh_present_cb,
					 lle);
			/*
			 * Need to reread as may have been
			 * replaced by prev func, and will not
			 * then be found in hash table.
			 */
			nhl = rcu_dereference(nh_tbl.entry[index]);
			if (!nhl)
				break;
		}
	}
}

static void
walk_nhs_for_route_change(enum nh_change (*upd_neigh_present_cb)(
				  struct next_hop *next,
				  int sibling,
				  void *arg))
{
	struct next_hop_list *nhl;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	ASSERT_MAIN();

	cds_lfht_for_each(nexthop_hash, &iter, node) {
		nhl = caa_container_of(node, struct next_hop_list, nh_node);

		route_change_process_nh(nhl, upd_neigh_present_cb);
	}
}

/*
 * On an arp add, should we set NEIGH_PRESENT from this NH.
 */
static enum nh_change routing_arp_add_gw_nh_replace_cb(struct next_hop *next,
						       int sibling __unused,
						       void *arg)
{
	struct llentry *lle = arg;
	struct in_addr *ip = ll_ipv4_addr(lle);
	struct ifnet *ifp = rcu_dereference(lle->ifp);

	if (!nh_is_gw(next) ||
	    (next->gateway.address.ip_v4.s_addr != ip->s_addr))
		return NH_NO_CHANGE;
	if (dp_nh_get_ifp(next) != ifp)
		return NH_NO_CHANGE;
	if (nh_is_local(next) || nh_is_neigh_present(next) ||
		nh_is_neigh_created(next))
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
route_change_link_arp(struct vrf *vrf, struct lpm *lpm,
		      uint32_t ip, uint8_t depth, uint32_t next_hop,
		      int16_t scope __unused)
{
	int i;
	const struct next_hop_list *nextl;
	const struct next_hop *array;
	struct subtree_walk_arg subtree_arg = {
		.ip = ip,
		.depth = depth,
		.delete = false,
		.vrf = vrf,
	};
	uint32_t cover_ip;
	uint8_t cover_depth;
	uint32_t cover_idx;

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
	nextl = rcu_dereference(nh_tbl.entry[next_hop]);
	if (next_hop_list_is_any_connected(nextl)) {
		lpm_subtree_walk(lpm, ip, depth,
				 subtree_walk_route_cleanup_cb,
				 &subtree_arg);
	} else if (lpm_find_cover(lpm, ip, depth, &cover_ip,
				  &cover_depth, &cover_idx) == 0) {
		const struct next_hop_list *cover_nextl;

		cover_nextl = rcu_dereference(nh_tbl.entry[cover_idx]);
		if (next_hop_list_is_any_connected(cover_nextl)) {
			lpm_subtree_walk(lpm, ip, depth,
					 subtree_walk_route_cleanup_cb,
					 &subtree_arg);
		}
	}

	/* Walk all the interfaces arp entries to do /32 processing */
	array = rcu_dereference(nextl->siblings);
	for (i = 0; i < nextl->nsiblings; i++) {
		const struct next_hop *next = array + i;
		const struct ifnet *ifp = dp_nh_get_ifp(next);

		if (!ifp)
			/* happens for local routes */
			continue;

		lltable_walk(ifp->if_lltable, lle_routing_insert_arp_cb, NULL);
	}

	/* Now do the gateway processing. */
	walk_nhs_for_route_change(routing_arp_add_gw_nh_replace_cb);
}

/*
 * This entry is about to be deleted.
 *
 * Invalidate any old arp links
 */
static void
route_delete_unlink_arp(struct vrf *vrf, struct lpm *lpm, uint32_t ip,
			uint8_t depth)
{
	const struct next_hop_list *nextl;
	uint32_t nh_idx;
	struct subtree_walk_arg subtree_arg = {
		.ip = ip,
		.depth = depth,
		.delete = true,
		.vrf = vrf,
	};
	uint32_t cover_ip;
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
	if (lpm_lookup_exact(lpm, ip, depth, &nh_idx))
		return;

	nextl = rcu_dereference(nh_tbl.entry[nh_idx]);
	if (next_hop_list_is_any_connected(nextl)) {
		subtree_walk_route_cleanup_cb(lpm, ip, depth, nh_idx,
					      &subtree_arg);
		lpm_subtree_walk(lpm, ip, depth,
				 subtree_walk_route_cleanup_cb,
				 &subtree_arg);
	} else if (lpm_find_cover(lpm, ip, depth, &cover_ip,
				  &cover_depth, &cover_idx) == 0) {
		const struct next_hop_list *cover_nextl;

		cover_nextl = rcu_dereference(nh_tbl.entry[cover_idx]);
		if (next_hop_list_is_any_connected(cover_nextl)) {
			lpm_subtree_walk(lpm, ip, depth,
					 subtree_walk_route_cleanup_cb,
					 &subtree_arg);
			subtree_walk_route_cleanup_cb(lpm, ip, depth, nh_idx,
						      &subtree_arg);
		}
	}
}

/*
 * This route has just been deleted. Create new arp links as required.
 */
static void
route_delete_relink_arp(struct lpm *lpm, uint32_t ip, uint8_t depth)
{
	const struct next_hop_list *nextl;
	uint32_t cover_ip;
	uint8_t cover_depth;
	uint32_t cover_nh_idx;
	const struct next_hop *array;
	int i;

	/*
	 * Find the cover of the entry just deleted. Walk all neighbours
	 * on that interface to see if there is work to do.
	 */
	if (lpm_find_cover(lpm, ip, depth, &cover_ip, &cover_depth,
				&cover_nh_idx)) {
		return;
	}

	/* Walk all the interfaces arp entries to do /32 processing */
	nextl = rcu_dereference(nh_tbl.entry[cover_nh_idx]);
	array = rcu_dereference(nextl->siblings);
	for (i = 0; i < nextl->nsiblings; i++) {
		const struct next_hop *next = array + i;
		const struct ifnet *ifp = dp_nh_get_ifp(next);

		if (!ifp)
			/* happens for local routes */
			continue;

		if (nh_is_connected(next))
			lltable_walk(ifp->if_lltable,
				     lle_routing_insert_arp_cb, NULL);
	}

	/* Now do the gateway processing. */
	walk_nhs_for_route_change(routing_arp_add_gw_nh_replace_cb);
}

/*
 * Add new route entry.
 */
int rt_insert(vrfid_t vrf_id, in_addr_t dst, uint8_t depth, uint32_t tableid,
	      uint8_t scope, uint8_t proto, struct next_hop hops[],
	      size_t size, bool replace)
{
	uint32_t old_idx;
	uint32_t idx = 0;
	int err_code;
	char b[INET_ADDRSTRLEN];
	struct lpm *lpm;
	struct vrf *vrf = NULL;

	/* use main table for local route */
	if (tableid == RT_TABLE_LOCAL)
		tableid = RT_TABLE_MAIN;

	/*
	 * This is reserved for our own purposes so don't accept any
	 * routes for it.
	 */
	if (tableid == RT_TABLE_UNSPEC)
		return -ENOENT;

	vrf = vrf_get_rcu(vrf_id);
	if (!vrf)
		return -ENOENT;
	lpm = rt_get_lpm(&vrf->v_rt4_head, tableid);
	if (lpm == NULL) {
		lpm = rt_create_lpm(tableid, vrf);
		if (lpm == NULL) {
			err_code = -ENOENT;
			goto err;
		}
	}

	/*
	 * If a /32 and not a GW then  we want to set the GW (but
	 * not the GW flag) so that we do not share with non /32
	 * routes.  This allows us to then link the arp entries
	 * without using the arp for a /32 entry when we should not.
	 */
	if (depth == 32) {
		unsigned int i;

		for (i = 0; i < size; i++) {
			if (hops[i].flags & RTF_GATEWAY)
				continue;

			assert(hops[i].gateway.address.ip_v4.s_addr == 0);
			hops[i].gateway.address.ip_v4.s_addr = dst;
			hops[i].gateway.type = AF_INET;
		}
	}

	err_code = route_nexthop_new(hops, size, proto, &idx);
	if (err_code < 0) {
		RTE_LOG(ERR, ROUTE,
			"route %s %s/%u failed - cannot create nexthop: %s\n",
			replace ? "replace" : "add",
			inet_ntop(AF_INET, &dst, b, sizeof(b)),
			depth,
			strerror(-err_code));
		goto err;
	}

	pthread_mutex_lock(&route_mutex);

	route_delete_unlink_arp(vrf, lpm, ntohl(dst), depth);
	if (replace) {
		if (lpm_nexthop_lookup(lpm, ntohl(dst), depth, scope,
				       &old_idx) != 0)
			replace = false;
	}
	if (replace) {
		err_code = route_lpm_update(vrf_id, lpm, dst, depth,
					    &old_idx, idx, scope);
	} else
		err_code = route_lpm_add(vrf_id, lpm, dst, depth, idx, scope);

	if (err_code >= 0) {
		if (replace)
			nexthop_put(AF_INET, old_idx);
		route_change_link_arp(vrf, lpm, ntohl(dst), depth, idx, scope);
	}

	pthread_mutex_unlock(&route_mutex);

	if (err_code < 0) {
		DP_LOG_W_VRF(ERR, ROUTE, vrf_id,
			     "route %s %s/%u idx %u failed (%d)\n",
			     replace ? "replace" : "add",
			     inet_ntop(AF_INET, &dst, b, sizeof(b)),
			     depth, idx, err_code);
		nexthop_put(AF_INET, idx);
		goto err;
	}

	DP_DEBUG_W_VRF(ROUTE, INFO, ROUTE, vrf_id,
		       "route %s %s/%u index %u table %u scope %u size %zu\n",
		       replace ? "replace" : "add",
		       inet_ntop(AF_INET, &dst, b, sizeof(b)),
		       depth, idx, tableid, scope, size);
	return 0;

err:
	return err_code;
}

int rt_delete(vrfid_t vrf_id, in_addr_t dst, uint8_t depth,
	      uint32_t id, uint8_t scope)
{
	uint32_t idx;
	int err;
	char b[INET_ADDRSTRLEN];
	struct lpm *lpm;
	struct vrf *vrf = vrf_get_rcu(vrf_id);

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

	lpm = rt_get_lpm(&vrf->v_rt4_head, id);
	if (lpm == NULL || rt_lpm_is_empty(lpm))
		return -ENOENT;

	pthread_mutex_lock(&route_mutex);
	route_delete_unlink_arp(vrf, lpm, ntohl(dst), depth);
	err = route_lpm_delete(vrf_id, lpm, dst, depth, &idx, scope);
	if (err >= 0) {
		/* Drop reference count on nexthop entry. */
		nexthop_put(AF_INET, idx);
		route_delete_relink_arp(lpm, ntohl(dst), depth);
	}

	pthread_mutex_unlock(&route_mutex);

	if (err)
		/*
		 * Expected now we get all deletes from RIB and still act on
		 * link down and purge.
		 */
		return -ENOENT;

	DP_DEBUG_W_VRF(ROUTE, DEBUG, ROUTE, vrf_id,
		       "route delete %s/%u table %d, index %d\n",
		       inet_ntop(AF_INET, &dst, b, sizeof(b)), depth, id, idx);
	return 0;
}

/* cleaner for the next hop */
static void flush_cleanup(struct lpm *lpm __rte_unused,
			  struct lpm_walk_params *params,
			  struct pd_obj_state_and_flags *pd_state,
			  void *arg)
{
	struct vrf *vrf = arg;
	int ret;

	route_sw_stats[PD_OBJ_STATE_FULL]--;

	if (pd_state->created) {
		ret = fal_ip4_del_route(vrf->v_id, htonl(params->ip),
					params->depth,
					lpm_get_id(lpm));
		switch (ret) {
		case 0:
			route_hw_stats[pd_state->state]--;
			break;
		default:
			/* General failure */
			if (ret < 0) {
				char b[INET_ADDRSTRLEN];
				in_addr_t dst = htonl(params->ip);

				DP_LOG_W_VRF(
					ERR, ROUTE, vrf->v_id,
					"route delete %s/%d failed via FAL (%d)\n",
					inet_ntop(AF_INET, &dst, b, sizeof(b)),
					params->depth, ret);
			}
			break;
		}
	} else
		route_hw_stats[pd_state->state]--;

	nexthop_put(AF_INET, params->next_hop);
}

void rt_flush(struct vrf *vrf)
{
	unsigned int id;
	struct route_head rt_head = vrf->v_rt4_head;

	if (vrf->v_id == VRF_INVALID_ID)
		return;

	pthread_mutex_lock(&route_mutex);
	for (id = 0; id < rt_head.rt_rtm_max; id++) {
		struct lpm *lpm = rt_head.rt_table[id];

		if (lpm && !rt_lpm_is_empty(lpm)) {
			lpm_delete_all(lpm, flush_cleanup, vrf);
			/* decrement ref cnt for empty LPM */
			if (!rt_lpm_add_reserved_routes(lpm, vrf)) {
				DP_LOG_W_VRF(ERR, ROUTE, vrf->v_id,
					"Failed to replace reserved routes %s\n",
					vrf->v_name);
			}
		}
	}
	pthread_mutex_unlock(&route_mutex);
}

void rt_flush_all(enum cont_src_en cont_src)
{
	vrfid_t vrf_id;
	struct vrf *vrf;

	if (cont_src == CONT_SRC_MAIN)
		VRF_FOREACH_KERNEL(vrf, vrf_id)
			rt_flush(vrf);
	else
		VRF_FOREACH_UPLINK(vrf, vrf_id)
			rt_flush(vrf);
}

static struct next_hop_list *
route_get_nh_blackhole(void)
{
	return nextl_blackhole;
}

struct nh_common nh4_common = {
	.nh_hash = nexthop_hashfn,
	.nh_compare = nexthop_cmpfn,
	.nh_get_hash_tbl = route_get_nh_hash_table,
	.nh_get_nh_tbl = route_get_nh_table,
	.nh_get_blackhole = route_get_nh_blackhole,
};

void nexthop_tbl_init(void)
{
	struct next_hop nh_drop = {
		.flags = RTF_BLACKHOLE,
	};
	uint32_t idx;

	nexthop_hash = cds_lfht_new(NEXTHOP_HASH_TBL_MIN,
				    NEXTHOP_HASH_TBL_MIN,
				    NEXTHOP_HASH_TBL_SIZE,
				    CDS_LFHT_AUTO_RESIZE,
				    NULL);
	if (!nexthop_hash)
		rte_panic("nexthop_tbl_init: can't create nexthop hash\n");

	nh_common_register(AF_INET, &nh4_common);

	/* reserve a drop nexthop */
	if (nexthop_new(AF_INET, &nh_drop, 1, RTPROT_UNSPEC, FAL_NHG_USE_IP,
			&idx))
		rte_panic("%s: can't create drop nexthop\n", __func__);
	nextl_blackhole =
		rcu_dereference(nh_tbl.entry[idx]);
	if (!nextl_blackhole)
		rte_panic("%s: can't create drop nexthop\n", __func__);
}

int route_init(struct vrf *vrf)
{
	struct lpm *lpm;

	lpm = rt_create_lpm(RT_TABLE_MAIN, vrf);
	if (!lpm) {
		DP_LOG_W_VRF(ERR, ROUTE, vrf->v_id,
			     "unable to create IPv4 route table\n");
		return -1;
	}

	return 0;
}

void route_uninit(struct vrf *vrf, struct route_head *rt_head)
{
	uint32_t id;

	if (rt_head == NULL)
		return;
	for (id = 0; id < rt_head->rt_rtm_max; id++) {
		struct lpm *lpm = rt_head->rt_table[id];

		if (lpm) {
			/* rule_count == 0, means table has been flushed */
			if (lpm_rule_count(lpm) != 0) {
				if (!rt_lpm_is_empty(lpm)) {
					RTE_LOG(ERR, ROUTE,
						"%s:non empty lpm vrf %u table %u\n",
						__func__, vrf->v_id, id);
					return;
				}
				rt_lpm_del_reserved_routes(lpm, vrf);
			}
			lpm_free(lpm);
		}
	}
	free_huge(rt_head->rt_table, (rt_head->rt_rtm_max *
				      sizeof(struct lpm *)));
	rt_head->rt_table = NULL;
}

void rt_print_nexthop(json_writer_t *json, uint32_t next_hop,
		      enum rt_print_nexthop_verbosity v)
{
	const struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[next_hop]);
	const struct next_hop *array;
	unsigned int i, j;

	jsonw_uint_field(json, "nh_index", next_hop);
	if (unlikely(!nextl))
		return;
	array = rcu_dereference(nextl->siblings);
	jsonw_uint_field(json, "nh_refcount", nextl->refcount);
	/*
	 * FAL may access hardware which may be slow or may otherwise
	 * increase the data returned greatly, so only output this
	 * information if requested.
	 */
	if (v == RT_PRINT_NH_DETAIL &&
	    fal_state_is_obj_present(nextl->pd_state)) {
		/*
		 * name disambuigates between next-hop-group state
		 * and possible future route state given we don't have a
		 * separate JSON object for the two.
		 */
		jsonw_name(json, "nhg_platform_state");
		jsonw_start_object(json);
		fal_ip_dump_next_hop_group(nextl->nhg_fal_obj, json);
		jsonw_end_object(json);
	}
	nexthop_map_display(nextl, json);
	jsonw_name(json, "next_hop");
	jsonw_start_array(json);
	for (i = 0; i < nextl->nsiblings; i++) {
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
			jsonw_string_field(json,
					   "state", "non-dataplane interface");
		else if (next->flags & RTF_GATEWAY) {
			char b1[INET_ADDRSTRLEN];

			jsonw_string_field(json, "state", "gateway");
			jsonw_string_field(json, "via",
					   inet_ntop(
						   AF_INET,
						   &next->gateway.address.ip_v4,
						   b1, sizeof(b1)));
		} else
			jsonw_string_field(json, "state", "directly connected");

		if (next->flags & RTF_DEAD)
			jsonw_bool_field(json, "dead", true);
		if (next->flags & RTF_NEIGH_PRESENT)
			jsonw_bool_field(json, "neigh_present", true);
		if (next->flags & RTF_NEIGH_CREATED)
			jsonw_bool_field(json, "neigh_created", true);
		if (next->flags & RTF_BACKUP)
			jsonw_bool_field(json, "backup", true);

		ifp = dp_nh_get_ifp(next);
		if (ifp)
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
		    fal_state_is_obj_present(nextl->pd_state)) {
			jsonw_name(json, "platform_state");
			jsonw_start_object(json);
			fal_ip_dump_next_hop(nextl->nh_fal_obj[i], json);
			jsonw_end_object(json);
		}

		jsonw_end_object(json);
	}
	jsonw_end_array(json);
}

/*
 * Walk FIB table.
 */
static void rt_local_display(
	struct lpm *lpm __rte_unused,
	struct lpm_walk_params *params,
	struct pd_obj_state_and_flags *pd_state __rte_unused,
	void *arg)
{
	FILE *f = arg;
	in_addr_t dst = htonl(params->ip);
	char b[INET_ADDRSTRLEN];
	const struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[params->next_hop]);
	const struct next_hop *nh;

	if (unlikely(!nextl))
		return;
	nh = rcu_dereference(nextl->siblings);

	if (nh->flags & RTF_LOCAL && !rt_is_reserved(params->ip,
						     params->depth,
						     params->scope))
		fprintf(f, "\t%s\n", inet_ntop(AF_INET, &dst, b, sizeof(b)));
}

static void __rt_display(json_writer_t *json, in_addr_t *dst, uint8_t depth,
			 int16_t scope, const struct next_hop_list *nextl,
			 uint32_t next_hop)
{
	char b1[INET_ADDRSTRLEN];
	char b2[INET6_ADDRSTRLEN]; /* extra room for mask, not for ipv6 here */
	const char *use_str = NULL;

	jsonw_start_object(json);

	sprintf(b2, "%s/%u",
		inet_ntop(AF_INET, dst, b1, sizeof(b1)), depth);
	jsonw_string_field(json, "prefix", b2);
	jsonw_int_field(json, "scope", scope);
	jsonw_uint_field(json, "proto", nextl->proto);
	switch (nextl->use) {
	case FAL_NHG_USE_IP:
		use_str = "ip";
		break;
	case FAL_NHG_USE_MPLS_LABEL_SWITCH:
		use_str = "mpls-lswitch";
		break;
	}
	if (use_str)
		jsonw_string_field(json, "use", use_str);
	rt_print_nexthop(json, next_hop, RT_PRINT_NH_BRIEF);

	jsonw_end_object(json);
}

static void rt_display(struct lpm *lpm __rte_unused,
		       struct lpm_walk_params *params,
		       struct pd_obj_state_and_flags *pd_state __rte_unused,
		       void *arg)
{
	json_writer_t *json = arg;
	in_addr_t dst = htonl(params->ip);

	const struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[params->next_hop]);
	const struct next_hop *nh;

	if (unlikely(!nextl))
		return;
	nh = rcu_dereference(nextl->siblings);
	/* Filter local route being displayed */
	if (nh->flags & RTF_LOCAL)
		return;

	/* Don't show if any paths are NEIGH_CREATED. */
	if (next_hop_list_nc_count(nextl))
		return;

	if (rt_is_reserved(params->ip, params->depth, params->scope))
		return;

	__rt_display(json, &dst, params->depth, params->scope, nextl,
		     params->next_hop);
}

static void rt_display_all(struct lpm *lpm __rte_unused,
			   struct lpm_walk_params *params,
			   struct pd_obj_state_and_flags *pd_state __rte_unused,
			   void *arg)
{
	json_writer_t *json = arg;
	in_addr_t dst = htonl(params->ip);
	const struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[params->next_hop]);

	if (unlikely(!nextl))
		return;
	__rt_display(json, &dst, params->depth, params->scope, nextl,
		     params->next_hop);
}

/* Route rule list (RB-tree) is not RCU safe */
static uint32_t
lpm_walk_safe(struct lpm *lpm, lpm_walk_func_t func,
		  struct lpm_walk_arg *r_arg)
{
	uint32_t ret;

	pthread_mutex_lock(&route_mutex);
	ret = lpm_walk(lpm, func, r_arg);
	pthread_mutex_unlock(&route_mutex);

	return ret;
}

static void
lpm_walk_all_safe(struct lpm *lpm, lpm_walk_func_t func, void *arg)
{
	struct lpm_walk_arg r_arg = {
		.is_segment = false,
		.walk_arg = arg,
	};

	lpm_walk_safe(lpm, func, &r_arg);
}

enum if_state_rx {
	IF_RX_LINK_DEL,
};

static void rt_if_dead(struct lpm *lpm, struct vrf *vrf,
		       struct lpm_walk_params *params,
		       void *arg, enum if_state_rx state_rx)
{
	struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[params->next_hop]);
	const struct ifnet *ifp = arg;
	unsigned int i, matches = 0;

	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *nh = nextl->siblings + i;

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

	if (matches == nextl->nsiblings || state_rx == IF_RX_LINK_DEL) {
		/*
		 * Delete entire route if;
		 * Either all nh's for this route are dead
		 * Or interface on one nh has been deleted. This mimics Kernel
		 * behaviour but is bad as we have other ECMP nh's available
		 */
		route_lpm_delete(vrf->v_id, lpm, htonl(params->ip),
				 params->depth, NULL,
				 params->scope);
		nexthop_put(AF_INET, params->next_hop);
	}
}

/* Interface is being deleted */
static void rt_if_deleted(struct lpm *lpm, struct vrf *vrf,
			  struct lpm_walk_params *params,
			  struct pd_obj_state_and_flags *pd_state __rte_unused,
			  void *arg)
{
	rt_if_dead(lpm, vrf, params, arg, IF_RX_LINK_DEL);
}

static void rt_if_clear_slowpath_flag(
	struct lpm *lpm __rte_unused,
	struct vrf *vrf __rte_unused,
	struct lpm_walk_params *params,
	struct pd_obj_state_and_flags *pd_state __rte_unused,
	void *arg)
{
	struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[params->next_hop]);
	const struct ifnet *ifp = arg;
	unsigned int i;

	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *nh = nextl->siblings + i;

		if (dp_nh_get_ifp(nh) == ifp)
			nh->flags &= ~RTF_SLOWPATH;
	}
}

static void rt_if_set_slowpath_flag(
	struct lpm *lpm __rte_unused,
	struct vrf *vrf __rte_unused,
	struct lpm_walk_params *params,
	struct pd_obj_state_and_flags *pd_state __rte_unused,
	void *arg)
{
	struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[params->next_hop]);
	const struct ifnet *ifp = arg;
	unsigned int i;

	for (i = 0; i < nextl->nsiblings; i++) {
		struct next_hop *nh = nextl->siblings + i;

		if (dp_nh_get_ifp(nh) == ifp)
			nh->flags |= RTF_SLOWPATH;
	}
}

struct rt_vrf_lpm_walk_ctx {
	struct vrf *vrf;
	void (*func)(struct lpm *lpm, struct vrf *vrf,
		     struct lpm_walk_params *params,
		     struct pd_obj_state_and_flags *pd_state,
		     void *arg);
	void *arg;
};

static void rt_vrf_lpm_walk_cb(struct lpm *lpm,
			       struct lpm_walk_params *params,
			       struct pd_obj_state_and_flags *pd_state,
			       void *arg)
{
	const struct rt_vrf_lpm_walk_ctx *ctx = arg;

	ctx->func(lpm, ctx->vrf, params, pd_state, ctx->arg);
}


static void rt_lpm_walk_util(
	void (*func)(struct lpm *lpm, struct vrf *vrf,
		     struct lpm_walk_params *params,
		     struct pd_obj_state_and_flags *pd_state,
		     void *arg),
	void *arg)
{
	unsigned int id;
	vrfid_t vrf_id;
	struct vrf *vrf;

	VRF_FOREACH(vrf, vrf_id) {
		for (id = 1; id < vrf->v_rt4_head.rt_rtm_max; id++) {
			struct lpm *lpm = vrf->v_rt4_head.rt_table[id];
			struct rt_vrf_lpm_walk_ctx ctx = {
				.vrf = vrf,
				.func = func,
				.arg = arg,
			};

			if (lpm && !rt_lpm_is_empty(lpm))
				lpm_walk_all_safe(lpm, rt_vrf_lpm_walk_cb,
						      &ctx);
		}
	}
}

/* Interface is being deleted clear all routes */
static void rt_if_purge(struct ifnet *ifp, uint32_t idx __unused)
{
	/*
	 * Walk through all the VRFs to delete the routes
	 * pointing to this interface.
	 */
	rt_lpm_walk_util(rt_if_deleted, ifp);
}

/* Explicitly stop routes pointing to this interface punting to slowpath */
void rt_if_handle_in_dataplane(struct ifnet *ifp)
{
	rt_lpm_walk_util(rt_if_clear_slowpath_flag, ifp);
}

/* Explicitly make routes pointing to this interface punt to slowpath */
void rt_if_punt_to_slowpath(struct ifnet *ifp)
{
	rt_lpm_walk_util(rt_if_set_slowpath_flag, ifp);
}

int rt_walk(struct route_head *rt_head, json_writer_t *json, uint32_t id,
	    uint32_t cnt, enum rt_walk_type type)
{
	lpm_walk_func_t cb = rt_display;
	struct lpm *lpm = rt_get_lpm(rt_head, id);
	struct lpm_walk_arg arg = {
		.is_segment = (cnt != UINT32_MAX),
		.walk_arg = json,
		.addr = 0,
		.depth = 0,
		.cnt = cnt,
	};

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE, "Unknown route table\n");
		return 0;
	}

	if (type == RT_WALK_ALL)
		cb = rt_display_all;

	if (lpm_walk_safe(lpm, cb, &arg)) {
		jsonw_start_object(json);
		jsonw_string_field(json, "prefix", "more");
		jsonw_end_object(json);
	}

	return 0;
}


int rt_walk_next(struct route_head *rt_head, json_writer_t *json,
		 uint32_t id, const struct in_addr *addr,
		 uint8_t plen, uint32_t cnt, enum rt_walk_type type)
{
	lpm_walk_func_t cb = rt_display;
	struct lpm *lpm = rt_get_lpm(rt_head, id);
	struct lpm_walk_arg arg = {
		.is_segment = true,
		.get_next = true,
		.walk_arg = json,
		.depth = plen,
		.cnt = cnt,
		.addr = ntohl(addr->s_addr),
	};

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE, "Unknown route table\n");
		return 0;
	}

	if (type == RT_WALK_ALL)
		cb = rt_display_all;

	if (lpm_walk_safe(lpm, cb, &arg)) {
		jsonw_start_object(json);
		jsonw_string_field(json, "prefix", "more");
		jsonw_end_object(json);
	}

	return 0;
}

int rt_local_show(struct route_head *rt_head, uint32_t id, FILE *f)
{
	struct lpm *lpm = rt_get_lpm(rt_head, id);

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE, "Unknown route table\n");
		return 0;
	}

	lpm_walk_all_safe(lpm, rt_local_display, f);

	return 0;
}

int rt_show(struct route_head *rt_head, json_writer_t *json, uint32_t tblid,
	    const struct in_addr *addr)
{
	struct lpm *lpm = rt_get_lpm(rt_head, tblid);
	uint32_t next_hop;

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE, "Unknown route table\n");
		return 0;
	}

	jsonw_start_object(json);
	jsonw_string_field(json, "address", inet_ntoa(*addr));

	if (lpm_lookup(lpm, ntohl(addr->s_addr), &next_hop) != 0)
		jsonw_string_field(json, "state", "nomatch");
	else
		rt_print_nexthop(json, next_hop, RT_PRINT_NH_DETAIL);
	jsonw_end_object(json);
	return 0;
}

int rt_show_exact(struct route_head *rt_head, json_writer_t *json,
		  uint32_t tblid, const struct in_addr *addr, uint8_t plen)
{
	char b1[INET_ADDRSTRLEN];
	char b2[INET_ADDRSTRLEN + sizeof("/255")];
	struct lpm *lpm = rt_get_lpm(rt_head, tblid);
	uint32_t next_hop;

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE, "Unknown route table\n");
		return 0;
	}

	jsonw_start_object(json);

	sprintf(b2, "%s/%u",
		inet_ntop(AF_INET, addr, b1, sizeof(b1)), plen);
	jsonw_string_field(json, "prefix", b2);

	if (lpm_lookup_exact(lpm, ntohl(addr->s_addr), plen, &next_hop) != 0)
		jsonw_string_field(json, "state", "nomatch");
	else
		rt_print_nexthop(json, next_hop, RT_PRINT_NH_DETAIL);
	jsonw_end_object(json);
	return 0;
}

static void rt_summarize(struct lpm *lpm __rte_unused,
			 struct lpm_walk_params *params,
			 struct pd_obj_state_and_flags *pd_state __rte_unused,
			 void *arg)
{
	uint32_t *rt_used = arg;
	const struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[params->next_hop]);
	const struct next_hop *nh;

	if (unlikely(!nextl))
		return;
	nh = rcu_dereference(nextl->siblings);
	/* Filter local route being displayed */
	if (nh->flags & RTF_LOCAL)
		return;

	/* Don't show if any paths are NEIGH_CREATED */
	if (next_hop_list_nc_count(nextl))
		return;

	if (rt_is_reserved(params->ip, params->depth, params->scope))
		return;

	++rt_used[params->depth];
}

static double nexthop_hash_load_factor(void)
{
	unsigned long count;
	long dummy;
	double factor;

	cds_lfht_count_nodes(nexthop_hash, &dummy, &count, &dummy);
	factor = (double) count / (double) NEXTHOP_HASH_TBL_SIZE;
	return factor;
}

int rt_stats(struct route_head *rt_head, json_writer_t *json, uint32_t id)
{
	uint8_t depth;
	unsigned int total = 0;
	uint32_t rt_used[LPM_MAX_DEPTH] = { 0 };
	struct lpm *lpm = rt_get_lpm(rt_head, id);

	if (lpm == NULL) {
		RTE_LOG(ERR, ROUTE, "Unknown route table\n");
		return 0;
	}

	lpm_walk_all_safe(lpm, rt_summarize, rt_used);
	jsonw_name(json, "prefix");
	jsonw_start_object(json);
	for (depth = 0; depth < LPM_MAX_DEPTH; depth++) {
		total += rt_used[depth];
		if (rt_used[depth]) {
			char buf[20];

			snprintf(buf, sizeof(buf), "%u", depth);
			jsonw_uint_field(json, buf, rt_used[depth]);
		}
	}
	jsonw_end_object(json);

	jsonw_uint_field(json, "total", total);
	jsonw_uint_field(json, "used", lpm_tbl8_count(lpm));
	jsonw_uint_field(json, "free", lpm_tbl8_free_count(lpm));

	jsonw_name(json, "nexthop");
	jsonw_start_object(json);
	jsonw_uint_field(json, "used", nh_tbl.in_use);
	jsonw_uint_field(json, "free", NEXTHOP_HASH_TBL_SIZE - nh_tbl.in_use);
	jsonw_uint_field(json, "hash",
			 (unsigned int) (100. * nexthop_hash_load_factor()));
	jsonw_uint_field(json, "neigh_present", nh_tbl.neigh_present);
	jsonw_uint_field(json, "neigh_created", nh_tbl.neigh_created);
	jsonw_end_object(json);

	return 0;
}

/*
 * Get egress interface for destination address.
 *
 * Must only be used on main thread.
 * Note for multipath routes, the first interface is always returned.
 */
struct ifnet *nhif_dst_lookup(const struct vrf *vrf,
			      in_addr_t dst,
			      bool *connected)
{
	struct ifnet *ifp;
	const struct next_hop_list *nextl;
	const struct next_hop *next;
	uint32_t nhindex;

	if (lpm_lookup(vrf->v_rt4_head.rt_table[RT_TABLE_MAIN],
			   ntohl(dst), &nhindex) != 0)
		return NULL;

	nextl = nh_tbl.entry[nhindex];
	if (nextl == NULL)
		return NULL;

	next = nextl->siblings;
	if (next == NULL)
		return NULL;

	ifp = dp_nh_get_ifp(next);
	if (ifp && connected)
		*connected = nh_is_connected(next);

	return ifp;
}

/*
 * Lookup NH information based on NH index, and use the hash in case
 * the NH is a multi-path nexthop
 *
 * INPUT:
 *    nhindex - NH index
 *    hash    - Hash value used to obtain the path information in case
 *              of multi-path nexthop
 * OUTPUT:
 *    nh      - IP address of the next hop
 *    ifindex - If index of the outgoing interface
 */
int dp_nh_lookup_by_index(uint32_t nhindex, uint32_t hash, in_addr_t *nh,
		       uint32_t *ifindex)
{
	const struct next_hop_list *nextl;
	struct next_hop *next;
	struct ifnet *ifp;
	uint32_t size;

	nextl = rcu_dereference(nh_tbl.entry[nhindex]);
	if (nextl == NULL)
		return -1;

	next = nextl->siblings;
	if (!next)
		return -1;

	size = nextl->nsiblings;
	if (size > 1)
		next = nexthop_mp_select(nextl, next, size, hash);

	if (next->flags & RTF_GATEWAY)
		*nh = next->gateway.address.ip_v4.s_addr;
	else
		*nh = INADDR_ANY;

	ifp = dp_nh_get_ifp(next);
	if (!ifp)
		return -1;

	*ifindex = ifp->if_index;
	return 0;
}

static void
route_create_arp(struct vrf *vrf, struct lpm *lpm,
		 struct in_addr *ip, struct llentry *lle)
{
	struct next_hop_list *nextl;
	uint32_t nh_idx;
	struct next_hop *nh;
	struct next_hop *cover_nh;
	struct ifnet *ifp = rcu_dereference(lle->ifp);
	int sibling;
	int size;

	if (lpm_lookup(lpm, ntohl(ip->s_addr), &nh_idx) == 0) {
		nextl = rcu_dereference(nh_tbl.entry[nh_idx]);

		/*
		 * Note that this does not support a connected with multiple
		 * paths that use the same ifp.
		 */
		cover_nh = next_hop_list_find_path_using_ifp(nextl, ifp,
							     &sibling);
		if (cover_nh && nh_is_connected(cover_nh)) {
			/*
			 * Have a connected cover so create a new entry for
			 * this. Will only be 1 NEIGH_CREATED path, but
			 * need to inherit other paths from the cover.
			 */
			nh = next_hop_list_copy_next_hops(nextl, &size);
			if (!nh)
				return;

			/*
			 * Set the correct NH to be NEIGH_CREATED. As this
			 * is copied from the cover nextl, the sibling gives
			 * the NH for the correct interface
			 */
			nh_set_neigh_created(AF_INET, &nh[sibling], lle);
			/*
			 * This is a /32 we are creating, therefore not a GW.
			 * Set the GW (but not the flag) so that we do not
			 * share with non /32 routes such as the connected
			 * cover.
			 */
			assert(nh[sibling].gateway.address.ip_v4.s_addr == 0);
			nh[sibling].gateway.address.ip_v4.s_addr = ip->s_addr;
			nh[sibling].gateway.type = AF_INET;
			if (route_nexthop_new(nh, size, RTPROT_UNSPEC,
					      &nh_idx) < 0) {
				free(nh);
				return;
			}
			route_lpm_add(vrf->v_id, lpm, ip->s_addr,
				      32, nh_idx, RT_SCOPE_LINK);
			free(nh);
		}
	}
}

/*
 * On an arp del, should we clear NEIGH_PRESENT from this NH.
 */
static enum nh_change routing_arp_del_gw_nh_replace_cb(struct next_hop *next,
						       int sibling __unused,
						       void *arg)
{
	struct llentry *lle = arg;
	struct in_addr *ip = ll_ipv4_addr(lle);
	struct ifnet *ifp = rcu_dereference(lle->ifp);

	if (!nh_is_gw(next) ||
	    (next->gateway.address.ip_v4.s_addr != ip->s_addr))
		return NH_NO_CHANGE;
	if (dp_nh_get_ifp(next) != ifp)
		return NH_NO_CHANGE;
	if (nh_is_local(next) || !nh_is_neigh_present(next))
		return NH_NO_CHANGE;

	return NH_CLEAR_NEIGH_PRESENT;
}


static void
walk_nhs_for_arp_change(struct llentry *lle,
			enum nh_change (*upd_neigh_present_cb)(
				struct next_hop *next,
				int sibling,
				void *arg))
{
	struct next_hop_list *nhl;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	ASSERT_MAIN();

	cds_lfht_for_each(nexthop_hash, &iter, node) {
		nhl = caa_container_of(node, struct next_hop_list, nh_node);
		route_nh_replace(AF_INET, nhl, nhl->index, lle, NULL,
				 upd_neigh_present_cb, lle);
	}
}

struct arp_add_nh_replace_arg {
	struct ifnet *ifp;
	bool count;
};

/*
 * On an arp add, should we set this NH as NEIGH_PRESENT, OR NEIGH_CREATED
 *
 * Set to NEIGH_PRESENT in the case where the route existed already, but not
 * because of an ARP entry. If there are any NHs that are NEIGH_CREATED then
 * it only exists due to the ARP entry, so this hop can become NEIGH_CREATED
 * too.
 */
static enum nh_change routing_arp_add_nh_replace_cb(struct next_hop *next,
						    int sibling __unused,
						    void *arg)
{
	struct arp_add_nh_replace_arg *args = arg;

	if (!nh_is_connected(next))
		return NH_NO_CHANGE;
	if (nh_is_neigh_present(next) || nh_is_neigh_created(next))
		return NH_NO_CHANGE;
	if (args->ifp != dp_nh_get_ifp(next))
		return NH_NO_CHANGE;

	if (args->count)
		return NH_SET_NEIGH_CREATED;

	return NH_SET_NEIGH_PRESENT;
}

/*
 * On an arp del, should we clear NEIGH_PRESENT from this NH.
 */
static enum nh_change routing_arp_del_nh_replace_cb(struct next_hop *next,
						    int sibling __unused,
						    void *arg)
{
	struct ifnet *ifp = arg;

	if (!nh_is_connected(next) || !nh_is_neigh_present(next))
		return NH_NO_CHANGE;
	if (ifp != dp_nh_get_ifp(next))
		return NH_NO_CHANGE;

	return NH_CLEAR_NEIGH_PRESENT;
}

struct arp_remove_purge_arg {
	int count; /* Count of number of NEIGH_CREATED in parent nextl */
	int sibling; /* Sibling that had the arp entry removed */
};

/*
 * Do we need to purge this NH. If the route was NEIGH_CREATED (any of the
 * paths were NEIGH_CREATED) and this path has had the ARP entry removed then
 * it either needs to be removed, or have NEIGH_CREATED removed.
 * If it is the last NEIGH_CREATED path then all paths to be removed.
 * If there will still be a NEIGH_CREATED path then this path should have
 * NEIGH_CREATED removed and revert back to inheriting from the cover.
 */
static enum nh_change arp_removal_nh_purge_cb(struct next_hop *next __unused,
					      int sibling,
					      void *arg)
{
	struct arp_remove_purge_arg *args = arg;

	if (sibling == args->sibling) {
		if (args->count > 1)
			return NH_CLEAR_NEIGH_CREATED;
		return NH_DELETE;
	}

	if (args->count > 1)
		return NH_NO_CHANGE;

	return NH_DELETE;
}

/*
 * When we are given a new arp entry we need to insert entries into the
 * routing table(s) for it.
 *
 * For the VRF the interface is in:
 *  - is there is already a /32 for this addr, mark it as NEIGH_PRESENT
 *    if connected.
 *  - is not then create it and mark it as NEIGH_PRESENT & NEIGH_CREATED
 *    if cover is connected.
 *
 *  - Walk the NHs that use this interface and have the GW as this IP addr.
 *    - mark as NEIGH_PRESESNT.
 *
 * All entries marked as NEIGH_PRESENT will then have the arp ptr stored,
 * so that forwarders can use that are entry without a lookup.
 */
void
routing_insert_arp_safe(struct llentry *lle, bool arp_change)
{
	struct in_addr *ip = ll_ipv4_addr(lle);
	struct vrf *vrf = get_vrf(if_vrfid(lle->ifp));
	struct lpm *lpm;
	struct next_hop_list *nextl;
	uint32_t nh_idx;
	struct ifnet *ifp = rcu_dereference(lle->ifp);
	struct next_hop *nh;
	int sibling;

	lpm = rcu_dereference(vrf->v_rt4_head.rt_table[RT_TABLE_MAIN]);
	pthread_mutex_lock(&route_mutex);
	if (lpm_lookup_exact(lpm, ntohl(ip->s_addr), 32, &nh_idx) == 0) {
		/* We already have a /32 so add the shortcut if connected */
		nextl = rcu_dereference(nh_tbl.entry[nh_idx]);

		/*
		 * Do we already have a nh for this interface?
		 * If so then we might need to modify it. As this is
		 * called when a route changes, we migh also need to
		 * modify the set of NHs, to reflect the ones the
		 * cover has.
		 */
		nh = next_hop_list_find_path_using_ifp(nextl, ifp, &sibling);
		if (nh) {
			struct arp_add_nh_replace_arg arg = {
				.ifp = ifp,
				.count = next_hop_list_nc_count(nextl),
			};

			route_nh_replace(AF_INET, nextl, nh_idx, lle, NULL,
					 routing_arp_add_nh_replace_cb, &arg);
		}
	} else {
		/* Have to create a /32. but only if cover is connected. */
		route_create_arp(vrf, lpm, ip, lle);
	}
	pthread_mutex_unlock(&route_mutex);

	/*
	 * If this is not an arp change don't do this here as it will lead
	 * to something like an n squared issue as we call this func for all
	 * lle entries. The caller will do an equivalent after.
	 */
	if (arp_change)
		/*
		 * Now walk the NHs using this interface that have the GW
		 * set as this IP address. For each of them add the link
		 * to the arp entry and mark as NEIGH_PRESENT.
		 */
		walk_nhs_for_arp_change(lle, routing_arp_add_gw_nh_replace_cb);
}

/*
 * The arp entry is going away. If we have any references to it then clean them
 * up.
 */
void
routing_remove_arp_safe(struct llentry *lle)
{
	struct in_addr *ip = ll_ipv4_addr(lle);
	struct vrf *vrf = get_vrf(if_vrfid(lle->ifp));
	struct lpm *lpm;
	struct next_hop_list *nextl;
	uint32_t nh_idx;
	struct ifnet *ifp = rcu_dereference(lle->ifp);
	int sibling;
	struct next_hop *nh;

	lpm = rcu_dereference(vrf->v_rt4_head.rt_table[RT_TABLE_MAIN]);
	pthread_mutex_lock(&route_mutex);
	if (lpm_lookup_exact(lpm, ntohl(ip->s_addr), 32, &nh_idx) == 0) {
		/* We have a /32 so unlink the arp (if there) */
		nextl = rcu_dereference(nh_tbl.entry[nh_idx]);

		/* Do we already have a nh for this interface? */
		nh = next_hop_list_find_path_using_ifp(nextl, ifp, &sibling);
		if (nh && nh_is_neigh_created(nh)) {
			/* Are we removing a path or the entire NH */
			if (nextl->nsiblings == 1) {
				route_lpm_delete(vrf->v_id,
						     lpm, ip->s_addr, 32,
						     &nh_idx, RT_SCOPE_LINK);
				nexthop_put(AF_INET, nh_idx);
			} else {
				struct arp_remove_purge_arg args = {
					.count = next_hop_list_nc_count(nextl),
					.sibling = sibling,
				};
				int del;
				uint32_t new_nh_idx;

				del = route_nh_replace(AF_INET,
						       nextl, nh_idx, lle,
						       &new_nh_idx,
						       arp_removal_nh_purge_cb,
						       &args);
				/* Can not delete a subset of paths here */
				if (del == nextl->nsiblings) {
					route_lpm_delete(vrf->v_id,
							     lpm, ip->s_addr,
							     32, &nh_idx,
							     RT_SCOPE_LINK);
					nexthop_put(AF_INET, nh_idx);
				}
			}
		} else {
			route_nh_replace(AF_INET, nextl, nh_idx, NULL, NULL,
					routing_arp_del_nh_replace_cb, ifp);
		}
	}
	pthread_mutex_unlock(&route_mutex);

	/*
	 * Now walk the NHs using this interface that have the GW
	 * set as this IP address. For each of them remove the link
	 * to the arp entry as it is going away
	 */
	walk_nhs_for_arp_change(lle, routing_arp_del_gw_nh_replace_cb);
}

uint32_t *route_sw_stats_get(void)
{
	return route_sw_stats;
}

uint32_t *route_hw_stats_get(void)
{
	return route_hw_stats;
}


struct rt_show_subset {
	json_writer_t *json;
	enum pd_obj_state subset;
	vrfid_t vrf;
};

static void rt_show_subset(struct lpm *lpm, struct vrf *vrf,
			   struct lpm_walk_params *params,
			   struct pd_obj_state_and_flags *pd_state,
			   void *arg)
{
	struct rt_show_subset *subset = arg;

	if (subset->vrf != vrf->v_id) {
		subset->vrf = vrf->v_id;
		jsonw_start_object(subset->json);
		jsonw_uint_field(subset->json, "vrf_id",
				 dp_vrf_get_external_id(vrf->v_id));
		jsonw_uint_field(subset->json, "table",
				 lpm_get_id(lpm));
		jsonw_end_object(subset->json);
	}

	if (subset->subset == pd_state->state)
		rt_display_all(lpm, params, pd_state, subset->json);
}

/*
 * Return the json for the given subset of stats.
 */
int route_get_pd_subset_data(json_writer_t *json, enum pd_obj_state subset)
{
	struct rt_show_subset arg = {
		.json = json,
		.subset = subset,
		.vrf = VRF_INVALID_ID,
	};
	rt_lpm_walk_util(rt_show_subset, &arg);

	return 0;
}

static void route_fal_upd_for_changed_nhl(
	struct lpm *lpm, struct vrf *vrf,
	struct lpm_walk_params *params,
	struct pd_obj_state_and_flags *pd_state,
	void *arg)
{
	const uint32_t *filter_nhl_index = arg;
	int rc;

	if (params->next_hop != *filter_nhl_index)
		return;

	if (pd_state->state != PD_OBJ_STATE_FULL)
		return;

	struct next_hop_list *nextl =
		rcu_dereference(nh_tbl.entry[params->next_hop]);

	rc = fal_ip4_upd_route(vrf->v_id, htonl(params->ip), params->depth,
			       lpm_get_id(lpm), nextl->siblings,
			       nextl->nsiblings, nextl->nhg_fal_obj);

	pd_state->state = fal_state_to_pd_state(rc);

	/* Kick trackers so that clients can learn about FAL changes */
	params->call_tracker_cbs = true;
}

static void
route_handle_fal_l3_enable_change(struct ifnet *ifp)
{
	struct cds_lfht_node *node;
	fal_object_t *old_nh_objs;
	struct next_hop_list *nhl;
	uint32_t nhls_updated = 0;
	struct cds_lfht_iter iter;
	fal_object_t old_nhg_obj;

	cds_lfht_for_each(nexthop_hash, &iter, node) {
		nhl = caa_container_of(node, struct next_hop_list, nh_node);

		if (!next_hop_list_fal_l3_enable_changed(AF_INET,
							 nhl, ifp,
							 &old_nhg_obj,
							 &old_nh_objs))
			continue;

		/*
		 * This is going to be very expensive if there are a
		 * lot of routes present in the system. The only
		 * consolation is that this is only anticipated to be
		 * done on major changes such as interface creation
		 * and removal.
		 */
		rt_lpm_walk_util(route_fal_upd_for_changed_nhl,
				 &nhl->index);
		mpls_update_all_routes_for_nh_change(AF_INET, nhl->index);

		next_hop_list_fal_l3_enable_changed_finish(
			AF_INET, nhl, old_nhg_obj, old_nh_objs);

		nhls_updated++;
	}

	if (nhls_updated)
		RTE_LOG(DEBUG, ROUTE,
			"Updated %u IPv4 next hop lists due to FAL L3 state change of interface %s\n",
			nhls_updated, ifp->if_name);
}

static void
rt_if_feat_mode_change(struct ifnet *ifp,
		       enum if_feat_mode_event event)
{
	switch (event) {
	case IF_FEAT_MODE_EVENT_L3_FAL_ENABLED:
	case IF_FEAT_MODE_EVENT_L3_FAL_DISABLED:
		route_handle_fal_l3_enable_change(ifp);
		break;
	default:
		break;
	}
}

static const struct dp_event_ops route_events = {
	.if_index_unset = rt_if_purge,
	.if_feat_mode_change = rt_if_feat_mode_change,
	.vrf_delete = rt_flush,
};

DP_STARTUP_EVENT_REGISTER(route_events);

