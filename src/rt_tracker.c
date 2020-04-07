/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_jhash.h>

#include "ip_forward.h"
#include "lpm/lpm.h"
#include "lpm/lpm6.h"
#include "rt_tracker.h"

/* Size of the tracker_info table. Must be a power of two. */
#define RT_TRACKER_HASH_MIN  8
#define RT_TRACKER_HASH_MAX  4096

static unsigned long rt_tracker_table_seed;

static int rt_tracker_init(struct vrf *vrf)
{
	vrf->v_rt_tracker_tbl = cds_lfht_new(RT_TRACKER_HASH_MIN,
					   RT_TRACKER_HASH_MIN,
					   RT_TRACKER_HASH_MAX,
					   CDS_LFHT_AUTO_RESIZE,
					   NULL);
	if (!vrf->v_rt_tracker_tbl)
		return -ENOMEM;

	rt_tracker_table_seed = random();

	return 0;
}

void rt_tracker_uninit(struct vrf *vrf)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct rt_tracker_info *ti_info;
	char b[INET_ADDRSTRLEN];

	if (vrf->v_rt_tracker_tbl) {
		/* hash table must be empty for delete to succeed */
		cds_lfht_for_each(vrf->v_rt_tracker_tbl, &iter, node) {
			ti_info = caa_container_of(node, struct rt_tracker_info,
						   rti_node);
			inet_ntop(AF_INET, &ti_info->dst_addr, b, sizeof(b));
			DP_LOG_W_VRF(ERR, LPM, vrf->v_id,
				     "Tracker for %s not deleted\n", b);
			cds_lfht_del(vrf->v_rt_tracker_tbl, &ti_info->rti_node);
		}
		cds_lfht_destroy(vrf->v_rt_tracker_tbl, NULL);
	}
}

static void
rt_tracker_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct rt_tracker_info, rti_rcu));
}

static void
rt_tracker_destroy(struct rt_tracker_info *ti_info)
{
	call_rcu(&ti_info->rti_rcu, rt_tracker_free);
}

static struct rt_tracker_client_t *
rt_tracker_client_find(struct rt_tracker_info *ti_info, void *cb_ctx)
{
	struct rt_tracker_client_t *client;
	struct cds_list_head *entry;

	if (!ti_info)
		return NULL;

	cds_list_for_each(entry, &ti_info->rti_client_list) {
		client = cds_list_entry(entry, struct rt_tracker_client_t,
					rtc_client_links);
		if (client->rtc_cb_ctx == cb_ctx)
			return client;
	}
	return NULL;
}

static void
rt_tracker_client_delete(struct rt_tracker_info *ti_info, void *cb_ctx)
{
	struct rt_tracker_client_t *client;
	struct cds_list_head *entry;

	if (!ti_info)
		return;

	cds_list_for_each(entry, &ti_info->rti_client_list) {
		client = cds_list_entry(entry, struct rt_tracker_client_t,
					rtc_client_links);
		if (client->rtc_cb_ctx == cb_ctx) {
			cds_list_del_rcu(&client->rtc_client_links);
			free(client);
			return;
		}
	}
}

static int
rt_tracker_client_add(struct rt_tracker_info *ti_info, void *cb_ctx,
		      tracker_change_notif cb)
{
	struct rt_tracker_client_t *client;

	/* Find existing client */
	client = rt_tracker_client_find(ti_info, cb_ctx);
	if (client) {
		RTE_LOG(ERR, LPM, "Failed to add tracker client: EEXISTS\n");
		return -1;
	}
	/* If not found create a new one */
	client = zmalloc_aligned(sizeof(*client));
	if (!client)
		return -1;

	client->rtc_cb_ctx = cb_ctx;
	client->rtc_cb_func = cb;
	cds_list_add_rcu(&client->rtc_client_links, &ti_info->rti_client_list);
	return 0;
}

uint32_t
rt_tracker_client_count(struct rt_tracker_info *tracker)
{
	struct cds_list_head *entry;
	uint32_t count = 0;

	if (!tracker)
		return 0;

	cds_list_for_each(entry, &tracker->rti_client_list) {
		count++;
	}
	return count;
}

static void
rt_tracker_update(void *ctx)
{
	struct rt_tracker_info *ti_info = (struct rt_tracker_info *)ctx;
	struct rt_tracker_client_t *client;
	struct cds_list_head *entry;

	if (!ti_info)
		return;

	cds_list_for_each(entry, &ti_info->rti_client_list) {
		client = cds_list_entry(entry, struct rt_tracker_client_t,
					rtc_client_links);
		client->rtc_cb_func(client->rtc_cb_ctx);
	}
}

static inline unsigned long
rt_tracker_hash(struct ip_addr *addr)
{
	switch (addr->type) {
	case AF_INET:
		return rte_jhash_1word(addr->address.ip_v4.s_addr,
				       rt_tracker_table_seed);
	case AF_INET6:
		return rte_jhash_32b(addr->address.ip_v6.s6_addr32, 4,
				     rt_tracker_table_seed);
	}
	return 0;
}

static int
rt_tracker_match_dst(struct cds_lfht_node *node, const void *key)
{
	const struct ip_addr *addr = key;

	const struct rt_tracker_info *ti_info
		= caa_container_of(node, const struct rt_tracker_info,
				   rti_node);

	return dp_addr_eq(addr, &ti_info->dst_addr);
}

static struct rt_tracker_info *
rt_tracker_lookup(struct cds_lfht *table, struct ip_addr *addr)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (!table)
		return NULL;

	cds_lfht_lookup(table,
			rt_tracker_hash(addr),
			rt_tracker_match_dst, addr, &iter);

	node = cds_lfht_iter_get_node(&iter);

	if (node)
		return caa_container_of(node, struct rt_tracker_info,
					rti_node);
	return NULL;
}

static int
rt_tracker_insert(struct cds_lfht *table, struct rt_tracker_info *ti_info)
{
	struct cds_lfht_node *ret_node;
	struct ip_addr *dst_addr = &ti_info->dst_addr;
	unsigned long hash = rt_tracker_hash(dst_addr);

	cds_lfht_node_init(&ti_info->rti_node);
	ret_node = cds_lfht_add_unique(table, hash,
				       rt_tracker_match_dst, dst_addr,
				       &ti_info->rti_node);

	if (ret_node != &ti_info->rti_node)
		return -EEXIST;

	return 0;
}

/*
 * Add a tracker to track the route resolution of a given destination
 *
 * INPUT:
 *     vrf - VRF of the destination to be tracked
 *     dst - IP address to be tracked
 *     hash - Hash value to be used in case of multi-path ECMP
 *     cb_ctx - Context for the callback
 *     cb - registered callback, in case there are changes
 *
 * OUTPUT:
 *     rt_tracker_info
 */
struct rt_tracker_info *
dp_rt_tracker_add(struct vrf *vrf, struct ip_addr *addr, void *cb_ctx,
	       tracker_change_notif cb)
{
	int ret = -1;
	struct rt_tracker_info *ti_info;
	struct lpm *lpm;
	struct lpm6 *lpm6;

	if (!vrf->v_rt_tracker_tbl)
		if (rt_tracker_init(vrf) < 0)
			return NULL;

	if (!addr)
		return NULL;

	ti_info = rt_tracker_lookup(vrf->v_rt_tracker_tbl, addr);
	if (ti_info)
		goto add_client;

	/* Create a new tracker */
	ti_info = zmalloc_aligned(sizeof(*ti_info));
	if (!ti_info)
		return NULL;

	CDS_INIT_LIST_HEAD(&ti_info->rti_client_list);

	ti_info->dst_addr = *addr;
	ti_info->rti_cb_func = &rt_tracker_update;

	/* Add it to hash table */
	if (rt_tracker_insert(vrf->v_rt_tracker_tbl, ti_info) < 0) {
		free(ti_info);
		return NULL;
	}

	switch (addr->type) {
	case AF_INET:
		lpm = rcu_dereference(vrf->v_rt4_head.rt_table[RT_TABLE_MAIN]);
		ret = lpm_tracker_add(lpm, ti_info);
		break;
	case AF_INET6:
		lpm6 = rcu_dereference(
			vrf->v_rt6_head.rt6_table[RT_TABLE_MAIN]);
		ret = lpm6_tracker_add(lpm6, ti_info);
		break;
	}
	if (ret < 0) {
		RTE_LOG(ERR, LPM, "Failed to add tracker\n");
		cds_lfht_del(vrf->v_rt_tracker_tbl, &ti_info->rti_node);
		free(ti_info);
		return NULL;
	}

add_client:
	ret = rt_tracker_client_add(ti_info, cb_ctx, cb);
	if (ret < 0) {
		RTE_LOG(ERR, LPM, "Failed to add tracker client\n");
		return NULL;
	}

	return ti_info;
}

void
dp_rt_tracker_delete(const struct vrf *vrf, struct ip_addr *ip, void *cb_ctx)
{
	struct rt_tracker_info *ti_info;

	ti_info = rt_tracker_lookup(vrf->v_rt_tracker_tbl, ip);
	if (!ti_info) {
		RTE_LOG(ERR, LPM, "Delete tracker: NOT FOUND\n");
		return;
	}
	rt_tracker_client_delete(ti_info, cb_ctx);
	if (cds_list_empty(&ti_info->rti_client_list)) {
		switch (ip->type) {
		case AF_INET:
			lpm_tracker_delete(ti_info);
			break;
		case AF_INET6:
			lpm6_tracker_delete(ti_info);
			break;
		}
		cds_lfht_del(vrf->v_rt_tracker_tbl, &ti_info->rti_node);
		rt_tracker_destroy(ti_info);
	}
}

/*
 * Get tracking status from RT Tracker
 * @param[in] rt_info  Route tracker information
 *
 * @return  true if being tracking, false otherwise.
 */
bool dp_get_rt_tracker_tracking(struct rt_tracker_info *rt_info)
{
	if (!rt_info)
		return false;

	return rt_info->tracking;
}

/*
 * Get tracking status from RT Tracker
 * @param[in] rt_info  Route tracker information
 *
 * @return  Index of NH.
 */
uint32_t dp_get_rt_tracker_nh_index(struct rt_tracker_info *rt_info)
{
	if (!rt_info)
		return 0;

	return rt_info->nhindex;
}

static void
rt_tracker_walk(struct vrf *vrf,
		void (*cb)(struct rt_tracker_info *ti_info, void *cb_ctx),
		void *cb_ctx)
{
	struct cds_lfht_iter iter;
	struct rt_tracker_info *ti_info;

	if (!vrf->v_rt_tracker_tbl)
		return;

	cds_lfht_for_each_entry(vrf->v_rt_tracker_tbl, &iter, ti_info, rti_node)
		cb(ti_info, cb_ctx);
}

static void rt_tracker_show(struct rt_tracker_info *ti_info, void *cb_ctx)
{
	json_writer_t *wr = cb_ctx;
	char b1[INET6_ADDRSTRLEN];
	char b2[INET6_ADDRSTRLEN + 10];
	int ret;
	struct ip_addr ip;
	uint8_t depth;
	int len;

	switch (ti_info->dst_addr.type) {
	case AF_INET:
		inet_ntop(AF_INET, &ti_info->dst_addr.address.ip_v4, b1,
			  sizeof(b1));
		ret = lpm_tracker_get_cover_ip_and_depth(
			ti_info,
			&ip.address.ip_v4.s_addr,
			&depth);
		if (ret) {
			inet_ntop(AF_INET, &ip.address.ip_v4, b2,
				  sizeof(b2));
			len = strlen(b2);
			snprintf(b2 + len, sizeof(b2) - len, "/%d", depth);
		} else {
			strncpy(b2, "No route", INET6_ADDRSTRLEN);
		}
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &ti_info->dst_addr.address.ip_v6, b1,
			  sizeof(b1));
		ret = lpm6_tracker_get_cover_ip_and_depth(
			ti_info,
			(uint8_t *)&ip.address.ip_v6,
			&depth);
		if (ret) {
			inet_ntop(AF_INET6, &ip.address.ip_v6, b2,
				  sizeof(b2));
			len = strlen(b2);
			snprintf(b2 + len, sizeof(b2) - len, "/%d", depth);
		} else {
			strncpy(b2, "No route", INET6_ADDRSTRLEN);
		}
		break;
	}
	jsonw_start_object(wr);
	jsonw_string_field(wr, "dest", b1);
	jsonw_uint_field(wr, "count", rt_tracker_client_count(ti_info));
	jsonw_string_field(wr, "cover", b2);
	jsonw_end_object(wr);
}

static void rt_tracker_show_all(json_writer_t *wr, struct vrf *vrf)
{
	jsonw_start_array(wr);
	rt_tracker_walk(vrf, rt_tracker_show, wr);
	jsonw_end_array(wr);
}

/* Return json showing the trackers for the given address */
int cmd_rt_tracker_op(FILE *f, int argc, char **argv)
{
	json_writer_t *wr;
	struct vrf *vrf = get_vrf(VRF_DEFAULT_ID);

	if (argc != 2)
		return -1;

	if (strcmp("show", argv[1]))
		return -1;

	wr = jsonw_new(f);
	jsonw_pretty(wr, true);
	jsonw_name(wr, "route_tracker_state");

	rt_tracker_show_all(wr, vrf);

	jsonw_destroy(&wr);

	return 0;
}

/*
 * For test only:
 * tracker <ADD|REMOVE> <ADDR>
 * tracker function can not be specified, it will always be a test one.
 */
static route_tracker_handler route_tracker_fn;

void cmd_rt_tracker_cfg_test_set(route_tracker_handler handler)
{
	route_tracker_fn = handler;
}

int cmd_rt_tracker_cfg(FILE *f, int argc, char **argv)
{
	if (route_tracker_fn)
		return route_tracker_fn(f, argc, argv);

	return 0;
}
