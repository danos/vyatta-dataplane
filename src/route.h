/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef ROUTE_H
#define ROUTE_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "fal_plugin.h"
#include "compiler.h"
#include "control.h"
#include "ip_forward.h"
#include "json_writer.h"
#include "mpls/mpls.h"
#include "nh_common.h"
#include "pd_show.h"
#include "pktmbuf_internal.h"
#include "route_flags.h"
#include "urcu.h"
#include "util.h"

struct ifnet;
struct rte_mbuf;
struct vrf;
struct ll_entry;

struct route_head {
	uint32_t rt_rtm_max;
	struct lpm **rt_table;
};

#define PBR_TABLEID_MAX 128

static inline bool
tableid_in_pbr_range(uint32_t tableid)
{
	return (tableid > 0 && tableid <= PBR_TABLEID_MAX);
}

/*
 * Nexthop (output information) related APIs
 */
struct next_hop *nexthop_select(int family, uint32_t nh_idx,
				const struct rte_mbuf *m,
				uint16_t ether_type);
struct next_hop *nexthop_get(uint32_t nh_idx, uint8_t *size);
void rt_print_nexthop(json_writer_t *json, uint32_t next_hop,
		      enum rt_print_nexthop_verbosity v);

/*
 * IPv4 route table apis.
 */
int route_init(struct vrf *vrf);
void route_uninit(struct vrf *vrf, struct route_head *rt_head);
struct next_hop *rt_lookup_fast(struct vrf *vrf, in_addr_t dst,
				uint32_t tblid,
				const struct rte_mbuf *m);

int rt_insert(vrfid_t vrf_id, in_addr_t dst, uint8_t depth, uint32_t id,
	      uint8_t scope, uint8_t proto, struct next_hop hops[],
	      size_t size, bool replace);
int rt_delete(vrfid_t vrf_id, in_addr_t dst, uint8_t depth,
	      uint32_t id, uint8_t scope);
void rt_flush_all(enum cont_src_en cont_src);
void rt_flush(struct vrf *vrf);
enum rt_walk_type {
	RT_WALK_LOCAL,
	RT_WALK_RIB,
	RT_WALK_ALL,
};
int rt_walk(struct route_head *rt_head, json_writer_t *json, uint32_t id,
	    uint32_t cnt, enum rt_walk_type type);
int rt_walk_next(struct route_head *rt_head, json_writer_t *json,
		 uint32_t id, const struct in_addr *addr,
		 uint8_t plen, uint32_t cnt, enum rt_walk_type type);
int rt_stats(struct route_head *, json_writer_t *, uint32_t);
void rt_if_handle_in_dataplane(struct ifnet *ifp);
void rt_if_punt_to_slowpath(struct ifnet *ifp);
int rt_show(struct route_head *rt_head, json_writer_t *json, uint32_t tblid,
	    const struct in_addr *addr);
int rt_show_exact(struct route_head *rt_head, json_writer_t *json,
		  uint32_t tblid, const struct in_addr *addr, uint8_t plen);
void nexthop_tbl_init(void);
bool rt_valid_tblid(vrfid_t vrfid, uint32_t tblid);
int rt_local_show(struct route_head *rt_head, uint32_t id, FILE *f);
bool is_local_ipv4(vrfid_t vrf_id, in_addr_t dst);

static inline bool
nexthop_is_local(const struct next_hop *nh)
{
	return nh->flags & RTF_LOCAL;
}

struct ifnet *nhif_dst_lookup(const struct vrf *vrf,
			      in_addr_t dst,
			      bool *connected);

void routing_insert_arp_safe(struct llentry *lle, bool arp_change);
void routing_remove_arp_safe(struct llentry *lle);

uint32_t *route_sw_stats_get(void);
uint32_t *route_hw_stats_get(void);

int route_get_pd_subset_data(json_writer_t *json, enum pd_obj_state subset);

int rt_show_platform_routes(const struct fal_ip_address_t *pfx,
			    uint8_t prefixlen,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    void *arg);
#endif
