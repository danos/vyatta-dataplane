/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef ROUTE_V6_H
#define ROUTE_V6_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/netlink.h>

#include "compiler.h"
#include "json_writer.h"
#include "mpls/mpls.h"
#include "pd_show.h"
#include "route_flags.h"
#include "util.h"

struct ifnet;
struct nlattr;
struct vrf;

enum cont_src_en;

#define IN6_IS_ADDR_UNSPEC_LINKLOCAL(a) \
	((((__const uint32_t *) (a))[0] & htonl(0xffc00000)) \
		 == htonl(0xfe800000)                        \
	 && (((__const uint32_t *) (a))[1] == 0)              \
	 && (((__const uint32_t *) (a))[2] == 0)              \
	 && (((__const uint32_t *) (a))[3] == 0))

/* per vrf route head */
struct route6_head {
	uint32_t rt6_rtm_max;
	struct lpm6 **rt6_table;
};

void nexthop_v6_tbl_init(void);
int route_v6_init(struct vrf *vrf);
void route_v6_uninit(struct vrf *vrf, struct route6_head *rt6_head);
struct rte_mbuf;

struct next_hop *nexthop6_select(uint32_t nh_idx,
				 const struct rte_mbuf *m,
				 uint16_t ether_type);
void nexthop6_put(int family, uint32_t idx);
void rt6_print_nexthop(json_writer_t *json, uint32_t next_hop,
		       enum rt_print_nexthop_verbosity v);

struct next_hop *rt6_lookup_fast(struct vrf *vrf,
				 const struct in6_addr *dst, uint32_t tbl_id,
				 const struct rte_mbuf *m);

void rt6_prefetch(const struct rte_mbuf *m, const struct in6_addr *dst);
void rt6_prefetch_fast(const struct rte_mbuf *m, const struct in6_addr *dst)
	__hot_func;
bool rt6_valid_tblid(vrfid_t vrfid, uint32_t tbl_id) __hot_func;

struct rtmsg;

int handle_route6(vrfid_t vrf_id, uint16_t type, const struct rtmsg *rtm,
		  uint32_t table, const void *dest, const void *nexthop,
		  unsigned int ifindex, uint8_t scope, struct nlattr *mpath,
		  uint32_t nl_flags, uint16_t num_labels, label_t *labels);
bool is_local_ipv6(vrfid_t vrf_id, const struct in6_addr *dst);

void rt6_flush_all(enum cont_src_en cont_src);

int cmd_route6(FILE *f, int argc, char **argv);
void rt6_local_show(struct route6_head *rt6_head, FILE *f);
void rt6_if_handle_in_dataplane(struct ifnet *ifp);
void rt6_if_punt_to_slowpath(struct ifnet *ifp);
struct ifnet *nhif_dst_lookup6(const struct vrf *vrf,
			       const struct in6_addr *dst,
			       bool *connected);

void routing6_insert_neigh_safe(struct llentry *lle, bool neigh_change);
void routing6_remove_neigh_safe(struct llentry *lle);

uint32_t *route6_sw_stats_get(void);
uint32_t *route6_hw_stats_get(void);
int route6_get_pd_subset_data(json_writer_t *json, enum pd_obj_state subset);

#endif
