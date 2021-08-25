/*
 * MPLS Label Table
 *
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef MPLS_LABEL_TABLE_H
#define MPLS_LABEL_TABLE_H

#include "mpls.h"
#include <linux/mpls.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "compiler.h"
#include "nh_common.h"
#include "route.h"
#include "mpls_forward.h"

#define MPLS_LABEL_ALL (1 << 20)

struct cds_lfht;
struct rte_mbuf;

#define MPLS_OAM_MAX_FANOUT     (16)
struct mpls_oam_outinfo {
	bool inuse;
	uint64_t bitmask;
	struct ifnet *ifp;
	union next_hop_outlabels outlabels;
	in_addr_t gateway;
};

extern int global_label_space_id;
extern struct cds_lfht *global_label_table;

void mpls_init(void);
void mpls_netlink_init(void);

struct cds_lfht *mpls_label_table_get_and_lock(int labelspace);
void mpls_label_table_unlock(int labelspace);
void mpls_label_table_insert_label(int labelspace, uint32_t in_label,
				   enum nh_type nh_type,
				   enum mpls_payload_type payload_type,
				   struct next_hop *hops,
				   size_t size);
void mpls_label_table_remove_label(int labelspace, uint32_t in_label);

struct next_hop *
mpls_label_table_lookup(struct cds_lfht *label_table, uint32_t in_label,
			const struct rte_mbuf *m, uint16_t ether_type,
			enum nh_type *nht,
			enum mpls_payload_type *payload_type)
	__hot_func;

void mpls_label_table_resize(int labelspace, uint32_t max_label);
void mpls_label_table_set_dump(FILE *fp, int labelspace,
			       uint32_t label_filter);
void mpls_oam_v4_lookup(int labelspace, uint8_t nlabels,
			const label_t *labels,
			uint32_t saddr, uint32_t daddr,
			unsigned short sport, unsigned short dport,
			uint64_t bitmask, unsigned int masklen,
			struct mpls_oam_outinfo outinfo[],
			unsigned int max_fanout);

uint32_t *mpls_label_table_hw_stats_get(void);
int mpls_label_table_get_pd_subset_data(json_writer_t *json,
					enum pd_obj_state subset);

void mpls_update_all_routes_for_nh_change(int family, uint32_t nhl_idx);

#endif /* MPLS_LABEL_TABLE_H */
