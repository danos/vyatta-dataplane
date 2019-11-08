/*
 * MPLS Label Table
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
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

#include "nh.h"
#include "route.h"

struct cds_lfht;
struct rte_mbuf;

enum mpls_payload_type {
	MPT_UNSPEC = RTMPT_IP,
	MPT_IPV4 = RTMPT_IPV4,
	MPT_IPV6 = RTMPT_IPV6,
};

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
				   union next_hop_v4_or_v6_ptr hops,
				   size_t size);
void mpls_label_table_remove_label(int labelspace, uint32_t in_label);

union next_hop_v4_or_v6_ptr
mpls_label_table_lookup(struct cds_lfht *label_table, uint32_t in_label,
			const struct rte_mbuf *m, uint16_t ether_type,
			enum nh_type *nht,
			enum mpls_payload_type *payload_type)
	__attribute__((hot));

void mpls_label_table_resize(int labelspace, uint32_t max_label);
void mpls_label_table_set_dump(FILE *fp, const int labelspace);
void mpls_oam_v4_lookup(int labelspace, uint8_t nlabels,
			const label_t *labels,
			uint32_t saddr, uint32_t daddr,
			unsigned short sport, unsigned short dport,
			uint64_t bitmask, unsigned int masklen,
			struct mpls_oam_outinfo outinfo[],
			unsigned int max_fanout);

#endif
