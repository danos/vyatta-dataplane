/*-
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2019 AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef RT_TRACKER_H
#define RT_TRACKER_H

#include <bsd/sys/tree.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "urcu.h"
#include "vrf.h"

typedef void (*tracker_change_notif)(void *cb_ctx);

struct rt_tracker_client_t {
	struct cds_list_head rtc_client_links;
	void                 *rtc_cb_ctx;
	tracker_change_notif rtc_cb_func;
};

struct rt_tracker_info {
	struct cds_lfht_node rti_node;
	struct cds_list_head rti_client_list;
	struct cds_list_head rti_links;
	RB_ENTRY(rt_tracker_info) rti_tree_node;
	tracker_change_notif rti_cb_func;
	struct ip_addr       dst_addr;
	uint32_t             nhindex;
	void                 *rule;
	struct rcu_head      rti_rcu;
	uint8_t              r_depth;
	bool                 tracking;
};


struct rt_tracker_info *
rt_tracker_add(struct vrf *vrf, struct ip_addr *addr, void *cb_ctx,
	       tracker_change_notif cb);
void
rt_tracker_delete(const struct vrf *vrf, struct ip_addr *addr, void *cb_ctx);
void rt_tracker_uninit(struct vrf *vrf);

uint32_t
rt_tracker_client_count(struct rt_tracker_info *ti_info);

int cmd_rt_tracker_op(FILE *f, int argc, char **argv);

/* For test only */
typedef int (*route_tracker_handler)(FILE *f, int argc, char **argv);
int cmd_rt_tracker_cfg(FILE *f, int argc, char **argv);
void cmd_rt_tracker_cfg_test_set(route_tracker_handler handler);

#endif /* RT_TRACKER */
