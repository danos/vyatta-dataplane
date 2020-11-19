/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
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
#include "vrf_internal.h"

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

void rt_tracker_uninit(struct vrf *vrf);

uint32_t
rt_tracker_client_count(struct rt_tracker_info *tracker);

int cmd_rt_tracker_op(FILE *f, int argc, char **argv);

/* For test only */
typedef int (*route_tracker_handler)(FILE *f, int argc, char **argv);
int cmd_rt_tracker_cfg(FILE *f, int argc, char **argv);
void cmd_rt_tracker_cfg_test_set(route_tracker_handler handler);

#endif /* RT_TRACKER */
