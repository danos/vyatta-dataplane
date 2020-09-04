/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef FAL_PLUGIN_TEST_H
#define FAL_PLUGIN_TEST_H
#include <stdbool.h>

extern bool dp_test_fal_plugin_called;
extern uint32_t dp_test_fal_plugin_state;
extern void *dp_test_fal_plugin_ptr;

struct fal_policer {
	uint32_t meter;  /* always packets */
	uint32_t mode;   /* always storm ctl */
	uint32_t rate;   /* always in bps, irrespective of user cfg.*/
	uint32_t action; /* Always drop */
	uint32_t burst;  /* always 1 */
	bool assert_transitions;
};

struct vlan_feat {
	int      ifindex;
	uint16_t vlan;
	uint32_t mac_limit;
	fal_object_t       map_obj;
	struct fal_policer *policer[FAL_TRAFFIC_MAX];
};

#endif /* FAL_PLUGIN_TEST_H */
