/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <src/util.h>
#include "fal.h"
#include "dp_test.h"
#include "dp_test_cpp_lim.h"

#define DEBUG(...)						\
	do {							\
		if (dp_test_debug_get() == 1)			\
			printf(__VA_ARGS__);			\
	} while (0)

#define NUM_LIMITER_RULES 3

struct fal_attribute_t l_attr_list[NUM_LIMITER_RULES];
fal_object_t l_attr_objs[NUM_LIMITER_RULES];
fal_object_t limiter_obj_id = FAL_NULL_OBJECT_ID;

struct fal_attribute_t lp_attr_list[1];

int create_and_commit_cpp_rate_limiter(void)
{
	int ret;

	/* Set up first policer, which will be used for "default" */
	struct fal_attribute_t policer_default_attr[] = {
		{ .id = FAL_POLICER_ATTR_METER_TYPE,
		  .value.u32 = FAL_POLICER_METER_TYPE_PACKETS },
		{ .id = FAL_POLICER_ATTR_MODE,
		  .value.u32 = FAL_POLICER_MODE_CPP },
		{ .id = FAL_POLICER_ATTR_RED_PACKET_ACTION,
		  .value.u32 = FAL_PACKET_ACTION_DROP},
		{ .id = FAL_POLICER_ATTR_CBS,
		  .value.u64 = 1 },
		{ .id = FAL_POLICER_ATTR_CIR,
		  .value.u64 = 3000 }
	};

	ret = fal_policer_create(ARRAY_SIZE(policer_default_attr),
					    policer_default_attr,
					    &l_attr_objs[0]);

	if (ret) {
		printf("Failed to create policer 0\n");
		assert(0);
		return ret;
	}


	/* Set up second rate limiter, which will be used for "OSPF" */

	struct fal_attribute_t policer_ospf_attr[] = {
		{ .id = FAL_POLICER_ATTR_METER_TYPE,
		  .value.u32 = FAL_POLICER_METER_TYPE_PACKETS },
		{ .id = FAL_POLICER_ATTR_MODE,
		  .value.u32 = FAL_POLICER_MODE_CPP },
		{ .id = FAL_POLICER_ATTR_RED_PACKET_ACTION,
		  .value.u32 = FAL_PACKET_ACTION_DROP},
		{ .id = FAL_POLICER_ATTR_CBS,
		  .value.u64 = 1 },
		{ .id = FAL_POLICER_ATTR_CIR,
		  .value.u64 = 10000 }
	};

	ret = fal_policer_create(ARRAY_SIZE(policer_ospf_attr),
					    policer_ospf_attr,
					    &l_attr_objs[1]);

	if (ret) {
		printf("Failed to create policer 1\n");
		fal_policer_delete(l_attr_objs[0]);
		assert(0);
		return ret;
	}

	/* Set up third rate limiter, which will be used for "BGP" */

	struct fal_attribute_t policer_bgp_attr[] = {
		{ .id = FAL_POLICER_ATTR_METER_TYPE,
		  .value.u32 = FAL_POLICER_METER_TYPE_BYTES },
		{ .id = FAL_POLICER_ATTR_MODE,
		  .value.u32 = FAL_POLICER_MODE_CPP },
		{ .id = FAL_POLICER_ATTR_RED_PACKET_ACTION,
		  .value.u32 = FAL_PACKET_ACTION_DROP},
		{ .id = FAL_POLICER_ATTR_CBS,
		  .value.u64 = 1 * (1024 / 8) },
		{ .id = FAL_POLICER_ATTR_CIR,
		  .value.u64 = 652 * (1024 / 8) }
	};

	ret = fal_policer_create(ARRAY_SIZE(policer_bgp_attr),
					    policer_bgp_attr,
					    &l_attr_objs[2]);

	if (ret) {
		printf("Failed to create policer 2\n");
		fal_policer_delete(l_attr_objs[0]);
		fal_policer_delete(l_attr_objs[1]);
		assert(0);
		return ret;
	}

	/* Associate the above objects with required limiters */

	l_attr_list[0].id = FAL_CPP_LIMITER_ATTR_DEFAULT;
	l_attr_list[0].value.objid = l_attr_objs[0];
	l_attr_list[1].id = FAL_CPP_LIMITER_ATTR_OSPF;
	l_attr_list[1].value.objid = l_attr_objs[1];
	l_attr_list[2].id = FAL_CPP_LIMITER_ATTR_BGP;
	l_attr_list[2].value.objid = l_attr_objs[2];

	ret = fal_create_cpp_limiter(ARRAY_SIZE(l_attr_list),
				     l_attr_list, &limiter_obj_id);

	if (ret) {
		printf("Failed to allocate limiter\n");
		fal_policer_delete(l_attr_objs[0]);
		fal_policer_delete(l_attr_objs[1]);
		fal_policer_delete(l_attr_objs[2]);
		assert(0);
		return ret;
	}

	struct fal_attribute_t sw_attr;

	sw_attr.id = FAL_SWITCH_ATTR_CPP_RATE_LIMITER;
	sw_attr.value.objid = limiter_obj_id;

	ret = fal_set_switch_attr(&sw_attr);

	if (ret) {
		printf("Failed to commit limiter to hardware\n");
		fal_remove_cpp_limiter(limiter_obj_id);
		limiter_obj_id = FAL_NULL_OBJECT_ID;
		fal_policer_delete(l_attr_objs[0]);
		fal_policer_delete(l_attr_objs[1]);
		fal_policer_delete(l_attr_objs[2]);
		assert(0);
		return ret;
	}

	return 0;
}

void remove_and_commit_cpp_rate_limiter(void)
{
	int ret;
	struct fal_attribute_t sw_attr;

	if (limiter_obj_id == FAL_NULL_OBJECT_ID)
		return;

	sw_attr.id = FAL_SWITCH_ATTR_CPP_RATE_LIMITER;
	sw_attr.value.objid = FAL_NULL_OBJECT_ID;

	ret = fal_set_switch_attr(&sw_attr);
	if (ret) {
		printf("Failed to remove limiter from hardware\n");
		assert(0);
	}

	ret = fal_remove_cpp_limiter(limiter_obj_id);
	if (ret) {
		printf("Failed to remove limiter");
		assert(0);
	}

	ret = fal_policer_delete(l_attr_objs[0]);
	if (ret) {
		printf("Failed to remove limiter profile 0\n");
		assert(0);
	}

	ret = fal_policer_delete(l_attr_objs[1]);
	if (ret) {
		printf("Failed to remove limiter profile 1\n");
		assert(0);
	}

	ret = fal_policer_delete(l_attr_objs[2]);
	if (ret) {
		printf("Failed to remove limiter profile 2\n");
		assert(0);
	}

	limiter_obj_id = FAL_NULL_OBJECT_ID;
}

void check_cpp_rate_limiter_stats(void)
{
	int ret;
	int i;

	enum fal_policer_stat_type cntr_ids[] = {
		FAL_POLICER_STAT_GREEN_PACKETS,
		FAL_POLICER_STAT_GREEN_BYTES,
		FAL_POLICER_STAT_RED_PACKETS,
		FAL_POLICER_STAT_RED_BYTES
	};
	uint64_t cntrs[FAL_POLICER_STAT_MAX];

	if (limiter_obj_id == FAL_NULL_OBJECT_ID) {
		printf("Limiter object has not been initialised\n");
		assert(0);
		return;
	}

	for (i = 0; i < NUM_LIMITER_RULES; i++) {
		ret = fal_policer_get_stats_ext(l_attr_objs[i],
						ARRAY_SIZE(cntr_ids), cntr_ids,
						FAL_STATS_MODE_READ, cntrs);
		if (ret) {
			printf("Failed to get stats for policer %d\n", i);
			assert(0);
			continue;
		}
		DEBUG("limiter %d: accepted: packets %lu, bytes %lu\n",
		       i, cntrs[0], cntrs[1]);
		DEBUG("            dropped: packets %lu, bytes %lu\n\n",
		       cntrs[2], cntrs[3]);
		assert(cntrs[0] == 10);
		assert(cntrs[1] == 11);
		assert(cntrs[2] == 12);
		assert(cntrs[3] == 13);
	}
}
