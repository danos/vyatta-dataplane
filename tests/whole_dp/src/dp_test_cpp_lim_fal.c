/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <libmnl/libmnl.h>
#include <rte_sched.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "fal.h"
#include "dp_test_cpp_lim.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_json_utils.h"

/* object where the limiter is stored in dp_test_cpp_lim.c */
extern fal_object_t limiter_obj_id;

DP_DECL_TEST_SUITE(cpp_lim_fal);

DP_DECL_TEST_CASE(cpp_lim_fal, cpp_lim_fal_basic, NULL, NULL);

DP_START_TEST(cpp_lim_fal_basic, fal_basic_1)
{
	int ret;

	/* Create a predefined limiter and have it committed */
	ret = create_and_commit_cpp_rate_limiter();

	dp_test_fail_unless((ret == 0),
			    "failed to configure the rate limiter\n");

	/* limiter object is in "limiter_obj_id" */
	dp_test_fail_unless((limiter_obj_id != FAL_NULL_OBJECT_ID),
			    "the rate limiter was not stored\n");


	/* first get the object ids of the protocol limiters */
#define NUM_LIMITER_RULES 3
	struct fal_attribute_t l_attr_list[NUM_LIMITER_RULES];
	l_attr_list[0].id = FAL_CPP_LIMITER_ATTR_DEFAULT;
	l_attr_list[1].id = FAL_CPP_LIMITER_ATTR_OSPF;
	l_attr_list[2].id = FAL_CPP_LIMITER_ATTR_BGP;

	ret = fal_get_cpp_limiter_attribute(limiter_obj_id,
		ARRAY_SIZE(l_attr_list), l_attr_list);

	dp_test_fail_unless((ret == 0),
			    "failed to get the rate limiter attributes\n");

	/* check if some statistics were returned */
	check_cpp_rate_limiter_stats();

	/* remove the rate limiter */
	remove_and_commit_cpp_rate_limiter();
} DP_END_TEST;
