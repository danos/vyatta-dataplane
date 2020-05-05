/*
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT IP pic edge tests
 */

#include <libmnl/libmnl.h>
#include <linux/random.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"

#include "dp_test_pktmbuf_lib_internal.h"

DP_DECL_TEST_SUITE(ip_pic_edge_suite);

DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge, NULL, NULL);
DP_START_TEST(ip_pic_edge, ip_pic_edge)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 nh 2.2.2.1 int:dp2T1 backup");
	dp_test_netlink_del_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 nh 2.2.2.1 int:dp2T1 backup");

	/* This is a full service dataplane - we support both orders! */
	dp_test_netlink_add_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 backup nh 2.2.2.1 int:dp2T1");
	dp_test_netlink_del_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 backup nh 2.2.2.1 int:dp2T1");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

} DP_END_TEST;
