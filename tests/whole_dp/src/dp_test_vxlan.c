/*
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT VXLAN tests
 */
#include "dp_test_lib_intf.h"
#include "dp_test_macros.h"

DP_DECL_TEST_SUITE(vxlan_suite);

/*
 * Check that we can add and delete a vxlan interface via netlink and that the
 * show command output matches what we asked for.
 */
DP_DECL_TEST_CASE(vxlan_suite, vxlan_cfg_single, NULL, NULL);
DP_START_TEST(vxlan_cfg_single, vxlan_cfg_single)
{
	dp_test_intf_vxlan_create("vxl50", 50, "dp1T0");
	dp_test_intf_vxlan_del("vxl50", 50);
} DP_END_TEST;

DP_DECL_TEST_CASE(vxlan_suite, vxlan_cfg_double, NULL, NULL);
DP_START_TEST(vxlan_cfg_double, vxlan_cfg_double)
{
	dp_test_intf_vxlan_create("vxl60", 60, "dp1T1");
	dp_test_intf_vxlan_create("vxl61", 61, "dp1T2");
	dp_test_intf_vxlan_del("vxl61", 61);
	dp_test_intf_vxlan_del("vxl60", 60);
} DP_END_TEST;

