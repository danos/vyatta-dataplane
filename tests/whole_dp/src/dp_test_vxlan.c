/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT VXLAN tests
 */
#include "dp_test_lib_intf_internal.h"
#include "dp_test/dp_test_macros.h"

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

/* Create 2 x vxlan on the same vni, 2nd creation should fail */
DP_DECL_TEST_CASE(vxlan_suite, vxlan_cfg_duplicate, NULL, NULL);
DP_START_TEST(vxlan_cfg_duplicate, vxlan_cfg_duplicate)
{
	/* Reintroduce when we have expect failure test api */
#if 0
	dp_test_intf_vxlan_create("vxl70", 70, "dp1T0");
	dp_test_intf_vxlan_create("vxl71", 70, "dp1T1"); /* dup vni */
	dp_test_intf_vxlan_del("vxl70", 70);
	/* vxlan 71 should have failed to be created, so we dont delete it */
#endif
} DP_END_TEST;
