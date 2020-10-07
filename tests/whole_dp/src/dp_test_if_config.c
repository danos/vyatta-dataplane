/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

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

DP_DECL_TEST_SUITE(if_cfg_suite);

DP_DECL_TEST_CASE(if_cfg_suite, if_config_vtun, NULL, NULL);
/*
 * Test dataplane allocates an ifp and index for OpenVPN "vtun"
 * interfaces.
 */
DP_START_TEST(if_config_vtun, add_vtun)
{
	int idx;
	struct ifnet *vifp;

	dp_test_intf_virt_add("vtun0");
	dp_test_netlink_set_interface_l2("vtun0");

	idx = ifnet_nametoindex("vtun0");
	dp_test_fail_unless(idx != 0, "Expected non-zero ifindex for vtun0");

	vifp = dp_ifnet_byifname("vtun0");
	dp_test_fail_unless(vifp != NULL, "Expected non-NULL ifp for vtun0");
	dp_test_fail_unless(vifp->if_name != NULL,
			    "Expected non-NULL ifp->if_name for vtun0");

	dp_test_netlink_del_interface_l2("vtun0");
	dp_test_intf_virt_del("vtun0");
} DP_END_TEST;
