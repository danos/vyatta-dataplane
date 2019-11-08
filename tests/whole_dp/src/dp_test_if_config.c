/*
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
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
#include "dp_test_netlink_state.h"
#include "dp_test_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib.h"

DP_DECL_TEST_SUITE(if_cfg_suite);

DP_DECL_TEST_CASE(if_cfg_suite, if_config_switchport, NULL, NULL);

/*
 * Check that the out of order infra works. Use switchport command
 * as it already uses the infra.
 */
DP_START_TEST(if_config_switchport, add_cmd)
{
	dp_test_send_config_src(dp_test_cont_src_get(),
				"switchport sw1 hw-switching enable");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"switchport sw1 hw-switching disable");

	/*
	 * Using a loopback here as we can create one of those easily.
	 * It does not matter that the command can not be applied to
	 * a loopback, because we are testing the replay infra here.
	 */
	dp_test_intf_loopback_create("sw2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"switchport sw1 hw-switching disable");

	dp_test_intf_loopback_delete("sw2");

} DP_END_TEST;

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

	vifp = ifnet_byifname("vtun0");
	dp_test_fail_unless(vifp != NULL, "Expected non-NULL ifp for vtun0");
	dp_test_fail_unless(vifp->if_name != NULL,
			    "Expected non-NULL ifp->if_name for vtun0");

	dp_test_netlink_del_interface_l2("vtun0");
	dp_test_intf_virt_del("vtun0");
} DP_END_TEST;
