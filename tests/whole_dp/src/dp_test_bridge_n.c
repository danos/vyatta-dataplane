/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dp_test_bridge_n.c dataplane UT Bridge tests, inject multiple paks
 *
 * It is useful to be able to inject multiple paks in a single test so we can
 * get some meaningful performance stats (dcache and icache hits) from a
 * single test.
 */
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_macros.h"

DP_DECL_TEST_SUITE(bridge_suite_n);

/*
 * Test injection of 2 paks.  Each should generate a bridge flood out of 3
 * ports. We are testing the that we can inject these 2 paks in one
 * process_burst, and that we get the expected 6 paks out, in the correct order
 */
DP_DECL_TEST_CASE(bridge_suite_n, bridge_unicast_m_2, NULL, NULL);
DP_START_TEST(bridge_unicast_m_2, bridge_unicast)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *rx_pak_n[2];
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0"); /* Inject */
	dp_test_intf_bridge_add_port("br1", "dp2T1"); /* flood 1 */
	dp_test_intf_bridge_add_port("br1", "dp3T1"); /* flood 2 */
	dp_test_intf_bridge_add_port("br1", "dp4T1"); /* flood 3 */

	/* Create 2x frame from mac_a to mac_b. Use different ethertypes to
	 * check the correct exp pak is matched to the correct rx pak
	 */
	rx_pak_n[0] = dp_test_create_l2_pak(mac_b, mac_a,
					    DP_TEST_ET_BANYAN, 1, &len);
	rx_pak_n[1] = dp_test_create_l2_pak(mac_b, mac_a,
					    DP_TEST_ET_ATALK, 1, &len);

	/*
	 * Create paks we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 *
	 * Test infra tx check seq is per interface so the expected
	 * order has the paks interleaved by interface.  This means we
	 * must append the exp paks one at a time.
	 */
	exp = dp_test_exp_create_m(rx_pak_n[0], 1);
	dp_test_exp_append_m(exp, rx_pak_n[1], 1);
	dp_test_exp_append_m(exp, rx_pak_n[0], 1);
	dp_test_exp_append_m(exp, rx_pak_n[1], 1);
	dp_test_exp_append_m(exp, rx_pak_n[0], 1);
	dp_test_exp_append_m(exp, rx_pak_n[1], 1);
	/* And expect them in interface order */
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T1");
	dp_test_exp_set_oif_name_m(exp, 2, "dp3T1");
	dp_test_exp_set_oif_name_m(exp, 3, "dp3T1");
	dp_test_exp_set_oif_name_m(exp, 4, "dp4T1");
	dp_test_exp_set_oif_name_m(exp, 5, "dp4T1");

	dp_test_pak_receive_n(rx_pak_n, 2, "dp1T0", exp);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_remove_port("br1", "dp3T1");
	dp_test_intf_bridge_remove_port("br1", "dp4T1");
	dp_test_intf_bridge_del("br1");
} DP_END_TEST;

