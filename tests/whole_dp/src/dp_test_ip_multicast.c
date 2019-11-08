/*
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT Multicast IP tests
 */
#include "ip_funcs.h"
#include "in_cksum.h"

#include "dp_test_lib_exp.h"
#include "dp_test_macros.h"
#include "dp_test_netlink_state.h"
#include "dp_test_pktmbuf_lib.h"

DP_DECL_TEST_SUITE(ip_msuite);

DP_DECL_TEST_CASE(ip_msuite, ip_mfwd_1, NULL, NULL);
DP_START_TEST(ip_mfwd_1, local)
{
	const char *multi_dest = "224.0.0.1"; /* Link local */
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Create multicast pak */
	test_pak = dp_test_create_ipv4_pak("10.73.1.1", multi_dest,
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_msuite, ip_mfwd_2, NULL, NULL);
DP_START_TEST(ip_mfwd_2, non_local)
{
	const char *multi_dest = "224.0.1.1"; /* Not link local */
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Create multicast pak */
	test_pak = dp_test_create_ipv4_pak("10.73.1.1", multi_dest,
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

/*
 * Limited broadcast.
 */
DP_DECL_TEST_CASE(ip_msuite, ip_mfwd_3, NULL, NULL);
DP_START_TEST(ip_mfwd_3, limited_broadcast)
{
	const char *multi_dest = "255.255.255.255"; /* Limited Broadcast */
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Create multicast pak */
	test_pak = dp_test_create_ipv4_pak("10.73.1.1", multi_dest,
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;
