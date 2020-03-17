/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dp_test_ip_n.c dataplane UT IPv4 tests, inject multiple paks
 *
 * It is useful to be able to inject multiple paks in a single test so we can
 * get some meaningful performance stats (dcache and icache hits) from a
 * single test.
 */
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_netlink_state_internal.h"

DP_DECL_TEST_SUITE(ip_suite_n);

DP_DECL_TEST_CASE(ip_suite_n, ip_fwd_2, NULL, NULL);
DP_START_TEST(ip_fwd_2, if_fwd_2)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *rx_pak_n[2];
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	/* Create pak to match the route added above */
	rx_pak_n[0] = dp_test_create_ipv4_pak("10.73.1.1", "10.73.2.1",
					      1, &len);
	rx_pak_n[1] = dp_test_create_ipv4_pak("10.73.1.1", "10.73.2.2",
					      1, &len);
	dp_test_pktmbuf_eth_init(rx_pak_n[0],
				 dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV4);
	dp_test_pktmbuf_eth_init(rx_pak_n[1],
				 dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create_m(rx_pak_n[0], 1);
	dp_test_exp_append_m(exp, rx_pak_n[1], 1);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak_m(exp, 0),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak_m(exp, 1),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak_m(exp, 0));
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak_m(exp, 1));

	dp_test_pak_receive_n(rx_pak_n, 2, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_suite_n, ip_fwd_n, NULL, NULL);
DP_START_TEST(ip_fwd_n, if_fwd_n)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *rx_pak_n[DP_TEST_MAX_EXPECTED_PAKS];
	const char *nh_mac_str;
	int i, len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	/* Create n paks to match the route added above */
	for (i = 0; i < DP_TEST_MAX_EXPECTED_PAKS; i++) {
		rx_pak_n[i] = dp_test_create_ipv4_pak("10.73.1.1",
						      "10.73.2.1", 1, &len);
		dp_test_pktmbuf_eth_init(rx_pak_n[i],
					 dp_test_intf_name2mac_str("dp1T0"),
					 DP_TEST_INTF_DEF_SRC_MAC,
					 RTE_ETHER_TYPE_IPV4);

		/* Create paks we expect to receive on the tx ring */
		if (i == 0)
			exp = dp_test_exp_create_m(rx_pak_n[i], 1);
		else
			dp_test_exp_append_m(exp, rx_pak_n[i], 1);

		dp_test_pktmbuf_eth_init(dp_test_exp_get_pak_m(exp, i),
					 nh_mac_str,
					 dp_test_intf_name2mac_str("dp2T1"),
					 RTE_ETHER_TYPE_IPV4);
		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak_m(exp, i));
		dp_test_exp_set_oif_name_m(exp, i, "dp2T1");
	}

	dp_test_pak_receive_n(rx_pak_n, DP_TEST_MAX_EXPECTED_PAKS, "dp1T0",
			      exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;
