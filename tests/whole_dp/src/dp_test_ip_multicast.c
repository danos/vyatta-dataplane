/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
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
#include "dp_test/dp_test_macros.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"

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
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV4);

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
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV4);

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
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

/*
 * Multicast forwarding
 *
 * Enables multicast forwarding on two interfaces, added a multicast route,
 * injects one pkt to 224.0.0.1 and expects it to be forwarded on both output
 * interfaces.
 */
DP_DECL_TEST_CASE(ip_msuite, ip_mfwd_4, NULL, NULL);
DP_START_TEST(ip_mfwd_4, dp_forwarding)
{
	const char *grp_dest = "224.0.1.1"; /* Not link local */
	const char *grp_mac = "01:00:5e:00:01:01";
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_netconf_mcast("dp1T0", AF_INET, true);

	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_netlink_netconf_mcast("dp2T1", AF_INET, true);

	dp_test_nl_add_ip_addr_and_connected("dp2T2", "3.3.3.3/24");
	dp_test_netlink_netconf_mcast("dp2T2", AF_INET, true);

	/* Add multicast route */
	dp_test_mroute_nl(RTM_NEWROUTE, "10.73.1.1", "dp1T0",
			  "224.0.1.1/32 nh int:dp2T1 nh int:dp2T2");

	/* Create multicast pak */
	test_pak = dp_test_create_ipv4_pak("10.73.1.1", grp_dest, 1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T2");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak_m(exp, 0),
				       grp_mac,
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak_m(exp, 0));

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak_m(exp, 1),
				       grp_mac,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak_m(exp, 1));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_mroute_nl(RTM_DELROUTE, "10.73.1.1", "dp1T0",
			  "224.0.1.1/32 nh int:dp2T1 nh int:dp2T2");

	dp_test_netlink_netconf_mcast("dp1T0", AF_INET, false);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	dp_test_netlink_netconf_mcast("dp2T1", AF_INET, false);
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_netconf_mcast("dp2T2", AF_INET, false);
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "3.3.3.3/24");

} DP_END_TEST;

/*
 * IPv6 multicast forwarding
 */
DP_DECL_TEST_CASE(ip_msuite, ip_mfwd_5, NULL, NULL);
DP_START_TEST(ip_mfwd_5, dp_forwarding)
{
	const char *grp_dest = "ff0e::1:1";
	const char *grp_mac = "33:33:00:01:00:01";
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2003:3:3::1/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::2",
				  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T2", "2003:3:3::2",
				  "aa:bb:cc:dd:3:c3");

	dp_test_netlink_netconf_mcast("dp1T0", AF_INET6, true);
	dp_test_netlink_netconf_mcast("dp2T1", AF_INET6, true);
	dp_test_netlink_netconf_mcast("dp2T2", AF_INET6, true);

	/* Add multicast route */
	dp_test_mroute_nl(RTM_NEWROUTE, "2001:1:1::2", "dp1T0",
			  "ff0e::1:1/128 nh int:dp2T1 nh int:dp2T2");


	/* Create multicast pak */
	test_pak = dp_test_create_ipv6_pak("2001:1:1::2",
					   grp_dest,
					   1, &len);

	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create_m(test_pak, 2);

	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T2");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak_m(exp, 0),
				       grp_mac,
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak_m(exp, 0));

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak_m(exp, 1),
				       grp_mac,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak_m(exp, 1));

	dp_test_pak_receive(test_pak, "dp1T0", exp);


	/* Cleanup */
	dp_test_mroute_nl(RTM_DELROUTE, "2001:1:1::2", "dp1T0",
			  "ff0e::1:1/128 nh int:dp2T1 nh int:dp2T2");

	dp_test_netlink_netconf_mcast("dp1T0", AF_INET6, false);
	dp_test_netlink_netconf_mcast("dp2T1", AF_INET6, false);
	dp_test_netlink_netconf_mcast("dp2T2", AF_INET6, false);

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::2",
				  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T2", "2003:3:3::2",
				  "aa:bb:cc:dd:3:c3");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2003:3:3::1/64");

} DP_END_TEST;
