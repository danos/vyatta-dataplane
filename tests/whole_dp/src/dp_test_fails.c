/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Tests that are supposed to fail to exercise UT infra and
 * other uts that are testing the infra itself.
 * Tests that cause failures are declared as DONT_RUN.
 * Any tests that do run are expected to pass.
 * Please investigate and fix any failures and fix any
 * compile errors in all tests.
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"

DP_DECL_TEST_SUITE(failure_suite);

DP_DECL_TEST_CASE(failure_suite, internals, NULL, NULL);
DP_START_TEST(internals, string_overflow)
{
	unsigned int written = 0;
	char buffer_ut[20];

	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s%d", "fit", 1);
	ck_assert(written == 4);
	ck_assert(strcmp(buffer_ut,
			 "fit1") == 0);
	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s%d", "fit", 2);
	ck_assert(written == 8);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2") == 0);

	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s%d%s%d", "fit", 3, "fit", 4);
	ck_assert(written == 16);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2fit3fit4") == 0);

	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s", "fit");

	/* this looks odd - but spush should return 20 rather than 19
	 * because trailing '\0' takes up the last char so no point
	 * returning size-1 forever
	 */
	ck_assert(written == 20);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2fit3fit4fit") == 0);
	/*
	 * More stuff from here makes no difference
	 */
	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%d%s%d", 5, "fit", 6);
	ck_assert(written == 20);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2fit3fit4fit") == 0);
	/*
	 * Now reset to empty and try a huge string
	 */
	written = 0;
	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s%d%s%d", "fit", 1,
			 "fit2fit3fit4fit5fit6fit7fit8fit9fit", 10);
	ck_assert(written == 20);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2fit3fit4fit") == 0);
} DP_END_TEST;

DP_DECL_TEST_CASE(failure_suite, rx_pkt, NULL, NULL);

DP_START_TEST_DONT_RUN(rx_pkt, wrong_oif)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2.2.2.2/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp3T2");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T2", "2.2.2.1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	/* deliberate error - should be "dp3T2" */
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str, "aa:aa:aa:aa:aa:3",
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp2T1", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
} DP_END_TEST;

DP_START_TEST_DONT_RUN(rx_pkt, cleanup1)
{
	/* Clean Up - tests don't cleanup if they fail */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
} DP_END_TEST;

DP_START_TEST_DONT_RUN(rx_pkt, wrong_pkt)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2.2.2.2/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp3T2");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T2", "2.2.2.1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");

	/* deliberate error - should be aa:aa:aa:aa:aa:3 */
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str, "aa:aa:aa:aa:aa:99",
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp2T1", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
} DP_END_TEST;

DP_START_TEST_DONT_RUN(rx_pkt, cleanup2)
{
	/* Clean Up - tests don't cleanup if they fail */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(failure_suite, cleanup, NULL, NULL);

DP_START_TEST_DONT_RUN(cleanup, routes_and_ifaddrs)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2.2.2.2/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp3T2");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T2", "2.2.2.1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str, "aa:aa:aa:aa:aa:2",
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp2T1", exp);

	/* cleanup deliberately missing */
	/* dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24"); */
	/* dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24"); */

} DP_END_TEST;

DP_START_TEST_DONT_RUN(cleanup, cleanup3)
{
	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(failure_suite, pkt_drop, NULL, NULL);

DP_START_TEST_DONT_RUN(pkt_drop, no_route)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2.2.2.2/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp3T2");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T2", "2.2.2.1", nh_mac_str);

	/* Deliberately wrong - add pkt to non-existent addr */
	test_pak = dp_test_create_ipv4_pak("88.88.88.88", "99.99.99.9",
					   1, &len);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str, "aa:aa:aa:aa:aa:3",
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp2T1", exp);

	/* cleanup deliberately missing */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");

} DP_END_TEST;

DP_START_TEST_DONT_RUN(pkt_drop, cleanup3)
{
	/* Clean Up - tests don't cleanup if they fail */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(failure_suite, bad_operstate, NULL, NULL);

DP_START_TEST_DONT_RUN(bad_operstate, no_local)
{
	char cmd[TEST_MAX_CMD_LEN];
	char expected[TEST_MAX_REPLY_LEN];

	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.1/24");

	/* deliberate mistake */
	strcpy(expected, "1.1.1.2");
	snprintf(cmd, TEST_MAX_CMD_LEN, "local");
	dp_test_check_state_gone_show(cmd, expected, 0);
	/* cleanup */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.1/24");

} DP_END_TEST;

DP_START_TEST_DONT_RUN(bad_operstate, cleanup4)
{
	/* Clean Up - tests don't cleanup if they fail */
	dp_test_intf_bridge_remove_port("br0", "dp1T0");
	dp_test_intf_bridge_remove_port("br0", "dp2T1");
	dp_test_intf_bridge_del("br0");
} DP_END_TEST;
