/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT IP tests
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

DP_DECL_TEST_SUITE(ip_suite);

DP_DECL_TEST_CASE(ip_suite, ip_cfg, NULL, NULL);
/*
 * Check that we can add and delete routes via netlink and that the
 * show command output matches what we asked for.
 */
DP_START_TEST(ip_cfg, route_add_del)
{
	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Add a route and check it */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");

	/* Now remove the route and check it has gone */
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

/*
 * Verifying adding and deleting a scale of routes such that the LPM
 * grows
 */
DP_START_TEST_FULL_RUN(ip_cfg, route_add_del_scale)
{
	json_object *expected_json;
	char summary_cmd[256];
	vrfid_t vrf_id;
	uint16_t i;

	dp_test_netlink_add_vrf(50, 1);

	/*
	 * Check the state we're starting from, so we know if we've
	 * successfully grown the LPM in this test.
	 */
	vrf_id = dp_test_translate_vrf_id(50);
	snprintf(summary_cmd, sizeof(summary_cmd),
		 "route vrf_id %u summary", vrf_id);
	expected_json = dp_test_json_create(
		"{"
		"    \"route_stats\": {"
		"        \"free\": 255,"
		"    }"
		"}");
	dp_test_check_json_state(summary_cmd, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected_json);

	/* not strictly necessary, but for real-world relevance */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.2.2.2/32");

	/*
	 * Why 258? This happens to be big enough to grow the tbl8
	 * database.
	 *
	 * We use a VRF to ensure a clean LPM state beforehand,
	 * i.e. to ensure the LPM is grown in this test.
	 */
	for (i = 0; i < 258; i++) {
		char route_str[sizeof(
				"vrf:50 255.255.1.1/32 nh 2.2.2.1 int:dp1T0")];

		/* loopback is special, so skip */
		if (i == 127)
			continue;

		dp_test_nl_add_route_fmt(
			true,
			"vrf:50 %u.%u.1.1/32 nh 2.2.2.1 int:dp1T0",
			i % 256, i / 256);
		snprintf(route_str, sizeof(route_str),
			 "vrf:50 %u.%u.1.1/32 nh 2.2.2.1 int:dp1T0",
			i % 256, i / 256);
		dp_test_wait_for_route_lookup(route_str, true);
	}

	for (i = 0; i < 258; i++) {
		/* loopback is special, so skip */
		if (i == 127)
			continue;

		dp_test_nl_del_route_fmt(
			true,
			"vrf:50 %u.%u.1.1/32 nh 2.2.2.1 int:dp1T0",
			i % 256, i / 256);
	}

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.2.2.2/32");

	/* Now verify that we did indeed grow the LPM */
	expected_json = dp_test_json_create(
		"{"
		"    \"route_stats\": {"
		"        \"free\": 511,"
		"    }"
		"}");
	dp_test_check_json_state(summary_cmd, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected_json);

	dp_test_netlink_del_vrf(50, 0);
} DP_END_TEST;

/*
 * Delete an interface address and check connected subnet is deleted.
 */
DP_DECL_TEST_CASE(ip_suite, ip_del_addr, NULL, NULL);
DP_START_TEST(ip_del_addr, del_connected)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_suite, ip_rx, NULL, NULL);
/*
 * Test pak sent to an interface using interface's
 * address is received.
 */
DP_START_TEST(ip_rx, this_ifs_addr)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Create pak to match dp1T0's address added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "1.1.1.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

DP_START_TEST(ip_rx, nondp_intf)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Add the route we want the packet to follow */
	dp_test_intf_nondp_create("nondp1");
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:nondp1");

	/* Create pak to match dp1T0's address added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:nondp1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_intf_nondp_delete("nondp1");
} DP_END_TEST;

DP_START_TEST(ip_rx, fwd_ping_nondp_intf)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int payload_len = 40;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	/* Add the route we want the packet to follow */
	dp_test_intf_nondp_create("nondp1");
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:nondp1");

	test_pak = dp_test_create_icmp_ipv4_pak("10.10.1.1",
						"10.73.2.1",
						ICMP_ECHO /* echo request */,
						0 /* no code */,
						DPT_ICMP_ECHO_DATA(0, 0),
						1 /* one mbuf */,
						&payload_len,
						NULL, NULL, NULL);

	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:nondp1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_intf_nondp_delete("nondp1");
} DP_END_TEST;

DP_START_TEST(ip_rx, lo_intf)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("lo", "2.2.2.2/24");

	/*
	 * Test 1 - send packet to loopback local address
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.2",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 2 - send packet to a connected address on the loopback
	 * interface
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.50",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("lo", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
} DP_END_TEST;

/*
 * Test pak sent to an interface using another interface's
 * address is received.
 */
DP_START_TEST(ip_rx, other_ifs_addr)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Create pak to match dp2T1's address added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "2.2.2.2",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

/*
 * Test pak sent to an interface without IP config
 * is received.
 */
DP_START_TEST(ip_rx, other_ifs_addr_this_no_ip)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up an interface */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Add a route / nh arp we don't want the packet to follow */
	dp_test_netlink_add_route("1.1.1.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	/* Create pak */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "1.1.1.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("1.1.1.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

DP_START_TEST(ip_rx, subnet_bcast)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", "1.1.1.1/24");

	/* First with L2 bcast - punted to slow path */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "1.1.1.255",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       "ff:ff:ff:ff:ff:ff",
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Then with L2 ucast - dropped */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "1.1.1.255",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_ip_address("dp1T0", "1.1.1.1/24");
} DP_END_TEST;

/*
 * Test various invalid packets that result in them being dropped on
 * ingress.
 */
DP_START_TEST(ip_rx, invalid_paks)
{
	struct rte_mbuf *good_pak, *test_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	struct iphdr *ip;
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/* IP route that our packet will match */
	dp_test_netlink_add_route("10.99.0.0/24 nh 5.0.0.2 int:dp2T2");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	good_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);
	(void)dp_test_pktmbuf_eth_init(good_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/*
	 * Test 1 - check that the payload packet without errors is
	 * forwarded OK (i.e. that we haven't cocked up any of the
	 * parameters above and that we're testing what we think we're
	 * testing).
	 */
	test_pak = dp_test_cp_pak(good_pak);

	exp = dp_test_exp_create(test_pak);
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_exp_set_oif_name(exp, "dp2T2");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 2 - truncate the packet so that it only includes 1
	 * byte of L3 and check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip = iphdr(test_pak);
	rte_pktmbuf_data_len(test_pak) = (char *)ip -
		rte_pktmbuf_mtod(test_pak, char *) + 1;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 3 - make the ip hdr len too small and check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip = iphdr(test_pak);
	ip->ihl = DP_TEST_PAK_DEFAULT_IHL - 1;
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 4 - make the checksum invalid and check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip = iphdr(test_pak);
	ip->check = 0xdead;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 5 - make the IP packet length too big and check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip = iphdr(test_pak);
	ip->tot_len = htons(2000);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 6 - make the IP packet length smaller than the header
	 * length and check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip = iphdr(test_pak);
	ip->tot_len = htons(sizeof(struct iphdr) - 1);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 7 - packet destined to loopback address - check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip = iphdr(test_pak);
	dp_test_fail_unless(inet_pton(AF_INET, "127.0.0.1", &ip->daddr) == 1,
			    "Couldn't parse ip address");
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 8 - packet with loopback source address - check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip = iphdr(test_pak);
	dp_test_fail_unless(inet_pton(AF_INET, "127.0.0.1", &ip->daddr) == 1,
			    "Couldn't parse ip address");
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 9 - IP unicast dest with L2 bcast dest - should be dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       "ff:ff:ff:ff:ff:ff",
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 10 - version not 4 - should be dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip = iphdr(test_pak);
	ip->version = 6;
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	rte_pktmbuf_free(good_pak);
	dp_test_netlink_del_neigh("dp2T2", "5.0.0.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_netlink_del_route("10.99.0.0/24 nh 5.0.0.2 int:dp2T2");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_suite, ip_fwd_basic, NULL, NULL);
DP_START_TEST(ip_fwd_basic, if_fwd_basic)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
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
	test_pak = dp_test_create_ipv4_pak("10.73.1.1", "10.73.2.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);


	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_suite, ip_fwd, NULL, NULL);
DP_START_TEST(ip_fwd, cover)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;
	const char *ip_src = "11.73.0.1";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

	dp_test_netlink_add_route("10.73.2.0/25 nh 2.2.2.1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_add_route("10.0.0.0/8 nh 3.3.3.1 int:dp3T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T1", "3.3.3.1", nh_mac_str);

	/* Test sending the packet via more specific prefix */
	test_pak = dp_test_create_ipv4_pak(ip_src, "10.73.2.0", 1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Now test sending the packet via less specific prefix */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.0.0.2",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp3T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Now delete more specific route and test it now follows less
	 * specific route
	 */
	dp_test_netlink_del_route("10.73.2.0/25 nh 2.2.2.1 int:dp2T1");

	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp3T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Now add a more specific route that is still covered by the
	 * /8 but is the other side of a boundary that might be
	 * interesting in the implementation.
	 */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");

	test_pak = dp_test_create_ipv4_pak(ip_src, "10.73.2.0", 1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp3T1", "3.3.3.1", nh_mac_str);
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.0.0.0/8 nh 3.3.3.1 int:dp3T1");
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
} DP_END_TEST;

struct dp_test_ip_frag {
	int num_segs;
	const int segs[6];
};

static struct dp_test_expected *
dp_test_frag_setup_exp(struct rte_mbuf **test_p, const char *nh_mac_str,
		       int num_segs, const int *seg_lens,
		       int num_frags, const struct dp_test_ip_frag *frag_lens)
{
	struct rte_mbuf *test_pak;
	struct dp_test_expected *exp;
	struct rte_mbuf *m;
	struct iphdr *ip;
	char data_val;
	char *data_ptr;
	int i, j;
	int hlen, foff;

	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   num_segs, seg_lens);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	/*
	 * Fragmentation happens as follows:
	 *
	 * ip .a. | ..b.. | ..c.. | ..d.. | ..e
	 *
	 * the fragments, in the order they are sent are:
	 * b, c, d, e, a
	 * where e is typically not a full mtu worth, and a..b are all
	 * mtu sized (or as close as possible given the multiple of 8 bytes
	 * that a fragment must be).
	 *
	 * The number of segments in the input/output mbufs should have no
	 * bearing on the contents of the fragments produced.
	 *
	 * Each fragment has the full ip header, including options, so the
	 * amount of data in the fragment is ((mtu - ip hdr size) / 8) * 8,
	 * and the expected fragment sizes are provided by the caller.
	 */

	ip = iphdr(test_pak);
	hlen = ip->ihl << 2;

	/*
	 * A 1500 byte packet going out a 1400 mtu would look like:
	 *  ip = 20  udp = 8  payload = 1472
	 * the frags are:
	 *  0  ip + 104 = 124   FO = 1376/8 = 172.
	 *  1  ip(20) + 1376 (udp hdr + udp data start) = 1396
	 */
	exp = dp_test_exp_create_m(NULL, num_frags);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	/*
	 * Segments of first fragment doesn't include udp header so
	 * add that first
	 */
	foff = sizeof(struct udphdr);
	for (i = 0; i < frag_lens[0].num_segs; i++)
		foff += frag_lens[0].segs[i];

	/* First pak out is the fragment with the end of the datagram */
	for (i = 0; i < num_frags - 1; i++) {
		m = dp_test_create_mbuf_chain(frag_lens[i + 1].num_segs,
					      frag_lens[i + 1].segs, 0);
		dp_test_pktmbuf_ip_init(m, "10.73.0.0", "10.73.2.0",
					IPPROTO_UDP);
		(void)dp_test_pktmbuf_eth_init(m, nh_mac_str,
					dp_test_intf_name2mac_str("dp1T1"),
					ETHER_TYPE_IPv4);
		ip = iphdr(m);
		dp_test_ipv4_decrement_ttl(m);

		if (i < num_frags - 2)
			dp_test_set_pak_ip_field(ip,
						 DP_TEST_SET_FRAG_MORE, 1);
		dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_OFFSET,
					 foff / 8);

		/* Payload is repeating pattern of incrementing bytes: 00 01 */
		data_ptr = (char *)(ip + 1);
		data_val = (foff - sizeof(struct udphdr)) % 256;
		/* assumes all in one segment */
		for (j = 0; j < (frag_lens[i + 1].segs[0] - hlen); j++) {
			*data_ptr = data_val++;
			data_ptr++;
		}
		dp_test_exp_set_pak_m(exp, i, m);

		foff += rte_pktmbuf_pkt_len(m) - dp_pktmbuf_l2_len(m) -
			dp_pktmbuf_l3_len(m);
	}

	/* And the last pak out has the start of the initial packet */
	m = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
				    frag_lens[0].num_segs,
				    frag_lens[0].segs);
	(void)dp_test_pktmbuf_eth_init(m, nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T1"),
				       ETHER_TYPE_IPv4);
	ip = iphdr(m);
	dp_test_ipv4_decrement_ttl(m);
	if (num_frags > 1)
		dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_MORE, 1);
	/* copy udp header from test_pak */
	memcpy(ip + 1, iphdr(test_pak) + 1, sizeof(struct udphdr));

	dp_test_exp_set_pak_m(exp, i, m);

	*test_p = test_pak;
	return exp;
}

DP_START_TEST_FULL_RUN(ip_fwd, fragment_smoke)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_netlink_set_interface_mtu("dp1T1", 1500);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	/*
	 * Test 1: single segment without fragmentation
	 */
	int len[] = { 1472 };
	const struct dp_test_ip_frag nofrag1500[] = {
		{ 1, {1472} },
	};
	exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
				     ARRAY_SIZE(len), len,
				     ARRAY_SIZE(nofrag1500), nofrag1500);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 2: single segment with fragmentation
	 */
	len[0] = 1572;
	const struct dp_test_ip_frag frag1600[] = {
		{ 1, {1472} },
		{ 1, {120} },
	};
	exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
				     ARRAY_SIZE(len), len,
				     ARRAY_SIZE(frag1600), frag1600);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(ip_fwd, fragment_boundary_values)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_netlink_set_interface_mtu("dp1T1", 1500);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	/*
	 * Test 1: MTU < minimal fragment size allowed (28 bytes)
	 */
	dp_test_netlink_set_interface_mtu("dp1T1", 23);
	int len[] = { 1472 };
	const struct dp_test_ip_frag nofrag1500[] = {
		{ 1, {1472} },
	};
	exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
				     ARRAY_SIZE(len), len,
				     ARRAY_SIZE(nofrag1500), nofrag1500);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 2: MTU >= minimal fragment size allowed (28 bytes)
	 *
	 * NOTE: The test framework doesn't allow zero payload packets.
	 *       Therefore the MTU of 36 is the lowest testable MTU.
	 */
	dp_test_netlink_set_interface_mtu("dp1T1", 36);
	len[0] = 48;
	const struct dp_test_ip_frag frag76[] = {
		{ 1, {8} },
		{ 1, {36} },
		{ 1, {36} },
		{ 1, {28} },
	};
	exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
				     ARRAY_SIZE(len), len,
				     ARRAY_SIZE(frag76), frag76);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 3: odd MTU settings (MTU - 20 mod 8 != 0)
	 *
	 * This tests that fragment sizes are always a multiple of 8
	 * (except for the last fragment) and therefore floored to the
	 * next multiple of 8.
	 */
	int i;
	for (i = 1 ; i < 8 ; ++i) {
		dp_test_netlink_set_interface_mtu("dp1T1", 36 + i);
		exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
					     ARRAY_SIZE(len), len,
					     ARRAY_SIZE(frag76), frag76);
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

	/*
	 * Test 4: last fragment sizes from 1 to MTU (includes sizes not
	 * divided by 8 and smaller than 8 bytes)
	 *
	 * NOTE: This test requires the MTU to be
	 *  mtu = 20 + (n * 8) , with n >= 2
	 */
	int mtu = 1004;
	dp_test_netlink_set_interface_mtu("dp1T1", mtu);
	for (i = 1; i <= mtu - 20; ++i) {
		const int segms[] = {
			mtu - 28,
			mtu - 20,
			mtu - 20,
			mtu - 20,
			i,
		};
		const struct dp_test_ip_frag frags[] = {
			{ 1, {mtu - 28} },
			{ 1, {mtu} },
			{ 1, {mtu} },
			{ 1, {mtu} },
			{ 1, {20 + i} },
		};
		exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
					     ARRAY_SIZE(segms), segms,
					     ARRAY_SIZE(frags), frags);
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(ip_fwd, fragment)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	const struct dp_test_ip_frag frag1400[] = {
		/* data is multiple of 8 bytes */
		{ 1, {1368} },
		{ 1, {124} },
	};
	const int len1500[] = {1472};
	const struct dp_test_ip_frag frag1600[] = {
		{ 1, {1472} },
		{ 1, {120} },
	};
	const int len9000[] = {1472, 1500, 1500, 1500, 1500, 1500};
	const struct dp_test_ip_frag frag9000[] = {
		{ 1, {1472} },
		{ 1, {1500} },
		{ 1, {1500} },
		{ 1, {1500} },
		{ 1, {1500} },
		{ 1, {1500} },
		{ 1, {120} },
	};
	const struct dp_test_ip_frag frag8000[] = {
		{ 6, {1472, 1500, 1500, 1500, 1500, 496} },
		{ 1, {1024} },
	};
	int i, j;
	int data_len;
	int mtu;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	mtu = 1400;
	dp_test_netlink_set_interface_mtu("dp1T1", mtu);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	/* Single segment coming in */
	exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
				     ARRAY_SIZE(len1500), len1500,
				     ARRAY_SIZE(frag1400), frag1400);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Spin through all valid segment sizes for the a 1500 byte
	 * packet, using only 2 segments.
	 * First segment must contain the full ip header.
	 */
	data_len = 1472;
	for (i = 0; i < data_len; i++) {
		int len2[] = {0, 0};

		len2[0] = i;
		len2[1] = data_len - i;
		exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
					     2, len2,
					     ARRAY_SIZE(frag1400),
					     frag1400);
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

	/* And now a lot of options with 3 segments */
	for (j = 100; j < data_len; j += 100) {
		for (i = 0; i < data_len - j; i += 10) {
			int len3[] = {0, 0, 0};

			len3[0] = j;
			len3[1] =  i;
			len3[2] = data_len - i - j;
			exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
						     3, len3,
						     ARRAY_SIZE(frag1400),
						     frag1400);
			dp_test_pak_receive(test_pak, "dp1T0", exp);
		}
	}

	/* Repeat for pkt size 1600, mtu 1500 */
	mtu = 1500;
	dp_test_netlink_set_interface_mtu("dp1T1", mtu);
	data_len = 1572;
	for (i = 0; i < data_len; i++) {
		int len2[] = {0, 0};

		len2[0] = i;
		len2[1] = data_len - i;
		exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
					     2, len2,
					     ARRAY_SIZE(frag1600),
					     frag1600);
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

	/* And now a lot of options with 3 segments */
	for (j = 100; j < data_len; j += 100) {
		for (i = 0; i < data_len - j; i += 10) {
			int len3[] = {0, 0, 0};

			len3[0] = j;
			len3[1] =  i;
			len3[2] = data_len - i - j;
			exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
						     3, len3,
						     ARRAY_SIZE(frag1600),
						     frag1600);
			dp_test_pak_receive(test_pak, "dp1T0", exp);
		}
	}

	/* Repeat for pkt size 9000, mtu 1500 */
	exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
				     ARRAY_SIZE(len9000), len9000,
				     ARRAY_SIZE(frag9000), frag9000);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Repeat for pkt size 9000, mtu 8000 */
	mtu = 8000;
	dp_test_netlink_set_interface_mtu("dp1T1", mtu);
	exp = dp_test_frag_setup_exp(&test_pak, nh_mac_str,
				     ARRAY_SIZE(len9000), len9000,
				     ARRAY_SIZE(frag8000), frag8000);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;

DP_START_TEST(ip_fwd, router_alert)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	struct iphdr *ip;
	const char *nh_mac_str;
	int len = 22 + 4;
	uint8_t *cp;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);
	ip = iphdr(test_pak);
	cp = (uint8_t *)(ip + 1);
	cp[IPOPT_OPTVAL] = IPOPT_RA;
	cp[IPOPT_OLEN] = 4;
	cp[IPOPT_OFFSET] = 0;
	cp[IPOPT_OFFSET + 1] = 0;
	ip->ihl = (sizeof(*ip) + 4) / 4;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
	test_pak->l3_len = sizeof(*ip) + 4;
	dp_test_pktmbuf_udp_init(test_pak, DP_TEST_PAK_DEFAULT_UDP_SRC_PORT,
				 DP_TEST_PAK_DEFAULT_UDP_DST_PORT, true);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

DP_START_TEST(ip_fwd, timestamp_opt)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	struct iphdr *ip;
	const char *nh_mac_str;
	int optlen = 12;
	int len = 22 + optlen;
	uint8_t *cp;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	/*
	 * Test 1 - timestamp and address successfully forwarded,
	 * packet unchanged as per RFC 7126 advice to either ignore or drop.
	 */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);
	ip = iphdr(test_pak);
	cp = (uint8_t *)(ip + 1);
	cp[IPOPT_OPTVAL] = IPOPT_TIMESTAMP;
	cp[IPOPT_OLEN] = optlen;
	cp[IPOPT_OFFSET] = 5;
	cp[IPOPT_OFFSET + 1] = IPOPT_TS_TSANDADDR;
	memset(&cp[IPOPT_OFFSET + 2], 0, optlen - (IPOPT_OFFSET + 1));
	ip->ihl = (sizeof(*ip) + optlen) / 4;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
	test_pak->l3_len = sizeof(*ip) + optlen;
	dp_test_pktmbuf_udp_init(test_pak, DP_TEST_PAK_DEFAULT_UDP_SRC_PORT,
				 DP_TEST_PAK_DEFAULT_UDP_DST_PORT, true);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);
	/*
	 * Test 2 - timestamp and address successfully forwarded,
	 * packet unchanged
	 */
	optlen = 20;
	len = 22 + optlen;
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);
	ip = iphdr(test_pak);
	cp = (uint8_t *)(ip + 1);
	cp[IPOPT_OPTVAL] = IPOPT_TIMESTAMP;
	cp[IPOPT_OLEN] = optlen;
	/*
	 * Pretend there is already one ts-and-addr there by setting
	 * the offset += 8
	 */
	cp[IPOPT_OFFSET] = 13;
	cp[IPOPT_OFFSET + 1] = IPOPT_TS_TSANDADDR;
	memset(&cp[IPOPT_OFFSET + 2], 0, optlen - (IPOPT_OFFSET + 1));
	ip->ihl = (sizeof(*ip) + optlen) / 4;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
	test_pak->l3_len = sizeof(*ip) + optlen;
	dp_test_pktmbuf_udp_init(test_pak, DP_TEST_PAK_DEFAULT_UDP_SRC_PORT,
				 DP_TEST_PAK_DEFAULT_UDP_DST_PORT, true);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 3 - timestamp and address out of space
	 */
	optlen = 12;
	len = 22 + optlen;
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);
	ip = iphdr(test_pak);
	cp = (uint8_t *)(ip + 1);
	cp[IPOPT_OPTVAL] = IPOPT_TIMESTAMP;
	cp[IPOPT_OLEN] = optlen;
	/*
	 * Pretend there is already one ts-and-addr there by setting
	 * the offset += 8
	 */
	cp[IPOPT_OFFSET] = 13;
	cp[IPOPT_OFFSET + 1] = IPOPT_TS_TSANDADDR;
	memset(&cp[IPOPT_OFFSET + 2], 0, optlen - (IPOPT_OFFSET + 1));
	ip->ihl = (sizeof(*ip) + 12) / 4;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
	test_pak->l3_len = sizeof(*ip) + optlen;
	dp_test_pktmbuf_udp_init(test_pak, DP_TEST_PAK_DEFAULT_UDP_SRC_PORT,
				 DP_TEST_PAK_DEFAULT_UDP_DST_PORT, true);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 4 - timestamp and prespecified address forwarded
	 */
	optlen = 12;
	len = 22 + optlen;
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);
	ip = iphdr(test_pak);
	cp = (uint8_t *)(ip + 1);
	cp[IPOPT_OPTVAL] = IPOPT_TIMESTAMP;
	cp[IPOPT_OLEN] = optlen;
	cp[IPOPT_OFFSET] = 5;
	cp[IPOPT_OFFSET + 1] = IPOPT_TS_PRESPEC;
	memset(&cp[IPOPT_OFFSET + 2], 0, optlen - (IPOPT_OFFSET + 1));
	/* 1.1.1.1 */
	*(in_addr_t *)&cp[IPOPT_OFFSET + 2] = htonl(0x01010101);
	ip->ihl = (sizeof(*ip) + optlen) / 4;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
	test_pak->l3_len = sizeof(*ip) + optlen;
	dp_test_pktmbuf_udp_init(test_pak, DP_TEST_PAK_DEFAULT_UDP_SRC_PORT,
				 DP_TEST_PAK_DEFAULT_UDP_DST_PORT, true);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 5 - timestamp and address destined to local address
	 */
	optlen = 12;
	len = 22 + optlen;
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "1.1.1.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);
	ip = iphdr(test_pak);
	cp = (uint8_t *)(ip + 1);
	cp[IPOPT_OPTVAL] = IPOPT_TIMESTAMP;
	cp[IPOPT_OLEN] = optlen;
	cp[IPOPT_OFFSET] = 5;
	cp[IPOPT_OFFSET + 1] = IPOPT_TS_TSANDADDR;
	memset(&cp[IPOPT_OFFSET + 2], 0, optlen - (IPOPT_OFFSET + 1));
	ip->ihl = (sizeof(*ip) + optlen) / 4;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
	test_pak->l3_len = sizeof(*ip) + optlen;
	dp_test_pktmbuf_udp_init(test_pak, DP_TEST_PAK_DEFAULT_UDP_SRC_PORT,
				 DP_TEST_PAK_DEFAULT_UDP_DST_PORT, true);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 6 - timestamp and prespecified address destined to local address
	 */
	optlen = 12;
	len = 22 + optlen;
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "1.1.1.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);
	ip = iphdr(test_pak);
	cp = (uint8_t *)(ip + 1);
	cp[IPOPT_OPTVAL] = IPOPT_TIMESTAMP;
	cp[IPOPT_OLEN] = optlen;
	cp[IPOPT_OFFSET] = 5;
	cp[IPOPT_OFFSET + 1] = IPOPT_TS_PRESPEC;
	memset(&cp[IPOPT_OFFSET + 2], 0, optlen - (IPOPT_OFFSET + 1));
	/* 1.1.1.1 */
	*(in_addr_t *)&cp[IPOPT_OFFSET + 2] = htonl(0x01010101);
	ip->ihl = (sizeof(*ip) + optlen) / 4;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
	test_pak->l3_len = sizeof(*ip) + optlen;
	dp_test_pktmbuf_udp_init(test_pak, DP_TEST_PAK_DEFAULT_UDP_SRC_PORT,
				 DP_TEST_PAK_DEFAULT_UDP_DST_PORT, true);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

DP_START_TEST(ip_fwd, multi_scope)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1;
	const char *nh_mac_str2;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str1);
	nh_mac_str2 = "11:22:33:44:55:66";
	dp_test_netlink_add_neigh("dp3T1", "3.3.3.1", nh_mac_str2);

	/*
	 * Test 1 - with only link-scope prefix added test that packet
	 * is forwarded accordingly.
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.1", 1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 2 - with both universe- and link-scoped information
	 * present for a prefix test that packet is forwarded using
	 * link-scoped forwarding information.
	 */
	dp_test_netlink_add_route("2.2.2.0/24 scope:0 nh 3.3.3.1 int:dp3T1");

	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.1", 1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 3 - remove link-scoped route to test that packet is
	 * forwarded using universe-scoped forwarding information.
	 */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str1);

	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.1", 1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp3T1"),
				       ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp3T1", "3.3.3.1", nh_mac_str2);
	dp_test_netlink_del_route("2.2.2.0/24 scope:0 nh 3.3.3.1 int:dp3T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_suite, ecmp, NULL, NULL);

DP_START_TEST(ecmp, ecmp)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1, *nh_mac_str2;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp4T3", "3.3.3.3/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route(
		"10.73.2.0/24 nh 2.2.2.1 int:dp3T2 nh 3.3.3.1 int:dp4T3");
	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T2", "2.2.2.1", nh_mac_str1);

	nh_mac_str2 = "11:22:33:44:55:66";
	dp_test_netlink_add_neigh("dp4T3", "3.3.3.1", nh_mac_str2);

	/*
	 * Create pak to match the route added above, with ports
	 * carefully chosen to take path through first path.
	 */
	test_pak = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
					       1001, 1003, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp3T2"),
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Create a second pak to match the route added above, with
	 * ports carefully chosen to take path through second path.
	 */
	test_pak = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
					       1112, 1010, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp4T3");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp4T3"),
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route(
		"10.73.2.0/24 nh 2.2.2.1 int:dp3T2 nh 3.3.3.1 int:dp4T3");
	dp_test_netlink_del_neigh("dp3T2", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp4T3", "3.3.3.1", nh_mac_str2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T3", "3.3.3.3/24");
} DP_END_TEST;

DP_START_TEST(ecmp, bad_l4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1, *nh_mac_str2;
	int len;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp4T3", "3.3.3.3/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route(
		"10.73.2.0/24 nh 2.2.2.1 int:dp3T2 nh 3.3.3.1 int:dp4T3");
	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T2", "2.2.2.1", nh_mac_str1);

	nh_mac_str2 = "11:22:33:44:55:66";
	dp_test_netlink_add_neigh("dp4T3", "3.3.3.1", nh_mac_str2);

	/*
	 * Test 1: UDP packet with no space for any part of UDP header.
	 */
	len = 0;
	test_pak = dp_test_create_raw_ipv4_pak("10.73.0.0", "10.73.2.0",
					       IPPROTO_UDP, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str1,
				 dp_test_intf_name2mac_str("dp3T2"),
				 ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 2: UDP packet with not enough space for UDP ports.
	 */
	len = 3;
	test_pak = dp_test_create_raw_ipv4_pak("10.73.0.0", "10.73.2.0",
					       IPPROTO_UDP, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str1,
				 dp_test_intf_name2mac_str("dp3T2"),
				 ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 3: TCP packet with no space for any part of TCP header.
	 */
	len = 0;
	test_pak = dp_test_create_raw_ipv4_pak("10.73.0.0", "10.73.2.0",
					       IPPROTO_TCP, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str1,
				 dp_test_intf_name2mac_str("dp3T2"),
				 ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 4: TCP packet with not enough space for TCP ports.
	 */
	len = 3;
	test_pak = dp_test_create_raw_ipv4_pak("10.73.0.0", "10.73.2.0",
					       IPPROTO_TCP, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str1,
				 dp_test_intf_name2mac_str("dp3T2"),
				 ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route(
		"10.73.2.0/24 nh 2.2.2.1 int:dp3T2 nh 3.3.3.1 int:dp4T3");
	dp_test_netlink_del_neigh("dp3T2", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp4T3", "3.3.3.1", nh_mac_str2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T3", "3.3.3.3/24");
} DP_END_TEST;

/*
 * IP forward ingressing into a virtual interface (vif)
 */
DP_DECL_TEST_CASE(ip_suite, vif_ingress, NULL, NULL);
DP_START_TEST(vif_ingress, vif_ingress)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Test setup */
	dp_test_intf_vif_create("dp1T3.100", "dp1T3", 100);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T3.100", "10.0.100.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.56.0.0/24 nh 2.2.2.1 int:dp3T3");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T3", "2.2.2.1", nh_mac_str);

	/*
	 * Create pak to match the route added above
	 */
	test_pak = dp_test_create_ipv4_pak("10.57.0.1", "10.56.0.1",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T3"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T3");

	/* Set the vlan in the test pak after we have created the exp pak */
	dp_test_pktmbuf_vlan_init(test_pak, 100);
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T3", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp3T3", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.56.0.0/24 nh 2.2.2.1 int:dp3T3");
	dp_test_nl_del_ip_addr_and_connected("dp1T3.100", "10.0.100.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "2.2.2.2/24");
	dp_test_intf_vif_del("dp1T3.100", 100);
} DP_END_TEST;

/*
 * IP forward egressing via a virtual interface (vif)
 */
DP_DECL_TEST_CASE(ip_suite, vif_egress, NULL, NULL);
DP_START_TEST(vif_egress, vif_egress)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Test setup */
	dp_test_intf_vif_create("dp3T3.100", "dp3T3", 100);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.100", "10.0.100.1/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.56.0.0/24 nh 10.0.100.2 int:dp3T3.100");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T3.100", "10.0.100.2", nh_mac_str);

	/*
	 * Create pak to match the route added above
	 */
	test_pak = dp_test_create_ipv4_pak("10.57.0.1", "10.56.0.1",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T3");
	dp_test_exp_set_vlan_tci(exp, 100);

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route("10.56.0.0/24 nh 10.0.100.2 int:dp3T3.100");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.100", "10.0.100.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_intf_vif_del("dp3T3.100", 100);
} DP_END_TEST;

/*
 * IP forward egressing via ecmp 2 x vif nh
 * ecmp hash setting should be ECMP_HASH_THRESHOLD
 */
DP_DECL_TEST_CASE(ip_suite, vif_ecmp2, NULL, NULL);
DP_START_TEST(vif_ecmp2, vif_ecmp2)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	const char *nh_mac_str[2] = {
		"aa:bb:cc:dd:ee:1",
		"aa:bb:cc:dd:ee:2",
	};

	/* Test setup */
	dp_test_intf_vif_create("dp3T3.100", "dp3T3", 100);
	dp_test_intf_vif_create("dp3T3.101", "dp3T3", 101);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.100", "10.0.100.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.101", "10.0.101.1/24");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route(
		"10.56.0.0/24 nh 10.0.100.2 int:dp3T3.100 nh 10.0.101.2 int:dp3T3.101");
	dp_test_netlink_add_neigh("dp3T3.100", "10.0.100.2", nh_mac_str[0]);
	dp_test_netlink_add_neigh("dp3T3.101", "10.0.101.2", nh_mac_str[1]);

	/*
	 * Create pak to match the 100 route added above
	 */
	test_pak = dp_test_create_ipv4_pak("10.57.0.1", "10.56.0.1",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* set udp ports to influence ecmp loadbalance choice */
	dp_test_pktmbuf_udp_init(test_pak, 1001, 2009, true); /* route 100 */

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T3");
	dp_test_exp_set_vlan_tci(exp, 100);

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str[0],
				       dp_test_intf_name2mac_str("dp3T3"),
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Create pak to match the 101 route added above
	 */
	test_pak = dp_test_create_ipv4_pak("10.57.0.1", "10.56.0.1",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	dp_test_pktmbuf_udp_init(test_pak, 1257, 1003, true); /* route 101 */

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T3");
	dp_test_exp_set_vlan_tci(exp, 101);

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str[1],
				       dp_test_intf_name2mac_str("dp3T3"),
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route(
		"10.56.0.0/24 nh 10.0.100.2 int:dp3T3.100 nh 10.0.101.2 int:dp3T3.101");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.100", "10.0.100.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.101", "10.0.101.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_intf_vif_del("dp3T3.100", 100);
	dp_test_intf_vif_del("dp3T3.101", 101);
} DP_END_TEST;

/*
 * Test that when we have an ecmp with 9 nh's, that when one nh is marked
 * RTF_DEAD because its associated vif interface is deleted, the 'extra'
 * nh is used.  We choose 8 as the dataplane is sent a max of 8 ecmp nh
 * per route.  When the vif interface is deleted, RIB will send a new
 * route update with the 8 active nhs.  The dead nh should be removed
 * rather than held ready for reuse.
 */
DP_DECL_TEST_CASE(ip_suite, vif_ecmp_intf_dead, NULL, NULL);
DP_START_TEST(vif_ecmp_intf_dead, vif_ecmp_intf_dead)
{
	const char *nh_mac_str[9] = {
		"aa:bb:cc:dd:ee:1",
		"aa:bb:cc:dd:ee:2",
		"aa:bb:cc:dd:ee:3",
		"aa:bb:cc:dd:ee:4",
		"aa:bb:cc:dd:ee:5",
		"aa:bb:cc:dd:ee:6",
		"aa:bb:cc:dd:ee:7",
		"aa:bb:cc:dd:ee:8",
		"aa:bb:cc:dd:ee:9",
	};

	/* Set up the ingress interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	/*
	 * Setup 9 vif subinterfaces
	 */
	dp_test_intf_vif_create("dp3T3.100", "dp3T3", 100);
	dp_test_intf_vif_create("dp3T3.101", "dp3T3", 101);
	dp_test_intf_vif_create("dp3T3.102", "dp3T3", 102);
	dp_test_intf_vif_create("dp3T3.103", "dp3T3", 103);
	dp_test_intf_vif_create("dp3T3.104", "dp3T3", 104);
	dp_test_intf_vif_create("dp3T3.105", "dp3T3", 105);
	dp_test_intf_vif_create("dp3T3.106", "dp3T3", 106);
	dp_test_intf_vif_create("dp3T3.107", "dp3T3", 107);
	dp_test_intf_vif_create("dp3T3.108", "dp3T3", 108);
	dp_test_nl_add_ip_addr_and_connected("dp3T3.100", "10.0.100.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.101", "10.0.101.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.102", "10.0.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.103", "10.0.103.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.104", "10.0.104.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.105", "10.0.105.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.106", "10.0.106.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.107", "10.0.107.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3.108", "10.0.108.1/24");

	/* Set up 9 nh arp entries */
	dp_test_netlink_add_neigh("dp3T3.100", "10.0.100.2", nh_mac_str[0]);
	dp_test_netlink_add_neigh("dp3T3.101", "10.0.101.2", nh_mac_str[1]);
	dp_test_netlink_add_neigh("dp3T3.102", "10.0.102.2", nh_mac_str[2]);
	dp_test_netlink_add_neigh("dp3T3.103", "10.0.103.2", nh_mac_str[3]);
	dp_test_netlink_add_neigh("dp3T3.104", "10.0.104.2", nh_mac_str[4]);
	dp_test_netlink_add_neigh("dp3T3.105", "10.0.105.2", nh_mac_str[5]);
	dp_test_netlink_add_neigh("dp3T3.106", "10.0.106.2", nh_mac_str[6]);
	dp_test_netlink_add_neigh("dp3T3.107", "10.0.107.2", nh_mac_str[7]);
	dp_test_netlink_add_neigh("dp3T3.108", "10.0.108.2", nh_mac_str[8]);

	/* Add one route via 8 ecmp nh's */
	dp_test_netlink_add_route(
		"10.56.0.0/24"
		" nh 10.0.100.2 int:dp3T3.100 nh 10.0.101.2 int:dp3T3.101"
		" nh 10.0.102.2 int:dp3T3.102 nh 10.0.103.2 int:dp3T3.103"
		" nh 10.0.104.2 int:dp3T3.104"
		" nh 10.0.105.2 int:dp3T3.105 nh 10.0.106.2 int:dp3T3.106"
		" nh 10.0.107.2 int:dp3T3.107");

	/* Delete vif 104 nh 10.0.104.2 and the entire route should go */
	/* TODO: _vif_del won't remove addr from local table so for
	   now do this first */
	dp_test_nl_del_ip_addr_and_connected("dp3T3.104", "10.0.104.1/24");
	dp_test_intf_vif_del("dp3T3.104", 104);

	/*
	 * Add same route via 8 ecmp nh's
	 * RIB will not advertise the one via nh 10.0.104.2 as its dead
	 * RIB will send 8, as long as it has 8 active.
	 * 10.0.108.2 should replace 10.0.104.2 in the dataplane, because
	 * the dataplane has deleted the entire route then added a 'new'
	 * one.
	 *
	 * Note on RIB/Kernel behaviour on interface delete.
	 * If an ip address is removed from an interface or if an interface
	 * goes down the kernel will mark the next hop dead.
	 * If an interface is deleted the kernel will delete all routes
	 * that have a next hop out of that interface.  Even though there
	 * may be other ECMP nh's, the entire route is removed.
	 * The 'new' route will then need to be signalled to the Kernel.
	 * After the interface delete has been sent to the Kernel, RIB
	 * will send the 'new' route with the NLM_F_CREATE and NLM_F_REPLACE
	 * flags set.  Since the Kernel no longer has this route it
	 * removes the NLM_F_REPLACE flag before sending on to the
	 * dataplane.  So the dataplane receives an _add_route not a
	 * _replace_route. - phew !
	 */
	dp_test_netlink_add_route(
		"10.56.0.0/24"
		" nh 10.0.100.2 int:dp3T3.100 nh 10.0.101.2 int:dp3T3.101"
		" nh 10.0.102.2 int:dp3T3.102 nh 10.0.103.2 int:dp3T3.103"
		" nh 10.0.108.2 int:dp3T3.108" /* 104 -> 108 */
		" nh 10.0.105.2 int:dp3T3.105 nh 10.0.106.2 int:dp3T3.106"
		" nh 10.0.107.2 int:dp3T3.107");

	/*
	 * Clean up
	 */
	dp_test_intf_vif_create("dp3T3.104", "dp3T3", 104);
	dp_test_intf_vif_del("dp3T3.104", 104);

	dp_test_nl_del_ip_addr_and_connected("dp3T3.100", "10.0.100.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.101", "10.0.101.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.102", "10.0.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.103", "10.0.103.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.105", "10.0.105.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.106", "10.0.106.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.107", "10.0.107.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3.108", "10.0.108.1/24");
	dp_test_intf_vif_del("dp3T3.100", 100);
	dp_test_intf_vif_del("dp3T3.101", 101);
	dp_test_intf_vif_del("dp3T3.102", 102);
	dp_test_intf_vif_del("dp3T3.103", 103);
	dp_test_intf_vif_del("dp3T3.105", 105);
	dp_test_intf_vif_del("dp3T3.106", 106);
	dp_test_intf_vif_del("dp3T3.107", 107);
	dp_test_intf_vif_del("dp3T3.108", 108);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
} DP_END_TEST;

/* Test IP primary address */
DP_DECL_TEST_CASE(ip_suite, ip_primary, NULL, NULL);
DP_START_TEST(ip_primary, ip_primary)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Primary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	/* Create pak to match primary address added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.1", "1.1.1.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
} DP_END_TEST;

/* Test IP secondary address */
DP_DECL_TEST_CASE(ip_suite, ip_secondary, NULL, NULL);
DP_START_TEST(ip_secondary, ip_secondary)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Primary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	/* Secondary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.2.2.2/24");

	/* Create pak to match secondary address added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.1", "2.2.2.2",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.2.2.2/24");
} DP_END_TEST;

/* Test IP tertiary address */
DP_DECL_TEST_CASE(ip_suite, ip_tertiary, NULL, NULL);
DP_START_TEST(ip_tertiary, ip_tertiary)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Primary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	/* Secondary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.2.2.2/24");

	/* Tertiary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "3.3.3.3/24");

	/* Create pak to match tertiary address added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.1", "3.3.3.3",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Delete the tertiary address and resend the packet
	 * We expect it to be dropped now
	 */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "3.3.3.3/24");
	test_pak = dp_test_create_ipv4_pak("10.73.0.1", "3.3.3.3",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.2.2.2/24");
} DP_END_TEST;


struct nh_info {
	const char *nh_addr;
	const char *nh_int;
	const char *nh_mac_str;
	bool unreach;
};

static void _build_and_send_pak(const char *src_addr, const char *dest_addr,
				struct nh_info nh, const char *func, int line)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	/* Test sending the packet via more specific prefix */
	test_pak = dp_test_create_ipv4_pak(src_addr, dest_addr,
					1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T3"),
				 NULL, ETHER_TYPE_IPv4);
	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	if (nh.unreach) {
		dp_test_exp_set_oif_name(exp, "dp1T3");
		dp_test_exp_set_check_len(exp, 0);
	} else {
		dp_test_exp_set_oif_name(exp, nh.nh_int);
		(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
					nh.nh_mac_str,
					dp_test_intf_name2mac_str(nh.nh_int),
					ETHER_TYPE_IPv4);
		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	}
	_dp_test_pak_receive(test_pak, "dp1T3", exp, __FILE__, func, line);
}

#define build_and_send_pak(src_addr, dest_addr, nh) \
	_build_and_send_pak(src_addr, dest_addr, nh, __func__, __LINE__)

#define SRC_ADDR "7.7.7.1"

#define NH1_0 "nh 1.1.1.1 int:dp1T1"
#define NH1_200 "nh 1.1.1.200 int:dp1T1"
#define NH1_254 "nh 1.1.1.254 int:dp1T1"

#define NH2_0 "nh 2.2.2.1 int:dp2T1"
#define NH2_200 "nh 2.2.2.200 int:dp2T1"
#define NH2_254 "nh 2.2.2.254 int:dp2T1"

#define NH4_0 "nh 4.4.4.1 int:dp4T1"
#define NH4_200 "nh 4.4.4.200 int:dp4T1"
#define NH4_254 "nh 4.4.4.254 int:dp4T1"

#define DEST_ROUTE_16_0 "3.3.0.0/16 scope:0"
#define DEST_ROUTE_16_200 "3.3.0.0/16 scope:200"
#define DEST_ROUTE_16_254 "3.3.0.0/16 scope:254"

#define DEST_ROUTE_24_0 "3.3.3.0/24 scope:0"
#define DEST_ROUTE_24_200 "3.3.3.0/24 scope:200"
#define DEST_ROUTE_24_254 "3.3.3.0/24 scope:254"

#define DEST_ROUTE_32_0 "3.3.3.3/32 scope:0"
#define DEST_ROUTE_32_200 "3.3.3.3/32 scope:200"
#define DEST_ROUTE_32_254 "3.3.3.3/32 scope:254"

#define DEST_16 "3.3.0.1"
#define DEST_24 "3.3.3.1"
#define DEST_32 "3.3.3.3"

/*
 * This test deals with adding/deleting routes from the LPM and
 * making sure that the packets are forwarded correctly when
 * we have a mix of scopes for the prefix, and a mix of covers.
 *
 * 3 scopes, 3 prefixes. try all variations.
 * Use macros due to the number of variations to code.
 *
 * Traffic arrives on interface dp1T3 which has the dest network as
 * 7.7.7/24. This is so that we can keep the  network 3.3...
 * as the one we inject  so that for the /24s we have more
 * entries in the lpm due to the connecteds, so test more.
 */
DP_DECL_TEST_CASE(ip_suite, ip_route_scopes_and_covers, NULL, NULL);
DP_START_TEST_FULL_RUN(ip_route_scopes_and_covers, ip_route_scopes_and_covers)
{
	struct nh_info nh1_0 = {.nh_mac_str = "11:11:11:11:11:0",
				.nh_addr = "1.1.1.1",
				.nh_int = "dp1T1"};
	struct nh_info nh1_200 = {.nh_mac_str = "11:11:11:11:11:20",
				  .nh_addr = "1.1.1.200",
				  .nh_int = "dp1T1"};
	struct nh_info nh1_254 = {.nh_mac_str = "11:11:11:11:11:25",
				  .nh_addr = "1.1.1.254",
				  .nh_int = "dp1T1"};
	struct nh_info nh2_0 = {.nh_mac_str = "22:22:22:22:22:0",
			      .nh_addr = "2.2.2.1",
			      .nh_int = "dp2T1"};
	struct nh_info nh2_200 = {.nh_mac_str = "22:22:22:22:22:20",
				  .nh_addr = "2.2.2.200",
				  .nh_int = "dp2T1"};
	struct nh_info nh2_254 = {.nh_mac_str = "22:22:22:22:22:25",
				  .nh_addr = "2.2.2.254",
				  .nh_int = "dp2T1"};
	struct nh_info nh4_0 = {.nh_mac_str = "44:44:44:44:44:0",
				.nh_addr = "4.4.4.1",
				.nh_int = "dp4T1"};
	struct nh_info nh4_200 = {.nh_mac_str = "44:44:44:44:44:20",
				  .nh_addr = "4.4.4.200",
				  .nh_int = "dp4T1"};
	struct nh_info nh4_254 = {.nh_mac_str = "44:44:44:44:44:25",
				  .nh_addr = "4.4.4.254",
				  .nh_int = "dp4T1"};
	struct nh_info nh_drop = {.unreach = true};
	/* this one is the src we send from */
	struct nh_info nh3 = {.nh_mac_str = "33:33:33:33:33:33",
			      .nh_addr = "7.7.7.1",
			      .nh_int = "dp1T3"};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T3", "7.7.7.7/24");
	dp_test_nl_add_ip_addr_and_connected("dp4T1", "4.4.4.4/24");

	dp_test_netlink_add_neigh(nh1_0.nh_int, nh1_0.nh_addr,
				  nh1_0.nh_mac_str);
	dp_test_netlink_add_neigh(nh1_200.nh_int, nh1_200.nh_addr,
				  nh1_200.nh_mac_str);
	dp_test_netlink_add_neigh(nh1_254.nh_int, nh1_254.nh_addr,
				  nh1_254.nh_mac_str);

	dp_test_netlink_add_neigh(nh2_0.nh_int, nh2_0.nh_addr,
				  nh2_0.nh_mac_str);
	dp_test_netlink_add_neigh(nh2_200.nh_int, nh2_200.nh_addr,
				  nh2_200.nh_mac_str);
	dp_test_netlink_add_neigh(nh2_254.nh_int, nh2_254.nh_addr,
				  nh2_254.nh_mac_str);

	dp_test_netlink_add_neigh(nh4_0.nh_int, nh4_0.nh_addr,
				  nh4_0.nh_mac_str);
	dp_test_netlink_add_neigh(nh4_200.nh_int, nh4_200.nh_addr,
				  nh4_200.nh_mac_str);
	dp_test_netlink_add_neigh(nh4_254.nh_int, nh4_254.nh_addr,
				  nh4_254.nh_mac_str);

	/* The src we send from */
	dp_test_netlink_add_neigh(nh3.nh_int, nh3.nh_addr, nh3.nh_mac_str);

	/* Send paks to all 3 destinations - no routes so drop */
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_24, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_32, nh_drop);

	/* add in all routes, and check forwarding. */
	dp_test_netlink_add_route(DEST_ROUTE_24_200 NH2_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_200);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2_200);

	dp_test_netlink_add_route(DEST_ROUTE_24_254 NH2_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2_254);

	dp_test_netlink_add_route(DEST_ROUTE_24_0 NH2_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2_254);

	dp_test_netlink_add_route(DEST_ROUTE_32_0 NH4_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_0);

	dp_test_netlink_add_route(DEST_ROUTE_32_200 NH4_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_200);

	dp_test_netlink_add_route(DEST_ROUTE_32_254 NH4_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);

	dp_test_netlink_add_route(DEST_ROUTE_16_0 NH1_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_0);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);

	dp_test_netlink_add_route(DEST_ROUTE_16_254 NH1_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);

	dp_test_netlink_add_route(DEST_ROUTE_16_200 NH1_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);

	/* Remove each route, test the forwarding then add it back. */
	dp_test_netlink_del_route(DEST_ROUTE_24_200 NH2_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);
	dp_test_netlink_add_route(DEST_ROUTE_24_200 NH2_200);

	dp_test_netlink_del_route(DEST_ROUTE_24_254 NH2_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_200);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);
	dp_test_netlink_add_route(DEST_ROUTE_24_254 NH2_254);

	dp_test_netlink_del_route(DEST_ROUTE_24_0 NH2_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);
	dp_test_netlink_add_route(DEST_ROUTE_24_0 NH2_0);

	dp_test_netlink_del_route(DEST_ROUTE_32_0 NH4_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);
	dp_test_netlink_add_route(DEST_ROUTE_32_0 NH4_0);

	dp_test_netlink_del_route(DEST_ROUTE_32_200 NH4_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);
	dp_test_netlink_add_route(DEST_ROUTE_32_200 NH4_200);

	dp_test_netlink_del_route(DEST_ROUTE_32_254 NH4_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_200);
	dp_test_netlink_add_route(DEST_ROUTE_32_254 NH4_254);

	dp_test_netlink_del_route(DEST_ROUTE_16_0 NH1_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);
	dp_test_netlink_add_route(DEST_ROUTE_16_0 NH1_0);

	dp_test_netlink_del_route(DEST_ROUTE_16_254 NH1_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_200);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);
	dp_test_netlink_add_route(DEST_ROUTE_16_254 NH1_254);

	dp_test_netlink_del_route(DEST_ROUTE_16_200 NH1_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_254);
	dp_test_netlink_add_route(DEST_ROUTE_16_200 NH1_200);

	/* Now delete starting from most specific and check forwarding */
	dp_test_netlink_del_route(DEST_ROUTE_32_254 NH4_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_200);

	dp_test_netlink_del_route(DEST_ROUTE_32_200 NH4_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4_0);

	dp_test_netlink_del_route(DEST_ROUTE_32_0 NH4_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2_254);

	dp_test_netlink_del_route(DEST_ROUTE_24_254 NH2_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_200);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2_200);

	dp_test_netlink_del_route(DEST_ROUTE_24_200 NH2_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2_0);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2_0);

	dp_test_netlink_del_route(DEST_ROUTE_24_0 NH2_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_24, nh1_254);
	build_and_send_pak(SRC_ADDR, DEST_32, nh1_254);

	dp_test_netlink_del_route(DEST_ROUTE_16_254 NH1_254);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_200);
	build_and_send_pak(SRC_ADDR, DEST_24, nh1_200);
	build_and_send_pak(SRC_ADDR, DEST_32, nh1_200);

	dp_test_netlink_del_route(DEST_ROUTE_16_200 NH1_200);
	build_and_send_pak(SRC_ADDR, DEST_16, nh1_0);
	build_and_send_pak(SRC_ADDR, DEST_24, nh1_0);
	build_and_send_pak(SRC_ADDR, DEST_32, nh1_0);

	dp_test_netlink_del_route(DEST_ROUTE_16_0 NH1_0);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_24, nh_drop);
	build_and_send_pak(SRC_ADDR, DEST_32, nh_drop);

	/*
	 * And tidy.
	 */
	dp_test_netlink_del_neigh(nh1_0.nh_int, nh1_0.nh_addr,
				  nh1_0.nh_mac_str);
	dp_test_netlink_del_neigh(nh1_200.nh_int, nh1_200.nh_addr,
				  nh1_200.nh_mac_str);
	dp_test_netlink_del_neigh(nh1_254.nh_int, nh1_254.nh_addr,
				  nh1_254.nh_mac_str);

	dp_test_netlink_del_neigh(nh2_0.nh_int, nh2_0.nh_addr,
				  nh2_0.nh_mac_str);
	dp_test_netlink_del_neigh(nh2_200.nh_int, nh2_200.nh_addr,
				  nh2_200.nh_mac_str);
	dp_test_netlink_del_neigh(nh2_254.nh_int, nh2_254.nh_addr,
				  nh2_254.nh_mac_str);

	dp_test_netlink_del_neigh(nh4_0.nh_int, nh4_0.nh_addr,
				  nh4_0.nh_mac_str);
	dp_test_netlink_del_neigh(nh4_200.nh_int, nh4_200.nh_addr,
				  nh4_200.nh_mac_str);
	dp_test_netlink_del_neigh(nh4_254.nh_int, nh4_254.nh_addr,
				  nh4_254.nh_mac_str);

	/* The src we send from */
	dp_test_netlink_del_neigh(nh3.nh_int, nh3.nh_addr, nh3.nh_mac_str);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "7.7.7.7/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T1", "4.4.4.4/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_suite, ip_default_route, NULL, NULL);
DP_START_TEST(ip_default_route, ip_default_route)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Add a default route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("0.0.0.0/0 nh 2.2.2.1 int:dp2T1");

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("10.73.1.1", "10.73.2.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);


	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("0.0.0.0/0 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

DP_START_TEST(ip_default_route, ip_default_route2)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:f1";

	dp_test_intf_vif_create("dp1T1.103", "dp1T1", 103);
	dp_test_nl_add_ip_addr_and_connected("dp1T1.103", "192.168.3.1/24");

	/*
	 * create a /32 then add a default route. The other 255 entries in the
	 * table8 are marked valid, with the NH of the default route.
	 * Delete the /32 and the entry should be marked invalid and the tbl8
	 * should then be marked invalid.
	 */
	dp_test_netlink_add_route("2.0.0.2/32 nh 192.168.3.2 int:dp1T1.103 ");
	dp_test_netlink_add_route("0.0.0.0/0 nh 192.168.3.2 int:dp1T1.103");
	dp_test_netlink_del_route("2.0.0.2/32 nh 192.168.3.2 int:dp1T1.103 ");
	dp_test_netlink_del_route("0.0.0.0/0 nh 192.168.3.2 int:dp1T1.103 ");

	/*
	 * Add a neighbour to verify that the old neigh is gone. If not gone
	 * then we end up with a crash due to null ptr deref.
	 */
	dp_test_netlink_add_neigh("dp1T1.103", "2.0.0.2", nh_mac_str1);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1.103", "192.168.3.1/24");
	dp_test_intf_vif_del("dp1T1.103", 103);

} DP_END_TEST;

