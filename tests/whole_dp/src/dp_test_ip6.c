/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * IPv6 tests
 */
#include "ip6_funcs.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"
#include "dp_test_cmd_state.h"

DP_DECL_TEST_SUITE(ip6_suite);

DP_DECL_TEST_CASE(ip6_suite, ip6_cfg, NULL, NULL);

/*
 * Check that we can add and delete routes via netlink and that the
 * show command output matches what we asked for.
 */
DP_START_TEST(ip6_cfg, route_add_del)
{
	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	/* Add a route and check it */
	dp_test_netlink_add_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");

	/* Now remove the route and check it has gone */
	dp_test_netlink_del_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
} DP_END_TEST;

/*
 * Verifying adding and deleting a scale of routes such that the LPM
 * grows
 */
DP_START_TEST(ip6_cfg, route_add_del_scale)
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
		 "route6 vrf_id %u summary", vrf_id);
	expected_json = dp_test_json_create(
		"{ \"route6_stats\":"
		"  {  "
		"     \"tbl8s\":"
		"       {"
		"         \"used\":"
		"           14,"
		"         \"free\":"
		"           242"
		"       },"
		"  },"
		"}");
	dp_test_check_json_state(summary_cmd, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected_json);

	/* not strictly necessary, but for real-world relevance */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100:61:2::2/64");

	/*
	 * Why 20? This happens to be big enough to grow the tbl8
	 * database with a little margin.
	 *
	 * We use a VRF to ensure a clean LPM state beforehand,
	 * i.e. to ensure the LPM is grown in this test.
	 */
	for (i = 0; i < 20; i++) {
		char route_str[sizeof(
				"vrf:50 ffff:1:1:1::1/128 nh 100:61:2::1 int:dp1T0")];

		dp_test_nl_add_route_fmt(
			true,
			"vrf:50 %x:1:1:1::1/128 nh 100:61:2::1 int:dp1T0", i);
		snprintf(route_str, sizeof(route_str),
			 "vrf:50 %x:1:1:1::1/128 nh 100:61:2::1 int:dp1T0", i);
		dp_test_wait_for_route_lookup(route_str, true);
	}

	for (i = 0; i < 20; i++)
		dp_test_nl_del_route_fmt(
			true,
			"vrf:50 %x:1:1:1::1/128 nh 100:61:2::1 int:dp1T0", i);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100:61:2::2/64");

	/* Now verify that we did indeed grow the LPM */
	expected_json = dp_test_json_create(
		"{ \"route6_stats\":"
		"  {  "
		"     \"tbl8s\":"
		"       {"
		"         \"used\":"
		"           14,"
		"         \"free\":"
		"           498"
		"       },"
		"  },"
		"}");
	dp_test_check_json_state(summary_cmd, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected_json);

	dp_test_netlink_del_vrf(50, 0);
} DP_END_TEST;

DP_DECL_TEST_CASE(ip6_suite, ip6_rx, NULL, NULL);

#define TEST_PREFIX1 "2001:1:1::"
#define TEST_PREFIX2 "2001:2:2::"

DP_START_TEST(ip6_rx, lo_intf)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	unsigned short i, pfxlens[] = {64, 128};
	char v6addr1[INET6_ADDRSTRLEN], v6addr2[INET6_ADDRSTRLEN];

	for (i = 0; i < sizeof(pfxlens)/sizeof(unsigned short); i++) {
		sprintf(v6addr1, TEST_PREFIX1 "1/%d", pfxlens[i]);
		sprintf(v6addr2, TEST_PREFIX2 "2/%d", pfxlens[i]);

		dp_test_nl_add_ip_addr_and_connected("dp1T0", v6addr1);
		dp_test_nl_add_ip_addr_and_connected("lo", v6addr2);

		/*
		 * Test 1 - send packet to loopback local address
		 */
		test_pak = dp_test_create_ipv6_pak(TEST_PREFIX1 "2",
						   TEST_PREFIX2 "2",
						   1, &len);
		(void)dp_test_pktmbuf_eth_init(
			test_pak, dp_test_intf_name2mac_str("dp1T0"),
			DP_TEST_INTF_DEF_SRC_MAC,
			RTE_ETHER_TYPE_IPV6);

		exp = dp_test_exp_create(test_pak);
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

		dp_test_pak_receive(test_pak, "dp1T0", exp);

		if (pfxlens[i] != 128) {
			/*
			 * Test 2 - send packet to a connected address on the
			 * loopback interface
			 */
			test_pak = dp_test_create_ipv6_pak(TEST_PREFIX2 "2",
					TEST_PREFIX2 "50", 1, &len);
			(void)dp_test_pktmbuf_eth_init(
				test_pak, dp_test_intf_name2mac_str("dp1T0"),
				DP_TEST_INTF_DEF_SRC_MAC,
				RTE_ETHER_TYPE_IPV6);

			exp = dp_test_exp_create(test_pak);
			dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

			dp_test_pak_receive(test_pak, "dp1T0", exp);
		}

		/* Clean Up */
		dp_test_nl_del_ip_addr_and_connected("lo", v6addr2);
		dp_test_nl_del_ip_addr_and_connected("dp1T0", v6addr1);
	}

} DP_END_TEST;

/*
 * Test pak sent to an interface using interface's
 * address is received.
 */
DP_START_TEST(ip6_rx, this_ifs_addr)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	/* Create pak to match dp1T0's address added above */
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2001:1:1::1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
} DP_END_TEST;

DP_START_TEST(ip6_rx, fwd_ping6_nondp_intf)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int payload_len = 40;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* Add the route we want the packet to follow */
	dp_test_intf_nondp_create("nondp1");
	dp_test_netlink_add_route("2010:73:2::/48 nh 2002:2:2::1 int:nondp1");

	test_pak = dp_test_create_icmp_ipv6_pak("1:1:1::1",
						"2010:73:2::2",
						ICMP6_ECHO_REQUEST,
						0 /* no code */,
						DPT_ICMP6_ECHO_DATA(0, 1),
						1 /* one mbuf */,
						&payload_len,
						NULL, NULL, NULL);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_route("2010:73:2::/48 nh 2002:2:2::1 int:nondp1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_intf_nondp_delete("nondp1");
} DP_END_TEST;

/*
 * Test various invalid packets that result in them being dropped on
 * ingress.
 */
DP_START_TEST(ip6_rx, invalid_paks)
{
	struct rte_mbuf *good_pak, *test_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	struct ip6_hdr *ip6;
	int len = 22;
	int newlen;

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2002:2:2::2/64");

	/* Add the nh neighbour we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "2002:2:2::1", nh_mac_str);

	/* Create ip packet to be payload */
	good_pak = dp_test_create_ipv6_pak("2001:1:1::1", "2002:2:2::1",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(good_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);

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
				       RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_exp_set_oif_name(exp, "dp2T2");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 2 - truncate the packet so that it only includes 1
	 * byte of L3 and check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	newlen = (char *)ip6 - rte_pktmbuf_mtod(test_pak, char *) + 1;
	rte_pktmbuf_trim(test_pak, test_pak->pkt_len - newlen);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 3 - make the IPv6 packet length too big and check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	ip6->ip6_plen = htons(2000);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 4 - packet destined to loopback address - check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	dp_test_fail_unless(inet_pton(AF_INET6, "::1", &ip6->ip6_dst) == 1,
			    "Couldn't parse ip address");

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 5 - packet destined to v4 mapped address - check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	dp_test_fail_unless(inet_pton(AF_INET6, "::ffff:192.168.0.1",
				      &ip6->ip6_dst) == 1,
			    "Couldn't parse ip address");

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 6 - packet with multicast dest address with scope of 1 -
	 * check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	dp_test_fail_unless(inet_pton(AF_INET6, "ff01:1:1::1",
				      &ip6->ip6_dst) == 1,
			    "Couldn't parse ip address");

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 7 - packet with loopback source address - check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	dp_test_fail_unless(inet_pton(AF_INET6, "::1", &ip6->ip6_src) == 1,
			    "Couldn't parse ip address");

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 8 - packet with multicast source address - check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	dp_test_fail_unless(inet_pton(AF_INET6, "ff02:1:1::1",
				      &ip6->ip6_src) == 1,
			    "Couldn't parse ip address");

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 9 - packet with v4 mapped source address - check it's dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	dp_test_fail_unless(inet_pton(AF_INET6, "::ffff:192.168.0.1",
				      &ip6->ip6_src) == 1,
			    "Couldn't parse ip address");

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 10 - version not 6 - should be dropped.
	 */
	test_pak = dp_test_cp_pak(good_pak);
	ip6 = ip6hdr(test_pak);
	ip6->ip6_vfc = (ip6->ip6_vfc & 0xf) | 0x40;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	rte_pktmbuf_free(good_pak);
	dp_test_netlink_del_neigh("dp2T2", "2002:2:2::1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip6_suite, ip6_fwd, NULL, NULL);
DP_START_TEST(ip6_fwd, basic)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV6);

	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", nh_mac_str);
	dp_test_netlink_del_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
} DP_END_TEST;

DP_START_TEST(ip6_fwd, bad_hbh)
{
	struct ip6_opt_router *opt_ra;
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *icmp_pak;
	const char *nh_mac_str1;
	const char *nh_mac_str2;
	struct ip6_hdr *ip6;
	struct ip6_hbh *hbh;
	struct ip6_opt *opt;
	int icmplen;
	int len;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_add_ip_address("dp1T0", "fe80::5054:ff:fe79:3f5/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", nh_mac_str1);
	nh_mac_str2 = "aa:bb:cc:ff:ee:dd";
	dp_test_netlink_add_neigh("dp1T0", "fe80::200:ff:fe00:100",
				  nh_mac_str2);

	/*
	 * Test 1 - hop-by-hop type, but insufficient data in packet
	 * for it
	 */
	len = sizeof(*hbh) - 1;
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 2 - hop-by-hop options with length exceeding packet length
	 */
	len = ((sizeof(*hbh) + sizeof(*opt_ra) + 7) & ~7) - 1;
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + sizeof(*opt_ra) + 7) / 8 - 1;
	opt_ra = (struct ip6_opt_router *)(hbh + 1);
	opt_ra->ip6or_type = IP6OPT_ROUTER_ALERT;
	opt_ra->ip6or_len = sizeof(*opt_ra) - sizeof(struct ip6_opt);
	opt_ra->ip6or_value[0] = ntohs(IP6_ALERT_RSVP) >> 8;
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 3 - hop-by-hop options with option length exceeding
	 * hbh header length
	 */
	len = sizeof(*hbh) + sizeof(*opt) + 6;
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + sizeof(*opt) + 7 + 7) / 8 - 1;
	opt = (struct ip6_opt *)(hbh + 1);
	opt->ip6o_type = IP6OPT_PADN;
	opt->ip6o_len = 7;
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 4 - insufficient space for padn header
	 */
	len = (sizeof(*hbh) + sizeof(*opt) + 3 + 7) & ~7;
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + sizeof(*opt) + 3 + 7) / 8 - 1;
	opt = (struct ip6_opt *)(hbh + 1);
	opt->ip6o_type = IP6OPT_PADN;
	opt->ip6o_len = 3;
	opt = (struct ip6_opt *)((uint8_t *)opt + 5);
	opt->ip6o_type = IP6OPT_PADN;
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 5 - padn length too large
	 */
	len = (sizeof(*hbh) + sizeof(*opt) + 4 + 7) & ~7;
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + sizeof(*opt) + 4 + 7) / 8 - 1;
	opt = (struct ip6_opt *)(hbh + 1);
	opt->ip6o_type = IP6OPT_PADN;
	opt->ip6o_len = 5;
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 6 - router alert not size of router alert option
	 */
	len = (sizeof(*hbh) + sizeof(*opt_ra) + 7) & ~7;
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + sizeof(*opt_ra) + 7) / 8 - 1;
	opt = (struct ip6_opt *)(hbh + 1);
	opt->ip6o_type = IP6OPT_ROUTER_ALERT;
	opt->ip6o_len = (hbh->ip6h_len + 1) * 8 - sizeof(*hbh);
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 7 - unknown option with ICMP bit set, destined to LL address
	 */
	len = (sizeof(*hbh) + sizeof(*opt) + 7) & ~7;
	test_pak = dp_test_create_ipv6_pak("fe80::200:ff:fe00:100",
					   "fe80::5054:ff:fe79:3f5",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 nh_mac_str2, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + sizeof(*opt) + 7) / 8 - 1;
	opt = (struct ip6_opt *)(hbh + 1);
	opt->ip6o_type = 135;
	opt->ip6o_len = (hbh->ip6h_len + 1) * 8 - sizeof(*hbh) - sizeof(*opt);
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	icmplen = sizeof(struct ip6_hdr) + len;
	icmp_pak = dp_test_create_icmp_ipv6_pak("fe80::5054:ff:fe79:3f5",
						"fe80::200:ff:fe00:100",
						ICMP6_PARAM_PROB,
						ICMP6_PARAMPROB_OPTION,
						42, /* pptr */
						1, &icmplen,
						ip6hdr(test_pak),
						NULL, NULL);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp1T0", exp);


	/*
	 * Test 8 - unknown option with ICMP bit set, destined to LL
	 * mcast address
	 */
	len = (sizeof(*hbh) + sizeof(*opt) + 7) & ~7;
	test_pak = dp_test_create_ipv6_pak("fe80::200:ff:fe00:100",
					   "ff02::1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 nh_mac_str2, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + sizeof(*opt) + 7) / 8 - 1;
	opt = (struct ip6_opt *)(hbh + 1);
	opt->ip6o_type = 135;
	opt->ip6o_len = (hbh->ip6h_len + 1) * 8 - sizeof(*hbh) - sizeof(*opt);
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	icmplen = sizeof(struct ip6_hdr) + len;
	icmp_pak = dp_test_create_icmp_ipv6_pak("fe80::5054:ff:fe79:3f5",
						"fe80::200:ff:fe00:100",
						ICMP6_PARAM_PROB,
						ICMP6_PARAMPROB_OPTION,
						42,  /* pptr */
						1, &icmplen,
						ip6hdr(test_pak),
						NULL, NULL);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T0", "fe80::200:ff:fe00:100",
				  nh_mac_str2);
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", nh_mac_str1);
	dp_test_netlink_del_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", "fe80::5054:ff:fe79:3f5/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
} DP_END_TEST;

DP_START_TEST(ip6_fwd, router_alert)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	struct ip6_hdr *ip6;
	struct ip6_hbh *hbh;
	struct ip6_opt *opt;
	struct ip6_opt_router *opt_ra;
	const char *nh_mac_str;
	int len;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", nh_mac_str);

	/*
	 * Packet with router alert option should be punted to slowpath.
	 */
	len = 22 + ((sizeof(*hbh) + sizeof(*opt_ra) + 7) & ~7);
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + sizeof(*opt_ra) + 7) / 8 - 1;
	opt_ra = (struct ip6_opt_router *)(hbh + 1);
	opt_ra->ip6or_type = IP6OPT_ROUTER_ALERT;
	opt_ra->ip6or_len = sizeof(*opt_ra) - sizeof(struct ip6_opt);
	opt_ra->ip6or_value[0] = ntohs(IP6_ALERT_RSVP) >> 8;
	opt_ra->ip6or_value[1] = ntohs(IP6_ALERT_RSVP) & ((1 << 8) - 1);
	/* fill out rest with padding */
	opt = (struct ip6_opt *)(opt_ra + 1);
	opt->ip6o_type = IP6OPT_PADN;
	opt->ip6o_len = (hbh->ip6h_len + 1) * 8 - sizeof(*hbh) -
		sizeof(*opt_ra) - 2;
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Packet with router alert option prepended with pad1 option
	 * should also be punted to slowpath.
	 */
	len = 22 + ((sizeof(*hbh) + 1 + sizeof(*opt_ra) + 7) & ~7);
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);
	ip6 = ip6hdr(test_pak);
	ip6->ip6_nxt = IPPROTO_HOPOPTS;
	hbh = (struct ip6_hbh *)(ip6 + 1);
	hbh->ip6h_nxt = ip6->ip6_nxt;
	hbh->ip6h_len = (sizeof(*hbh) + 1 + sizeof(*opt_ra) + 7) / 8 - 1;
	opt = (struct ip6_opt *)(hbh + 1);
	opt->ip6o_type = IP6OPT_PAD1;
	opt_ra = (struct ip6_opt_router *)((uint8_t *)opt + 1);
	opt_ra->ip6or_type = IP6OPT_ROUTER_ALERT;
	opt_ra->ip6or_len = sizeof(*opt_ra) - sizeof(struct ip6_opt);
	opt_ra->ip6or_value[0] = ntohs(IP6_ALERT_RSVP) >> 8;
	opt_ra->ip6or_value[1] = ntohs(IP6_ALERT_RSVP) & ((1 << 8) - 1);
	/* fill out rest with padding */
	opt = (struct ip6_opt *)(opt_ra + 1);
	dp_test_fail_unless((hbh->ip6h_len + 1) * 8 - sizeof(*hbh) - 1 -
			    sizeof(*opt_ra) == 1,
			    "expected length of remaining data to be 1, but is %ld",
			    (hbh->ip6h_len + 1) * 8 - sizeof(*hbh) - 1 -
			    sizeof(*opt_ra));
	opt->ip6o_type = IP6OPT_PAD1;
	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", nh_mac_str);
	dp_test_netlink_del_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
} DP_END_TEST;

DP_START_TEST(ip6_fwd, multi_scope)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1;
	const char *nh_mac_str2;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "2003:3:3::3/64");

	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", nh_mac_str1);
	nh_mac_str2 = "11:22:33:44:55:66";
	dp_test_netlink_add_neigh("dp3T1", "2003:3:3::1", nh_mac_str2);

	/*
	 * Test 1 - with only link-scope prefix added test that packet
	 * is forwarded accordingly.
	 */
	test_pak = dp_test_create_ipv6_pak("2001:1:1::2", "2002:2:2::1", 1,
					   &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 2 - with both universe- and link-scoped information
	 * present for a prefix test that packet is forwarded using
	 * link-scoped forwarding information.
	 */
	dp_test_netlink_add_route(
		"2002:2:2::/64 scope:0 nh 2003:3:3::1 int:dp3T1");

	test_pak = dp_test_create_ipv6_pak("2001:1:1::2", "2002:2:2::1", 1,
					   &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 3 - remove link-scoped route to test that packet is
	 * forwarded using universe-scoped forwarding information.
	 */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", nh_mac_str1);

	test_pak = dp_test_create_ipv6_pak("2001:1:1::2", "2002:2:2::1", 1,
					   &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC, RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp3T1"),
				       RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp3T1", "2003:3:3::1", nh_mac_str2);
	dp_test_netlink_del_route(
		"2002:2:2::/64 scope:0 nh 2003:3:3::1 int:dp3T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "2003:3:3::3/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip6_suite, ecmp6, NULL, NULL);

DP_START_TEST(ecmp6, ecmp)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1, *nh_mac_str2;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp4T3", "2003:3:3::3/64");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route(
		"2010:73:2::/64 "
		"nh 2002:2:2::1 int:dp3T2 "
		"nh 2003:3:3::1 int:dp4T3");
	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T2", "2002:2:2::1", nh_mac_str1);

	nh_mac_str2 = "11:22:33:44:55:66";
	dp_test_netlink_add_neigh("dp4T3", "2003:3:3::1", nh_mac_str2);

	/*
	 * Create pak to match the route added above, with ports
	 * carefully chosen to take path through first path.
	 */
	test_pak = dp_test_create_udp_ipv6_pak("2010:73::", "2010:73:2::",
					       1001, 1002, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp4T3");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp4T3"),
				       RTE_ETHER_TYPE_IPV6);

	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Create a second pak to match the route added above, with
	 * ports carefully chosen to take path through second path.
	 */
	test_pak = dp_test_create_udp_ipv6_pak("2010:73::", "2010:73:2::",
					       1111, 1005, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T2");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp3T2"),
				       RTE_ETHER_TYPE_IPV6);

	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route(
		"2010:73:2::/64 "
		"nh 2002:2:2::1 int:dp3T2 "
		"nh 2003:3:3::1 int:dp4T3");
	dp_test_netlink_del_neigh("dp3T2", "2002:2:2::1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp4T3", "2003:3:3::1", nh_mac_str2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp4T3", "2003:3:3::3/64");
} DP_END_TEST;


DP_START_TEST(ecmp6, ecmp2)
{
	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp4T3", "2003:3:3::3/64");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route(
		"2010:73:2::/64 "
		"nh 2002:2:2::1 int:dp3T2 ");

	/* Add a 2nd path */
	dp_test_netlink_add_route_nv(
		"2010:73:2::/64 "
		"nh 2002:2:2::1 int:dp3T2 "
		"nh 2003:3:3::1 int:dp4T3");

	dp_test_verify_add_route("2010:73:2::/64 "
				 "nh 2002:2:2::1 int:dp3T2 "
				 "nh 2003:3:3::1 int:dp4T3", true);


	/* Add a 3rd path */
	dp_test_netlink_add_route_nv("2010:73:2::/64 "
				     "nh 2002:1:1::1 int:dp1T1 "
				     "nh 2002:2:2::1 int:dp3T2 "
				     "nh 2003:3:3::1 int:dp4T3");

	dp_test_verify_add_route("2010:73:2::/64 "
				 "nh 2002:1:1::1 int:dp1T1 "
				 "nh 2002:2:2::1 int:dp3T2 "
				 "nh 2003:3:3::1 int:dp4T3", true);

	/* Drop back to 1 path */
	dp_test_netlink_replace_route("2010:73:2::/64 "
				      "nh 2002:1:1::1 int:dp1T1 ");

	/* Clean Up */
	dp_test_netlink_del_route(
		"2010:73:2::/64 "
		"nh 2002:1:1::1 int:dp1T1 ");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp4T3", "2003:3:3::3/64");
} DP_END_TEST;


DP_START_TEST(ecmp6, bad_l4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1, *nh_mac_str2;
	int len;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp4T3", "2003:3:3::3/64");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route(
		"2010:73:2::/64 "
		"nh 2002:2:2::1 int:dp3T2 "
		"nh 2003:3:3::1 int:dp4T3");
	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T2", "2002:2:2::1", nh_mac_str1);

	nh_mac_str2 = "11:22:33:44:55:66";
	dp_test_netlink_add_neigh("dp4T3", "2003:3:3::1", nh_mac_str2);

	/*
	 * Test 1: UDP packet with no space for any part of UDP header.
	 */
	len = 0;
	test_pak = dp_test_create_raw_ipv6_pak("2010:73:5::", "2010:73:2::",
					       IPPROTO_UDP, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp4T3");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str2,
				 dp_test_intf_name2mac_str("dp4T3"),
				 RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 2: UDP packet with not enough space for UDP ports.
	 */
	len = 3;
	test_pak = dp_test_create_raw_ipv6_pak("2010:73:5::", "2010:73:2::",
					       IPPROTO_UDP, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp4T3");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str2,
				 dp_test_intf_name2mac_str("dp4T3"),
				 RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 3: TCP packet with no space for any part of UDP header.
	 */
	len = 0;
	test_pak = dp_test_create_raw_ipv6_pak("2010:73::", "2010:73:2::",
					       IPPROTO_TCP, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp4T3");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str2,
				 dp_test_intf_name2mac_str("dp4T3"),
				 RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 4: TCP packet with not enough space for TCP ports.
	 */
	len = 3;
	test_pak = dp_test_create_raw_ipv6_pak("2010:73::", "2010:73:2::",
					       IPPROTO_TCP, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp4T3");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str2,
				 dp_test_intf_name2mac_str("dp4T3"),
				 RTE_ETHER_TYPE_IPV6);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route(
		"2010:73:2::/64 "
		"nh 2002:2:2::1 int:dp3T2 "
		"nh 2003:3:3::1 int:dp4T3");
	dp_test_netlink_del_neigh("dp3T2", "2002:2:2::1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp4T3", "2003:3:3::1", nh_mac_str2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp4T3", "2003:3:3::3/64");
} DP_END_TEST;

/* Test IPv6 primary address */
DP_DECL_TEST_CASE(ip6_suite, ip6_primary, NULL, NULL);
DP_START_TEST(ip6_primary, ip6_primary)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Primary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* Create pak to match primary address added above */
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2001:1:1::1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
} DP_END_TEST;

/* Test IPv6 secondary address */
DP_DECL_TEST_CASE(ip6_suite, ip6_secondary, NULL, NULL);
DP_START_TEST(ip6_secondary, ip6_secondary)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Primary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* Secondary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:2:2::2/64");

	/* Create pak to match secondary address added above */
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2001:2:2::2",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:2:2::2/64");
} DP_END_TEST;

/* Test IPv6 tertiary address */
DP_DECL_TEST_CASE(ip6_suite, ip6_tertiary, NULL, NULL);
DP_START_TEST(ip6_tertiary, ip6_tertiary)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Primary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* Secondary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:2:2::2/64");

	/* Tertiary interface address */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:3:3::3/64");

	/* Create pak to match secondary address added above */
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2001:3:3::3",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Delete the tertiary address and resend the packet
	 * We expect it to be dropped now
	 */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:3:3::3/64");
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2001:3:3::3",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       NULL, RTE_ETHER_TYPE_IPV6);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:2:2::2/64");
} DP_END_TEST;

/*
 * Test multiple NHs over non dataplane interfaces with IPv6.
 * Have to use manual verification of the routes due to the
 * adding and removing of individual NHs.
 *
 * Note that as non dataplane interfaces are shown as
 * 'non-dataplane-interface' the verification would match the
 * wrong non dp interfaces too, but will check the number of them
 * is correct.
 */
DP_DECL_TEST_CASE(ip6_suite, ip6_loopback, NULL, NULL);
DP_START_TEST(ip6_loopback, ip6_loopback)
{
	dp_test_netlink_add_route("ab00::/8 "
				  "nh int:dp1T0 "
				  "nh int:dp1T1");

	/* Add lo1 */
	dp_test_intf_loopback_create("lo1");
	dp_test_netlink_add_route_nv("ab00::/8 "
				     "nh int:dp1T0 "
				     "nh int:dp1T1 "
				     "nh int:lo1");
	dp_test_wait_for_route("ab00::/8 "
			       "nh int:dp1T0 "
			       "nh int:dp1T1 "
			       "nh int:lo1 ", true);

	/* Add lo3 */
	dp_test_intf_loopback_create("lo3");
	dp_test_netlink_add_route_nv("ab00::/8 "
				     "nh int:dp1T0 "
				     "nh int:dp1T1 "
				     "nh int:lo1 "
				     "nh int:lo3");
	dp_test_wait_for_route("ab00::/8 "
			       "nh int:dp1T0 "
			       "nh int:dp1T1 "
			       "nh int:lo1 "
			       "nh int:lo3 ", true);

	/* Del lo3 */
	dp_test_netlink_replace_route("ab00::/8 "
				      "nh int:dp1T0 "
				      "nh int:dp1T1 "
				      "nh int:lo1 ");
	dp_test_intf_loopback_delete("lo3");

	/* Add lo2 */
	dp_test_intf_loopback_create("lo2");
	dp_test_netlink_add_route_nv("ab00::/8 "
				     "nh int:dp1T0 "
				     "nh int:dp1T1 "
				     "nh int:lo1 "
				     "nh int:lo2");
	dp_test_wait_for_route("ab00::/8 "
			       "nh int:dp1T0 "
			       "nh int:dp1T1 "
			       "nh int:lo1 "
			       "nh int:lo2 ", true);

	/* del lo1 */
	dp_test_netlink_replace_route("ab00::/8 "
				      "nh int:dp1T0 "
				      "nh int:dp1T1 "
				      "nh int:lo2 ");
	dp_test_intf_loopback_delete("lo1");

	/* del lo2 */
	dp_test_netlink_replace_route("ab00::/8 "
				      "nh int:dp1T0 "
				      "nh int:dp1T1 ");

	dp_test_intf_loopback_delete("lo2");

	dp_test_netlink_del_route("ab00::/8 "
				  "nh int:dp1T0 "
				  "nh int:dp1T1");
} DP_END_TEST;

struct nh_info {
	const char *nh_addr;
	const char *nh_int;
	const char *nh_mac_str;
	bool drop;
};


#define SRC_MAC_STR "11:11:11:11:11:11"

#define build_and_send_pak(src_addr, dest_addr, nh)                            \
{                                                                              \
	struct dp_test_expected *exp;                                          \
	struct rte_mbuf *test_pak;                                             \
	int len = 22;                                                          \
	/* Test sending the packet via more specific prefix */                 \
	test_pak = dp_test_create_ipv6_pak(src_addr, dest_addr,                \
					1, &len);                              \
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"), \
				 SRC_MAC_STR, RTE_ETHER_TYPE_IPV6);            \
	/* Create pak we expect to receive on the tx ring */                   \
	exp = dp_test_exp_create(test_pak);				       \
	if ((nh).drop) {						       \
		/* Is dropped, but we send an icmp unreachable */              \
		dp_test_exp_set_oif_name(exp, "dp1T0");		               \
		dp_test_exp_set_check_len(exp, 0);                             \
	} else {                                                               \
		dp_test_exp_set_oif_name(exp, (nh).nh_int);		       \
		(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),       \
					       (nh).nh_mac_str,		       \
				       dp_test_intf_name2mac_str((nh).nh_int), \
					RTE_ETHER_TYPE_IPV6);		       \
		dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));	       \
	}                                                                      \
	dp_test_pak_receive(test_pak, "dp1T0", exp);                           \
}

#define SRC_ADDR "2001:1:1::2"

#define NH2 "nh 2002:2:2::1 int:dp2T1"
#define NH3 "nh 2003:3:3::1 int:dp3T1"
#define NH4 "nh 2004:4:4::1 int:dp4T1"

#define DEST_ROUTE_8 "7700::/8 "
#define DEST_ROUTE_16 "7777::/16 "
#define DEST_ROUTE_24 "7777:7700::/24 "

#define DEST_ROUTE_28 "7777:7770::/28 "
#define DEST_ROUTE_30 "7777:7774::/30 "
#define DEST_ROUTE_32 "7777:7777::/32 "

#define DEST_ROUTE_40 "7777:7777:7700::/40 "

#define DEST_ROUTE_44 "7777:7777:7770::/44 "
#define DEST_ROUTE_46 "7777:7777:7774::/46 "
#define DEST_ROUTE_48 "7777:7777:7777::/48 "

#define DEST_ROUTE_56 "7777:7777:7777:7700::/56 "
#define DEST_ROUTE_64 "7777:7777:7777:7777::/64 "


#define DEST_8 "7700::1"
#define DEST_16 "7777::1"

#define DEST_24 "7777:7700::1"

#define DEST_28 "7777:7770::1"
#define DEST_30 "7777:7774::1"
#define DEST_32 "7777:7777::1"

#define DEST_40 "7777:7777:7700::1"

#define DEST_44 "7777:7777:7770::1"
#define DEST_46 "7777:7777:7774::1"
#define DEST_48 "7777:7777:7777::1"

#define DEST_56 "7777:7777:7777:7700::1"
#define DEST_64 "7777:7777:7777:7777::1"

/*
 * This test case deals with deleting routes from the lpm6 and
 * verifying that the correct stuff is done.
 * Due to the number of tests (based on knowledge of the implementation)
 * a macro is used to build/send/verify packets to keep the size of
 * the tests easily manageable.
 */
DP_DECL_TEST_CASE(ip6_suite, ip6_route_cover, NULL, NULL);
DP_START_TEST(ip6_route_cover, ip6_route_cover)
{
	struct nh_info nh2 = {.nh_mac_str = "22:22:22:22:22:22",
			      .nh_addr = "2002:2:2::1",
			      .nh_int = "dp2T1"};
	struct nh_info nh3 = {.nh_mac_str = "33:33:33:33:33:33",
			      .nh_addr = "2003:3:3::1",
			      .nh_int = "dp3T1"};
	struct nh_info nh4 = {.nh_mac_str = "44:44:44:44:44:44",
			      .nh_addr = "2004:4:4::1",
			      .nh_int = "dp4T1"};
	struct nh_info nh_drop = {.drop = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "2003:3:3::3/64");
	dp_test_nl_add_ip_addr_and_connected("dp4T1", "2004:4:4::4/64");

	dp_test_netlink_add_neigh("dp1T0", SRC_ADDR, SRC_MAC_STR);
	dp_test_netlink_add_neigh(nh2.nh_int, nh2.nh_addr, nh2.nh_mac_str);
	dp_test_netlink_add_neigh(nh3.nh_int, nh3.nh_addr, nh3.nh_mac_str);
	dp_test_netlink_add_neigh(nh4.nh_int, nh4.nh_addr, nh4.nh_mac_str);

	/*
	 * Start with tests that have 3 routes. Send packet to each of
	 * the 3 routes, then modify the set of the routes, and check the
	 * packet dest changes. Start with all routes in their own tbl8,
	 * with a tbl8 between each.
	 */
	dp_test_netlink_add_route(DEST_ROUTE_32 NH2);
	dp_test_netlink_add_route(DEST_ROUTE_40 NH3);
	dp_test_netlink_add_route(DEST_ROUTE_48 NH4);

	build_and_send_pak(SRC_ADDR, DEST_32, nh2);
	build_and_send_pak(SRC_ADDR, DEST_40, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_del_route(DEST_ROUTE_32 NH2);
	build_and_send_pak(SRC_ADDR, DEST_32, nh_drop)
	build_and_send_pak(SRC_ADDR, DEST_40, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_32 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_40 NH3);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2);
	build_and_send_pak(SRC_ADDR, DEST_40, nh2);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_40 NH3);
	dp_test_netlink_del_route(DEST_ROUTE_48 NH4);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2);
	build_and_send_pak(SRC_ADDR, DEST_40, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh3);

	dp_test_netlink_del_route(DEST_ROUTE_32 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_40 NH3);

	/* 3 different tbl8s, but with a furtehr tbl8 in between */
	dp_test_netlink_add_route(DEST_ROUTE_32 NH2);
	dp_test_netlink_add_route(DEST_ROUTE_48 NH3);
	dp_test_netlink_add_route(DEST_ROUTE_64 NH4);

	build_and_send_pak(SRC_ADDR, DEST_32, nh2);
	build_and_send_pak(SRC_ADDR, DEST_48, nh3);
	build_and_send_pak(SRC_ADDR, DEST_64, nh4);

	dp_test_netlink_del_route(DEST_ROUTE_32 NH2);
	build_and_send_pak(SRC_ADDR, DEST_32, nh_drop)
	build_and_send_pak(SRC_ADDR, DEST_48, nh3);
	build_and_send_pak(SRC_ADDR, DEST_64, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_32 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_48 NH3);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2);
	build_and_send_pak(SRC_ADDR, DEST_48, nh2);
	build_and_send_pak(SRC_ADDR, DEST_64, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_48 NH3);
	dp_test_netlink_del_route(DEST_ROUTE_64 NH4);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2);
	build_and_send_pak(SRC_ADDR, DEST_48, nh3);
	build_and_send_pak(SRC_ADDR, DEST_64, nh3);

	dp_test_netlink_del_route(DEST_ROUTE_32 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_48 NH3);

	/* All 3 within the same tbl8 */
	dp_test_netlink_add_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_add_route(DEST_ROUTE_30 NH3);
	dp_test_netlink_add_route(DEST_ROUTE_32 NH4);

	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_30, nh3);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4);

	dp_test_netlink_del_route(DEST_ROUTE_28 NH2);
	build_and_send_pak(SRC_ADDR, DEST_28, nh_drop)
	build_and_send_pak(SRC_ADDR, DEST_30, nh3);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_30 NH3);
	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_30, nh2);
	build_and_send_pak(SRC_ADDR, DEST_32, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_30 NH3);
	dp_test_netlink_del_route(DEST_ROUTE_32 NH4);
	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_30, nh3);
	build_and_send_pak(SRC_ADDR, DEST_32, nh3);

	dp_test_netlink_del_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_30 NH3);

	/* First 2 routes in same tbl8, 3rd route in its own. */
	dp_test_netlink_add_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_add_route(DEST_ROUTE_30 NH3);
	dp_test_netlink_add_route(DEST_ROUTE_48 NH4);

	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_30, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_del_route(DEST_ROUTE_28 NH2);
	build_and_send_pak(SRC_ADDR, DEST_28, nh_drop)
	build_and_send_pak(SRC_ADDR, DEST_30, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_30 NH3);
	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_30, nh2);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_30 NH3);
	dp_test_netlink_del_route(DEST_ROUTE_48 NH4);
	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_30, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh3);

	dp_test_netlink_del_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_30 NH3);

	/* First route in tbl8, 2nd and 3rd route in different tbl8. */
	dp_test_netlink_add_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_add_route(DEST_ROUTE_46 NH3);
	dp_test_netlink_add_route(DEST_ROUTE_48 NH4);

	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_46, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_del_route(DEST_ROUTE_28 NH2);
	build_and_send_pak(SRC_ADDR, DEST_28, nh_drop)
	build_and_send_pak(SRC_ADDR, DEST_46, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_46 NH3);
	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_46, nh2);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_46 NH3);
	dp_test_netlink_del_route(DEST_ROUTE_48 NH4);
	build_and_send_pak(SRC_ADDR, DEST_28, nh2);
	build_and_send_pak(SRC_ADDR, DEST_46, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh3);

	dp_test_netlink_del_route(DEST_ROUTE_28 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_46 NH3);

	/* First route in tbl24, other in further tbl8s*/
	dp_test_netlink_add_route(DEST_ROUTE_16 NH2);
	dp_test_netlink_add_route(DEST_ROUTE_32 NH3);
	dp_test_netlink_add_route(DEST_ROUTE_48 NH4);

	build_and_send_pak(SRC_ADDR, DEST_16, nh2);
	build_and_send_pak(SRC_ADDR, DEST_32, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_del_route(DEST_ROUTE_16 NH2);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop)
	build_and_send_pak(SRC_ADDR, DEST_32, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_16 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_32 NH3);
	build_and_send_pak(SRC_ADDR, DEST_16, nh2);
	build_and_send_pak(SRC_ADDR, DEST_32, nh2);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_32 NH3);
	dp_test_netlink_del_route(DEST_ROUTE_48 NH4);
	build_and_send_pak(SRC_ADDR, DEST_16, nh2);
	build_and_send_pak(SRC_ADDR, DEST_32, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh3);

	dp_test_netlink_del_route(DEST_ROUTE_16 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_32 NH3);

	/* First 2 in tbl24, 3rd in further tbl8 */
	dp_test_netlink_add_route(DEST_ROUTE_16 NH2);
	dp_test_netlink_add_route(DEST_ROUTE_24 NH3);
	dp_test_netlink_add_route(DEST_ROUTE_48 NH4);

	build_and_send_pak(SRC_ADDR, DEST_16, nh2);
	build_and_send_pak(SRC_ADDR, DEST_24, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_del_route(DEST_ROUTE_16 NH2);
	build_and_send_pak(SRC_ADDR, DEST_16, nh_drop)
	build_and_send_pak(SRC_ADDR, DEST_24, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_16 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_24 NH3);
	build_and_send_pak(SRC_ADDR, DEST_16, nh2);
	build_and_send_pak(SRC_ADDR, DEST_24, nh2);
	build_and_send_pak(SRC_ADDR, DEST_48, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_24 NH3);
	dp_test_netlink_del_route(DEST_ROUTE_48 NH4);
	build_and_send_pak(SRC_ADDR, DEST_16, nh2);
	build_and_send_pak(SRC_ADDR, DEST_24, nh3);
	build_and_send_pak(SRC_ADDR, DEST_48, nh3);

	dp_test_netlink_del_route(DEST_ROUTE_16 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_24 NH3);

	/* All 3 in tbl24 */
	dp_test_netlink_add_route(DEST_ROUTE_8 NH2);
	dp_test_netlink_add_route(DEST_ROUTE_16 NH3);
	dp_test_netlink_add_route(DEST_ROUTE_24 NH4);

	build_and_send_pak(SRC_ADDR, DEST_8, nh2);
	build_and_send_pak(SRC_ADDR, DEST_16, nh3);
	build_and_send_pak(SRC_ADDR, DEST_24, nh4);

	dp_test_netlink_del_route(DEST_ROUTE_8 NH2);
	build_and_send_pak(SRC_ADDR, DEST_8, nh_drop)
	build_and_send_pak(SRC_ADDR, DEST_16, nh3);
	build_and_send_pak(SRC_ADDR, DEST_24, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_8 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_16 NH3);
	build_and_send_pak(SRC_ADDR, DEST_8, nh2);
	build_and_send_pak(SRC_ADDR, DEST_16, nh2);
	build_and_send_pak(SRC_ADDR, DEST_24, nh4);

	dp_test_netlink_add_route(DEST_ROUTE_16 NH3);
	dp_test_netlink_del_route(DEST_ROUTE_24 NH4);
	build_and_send_pak(SRC_ADDR, DEST_8, nh2);
	build_and_send_pak(SRC_ADDR, DEST_16, nh3);
	build_and_send_pak(SRC_ADDR, DEST_24, nh3);

	dp_test_netlink_del_route(DEST_ROUTE_8 NH2);
	dp_test_netlink_del_route(DEST_ROUTE_16 NH3);


	/* Clean up */
	dp_test_netlink_del_neigh("dp1T0", SRC_ADDR, SRC_MAC_STR);
	dp_test_netlink_del_neigh(nh2.nh_int, nh2.nh_addr, nh2.nh_mac_str);
	dp_test_netlink_del_neigh(nh3.nh_int, nh3.nh_addr, nh3.nh_mac_str);
	dp_test_netlink_del_neigh(nh4.nh_int, nh4.nh_addr, nh4.nh_mac_str);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "2003:3:3::3/64");
	dp_test_nl_del_ip_addr_and_connected("dp4T1", "2004:4:4::4/64");

} DP_END_TEST;

/*
 * disabled due to intermittent test failure with redirect packet
 * going walkabouts
 */
DP_START_TEST_DONT_RUN(ip6_fwd, ll_dst)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1;
	struct rte_mbuf *icmp_pak;
	struct ip6_hdr *in6_inner;
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct nd_redirect *nd_rd;
	struct nd_opt_rd_hdr *rd_hdr;
	struct nd_neighbor_solicit *nd_ns;
	struct nd_opt_hdr *nd_opt;
	int icmplen;
	int optlen;
	int len;

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", "fe80::5054:ff:fe79:3f5/64");
	dp_test_netlink_add_ip_address("dp2T1", "fe80::6054:ff:fe79:3f5/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	nh_mac_str1 = "aa:bb:cc:ff:ee:dd";
	dp_test_netlink_add_neigh("dp1T0", "fe80::200:ff:fe00:100",
				  nh_mac_str1);

	len = 24;
	/* Test 1: link local packet within scope - punted to kernel */
	test_pak = dp_test_create_ipv6_pak("fe80::200:ff:fe00:100",
					   "fe80::5054:ff:fe79:3f5",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 2: link local packet to a local address but out of
	 * scope - punted to kernel
	 */
	test_pak = dp_test_create_ipv6_pak("fe80::200:ff:fe00:100",
					   "fe80::5054:ff:fe79:3f5",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(test_pak);
	/* the kernel will deal with verifying the scope */
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test 3: link local packet an out of scope address -
	 * generate redirect and try to resolve LL address out of
	 * interface packet came in on
	 */
	test_pak = dp_test_create_ipv6_pak("fe80::200:ff:fe00:100",
					   "fe80::7054:ff:fe79:3f5",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	icmplen = len + sizeof(struct ip6_hdr) + sizeof(struct nd_redirect) -
		sizeof(struct icmp6_hdr) + sizeof(struct nd_opt_rd_hdr);
	icmp_pak = dp_test_create_icmp_ipv6_pak("fe80::5054:ff:fe79:3f5",
						"fe80::200:ff:fe00:100",
						ND_REDIRECT,
						0, /* code */
						0 /* mtu */,
						1, &icmplen,
						NULL,
						NULL, &icmp6);
	dp_test_pktmbuf_eth_init(icmp_pak,
				 nh_mac_str1,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_IPV6);
	nd_rd = (struct nd_redirect *)icmp6;
	nd_rd->nd_rd_type = ND_REDIRECT;
	nd_rd->nd_rd_code = 0;
	nd_rd->nd_rd_reserved = 0;
	nd_rd->nd_rd_target = ip6hdr(test_pak)->ip6_dst;
	nd_rd->nd_rd_dst = nd_rd->nd_rd_target;

	rd_hdr = (struct nd_opt_rd_hdr *)(nd_rd + 1);
	rd_hdr->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
	rd_hdr->nd_opt_rh_reserved1 = 0;
	rd_hdr->nd_opt_rh_reserved2 = 0;
	rd_hdr->nd_opt_rh_len = (sizeof(struct nd_opt_rd_hdr) + len +
				 sizeof(struct ip6_hdr)) / 8;
	in6_inner = (struct ip6_hdr *)(rd_hdr + 1);
	memcpy(in6_inner, ip6hdr(test_pak), len + sizeof(struct ip6_hdr));
	in6_inner->ip6_hlim--;

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum =
		dp_test_ipv6_icmp_cksum(icmp_pak, ip6hdr(icmp_pak), icmp6);

	dp_test_exp_set_pak_m(exp, 0, icmp_pak);

	optlen = (sizeof(struct nd_opt_hdr) + RTE_ETHER_ADDR_LEN + 7) & ~7;
	icmplen = sizeof(struct nd_neighbor_solicit) -
		sizeof(struct icmp6_hdr) + optlen;
	icmp_pak = dp_test_create_icmp_ipv6_pak("fe80::5054:ff:fe79:3f5",
						"ff02::1:ff79:3f5",
						ND_NEIGHBOR_SOLICIT,
						0, /* code */
						0,
						1, &icmplen,
						NULL,
						&ip6, &icmp6);
	dp_test_pktmbuf_eth_init(icmp_pak,
				 "33:33:ff:79:03:f5",
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_IPV6);

	ip6->ip6_hlim = 255;

	nd_ns = (struct nd_neighbor_solicit *)icmp6;
	nd_ns->nd_ns_target = ip6hdr(test_pak)->ip6_dst;

	nd_opt = (struct nd_opt_hdr *)(nd_ns + 1);
	memset((void *)nd_opt, 0, optlen);
	nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	nd_opt->nd_opt_len = optlen >> 3;
	rte_ether_addr_copy(&rte_pktmbuf_mtod(test_pak,
					      struct rte_ether_hdr *)->d_addr,
			(struct rte_ether_addr *)(nd_opt + 1));

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum =
		dp_test_ipv6_icmp_cksum(icmp_pak, ip6hdr(icmp_pak), icmp6);

	dp_test_exp_set_pak_m(exp, 1, icmp_pak);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T0", "fe80::200:ff:fe00:100",
				  nh_mac_str1);
	dp_test_netlink_del_ip_address("dp2T1", "fe80::6054:ff:fe79:3f5/64");
	dp_test_netlink_del_ip_address("dp1T0", "fe80::5054:ff:fe79:3f5/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	dp_test_neigh_clear_entry("dp1T0", "fe80::7054:ff:fe79:3f5");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip6_suite, ip6_show, NULL, NULL);

/*
 * Verify that the route6 summary command is correct.
 */
DP_START_TEST(ip6_show, show_routes)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	/* Should be no entries as locals are filtered out */
	dp_test_check_state_gone_show("route6 summary", "\"128\"", false);

	dp_test_netlink_add_route("2010:73:2::/128 nh 2002:2:2::1 int:dp2T1");
	dp_test_check_state_show("route6 summary", "\"128\":1", false);

	dp_test_netlink_del_route("2010:73:2::/128 nh 2002:2:2::1 int:dp2T1");
	dp_test_check_state_gone_show("route6 summary", "\"128\"", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

} DP_END_TEST;

/*
 * Create routes via a vif interface, and then delete that vif. The
 * routing table needs to have routes out of that interface purged
 * if the interface delete comes before the route delete. Otherwise
 * there will be entries in the routing table with freed ifps in.
 */
DP_DECL_TEST_CASE(ip6_suite, ip6_route_via_vif, NULL, NULL);
DP_START_TEST(ip6_route_via_vif, ip6_route_via_vif)
{
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:2";
	const char *nh_mac_str3 = "aa:bb:cc:dd:ee:3";
	const char *nh_mac_str4 = "aa:bb:cc:dd:ee:4";

	dp_test_intf_vif_create("dp1T3.102", "dp1T3", 102);
	dp_test_intf_vif_create("dp1T3.103", "dp1T3", 103);
	dp_test_intf_vif_create("dp1T3.104", "dp1T3", 104);

	dp_test_nl_add_ip_addr_and_connected("dp1T3.102", "192:168:2::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T3.103", "192:168:3::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T3.104", "192:168:4::1/64");

	dp_test_netlink_add_route(
		"51:1:1::/64"
		" nh 192:168:2::2 int:dp1T3.102"
		" nh 192:168:3::2 int:dp1T3.103"
		" nh 192:168:4::2 int:dp1T3.104");

	/*
	 * Delete the addr first as can't do it after, and addr/link
	 * messages can't overtake each other.
	 */
	dp_test_netlink_del_ip_address("dp1T3.103", "192:168:3::1/64");
	dp_test_intf_vif_del("dp1T3.103", 103);

	dp_test_netlink_add_route_nv(
		"51:1:1::/64"
		" nh 192:168:2::2 int:dp1T3.102"
		" nh 192:168:4::2 int:dp1T3.104");

	/* Add neighbours here to try to force code to walk the lpm */
	dp_test_netlink_add_neigh("dp1T3.102", "192:168:2::2", nh_mac_str2);
	dp_test_netlink_add_neigh("dp1T3.104", "192:168:4::2", nh_mac_str4);

	/* recreate interface and this time try with neighbours */
	dp_test_intf_vif_create("dp1T3.103", "dp1T3", 103);
	dp_test_nl_add_ip_addr_and_connected("dp1T3.103", "192:168:3::1/64");
	dp_test_netlink_add_neigh("dp1T3.103", "192:168:3::2", nh_mac_str3);

	dp_test_netlink_add_route_nv(
		"51:1:1::/64"
		" nh 192:168:2::2 int:dp1T3.102"
		" nh 192:168:3::2 int:dp1T3.103"
		" nh 192:168:4::2 int:dp1T3.104");

	dp_test_wait_for_route("51:1:1::/64"
			       " nh 192:168:2::2 int:dp1T3.102"
			       " nh 192:168:3::2 int:dp1T3.103"
			       " nh 192:168:4::2 int:dp1T3.104",
			       true);

	dp_test_netlink_del_ip_address("dp1T3.103", "192:168:3::1/64");
	dp_test_intf_vif_del("dp1T3.103", 103);

	dp_test_netlink_del_neigh("dp1T3.102", "192:168:2::2", nh_mac_str2);
	dp_test_netlink_del_neigh("dp1T3.104", "192:168:4::2", nh_mac_str4);

	dp_test_nl_del_ip_addr_and_connected("dp1T3.102", "192:168:2::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T3.104", "192:168:4::1/64");

	dp_test_intf_vif_del("dp1T3.102", 102);
	dp_test_intf_vif_del("dp1T3.104", 104);

} DP_END_TEST;

/* add a route that is the same as the local addr */
DP_DECL_TEST_CASE(ip6_suite, ip6_route_128_replace, NULL, NULL);
DP_START_TEST(ip6_route_128_replace, ip6_route_128_replace)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	dp_test_netlink_add_route_nv(
		"2001:1:1::1/128 scope:254 nh 2002:2:2::1 int:dp2T1");
	dp_test_netlink_del_route_nv(
		"2001:1:1::1/128 scope:254 nh 2002:2:2::1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip6_suite, ip6_default_route, NULL, NULL);
DP_START_TEST(ip6_default_route, ip6_default_route2)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:f1";

	dp_test_intf_vif_create("dp1T1.102", "dp1T1", 102);
	dp_test_nl_add_ip_addr_and_connected("dp1T1.102", "192:168:2::1/64");


	/*
	 * create a /32 then add a default route. The other 255 entries in the
	 * table8 are marked valid, with the NH of the default route.
	 * Delete the /32 and the entry should be marked invalid and the tbl8
	 * should then be marked invalid.
	 */
	dp_test_netlink_add_route("51:1:1::/64 nh 192:168:2::2 int:dp1T1.102");
	dp_test_netlink_add_route("0::0/0 nh 192:168:2::2 int:dp1T1.102");
	dp_test_netlink_del_route("51:1:1::/64 nh 192:168:2::2 int:dp1T1.102");
	dp_test_netlink_del_route("0::0/0 nh 192:168:2::2 int:dp1T1.102");

	/*
	 * Add a neighbour to verify that the old neigh is gone. If not gone
	 * then we end up with a crash due to null ptr deref.
	 */
	dp_test_netlink_add_neigh("dp1T1.102", "51:1:1::1", nh_mac_str1);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1.102", "192:168:2::1/64");
	dp_test_intf_vif_del("dp1T1.102", 102);

} DP_END_TEST;

DP_DECL_TEST_CASE(ip6_suite, ip6_pic_edge, NULL, NULL);
DP_START_TEST(ip6_pic_edge, ip6_pic_edge)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_route(
		"2010:0:1::/64 nh 2001:1:1::2 int:dp1T1 nh 2002:2:2::1 int:dp2T1 backup");
	dp_test_netlink_del_route(
		"2010:0:1::/64 nh 2001:1:1::2 int:dp1T1 nh 2002:2:2::1 int:dp2T1 backup");

	/* This is a full service dataplane - we support both orders! */
	dp_test_netlink_add_route(
		"2010:0:1::/64 nh 2001:1:1::2 int:dp1T1 backup nh 2002:2:2::1 int:dp2T1");
	dp_test_netlink_del_route(
		"2010:0:1::/64 nh 2001:1:1::2 int:dp1T1 backup nh 2002:2:2::1 int:dp2T1");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

} DP_END_TEST;
