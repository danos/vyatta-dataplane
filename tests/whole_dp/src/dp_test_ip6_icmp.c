/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * IPv6 ICMP generation tests
 */
#include "ip_funcs.h"
#include "ip6_funcs.h"

#include "dp_test.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"

DP_DECL_TEST_SUITE(ip6_icmp_suite);

DP_DECL_TEST_CASE(ip6_icmp_suite, ip6_icmp, NULL, NULL);

/*
 * Test generate ICMPv6 message upon packet too big. Not fragmenting as we are
 * not originating the packet.
 */
DP_START_TEST(ip6_icmp, too_big)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *neigh2_mac_str = "bb:aa:cc:ee:dd:21";
	int len = 1572;
	int icmplen;
	struct ip6_hdr *ip6, *in6_inner;
	struct icmp6_hdr *icmp6;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	/* Add the route / nh neighbour we want the packet to follow */
	dp_test_netlink_add_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", neigh2_mac_str);

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2", neigh1_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv6_pak("2001:1:1::2", "2010:73:2::2",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 neigh1_mac_str, RTE_ETHER_TYPE_IPV6);


	/*
	 * Expected packet
	 */
	icmplen = ICMP6_PAYLOAD_SIZE;
	icmp_pak = dp_test_create_icmp_ipv6_pak("2001:1:1::1", "2001:1:1::2",
						ICMP6_PACKET_TOO_BIG,
						0, /* code */
						1500 /* mtu */,
						1, &icmplen,
						ip6hdr(test_pak),
						&ip6, &icmp6);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh1_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV6);

	/* Forwarding code will have already decremented hop limit */
	in6_inner = (struct ip6_hdr *)(icmp6 + 1);
	in6_inner->ip6_hlim--;

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(icmp_pak, ip6, icmp6);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", neigh2_mac_str);
	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2", neigh1_mac_str);

	dp_test_netlink_del_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

} DP_END_TEST;

/*
 * Test generate ICMPv6 message upon hop limit exceeded.
 */
DP_START_TEST(ip6_icmp, ttl)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *neigh2_mac_str = "bb:aa:cc:ee:dd:21";
	int len = 24;
	int icmplen;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	/* Add the route / nh neighbour we want the packet to follow */
	dp_test_netlink_add_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", neigh2_mac_str);

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2", neigh1_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv6_pak("2001:1:1::2", "2010:73:2::2",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 neigh1_mac_str, RTE_ETHER_TYPE_IPV6);
	ip6hdr(test_pak)->ip6_hlim = 1;

	/*
	 * Expected packet
	 */
	icmplen = len + sizeof(struct ip6_hdr);
	icmp_pak = dp_test_create_icmp_ipv6_pak("2001:1:1::1", "2001:1:1::2",
						ICMP6_TIME_EXCEEDED,
						ICMP6_TIME_EXCEED_TRANSIT,
						0,
						1, &icmplen,
						ip6hdr(test_pak),
						NULL, NULL);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh1_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", neigh2_mac_str);
	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2", neigh1_mac_str);

	dp_test_netlink_del_route("2010:73:2::/48 nh 2002:2:2::1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

} DP_END_TEST;
