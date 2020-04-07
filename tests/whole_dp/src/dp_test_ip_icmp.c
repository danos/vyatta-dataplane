/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * IPv4 ICMP generation tests
 */
#include "ip_funcs.h"

#include "dp_test.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_controller.h"

DP_DECL_TEST_SUITE(ip_icmp_suite);

DP_DECL_TEST_CASE(ip_icmp_suite, ip_icmp, NULL, NULL);

/*
 * Test generate ICMP message upon packet too big with don't fragment
 * flag set
 */
DP_START_TEST(ip_icmp, df)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *neigh3_mac_str = "aa:bb:cc:dd:ee:ff";
	const char *neigh1_mac_str = "bb:aa:cc:ee:dd:ff";
	struct iphdr *ip_inner;
	struct icmphdr *icph;
	struct iphdr *ip;
	int len = 1472;
	int icmplen;


	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1400);

	/* Add the nh arp we want the packet to follow */
	dp_test_netlink_add_neigh("dp3T3", "2.2.2.1", neigh3_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("2.2.2.1", "1.1.1.2",
					   1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp3T3"),
				       neigh3_mac_str, ETHER_TYPE_IPv4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("2.2.2.2", "2.2.2.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen,
						iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh3_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       ETHER_TYPE_IPv4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);
	/*
	 * The TTL allowed to be changed from the original. From RFC
	 * 1812 s4.3.2.3:
	 *   The returned IP header (and user data) MUST be identical to
	 *   that which was received, except that the router is not
	 *   required to undo any modifications to the IP header that are
	 *   normally performed in forwarding that were performed before
	 *   the error was detected (e.g., decrementing the TTL, or
	 *   updating options)
	*/
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp3T3");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp3T3", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp3T3", "2.2.2.1", neigh3_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;


/*
 * Test generate ICMP message upon packet too big with don't fragment
 * flag set
 */
DP_START_TEST(ip_icmp, df2)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *neigh2_mac_str = "aa:bb:cc:dd:ee:ff";
	const char *neigh1_mac_str = "bb:aa:cc:ee:dd:ff";
	struct iphdr *ip_inner;
	struct icmphdr *icph;
	struct iphdr *ip;
	int len = 1472;
	int icmplen;


	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1400);

	/* Add the nh arp we want the packet to follow */
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", neigh2_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("2.2.2.1", "1.1.1.2",
					   1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp2T2"),
				       neigh2_mac_str, ETHER_TYPE_IPv4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("2.2.2.2", "2.2.2.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen,
						iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh2_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       ETHER_TYPE_IPv4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);
	/*
	 * The TTL allowed to be changed from the original. From RFC
	 * 1812 s4.3.2.3:
	 *   The returned IP header (and user data) MUST be identical to
	 *   that which was received, except that the router is not
	 *   required to undo any modifications to the IP header that are
	 *   normally performed in forwarding that were performed before
	 *   the error was detected (e.g., decrementing the TTL, or
	 *   updating options)
	*/
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp2T2", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", neigh2_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;

/*
 * Test generate ICMP message upon packet too big with don't fragment
 * flag set. This test is specifically for macvlan (VRRP) interfaces,
 * to make sure that the ICMP is generated with the correct src IP, i.e
 * using the virtual IP address rather than that of the physical intf
 * that the packet was received on.
 */
DP_START_TEST(ip_icmp, df3)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *neigh1_mac_str = "bb:aa:cc:ee:dd:ff";
	const char *neigh2_mac_str = "aa:bb:cc:dd:ee:ff";
	struct iphdr *ip_inner;
	struct icmphdr *icph;
	struct iphdr *ip;
	int len = 1472;
	int icmplen;

	/* Set up the interface addresses */
	const char *l3_macvlan_intf = "dp1vrrp1";
	const char *macvlan_mac = "00:00:5E:00:01:01";

	/* Set up the interface addresses */
	dp_test_intf_macvlan_create(l3_macvlan_intf, "dp1T1", macvlan_mac);
	dp_test_nl_add_ip_addr_and_connected(l3_macvlan_intf, "10.10.10.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2.2.2.1/24");

	dp_test_netlink_set_interface_mtu("dp1T2", 1400);

	/* Add the nh arp we want the packet to follow */
	dp_test_netlink_add_neigh(l3_macvlan_intf, "10.10.10.2",
				  neigh1_mac_str);
	dp_test_netlink_add_neigh("dp1T2", "2.2.2.2", neigh2_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("10.10.10.2", "2.2.2.2",
					   1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       macvlan_mac,
				       neigh1_mac_str, ETHER_TYPE_IPv4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("10.10.10.1", "10.10.10.2",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen,
						iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh1_mac_str,
				       macvlan_mac,
				       ETHER_TYPE_IPv4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);
	/*
	 * The TTL allowed to be changed from the original. From RFC
	 * 1812 s4.3.2.3:
	 *   The returned IP header (and user data) MUST be identical to
	 *   that which was received, except that the router is not
	 *   required to undo any modifications to the IP header that are
	 *   normally performed in forwarding that were performed before
	 *   the error was detected (e.g., decrementing the TTL, or
	 *   updating options)
	 */
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp1T1");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T2", "2.2.2.2", neigh2_mac_str);
	dp_test_netlink_del_neigh(l3_macvlan_intf, "10.10.10.2",
				  neigh1_mac_str);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2.2.2.1/24");
	dp_test_nl_del_ip_addr_and_connected(l3_macvlan_intf, "10.10.10.1/24");
	dp_test_intf_macvlan_del(l3_macvlan_intf);

	dp_test_netlink_set_interface_mtu("dp1T2", 1500);
} DP_END_TEST;

/*
 * Test generate ICMP message upon TTL expiry
 */
DP_START_TEST(ip_icmp, ttl)
{
	int len = 128 - sizeof(struct udphdr);
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	struct icmphdr *icph;
	struct iphdr *ip;
	int icmplen;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.1",
					   1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, ETHER_TYPE_IPv4);

	/*
	 * Expected packet
	 */
	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
	icmp_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1", "1.1.1.2",
						ICMP_TIME_EXCEEDED,
						ICMP_EXC_TTL,
						0,
						1, &icmplen,
						iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T1"),
				       ETHER_TYPE_IPv4);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);


	/*
	 * Now test a packet destined to a local address.
	 *
	 * RFC1812 section 4.2.2.9:
	 *
	 *    A router MUST NOT discard a datagram just because it was
	 *    received with TTL equal to zero or one; if it is to the
	 *    router and otherwise valid, the router MUST attempt to
	 *    receive it.
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.2",
					   1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
} DP_END_TEST;

/*
 * Test generate ICMP message upon no route to destination
 */
DP_START_TEST(ip_icmp, noroute)
{
	int len = 128 - sizeof(struct udphdr);
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	struct icmphdr *icph;
	struct iphdr *ip;
	int icmplen;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "6.6.6.0",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, ETHER_TYPE_IPv4);

	/*
	 * Expected packet
	 */
	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
	icmp_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1", "1.1.1.2",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T1"),
				       ETHER_TYPE_IPv4);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
} DP_END_TEST;

/*
 * Test that ICMP REDIRECT messages are generated when configuration
 * doesn't disable it
 */
DP_START_TEST(ip_icmp, redirect)
{
	int len = 128 - sizeof(struct udphdr);
	struct dp_test_expected *exp;
	struct rte_mbuf *tx_pak_n[2];
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *payload;
	const char *nh_mac_str2;
	const char *nh_mac_str3;
	struct dp_test_addr gw;
	struct icmphdr *icph;
	struct iphdr *ip;
	int icmplen;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str2 = "aa:bb:cc:dd:ee:ee";
	nh_mac_str3 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str2);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.3", nh_mac_str3);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("6.6.6.0/24 nh 1.1.1.3 int:dp1T1");

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "6.6.6.1",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, ETHER_TYPE_IPv4);

	dp_test_addr_str_to_addr("1.1.1.3", &gw);
	payload = dp_test_cp_pak(test_pak);
	dp_test_ipv4_decrement_ttl(payload);
	(void)dp_test_pktmbuf_eth_init(payload,
				       nh_mac_str3,
				       dp_test_intf_name2mac_str("dp1T1"),
				       ETHER_TYPE_IPv4);

	/*
	 * Expected packet
	 */
	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
	icmp_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1", "1.1.1.2",
						ICMP_REDIRECT,
						ICMP_REDIR_HOST,
						ntohl(gw.addr.ipv4),
						1, &icmplen,
						iphdr(payload),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp1T1"),
				       ETHER_TYPE_IPv4);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	tx_pak_n[0] = icmp_pak;
	tx_pak_n[1] = payload;
	exp = dp_test_exp_create_m(tx_pak_n[0], 1);
	dp_test_exp_append_m(exp, tx_pak_n[1], 1);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	rte_pktmbuf_free(icmp_pak);
	rte_pktmbuf_free(payload);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str2);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.3", nh_mac_str3);
	dp_test_netlink_del_route("6.6.6.0/24 nh 1.1.1.3 int:dp1T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
} DP_END_TEST;

static void _icmp_redirect_verify_config(bool enable, const char *file,
					 const char *func, int line)
{
	char exp_str[100];

	snprintf(exp_str, sizeof(exp_str), "\"redirects\": %s",
		 enable ? "1" : "0");
	_dp_test_check_state_show(file, line, "ifconfig",
				  exp_str, false, DP_TEST_CHECK_STR_SUBSET);
}

#define icmp_redirect_verify_config(enable)	\
	_icmp_redirect_verify_config(enable,	\
				     __FILE__, __func__, __LINE__)

/*
 * Test that ICMP REDIRECT messages are not generated when configuration
 * disables it
 */
DP_START_TEST(ip_icmp, noredirect)
{
	int len = 128 - sizeof(struct udphdr);
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str2;
	const char *nh_mac_str3;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/* Disable ICMP REDIRECTS */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"ip4 redirects disable");

	icmp_redirect_verify_config(false);
	/* Add the nh arp we want the packet to follow */
	nh_mac_str2 = "aa:bb:cc:dd:ee:ee";
	nh_mac_str3 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str2);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.3", nh_mac_str3);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("6.6.6.0/24 nh 1.1.1.3 int:dp1T1");

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "6.6.6.1",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, ETHER_TYPE_IPv4);

	/*
	 * Expected packet
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str3,
				       dp_test_intf_name2mac_str("dp1T1"),
				       ETHER_TYPE_IPv4);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"ip4 redirects enable");
	icmp_redirect_verify_config(true);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str2);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.3", nh_mac_str3);
	dp_test_netlink_del_route("6.6.6.0/24 nh 1.1.1.3 int:dp1T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
} DP_END_TEST;

/*
 * Test that ICMP REDIRECT messages are not generated when configuration
 * disables it
 */
DP_START_TEST(ip_icmp, rfc_redirect)
{
	int len = 128 - sizeof(struct udphdr);
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str2;
	const char *nh_mac_str3;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str2 = "aa:bb:cc:dd:ee:ee";
	nh_mac_str3 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str2);
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.3", nh_mac_str3);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("6.6.6.0/24 nh 2.2.2.3 int:dp1T1");

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "6.6.6.1",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, ETHER_TYPE_IPv4);

	/*
	 * Expected packet
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str3,
				       dp_test_intf_name2mac_str("dp1T1"),
				       ETHER_TYPE_IPv4);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str2);
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.3", nh_mac_str3);
	dp_test_netlink_del_route("6.6.6.0/24 nh 2.2.2.3 int:dp1T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
} DP_END_TEST;
