/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT Firewall tests for packet to/from the kernel.  Local packets
 * and packets that have been forwarded in the kernel.
 */

#include <libmnl/libmnl.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "protobuf/ForwardingClassConfig.pb-c.h"


DP_DECL_TEST_SUITE(npf_local);

DP_DECL_TEST_CASE(npf_local, ipv4, NULL, NULL);

/*
 * This test currently doesnt do any npf tests.  It simply exercises the spath
 * in/out test code.
 */
DP_START_TEST(ipv4, spath)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * First simulate pkt from kernel to be tx on intf1
	 */
	struct dp_test_pkt_desc_t v4_pktA = {
		.text       = "Packet A, Local -> Neighbour 1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.1",
		.l2_src     = "0:0:0:0:0:0",
		.l3_dst     = "1.1.1.2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};
	pkt = &v4_pktA;

	test_pak = dp_test_from_spath_v4_pkt_from_desc(pkt);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, pkt->tx_intf);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test.  kernel -> intf1 -> n1 */
	dp_test_send_slowpath_pkt(test_pak, test_exp);

	/*
	 * Next simulate pkt rcvd on intf1 addressed to the router.
	 */
	struct dp_test_pkt_desc_t v4_pktB = {
		.text       = "Packet B, Neighbour 1 -> Local",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "1.1.1.1",
		.l2_dst     = "0:0:0:0:0:0",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
				.dport = 41000,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};
	pkt = &v4_pktB;

	test_pak = dp_test_v4_pkt_from_desc(pkt);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, pkt->tx_intf);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_LOCAL);

	/* Run the test.  n1 -> intf1 -> kernel */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Cleanup */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

} DP_END_TEST;

/*
 * Test that a packet forwarded by the kernel passes though the output
 * interface firewall, and not the local firewall.
 */
DP_START_TEST(ipv4, kernel_forwarded)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

	struct dp_test_npf_rule_t rules[] = {
		RULE_10_PASS_TO_ANY,
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/*
	 * source address is *not* an address belonging to the router.  This
	 * simulates a packet that has been forwarded by the kernel.
	 */
	struct dp_test_pkt_desc_t v4_pktA = {
		.text       = "Packet B, Non-local -> Neighbour 1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "2.2.2.2",
		.l2_src     = "aa:bb:cc:dd:2:a2",
		.l3_dst     = "1.1.1.2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};
	pkt = &v4_pktA;

	test_pak = dp_test_from_spath_v4_pkt_from_desc(pkt);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, pkt->tx_intf);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test.  kernel -> intf1 -> n1 */
	dp_test_send_slowpath_pkt(test_pak, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

} DP_END_TEST;

/*
 * Test creates ipv4 tcp packet and send it to shadow interface.
 * Originate firewall is configured in the interface to verify
 * dscp mark function and action drop.
 *
 *                                  |
 *                                  |
 *                                  v
 *                          +-----+ 1.1.1.1
 *                          |     |
 *                          | uut |---------------host 1.1.1.2
 *                          |     | dp1T0
 *                          +-----+ intf1
 *
 *              --> Forwards (on output)
 *              Source 1.1.1.1 Destination 1.1.1.2
 *
 */
DP_DECL_TEST_SUITE(npf_orig);

DP_DECL_TEST_CASE(npf_orig, ipv4_tcp_shadow, NULL, NULL);

static void npf_orig_ipv4_tcp_shadow_setup(
		struct dp_test_expected **test_exp,
		struct rte_mbuf **test_pak)
{
	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *exp_pak;
	struct iphdr *ip;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * Simulate pkt from kernel to be tx on intf1
	 */
	struct dp_test_pkt_desc_t v4_pktA = {
		.text       = "Packet A, Local -> Neighbour 1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.1",
		.l2_src     = "0:0:0:0:0:0",
		.l3_dst     = "1.1.1.2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};
	pkt = &v4_pktA;

	*test_pak = dp_test_from_spath_v4_pkt_from_desc(pkt);

	*test_exp = dp_test_exp_create(*test_pak);
	exp_pak = dp_test_exp_get_pak_m(*test_exp, 0);
	ip = iphdr(exp_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS, IPTOS_DSCP_AF12);
	dp_test_exp_set_dont_care(*test_exp, 0, (uint8_t *)&ip->check, 2);
}

DP_START_TEST(ipv4_tcp_shadow, accept_and_dscp_remark)
{
	struct dp_test_expected *test_exp = NULL;
	struct rte_mbuf *test_pak = NULL;

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto-final=6 src-port=41000"
						" rproc=markdscp(12)"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_TCP_ORIG",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	npf_orig_ipv4_tcp_shadow_setup(&test_exp, &test_pak);

	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test.  kernel -> intf1 -> n1 */
	dp_test_send_slowpath_pkt(test_pak, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

} DP_END_TEST;

DP_START_TEST(ipv4_tcp_shadow, drop)
{
	struct dp_test_expected *test_exp = NULL;
	struct rte_mbuf *test_pak = NULL;

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=6 src-port=41000"
						" rproc=markdscp(12)"},
		RULE_DEF_PASS,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_TCP_ORIG",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	npf_orig_ipv4_tcp_shadow_setup(&test_exp, &test_pak);

	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test.  kernel -> intf1 -> n1 */
	dp_test_send_slowpath_pkt(test_pak, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

} DP_END_TEST;

/*
 * Test creates ipv6 tcp packet and send it to shadow interface.
 * Originate firewall is configured in the interface to verify
 * dscp mark function and action drop.
 *
 *                                  |
 *                                  |
 *                                  v
 *                          +-----+ 2001::1/64
 *                          |     |
 *                          | uut |---------------host 2001::2
 *                          |     | dp1T0
 *                          +-----+ intf1
 *
 *              --> Forwards (on output)
 *              Source 2001::1 Destination 2001::2
 *
 */
DP_DECL_TEST_CASE(npf_orig, ipv6_tcp_shadow, NULL, NULL);

static void npf_orig_ipv6_tcp_shadow_setup(
		struct dp_test_expected **test_exp,
		struct rte_mbuf **test_pak)
{
	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *exp_pak;
	struct ip6_hdr *ip6;

	/* Setup interfaces and neighbors */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001::1/64");

	/*
	 * Simulate pkt from kernel to be tx on intf1
	 */
	struct dp_test_pkt_desc_t v4_pktA = {
		.text       = "Packet A, Local -> Neighbour 1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001::1",
		.l2_src     = "0:0:0:0:0:0",
		.l3_dst     = "2001::2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};
	pkt = &v4_pktA;

	*test_pak = dp_test_from_spath_pkt_from_desc(pkt);

	*test_exp = dp_test_exp_create(*test_pak);
	exp_pak = dp_test_exp_get_pak_m(*test_exp, 0);
	ip6 = ip6hdr(exp_pak);
	dp_test_set_pak_ip6_field(ip6, DP_TEST_SET_TOS, IPTOS_DSCP_AF12);
}

DP_START_TEST(ipv6_tcp_shadow, dscp_remark)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	npf_orig_ipv6_tcp_shadow_setup(&test_exp, &test_pak);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto-final=6 src-port=41000"
					" rproc=markdscp(12)"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_TCP_ORIG",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test.  kernel -> intf1 -> n1 */
	dp_test_send_slowpath_pkt(test_pak, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001::1/64");
} DP_END_TEST;

DP_START_TEST(ipv6_tcp_shadow, drop)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	npf_orig_ipv6_tcp_shadow_setup(&test_exp, &test_pak);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=6 src-port=41000"
						" rproc=markdscp(12)"},
		RULE_DEF_PASS,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_TCP_ORIG",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test.  kernel -> intf1 -> n1 */
	dp_test_send_slowpath_pkt(test_pak, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001::1/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(npf_orig, ipv4_icmp_transit, NULL, NULL);

/*
 * Match on ICMP type and code
 * Test generate ICMP message upon packet too big with don't fragment
 * flag set
 *
 *                  2.2.2.2 +-----+ 1.1.1.1
 *                          |     |
 * host 2.2.2.1 ------------| uut |---------------host 1.1.1.2
 *                    dp3T3 |     | dp1T1 (mtu 1400)
 *                    intf1 +-----+ intf2
 *
 *
 *              --> Forwards (on output)
 *              Source 2.2.2.1 Destination 1.1.1.2 (length 1472, DSCP 0)
 *
 *                <-- Back ICMP
 *              Source 1.1.1.2 Destination 2.2.2.2
 */
static void npf_orig_ipv4_icmp_transit_setup(
		struct dp_test_expected **exp,
		struct rte_mbuf **test_pak)
{
	struct rte_mbuf *icmp_pak;
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
	*test_pak = dp_test_create_ipv4_pak("2.2.2.1", "1.1.1.2",
					   1, &len);
	ip = iphdr(*test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(*test_pak,
				       dp_test_intf_name2mac_str("dp3T3"),
				       neigh3_mac_str, RTE_ETHER_TYPE_IPV4);

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
						iphdr(*test_pak),
						&ip, &icph);

	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh3_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_IPV4);

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

	ip = iphdr(icmp_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS, IPTOS_DSCP_AF12);

	*exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
}

DP_START_TEST(ipv4_icmp_transit, packet_to_big_dscp_remark)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;

	/* Configure ICMPv4 error packets to be marked as AF12*/
	dp_test_fail_unless(
		(dp_test_ForwardingClassConfig_execute(
			 FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV4,
			 FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP, IPTOS_DSCP_AF12) == true),
		"TOS configuration is failed");

	npf_orig_ipv4_icmp_transit_setup(&exp, &test_pak);

	dp_test_exp_set_oif_name(exp, "dp3T3");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp3T3", exp);

	/*Cleanup */

	/* Configure ICMPv4 error packets to be marked as default value*/
	dp_test_fail_unless((dp_test_ForwardingClassConfig_execute(
				     FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV4,
				     FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP,
				     IPTOS_PREC_INTERNETCONTROL) == true),
			    "TOS configuration is failed");

	dp_test_netlink_del_neigh("dp3T3", "2.2.2.1", "aa:bb:cc:dd:ee:ff");
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", "bb:aa:cc:ee:dd:ff");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;

/*
 * Negative Case, Since NPF is not invoked as part of ICMPv4 error packets
 * Making sure the NPF rules doesn't hit for ICMPv4 error packets
 */

DP_START_TEST(ipv4_icmp_transit, no_rule_matched)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;

	/* Configure ICMPv4 error packets to be marked as AF12*/
	dp_test_fail_unless(
		(dp_test_ForwardingClassConfig_execute(
			 FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV4,
			 FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP, IPTOS_DSCP_AF12) == true),
		"TOS configuration is failed");

	npf_orig_ipv4_icmp_transit_setup(&exp, &test_pak);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=1 rproc=markdscp(12)"},
		RULE_DEF_PASS,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_ICMPv4_ORIG",
		.enable = 1,
		.attach_point   = "dp3T3",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	dp_test_exp_set_oif_name(exp, "dp3T3");

	/* Run test */
	dp_test_pak_receive(test_pak, "dp3T3", exp);

	/* After test validations , no hit on npf rule*/
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);

	/* Clean Up */

	/* Configure ICMPv4 error packets to be marked as default value*/
	dp_test_fail_unless((dp_test_ForwardingClassConfig_execute(
				     FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV4,
				     FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP,
				     IPTOS_PREC_INTERNETCONTROL) == true),
			    "TOS configuration is failed");

	dp_test_npf_fw_del(&fw, false);

	dp_test_netlink_del_neigh("dp3T3", "2.2.2.1", "aa:bb:cc:dd:ee:ff");
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", "bb:aa:cc:ee:dd:ff");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;

DP_DECL_TEST_CASE(npf_orig, ipv6_icmp_transit, NULL, NULL);
/*
 * Test creates ipv6 icmp packet with DF bit set and route it
 * to dataplane interface that has mtu less than the packet size.
 * Router creates and sends ipv6 icmp packet to big message back.
 *
 *           2001:1:1::1/64 +-----+ 2002:2:2::2/64
 *                          |     |
 * host 2001:1:1::2 --------| uut |---------------host 2002:2:2::1
 *                    dp1T0 |     | dp2T1 (mtu 1400)
 *                    intf1 +-----+ intf2
 *                    Route:
 * *
 *
 *        --> Forwards
 *      Source 2001:1:1::2 Destination 2002:2:2::1 (length 1572, DSCP 0)
 *
 *        <-- Back ICMP
 *      Source 2002:2:2::1 Destination 2001:1:1::2 (DSCP AF12)
 */
static void npf_orig_ipv6_icmp_transit_setup(
		struct dp_test_expected **exp,
		struct rte_mbuf **test_pak)
{
	struct rte_mbuf *icmp_pak;
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
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", neigh2_mac_str);

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2", neigh1_mac_str);
	/* Create pak to match the route added above */
	*test_pak = dp_test_create_ipv6_pak("2001:1:1::2", "2002:2:2::1",
					   1, &len);
	dp_test_pktmbuf_eth_init(*test_pak,
			dp_test_intf_name2mac_str("dp1T0"),
			neigh1_mac_str, RTE_ETHER_TYPE_IPV6);

	/*
	 * Expected packet
	 */
	icmplen = 1280 - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
	icmp_pak = dp_test_create_icmp_ipv6_pak("2001:1:1::1", "2001:1:1::2",
						ICMP6_PACKET_TOO_BIG,
						0, /* code */
						1500 /* mtu */,
						1, &icmplen,
						ip6hdr(*test_pak),
						&ip6, &icmp6);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh1_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV6);

	/* Forwarding code will have already decremented hop limit */
	in6_inner = (struct ip6_hdr *)(icmp6 + 1);
	in6_inner->ip6_hlim--;
	dp_test_set_pak_ip6_field(ip6, DP_TEST_SET_TOS, IPTOS_DSCP_AF12);

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(icmp_pak, ip6, icmp6);

	*exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
}

DP_START_TEST(ipv6_icmp_transit, packet_to_big_dscp_remark)
{
	struct dp_test_expected *exp = NULL;
	struct rte_mbuf *test_pak = NULL;

	/* Configure ICMPv6 error packets to be marked as AF12*/
	dp_test_fail_unless(
		(dp_test_ForwardingClassConfig_execute(
			 FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV6,
			 FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP, IPTOS_DSCP_AF12) == true),
		"TOS configuration is failed");

	npf_orig_ipv6_icmp_transit_setup(&exp, &test_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/* Run test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*Clean up*/
	/* Configure ICMPv6 error packets to be marked as default*/
	dp_test_fail_unless((dp_test_ForwardingClassConfig_execute(
				     FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV6,
				     FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP,
				     IPTOS_PREC_NETCONTROL) == true),
			    "TOS configuration is failed");

	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", "bb:aa:cc:ee:dd:21");
	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2", "aa:bb:cc:dd:ee:10");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

} DP_END_TEST;

/*
 * Negative Case, Since NPF is not invoked as part of ICMPv6 error packets
 * Making sure the NPF rules doesn't hit for ICMPv6 error packets
 */

DP_START_TEST(ipv6_icmp_transit, no_npf_match)
{
	struct dp_test_expected *exp = NULL;
	struct rte_mbuf *test_pak = NULL;

	/* Configure ICMPv6 error packets to be marked as AF12*/
	dp_test_fail_unless(
		(dp_test_ForwardingClassConfig_execute(
			 FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV6,
			 FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP, IPTOS_DSCP_AF12) == true),
		"TOS configuration is failed");
	npf_orig_ipv6_icmp_transit_setup(&exp, &test_pak);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=58 rproc=markdscp(12)"},
		RULE_DEF_PASS,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_ICMPv6_ORIG",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/* Run test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* After test validationsi, no hit for NPF rule */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);

	/* Clean Up */
	/* Configure ICMPv6 error packets to be marked as default*/
	dp_test_fail_unless((dp_test_ForwardingClassConfig_execute(
				     FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV6,
				     FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP,
				     IPTOS_PREC_NETCONTROL) == true),
			    "TOS configuration is failed");
	dp_test_npf_fw_del(&fw, false);

	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", "bb:aa:cc:ee:dd:21");
	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2", "aa:bb:cc:dd:ee:10");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

} DP_END_TEST;


DP_DECL_TEST_CASE(npf_orig, ipv6_nd_na, NULL, NULL);
/*
 * Test generates ND Solicitation message and sends to Router.
 * Router replay with ND Advertisement.
 * Originate firewall is configured in the output interface to verify
 * dscp mark function and action drop.
 *
 *        fe80::5054:ff:fe79:3f5/64
 *                   2001:1:1::1/64 +-----+
 *                                  |     |
 * host fe80::409f:1ff:fee8:101 ----| uut |
 *                            dp1T0 |     |
 *                            intf1 +-----+
 *
 * --> Forwards NS
 * Source 2001:1:1::2 Destination ff02::1:ff00:2
 *
 * <-- Back NA
 * Source fe80::5054:ff:fe79:3f5 Destination fe80::409f:1ff:fee8:101
 */
static struct rte_mbuf *dp_test_create_na_pak(const char *saddr,
		const char *daddr, uint16_t tos, const char *smac,
		const char *dmac, const char *target)
{
	struct rte_mbuf *na_pak = NULL;
	struct nd_neighbor_advert *nd_na = NULL;
	struct ip6_hdr *ip6 = NULL;
	struct nd_opt_hdr *nd_opt = NULL;
	struct icmp6_hdr *icmp6 = NULL;
	struct in6_addr addr6;

	int optlen = (sizeof(struct nd_opt_hdr)
			+ RTE_ETHER_ADDR_LEN + 7) & ~7;
	int icmplen = sizeof(struct nd_neighbor_solicit) -
		sizeof(struct icmp6_hdr) + optlen;
	na_pak = dp_test_create_icmp_ipv6_pak(saddr,
						daddr,
						ND_NEIGHBOR_ADVERT,
						0, /* code */
						0,
						1, &icmplen,
						NULL,
						&ip6, &icmp6);

	ip6->ip6_hlim = 255;
	dp_test_set_pak_ip6_field(ip6, DP_TEST_SET_TOS, tos);

	nd_na = (struct nd_neighbor_advert *)icmp6;

	if (inet_pton(AF_INET6, target, &addr6) != 1)
		dp_test_fail("Couldn't create ipv6 address");

	memcpy(nd_na->nd_na_target.s6_addr, addr6.s6_addr, 16);
	nd_na->nd_na_flags_reserved = ND_NA_FLAG_ROUTER
			| ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;

	nd_opt = (struct nd_opt_hdr *)(nd_na + 1);
	memset((void *)nd_opt, 0, optlen);
	nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	nd_opt->nd_opt_len = optlen >> 3;

	dp_test_pktmbuf_eth_init(na_pak, dmac, smac, RTE_ETHER_TYPE_IPV6);

	rte_ether_addr_copy(&rte_pktmbuf_mtod(na_pak,
			struct rte_ether_hdr *)->s_addr,
			(struct rte_ether_addr *)(nd_opt + 1));

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(na_pak,
			ip6hdr(na_pak), icmp6);

	return na_pak;
}

static struct rte_mbuf *dp_test_create_ns_pak(const char *saddr,
		const char *daddr, uint16_t tos, const char *smac,
		const char *dmac, const char *target)
{
	struct rte_mbuf *ns_pak = NULL;
	struct nd_neighbor_solicit *nd_ns = NULL;
	struct ip6_hdr *ip6 = NULL;
	struct nd_opt_hdr *nd_opt = NULL;
	struct icmp6_hdr *icmp6 = NULL;
	struct in6_addr addr6;

	int optlen = (sizeof(struct nd_opt_hdr) + RTE_ETHER_ADDR_LEN + 7) & ~7;
	int icmplen = sizeof(struct nd_neighbor_solicit) -
		sizeof(struct icmp6_hdr) + optlen;
	ns_pak = dp_test_create_icmp_ipv6_pak(saddr,
						daddr,
						ND_NEIGHBOR_SOLICIT,
						0, /* code */
						0,
						1, &icmplen,
						NULL,
						&ip6, &icmp6);

	ip6->ip6_hlim = 255;
	dp_test_set_pak_ip6_field(ip6, DP_TEST_SET_TOS, tos);

	nd_ns = (struct nd_neighbor_solicit *)icmp6;

	if (inet_pton(AF_INET6, target, &addr6) != 1)
		dp_test_fail("Couldn't create ipv6 address");

	memcpy(nd_ns->nd_ns_target.s6_addr, addr6.s6_addr, 16);

	nd_opt = (struct nd_opt_hdr *)(nd_ns + 1);
	memset((void *)nd_opt, 0, optlen);
	nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	nd_opt->nd_opt_len = optlen >> 3;

	dp_test_pktmbuf_eth_init(ns_pak, dmac, smac, RTE_ETHER_TYPE_IPV6);

	rte_ether_addr_copy(&rte_pktmbuf_mtod(ns_pak,
			struct rte_ether_hdr *)->s_addr,
			(struct rte_ether_addr *)(nd_opt + 1));

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum =
		dp_test_ipv6_icmp_cksum(ns_pak, ip6hdr(ns_pak), icmp6);

	return ns_pak;
}

DP_START_TEST(ipv6_nd_na, packet_na_dscp_remark)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ns_pak;
	struct rte_mbuf *exp_na_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *host_ll_ip = "fe80::409f:1ff:fee8:101";
	const char *router_ll_ip =        "fe80::5054:ff:fe79:3f5";
	const char *router_ll_ip_subnet = "fe80::5054:ff:fe79:3f5/64";

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", router_ll_ip_subnet);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", host_ll_ip, neigh1_mac_str);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto-final=58 rproc=markdscp(12)"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_ICMPv6_ORIG",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/*
	 * Test packet
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		IPTOS_CLASS_CS5, neigh1_mac_str, "33:33:ff:00:00:02",
		"2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			IPTOS_DSCP_AF12, dp_test_intf_name2mac_str("dp1T0"),
			neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/* After test validations */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Clean Up */
	dp_test_npf_fw_del(&fw, false);

	dp_test_netlink_del_neigh("dp1T0", host_ll_ip, neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", router_ll_ip_subnet);
} DP_END_TEST;

DP_START_TEST(ipv6_nd_na, drop)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ns_pak;
	struct rte_mbuf *exp_na_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *host_ll_ip = "fe80::409f:1ff:fee8:101";
	const char *router_ll_ip =        "fe80::5054:ff:fe79:3f5";
	const char *router_ll_ip_subnet = "fe80::5054:ff:fe79:3f5/64";

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", router_ll_ip_subnet);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", host_ll_ip, neigh1_mac_str);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=58 rproc=markdscp(12)"},
		RULE_DEF_PASS,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_ICMPv6_ORIG",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/*
	 * Test packet
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		IPTOS_CLASS_CS5, neigh1_mac_str, "33:33:ff:00:00:02",
		"2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			IPTOS_DSCP_AF12, dp_test_intf_name2mac_str("dp1T0"),
			neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/* After test validations */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Clean Up */
	dp_test_npf_fw_del(&fw, false);

	dp_test_netlink_del_neigh("dp1T0", host_ll_ip, neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", router_ll_ip_subnet);
} DP_END_TEST;

DP_DECL_TEST_CASE(npf_local, cgnat_icmpv4, NULL, NULL);
/*
 * Test sends ipv4 icmp echo request message to router sgnat public pool.
 * Router sgnat generates and sends ipv4 icmp echo reply.
 * Originate firewall is configured in the output interface to verify
 * dscp mark function and action drop.
 *
 *
 *    Private                                       Public
 *                       1.1.1.254/24
 *                +-----+
 *                |     |--------------- 1.1.1.1/24
 *                | dut |
 *                |     | pool 1.1.1.11/32
 *                |     |
 *                +-----+ dp2T1
 *
 *                    <--- ICMP Echo Req Source 1.1.1.1 Destination 1.1.1.11
 *                    ---> ICMP Echo Reply Source 1.1.1.11 Destination 1.1.1.1
 */
static void cgnat_icmpv4_setup(struct dp_test_expected **test_exp,
		struct rte_mbuf **test_pak)
{
	struct rte_mbuf *exp_pak = NULL;
	struct iphdr *ip = NULL;

	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.254/24");
	dp_test_netlink_add_neigh("dp2T1", "1.1.1.1", "aa:bb:cc:dd:2:b1");

	/* Pre IPv4 ICMP packet */
	struct dp_test_pkt_desc_t test_pak_ICMP = {
		.text       = "IPv4 ICMP req",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "1.1.1.11",
		.l2_dst     = dp_test_intf_name2mac_str("dp2T1"),
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = 1024,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp2T1"
	};

	/* Post IPv4 ICMP packet */
	struct dp_test_pkt_desc_t exp_pkt_ICMP = {
		.text       = "IPv4 ICMP echo reply from NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.11",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "1.1.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHOREPLY,
				.code = 0,
				{
					.dpt_icmp_id = 1024,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp2T1"
	};

	*test_pak = dp_test_v4_pkt_from_desc(&test_pak_ICMP);
	exp_pak = dp_test_v4_pkt_from_desc(&exp_pkt_ICMP);
	ip = iphdr(exp_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS, IPTOS_DSCP_AF12);
	dp_test_pktmbuf_eth_init(exp_pak, exp_pkt_ICMP.l2_dst,
			exp_pkt_ICMP.l2_src, exp_pkt_ICMP.ether_type);

	*test_exp = dp_test_exp_create(exp_pak);
	rte_pktmbuf_free(exp_pak);
}

static void cgnat_icmpv4_teardown(void)
{
	/* Check cgnat feature is disabled */
	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-cgnat-in",
				      "ipv4-validate");
	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-cgnat-out",
				      "ipv4-out");

	/* Cleanup */
	dp_test_netlink_del_neigh("dp2T1", "1.1.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.254/24");
	dp_test_npf_cleanup();
}

#define cgnat_policy_add(_a, _b, _c, _d, _e, _f, _g, _h, _i)		\
	_cgnat_policy_add(_a, _b, _c, _d, _e, _f, _g, _h, _i, true,	\
			  __FILE__, __func__, __LINE__)

DP_START_TEST(cgnat_icmpv4, packet_dscp_remark)
{
	struct dp_test_expected *test_exp = NULL;
	struct rte_mbuf *test_pak = NULL;

	cgnat_icmpv4_setup(&test_exp, &test_pak);

	dp_test_npf_cmd("nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE2/1.1.1.11/32", false);

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto-final=1 rproc=markdscp(12)"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_ICMPv4_ORIG",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/* Set test expectations */

	dp_test_exp_set_oif_name(test_exp, "dp2T1");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/* After test validations */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Clean Up */
	dp_test_npf_fw_del(&fw, false);

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	cgnat_icmpv4_teardown();
} DP_END_TEST;

DP_START_TEST(cgnat_icmpv4, drop)
{
	struct dp_test_expected *test_exp = NULL;
	struct rte_mbuf *test_pak = NULL;

	cgnat_icmpv4_setup(&test_exp, &test_pak);

	dp_test_npf_cmd("nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE2/1.1.1.11/32", false);

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=1 rproc=markdscp(12)"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_ICMPv4_ORIG",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/* Set test expectations */

	dp_test_exp_set_oif_name(test_exp, "dp2T1");
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/* After test validations */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Clean Up */
	dp_test_npf_fw_del(&fw, false);

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	cgnat_icmpv4_teardown();
} DP_END_TEST;

/*
 * IPv6 ND and originate firewall
 *
 * Inject an IPv6 Neighbor Solicitation pkt in order to generate a Neighbor
 * Advertisement pkt.
 */
DP_DECL_TEST_CASE(npf_local, npf_v6nbr1, NULL, NULL);
DP_START_TEST(npf_v6nbr1, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ns_pak;
	struct rte_mbuf *exp_na_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *host_ll_ip = "fe80::409f:1ff:fee8:101";
	const char *router_ll_ip =        "fe80::5054:ff:fe79:3f5";
	const char *router_ll_ip_subnet = "fe80::5054:ff:fe79:3f5/64";

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", router_ll_ip_subnet);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", host_ll_ip, neigh1_mac_str);

	struct dp_test_npf_rule_t rules[] = {
		{
			/* Router Solicitation */
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto=58 icmpv6=133"
		},
		{
			/* Router Advertisement */
			.rule     = "20",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto=58 icmpv6=134"
		},
		{
			/* Neighbor Solicitation */
			.rule     = "30",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto=58 icmpv6=135"
		},
		{
			/* Neighbor Advertisement */
#define NA_RULE_INDEX 3
			.rule     = "40",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto=58 icmpv6=136"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_ORIG",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/*
	 * Test packet
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		       IPTOS_CLASS_CS6, neigh1_mac_str, "33:33:ff:00:00:02",
		       "2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			   IPTOS_CLASS_CS6, dp_test_intf_name2mac_str("dp1T0"),
			   neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/*
	 * Change firewall to drop NA packet
	 */
	dp_test_npf_fw_del(&fw, false);
	rules[NA_RULE_INDEX].pass = BLOCK;
	dp_test_npf_fw_add(&fw, false);

	/*
	 * Test packet
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		       IPTOS_CLASS_CS6, neigh1_mac_str, "33:33:ff:00:00:02",
		       "2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			   IPTOS_CLASS_CS6, dp_test_intf_name2mac_str("dp1T0"),
			   neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_npf_fw_del(&fw, false);

	dp_test_netlink_del_neigh("dp1T0", host_ll_ip, neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", router_ll_ip_subnet);
} DP_END_TEST;

/*
 * IPv6 ND, zone on interface, no local zone.
 *
 * Inject an IPv6 Neighbor Solicitation pkt in order to generate a Neighbor
 * Advertisement pkt.
 *
 * The ND packet is forwarded.  Normally a "no-zone to zone" transition would
 * be blocked.  However an exception is made because the flag NPF_FLAG_FROM_US
 * is set.
 */
DP_DECL_TEST_CASE(npf_local, npf_v6nbr2, NULL, NULL);
DP_START_TEST(npf_v6nbr2, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ns_pak;
	struct rte_mbuf *exp_na_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *host_ll_ip = "fe80::409f:1ff:fee8:101";
	const char *router_ll_ip =        "fe80::5054:ff:fe79:3f5";
	const char *router_ll_ip_subnet = "fe80::5054:ff:fe79:3f5/64";
	bool debug = false;

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", router_ll_ip_subnet);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", host_ll_ip, neigh1_mac_str);

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp2T1", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = {0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * Test packet
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		       IPTOS_CLASS_CS6, neigh1_mac_str, "33:33:ff:00:00:02",
		       "2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			   IPTOS_CLASS_CS6, dp_test_intf_name2mac_str("dp1T0"),
			   neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/* Clean Up */
	dpt_zone_cfg(&cfg, false, debug);

	dp_test_netlink_del_neigh("dp1T0", host_ll_ip, neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", router_ll_ip_subnet);
} DP_END_TEST;

/*
 * IPv6 ND, zone on interface, local zone.  Pass rule in LOCAL_TO_PRIV
 * ruleset.
 *
 * Inject an IPv6 Neighbor Solicitation pkt in order to generate a Neighbor
 * Advertisement pkt.
 */
DP_DECL_TEST_CASE(npf_local, npf_v6nbr3, NULL, NULL);
DP_START_TEST(npf_v6nbr3, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ns_pak;
	struct rte_mbuf *exp_na_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *host_ll_ip = "fe80::409f:1ff:fee8:101";
	const char *router_ll_ip =        "fe80::5054:ff:fe79:3f5";
	const char *router_ll_ip_subnet = "fe80::5054:ff:fe79:3f5/64";
	bool debug = false;

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", router_ll_ip_subnet);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", host_ll_ip, neigh1_mac_str);

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp2T1", NULL },
			.local = false,
		},
		.local = {
			.name = "LOCAL",
			.intf = { NULL },
			.local = true,
		},
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = {
			.name		= "LOCAL_TO_PRIV",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_local = {
			.name		= "PRIV_TO_LOCAL",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * Test packet
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		       IPTOS_CLASS_CS6, neigh1_mac_str, "33:33:ff:00:00:02",
		       "2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			   IPTOS_CLASS_CS6, dp_test_intf_name2mac_str("dp1T0"),
			   neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/* Clean Up */
	dpt_zone_cfg(&cfg, false, debug);

	dp_test_netlink_del_neigh("dp1T0", host_ll_ip, neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", router_ll_ip_subnet);
} DP_END_TEST;

/*
 * IPv6 ND, zone on interface, local zone.  Pass rule in LOCAL_TO_PRIV
 * ruleset, but packet does not match.  The UNMATCHED decision is overridden
 * in npf_apply_firewall.
 *
 * Inject an IPv6 Neighbor Solicitation pkt in order to generate a Neighbor
 * Advertisement pkt.
 */
DP_DECL_TEST_CASE(npf_local, npf_v6nbr4, NULL, NULL);
DP_START_TEST(npf_v6nbr4, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ns_pak;
	struct rte_mbuf *exp_na_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *host_ll_ip = "fe80::409f:1ff:fee8:101";
	const char *router_ll_ip =        "fe80::5054:ff:fe79:3f5";
	const char *router_ll_ip_subnet = "fe80::5054:ff:fe79:3f5/64";
	bool debug = false;

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", router_ll_ip_subnet);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", host_ll_ip, neigh1_mac_str);

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp2T1", NULL },
			.local = false,
		},
		.local = {
			.name = "LOCAL",
			.intf = { NULL },
			.local = true,
		},
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = {
			.name		= "LOCAL_TO_PRIV",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "proto-final=1",
		},
		.priv_to_local = {
			.name		= "PRIV_TO_LOCAL",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * Test packet
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		       IPTOS_CLASS_CS6, neigh1_mac_str, "33:33:ff:00:00:02",
		       "2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			   IPTOS_CLASS_CS6, dp_test_intf_name2mac_str("dp1T0"),
			   neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/* Clean Up */
	dpt_zone_cfg(&cfg, false, debug);

	dp_test_netlink_del_neigh("dp1T0", host_ll_ip, neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", router_ll_ip_subnet);
} DP_END_TEST;

/*
 * IPv6 ND, zone on interface, local zone.  Block rule in LOCAL_TO_PRIV
 * ruleset.   However the block rule is overridden in npf_apply_firewall.
 *
 * Inject an IPv6 Neighbor Solicitation pkt in order to generate a Neighbor
 * Advertisement pkt.
 */
DP_DECL_TEST_CASE(npf_local, npf_v6nbr5, NULL, NULL);
DP_START_TEST(npf_v6nbr5, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ns_pak;
	struct rte_mbuf *exp_na_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *host_ll_ip = "fe80::409f:1ff:fee8:101";
	const char *router_ll_ip =        "fe80::5054:ff:fe79:3f5";
	const char *router_ll_ip_subnet = "fe80::5054:ff:fe79:3f5/64";
	bool debug = false;

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", router_ll_ip_subnet);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", host_ll_ip, neigh1_mac_str);

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp2T1", NULL },
			.local = false,
		},
		.local = {
			.name = "LOCAL",
			.intf = { NULL },
			.local = true,
		},
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = {
			.name		= "LOCAL_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_local = {
			.name		= "PRIV_TO_LOCAL",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * Test packet
	 *
	 * In this case the NPF_FLAG_FROM_US flag does *not* cause the BLOCK
	 * decision to be overidden in npf_apply_firewall.  The
	 * NPF_FLAG_FROM_LOCAL and NPF_FLAG_FROM_ZONE take priority, and the
	 * BLOCK decision is adhered to,
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		       IPTOS_CLASS_CS6, neigh1_mac_str, "33:33:ff:00:00:02",
		       "2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			   IPTOS_CLASS_CS6, dp_test_intf_name2mac_str("dp1T0"),
			   neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/* Clean Up */
	dpt_zone_cfg(&cfg, false, debug);

	dp_test_netlink_del_neigh("dp1T0", host_ll_ip, neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", router_ll_ip_subnet);
} DP_END_TEST;

/*
 * IPv6 ND, zone on interface, local zone.  No LOCAL_TO_PRIV ruleset.  The
 * implicit BLOCK is overridden in npf_get_zone_config.
 *
 * Inject an IPv6 Neighbor Solicitation pkt in order to generate a Neighbor
 * Advertisement pkt.
 */
DP_DECL_TEST_CASE(npf_local, npf_v6nbr6, NULL, NULL);
DP_START_TEST(npf_v6nbr6, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ns_pak;
	struct rte_mbuf *exp_na_pak;
	const char *neigh1_mac_str = "aa:bb:cc:dd:ee:10";
	const char *host_ll_ip = "fe80::409f:1ff:fee8:101";
	const char *router_ll_ip =        "fe80::5054:ff:fe79:3f5";
	const char *router_ll_ip_subnet = "fe80::5054:ff:fe79:3f5/64";
	bool debug = false;

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address("dp1T0", router_ll_ip_subnet);
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");

	/* And the neighbour for the return icmp packet */
	dp_test_netlink_add_neigh("dp1T0", host_ll_ip, neigh1_mac_str);

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp2T1", NULL },
			.local = false,
		},
		.local = {
			.name = "LOCAL",
			.intf = { NULL },
			.local = true,
		},
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = {
			.name		= "PRIV_TO_LOCAL",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * Test packet
	 */
	ns_pak = dp_test_create_ns_pak(host_ll_ip, "ff02::1:ff00:2",
		       IPTOS_CLASS_CS6, neigh1_mac_str, "33:33:ff:00:00:02",
		       "2001:1:1::1");

	/*
	 * Expected packet
	 */
	exp_na_pak = dp_test_create_na_pak(router_ll_ip, host_ll_ip,
			   IPTOS_CLASS_CS6, dp_test_intf_name2mac_str("dp1T0"),
			   neigh1_mac_str, "2001:1:1::1");

	exp = dp_test_exp_create(exp_na_pak);
	rte_pktmbuf_free(exp_na_pak);

	/* Set test expectations */
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run test */
	dp_test_pak_receive(ns_pak, "dp1T0", exp);

	/* Clean Up */
	dpt_zone_cfg(&cfg, false, debug);

	dp_test_netlink_del_neigh("dp1T0", host_ll_ip, neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_netlink_del_ip_address("dp1T0", router_ll_ip_subnet);
} DP_END_TEST;

/*
 * ICMP originated packets with the originate firewall.
 *
 * Test generate ICMP message upon packet too big with don't fragment
 * flag set (from dp_test_ip_icmp.c, DP_START_TEST(ip_icmp, df))
 *
 * Two ICMP packets are generated.  First one is allowed out via a PASS rule.
 * Second one is dropped by a BLOCK rule.
 *
 * Exercises the ip_output code path.
 */
DP_DECL_TEST_CASE(npf_local, npf_icmp_orig1, NULL, NULL);
DP_START_TEST(npf_icmp_orig1, test)
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

	/* Add originate firewall rule */
	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "1",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto-base=1",
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "originate",
		.name   = "FW_ORIG",
		.enable = 1,
		.attach_point = "dp3T3",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("2.2.2.1", "1.1.1.2", 1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp3T3"),
				       neigh3_mac_str, RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("2.2.2.2", "2.2.2.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen, iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh3_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);

	/* The TTL allowed to be changed from the original */
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp3T3");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp3T3", exp);

	/*
	 * Repeat
	 */
	dp_test_npf_fw_del(&fw, false);
	rules[0].pass = BLOCK;
	dp_test_npf_fw_add(&fw, false);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("2.2.2.1", "1.1.1.2", 1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp3T3"),
				       neigh3_mac_str, RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("2.2.2.2", "2.2.2.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen, iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh3_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);

	/* The TTL allowed to be changed from the original */
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp3T3");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp3T3", exp);


	/* Clean Up */
	dp_test_npf_fw_del(&fw, false);

	dp_test_netlink_del_neigh("dp3T3", "2.2.2.1", neigh3_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;

/*
 * ICMP originated packets with egress ACLs.
 *
 * Test generate ICMP message upon packet too big with don't fragment
 * flag set (from dp_test_ip_icmp.c, DP_START_TEST(ip_icmp, df))
 *
 * Two ICMP packets are generated.  First one is allowed out via a PASS rule.
 * Second one is dropped by a BLOCK rule.
 *
 * Exercises the ip_output code path.
 */
DP_DECL_TEST_CASE(npf_local, npf_icmp_orig2, NULL, NULL);
DP_START_TEST(npf_icmp_orig2, test)
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

	/* Add egress ACL */
	dp_test_npf_cmd("npf-ut add acl:v4test 0 family=inet", false);
	dp_test_npf_cmd("npf-ut add acl:v4test 10 "
			"proto-base=1 "
			"action=accept", false);
	dp_test_npf_cmd("npf-ut attach interface:dpT33 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut commit", false);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("2.2.2.1", "1.1.1.2", 1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp3T3"),
				       neigh3_mac_str, RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("2.2.2.2", "2.2.2.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen, iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh3_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);

	/* The TTL allowed to be changed from the original */
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp3T3");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp3T3", exp);

	/*
	 * Repeat
	 */
	dp_test_npf_cmd("npf-ut add acl:v4test 10 "
			"proto-base=1 "
			"action=drop", false);
	dp_test_npf_cmd("npf-ut commit", false);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("2.2.2.1", "1.1.1.2", 1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp3T3"),
				       neigh3_mac_str, RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("2.2.2.2", "2.2.2.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen, iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh3_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);

	/* The TTL allowed to be changed from the original */
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp3T3");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp3T3", exp);


	/* Clean Up */
	dp_test_npf_cmd("npf-ut detach interface:dpT33 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

	dp_test_netlink_del_neigh("dp3T3", "2.2.2.1", neigh3_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
} DP_END_TEST;
