/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane bridge Firewall tests
 */

#include <libmnl/libmnl.h>
#include <netinet/ip_icmp.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "ether.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_lib.h"


DP_DECL_TEST_SUITE(npf_bridge);

DP_DECL_TEST_CASE(npf_bridge, bridge_fwd, NULL, NULL);

/*
 * Tests packets bridges from dp1T0 to dp21, matching on ether-type, source
 * MAC and dest MAC.
 *
 *                          +-----+
 *                          |     |
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 */
DP_START_TEST(bridge_fwd, test1)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *mac_a = "00:00:a4:00:00:aa";
	const char *mac_b = "00:00:a4:00:00:bb";
	const char *mac_c = "00:00:a4:00:00:cc";
	const char *mac_d = "00:00:a4:00:00:dd";
	char npf10[60];
	char npf20[60];
	char npf30[60];
	int len = 50;

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

	spush(npf10, sizeof(npf10),
	      "ether-type=%u", DP_TEST_ET_ATALK);

	spush(npf20, sizeof(npf20),
	      "src-mac=%s", mac_a);

	spush(npf30, sizeof(npf30),
	      "dst-mac=%s", mac_b);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf10
		},
		{
			.rule     = "20",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf20
		},
		{
			.rule     = "30",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf30
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "bridge",
		.name   = "FW_BR",
		.enable = 1,
		.attach_point   = "br1",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	/*
	 * Packet 1: Bridge packet from dp1T0 to dp2T1.  Expect an "accept"
	 * with bridge firewall rule 10 (matching ether type).
	 */
	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
					 DP_TEST_ET_ATALK, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to receive on the tx ring. Transparent
	 * bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[2].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[3].rule, 0);
	dp_test_npf_clear("bridge");

	/*
	 * Packet 2: Bridge packet from dp1T0 to dp2T1. Expect an "accept"
	 * with bridge firewall rule 20 (matching source MAC).
	 */
	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
					 DP_TEST_ET_LLDP, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to receive on the tx ring. Transparent
	 * bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 1);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[2].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[3].rule, 0);
	dp_test_npf_clear("bridge");

	/*
	 * Packet 3: Bridge packet from dp1T0 to dp2T1. Expect an "accept"
	 * with bridge firewall rule 30 (matching dest MAC).
	 */
	test_pak = dp_test_create_l2_pak(mac_b, mac_c,
					 DP_TEST_ET_LLDP, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to receive on the tx ring. Transparent
	 * bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[2].rule, 1);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[3].rule, 0);
	dp_test_npf_clear("bridge");

	/*
	 * Packet 4: Bridge packet from dp1T0 to dp2T1. Expect to hit default
	 * block rule.
	 */
	test_pak = dp_test_create_l2_pak(mac_d, mac_c,
					 DP_TEST_ET_LLDP, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to receive on the tx ring. Transparent
	 * bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[2].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[3].rule, 1);
	dp_test_npf_clear("bridge");

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_del("br1");

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_bridge, bridge_local, NULL, NULL);

/*
 * Tests packets destined to the bridge IP address.
 *
 *  We test with bridge firewall, assigned 'l2' on bridge br1.
 *
 *                          +-----+
 *                          |     |
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 */
DP_START_TEST(bridge_local, to)
{
	struct dp_test_expected *exp;
	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *test_pak;
	char npf10[60];
	char npf20[60];
	char npf30[60];

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

	dp_test_nl_add_ip_addr_and_connected("br1", "10.0.1.1/24");
	dp_test_netlink_add_neigh("br1", "10.0.1.2", "aa:bb:cc:dd:1:a1");

	/*
	 * Bridge firewall, assigned on br1
	 */
	spush(npf10, sizeof(npf10),
	      "ether-type=%u", ETHER_TYPE_IPv4);

	spush(npf20, sizeof(npf20),
	      "src-mac=%s", "aa:bb:cc:dd:01:a1");

	spush(npf30, sizeof(npf30),
	      "dst-mac=%s", "aa:bb:cc:dd:02:a2");

	struct dp_test_npf_rule_t rules_br[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf10
		},
		{
			.rule     = "20",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf20
		},
		{
			.rule     = "30",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf30
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw_br = {
		.rstype = "bridge",
		.name   = "FW_BR",
		.enable = 1,
		.attach_point   = "br1",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules_br
	};

	dp_test_npf_fw_add(&fw_br, false);

	/*
	 * Packet 1: TCP packet from nbr1 to nbr2.  Expect this to be
	 * forwarded, and to hit (pass) the bridge firewall rule 10.
	 */
	struct dp_test_pkt_desc_t v4_pktA = {
		.text       = "Neighbour 1 -> Neighbour 2",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.0.1.3",
		.l2_dst     = "aa:bb:cc:dd:2:a2",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pktA;

	test_pak = dp_test_bridge_pkt_from_desc(pkt);

	/*
	 * Create pak we expect to receive on the tx ring. Transparent
	 * bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, pkt->tx_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[0].rule, 1);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[1].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[2].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[3].rule, 0);

	dp_test_npf_clear("bridge");

	/*
	 * Packet 2: TCP packet from nbr1 to bridge IP address.  We expect
	 * this to be seen by both the bridge firewall and the normal firewall
	 * on the bridge interface.
	 */
	struct dp_test_pkt_desc_t v4_pktB = {
		.text       = "Neighbour 1 -> Bridge IP address",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.0.1.1",
		.l2_dst     = NULL,
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "br1",
		.tx_intf    = "dp1T0"
	};
	pkt = &v4_pktB;

	/*
	 * Use dp_test_rt_pkt_from_desc so that the dest MAC is set to the
	 * bridge interface MAC, but inject the packet onto the bridge port,
	 * dp1T0.
	 */
	test_pak = dp_test_rt_pkt_from_desc(pkt);

	/*
	 * Create pak we expect to receive. Transparent bridging so we expect
	 * pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);

	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * bridge_input checks the bridge firewall *before* looking for local
	 * packets
	 */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[0].rule, 1);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[1].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[2].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[3].rule, 0);

	/* Cleanup */
	dp_test_npf_fw_del(&fw_br, false);

	dp_test_netlink_del_neigh("br1", "10.0.1.2", "aa:bb:cc:dd:1:a1");
	dp_test_nl_del_ip_addr_and_connected("br1", "10.0.1.1/24");

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_del("br1");

} DP_END_TEST;

/*
 * Tests packets originated from the kernel or forwarded (routed or bridged)
 * by the kernel, and destined to either a bridge interface or bridge port.
 *
 * Note, we dont test IP packet from kernel, sent out on bridge interface via
 * the path shown below.  Whilst the code handles this case, it it not thought
 * to occur in practise so the corresponding test has been removed.
 *
 *   tap_reader/gre_reader
 *   ip_spath_output
 *   if_output("br1")
 *   bridge_output
 *   if_output("dp1T0")
 *
 *                          +-----+
 *                          |     |
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 */
DP_START_TEST(bridge_local, from)
{
	struct dp_test_expected *exp;
	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *test_pak;
	char npf10[60];
	char npf20[60];
	char npf30[60];

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");

	dp_test_nl_add_ip_addr_and_connected("br1", "10.0.1.1/24");
	dp_test_netlink_add_neigh("br1", "10.0.1.2", "aa:bb:cc:dd:1:a1");

	/*
	 * Bridge firewall
	 */
	spush(npf10, sizeof(npf10),
	      "ether-type=%u", ETHER_TYPE_IPv4);

	spush(npf20, sizeof(npf20),
	      "src-mac=%s", "aa:bb:cc:dd:01:a1");

	spush(npf30, sizeof(npf30),
	      "dst-mac=%s", "aa:bb:cc:dd:02:a2");

	struct dp_test_npf_rule_t rules_br[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf10
		},
		{
			.rule     = "20",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf20
		},
		{
			.rule     = "30",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf30
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw_br = {
		.rstype = "bridge",
		.name   = "FW_BR",
		.enable = 1,
		.attach_point   = "br1",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules_br
	};

	dp_test_npf_fw_add(&fw_br, false);

	/*
	 * Packet 1: TCP packet received on dp1T0..  This is used to add v4n1
	 * MAC address to the bridge MAC table.  We specify a tx_intf as a lot
	 * of the infra expects that (even though we know the okt will be
	 * dropped).
	 */
	struct dp_test_pkt_desc_t v4_pktA = {
		.text       = "Neighbour 1 -> Neighbour 2",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.0.1.3",
		.l2_dst     = "aa:bb:cc:dd:2:a2",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pktA;

	test_pak = dp_test_bridge_pkt_from_desc(pkt);

	/*
	 * There is only one bridge port, so the effect will be that the packet
	 * is "dropped" from the UT point-of-view.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, pkt->tx_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[0].rule, 1);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[1].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[2].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[3].rule, 0);

	dp_test_npf_clear("bridge");

	/*
	 * Pkt 2: IP packet from the kernel, with the bridge port as dest
	 * interface.  This emulates packets bridged by the kernel.  Packet
	 * path is:
	 *
	 *   tap_reader/gre_reader
	 *   ip_spath_output
	 *   if_output("dp1T0")
	 *
	 * We dont expect this to hit *any* firewalls.
	 */
	struct dp_test_pkt_desc_t v4_pktC = {
		.text       = "Neighbour 2 -> Neighbour 1",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.0.1.3",
		.l2_src     = "aa:bb:cc:dd:2:a2",
		.l3_dst     = "10.0.1.2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = NULL,
		.tx_intf    = "dp1T0"
	};
	pkt = &v4_pktC;

	test_pak = dp_test_bridge_pkt_from_desc(pkt);

	/*
	 * Create pak we expect to receive. Transparent bridging so we expect
	 * pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_send_slowpath_pkt(test_pak, exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[1].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[2].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[3].rule, 0);

	dp_test_npf_clear("bridge");

	/*
	 * Pkt 3: ARP packet from the kernel, with the bridge port as dest
	 * interface.  This emulates ARP packets that for flooded to all ports
	 * by the kernel bridge. Packet path is:
	 *
	 *   tap_reader/gre_reader
	 *   if_output("dp1T0")
	 *
	 * We dont expect this to hit *any* firewalls.  The majority (only?)
	 * non-IPv4/IPv6 traffic that is expected to use this path is ARP and
	 * Spanning Tree.
	 */
	int len = 50;

	test_pak = dp_test_create_l2_pak(
		"FF:FF:FF:FF:FF:FF",
		dp_test_intf_name2mac_str("br1"),
		ETHER_TYPE_ARP, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to receive. Transparent bridging so we expect
	 * pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_send_slowpath_pkt(test_pak, exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[1].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[2].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw_br, fw_br.rules[3].rule, 0);

	dp_test_npf_clear("bridge");

	/* Cleanup */
	dp_test_npf_fw_del(&fw_br, false);

	dp_test_netlink_del_neigh("br1", "10.0.1.2", "aa:bb:cc:dd:1:a1");
	dp_test_nl_del_ip_addr_and_connected("br1", "10.0.1.1/24");

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_del("br1");


} DP_END_TEST;

/*
 * Test l2 multicast frames
 *
 * . link local multicast should not hit the l2 firewall.
 * . non link local multicast should hit the l2 firewall.
 * . broadcast should hit the l2 firewall.
 *
 * Firewall rule is Apple talk should pass, else drop.
 *
 *                          +-----+
 *                          |     |
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd_multi, NULL, NULL);
DP_START_TEST(bridge_fwd_multi, bridge_fwd_multi)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *mac_src = "00:00:a4:00:00:aa";
	const char *mac_link_local_multi = "01:80:c2:00:00:03";
	const char *mac_global_multi = "01:00:5e:00:ca:fe";
	const char *mac_broadcast = "ff:ff:ff:ff:ff:ff";
	char npf10[60];
	int len = 50;

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

	spush(npf10, sizeof(npf10),
	      "ether-type=%u", DP_TEST_ET_ATALK);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = npf10
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "bridge",
		.name   = "FW_BR",
		.enable = 1,
		.attach_point   = "br1",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	/*
	 * Packet 1: link local apple talk, should not hit firewall.
	 */
	test_pak = dp_test_create_l2_pak(mac_link_local_multi, mac_src,
					 DP_TEST_ET_ATALK, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to receive on the slowpath. Transparent
	 * bridging so we expect pak to be identical in VR
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 0);
	dp_test_npf_clear("bridge");

	/*
	 * Packet 2: link local banyan, should not hit firewall.
	 */
	test_pak = dp_test_create_l2_pak(mac_link_local_multi, mac_src,
					 DP_TEST_ET_LLDP, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to receive on the slowpath. Transparent
	 * bridging so we expect pak to be identical in VR
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 0);
	dp_test_npf_clear("bridge");

	/*
	 * Packet 3: global apple talk, should hit firewall and pass.
	 */
	test_pak = dp_test_create_l2_pak(mac_global_multi, mac_src,
					 DP_TEST_ET_ATALK, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	exp = dp_test_exp_create_m(test_pak, 1);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 0);
	dp_test_npf_clear("bridge");

	/*
	 * Packet 4: global banyan, should hit firewall and drop.
	 */
	test_pak = dp_test_create_l2_pak(mac_global_multi, mac_src,
					 DP_TEST_ET_LLDP, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to receive on the slowpath. Transparent
	 * bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 1);
	dp_test_npf_clear("bridge");

	/*
	 * Packet 5: broadcast apple talk, should hit firewall and pass.
	 */
	test_pak = dp_test_create_l2_pak(mac_broadcast, mac_src,
					 DP_TEST_ET_ATALK, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/* We expect the dataplane to flood to member ports */
	exp = dp_test_exp_create_m(test_pak, 1);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 0);
	dp_test_npf_clear("bridge");

	/*
	 * Packet 6: broadcast banyan, should hit firewall and drop.
	 */
	test_pak = dp_test_create_l2_pak(mac_broadcast, mac_src,
					 DP_TEST_ET_LLDP, 1, &len);
	dp_test_fail_unless(test_pak, "Failed to create l2 pak");

	/*
	 * Create pak we expect to drop. Transparent bridging so we expect pak
	 * to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 0);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 1);
	dp_test_npf_clear("bridge");

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_del("br1");

} DP_END_TEST;


/*
 * Test traffic to/from router interface from/to bridge interface, with
 * input or output firewall on routed interface.
 *
 * Tests stateful and stateless firewalls.  Tests with UDP and ICMP traffic.
 *
 *                          +-----+
 *                    router|     | bridge
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp1T1
 *                          +-----+
 */

enum test_fw {
	TEST_FW_ADD,
	TEST_FW_REMOVE,
	TEST_FW_VERIFY
};

struct dp_test_bridge_ctx {
	bool         stateful;
	bool         in;
	uint         proto;  /* 1 for ICMP, 6 for TCP, or 17 for UDP */
	uint         fw_count;
};

static void
dp_test_npf_fw1(enum test_fw action, const struct dp_test_bridge_ctx *ctx)
{
	char proto_str[40];

	snprintf(proto_str, sizeof(proto_str), "proto=%u", ctx->proto);

	/* UDP */
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = ctx->stateful,
			.npf      = proto_str
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = ctx->in ? "fw-in" : "fw-out",
		.name   = ctx->in ? "FW1_IN" : "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = ctx->in ? "in" : "out",
		.rules  = rset
	};

	if (action == TEST_FW_ADD)
		dp_test_npf_fw_add(&fw, false);

	if (action == TEST_FW_REMOVE)
		dp_test_npf_fw_del(&fw, false);

	if (action == TEST_FW_VERIFY)
		dp_test_npf_verify_rule_pkt_count(NULL, &fw,
						  fw.rules[0].rule,
						  ctx->fw_count);
}

/*
 * Input firewall rule.  Allows UDP.  Blocks everything else.
 */
static void dp_test_npf_1(const struct dp_test_bridge_ctx *ctx)
{
	struct dp_test_expected *test_exp;
	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T1");
	dp_test_nl_add_ip_addr_and_connected("br1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("br1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_npf_fw1(TEST_FW_ADD, ctx);

	struct ether_addr *br1_eth;
	char real_ifname[IFNAMSIZ];
	char br1_eth_str[ETH_ADDR_STR_LEN];

	dp_test_intf_real("br1", real_ifname);
	br1_eth = dp_test_intf_name2mac(real_ifname);
	ether_ntoa_r(br1_eth, br1_eth_str);

	/*
	 * UDP packet
	 */
	struct dp_test_pkt_desc_t udp_pkt1 = {
		.text       = "pkt1",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};
	pkt = &udp_pkt1;

	if (ctx->proto == 6 || ctx->proto == 17) {
		pkt->proto = ctx->proto;
		pkt->l4.udp.sport = 0xDEAD;
		pkt->l4.udp.dport = 0xBEEF;
	} else {
		pkt->proto = 1; /* ICMP */
		pkt->l4.icmp.type = 8; /* echo-request */
		pkt->l4.icmp.code = 0;
	}

	/* use "br1" so that src mac is correct */
	pkt->tx_intf = "br1";

	test_pak = dp_test_v4_pkt_from_desc(pkt);

	test_exp = dp_test_exp_from_desc(test_pak, pkt);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name(test_exp, "dp1T1");

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_fw1(TEST_FW_VERIFY, ctx);

	if (ctx->stateful == STATELESS)
		dp_test_npf_session_count_verify(0);
	else
		dp_test_npf_session_verify_desc(NULL, pkt, "dp1T0",
						SE_ACTIVE, SE_FLAGS_AE, true);

	struct dp_test_pkt_desc_t udp_pkt2 = {
		.text       = "pkt2",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "2.2.2.11",
		.l2_src     = "aa:bb:cc:dd:2:11",
		.l3_dst     = "1.1.1.11",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};
	pkt = &udp_pkt2;

	if (ctx->proto == 6 || ctx->proto == 17) {
		pkt->proto = ctx->proto;
		pkt->l4.udp.sport = 0xBEEF;
		pkt->l4.udp.dport = 0xDEAD;
	} else {
		pkt->proto = 1; /* ICMP */
		pkt->l4.icmp.type = 0; /* echo-reply */
		pkt->l4.icmp.code = 0;
	}

	/* Set rx_inf to br1 so that dest mac is bridge mac */
	pkt->rx_intf = "br1";
	test_pak = dp_test_v4_pkt_from_desc(pkt);

	test_exp = dp_test_exp_from_desc(test_pak, pkt);
	pkt->rx_intf = "dp1T1";

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Cleanup */
	dp_test_npf_fw1(TEST_FW_REMOVE, ctx);
	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("br1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("br1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_intf_bridge_remove_port("br1", "dp1T1");
	dp_test_intf_bridge_del("br1");
}


/*
 * Output firewall rule.  Allows UDP.  Blocks everything else.
 */
static void dp_test_npf_2(const struct dp_test_bridge_ctx *ctx)
{
	struct dp_test_expected *test_exp;
	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T1");
	dp_test_nl_add_ip_addr_and_connected("br1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("br1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_npf_fw1(TEST_FW_ADD, ctx);

	struct ether_addr *br1_eth;
	char real_ifname[IFNAMSIZ];
	char br1_eth_str[ETH_ADDR_STR_LEN];

	dp_test_intf_real("br1", real_ifname);
	br1_eth = dp_test_intf_name2mac(real_ifname);
	ether_ntoa_r(br1_eth, br1_eth_str);

	/*
	 * dp1T1 -> dp1T0
	 */
	struct dp_test_pkt_desc_t udp_pkt1 = {
		.text       = "UDP pkt1",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "2.2.2.11",
		.l2_src     = "aa:bb:cc:dd:2:11",
		.l3_dst     = "1.1.1.11",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};
	pkt = &udp_pkt1;

	if (ctx->proto == 6 || ctx->proto == 17) {
		pkt->proto = ctx->proto;
		pkt->l4.udp.sport = 0xBEEF;
		pkt->l4.udp.dport = 0xDEAD;
	} else {
		pkt->proto = 1; /* ICMP */
		pkt->l4.icmp.type = 8; /* echo-request */
		pkt->l4.icmp.code = 0;
	}

	/* Set rx_inf to br1 so that dest mac is bridge mac */
	pkt->rx_intf = "br1";
	test_pak = dp_test_v4_pkt_from_desc(pkt);

	test_exp = dp_test_exp_from_desc(test_pak, pkt);
	pkt->rx_intf = "dp1T1";

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_fw1(TEST_FW_VERIFY, ctx);

	if (ctx->stateful == STATELESS)
		dp_test_npf_session_count_verify(0);
	else
		dp_test_npf_session_verify_desc(NULL, pkt, "dp1T0",
						SE_ACTIVE, SE_FLAGS_AE, true);


	struct dp_test_pkt_desc_t udp_pkt2 = {
		.text       = "UDP pkt3",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};
	pkt = &udp_pkt2;

	if (ctx->proto == 6 || ctx->proto == 17) {
		pkt->proto = ctx->proto;
		pkt->l4.udp.sport = 0xDEAD;
		pkt->l4.udp.dport = 0xBEEF;
	} else {
		pkt->proto = 1; /* ICMP */
		pkt->l4.icmp.type = 0; /* echo-reply */
		pkt->l4.icmp.code = 0;
	}

	/* use "br1" so that src mac is correct */
	pkt->tx_intf = "br1";

	test_pak = dp_test_v4_pkt_from_desc(pkt);

	test_exp = dp_test_exp_from_desc(test_pak, pkt);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name(test_exp, "dp1T1");

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/* Cleanup */
	dp_test_npf_fw1(TEST_FW_REMOVE, ctx);
	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("br1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("br1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_intf_bridge_remove_port("br1", "dp1T1");
	dp_test_intf_bridge_del("br1");
}


/*
 * dp1T0: routed; input firewall; stateless
 * dp1T1: bridged
 *
 * Pkt1: UDP, routed intf dp1T0 to bridge intf dp1T1
 * Pkt2: UDP, bridge intf dp1T1 to routed intf dp1T0
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd2, NULL, NULL);
DP_START_TEST(bridge_fwd2, test1)
{
	const struct dp_test_bridge_ctx ctx = {
		.stateful = STATELESS,
		.in       = true,
		.proto    = 17,
		.fw_count = 1
	};
	dp_test_npf_1(&ctx);
} DP_END_TEST;

/*
 * dp1T0: routed; input firewall; stateful
 * dp1T1: bridged
 *
 * Pkt1: UDP, routed intf dp1T0 to bridge intf dp1T1
 * Pkt2: UDP, bridge intf dp1T1 to routed intf dp1T0
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd3, NULL, NULL);
DP_START_TEST(bridge_fwd3, test1)
{
	const struct dp_test_bridge_ctx ctx = {
		.stateful = STATEFUL,
		.in       = true,
		.proto    = 17,
		.fw_count = 1
	};
	dp_test_npf_1(&ctx);
} DP_END_TEST;

/*
 * dp1T0: routed; output firewall; stateless
 * dp1T1: bridged
 *
 * Pkt1: UDP, bridge intf dp1T1 to routed intf dp1T0
 * Pkt2: UDP, routed intf dp1T0 to bridge intf dp1T1
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd4, NULL, NULL);
DP_START_TEST(bridge_fwd4, test1)
{
	const struct dp_test_bridge_ctx ctx = {
		.stateful = STATELESS,
		.in       = false,
		.proto    = 17,
		.fw_count = 1
	};
	dp_test_npf_2(&ctx);
} DP_END_TEST;

/*
 * dp1T0: routed; output firewall; stateful
 * dp1T1: bridged
 *
 * Pkt1: UDP, bridge intf dp1T1 to routed intf dp1T0
 * Pkt2: UDP, routed intf dp1T0 to bridge intf dp1T1
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd5, NULL, NULL);
DP_START_TEST(bridge_fwd5, test1)
{
	const struct dp_test_bridge_ctx ctx = {
		.stateful = STATEFUL,
		.in       = false,
		.proto    = 17,
		.fw_count = 1
	};
	dp_test_npf_2(&ctx);
} DP_END_TEST;

/*
 * ICMP echo-request and echo-reply
 */

/*
 * dp1T0: routed; input firewall; stateless
 * dp1T1: bridged
 *
 * Pkt1: ICMP echo-request, routed intf dp1T0 to bridge intf dp1T1
 * Pkt2: ICMP echo-reply,   bridge intf dp1T1 to routed intf dp1T0
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd6, NULL, NULL);
DP_START_TEST(bridge_fwd6, test1)
{
	const struct dp_test_bridge_ctx ctx = {
		.stateful = STATELESS,
		.in       = true,
		.proto    = 1,
		.fw_count = 1
	};
	dp_test_npf_1(&ctx);
} DP_END_TEST;

/*
 * dp1T0: routed; input firewall; stateful
 * dp1T1: bridged
 *
 * Pkt1: ICMP echo-request, routed intf dp1T0 to bridge intf dp1T1
 * Pkt2: ICMP echo-reply,   bridge intf dp1T1 to routed intf dp1T0
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd7, NULL, NULL);
DP_START_TEST(bridge_fwd7, test1)
{
	const struct dp_test_bridge_ctx ctx = {
		.stateful = STATEFUL,
		.in       = true,
		.proto    = 1,
		.fw_count = 1
	};
	dp_test_npf_1(&ctx);
} DP_END_TEST;

/*
 * dp1T0: routed; output firewall; stateless
 * dp1T1: bridged
 *
 * Pkt1: ICMP echo-request, bridge intf dp1T1 to routed intf dp1T0
 * Pkt2: ICMP echo-reply,   routed intf dp1T0 to bridge intf dp1T1
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd8, NULL, NULL);
DP_START_TEST(bridge_fwd8, test1)
{
	const struct dp_test_bridge_ctx ctx = {
		.stateful = STATELESS,
		.in       = false,
		.proto    = 1,
		.fw_count = 1
	};
	dp_test_npf_2(&ctx);
} DP_END_TEST;

/*
 * dp1T0: routed; output firewall; stateful
 * dp1T1: bridged
 *
 * Pkt1: ICMP echo-request, bridge intf dp1T1 to routed intf dp1T0
 * Pkt2: ICMP echo-reply,   routed intf dp1T0 to bridge intf dp1T1
 */
DP_DECL_TEST_CASE(npf_bridge, bridge_fwd9, NULL, NULL);
DP_START_TEST(bridge_fwd9, test1)
{
	const struct dp_test_bridge_ctx ctx = {
		.stateful = STATEFUL,
		.in       = false,
		.proto    = 1,
		.fw_count = 1
	};
	dp_test_npf_2(&ctx);
} DP_END_TEST;

