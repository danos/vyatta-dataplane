/*
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
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
#include "dp_test_lib.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"


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
		.ether_type = ETHER_TYPE_IPv4,
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
		.ether_type = ETHER_TYPE_IPv4,
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
		.ether_type = ETHER_TYPE_IPv4,
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
