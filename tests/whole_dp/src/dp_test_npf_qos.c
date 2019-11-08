/**
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * @file dp_test_npf_qos.h
 * @brief Dataplane unit-tests for npf QoS
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
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_intf.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"


DP_DECL_TEST_SUITE(npf_qos);

DP_DECL_TEST_CASE(npf_qos, qos_ipv4, NULL, NULL);

/*
 * Match on ICMP type and code
 *
 *                  1.1.1.1 +-----+ 2.2.2.2
 *                          |     |
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 */
DP_START_TEST(qos_ipv4, test1)
{
	struct dp_test_pkt_desc_t *pdesc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");

	struct dp_test_pkt_desc_t v4_pkt_desc = {
		.text       = "TCP IPv4",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
				.dport = 1001,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pdesc = &v4_pkt_desc;

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATELESS,
			.npf = "rproc=policer(1,0,0,drop,,0,1000)"
		},
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	/* Setup firewall */
	dp_test_npf_fw_add(&fw, false);

	/*
	 * First packet is forwarded
	 */
	test_pak = dp_test_v4_pkt_from_desc(&v4_pkt_desc);
	test_exp = dp_test_exp_from_desc(test_pak, pdesc);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pdesc->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/*
	 * Second packet is dropped as the pps has been exceeded.
	 * Firewall rule pkt count will still be incremented
	 */
	test_pak = dp_test_v4_pkt_from_desc(&v4_pkt_desc);
	test_exp = dp_test_exp_from_desc(test_pak, pdesc);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pdesc->rx_intf, test_exp);

	/* Verify */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");

} DP_END_TEST;
