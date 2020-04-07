/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane ICMP Firewall tests
 */

#include <libmnl/libmnl.h>
#include <netinet/ip_icmp.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf_state.h"

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
#include "dp_test_npf_nat_lib.h"


struct dp_test_npf_icmp_t {
	/* DP_TEST_FWD_FORWARDED or DP_TEST_FWD_DROPPED */
	enum dp_test_fwd_result_e fwd_status;

	uint8_t icmp_type;
	uint8_t icmp_code;

	/** ICMP type specific field */
	union {
		uint32_t udata32;
		uint16_t udata16[2];
		uint8_t  udata8[4];
	};
	const char *npf;
};


DP_DECL_TEST_SUITE(npf_icmp);

DP_DECL_TEST_CASE(npf_icmp, icmp_ipv4, NULL, NULL);

/*
 * Match on ICMP type and code
 *
 *                  1.1.1.1 +-----+ 2.2.2.2
 *                          |     |
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 */
DP_START_TEST(icmp_ipv4, test1)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	uint i;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");

	struct dp_test_pkt_desc_t v4_pkt = {
		.text       = "ICMP IPv4",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = 0,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt;

	/*
	 * See vplane-config-npf/yang/vyatta-fw-types-v1.yang for list of
	 * supported names
	 *
	 *				Type	Code
	 *				-	-
	 * echo-reply			0	-
	 * destination-unreachable	3	-
	 * network-unreachable		3	0
	 * host-unreachable		3	1
	 * protocol-unreachable		3	2
	 * port-unreachable		3	3
	 * fragmentation-needed		3	4
	 * source-quench		4	-
	 * echo-request			8	-
	 * router-advertisement		9	-
	 */
	struct dp_test_npf_icmp_t npf_ipv4_icmp[] = {
		{
			.fwd_status = DP_TEST_FWD_FORWARDED,
			.icmp_type = 8,
			.icmp_code = 0,
			{
				.dpt_icmp_id = 0,
				.dpt_icmp_seq = 0,
			},
			.npf = "proto=1 icmpv4=8"
		},
		{
			.fwd_status = DP_TEST_FWD_FORWARDED,
			.icmp_type = 8,
			.icmp_code = 0,
			{
				.dpt_icmp_id = 0,
				.dpt_icmp_seq = 0,
			},
			.npf = "proto=1 icmpv4=echo-request"
		},
		{
			.fwd_status = DP_TEST_FWD_FORWARDED,
			.icmp_type = 3,
			.icmp_code = 3,
			{
				.udata32 = 0
			},
			"proto=1 icmpv4=3:3"
		},
		{
			.fwd_status = DP_TEST_FWD_FORWARDED,
			.icmp_type = 3,
			.icmp_code = 3,
			{
				.udata32 = 0
			},
			"proto=1 icmpv4=port-unreachable"
		},
		{
			.fwd_status = DP_TEST_FWD_DROPPED,
			.icmp_type = 3,
			.icmp_code = 2,
			{
				.udata32 = 0
			},
			"proto=1 icmpv4=3:3"
		},
		{
			.fwd_status = DP_TEST_FWD_DROPPED,
			.icmp_type = 3,
			.icmp_code = 2,
			{
				.udata32 = 0
			},
			"proto=1 icmpv4=port-unreachable"
		},
	};

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = NULL},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	/*
	 * Run the test for npf each rule
	 */
	for (i = 0; i < ARRAY_SIZE(npf_ipv4_icmp); i++) {
		/* Setup firewall */
		fw.rules[0].npf = npf_ipv4_icmp[i].npf;
		dp_test_npf_fw_add(&fw, false);

		/* Adjust packet */
		pkt->l4.icmp.type = npf_ipv4_icmp[i].icmp_type;
		pkt->l4.icmp.code = npf_ipv4_icmp[i].icmp_code;
		pkt->l4.icmp.udata32 = npf_ipv4_icmp[i].udata32;

		test_pak = dp_test_v4_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_ipv4_icmp[i].fwd_status);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%u: %s", i, npf_ipv4_icmp[i].npf);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify firewall packet count */
		dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule,
					   npf_ipv4_icmp[i].fwd_status ==
					   DP_TEST_FWD_FORWARDED ? 1 : 0);

		dp_test_npf_fw_del(&fw, false);
	}

	/* Cleanup */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");

} DP_END_TEST;


/*
 * ICMP groups, accept packets specified by the firewall
 */
DP_START_TEST(icmp_ipv4, test2)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * echo-reply (0)
	 * source-quench (4)
	 * echo-request (8)
	 */
	dp_test_npf_cmd("npf-ut add icmp-group:ICMP1 0 0;source-quench",
			false);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto=1 icmpv4-group=ICMP1"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dp_test_pkt_desc_t v4_pkt = {
		.text       = "ICMP IPv4",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = 0,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/*
	 * Change icmp type to 4
	 */
	pkt->l4.icmp.type = 4;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);

	/*
	 * Change icmp type to 9 (not in ICMP group)
	 */
	pkt->l4.icmp.type = 9;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 1);


	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_cmd("npf-ut delete icmp-group:ICMP1", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");

} DP_END_TEST;

/*
 * ICMP groups, drop packets specified by the firewall
 */
DP_START_TEST(icmp_ipv4, test3)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * echo-reply (0)
	 * source-quench (4)
	 * echo-request (8)
	 */
	dp_test_npf_cmd("npf-ut add icmp-group:ICMP1 0 0;source-quench",
			false);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto=1 icmpv4-group=ICMP1"},
		RULE_DEF_PASS,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dp_test_pkt_desc_t v4_pkt = {
		.text       = "ICMP IPv4",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = 0,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/*
	 * Change icmp type to source-quench (4)
	 */
	pkt->l4.icmp.type = 4;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);

	/*
	 * Change icmp type to 9 (not in ICMP group)
	 */
	pkt->l4.icmp.type = 9;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 1);



	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_cmd("npf-ut delete icmp-group:ICMP1", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_icmp, icmp_ipv6, NULL, NULL);

/*
 * Match on ICMP type and code
 *
 *                          +-----+
 *              2001:1:1::1 |     | 2002:2:2::2
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 *
 */
DP_START_TEST(icmp_ipv6, test1)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	uint i;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

	struct dp_test_pkt_desc_t v6_pkt = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = 0,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v6_pkt;

	/*
	 *				Type	Code
	 *				-	-
	 * protocol-unreachable		3	2
	 * port-unreachable		1	4
	 * echo-request			128	-
	 */
	struct dp_test_npf_icmp_t npf_ipv6_icmp[] = {
		{
			.fwd_status = DP_TEST_FWD_FORWARDED,
			.icmp_type = 128,
			.icmp_code = 0,
			{
				.dpt_icmp_id = 0,
				.dpt_icmp_seq = 0,
			},
			.npf = "proto=58 icmpv6=128"
		},
		{
			.fwd_status = DP_TEST_FWD_FORWARDED,
			.icmp_type = 128,
			.icmp_code = 0,
			{
				.dpt_icmp_id = 0,
				.dpt_icmp_seq = 0,
			},
			.npf = "proto=58 icmpv6=echo-request"
		},
		{
			.fwd_status = DP_TEST_FWD_FORWARDED,
			.icmp_type = 1,
			.icmp_code = 4,
			{
				.udata32 = 0
			},
			.npf = "proto=58 icmpv6=1:4"
		},
		{
			.fwd_status = DP_TEST_FWD_FORWARDED,
			.icmp_type = 1,
			.icmp_code = 4,
			{
				.udata32 = 0
			},
			.npf = "proto=58 icmpv6=port-unreachable"
		},
		{
			.fwd_status = DP_TEST_FWD_DROPPED,
			.icmp_type = 1,
			.icmp_code = 5,
			{
				.udata32 = 0
			},
			.npf = "proto=58 icmpv6=1:4"
		},
		{
			.fwd_status = DP_TEST_FWD_DROPPED,
			.icmp_type = 1,
			.icmp_code = 5,
			{
				.udata32 = 0
			},
			.npf = "proto=58 icmpv6=port-unreachable"
		},
	};

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = NULL},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	/*
	 * Run the test for npf each rule
	 */
	for (i = 0; i < ARRAY_SIZE(npf_ipv6_icmp); i++) {
		/* Setup firewall */
		fw.rules[0].npf = npf_ipv6_icmp[i].npf;
		dp_test_npf_fw_add(&fw, false);

		/* Adjust packet */
		pkt->l4.icmp.type = npf_ipv6_icmp[i].icmp_type;
		pkt->l4.icmp.code = npf_ipv6_icmp[i].icmp_code;
		pkt->l4.icmp.udata32 = npf_ipv6_icmp[i].udata32;

		test_pak = dp_test_v6_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);
		dp_test_exp_set_fwd_status(test_exp,
					   npf_ipv6_icmp[i].fwd_status);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify firewall packet count */
		dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule,
					   npf_ipv6_icmp[i].fwd_status ==
					   DP_TEST_FWD_FORWARDED ? 1 : 0);

		dp_test_npf_fw_del(&fw, false);
	}

	/* Cleanup */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

} DP_END_TEST;

/*
 * ICMP groups, accept packets specified by the firewall
 */
DP_START_TEST(icmp_ipv6, test2)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * echo-reply (0)
	 * echo-request (8)
	 */
	dp_test_npf_cmd("npf-ut add icmpv6-group:ICMP1 0 128;129", false);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto=58 icmpv6-group=ICMP1"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dp_test_pkt_desc_t v6_pkt = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = 128,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v6_pkt;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/*
	 * Change icmp type to 129
	 */
	pkt->l4.icmp.type = 129;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);


	/*
	 * Change icmp type to 131 (not in ICMP group)
	 */
	pkt->l4.icmp.type = 131;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 1);


	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_cmd("npf-ut delete icmpv6-group:ICMP1", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

} DP_END_TEST;

/*
 * ICMP groups, drop packets specified by the firewall
 */
DP_START_TEST(icmp_ipv6, test3)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * echo-reply (0)
	 * echo-request (8)
	 */
	dp_test_npf_cmd("npf-ut add icmpv6-group:ICMP1 0 128;129", false);

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto=58 icmpv6-group=ICMP1"},
		RULE_DEF_PASS,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dp_test_pkt_desc_t v6_pkt = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = 128,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v6_pkt;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/*
	 * Change icmp type
	 */
	pkt->l4.icmp.type = 129;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);


	/*
	 * Change icmp type to 131 (not in ICMP group)
	 */
	pkt->l4.icmp.type = 131;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify firewall packet count */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[1].rule, 1);


	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_cmd("npf-ut delete icmpv6-group:ICMP1", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

} DP_END_TEST;

/*
 * ICMP echo request and reply  with a stateful firewall rule
 */
DP_START_TEST(icmp_ipv4, test4)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");


	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	uint16_t test_icmp_id = 0xF00D;

	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHOREPLY,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHOREPLY,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/*
	 * Forwards
	 */
	pre = &ins_pre;
	post = &ins_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	dp_test_npf_session_verify(NULL, "100.101.102.103",
				   test_icmp_id,
				   "200.201.202.203",
				   test_icmp_id,
				   IPPROTO_ICMP,
				   "dp2T1",
				   SE_ACTIVE | SE_PASS,
				   SE_FLAGS_MASK, true);

	/*
	 * Backwards
	 */
	pre = &outs_pre;
	post = &outs_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);


	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;


/*
 * ICMPv6 echo request and reply  with a stateful firewall rule
 */
DP_START_TEST(icmp_ipv6, test4)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", "aa:bb:cc:dd:2:b1");

	struct dp_test_pkt_desc_t ins = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2002:2:2::1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:1:1::2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REPLY,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATEFUL,
			.npf      = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	/*
	 * Echo Request Forwards
	 */
	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *test_pak;
	struct dp_test_expected *test_exp;

	pkt = &ins;
	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_session_verify(NULL, "2001:1:1::2", 0,
				   "2002:2:2::1", 0,
				   IPPROTO_ICMPV6,
				   "dp2T1",
				   SE_ACTIVE | SE_PASS,
				   SE_FLAGS_MASK, true);

	/*
	 * Echo Reply Back
	 */
	pkt = &outs;
	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", "aa:bb:cc:dd:2:b1");

} DP_END_TEST;


/*
 * Strict ICMP echo request/response sessions
 *
 * It is not uncommon to use ICMP echo replies as a mechanism to evade
 * firewall systems.  So only allow a session to be created from an echo
 * request.
 *
 * Then enforce within that session that the forward packets must be echo
 * requests, and the reverse packets echo replies.
 */
DP_START_TEST(icmp_ipv4, test5)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");
	npf_state_set_icmp_strict(true);

	uint16_t test_icmp_id = 0xF00D;

	struct dp_test_pkt_desc_t ins = {
		.text       = "Inside",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs = {
		.text       = "Outside",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHOREPLY,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *test_pak;
	struct dp_test_expected *test_exp;

	/*
	 * Forwards echo reply.  Verify pkt dropped and no session created.
	 */
	pkt = &ins;
	pkt->l4.icmp.type = ICMP_ECHOREPLY;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Check session was not created */
	dp_test_npf_session_verify(NULL, "100.101.102.103",
				   test_icmp_id,
				   "200.201.202.203",
				   test_icmp_id,
				   IPPROTO_ICMP,
				   "dp2T1",
				   SE_ACTIVE | SE_PASS,
				   SE_FLAGS_MASK, false);

	/*
	 * Forwards echo request.  Verify pkt forwarded and session created.
	 */
	pkt = &ins;
	pkt->l4.icmp.type = ICMP_ECHO;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_session_verify(NULL, "100.101.102.103",
				   test_icmp_id,
				   "200.201.202.203",
				   test_icmp_id,
				   IPPROTO_ICMP,
				   "dp2T1",
				   SE_ACTIVE | SE_PASS,
				   SE_FLAGS_MASK, true);

	/*
	 * Backwards echo reply.  Verify pkt forwarded.
	 */
	pkt = &outs;
	pkt->l4.icmp.type = ICMP_ECHOREPLY;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/*
	 * Backwards echo request.  Verify pkt is dropped.
	 */
	pkt = &outs;
	pkt->l4.icmp.type = ICMP_ECHO;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/*
	 * Backwards echo request, non strict.  Verify pkt is passed.
	 */
	npf_state_set_icmp_strict(false);
	pkt = &outs;
	pkt->l4.icmp.type = ICMP_ECHO;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;


/*
 * Strict ICMP echo request/response sessions
 *
 * It is not uncommon to use ICMP echo replies as a mechanism to evade
 * firewall systems.  So only allow a session to be created from an echo
 * request.
 *
 * Then enforce within that session that the forward packets must be echo
 * requests, and the reverse packets echo replies.
 */
DP_START_TEST(icmp_ipv6, test5)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", "aa:bb:cc:dd:2:b1");
	npf_state_set_icmp_strict(true);

	struct dp_test_pkt_desc_t ins = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2002:2:2::1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:1:1::2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REPLY,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATEFUL,
			.npf      = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dp_test_pkt_desc_t *pkt;
	struct rte_mbuf *test_pak;
	struct dp_test_expected *test_exp;

	/*
	 * Forwards echo reply.  Verify pkt dropped and no session created.
	 */
	pkt = &ins;
	pkt->l4.icmp.type = ICMP6_ECHO_REPLY;

	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Check session was not created */
	dp_test_npf_session_verify(NULL, "2001:1:1::2", 0,
				   "2002:2:2::1", 0,
				   IPPROTO_ICMPV6,
				   "dp2T1",
				   SE_ACTIVE | SE_PASS,
				   SE_FLAGS_MASK, false);

	/*
	 * Forwards echo request.  Verify pkt forwarded and session created.
	 */
	pkt = &ins;
	pkt->l4.icmp.type = ICMP6_ECHO_REQUEST;

	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Check session was created */
	dp_test_npf_session_verify(NULL, "2001:1:1::2", 0,
				   "2002:2:2::1", 0,
				   IPPROTO_ICMPV6,
				   "dp2T1",
				   SE_ACTIVE | SE_PASS,
				   SE_FLAGS_MASK, true);

	/*
	 * Backwards echo reply.  Verify pkt forwarded.
	 */
	pkt = &outs;
	pkt->l4.icmp.type = ICMP6_ECHO_REPLY;

	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/*
	 * Backwards echo request.  Verify pkt is dropped.
	 */
	pkt = &outs;
	pkt->l4.icmp.type = ICMP6_ECHO_REQUEST;

	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/*
	 * Backwards echo request, non strict.  Verify pkt is passed.
	 */
	npf_state_set_icmp_strict(false);
	pkt = &outs;
	pkt->l4.icmp.type = ICMP6_ECHO_REQUEST;

	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", "aa:bb:cc:dd:2:b1");

} DP_END_TEST;


/*
 * ICMP echo request and reply with SNAT
 */
DP_START_TEST(icmp_ipv4, test6)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	uint16_t test_icmp_id = 0xF00D;
	uint16_t test_icmp_seq = 0;

	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = test_icmp_seq,
				},
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.2",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = test_icmp_seq,
				},
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "200.201.202.2",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHOREPLY,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = test_icmp_seq,
				},
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = ICMP_ECHOREPLY,
				.code = 0,
				{
					.dpt_icmp_id = test_icmp_id,
					.dpt_icmp_seq = test_icmp_seq,
				},
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	/*
	 * Add SNAT rule.  Translate src addr from the host1 inside addr
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_ICMP,
		.map		= "dynamic",
		.from_addr	= "100.101.102.103",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "200.201.202.2",
		.trans_port	= NULL};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * Validation context.  This validates the NAT session is correct
	 * *before* it checks the packet.
	 */
	struct dp_test_nat_ctx nat_context;
	struct dp_test_nat_ctx *nat_ctx = &nat_context;

	static struct dp_test_nat_cb_ctx cb_ctx = {
		.snat = NULL,
		.dnat = NULL,
		.saved_cb = dp_test_pak_verify
	};
	cb_ctx.snat = nat_ctx;
	memset(nat_ctx, 0, sizeof(*nat_ctx));

	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/*
	 * Forwards
	 */
	pre = &ins_pre;
	post = &ins_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);


	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/*
	 * Backwards
	 */
	pre = &outs_pre;
	post = &outs_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_BACK, DP_TEST_TRANS_SNAT,
			    pre, post, false);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);


	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_clear_sessions();
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;
