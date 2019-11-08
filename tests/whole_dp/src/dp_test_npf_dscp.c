/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane DSCP Firewall tests
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

/*
 * Network config is as follows for the tests:
 *
 * IPv4:
 *                  1.1.1.1 +-----+ 2.2.2.2
 *                          |     |
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 *
 * IPv6:
 *                          +-----+
 *              2001:1:1::1 |     | 2002:2:2::2
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 *
 */

struct dp_test_npf_dscp_t {
	/* DP_TEST_FWD_FORWARDED or DP_TEST_FWD_DROPPED */
	enum dp_test_fwd_result_e fwd_status;

	uint8_t dscp;

	const char *npf;
};

DP_DECL_TEST_SUITE(npf_dscp);

DP_DECL_TEST_CASE(npf_dscp, dscp_ipv4, NULL, NULL);
DP_DECL_TEST_CASE(npf_dscp, dscp_ipv6, NULL, NULL);

/*
 * Used for both IPv4 and IPv6 single tests.
 */
static struct dp_test_npf_dscp_t npf_dscp_single[] = {
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 63,
		.npf = "dscp=63"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 62,
		.npf = "dscp=63"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 53,
		.npf = "dscp=53"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 54,
		.npf = "dscp=53"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 31,
		.npf = "dscp=31"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 31,
		.npf = "dscp=32"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 1,
		.npf = "dscp=1"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 0,
		.npf = "dscp=1"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 0,
		.npf = "dscp=0"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 1,
		.npf = "dscp=0"
	},
};

/*
 * Match on single DSCP values - IPv4
 */
DP_START_TEST(dscp_ipv4, single_dscp)
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
		.text       = "DSCP IPv4 single",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = 100,
					.dpt_icmp_seq = 100,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt;

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = NULL
		},
		RULE_DEF_BLOCK,
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

	/*
	 * Run the test for npf each rule
	 */
	for (i = 0; i < ARRAY_SIZE(npf_dscp_single); i++) {
		/* Setup firewall */
		fw.rules[0].npf = npf_dscp_single[i].npf;
		dp_test_npf_fw_add(&fw, false);

		/* Adjust packet */
		pkt->traf_class = npf_dscp_single[i].dscp << 2;

		test_pak = dp_test_v4_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_dscp_single[i].fwd_status);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%u: %s", i, npf_dscp_single[i].npf);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify firewall packet count */
		dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule,
					   npf_dscp_single[i].fwd_status ==
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
 * Match on single DSCP values - IPv6
 */
DP_START_TEST(dscp_ipv6, single_dscp)
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
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{
					.dpt_icmp_id = 100,
					.dpt_icmp_seq = 100,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v6_pkt;

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = NULL
		},
		RULE_DEF_BLOCK,
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

	/*
	 * Run the test for npf each rule
	 */
	for (i = 0; i < ARRAY_SIZE(npf_dscp_single); i++) {
		/* Setup firewall */
		fw.rules[0].npf = npf_dscp_single[i].npf;
		dp_test_npf_fw_add(&fw, false);

		/* Adjust packet */
		pkt->traf_class = npf_dscp_single[i].dscp << 2;

		test_pak = dp_test_v6_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_dscp_single[i].fwd_status);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%u: %s", i, npf_dscp_single[i].npf);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify firewall packet count */
		dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule,
					   npf_dscp_single[i].fwd_status ==
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
 * Used for both IPv4 and IPv6 match group tests.
 */
struct dp_test_npf_dscp_t npf_dscp_match_group[] = {
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 63,
		.npf = "dscp-group=ALL"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 33,
		.npf = "dscp-group=ALL"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 1,
		.npf = "dscp-group=ALL"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 0,
		.npf = "dscp-group=ALL"
	},

	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 0,
		.npf = "dscp-group=CS"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 8,
		.npf = "dscp-group=CS"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 24,
		.npf = "dscp-group=CS"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 56,
		.npf = "dscp-group=CS"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 57,
		.npf = "dscp-group=CS"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 1,
		.npf = "dscp-group=CS"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 44,
		.npf = "dscp-group=CS"
	},

	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 34,
		.npf = "dscp-group=AF4"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 36,
		.npf = "dscp-group=AF4"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.dscp = 38,
		.npf = "dscp-group=AF4"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 35,
		.npf = "dscp-group=AF4"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 37,
		.npf = "dscp-group=AF4"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 0,
		.npf = "dscp-group=AF4"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 1,
		.npf = "dscp-group=AF4"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.dscp = 62,
		.npf = "dscp-group=AF4"
	},
};

/*
 * Match on group of DSCP values - IPv4
 */
DP_START_TEST(dscp_ipv4, group_dscp)
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

	/* set up DSCP resource groups */
	dp_test_npf_cmd("npf-ut add dscp-group:ALL 0 0;1;2;3;4;5;6;7;8;9;10;"
			"11;12;13;14;15;16;17;18;19;20;21;22;23;24;25;26;27;"
			"28;29;30;31;32;33;34;35;36;37;38;39;40;41;42;43;44;"
			"45;46;47;48;49;50;51;52;53;54;55;56;57;58;59;60;61;"
			"62;63", false);
	dp_test_npf_cmd("npf-ut add dscp-group:CS 0 0;8;16;24;32;40;48;56",
			false);
	dp_test_npf_cmd("npf-ut add dscp-group:AF4 0 34;36;38", false);

	struct dp_test_pkt_desc_t v4_pkt = {
		.text       = "DSCP IPv4",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = 100,
					.dpt_icmp_seq = 100,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt;

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = NULL
		},
		RULE_DEF_BLOCK,
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

	/*
	 * Run the test for npf each rule
	 */
	for (i = 0; i < ARRAY_SIZE(npf_dscp_match_group); i++) {
		/* Setup firewall */
		fw.rules[0].npf = npf_dscp_match_group[i].npf;
		dp_test_npf_fw_add(&fw, false);

		/* Adjust packet */
		pkt->traf_class = npf_dscp_match_group[i].dscp << 2;

		test_pak = dp_test_v4_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_dscp_match_group[i].fwd_status);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%u: %s", i, npf_dscp_match_group[i].npf);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify firewall packet count */
		dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule,
					   npf_dscp_match_group[i].fwd_status ==
					   DP_TEST_FWD_FORWARDED ? 1 : 0);

		dp_test_npf_fw_del(&fw, false);
	}

	/* Cleanup */
	dp_test_npf_cmd("npf-ut delete dscp-group:ALL", false);
	dp_test_npf_cmd("npf-ut delete dscp-group:AF4", false);
	dp_test_npf_cmd("npf-ut delete dscp-group:CS", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");
} DP_END_TEST;


/*
 * Match on group of DSCP values - IPv6
 */
DP_START_TEST(dscp_ipv6, group_dscp)
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

	/* set up DSCP resource groups */
	dp_test_npf_cmd("npf-ut add dscp-group:ALL 0 0;1;2;3;4;5;6;7;8;9;10;"
			"11;12;13;14;15;16;17;18;19;20;21;22;23;24;25;26;27;"
			"28;29;30;31;32;33;34;35;36;37;38;39;40;41;42;43;44;"
			"45;46;47;48;49;50;51;52;53;54;55;56;57;58;59;60;61;"
			"62;63", false);
	dp_test_npf_cmd("npf-ut add dscp-group:CS 0 0;8;16;24;32;40;48;56",
			false);
	dp_test_npf_cmd("npf-ut add dscp-group:AF4 0 34;36;38", false);

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
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{
					.dpt_icmp_id = 100,
					.dpt_icmp_seq = 100,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v6_pkt;

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = NULL
		},
		RULE_DEF_BLOCK,
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

	/*
	 * Run the test for npf each rule
	 */
	for (i = 0; i < ARRAY_SIZE(npf_dscp_match_group); i++) {
		/* Setup firewall */
		fw.rules[0].npf = npf_dscp_match_group[i].npf;
		dp_test_npf_fw_add(&fw, false);

		/* Adjust packet */
		pkt->traf_class = npf_dscp_match_group[i].dscp << 2;

		test_pak = dp_test_v6_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_dscp_match_group[i].fwd_status);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%u: %s", i, npf_dscp_match_group[i].npf);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify firewall packet count */
		dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule,
					   npf_dscp_match_group[i].fwd_status ==
					   DP_TEST_FWD_FORWARDED ? 1 : 0);

		dp_test_npf_fw_del(&fw, false);
	}

	/* Cleanup */
	dp_test_npf_cmd("npf-ut delete dscp-group:ALL", false);
	dp_test_npf_cmd("npf-ut delete dscp-group:AF4", false);
	dp_test_npf_cmd("npf-ut delete dscp-group:CS", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
} DP_END_TEST;
