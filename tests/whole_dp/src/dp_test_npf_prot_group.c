/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane protocol group firewall tests
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

struct dp_test_npf_proto_grp_t {
	/* DP_TEST_FWD_FORWARDED or DP_TEST_FWD_DROPPED */
	enum dp_test_fwd_result_e fwd_status;

	uint8_t proto;

	const char *npf;
};

DP_DECL_TEST_SUITE(npf_proto_grp);

DP_DECL_TEST_CASE(npf_proto_grp, proto_grp_ipv4, NULL, NULL);
DP_DECL_TEST_CASE(npf_proto_grp, proto_grp_ipv6, NULL, NULL);

/*
 * Used for both IPv4 and IPv6 match group tests.
 */
struct dp_test_npf_proto_grp_t npf_proto_grp_match[] = {
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.proto = IPPROTO_TCP,
		.npf = "protocol-group=GRP1"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.proto = IPPROTO_ICMP,
		.npf = "protocol-group=GRP1"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.proto = IPPROTO_UDP,
		.npf = "protocol-group=GRP1"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.proto = IPPROTO_DCCP,
		.npf = "protocol-group=GRP1"
	},

	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.proto = IPPROTO_UDP,
		.npf = "protocol-group=HASPORTS"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.proto = IPPROTO_TCP,
		.npf = "protocol-group=HASPORTS"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.proto = IPPROTO_ICMP,
		.npf = "protocol-group=HASPORTS"
	},
	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.proto = IPPROTO_DCCP,
		.npf = "protocol-group=HASPORTS"
	},

	{
		.fwd_status = DP_TEST_FWD_FORWARDED,
		.proto = IPPROTO_UDP,
		.npf = "protocol-group=UDP-GRE"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.proto = IPPROTO_TCP,
		.npf = "protocol-group=UDP-GRE"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.proto = IPPROTO_ICMP,
		.npf = "protocol-group=UDP-GRE"
	},
	{
		.fwd_status = DP_TEST_FWD_DROPPED,
		.proto = IPPROTO_PIM,
		.npf = "protocol-group=UDP-GRE"
	},
};

/*
 * Match on group of protocol values - IPv4
 */
DP_START_TEST(proto_grp_ipv4, group_proto_grp)
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

	/* set up protocol resource groups */
	dp_test_npf_cmd("npf-ut add protocol-group:GRP1 0 1;58;6;6", false);
	dp_test_npf_cmd("npf-ut add protocol-group:HASPORTS 0 6;17;33;136;132",
			false);
	dp_test_npf_cmd("npf-ut add protocol-group:UDP-GRE 0 17;47", false);

	struct dp_test_pkt_desc_t v4_icmp_pkt = {
		.text       = "Prot-group IPv4 ICMP",
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

	struct dp_test_pkt_desc_t v4_tcp_pkt = {
		.text       = "Prot-group IPv4 TCP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
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

	struct dp_test_pkt_desc_t v4_udp_pkt = {
		.text       = "Prot-group IPv4 UDP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 1000,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v4_raw_pkt = {
		.text       = "Prot-group IPv4 raw",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = 0,
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

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
	for (i = 0; i < ARRAY_SIZE(npf_proto_grp_match); i++) {
		/* Setup firewall */
		fw.rules[0].npf = npf_proto_grp_match[i].npf;
		dp_test_npf_fw_add(&fw, false);

		/* Choose the packet to send */

		switch (npf_proto_grp_match[i].proto) {
		case IPPROTO_TCP:
			pkt = &v4_tcp_pkt;
			break;
		case IPPROTO_UDP:
			pkt = &v4_udp_pkt;
			break;
		case IPPROTO_ICMP:
			pkt = &v4_icmp_pkt;
			break;
		default:
			pkt = &v4_raw_pkt;
			pkt->proto = npf_proto_grp_match[i].proto;
			break;
		}

		test_pak = dp_test_v4_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_proto_grp_match[i].fwd_status);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%u: %s", i, npf_proto_grp_match[i].npf);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify firewall packet count */
		dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule,
					   npf_proto_grp_match[i].fwd_status ==
					   DP_TEST_FWD_FORWARDED ? 1 : 0);

		dp_test_npf_fw_del(&fw, false);
	}

	/* Cleanup */
	dp_test_npf_cmd("npf-ut delete protocol-group:GRP1", false);
	dp_test_npf_cmd("npf-ut delete protocol-group:UDP-GRE", false);
	dp_test_npf_cmd("npf-ut delete protocol-group:HASPORTS", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:b1");
} DP_END_TEST;

/*
 * Match on group of protocol values - IPv6
 */
DP_START_TEST(proto_grp_ipv6, group_proto_grp)
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

	/* set up protocol resource groups */
	dp_test_npf_cmd("npf-ut add protocol-group:GRP1 0 1;58;6;6", false);
	dp_test_npf_cmd("npf-ut add protocol-group:HASPORTS 0 6;17;33;136;132",
			false);
	dp_test_npf_cmd("npf-ut add protocol-group:UDP-GRE 0 17;47", false);

	struct dp_test_pkt_desc_t v6_icmp_pkt = {
		.text       = "Prot-group IPv6 ICMP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
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

	struct dp_test_pkt_desc_t v6_tcp_pkt = {
		.text       = "Prot-group IPv6 TCP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
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

	struct dp_test_pkt_desc_t v6_udp_pkt = {
		.text       = "Prot-group IPv6 UDP",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 1000,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v6_raw_pkt = {
		.text       = "Prot-group IPv6 raw",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = 0,
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

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
	for (i = 0; i < ARRAY_SIZE(npf_proto_grp_match); i++) {
		/* Setup firewall */
		fw.rules[0].npf = npf_proto_grp_match[i].npf;
		dp_test_npf_fw_add(&fw, false);

		/* Choose the packet to send */

		switch (npf_proto_grp_match[i].proto) {
		case IPPROTO_TCP:
			pkt = &v6_tcp_pkt;
			break;
		case IPPROTO_UDP:
			pkt = &v6_udp_pkt;
			break;
		case IPPROTO_ICMP:
			pkt = &v6_icmp_pkt;
			break;
		default:
			pkt = &v6_raw_pkt;
			pkt->proto = npf_proto_grp_match[i].proto;
			break;
		}

		test_pak = dp_test_v6_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_proto_grp_match[i].fwd_status);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%u: %s", i, npf_proto_grp_match[i].npf);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify firewall packet count */
		dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule,
					   npf_proto_grp_match[i].fwd_status ==
					   DP_TEST_FWD_FORWARDED ? 1 : 0);

		dp_test_npf_fw_del(&fw, false);
	}

	/* Cleanup */
	dp_test_npf_cmd("npf-ut delete protocol-group:GRP1", false);
	dp_test_npf_cmd("npf-ut delete protocol-group:UDP-GRE", false);
	dp_test_npf_cmd("npf-ut delete protocol-group:HASPORTS", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
} DP_END_TEST;
