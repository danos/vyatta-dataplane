/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf hairpin tests
 *
 * UDP tests send 4 pacekts - forwards, reverse, forwards, reverse.
 *
 * npf_hairpin_udp1 has only stateless firewall cfgd.  All pkts are forwarded.
 *
 * npf_hairpin_udp2 has stateful input firewall.  Only forwards pkts get
 * through just now.  Reverse pkts cause session to be closed, and pkt is
 * dropped.
 *
 * icmp tests are similar to UDP.  They use an ICMP echo request for the
 * forwards packet, and a reply for the reverse packet.
 *
 * The TCP tests simulate a TCP call (syn, syn-ack etc).  tcp1 has stateless
 * firewall.  tcp2 has stateful input firewall.  tcp3 has stateful input
 * firewall, and tcp-strict is enabled. tcp4 and tcp5 handle a reset
 * in response to a SYN for tcp-strict stateful - tcp4 uses an input firewall
 * and tcp5 uses an output firewall.
 *
 *
 * To run each test in the chroot setup:
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_udp1
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_udp2
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_tcp1
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_tcp2
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_tcp3
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_tcp4
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_tcp5
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_icmp1
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_hairpin_icmp2
 *
 * To run all the tests:
 *
 * make -j4 dataplane_test_run CK_RUN_SUITE=dp_test_npf_hairpin.c
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf_state.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state.h"
#include "dp_test_lib.h"
#include "dp_test_str.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"

#define DPT_FW_IN            0x01
#define DPT_FW_IN_STATEFUL   0x02
#define DPT_FW_OUT           0x04
#define DPT_FW_OUT_STATEFUL  0x08

static void dp_test_fw_cfg(bool enable, uint32_t flags)
{
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATELESS,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw_in = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rset
	};

	struct dp_test_npf_ruleset_t fw_out = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rset
	};

	if (flags & DPT_FW_IN) {
		if (flags & DPT_FW_IN_STATEFUL)
			rset[0].stateful = STATEFUL;
		else
			rset[0].stateful = STATELESS;

		if (enable)
			dp_test_npf_fw_add(&fw_in, false);
		else
			dp_test_npf_fw_del(&fw_in, false);
	}

	if (flags & DPT_FW_OUT) {
		if (flags & DPT_FW_OUT_STATEFUL)
			rset[0].stateful = STATEFUL;
		else
			rset[0].stateful = STATELESS;

		if (enable)
			dp_test_npf_fw_add(&fw_out, false);
		else
			dp_test_npf_fw_del(&fw_out, false);
	}

}


DP_DECL_TEST_SUITE(npf_hairpin);

/*
 * Routes a UDP packet out the same interface it came in on.  Stateless
 * firewall only cfgd.
 *
 * Sends 4 packets - fwd, rev, fwd, rev
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_udp1, NULL, NULL);
DP_START_TEST(npf_hairpin_udp1, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_OUT);

	/*
	 * UDP forwards packet
	 */
	struct dp_test_pkt_desc_t forw_in = {
		.text       = "UDP Forwards In",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD, /* 57005 */
				.dport = 0xBEEF, /* 48879 */
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	/*
	 * UDP reverse packet
	 */
	struct dp_test_pkt_desc_t rev_in = {
		.text       = "UDP Forwards In",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xBEEF, /* 48879 */
				.dport = 0xDEAD, /* 57005 */
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;
	int i, count = 2;

	/*
	 * Forwards packet
	 */
	for (i = 0; i < count; i++) {
		pre_desc = &forw_in;
		post_desc = &forw_in;

		pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
		post_pak = dp_test_v4_pkt_from_desc(post_desc);

		test_exp = dp_test_exp_from_desc(post_pak, post_desc);
		rte_pktmbuf_free(post_pak);
		post_pak = dp_test_exp_get_pak(test_exp);

		/* Dest MAC is the MAC of the nexthop, 1.1.1.12 */
		dp_test_pktmbuf_eth_init(
			post_pak,
			"aa:bb:cc:dd:1:12",
			dp_test_intf_name2mac_str(post_desc->tx_intf),
			post_desc->ether_type);

		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);


		/*
		 * Reverse packet
		 */
		pre_desc = &rev_in;
		post_desc = &rev_in;

		pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
		post_pak = dp_test_v4_pkt_from_desc(post_desc);

		test_exp = dp_test_exp_from_desc(post_pak, post_desc);
		rte_pktmbuf_free(post_pak);
		post_pak = dp_test_exp_get_pak(test_exp);

		/*
		 * Dest MAC of the post-pkt is the MAC of the nexthop,
		 * 1.1.1.11
		 */
		dp_test_pktmbuf_eth_init(
			post_pak,
			"aa:bb:cc:dd:1:11",
			dp_test_intf_name2mac_str(post_desc->tx_intf),
			post_desc->ether_type);

		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);
	}

	/* Cleanup */
	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_OUT);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

} DP_END_TEST;

/*
 * Routes a UDP packet out the same interface it came in on.
 *
 * Stateful input firewall.
 *
 * Sends 4 packets - fwd, rev, fwd, rev
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 * UDP, stateful input firewall
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_udp2, NULL, NULL);
DP_START_TEST(npf_hairpin_udp2, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_IN_STATEFUL | DPT_FW_OUT);

	/*
	 * UDP forwards packet
	 */
	struct dp_test_pkt_desc_t forw_in = {
		.text       = "UDP Forwards In",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD, /* 57005 */
				.dport = 0xBEEF, /* 48879 */
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	/*
	 * UDP reverse packet
	 */
	struct dp_test_pkt_desc_t rev_in = {
		.text       = "UDP Forwards In",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xBEEF, /* 48879 */
				.dport = 0xDEAD, /* 57005 */
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;
	int i, count = 2;

	/*
	 * Forwards packet
	 */
	for (i = 0; i < count; i++) {
		pre_desc = &forw_in;
		post_desc = &forw_in;

		pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
		post_pak = dp_test_v4_pkt_from_desc(post_desc);

		test_exp = dp_test_exp_from_desc(post_pak, post_desc);
		rte_pktmbuf_free(post_pak);
		post_pak = dp_test_exp_get_pak(test_exp);

		/* Dest MAC is the MAC of the nexthop, 1.1.1.12 */
		dp_test_pktmbuf_eth_init(
			post_pak,
			"aa:bb:cc:dd:1:12",
			dp_test_intf_name2mac_str(post_desc->tx_intf),
			post_desc->ether_type);

		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		spush(test_exp->description, sizeof(test_exp->description),
		      "\nTest: \"%s\", Forwards %d", __func__, i+1);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);


		/*
		 * Reverse packet
		 */
		pre_desc = &rev_in;
		post_desc = &rev_in;

		pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
		post_pak = dp_test_v4_pkt_from_desc(post_desc);

		test_exp = dp_test_exp_from_desc(post_pak, post_desc);
		rte_pktmbuf_free(post_pak);
		post_pak = dp_test_exp_get_pak(test_exp);

		/*
		 * Dest MAC of the post-pkt is the MAC of the nexthop,
		 * 1.1.1.11
		 */
		dp_test_pktmbuf_eth_init(
			post_pak,
			"aa:bb:cc:dd:1:11",
			dp_test_intf_name2mac_str(post_desc->tx_intf),
			post_desc->ether_type);

		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		spush(test_exp->description, sizeof(test_exp->description),
		      "\nTest: \"%s\", Reverse %d", __func__, i+1);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);
	}

	/* Cleanup */
	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_IN_STATEFUL | DPT_FW_OUT);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

} DP_END_TEST;

/*
 * Callback function for TCP call simulator
 */
static void tcp_test_cb1(const char *str,
			 uint pktno, enum dp_test_tcp_dir dir,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}

/*
 * Routes a TCP call out the same interface it came in on.  Stateless firewall
 * only condigured.
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_tcp1, NULL, NULL);
DP_START_TEST(npf_hairpin_tcp1, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_OUT);

	/*
	 * TCP packet
	 */
	struct dp_test_pkt_desc_t fwd_in = {
		.text       = "TCP Forwards In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t fwd_out = {
		.text       = "TCP Forwards Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "aa:bb:cc:dd:1:12",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_in = {
		.text       = "TCP Reverse In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_out = {
		.text       = "TCP Reverse Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &fwd_in,
			.post = &fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &rev_in,
			.post = &rev_out,
		},
		.test_cb = tcp_test_cb1,
		.post_cb = NULL,
	};

	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		{DP_DIR_FORW, TH_ACK, 50, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 10, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/* Cleanup */
	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_OUT);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
} DP_END_TEST;


/*
 * Callback function for TCP call simulator for stateful fw
 */
static void tcp_test_cb2(const char *str,
			 uint pktno, enum dp_test_tcp_dir dir,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}

/*
 * Routes a TCP call out the same interface it came in on.
 *
 * Stateful input firewall configured.
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_tcp2, NULL, NULL);
DP_START_TEST(npf_hairpin_tcp2, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_IN_STATEFUL | DPT_FW_OUT);

	/*
	 * TCP packet
	 */
	struct dp_test_pkt_desc_t fwd_in = {
		.text       = "TCP Forwards In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t fwd_out = {
		.text       = "TCP Forwards Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "aa:bb:cc:dd:1:12",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_in = {
		.text       = "TCP Reverse In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_out = {
		.text       = "TCP Reverse Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &fwd_in,
			.post = &fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &rev_in,
			.post = &rev_out,
		},
		.test_cb = tcp_test_cb2,
		.post_cb = NULL,
	};

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		{DP_DIR_FORW, TH_ACK, 50, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 10, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/* Cleanup */
	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_IN_STATEFUL | DPT_FW_OUT);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
} DP_END_TEST;


/*
 * Callback function for TCP call simulator for stateful fw with tcp-strict
 */
static void tcp_test_cb3(const char *str,
			 uint pktno, enum dp_test_tcp_dir dir,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}

/*
 * Routes a TCP call out the same interface it came in on.
 *
 * Stateful input firewall configured, TCP strict enabled.
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_tcp3, NULL, NULL);
DP_START_TEST(npf_hairpin_tcp3, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_IN_STATEFUL | DPT_FW_OUT);

	dp_test_npf_cmd("npf-ut fw global tcp-strict enable", false);
	dp_test_npf_commit();

	/*
	 * TCP packet
	 */
	struct dp_test_pkt_desc_t fwd_in = {
		.text       = "TCP Forwards In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t fwd_out = {
		.text       = "TCP Forwards Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "aa:bb:cc:dd:1:12",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_in = {
		.text       = "TCP Reverse In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_out = {
		.text       = "TCP Reverse Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &fwd_in,
			.post = &fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &rev_in,
			.post = &rev_out,
		},
		.test_cb = tcp_test_cb3,
		.post_cb = NULL,
	};

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		{DP_DIR_FORW, TH_ACK, 50, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 10, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/* Cleanup */
	dp_test_npf_cmd("npf-ut fw global tcp-strict disable", false);
	dp_test_npf_commit();

	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_IN_STATEFUL | DPT_FW_OUT);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
} DP_END_TEST;


/*
 * Routes a TCP call out the same interface it came in on.
 *
 * Stateful input firewall configured, TCP strict enabled, expecting reset
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_tcp4, NULL, NULL);
DP_START_TEST(npf_hairpin_tcp4, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_IN_STATEFUL);

	dp_test_npf_cmd("npf-ut fw global tcp-strict enable", false);
	dp_test_npf_commit();

	/*
	 * TCP packet
	 */
	struct dp_test_pkt_desc_t fwd_in = {
		.text       = "TCP Forwards In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t fwd_out = {
		.text       = "TCP Forwards Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "aa:bb:cc:dd:1:12",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_in = {
		.text       = "TCP Reverse In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_out = {
		.text       = "TCP Reverse Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &fwd_in,
			.post = &fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &rev_in,
			.post = &rev_out,
		},
		.test_cb = tcp_test_cb3,
		.post_cb = NULL,
	};

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0},	   /* NPF_TCPS_SYN_SENT */
		{DP_DIR_BACK, TH_RST | TH_ACK, 0}, /* NPF_TCPS_CLOSED */
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/* Cleanup */
	dp_test_npf_cmd("npf-ut fw global tcp-strict disable", false);
	dp_test_npf_commit();

	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_IN_STATEFUL);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
} DP_END_TEST;


/*
 * Routes a TCP call out the same interface it came in on.
 *
 * Stateful output firewall configured, TCP strict enabled, expecting reset
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_tcp5, NULL, NULL);
DP_START_TEST(npf_hairpin_tcp5, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_OUT | DPT_FW_OUT_STATEFUL);

	dp_test_npf_cmd("npf-ut fw global tcp-strict enable", false);
	dp_test_npf_commit();

	/*
	 * TCP packet
	 */
	struct dp_test_pkt_desc_t fwd_in = {
		.text       = "TCP Forwards In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t fwd_out = {
		.text       = "TCP Forwards Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "aa:bb:cc:dd:1:12",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 1000,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_in = {
		.text       = "TCP Reverse In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t rev_out = {
		.text       = "TCP Reverse Out",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "00:00:a4:00:00:64",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 1000,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &fwd_in,
			.post = &fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &rev_in,
			.post = &rev_out,
		},
		.test_cb = tcp_test_cb3,
		.post_cb = NULL,
	};

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0},	   /* NPF_TCPS_SYN_SENT */
		{DP_DIR_BACK, TH_RST | TH_ACK, 0}, /* NPF_TCPS_CLOSED */
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/* Cleanup */
	dp_test_npf_cmd("npf-ut fw global tcp-strict disable", false);
	dp_test_npf_commit();

	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_OUT | DPT_FW_OUT_STATEFUL);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
} DP_END_TEST;


/*
 * Routes a ICMP packet out the same interface it came in on.  Stateless
 * firewall only cfgd.
 *
 * Sends 4 packets - fwd, rev, fwd, rev
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_icmp1, NULL, NULL);
DP_START_TEST(npf_hairpin_icmp1, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_OUT);

	/*
	 * ICMP forwards packet (Echo request)
	 */
	struct dp_test_pkt_desc_t forw_in = {
		.text       = "ICMP Forwards In",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = 8,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	/*
	 * ICMP reverse packet (Echo reply)
	 */
	struct dp_test_pkt_desc_t rev_in = {
		.text       = "ICMP Forwards In",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = 0,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;
	int i, count = 2;

	/*
	 * Forwards packet
	 */
	for (i = 0; i < count; i++) {
		pre_desc = &forw_in;
		post_desc = &forw_in;

		pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
		post_pak = dp_test_v4_pkt_from_desc(post_desc);

		test_exp = dp_test_exp_from_desc(post_pak, post_desc);
		rte_pktmbuf_free(post_pak);
		post_pak = dp_test_exp_get_pak(test_exp);

		/* Dest MAC is the MAC of the nexthop, 1.1.1.12 */
		dp_test_pktmbuf_eth_init(
			post_pak,
			"aa:bb:cc:dd:1:12",
			dp_test_intf_name2mac_str(post_desc->tx_intf),
			post_desc->ether_type);

		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);


		/*
		 * Reverse packet
		 */
		pre_desc = &rev_in;
		post_desc = &rev_in;

		pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
		post_pak = dp_test_v4_pkt_from_desc(post_desc);

		test_exp = dp_test_exp_from_desc(post_pak, post_desc);
		rte_pktmbuf_free(post_pak);
		post_pak = dp_test_exp_get_pak(test_exp);

		/*
		 * Dest MAC of the post-pkt is the MAC of the nexthop,
		 * 1.1.1.11
		 */
		dp_test_pktmbuf_eth_init(
			post_pak,
			"aa:bb:cc:dd:1:11",
			dp_test_intf_name2mac_str(post_desc->tx_intf),
			post_desc->ether_type);

		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);
	}

	/* Cleanup */
	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_OUT);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

} DP_END_TEST;

/*
 * Routes a ICMP packet out the same interface it came in on.
 *
 * Stateful input firewall.
 *
 * Sends 4 packets - fwd, rev, fwd, rev
 *
 *                              |
 *  4.4.4.4 ----- 1.1.1.11 -----+
 *         ==> Fwd              |
 *                              |                 +----------+
 *                              |           dp1T0 |          |
 *                              +-----------------+          |
 *                              |         1.1.1.1 |          |
 *                              |                 +----------+
 *                              |
 *  3.3.3.3 ----- 1.1.1.12 -----+
 *          <== Rev             |
 *
 * ICMP, stateful input firewall
 */
DP_DECL_TEST_CASE(npf_hairpin, npf_hairpin_icmp2, NULL, NULL);
DP_START_TEST(npf_hairpin_icmp2, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_add_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_fw_cfg(true, DPT_FW_IN | DPT_FW_IN_STATEFUL | DPT_FW_OUT);

	/*
	 * ICMP forwards packet (Echo request)
	 */
	struct dp_test_pkt_desc_t forw_in = {
		.text       = "ICMP Forwards In",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "4.4.4.4",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "3.3.3.3",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = 8,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	/*
	 * ICMP reverse packet (Echo reply)
	 */
	struct dp_test_pkt_desc_t rev_in = {
		.text       = "ICMP Forwards In",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "3.3.3.3",
		.l2_src     = "aa:bb:cc:dd:1:12",
		.l3_dst     = "4.4.4.4",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_ICMP,
		.l4	 = {
			.icmp = {
				.type = 0,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;
	int i, count = 2;

	/*
	 * Forwards packet
	 */
	for (i = 0; i < count; i++) {
		pre_desc = &forw_in;
		post_desc = &forw_in;

		pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
		post_pak = dp_test_v4_pkt_from_desc(post_desc);

		test_exp = dp_test_exp_from_desc(post_pak, post_desc);
		rte_pktmbuf_free(post_pak);
		post_pak = dp_test_exp_get_pak(test_exp);

		/* Dest MAC is the MAC of the nexthop, 1.1.1.12 */
		dp_test_pktmbuf_eth_init(
			post_pak,
			"aa:bb:cc:dd:1:12",
			dp_test_intf_name2mac_str(post_desc->tx_intf),
			post_desc->ether_type);

		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		spush(test_exp->description, sizeof(test_exp->description),
		      "\nTest: \"%s\", Forwards %d", __func__, i+1);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);


		/*
		 * Reverse packet
		 */
		pre_desc = &rev_in;
		post_desc = &rev_in;

		pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
		post_pak = dp_test_v4_pkt_from_desc(post_desc);

		test_exp = dp_test_exp_from_desc(post_pak, post_desc);
		rte_pktmbuf_free(post_pak);
		post_pak = dp_test_exp_get_pak(test_exp);

		/*
		 * Dest MAC of the post-pkt is the MAC of the nexthop,
		 * 1.1.1.11
		 */
		dp_test_pktmbuf_eth_init(
			post_pak,
			"aa:bb:cc:dd:1:11",
			dp_test_intf_name2mac_str(post_desc->tx_intf),
			post_desc->ether_type);

		spush(test_exp->description, sizeof(test_exp->description),
		      "\nTest: \"%s\", Reverse %d", __func__, i+1);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);
	}

	/* Cleanup */
	dp_test_fw_cfg(false, DPT_FW_IN | DPT_FW_IN_STATEFUL | DPT_FW_OUT);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.12 int:dp1T0");
	dp_test_netlink_del_route("4.4.4.0/24 nh 1.1.1.11 int:dp1T0");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

} DP_END_TEST;

