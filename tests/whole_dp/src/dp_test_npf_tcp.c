/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf TCP tests
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

#define CORE_TCP_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK)

/*
 * Callback from dp_test_tcp_pak_receive
 */
static void
dp_test_npf_tcp_test_cb(const char *str,
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


DP_DECL_TEST_SUITE(npf_tcp);

DP_DECL_TEST_CASE(npf_tcp, strict_state, NULL, NULL);

/*
 *            100.101.102.x                  200.201.202.x
 *                            +----------+
 *                          .1|          |.1
 *    .103 -------------------|    UUT   |------------------ .203
 *                       dp1T0|          |dp2T1
 *                            +----------+
 *
 *
 * Test that the TCP state transitions defined in npf_tcp_fsm are not
 * disallowed by the npf strict FSM, npf_tcp_strict_fsm
 */
DP_START_TEST(strict_state, t1)
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


	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
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

	dp_test_npf_cmd("npf-ut fw global tcp-strict enable", false);
	dp_test_npf_commit();

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ins_pre,
			.post = &ins_post,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &outs_pre,
			.post = &outs_post,
		},
		.test_cb = dp_test_npf_tcp_test_cb,
		.post_cb = NULL,
	};

	/*
	 * Test 1
	 */
	spush(tcp_call.str, sizeof(tcp_call.str), "npf TCP strict Test 1.1");

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
		{DP_DIR_FORW, TH_SYN, 0, NULL},
	};

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/*
	 * Test 2
	 */
	spush(tcp_call.str, sizeof(tcp_call.str), "npf TCP strict Test 1.2");

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt2[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL}
	};

	/*
	 * Incremement the forwards source port so that a new session is
	 * created
	 */
	tcp_call.desc[DP_DIR_FORW].pre->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_FORW].post->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_BACK].pre->l4.tcp.dport++;
	tcp_call.desc[DP_DIR_BACK].post->l4.tcp.dport++;

	dp_test_tcp_call(&tcp_call, tcp_pkt2, ARRAY_SIZE(tcp_pkt2), NULL, 0);

	/*
	 * Test 3
	 */
	spush(tcp_call.str, sizeof(tcp_call.str), "npf TCP strict Test 1.3");

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt3[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL}
	};

	tcp_call.desc[DP_DIR_FORW].pre->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_FORW].post->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_BACK].pre->l4.tcp.dport++;
	tcp_call.desc[DP_DIR_BACK].post->l4.tcp.dport++;

	dp_test_tcp_call(&tcp_call, tcp_pkt3, ARRAY_SIZE(tcp_pkt3), NULL, 0);

	/*
	 * Test 4
	 */
	spush(tcp_call.str, sizeof(tcp_call.str), "npf TCP strict Test 1.4");

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt4[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL}
	};

	tcp_call.desc[DP_DIR_FORW].pre->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_FORW].post->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_BACK].pre->l4.tcp.dport++;
	tcp_call.desc[DP_DIR_BACK].post->l4.tcp.dport++;

	dp_test_tcp_call(&tcp_call, tcp_pkt4, ARRAY_SIZE(tcp_pkt4), NULL, 0);

	/*
	 * Test 5
	 */
	spush(tcp_call.str, sizeof(tcp_call.str), "npf TCP strict Test 1.5");

	struct dp_test_tcp_flow_pkt tcp_pkt5[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN, 0, NULL},
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_FORW, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL}
	};

	tcp_call.desc[DP_DIR_FORW].pre->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_FORW].post->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_BACK].pre->l4.tcp.dport++;
	tcp_call.desc[DP_DIR_BACK].post->l4.tcp.dport++;

	dp_test_tcp_call(&tcp_call, tcp_pkt5, ARRAY_SIZE(tcp_pkt5), NULL, 0);


	/*
	 * Test 6
	 */
	spush(tcp_call.str, sizeof(tcp_call.str), "npf TCP strict Test 1.6");

	struct dp_test_tcp_flow_pkt tcp_pkt6[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL}
	};

	tcp_call.desc[DP_DIR_FORW].pre->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_FORW].post->l4.tcp.sport++;
	tcp_call.desc[DP_DIR_BACK].pre->l4.tcp.dport++;
	tcp_call.desc[DP_DIR_BACK].post->l4.tcp.dport++;

	dp_test_tcp_call(&tcp_call, tcp_pkt6, ARRAY_SIZE(tcp_pkt6), NULL, 0);

	/*
	 * End
	 */
	dp_test_npf_cmd("npf-ut fw global tcp-strict disable", false);
	dp_test_npf_commit();


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


DP_DECL_TEST_CASE(npf_tcp, strict_syn, NULL, NULL);

/*
 * Verify that a TCP packet with just the SYN flag set can create a session
 * when TCP-strict is enabled.
 */
static void
dp_test_npf_tcp_test_cb2(const char *desc,
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
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", desc);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}

static void
dp_test_npf_tcp_post_cb2(uint pktno, enum dp_test_tcp_dir dir,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 const char *desc)
{
	uint count = 1;

	dp_test_npf_session_count(&count);
	dp_test_fail_unless(count == 0, "%s", desc);
}

DP_START_TEST(strict_syn, t1)
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


	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 50152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 50152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 50152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 50152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
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

	dp_test_npf_cmd("npf-ut fw global tcp-strict enable", false);
	dp_test_npf_commit();

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ins_pre,
			.post = &ins_post,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &outs_pre,
			.post = &outs_post,
		},
		.test_cb = dp_test_npf_tcp_test_cb2,
		.post_cb = dp_test_npf_tcp_post_cb2,
	};

	/*
	 * Test 2.1.  Verify that a SYN-only can create a session
	 */

	struct dp_test_tcp_flow_pkt tcp_pkt[] = {
		{DP_DIR_FORW, 0, 0, NULL},
	};

	uint i;

	for (i = 0; i < 256; i++) {
		if ((i & CORE_TCP_FLAGS) == TH_SYN ||
		    (i & TH_RST) != 0)
			continue;

		spush(tcp_call.str, sizeof(tcp_call.str),
		      "npf TCP strict Test 2.1.%u", i);
		tcp_pkt[0].flags = i;
		dp_test_tcp_call(&tcp_call, tcp_pkt,
				 ARRAY_SIZE(tcp_pkt), NULL, 0);
	}

	/*
	 * Test 2.2.  Verify that session cannot be created in
	 *            reverse direction whatever the flags are.
	 */

	tcp_pkt[0].dir = DP_DIR_BACK;

	for (i = 0; i < 256; i++) {
		spush(tcp_call.str, sizeof(tcp_call.str),
		      "npf TCP strict Test 2.2.%u", i);
		tcp_pkt[0].flags = i;
		dp_test_tcp_call(&tcp_call, tcp_pkt,
				 ARRAY_SIZE(tcp_pkt), NULL, 0);
	}

	/*
	 * End
	 */
	dp_test_npf_cmd("npf-ut fw global tcp-strict disable", false);
	dp_test_npf_commit();


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


DP_DECL_TEST_CASE(npf_tcp, strict_nat, NULL, NULL);

/*
 * Test 3.  Simple stateful NAT test with TCP strict enabled that tests a
 * packet with a TCP option.
 */
static void
dp_test_npf_tcp_test_cb3(const char *desc,
			 uint pktno, enum dp_test_tcp_dir dir,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 void *data, uint index)
{
	static uint8_t tcp_opt_wscale[] = {3, 3, 1, 0};
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	if (flags & TH_SYN) {
		pre->l4.tcp.opts = tcp_opt_wscale;
		post->l4.tcp.opts = tcp_opt_wscale;
	} else {
		pre->l4.tcp.opts = NULL;
		post->l4.tcp.opts = NULL;
	}

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", desc);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}

DP_START_TEST(strict_nat, t1)
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


	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
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

	dp_test_npf_cmd("npf-ut fw global tcp-strict enable", false);
	dp_test_npf_commit();

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ins_pre,
			.post = &ins_post,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &outs_pre,
			.post = &outs_post,
		},
		.test_cb = dp_test_npf_tcp_test_cb3,
		.post_cb = NULL,
	};

	/*
	 * Test 1
	 */
	spush(tcp_call.str, sizeof(tcp_call.str), "npf TCP strict Test 3.1");

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		/* Open */
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* Data */
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		{DP_DIR_FORW, TH_ACK, 50, NULL},

		/* Close */
		{DP_DIR_FORW, TH_ACK | TH_FIN, 10, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
	};

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/*
	 * End
	 */
	dp_test_npf_cmd("npf-ut fw global tcp-strict disable", false);
	dp_test_npf_commit();


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
 * Tests TIME-WAIT assassination (RFC 1337)
 */

DP_DECL_TEST_CASE(npf_tcp, time_wait, NULL, NULL);

static void
dp_test_npf_tcp_test_cb4(const char *desc,
			 uint pktno, enum dp_test_tcp_dir dir,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 void *data, uint index)
{
	static uint old_seq, old_ack;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	if (dir == DP_DIR_BACK) {
		/*
		 * Remember seq and ack from first BACK packet after handshake
		 */
		if (pktno > 2 && pktno < 10 && old_seq == 0) {
			old_seq = pre->l4.tcp.seq;
			old_ack = pre->l4.tcp.ack;
		}

		if (pktno > 12 && old_seq != 0) {
			/* Old duplicate */
			pre->l4.tcp.seq = old_seq;
			pre->l4.tcp.ack = old_ack;
			post->l4.tcp.seq = old_seq;
			post->l4.tcp.ack = old_ack;
			old_seq = old_ack = 0;
		}
	}

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", desc);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}

static void
dp_test_npf_tcp_post_cb4(uint pktno, enum dp_test_tcp_dir dir,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 const char *desc)
{
	uint state;
	bool rv;

	/*
	 * Expected TCP state *after* packet
	 */
	uint expected_tcp_state[] = {
		[0] = NPF_TCPS_SYN_SENT,
		[1] = NPF_TCPS_SYN_RECEIVED,
		[2] = NPF_TCPS_ESTABLISHED,
		[3] = NPF_TCPS_ESTABLISHED,
		[4] = NPF_TCPS_ESTABLISHED,
		[5] = NPF_TCPS_ESTABLISHED,
		[6] = NPF_TCPS_ESTABLISHED,
		[7] = NPF_TCPS_ESTABLISHED,
		[8] = NPF_TCPS_ESTABLISHED,
		[9] = NPF_TCPS_FIN_SENT,
		[10] = NPF_TCPS_FIN_WAIT,
		[11] = NPF_TCPS_LAST_ACK,
		[12] = NPF_TCPS_TIME_WAIT,
		[13] = NPF_TCPS_TIME_WAIT,	/* After old duplicate */
		[14] = NPF_TCPS_TIME_WAIT,
		[15] = NPF_TCPS_TIME_WAIT,	/* After RST */
	};

	rv = dp_test_npf_session_state("100.101.102.103", 49152,
				       "200.201.202.203", 80,
				       IPPROTO_TCP, "dp2T1", &state);
	if (!rv) {
		dp_test_fail("Session not found: %s", desc);
		dp_test_npf_print_sessions(NULL);
	} else {
		if (pktno < ARRAY_SIZE(expected_tcp_state) &&
		    state != expected_tcp_state[pktno]) {
			dp_test_fail(
				"%s, exp state %s, actual state %s",
				desc,
				npf_state_get_state_name(
					expected_tcp_state[pktno],
					NPF_PROTO_IDX_TCP),
				npf_state_get_state_name(state,
							 NPF_PROTO_IDX_TCP));
		}
	}
}

DP_START_TEST(time_wait, t1)
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


	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
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

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ins_pre,
			.post = &ins_post,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &outs_pre,
			.post = &outs_post,
		},
		.test_cb = dp_test_npf_tcp_test_cb4,
		.post_cb = dp_test_npf_tcp_post_cb4,
	};

	/*
	 * Test 1
	 */
	spush(tcp_call.str, sizeof(tcp_call.str),
	      "npf TCP TIME-WAIT assassination Test 4.1");

	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		{DP_DIR_FORW, TH_ACK, 100, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		{DP_DIR_FORW, TH_ACK, 50, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		{DP_DIR_FORW, TH_ACK, 50, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},

		{DP_DIR_FORW, TH_ACK | TH_FIN, 10, NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		{DP_DIR_BACK, TH_ACK, 0, NULL},	/* Old duplicate */
		{DP_DIR_FORW, TH_ACK, 0, NULL},	/* */
		{DP_DIR_BACK, TH_RST, 0, NULL},	/* */
	};

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/*
	 * End
	 */

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

DP_DECL_TEST_CASE(npf_tcp, rst_estb, NULL, NULL);

/*
 * Test 5: TCP reset when in Established state
 */
static void
dp_test_npf_tcp_post_cb5(uint pktno, enum dp_test_tcp_dir dir,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 const char *desc)
{
	uint state;
	bool rv;

	/*
	 * Expected TCP state *after* packet
	 */
	uint expected_tcp_state[] = {
		[0] = NPF_TCPS_SYN_SENT,
		[1] = NPF_TCPS_SYN_RECEIVED,
		[2] = NPF_TCPS_ESTABLISHED,
		[3] = NPF_TCPS_ESTABLISHED,
		[4] = NPF_TCPS_ESTABLISHED,
		[5] = NPF_TCPS_RST_RECEIVED,	/* After RST */
	};

	rv = dp_test_npf_session_state("100.101.102.103", 49152,
				       "200.201.202.203", 80,
				       IPPROTO_TCP, "dp2T1", &state);
	if (!rv) {
		/*
		 * Special case....
		 *
		 * For tst pkt # 5, the session will have been expired, and
		 * consequently DNE in the session table.
		 *
		 * So check for that and merely return.
		 */
		if (pktno == 5)
			return;
		dp_test_fail("Session not found: %s", desc);
		dp_test_npf_print_sessions(NULL);
	} else {
		if (pktno < ARRAY_SIZE(expected_tcp_state) &&
		    state != expected_tcp_state[pktno]) {
			dp_test_fail(
				"%s, exp state %s, actual state %s",
				desc,
				npf_state_get_state_name(
					expected_tcp_state[pktno],
					NPF_PROTO_IDX_TCP),
				npf_state_get_state_name(state,
							 NPF_PROTO_IDX_TCP));
		}
	}

	/*
	 * Expected session flags *after* packet
	 */
	int expected_session_flags[] = {
		[0] = SE_ACTIVE | SE_PASS,
		[1] = SE_ACTIVE | SE_PASS,
		[2] = SE_ACTIVE | SE_PASS,
		[3] = SE_ACTIVE | SE_PASS,
		[4] = SE_ACTIVE | SE_PASS,
		[5] = SE_ACTIVE | SE_PASS,	/* After RST */
	};

	if (pktno < ARRAY_SIZE(expected_session_flags)) {

		rv = dp_test_npf_session_verify(NULL, "100.101.102.103", 49152,
					       "200.201.202.203", 80,
					       IPPROTO_TCP, "dp2T1",
					       expected_session_flags[pktno],
					       SE_FLAGS_MASK, true);
		if (!rv) {
			dp_test_fail("Session not found: %s", desc);
			dp_test_npf_print_sessions(NULL);
		};
	}
}

DP_START_TEST(rst_estb, t1)
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


	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
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

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ins_pre,
			.post = &ins_post,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &outs_pre,
			.post = &outs_post,
		},
		.test_cb = dp_test_npf_tcp_test_cb,
		.post_cb = dp_test_npf_tcp_post_cb5,
	};

	/*
	 * Test 1
	 */
	spush(tcp_call.str, sizeof(tcp_call.str), "npf TCP dev");

	/* Comment is new npf_tcp_fsm state */
	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		{DP_DIR_FORW, TH_ACK, 50, NULL},
		{DP_DIR_FORW, TH_RST, 0, NULL},
	};

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), NULL, 0);

	/*
	 * End
	 */

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
 * Send a RST only when no session currently exists.  We expect packet to be
 * forwarded, but for no session to be created.
 */
DP_DECL_TEST_CASE(npf_tcp, rst_only, NULL, NULL);

DP_START_TEST(rst_only, test1)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	/*
	 * Ruleset
	 */
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

	struct dp_test_npf_ruleset_t rset = {
		.rstype = "fw-in",
		.name   = "FW1",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&rset, false);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	struct dp_test_pkt_desc_t fwd_pkt = {
		.text       = "Fwd",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_RST | TH_ACK,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};


	struct dp_test_pkt_desc_t pkt_copy;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	bool rv;

	test_pak = dp_test_v4_pkt_from_desc(&fwd_pkt);

	pkt_copy = fwd_pkt;
	pkt_copy.l2_src = dp2T1_mac;
	pkt_copy.l2_dst = "aa:bb:cc:18:0:1";

	test_exp = dp_test_exp_from_desc(test_pak, &pkt_copy);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/* Verify session does *not* exist */
	rv = dp_test_npf_session_verify(NULL, "100.101.102.103", 49152,
					"200.201.202.203", 80,
					IPPROTO_TCP, "dp1T0",
					0, 0, false);
	if (!rv) {
		dp_test_fail("Session found when not expected");
		dp_test_npf_print_sessions(NULL);
	};

	/* Cleanup */

	dp_test_npf_fw_del(&rset, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;
