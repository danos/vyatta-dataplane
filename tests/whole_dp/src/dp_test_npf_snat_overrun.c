/*
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane SNAT test to cause running out of ports
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state.h"
#include "dp_test_lib.h"
#include "dp_test_str.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_portmap_lib.h"
#include "dp_test_npf_nat_lib.h"

/*
 * To debug:
 *
 * Call "dp_test_npf_nat_set_debug(true)" before injecting the packet.  This
 * will display the NAT firewall rules and NAT sessions *after* the packet has
 * been NAT'd but *before* it is placed on the transmit queue and verified.
 */


DP_DECL_TEST_SUITE(npf_snat_overrun);

/*
 * Source NAT
 *
 * Inside -> Outside, applied outbound
 *
 *                      inside         outside
 *                             +-----+
 * host1            10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 *                      dp1T0  |     | dp2T1
 *                             +-----+
 *                              snat -->
 *
 *                                   --> Forwards (on output)
 *                              Source 10.0.1.1:<port> changed to
 *                                     172.0.2.1:<port>
 *
 *
 */
DP_DECL_TEST_CASE(npf_snat_overrun, npf_snat_overrun_1, NULL, NULL);

DP_START_TEST(npf_snat_overrun_1, test1)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	int i;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

	/* host 3 */
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");
	/* host 1 */
	dp_test_netlink_add_neigh("dp1T0", "10.0.1.1", "aa:bb:cc:dd:2:b1");

	/*
	 * Update SYN-SENT timeout, so sessions are not expired too quickly -
	 * this was an issue when running under valgrind.
	 */
	dp_test_npf_cmd("npf-ut fw global timeout 1 update tcp syn-sent 300",
			false);

	/*
	 * Add SNAT rule.  Translate src addr from the host1 inside addr,
	 * and limited to 100 ports.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "10.0.1.1",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "172.0.2.1",
		.trans_port	= "1-100"};

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


	/*****************************************************************
	 * 1. Packet A: Forwards, Host1 Inside -> Host3 Outside
	 *****************************************************************/

	struct dp_test_pkt_desc_t v4_pktA_pre = {
		.text       = "Forw, Host1 Ins -> Host3 Outs, pre-NAT",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 0, /* varies */
				.dport = 49152,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v4_pktA_post = {
		.text       = "Forw, Host1 Ins -> Host3 Outs, post-NAT",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "172.0.2.1",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 0, /* varies */
				.dport = 49152,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	pre = &v4_pktA_pre;
	post = &v4_pktA_post;

	/*
	 * Send 200 packets to cause all the NAT ports to be used up.
	 * There are 100 ports, so that means 100 should get packets
	 * NATed, and 100 fail due to not having enough ports to NAT to.
	 */
	for (i = 0; i < 200; i++) {

		pre->l4.tcp.sport = i + 1;
		post->l4.tcp.sport = i + 1; // NAT tries to use the same port

		pre_pak = dp_test_v4_pkt_from_desc(pre);
		post_pak = dp_test_v4_pkt_from_desc(post);
		test_exp = dp_test_exp_from_desc(post_pak, post);
		rte_pktmbuf_free(post_pak);

		/* Setup NAT validation context */
		dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW,
			    DP_TEST_TRANS_SNAT, pre, post, true);

		dp_test_nat_set_validation(&cb_ctx, test_exp);

		/*
		 * There are only another NAT ports available for 100,
		 * so above that it should drop the packets as fails to
		 * get a port to translate to.
		 */
		dp_test_exp_set_fwd_status(test_exp,
			(i < 100) ? DP_TEST_FWD_FORWARDED :
				    DP_TEST_FWD_DROPPED);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

		if (i < 100)
			dp_test_npf_portmap_port_verify("172.0.2.1",
							pre->l4.tcp.sport);
	}

	/* Verify pkt count - note that it still counts the dropped ones */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 200);

	/* Cleanup */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "10.0.1.1", "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;
