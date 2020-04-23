/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane NAT tests
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_str.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_portmap_lib.h"
#include "dp_test_npf_nat_lib.h"

/*
 * NAT Tests:
 *
 * 1. Source NAT (One-to-One)
 * 2. Source NAT (masquerade)
 * 3. Destination NAT (One-to-One)
 * 4. Bidirectional NAT (snat-dnat, different interfaces)
 * 5. Bidirectional NAT (snat-dnat, same interface)
 * 6. Mapping of address ranges
 * 7. The "exclude" option
 * 8. Source NAT (port range)
 *
 * To debug:
 *
 * Call "dp_test_npf_nat_set_debug(true)" before injecting the packet.  This
 * will display the NAT firewall rules and NAT sessions *after* the packet has
 * been NAT'd but *before* it is placed on the transmit queue and verified.
 */


DP_DECL_TEST_SUITE(npf_nat);

/*
 * Source NAT (One-to-One)
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
 *                              Source 10.0.1.1 changed to 172.0.2.1
 *
 *                                   <-- Back (on input)
 *                              Dest 172.0.2.1 changed to 10.0.1.1
 *
 */
DP_DECL_TEST_CASE(npf_nat, npf_snat, NULL, NULL);

DP_START_TEST(npf_snat, test1)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

	/* host 3 */
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");
	/* host 1 */
	dp_test_netlink_add_neigh("dp1T0", "10.0.1.1", "aa:bb:cc:dd:2:b1");

	/*
	 * Add SNAT rule.  Translate src addr from the host1 inside addr
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


	/*****************************************************************
	 * 1. Packet A: Forwards, Host1 Inside -> Host3 Outside
	 *****************************************************************/

	struct dp_test_pkt_desc_t v4_pktA_pre = {
		.text       = "Forw, Host1 Ins -> Host3 Outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
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
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.1",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
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

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 1);

	dp_test_npf_portmap_port_verify("tcp", "172.0.2.1", pre->l4.tcp.sport);


	/*****************************************************************
	 * 2. Packet B: Backwards, Host3 Outside -> Host1 Intside
	 *****************************************************************/

	struct dp_test_pkt_desc_t v4_pktB_pre = {
		.text       = "Back, Host3 Outs -> Host1 Ins, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "172.0.2.1",
		.l2_dst     = dp_test_intf_name2mac_str("dp2T1"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pktB_post = {
		.text       = "Back, Host3 Outs -> Host1 Ins, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = dp_test_intf_name2mac_str("dp1T0"),
		.l3_dst     = "10.0.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	pre = &v4_pktB_pre;
	post = &v4_pktB_post;

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

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 2);

	/*****************************************************************
	 * 3. Packet A: Forwards, Host1 Inside -> Host3 Outside
	 *****************************************************************/

	pre = &v4_pktA_pre;
	post = &v4_pktA_post;

	pre->l4.tcp.flags = post->l4.tcp.flags = TH_ACK;
	pre->l4.tcp.seq = post->l4.tcp.seq = 1;
	pre->l4.tcp.ack = post->l4.tcp.ack = 1;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 3);


	/* Cleanup */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "10.0.1.1", "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;

/*
 * Source NAT (masquerade)
 *
 * Inside -> Outside, applied outbound
 *
 *                      inside         outside
 *                             +-----+
 * hosts1           10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 * host2                dp1T0  |     | dp2T1
 * 10.0.1.2                    +-----+
 *                              snat -->
 *
 *                                   --> Forwards (on output)
 *                              Source 10.0.1.x changed to 172.0.2.254, port y
 *
 *                                   <-- Back (on input)
 *                              Dest 172.0.2.254, port y changed to 10.0.1.x
 *
 */
DP_DECL_TEST_CASE(npf_nat, npf_snat_masquerade, NULL, NULL);

DP_START_TEST(npf_snat_masquerade, test1)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",  "10.0.1.254/24");

	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a3");

	/*
	 * Add SNAT masquerade rule.  Packets outbound on dp2T1 will have
	 * their source addresses changed to the outside interface address,
	 * 172.0.2.254
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "10.0.1.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade",
		.trans_port	= NULL};

	dp_test_npf_snat_add(&snat, true);


	/*
	 * Validation context
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


	/*******************************************************************
	 * Pkt1: Forwards direction, Inside host 1 -> Outside host 3
	 *
	 * Expect SNAT sessions src addr 172.0.2.254, dest addr 172.0.2.3, on
	 * outbound interface dpT21, with trans port 1000
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pkt1_pre = {
		.text       = "Forw, Ins host1 -> Outs host3, Pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
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

	struct dp_test_pkt_desc_t v4_pkt1_post = {
		.text       = "Forw, Ins host1 -> Outs host3, Post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.254",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a3",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
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

	pre = &v4_pkt1_pre;
	post = &v4_pkt1_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 1);

	dp_test_npf_portmap_verify("tcp", "172.0.2.254", "ACTIVE", 1);
	dp_test_npf_portmap_port_verify("tcp", "172.0.2.254",
					pre->l4.tcp.sport);


	/*******************************************************************
	 * Pkt2: Backwards direction
	 *
	 * Outside host3 (172.0.2.3) -> UUT Outside intf (172.0.2.254)
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pkt2_pre = {
		.text       = "Back, Outs host3 -> Outs UUT intf, Pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a3",
		.l3_dst     = "172.0.2.254",
		.l2_dst     = dp_test_intf_name2mac_str("dp2T1"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1000,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5480,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pkt2_post = {
		.text       = "Back, Outs host -> Outs UUT intf, Post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = dp_test_intf_name2mac_str("dp1T0"),
		.l3_dst     = "10.0.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1000,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5480,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	pre = &v4_pkt2_pre;
	post = &v4_pkt2_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 2);


	/*******************************************************************
	 * Pkt3: Repeat initial packet in forwards direction:
	 *******************************************************************/

	pre = &v4_pkt1_pre;
	post = &v4_pkt1_post;

	pre->l4.tcp.flags = post->l4.tcp.flags = TH_ACK;
	pre->l4.tcp.seq = post->l4.tcp.seq = 1;
	pre->l4.tcp.ack = post->l4.tcp.ack = 1;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 3);


	/*******************************************************************
	 * Pkt4: Forwards direction:
	 *
	 * Inside host2 (10.0.1.2) -> Outside host3 (172.0.2.3)
	 *
	 * This packet is identical to packet 1, except its from source
	 * address 10.0.1.2 instead of 10.0.1.1.  In order to differentiate
	 * the packet on the outside network, SNAT will use translation port
	 * 1001.
	 *
	 * Expect SNAT sessions src addr 10.0.1.2, dest addr 172.0.2.3, on
	 * outbound interface dpT21, with trans port 1001
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pkt4_pre = {
		.text       = "Forw, Ins host2 p1000 -> Outs host3, Pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "aa:bb:cc:dd:2:b2",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
				.dport = 49152,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5480,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v4_pkt4_post = {
		.text       = "Forw, Ins host2 p1000 -> Outs host3, Post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.254",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a3",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1001, /* Changed */
				.dport = 49152,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5480,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	pre = &v4_pkt4_pre;
	post = &v4_pkt4_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 4);

	dp_test_npf_portmap_verify("tcp", "172.0.2.254", "ACTIVE", 2);
	dp_test_npf_portmap_port_verify("tcp", "172.0.2.254",
					post->l4.tcp.sport);


	/*******************************************************************
	 * Pkt5: Backwards direction.
	 *
	 * Outside host3 (172.0.2.3) -> UUT Outside intf (172.0.2.254),
	 * dest port 1001
	 *
	 * This is the "backwards" flow of packet 4.  The dest port of 1001
	 * allows NAT to find the correct session table entry.
	 *
	 * This should match the SNAT session created by pkt 4, and translate
	 * destination address to host2 (10.0.1.2), dest port 1000
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pkt5_pre = {
		.text       = "Back, Outs host3 -> Outs UUT p1001, Pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a3",
		.l3_dst     = "172.0.2.254",
		.l2_dst     = dp_test_intf_name2mac_str("dp2T1"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1001,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5480,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pkt5_post = {
		.text       = "Back, Outs n1 -> Outs UUT p1001, Post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = dp_test_intf_name2mac_str("dp1T0"),
		.l3_dst     = "10.0.1.2",
		.l2_dst     = "aa:bb:cc:dd:2:b2",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1000,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5480,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	pre = &v4_pkt5_pre;
	post = &v4_pkt5_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 5);


	/* Cleanup */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a3");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;


/*
 * Destination NAT (One-to-One)
 *
 *                      inside         outside
 *                             +-----+
 * hosts1           10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 * host2                dp1T0  |     | dp2T1
 * 10.0.1.2                    +-----+
 *                                   <-- dnat
 *
 *                                   <-- Forwards (on Input)
 *                     Dest 172.0.2.1 changed to 10.0.1.1
 *
 *                                   --> Back (on Output)
 *                     Source 10.0.1.1 changed to 172.0.2.1
 *
 */
DP_DECL_TEST_CASE(npf_nat, npf_dnat, NULL, NULL);

DP_START_TEST(npf_dnat, test1)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",  "10.0.1.254/24");

	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a3");

	/*
	 * Add DNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "172.0.2.1",
		.to_port	= "80",
		.trans_addr	= "10.0.1.1",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

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
	cb_ctx.dnat = nat_ctx;
	memset(nat_ctx, 0, sizeof(*nat_ctx));


	/*******************************************************************
	 * Pkt1: Forwards direction, Outside host 3 -> Inside host 1
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pktA_pre = {
		.text       = "Forw, host3 outs -> host1 ins, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a3",
		.l3_dst     = "172.0.2.1",
		.l2_dst     = dp_test_intf_name2mac_str("dp2T1"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pktA_post = {
		.text       = "Forw, host3 outs -> host1 ins, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = dp_test_intf_name2mac_str("dp1T0"),
		.l3_dst     = "10.0.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	pre = &v4_pktA_pre;
	post = &v4_pktA_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_DNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 1);


	/*******************************************************************
	 * Pkt2: Backwards direction, Inside host 1 -> Outside host 3
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pktB_pre = {
		.text       = "Back, host1 ins -> host3 outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v4_pktB_post = {
		.text       = "Back, host1 ins -> host3 outs, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.1",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a3",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	pre = &v4_pktB_pre;
	post = &v4_pktB_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 2);


	/*******************************************************************
	 * Pkt3: Forwards direction, Outside host 3 -> Inside host 1
	 *
	 * Repeat initial packet
	 *******************************************************************/

	pre = &v4_pktA_pre;
	post = &v4_pktA_post;

	pre->l4.tcp.flags = post->l4.tcp.flags = TH_ACK;
	pre->l4.tcp.seq = post->l4.tcp.seq = 1;
	pre->l4.tcp.ack = post->l4.tcp.ack = 1;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 3);


	/* Cleanup */
	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a3");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;


/*
 * Bidirectional NAT
 *
 *                      inside         outside
 *                             +-----+
 * hosts1           10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 * host2                dp1T0  |     | dp2T1
 * 10.0.1.2                    +-----+
 *                      snat <--     <-- dnat
 *
 *                                   <-- Forwards (on Input)
 *                     Dest 172.0.2.1 changed to 10.0.1.1
 *
 *                                   --> Back (on Output)
 *                     Source 10.0.1.1 changed to 172.0.2.1
 *
 *                           <-- Forwards (on Output)
 *              Source 172.0.2.3 changed to 10.0.1.3
 *
 *                           --> Back (on Input)
 *              Dest 10.0.1.3 changed to 172.0.2.3
 *
 */
DP_DECL_TEST_CASE(npf_nat, npf_bidir_nat, NULL, NULL);

DP_START_TEST_DONT_RUN(npf_bidir_nat, test1)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",  "10.0.1.254/24");

	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.2", "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a3");

	/*
	 * Add DNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "172.0.2.1",
		.to_port	= "80",
		.trans_addr	= "10.0.1.1",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "172.0.2.3",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "10.0.1.3",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * Validation context.  This validates the NAT session is correct
	 * *before* it checks the packet.
	 */
	struct dp_test_nat_ctx dnat_context;
	struct dp_test_nat_ctx *dnat_ctx = &dnat_context;
	struct dp_test_nat_ctx snat_context;
	struct dp_test_nat_ctx *snat_ctx = &snat_context;

	static struct dp_test_nat_cb_ctx cb_ctx = {
		.snat = NULL,
		.dnat = NULL,
		.saved_cb = dp_test_pak_verify
	};
	cb_ctx.snat = snat_ctx;
	cb_ctx.dnat = dnat_ctx;
	memset(snat_ctx, 0, sizeof(*snat_ctx));
	memset(dnat_ctx, 0, sizeof(*dnat_ctx));


	/*******************************************************************
	 * Pkt1: Forwards direction, Outside host 3 -> Inside host 1
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pktA_pre = {
		.text       = "Fwd, host3 outs -> host1 ins, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a3",
		.l3_dst     = "172.0.2.1",
		.l2_dst     = dp_test_intf_name2mac_str("dp2T1"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pktA_post = {
		.text       = "Fwd, host3 outs -> host1 ins, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.3",
		.l2_src     = dp_test_intf_name2mac_str("dp1T0"),
		.l3_dst     = "10.0.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	pre = &v4_pktA_pre;
	post = &v4_pktA_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(snat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_ctx(dnat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_DNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count and npf session */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 1);
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 1);

	dp_test_npf_portmap_port_verify("tcp", "10.0.1.3", pre->l4.tcp.sport);


	/*******************************************************************
	 * Pkt2: Backwards direction, Inside host 1 -> Outside host 3
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pktB_pre = {
		.text       = "Back, host 1 ins -> host3 outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "10.0.1.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v4_pktB_post = {
		.text       = "Back, host 1 ins -> host3 outs, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.1",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a3",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	pre = &v4_pktB_pre;
	post = &v4_pktB_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(snat_ctx, DP_TEST_NAT_DIR_BACK, DP_TEST_TRANS_SNAT,
			    pre, post, false);
	dp_test_nat_set_ctx(dnat_ctx, DP_TEST_NAT_DIR_BACK, DP_TEST_TRANS_DNAT,
			    pre, post, false);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count and npf session */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 2);
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 2);


	/*******************************************************************
	 * Pkt3: Forwards direction, Outside host 3 -> Inside host 1
	 *
	 * Repeat initial packet
	 *******************************************************************/

	pre = &v4_pktA_pre;
	post = &v4_pktA_post;

	pre->l4.tcp.flags = post->l4.tcp.flags = TH_ACK;
	pre->l4.tcp.seq = post->l4.tcp.seq = 1;
	pre->l4.tcp.ack = post->l4.tcp.ack = 1;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(snat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_ctx(dnat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_DNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count and npf session */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 3);
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 3);


	/* Cleanup */
	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a3");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;


/*
 * Bidirectional NAT (same interface)
 *
 *                      inside         outside
 *                             +-----+
 * hosts1           10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 * host2                dp1T0  |     | dp2T1
 * 10.0.1.2                    +-----+
 *                                   <-- dnat
 *
 *                                   <-- Forwards (on Input)
 *                     Dest 172.0.2.1 changed to 10.0.1.1
 *
 *                                   --> Back (on Output)
 *                     Source 10.0.1.1 changed to 172.0.2.1
 *
 *                                   --> snat
 *
 *                                   --> Forwards (on Output)
 *                     Source 10.0.1.2 changed to 172.0.2.2
 *
 *                                   <-- Back (on Input)
 *                     Dest 172.2.2 changed to 10.0.1.2
 *
 * The backwards packet hits the reverse DNAT session created by packet 1, and
 * so never hits the SNAT rule.
 */
DP_DECL_TEST_CASE(npf_nat, npf_bidir_nat2, NULL, NULL);

DP_START_TEST_DONT_RUN(npf_bidir_nat2, test1)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",  "10.0.1.254/24");

	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3",  "aa:bb:cc:dd:1:a3");

	/*
	 * Add DNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "172.0.2.1",
		.to_port	= "80",
		.trans_addr	= "10.0.1.1",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "10.0.1.2",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "172.0.2.2",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * Validation context.  This validates the NAT session is correct
	 * *before* it checks the packet.
	 */
	struct dp_test_nat_ctx dnat_context;
	struct dp_test_nat_ctx *dnat_ctx = &dnat_context;
	struct dp_test_nat_ctx snat_context;
	struct dp_test_nat_ctx *snat_ctx = &snat_context;

	static struct dp_test_nat_cb_ctx cb_ctx = {
		.snat = NULL,
		.dnat = NULL,
		.saved_cb = dp_test_pak_verify
	};
	cb_ctx.snat = snat_ctx;
	cb_ctx.dnat = dnat_ctx;
	memset(snat_ctx, 0, sizeof(*snat_ctx));
	memset(dnat_ctx, 0, sizeof(*dnat_ctx));


	/*******************************************************************
	 * Pkt1: DNAT Forwards direction, Outside host 3 -> Inside host 1
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pktA_pre = {
		.text       = "Fwd, host3 outs -> host1 ins, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a3",
		.l3_dst     = "172.0.2.1",
		.l2_dst     = dp_test_intf_name2mac_str("dp2T1"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pktA_post = {
		.text       = "Fwd, host3 outs -> host1 ins, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = dp_test_intf_name2mac_str("dp1T0"),
		.l3_dst     = "10.0.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	pre = &v4_pktA_pre;
	post = &v4_pktA_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(dnat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_DNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);
	cb_ctx.snat = NULL; /* No snat */

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 1);
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 0);

	dp_test_npf_session_count_verify(1);
	dp_test_npf_nat_session_count_verify(1);


	/*******************************************************************
	 * Pkt2: DNAT Backwards direction, Inside host 1 -> Outside host 3
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pktB_pre = {
		.text       = "Rev, host 1 ins -> host3 outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v4_pktB_post = {
		.text       = "Rev, host 1 ins -> host3 outs, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.1",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a3",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	pre = &v4_pktB_pre;
	post = &v4_pktB_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 2);
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 0);

	dp_test_npf_session_count_verify(1);
	dp_test_npf_nat_session_count_verify(1);


	/*******************************************************************
	 * Pkt3: DNAT Forwards direction, Outside host 3 -> Inside host 1
	 *
	 * Repeat packet 1
	 *******************************************************************/

	pre = &v4_pktA_pre;
	post = &v4_pktA_post;

	pre->l4.tcp.flags = post->l4.tcp.flags = TH_ACK;
	pre->l4.tcp.seq = post->l4.tcp.seq = 1;
	pre->l4.tcp.ack = post->l4.tcp.ack = 1;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(dnat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_DNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);
	cb_ctx.snat = NULL; /* No snat */

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 3);
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 0);

	dp_test_npf_session_count_verify(1);
	dp_test_npf_nat_session_count_verify(1);


	/*******************************************************************
	 * Pkt4: SNAT Forwards direction, Inside host 2 -> Outside host 3
	 *
	 * This will hit the SNAT rule only
	 *
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pktC_pre = {
		.text       = "Fwd, host2 ins -> host3 outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "aa:bb:cc:dd:2:b2",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49101,
				.dport = 1000,
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

	struct dp_test_pkt_desc_t v4_pktC_post = {
		.text       = "Fwd, host2 ins -> host3 outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.2",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a3",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49101,
				.dport = 1000,
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

	pre = &v4_pktC_pre;
	post = &v4_pktC_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(snat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);
	cb_ctx.dnat = NULL; /* No dnat */

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_dnat_verify_pkts(dnat.ifname, dnat.rule, 3);
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 1);

	dp_test_npf_session_count_verify(2);
	dp_test_npf_nat_session_count_verify(2);


	/* Cleanup */
	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a3");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;



/*
 * Mapping of address ranges (SNAT)
 *
 * Inside -> Outside, applied outbound
 *
 *                      inside         outside
 *                             +-----+
 * host1            10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 * host2                dp1T0  |     | dp2T1
 * 10.0.1.2                    +-----+
 *                              snat -->
 *
 *                                   --> Forwards (on output)
 *                              Source 10.0.1.x changed to 172.0.2.11-20
 *
 *                                   <-- Back (on input)
 *                              Dest 172.0.2.11-20 changed to 10.0.1.x
 *
 */

DP_START_TEST(npf_snat, addr_ranges)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

	dp_test_netlink_add_neigh("dp1T0", "10.0.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0", "10.0.1.2", "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");

	/*
	 * Add SNAT rule.  Translate src addr from the host3 inside addr
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "10.0.1.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "172.0.2.11-172.0.2.20",
		.trans_port	= NULL
	};

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
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1000,
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
		.text       = "Forw, Host1 Ins -> Host3 Outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.18",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1000,
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

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 1);

	dp_test_npf_portmap_port_verify("tcp", "172.0.2.18", pre->l4.tcp.sport);


	/*****************************************************************
	 * 2. Packet B: Forwards, Host2 Inside -> Host3 Outside
	 *****************************************************************/

	struct dp_test_pkt_desc_t v4_pktB_pre = {
		.text       = "Forw, Host2 Ins -> Host3 Outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "aa:bb:cc:dd:2:b2",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 48001,
				.dport = 1000,
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

	struct dp_test_pkt_desc_t v4_pktB_post = {
		.text       = "Forw, Host2 Ins -> Host3 Outs, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.19",
		.l2_src     = "aa:bb:cc:dd:2:b2",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 48001,
				.dport = 1000,
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

	pre = &v4_pktB_pre;
	post = &v4_pktB_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 2);

	dp_test_npf_session_count_verify(2);
	dp_test_npf_nat_session_count_verify(2);

	dp_test_npf_portmap_port_verify("tcp", "172.0.2.19", pre->l4.tcp.sport);


	/* Cleanup */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "10.0.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0", "10.0.1.2", "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;


/*
 * Source NAT (masquerade), with exclude option
 *
 * Inside -> Outside, applied outbound
 *
 *                      inside         outside
 *                             +-----+
 * hosts1           10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 * host2                dp1T0  |     | dp2T1
 * 10.0.1.2                    +-----+
 *                              snat -->
 *
 *                                   --> Forwards (on output)
 *                              Source 10.0.1.x changed to 172.0.2.254, port y
 *
 *                                   <-- Back (on input)
 *                              Dest 172.0.2.254, port y changed to 10.0.1.x
 *
 */
DP_DECL_TEST_CASE(npf_nat, npf_snat_exclude, NULL, NULL);

DP_START_TEST(npf_snat_exclude, test1)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",  "10.0.1.254/24");

	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");

	/*
	 * Add SNAT masquerade rule.  Packets outbound on dp2T1 will have
	 * their source addresses changed to the outside interface address,
	 * 172.0.2.254 *except* for host2
	 */
	struct dp_test_npf_nat_rule_t snat_10 = {
		.desc		= "snat 10",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "exclude",
		.from_addr	= "10.0.1.2",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= NULL,
		.trans_port	= NULL
	};

	struct dp_test_npf_nat_rule_t snat_20 = {
		.desc		= "snat 20",
		.rule		= "20",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "10.0.1.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat_10, true);
	dp_test_npf_snat_add(&snat_20, true);

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


	/*******************************************************************
	 * Pkt1: Forwards direction, Inside host 1 -> Outside host 3
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pkt1_pre = {
		.text       = "Fwd, Ins host1 -> Outs host3, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
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

	struct dp_test_pkt_desc_t v4_pkt1_post = {
		.text       = "Fwd, Ins host1 -> Outs host3, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.254",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
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


	pre = &v4_pkt1_pre;
	post = &v4_pkt1_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat_10.ifname, snat_10.rule, 0);
	dp_test_npf_snat_verify_pkts(snat_20.ifname, snat_20.rule, 1);

	dp_test_npf_portmap_port_verify("tcp", "172.0.2.254",
					pre->l4.tcp.sport);


	/*******************************************************************
	 * Pkt2: Backwards direction
	 *
	 * Outside host3 (172.0.2.3) -> UUT Outside intf (172.0.2.254)
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pkt2_pre = {
		.text       = "Rev, Outs host3 -> Outs UUT intf, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "172.0.2.254",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1000,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pkt2_post = {
		.text       = "Rev, Outs host3 -> Outs UUT intf, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.0.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1000,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	pre = &v4_pkt2_pre;
	post = &v4_pkt2_post;

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

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat_10.ifname, snat_10.rule, 0);
	dp_test_npf_snat_verify_pkts(snat_20.ifname, snat_20.rule, 2);


	/*******************************************************************
	 * Pkt3: Inside host2 (10.0.1.2) -> Outside host3 (172.0.2.3)
	 *
	 * This packet is identical to packet 1, except its from source
	 * address 10.0.1.2 instead of 10.0.1.1.
	 *
	 * Expect no SNAT translation since it is in the exclude rule
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pkt3_pre = {
		.text       = "Fwd, Ins host2 p1000 -> Outs host3, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "aa:bb:cc:dd:2:b2",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
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

	pre = &v4_pkt3_pre;
	post = &v4_pkt3_pre;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat_10.ifname, snat_10.rule, 1);
	dp_test_npf_snat_verify_pkts(snat_20.ifname, snat_20.rule, 2);


	/* Cleanup */
	dp_test_npf_snat_del(snat_10.ifname, snat_10.rule, true);
	dp_test_npf_snat_del(snat_20.ifname, snat_20.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;


/*
 * Source NAT (port range)
 *
 * Translated source port to a port in the range 4096-8191
 *
 *                      inside         outside
 *                             +-----+
 * host1            10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 *                      dp1T0  |     | dp2T1
 *                             +-----+
 *                              snat -->
 */
DP_DECL_TEST_CASE(npf_nat, npf_snat_port_range, NULL, NULL);

DP_START_TEST(npf_snat_port_range, test1)
{

	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "10.0.1.1", "aa:bb:cc:dd:2:b1");

	/*
	 * Add SNAT rule.  Translate src addr from the host1 inside addr
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
		.trans_addr	= "172.0.2.18",
		.trans_port	= "4096-8191"
	};

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
	 * 1. Packet A: Forwards, Host1 Inside port 1000 -> Host3 Outside
	 *****************************************************************/

	struct dp_test_pkt_desc_t v4_pktA_pre = {
		.text       = "Forw, Host1 Ins -> Host3 Outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = dp_test_intf_name2mac_str("dp1T0"),
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
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
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.18",
		.l2_src     = dp_test_intf_name2mac_str("dp2T1"),
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 0,
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

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context - dont verify session yet */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, false);
	dp_test_nat_set_validation(&cb_ctx, test_exp);
	dp_test_npf_nat_ctx_set_oport(nat_ctx, 1000);
	dp_test_npf_nat_ctx_set_tport(nat_ctx, 4096, 8191);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 1);

	/*
	 * The validation callback should have set nat_ctx->eport to the value
	 * chosen by the NAT translation.
	 */
	dp_test_npf_portmap_port_verify("tcp", "172.0.2.18", nat_ctx->eport);

	dp_test_npf_nat_session_verify(NULL,
				       pre->l3_src, pre->l4.tcp.sport,
				       pre->l3_dst, pre->l4.tcp.dport,
				       pre->proto,
				       snat.trans_addr,
				       nat_ctx->eport,
				       TRANS_TYPE_NATOUT,
				       pre->tx_intf,
				       SE_ACTIVE, SE_FLAGS_AE, true);

	/*
	 * Verify source port is changed
	 */
	dp_test_fail_unless(nat_ctx->eport != post->l4.tcp.sport,
			    "source port unchanged, got %u, expected %u",
			    nat_ctx->eport, post->l4.tcp.sport);


	/*****************************************************************
	 * 2. Packet B: Backwards, Host3 Outside -> Host1 Inside
	 *****************************************************************/

	struct dp_test_pkt_desc_t v4_pktB_pre = {
		.text       = "Back, Host3 Outs -> Host1 Ints, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "172.0.2.18",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = nat_ctx->eport,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pktB_post = {
		.text       = "Back, Host3 Outs -> Host1 Ints, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.3",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.0.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 1000,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 1,
				.win = 5840,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	pre = &v4_pktB_pre;
	post = &v4_pktB_post;

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

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 2);


	/*****************************************************************
	 * 3. Packet C: Forwards, Host1 Inside -> Host3 Outside
	 *
	 * Source port is already in the translation range, so the same port
	 * should be used.  However we need to be careful its not the port
	 * used by the previous packet.
	 *****************************************************************/

	uint16_t sport;

	/*
	 * Pick a source port in the trans range, but is not the one already
	 * inuse
	 */
	if (nat_ctx->eport != 5097)
		sport = 5097;
	else
		sport = 5099;

	struct dp_test_pkt_desc_t v4_pktC_pre = {
		.text       = "Forw, Host1 Ins -> Host3 Outs, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = sport,
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

	struct dp_test_pkt_desc_t v4_pktC_post = {
		.text       = "Forw, Host1 Ins -> Host3 Outs, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.18",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = sport,
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

	pre = &v4_pktC_pre;
	post = &v4_pktC_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context - dont verify session yet */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, false);
	dp_test_nat_set_validation(&cb_ctx, test_exp);
	dp_test_npf_nat_ctx_set_oport(nat_ctx, sport);
	dp_test_npf_nat_ctx_set_tport(nat_ctx, 4096, 8191);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 3);

	/*
	 * The validation callback should have set nat_ctx->eport to the value
	 * chosen by the NAT translation.
	 */
	post->l4.tcp.sport = nat_ctx->eport;

	dp_test_npf_portmap_port_verify("tcp", "172.0.2.18", nat_ctx->eport);

	dp_test_npf_nat_session_verify(NULL,
				       pre->l3_src, pre->l4.tcp.sport,
				       pre->l3_dst, pre->l4.tcp.dport,
				       pre->proto,
				       snat.trans_addr,
				       nat_ctx->eport,
				       TRANS_TYPE_NATOUT,
				       pre->tx_intf,
				       SE_ACTIVE, SE_FLAGS_AE, true);
	/*
	 * Verify source port is unchanged
	 */
	dp_test_fail_unless(nat_ctx->eport == post->l4.tcp.sport,
			    "source port changed, got %u, expected %u",
			    nat_ctx->eport, post->l4.tcp.sport);


	/* Cleanup */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "10.0.1.1", "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;


/*
 * Source NAT (masquerade, Address and Port Groups)
 *
 * Inside -> Outside, applied outbound
 *
 *                      inside         outside
 *                             +-----+
 * hosts1           10.0.1.254 |     | 172.0.2.254     host3
 * 10.0.1.1   -----------------| uut |---------------  172.0.2.3
 * host2                dp1T0  |     | dp2T1
 * 10.0.1.2                    +-----+
 *                              snat -->
 *
 *                                   --> Forwards (on output)
 *                              Source 10.0.1.x changed to 172.0.2.254, port y
 *
 *                                   <-- Back (on input)
 *                              Dest 172.0.2.254, port y changed to 10.0.1.x
 *
 */
DP_DECL_TEST_CASE(npf_nat, npf_snat_groups, NULL, NULL);

DP_START_TEST(npf_snat_groups, test1)
{
	struct dp_test_pkt_desc_t *pre, *post;
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	char inside_sm[20]; /* subnet and mask */

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",  "10.0.1.254/24");

	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");

	/* Add address group */
	dp_test_ipstr_to_netstr("10.0.1.254/24", inside_sm, sizeof(inside_sm));
	dp_test_npf_fw_addr_group_add("ADDR_GRP0");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", inside_sm);

	/* Add port group */
	dp_test_npf_fw_port_group_add("PORT_GRP", "1000");

	/*
	 * Add SNAT masquerade rule.  Packets outbound on dp2T1 will have
	 * their source addresses changed to the outside interface address,
	 * 172.0.2.254
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "ADDR_GRP0",
		.from_port	= "PORT_GRP",
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, false);


	/*
	 * Validation context
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


	/*******************************************************************
	 * Pkt1: Forwards direction, Inside host 1 -> Outside host 3
	 *******************************************************************/

	struct dp_test_pkt_desc_t v4_pkt1_pre = {
		.text       = "Fwd, Ins host1 -> Outs host3, pre-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
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

	struct dp_test_pkt_desc_t v4_pkt1_post = {
		.text       = "Fwd, Ins host1 -> Outs host3, post-NAT",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "172.0.2.254",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "172.0.2.3",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
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

	pre = &v4_pkt1_pre;
	post = &v4_pkt1_post;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);
	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Setup NAT validation context */
	dp_test_nat_set_ctx(nat_ctx, DP_TEST_NAT_DIR_FORW, DP_TEST_TRANS_SNAT,
			    pre, post, true);
	dp_test_nat_set_validation(&cb_ctx, test_exp);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/* Verify pkt count */
	dp_test_npf_snat_verify_pkts(snat.ifname, snat.rule, 1);

	dp_test_npf_portmap_verify("tcp", "172.0.2.254", "ACTIVE", 1);
	dp_test_npf_portmap_port_verify("tcp", "172.0.2.254",
					pre->l4.tcp.sport);


	/* Cleanup */
	dp_test_npf_fw_port_group_del("PORT_GRP");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", inside_sm);
	dp_test_npf_fw_addr_group_del("ADDR_GRP0");

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.1",  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0",  "10.0.1.2",  "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "172.0.2.3", "aa:bb:cc:dd:1:a1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "172.0.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.254/24");

} DP_END_TEST;


/*
 * Tests SNAT where same source address and source port are presented to SNAT
 * with different protocols.
 *
 * The second session will have the same trans port.
 */
DP_DECL_TEST_CASE(npf_nat, npf_snat10, NULL, NULL);
DP_START_TEST(npf_snat10, test1)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "192.0.2.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "203.0.113.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "203.0.114.1/24");

	dp_test_netlink_add_neigh("dp1T0", "192.0.2.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "203.0.113.203",
				  "aa:bb:cc:18:0:1");
	dp_test_netlink_add_neigh("dp2T1", "203.0.114.203",
				  "aa:bb:cc:18:0:1");

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "192.0.2.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 203.0.113.1 */
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/* UDP Forwards */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"203.0.113.1", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* UDP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "203.0.113.1", 10000,
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/* TCP Forwards */
	dpt_tcp(TH_SYN, "dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60001,
		"203.0.113.1", 10000, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* TCP Back */
	dpt_tcp(TH_SYN | TH_ACK, "dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "203.0.113.1", 10000,
		"203.0.113.203", 60001, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "192.0.2.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "203.0.113.203",
				  "aa:bb:cc:18:0:1");
	dp_test_netlink_del_neigh("dp2T1", "203.0.114.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "192.0.2.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "203.0.113.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "203.0.114.1/24");

} DP_END_TEST;
