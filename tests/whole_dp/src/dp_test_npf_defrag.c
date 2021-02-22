/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <errno.h>
#include <time.h>
#include <values.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include <rte_ip.h>
#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_sess_lib.h"


DP_DECL_TEST_SUITE(npf_defrag);

static void defrag_setup(void);
static void defrag_teardown(void);

static void
_defrag_udp(const char *rx_intf, const char *pre_smac, int pre_vlan,
	   const char *pre_saddr, uint16_t pre_sport,
	   const char *pre_daddr, uint16_t pre_dport,
	   const char *post_saddr, uint16_t post_sport,
	   const char *post_daddr, uint16_t post_dport,
	   const char *post_dmac, int post_vlan, const char *tx_intf,
	   int status,
	   const char *file, const char *func, int line);
#define defrag_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		   _i, _j, _k, _l, _m, _n, _o)				\
	_defrag_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		    _i, _j, _k, _l, _m, _n, _o,				\
		    __FILE__, __func__, __LINE__)

static void
_defrag_multi(const char *rx_intf, const char *pre_smac, int pre_vlan,
	      const char *pre_saddr, uint16_t pre_sport,
	      const char *pre_daddr, uint16_t pre_dport,
	      const char *post_saddr, uint16_t post_sport,
	      const char *post_daddr, uint16_t post_dport,
	      const char *post_dmac, int post_vlan, const char *tx_intf,
	      int status,
	      const char *file, const char *func, int line);
#define defrag_multi(_a, _b, _c, _d, _e, _f, _g, _h,			\
		     _i, _j, _k, _l, _m, _n, _o)			\
	_defrag_multi(_a, _b, _c, _d, _e, _f, _g, _h,			\
		      _i, _j, _k, _l, _m, _n, _o,			\
		      __FILE__, __func__, __LINE__)

static void
_defrag_duplicate(const char *rx_intf, const char *pre_smac, int pre_vlan,
		const char *pre_saddr, uint16_t pre_sport,
		const char *pre_daddr, uint16_t pre_dport,
		const char *post_saddr, uint16_t post_sport,
		const char *post_daddr, uint16_t post_dport,
		const char *post_dmac, int post_vlan, const char *tx_intf,
		int status, int duplicate_index,
		const char *file, const char *func, int line);
#define defrag_duplicate(_a, _b, _c, _d, _e, _f, _g, _h,                \
			_i, _j, _k, _l, _m, _n, _o, _p)                 \
		_defrag_duplicate(_a, _b, _c, _d, _e, _f, _g, _h,       \
			_i, _j, _k, _l, _m, _n, _o, _p,                 \
			__FILE__, __func__, __LINE__)

/*
 * defrag1 - Tests defrag with SNAT and UDP.
 *
 * Sends 4 fragments, and verifies re-assembled packet after translation.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_defrag, defrag1, defrag_setup, defrag_teardown);
DP_START_TEST(defrag1, test)
{
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= "100.64.0.1",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "1.1.1.11",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/* Check defrag feature is enabled */
	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv4-defrag-in",
				 "ipv4-validate");
	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv4-defrag-out",
				 "ipv4-out");

	defrag_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		   "100.64.0.1", 49152, "1.1.1.1", 80,
		   "1.1.1.11", 49152, "1.1.1.1", 80,
		   "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		   DP_TEST_FWD_FORWARDED);

	/* Cleanup */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	/* Check defrag feature is disabled */
	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-defrag-in",
				      "ipv4-validate");
	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-defrag-out",
				      "ipv4-out");

} DP_END_TEST;


/*
 * defrag2 - Tests defrag with output firewall and UDP.
 *
 * Sends 4 fragments, and verifies re-assembled packet.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_defrag, defrag2, defrag_setup, defrag_teardown);
DP_START_TEST(defrag2, test)
{
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = false,
			.npf      = "proto-final=17"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "OUT_FW",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rset
	};

	dp_test_npf_fw_add(&fw, false);

	/* Check defrag feature is enabled */
	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv4-defrag-in",
				 "ipv4-validate");
	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv4-defrag-out",
				 "ipv4-out");

	defrag_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		   "100.64.0.1", 49152, "1.1.1.1", 80,
		   "100.64.0.1", 49152, "1.1.1.1", 80,
		   "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		   DP_TEST_FWD_FORWARDED);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	/* Check defrag feature is disabled */
	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-defrag-in",
				      "ipv4-validate");
	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-defrag-out",
				      "ipv4-out");

} DP_END_TEST;


/*
 * defrag3 - Tests defrag with input firewall and UDP.
 *
 * Sends 4 fragments, and verifies re-assembled packet.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_defrag, defrag3, defrag_setup, defrag_teardown);
DP_START_TEST(defrag3, test)
{
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = false,
			.npf      = "proto-final=17"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "IN_FW",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rset
	};

	dp_test_npf_fw_add(&fw, false);

	/* Check defrag feature is enabled */
	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-defrag-in",
				 "ipv4-validate");
	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-defrag-out",
				 "ipv4-out");

	defrag_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		   "100.64.0.1", 49152, "1.1.1.1", 80,
		   "100.64.0.1", 49152, "1.1.1.1", 80,
		   "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		   DP_TEST_FWD_FORWARDED);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	/* Check defrag feature is disabled */
	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-defrag-in",
				      "ipv4-validate");
	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-defrag-out",
				      "ipv4-out");

} DP_END_TEST;


/*
 * defrag4 - Tests defrag with input firewall and multi fragments.
 *
 * Sends two interleaved fragmented packets.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */

DP_DECL_TEST_CASE(npf_defrag, defrag4, defrag_setup, defrag_teardown);
DP_START_TEST(defrag4, test)
{
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = false,
			.npf      = "proto-final=17"
		},
		{
			.rule     = "20",
			.pass     = PASS,
			.stateful = false,
			.npf      = "proto-final=6"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "IN_FW",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rset
	};

	dp_test_npf_fw_add(&fw, false);

	/* Check defrag feature is enabled */
	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-defrag-in",
				 "ipv4-validate");
	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-defrag-out",
				 "ipv4-out");

	defrag_multi("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		     "100.64.0.1", 49152, "1.1.1.1", 80,
		     "100.64.0.1", 49152, "1.1.1.1", 80,
		     "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		     DP_TEST_FWD_FORWARDED);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	/* Check defrag feature is disabled */
	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-defrag-in",
				      "ipv4-validate");
	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-defrag-out",
				      "ipv4-out");

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_defrag, defrag5, defrag_setup, defrag_teardown);
DP_START_TEST(defrag5, test)
{
		struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = false,
			.npf      = "proto-final=17"
		},
		{
			.rule     = "20",
			.pass     = PASS,
			.stateful = false,
			.npf      = "proto-final=6"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "IN_FW",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rset
	};

	dp_test_npf_fw_add(&fw, false);

	/* Check defrag feature is enabled */
	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-defrag-in",
				"ipv4-validate");
	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-defrag-out",
				"ipv4-out");

	defrag_duplicate("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			"100.64.0.1", 49152, "1.1.1.1", 80,
			"100.64.0.1", 49152, "1.1.1.1", 80,
			"aa:bb:cc:dd:2:b1", 0, "dp2T1",
			DP_TEST_FWD_FORWARDED, 0);

	defrag_duplicate("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			"100.64.0.1", 49152, "1.1.1.1", 80,
			"100.64.0.1", 49152, "1.1.1.1", 80,
			"aa:bb:cc:dd:2:b1", 0, "dp2T1",
			DP_TEST_FWD_FORWARDED, 1);

	defrag_duplicate("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			"100.64.0.1", 49152, "1.1.1.1", 80,
			"100.64.0.1", 49152, "1.1.1.1", 80,
			"aa:bb:cc:dd:2:b1", 0, "dp2T1",
			DP_TEST_FWD_FORWARDED, 2);

	defrag_duplicate("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			"100.64.0.1", 49152, "1.1.1.1", 80,
			"100.64.0.1", 49152, "1.1.1.1", 80,
			"aa:bb:cc:dd:2:b1", 0, "dp2T1",
			DP_TEST_FWD_FORWARDED, 3);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, false);

	/* Check defrag feature is disabled */
	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-defrag-in",
					"ipv4-validate");
	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-defrag-out",
					"ipv4-out");

} DP_END_TEST;

static void defrag_setup(void)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.64.0.254/16");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.254/24");

	/*
	 * Inside
	 */
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.2",
				  "aa:bb:cc:dd:1:a2");
	dp_test_netlink_add_neigh("dp1T0", "100.64.1.1",
				  "aa:bb:cc:dd:1:a3");

	/*
	 * Outside
	 */
	dp_test_netlink_add_neigh("dp2T1", "1.1.1.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "1.1.1.2",
				  "aa:bb:cc:dd:2:b2");

}

static void defrag_teardown(void)
{
	/* Cleanup */
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.1", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.2", "aa:bb:cc:dd:1:a2");
	dp_test_netlink_del_neigh("dp1T0", "100.64.1.1", "aa:bb:cc:dd:1:a3");
	dp_test_netlink_del_neigh("dp2T1", "1.1.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "1.1.1.2", "aa:bb:cc:dd:2:b2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.64.0.254/16");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.254/24");

	dp_test_npf_cleanup();
}

/*
 * defrag_udp
 *
 * Sends 4 fragments, and expects 1 reassembled packet
 */
static void
_defrag_udp(const char *rx_intf, const char *pre_smac, int pre_vlan,
	    const char *pre_saddr, uint16_t pre_sport,
	    const char *pre_daddr, uint16_t pre_dport,
	    const char *post_saddr, uint16_t post_sport,
	    const char *post_daddr, uint16_t post_dport,
	    const char *post_dmac, int post_vlan, const char *tx_intf,
	    int status,
	    const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;
	int len = 1200;

	/* Pre IPv4 UDP packet */
	struct dp_test_pkt_desc_t pre_pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = len,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = pre_sport,
				.dport = pre_dport
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	/* Post IPv4 UDP packet */
	struct dp_test_pkt_desc_t post_pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = len,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = post_saddr,
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = post_daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = post_sport,
				.dport = post_dport
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	test_pak = dp_test_v4_pkt_from_desc(&pre_pkt_UDP);

	/* Fragment test pak */
	struct rte_mbuf *frag_pkts[4] =  { 0 };
	uint16_t frag_sizes[4] = { 400, 400, 400, 8 };
	int rc;

	rc = dp_test_ipv4_fragment_packet(test_pak, frag_pkts,
					  4, frag_sizes, 0);
	dp_test_fail_unless(rc == ARRAY_SIZE(frag_pkts),
			    "dp_test_ipv4_fragment_packet failed: %d", rc);
	rte_pktmbuf_free(test_pak);

	/* 1st fragment */
	test_pak = frag_pkts[0];

	/* Doesn't matter what exp pkt is created ... it will be 'dropped' */
	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);
	rte_pktmbuf_free(exp_pak);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);

	/* 2nd fragment */
	test_pak = frag_pkts[1];

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);
	rte_pktmbuf_free(exp_pak);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);

	/* 3rd fragment */
	test_pak = frag_pkts[2];

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);
	rte_pktmbuf_free(exp_pak);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);

	/* Last fragment */
	test_pak = frag_pkts[3];

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	dp_test_exp_set_fwd_status(test_exp, status);
	rte_pktmbuf_free(exp_pak);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}

/*
 * Note, the fragments created are not in order. The last mbuf is the first
 * fragment.  So for 4 fragments, the order in the frags[] array is 3, 0, 1, 2
 */
static void
_defrag_create_frags(struct dp_test_pkt_desc_t *pkt,
		      struct rte_mbuf **frags,
		      uint16_t *frag_sizes, int nfrags,
		      const char *file, const char *func, int line)
{
	struct rte_mbuf *test_pak;
	int rc;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	_dp_test_fail_unless(test_pak, file, line,
			     "Failed to create test_pak");

	rc = dp_test_ipv4_fragment_packet(test_pak, frags, nfrags,
					  frag_sizes, 0);

	_dp_test_fail_unless(rc == nfrags, file, line,
			     "dp_test_ipv4_fragment_packet failed: %d",
			     rc);
	rte_pktmbuf_free(test_pak);
}

#define defrag_create_frags(_a, _b, _c, _d)			\
	_defrag_create_frags(_a, _b, _c, _d,			\
			      __FILE__, __func__, __LINE__)

static void
_defrag_send_frag(struct rte_mbuf *frag,
		   struct dp_test_pkt_desc_t *pkt, int status,
		   const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *exp_pak;

	exp_pak = dp_test_v4_pkt_from_desc(pkt);

	test_exp = dp_test_exp_from_desc(exp_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, status);
	rte_pktmbuf_free(exp_pak);

	_dp_test_pak_receive(frag, pkt->rx_intf, test_exp, file, func, line);
}

#define defrag_send_frag(_a, _b, _c)				\
	_defrag_send_frag(_a, _b, _c, __FILE__, __func__, __LINE__)


/*
 * defrag_multi
 *
 * Interleave two sets of packet fragments.  Only difference in the packets is
 * the protocol (TCP and UDP).
 */
static void
_defrag_multi(const char *rx_intf, const char *pre_smac, int pre_vlan,
	      const char *pre_saddr, uint16_t pre_sport,
	      const char *pre_daddr, uint16_t pre_dport,
	      const char *post_saddr, uint16_t post_sport,
	      const char *post_daddr, uint16_t post_dport,
	      const char *post_dmac, int post_vlan, const char *tx_intf,
	      int status,
	      const char *file, const char *func, int line)
{
	/* IPv4 UDP packet */
	struct dp_test_pkt_desc_t pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = 1200,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = pre_sport,
				.dport = pre_dport
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	/* IPv4 TCP packet */
	struct dp_test_pkt_desc_t pkt_TCP = {
		.text       = "IPv4 TCP",
		.len        = 1204,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = pre_sport,
				.dport = pre_dport,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};


	/* Fragment UDP test pak */
	struct rte_mbuf *frag_pkts1[4] =  { 0 };
	uint16_t frag_sizes1[4] = { 400, 400, 400, 8 };

	defrag_create_frags(&pkt_UDP, frag_pkts1, frag_sizes1, 4);


	/* Fragment TCP test pak */
	struct rte_mbuf *frag_pkts2[4] =  { 0 };
	uint16_t frag_sizes2[4] = { 400, 400, 400, 24 };

	defrag_create_frags(&pkt_TCP, frag_pkts2, frag_sizes2, 4);

	/* 1st UDP fragment */
	defrag_send_frag(frag_pkts1[3], &pkt_UDP, DP_TEST_FWD_DROPPED);

	/* 1st TCP fragment */
	defrag_send_frag(frag_pkts2[3], &pkt_TCP, DP_TEST_FWD_DROPPED);

	/* 2nd UDP fragment */
	defrag_send_frag(frag_pkts1[0], &pkt_UDP, DP_TEST_FWD_DROPPED);

	/* 2nd TCP fragment */
	defrag_send_frag(frag_pkts2[0], &pkt_TCP, DP_TEST_FWD_DROPPED);

	/* 3rd UDP fragment */
	defrag_send_frag(frag_pkts1[1], &pkt_UDP, DP_TEST_FWD_DROPPED);

	/* 3rd TCP fragment */
	defrag_send_frag(frag_pkts2[1], &pkt_TCP, DP_TEST_FWD_DROPPED);

	/* Last UDP fragment */
	defrag_send_frag(frag_pkts1[2], &pkt_UDP, DP_TEST_FWD_FORWARDED);

	/* Last TCP fragment */
	defrag_send_frag(frag_pkts2[2], &pkt_TCP, DP_TEST_FWD_FORWARDED);
}



/*
 * defrag_multi
 *
 * Interleave two sets of packet fragments.  Only difference in the packets is
 * the protocol (TCP and UDP).
 */
static void
_defrag_duplicate(const char *rx_intf, const char *pre_smac, int pre_vlan,
		const char *pre_saddr, uint16_t pre_sport,
		const char *pre_daddr, uint16_t pre_dport,
		const char *post_saddr, uint16_t post_sport,
		const char *post_daddr, uint16_t post_dport,
		const char *post_dmac, int post_vlan, const char *tx_intf,
		int status, int duplicate_index,
		const char *file, const char *func, int line)
{
	/* IPv4 UDP packet */
	struct dp_test_pkt_desc_t pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = 1200,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
				.udp = {
				.sport = pre_sport,
				.dport = pre_dport
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};
	enum dp_test_fwd_result_e fwd_status = DP_TEST_FWD_DROPPED;

	/* Fragment UDP test pak */
	struct rte_mbuf *frag_pkts1[4] =  { 0 };
	uint16_t frag_sizes1[4] = { 400, 400, 400, 8 };

	defrag_create_frags(&pkt_UDP, frag_pkts1, frag_sizes1, 4);

	/* Array indices to get an in order packet are: 3,0,1,2 */

	/* Send the duplicate first */
	_defrag_send_frag(frag_pkts1[duplicate_index],
			  &pkt_UDP, fwd_status,
			  file, func, line);

	/* First packet - start of packet */
	_defrag_send_frag(frag_pkts1[3], &pkt_UDP, fwd_status,
			  file, func, line);

	/* 2nd UDP fragment */
	_defrag_send_frag(frag_pkts1[0], &pkt_UDP, fwd_status,
			  file, func, line);

	/* 3rd UDP fragment */
	if (duplicate_index == 2)
		fwd_status = DP_TEST_FWD_FORWARDED;
	_defrag_send_frag(frag_pkts1[1], &pkt_UDP, fwd_status,
			  file, func, line);

	/* Last UDP fragment */
	if (duplicate_index == 2)
		fwd_status = DP_TEST_FWD_DROPPED;
	else
		fwd_status = DP_TEST_FWD_FORWARDED;
	_defrag_send_frag(frag_pkts1[2], &pkt_UDP, fwd_status,
			file, func, line);
}

