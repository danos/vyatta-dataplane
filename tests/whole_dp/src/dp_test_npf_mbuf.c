/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
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

#include "npf/nat/nat_pool_public.h"
#include "npf/cgnat/cgn.h"
#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_session.h"


DP_DECL_TEST_SUITE(npf_mbuf);

static void mbuf_setup(void);
static void mbuf_teardown(void);

/*
 * npf_mbuf1 - No npf
 * npf_mbuf2 - Firewall
 * npf_mbuf3 - SNAT
 * npf_mbuf4 - CGNAT
 */

/*
 * Split TCP header over two chained mbufs
 *
 * First test packet has all the l3 and l4 header in the first mbuf, and all
 * the payload in the second mbuf.
 *
 * Test is repeated 20 times (size of TCP hdr).  Each time round the loop one
 * more byte from the end of the first mbuf is prepended to the start of the
 * second mbuf.
 */
DP_DECL_TEST_CASE(npf_mbuf, npf_mbuf1, mbuf_setup, mbuf_teardown);
DP_START_TEST(npf_mbuf1, test)
{

	struct rte_mbuf *test_pak;
	struct dp_test_expected *exp;
	int len[2] = { 0, 20 };
	uint copy_bytes;
	uint copy_max = 20; /* size of TCP header */

	for (copy_bytes = 0; copy_bytes < copy_max; copy_bytes++) {

		test_pak = dp_test_create_tcp_ipv4_pak(
			"100.64.0.1", "1.1.1.1", 49152, 80, TH_SYN,
			0, 0, 5840, NULL, 2, len);

		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 "aa:bb:cc:dd:1:a1",
					 RTE_ETHER_TYPE_IPV4);

		exp = dp_test_exp_create(test_pak);

		dp_test_exp_set_oif_name(exp, "dp2T1");

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(exp), "aa:bb:cc:dd:2:b1",
			dp_test_intf_name2mac_str("dp2T1"),
			RTE_ETHER_TYPE_IPV4);

		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

		struct rte_mbuf *m = test_pak;
		uint i;
		char *src, *dst;

		/* Copy part of header to second buffer */

		/* assert that src has at least this many bytes */
		assert(copy_bytes < m->data_len);
		src = rte_pktmbuf_mtod(m, char *) + m->data_len - copy_bytes;

		/* assert that dst has at least this much headroom */
		assert(copy_bytes < rte_pktmbuf_headroom(m->next));
		dst = rte_pktmbuf_prepend(m->next, copy_bytes);

		for (i = 0; i < copy_bytes; i++)
			dst[i] = src[i];

		m->data_len -= copy_bytes;

		/* Run the test */
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

} DP_END_TEST;


/*
 * npf_mbuf2 -- Firewall
 */
DP_DECL_TEST_CASE(npf_mbuf, npf_mbuf2, mbuf_setup, mbuf_teardown);
DP_START_TEST(npf_mbuf2, test)
{

	struct rte_mbuf *test_pak;
	struct dp_test_expected *exp;
	int len[2] = { 0, 20 };
	uint copy_bytes;
	uint copy_max = 20; /* size of TCP header */

	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = false,
			.npf      = "proto-final=6 src-port=49152 dst-port=80 "
			"src-addr=100.64.0.1 dst-addr=1.1.1.1"
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

	for (copy_bytes = 0; copy_bytes < copy_max; copy_bytes++) {

		test_pak = dp_test_create_tcp_ipv4_pak(
			"100.64.0.1", "1.1.1.1", 49152, 80, TH_SYN,
			0, 0, 5840, NULL, 2, len);

		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 "aa:bb:cc:dd:1:a1",
					 RTE_ETHER_TYPE_IPV4);

		exp = dp_test_exp_create(test_pak);

		dp_test_exp_set_oif_name(exp, "dp2T1");

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(exp), "aa:bb:cc:dd:2:b1",
			dp_test_intf_name2mac_str("dp2T1"),
			RTE_ETHER_TYPE_IPV4);

		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

		struct rte_mbuf *m = test_pak;
		uint i;
		char *src, *dst;

		/* Copy part of header to second buffer */

		/* assert that src has at least this many bytes */
		assert(copy_bytes < m->data_len);
		src = rte_pktmbuf_mtod(m, char *) + m->data_len - copy_bytes;

		/* assert that dst has at least this much headroom */
		assert(copy_bytes < rte_pktmbuf_headroom(m->next));
		dst = rte_pktmbuf_prepend(m->next, copy_bytes);

		for (i = 0; i < copy_bytes; i++)
			dst[i] = src[i];

		m->data_len -= copy_bytes;

		/* Run the test */
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

	dp_test_npf_fw_del(&fw, false);

} DP_END_TEST;


/*
 * npf_mbuf3 -- SNAT
 */
DP_DECL_TEST_CASE(npf_mbuf, npf_mbuf3, mbuf_setup, mbuf_teardown);
DP_START_TEST(npf_mbuf3, test)
{

	struct rte_mbuf *test_pak, *exp_pak;
	struct dp_test_expected *exp;
	int len[2] = { 0, 20 };
	uint copy_bytes;
	uint copy_max = 20; /* size of TCP header */

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "100.64.0.1",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "1.1.1.13",
		.trans_port	= "1042-1042"
	};

	dp_test_npf_snat_add(&snat, true);

	for (copy_bytes = 0; copy_bytes < copy_max; copy_bytes++) {

		test_pak = dp_test_create_tcp_ipv4_pak(
			"100.64.0.1", "1.1.1.1", 0x123, 80, TH_SYN,
			0, 0, 5840, NULL, 2, len);

		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 "aa:bb:cc:dd:1:a1",
					 RTE_ETHER_TYPE_IPV4);

		exp_pak = dp_test_create_tcp_ipv4_pak(
			"1.1.1.13", "1.1.1.1", 0x412, 80, TH_SYN,
			0, 0, 5840, NULL, 2, len);

		dp_test_pktmbuf_eth_init(exp_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 "aa:bb:cc:dd:1:a1",
					 RTE_ETHER_TYPE_IPV4);

		exp = dp_test_exp_create(exp_pak);
		rte_pktmbuf_free(exp_pak);

		dp_test_exp_set_oif_name(exp, "dp2T1");

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(exp), "aa:bb:cc:dd:2:b1",
			dp_test_intf_name2mac_str("dp2T1"),
			RTE_ETHER_TYPE_IPV4);

		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

		struct rte_mbuf *m = test_pak;
		uint i;
		char *src, *dst;

		/* Copy part of header to second buffer */

		/* assert that src has at least this many bytes */
		assert(copy_bytes < m->data_len);
		src = rte_pktmbuf_mtod(m, char *) + m->data_len - copy_bytes;

		/* assert that dst has at least this much headroom */
		assert(copy_bytes < rte_pktmbuf_headroom(m->next));
		dst = rte_pktmbuf_prepend(m->next, copy_bytes);

		for (i = 0; i < copy_bytes; i++)
			dst[i] = src[i];

		m->data_len -= copy_bytes;

		/* Run the test */
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

} DP_END_TEST;


/*
 * npf_mbuf4 -- CGNAT
 */
DP_DECL_TEST_CASE(npf_mbuf, npf_mbuf4, mbuf_setup, mbuf_teardown);
DP_START_TEST(npf_mbuf4, test)
{

	struct rte_mbuf *test_pak, *exp_pak;
	struct dp_test_expected *exp;
	int len[2] = { 0, 20 };
	uint copy_bytes;
	uint copy_max = 20; /* size of TCP header */

	dp_test_npf_cmd_fmt(false,
			    "nat-ut pool add POOL1 "
			    "type=cgnat "
			    "address-range=RANGE1/1.1.1.13-1.1.1.13");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/24", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF,
			 CGN_3TUPLE, true);

	for (copy_bytes = 0; copy_bytes < copy_max; copy_bytes++) {

		test_pak = dp_test_create_tcp_ipv4_pak(
			"100.64.0.1", "1.1.1.1", 0x123, 80, TH_SYN,
			0, 0, 5840, NULL, 2, len);

		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 "aa:bb:cc:dd:1:a1",
					 RTE_ETHER_TYPE_IPV4);

		exp_pak = dp_test_create_tcp_ipv4_pak(
			"1.1.1.13", "1.1.1.1", 1024, 80, TH_SYN,
			0, 0, 5840, NULL, 2, len);

		dp_test_pktmbuf_eth_init(exp_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 "aa:bb:cc:dd:1:a1",
					 RTE_ETHER_TYPE_IPV4);

		exp = dp_test_exp_create(exp_pak);
		rte_pktmbuf_free(exp_pak);

		dp_test_exp_set_oif_name(exp, "dp2T1");

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(exp), "aa:bb:cc:dd:2:b1",
			dp_test_intf_name2mac_str("dp2T1"),
			RTE_ETHER_TYPE_IPV4);

		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

		struct rte_mbuf *m = test_pak;
		uint i;
		char *src, *dst;

		/* Copy part of header to second buffer */

		/* assert that src has at least this many bytes */
		assert(copy_bytes < m->data_len);
		src = rte_pktmbuf_mtod(m, char *) + m->data_len - copy_bytes;

		/* assert that dst has at least this much headroom */
		assert(copy_bytes < rte_pktmbuf_headroom(m->next));
		dst = rte_pktmbuf_prepend(m->next, copy_bytes);

		for (i = 0; i < copy_bytes; i++)
			dst[i] = src[i];

		m->data_len -= copy_bytes;

		/* Run the test */
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


static void mbuf_setup(void)
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

static void mbuf_teardown(void)
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

