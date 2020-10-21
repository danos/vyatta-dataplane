/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
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
#include <rte_hash.h>
#include <rte_jhash.h>
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
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_ppp.h"

DP_DECL_TEST_SUITE(npf_acl);

static void acl_setup(void)
{
	/* Setup v4 interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.0.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "20.0.2.1/24");

	dp_test_netlink_add_neigh("dp1T0", "10.0.1.2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "20.0.2.2", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "20.0.2.3", "aa:bb:cc:dd:2:b3");

	/* Setup v6 interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::3",
				  "aa:bb:cc:dd:2:b3");

}

static void acl_teardown(void)
{
	dp_test_netlink_del_neigh("dp1T0", "10.0.1.2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "20.0.2.2", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "20.0.2.3", "aa:bb:cc:dd:2:b3");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "20.0.2.1/24");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::3",
				  "aa:bb:cc:dd:2:b3");

}

static void _dpt_icmp6(uint8_t icmp_type, const char *rx_intf,
		       const char *pre_smac, const char *saddr, uint16_t icmpid,
		       const char *daddr, const char *post_dmac,
		       const char *tx_intf, int status,
		       const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	struct dp_test_pkt_desc_t v6_pkt = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = saddr,
		.l2_src     = pre_smac,
		.l3_dst     = daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = icmp_type,
				.code = 0,
				{
					.dpt_icmp_id = icmpid,
					.dpt_icmp_seq = 0,
				}
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	test_pak = dp_test_v6_pkt_from_desc(&v6_pkt);

	exp_pak = dp_test_v6_pkt_from_desc(&v6_pkt);
	test_exp = dp_test_exp_from_desc(exp_pak, &v6_pkt);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, status);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}

#define dpt_icmp6(_a, _b, _c, _d, _e, _f, _g, _h, _i)			\
	_dpt_icmp6(_a, _b, _c, _d, _e, _f, _g, _h, _i,			\
		   __FILE__, __func__, __LINE__)

/*
 * acl1 - IPv4 acl on input
 */
DP_DECL_TEST_CASE(npf_acl, acl1, acl_setup, acl_teardown);
DP_START_TEST(acl1, test)
{
	dp_test_npf_cmd("npf-ut add acl:v4test 0 family=inet", false);

	/* Drop ICMP */
	dp_test_npf_cmd("npf-ut add acl:v4test 10 "
			"src-addr=10.0.1.2 "
			"dst-addr=20.0.2.2 "
			"proto-base=1 "
			"action=drop", false);

	/* Drop UDP */
	dp_test_npf_cmd("npf-ut add acl:v4test 20 "
			"src-addr=10.0.1.2 src-port=10000 "
			"dst-addr=20.0.2.2 dst-port=20000 "
			"proto-base=17 "
			"action=drop", false);

	/* Drop TCP */
	dp_test_npf_cmd("npf-ut add acl:v4test 30 "
			"src-addr=10.0.1.2 src-port=32878 "
			"dst-addr=20.0.2.2 dst-port=80 "
			"proto-base=6 "
			"action=drop", false);

	dp_test_npf_cmd("npf-ut attach interface:dpT10 acl-in acl:v4test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	/* ICMP, no acl match */
	dpt_icmp(ICMP_ECHO,
		 "dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.3", 1234, "20.0.2.2",
		 "10.0.1.3", 1234, "20.0.2.2",
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_FORWARDED);

	/* ICMP, acl match */
	dpt_icmp(ICMP_ECHO,
		 "dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.2", 10000, "20.0.2.2",
		 "10.0.1.2", 10000, "20.0.2.2",
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_DROPPED);

	/* ICMP6 */
	dpt_icmp6(ICMP6_ECHO_REQUEST,
		  "dp1T0", "aa:bb:cc:dd:1:a1",
		  "2001:1:1::2", 10000, "2002:2:2::1",
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* UDP, no acl match */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.2", 10000, "20.0.2.3", 30000,
		 "10.0.1.2", 10000, "20.0.2.3", 30000,
		 "aa:bb:cc:dd:2:b3", "dp2T1",
		 DP_TEST_FWD_FORWARDED);

	/* UDP, acl match */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.2", 10000, "20.0.2.2", 20000,
		 "10.0.1.2", 10000, "20.0.2.2", 20000,
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_DROPPED);

	/* TCP, no acl match */
	dpt_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		"10.0.1.2", 32878, "20.0.2.2", 1024,
		"10.0.1.2", 32878, "20.0.2.2", 1024,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* TCP, acl match */
	dpt_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		"10.0.1.2", 32878, "20.0.2.2", 80,
		"10.0.1.2", 32878, "20.0.2.2", 80,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_DROPPED);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT10 acl-in acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;

/*
 * acl2 - v6 drop acl on input
 */
DP_DECL_TEST_CASE(npf_acl, acl2, acl_setup, acl_teardown);
DP_START_TEST(acl2, test)
{
	dp_test_npf_cmd("npf-ut add acl:v6test 0 family=inet6", false);

	/* Drop ICMP */
	dp_test_npf_cmd("npf-ut add acl:v6test 10 "
			"src-addr=2001:1:1::2 "
			"dst-addr=2002:2:2::1 "
			"proto-base=58 "
			"action=drop", false);

	/* Drop UDP */
	dp_test_npf_cmd("npf-ut add acl:v6test 20 "
			"src-addr=2001:1:1::2 "
			"dst-addr=2002:2:2::1 "
			"proto-base=17 "
			"action=drop", false);

	/* Drop TCP */
	dp_test_npf_cmd("npf-ut add acl:v6test 30 "
			"src-addr=2001:1:1::2 "
			"dst-addr=2002:2:2::1 dst-port=80 "
			"proto-base=6 "
			"action=drop", false);

	dp_test_npf_cmd("npf-ut attach interface:dpT10 acl-in acl:v6test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	dpt_icmp(ICMP_ECHO,
		 "dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.2", 10000, "20.0.2.2",
		 "10.0.1.2", 10000, "20.0.2.2",
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_FORWARDED);

	/* ICMP, no acl match */
	dpt_icmp6(ICMP6_ECHO_REQUEST,
		  "dp1T0", "aa:bb:cc:dd:1:a1",
		  "2001:1:1::3", 10000, "2002:2:2::1",
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* ICMP, acl match */
	dpt_icmp6(ICMP6_ECHO_REQUEST,
		  "dp1T0", "aa:bb:cc:dd:1:a1",
		  "2001:1:1::2", 10000, "2002:2:2::1",
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_DROPPED);

	/* UDP, no acl match */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"2001:1:1::3", 4321, "2002:2:2::1", 1024,
		"2001:1:1::3", 4321, "2002:2:2::1", 1024,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* UDP, acl match */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"2001:1:1::2", 1234, "2002:2:2::1", 1024,
		"2001:1:1::2", 1234, "2002:2:2::1", 1024,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_DROPPED);

	/* TCP, no acl match */
	dpt_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		"2001:1:1::3", 30123, "2002:2:2::1", 80,
		"2001:1:1::3", 30123, "2002:2:2::1", 80,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* TCP, acl match */
	dpt_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		"2001:1:1::2", 2121, "2002:2:2::1", 80,
		"2001:1:1::2", 2121, "2002:2:2::1", 80,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_DROPPED);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT10 acl-in acl:v6test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v6test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;


/*
 * acl3 - IPv4 acl on output
 */
DP_DECL_TEST_CASE(npf_acl, acl3, acl_setup, acl_teardown);
DP_START_TEST(acl3, test)
{
	dp_test_npf_cmd("npf-ut add acl:v4test 0 family=inet", false);

	/* Drop UDP */
	dp_test_npf_cmd("npf-ut add acl:v4test 20 "
			"src-addr=10.0.1.2 "
			"dst-addr=20.0.2.2 "
			"proto-base=17 "
			"action=drop", false);

	dp_test_npf_cmd("npf-ut attach interface:dpT21 acl-out acl:v4test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	/* UDP, no acl match */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.3", 10000, "20.0.2.2", 30000,
		 "10.0.1.3", 10000, "20.0.2.2", 30000,
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_FORWARDED);

	/* UDP, acl match */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.2", 10000, "20.0.2.2", 20000,
		 "10.0.1.2", 10000, "20.0.2.2", 20000,
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_DROPPED);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT21 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;

/*
 * acl4 - v6 drop acl on output
 */
DP_DECL_TEST_CASE(npf_acl, acl4, acl_setup, acl_teardown);
DP_START_TEST(acl4, test)
{
	dp_test_npf_cmd("npf-ut add acl:v6test 0 family=inet6", false);

	/* Drop TCP */
	dp_test_npf_cmd("npf-ut add acl:v6test 30 "
			"src-addr=2001:1:1::2 "
			"dst-addr=2002:2:2::1 dst-port=80 "
			"proto-base=6 "
			"action=drop", false);

	dp_test_npf_cmd("npf-ut attach interface:dpT21 acl-out acl:v6test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	/* TCP, no acl match */
	dpt_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		"2001:1:1::3", 30123, "2002:2:2::1", 80,
		"2001:1:1::3", 30123, "2002:2:2::1", 80,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* TCP, acl match */
	dpt_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		"2001:1:1::2", 2121, "2002:2:2::1", 80,
		"2001:1:1::2", 2121, "2002:2:2::1", 80,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_DROPPED);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT21 acl-out acl:v6test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v6test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;

/*
 *
 */
static void dpt_gre_spath(const char *gre_name,
			  const char *gre_local, const char *gre_remote,
			  const char *tx_intf, const char *nh_mac_str,
			  int status)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak, *payload_pak;
	int len = 64;
	int gre_pl_len;
	void *gre_payload;

	payload_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(payload_pak, nh_mac_str,
				 dp_test_intf_name2mac_str(tx_intf),
				 RTE_ETHER_TYPE_IPV4);

	gre_pl_len = rte_pktmbuf_data_len(payload_pak);

	test_pak = dp_test_create_gre_ipv4_pak(
		gre_local, gre_remote, 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(payload_pak,
				const struct rte_ether_hdr *), gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(test_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(test_pak,
				 nh_mac_str,
				 dp_test_intf_name2mac_str(tx_intf),
				 RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	rte_pktmbuf_free(test_pak);
	dp_test_exp_set_oif_name(exp, tx_intf);
	dp_test_exp_set_fwd_status(exp, status);
	dp_test_send_spath_pkt(payload_pak, gre_name, exp);
}

/*
 * acl5. Tests ACL egress on the ip_lookup_and_originate output path using a
 * GRE tunneled pkt.
 */
DP_DECL_TEST_CASE(npf_acl, acl5, NULL, NULL);
DP_START_TEST(acl5, test)
{
	const char *nh_mac_str2, *nh_mac_str3;

	dp_test_npf_cmd("npf-ut add acl:v4test 0 family=inet", false);
	dp_test_npf_cmd("npf-ut add acl:v4test 10 "
			"dst-addr=1.1.2.3 action=drop", false);
	dp_test_npf_cmd("npf-ut attach interface:dpT11 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut commit", false);

	nh_mac_str2 = "aa:bb:cc:dd:ee:f2";
	nh_mac_str3 = "aa:bb:cc:dd:ee:f3";

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.2.1/24");
	dp_test_netlink_add_neigh("dp1T1", "1.1.2.2", nh_mac_str2);
	dp_test_netlink_add_neigh("dp1T1", "1.1.2.3", nh_mac_str3);

	/*
	 * No acl match
	 */
	dp_test_intf_gre_l2_create("tun1", "1.1.2.1", "1.1.2.2", 0);
	dpt_gre_spath("tun1", "1.1.2.1", "1.1.2.2", "dp1T1", nh_mac_str2,
		      DP_TEST_FWD_FORWARDED);
	dp_test_intf_gre_l2_delete("tun1", "1.1.2.1", "1.1.2.2", 0);

	/*
	 * acl match
	 */
	dp_test_intf_gre_l2_create("tun2", "1.1.2.1", "1.1.2.3", 0);
	dpt_gre_spath("tun2", "1.1.2.1", "1.1.2.3", "dp1T1", nh_mac_str3,
		      DP_TEST_FWD_DROPPED);
	dp_test_intf_gre_l2_delete("tun2", "1.1.2.1", "1.1.2.3", 0);


	/*
	 * Clean up
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT11 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

	dp_test_netlink_del_neigh("dp1T1", "1.1.2.2", nh_mac_str2);
	dp_test_netlink_del_neigh("dp1T1", "1.1.2.3", nh_mac_str3);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.2.1/24");

} DP_END_TEST;

/*
 * acl6.  Tests ACL egress on IPv4 spath output
 */
DP_DECL_TEST_CASE(npf_acl, acl6, acl_setup, acl_teardown);
DP_START_TEST(acl6, test)
{
	dp_test_npf_cmd("npf-ut add acl:v4test 0 family=inet", false);

	/* Drop UDP */
	dp_test_npf_cmd("npf-ut add acl:v4test 20 "
			"dst-addr=20.0.2.2 "
			"proto-base=17 "
			"action=drop", false);

	dp_test_npf_cmd("npf-ut attach interface:dpT21 acl-out acl:v4test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	/* UDP, no acl match */
	dpt_udp(NULL, "aa:bb:cc:dd:1:a1",
		 "20.0.2.1", 10000, "20.0.2.3", 30000,
		 "20.0.2.1", 10000, "20.0.2.3", 30000,
		 "aa:bb:cc:dd:2:b3", "dp2T1",
		 DP_TEST_FWD_FORWARDED);

	/* UDP, acl match */
	dpt_udp(NULL, "aa:bb:cc:dd:1:a1",
		 "20.0.2.1", 10000, "20.0.2.2", 20000,
		 "20.0.2.1", 10000, "20.0.2.2", 20000,
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_DROPPED);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT21 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;

/*
 * acl7.  Tests ACL egress on IPv6 spath output
 */
DP_DECL_TEST_CASE(npf_acl, acl7, acl_setup, acl_teardown);
DP_START_TEST(acl7, test)
{

	dp_test_npf_cmd("npf-ut add acl:v6test 0 family=inet6", false);

	/* Drop UDP */
	dp_test_npf_cmd("npf-ut add acl:v6test 30 "
			"dst-addr=2002:2:2::1 "
			"proto-base=17 "
			"action=drop", false);

	dp_test_npf_cmd("npf-ut attach interface:dpT21 acl-out acl:v6test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	/* UDP, no acl match */
	dpt_udp(NULL, "aa:bb:cc:dd:1:a1",
		"2002:2:2::2", 4321, "2002:2:2::3", 1024,
		"2002:2:2::2", 4321, "2002:2:2::3", 1024,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* UDP, acl match */
	dpt_udp(NULL, "aa:bb:cc:dd:1:a1",
		"2002:2:2::2", 1234, "2002:2:2::1", 1024,
		"2002:2:2::2", 1234, "2002:2:2::1", 1024,
		"aa:bb:cc:dd:2:b1", "dp2T1",
		DP_TEST_FWD_DROPPED);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT21 acl-out acl:v6test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v6test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;

/*
 * acl8 - IPv4 drop acl on output, fragmented packet
 */
DP_DECL_TEST_CASE(npf_acl, acl8, acl_setup, acl_teardown);
DP_START_TEST(acl8, test)
{
	dp_test_npf_cmd("npf-ut add acl:v4test 0 family=inet", false);

	/* Drop UDP */
	dp_test_npf_cmd("npf-ut add acl:v4test 10 "
			"fragment=y "
			"src-addr=10.0.1.2 "
			"dst-addr=20.0.2.2 "
			"proto-base=17 "
			"action=drop", false);

	dp_test_npf_cmd("npf-ut attach interface:dpT21 acl-out acl:v4test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 800;

	struct dp_test_pkt_desc_t pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = len,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.0.1.3",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "20.0.2.2",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 10000,
				.dport = 30000
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/*
	 * 1st fragmented packet.  Source address does not match drop ACL so
	 * packet should be forwarded.
	 *
	 * First fragment is last in the array. Array indices to get an
	 * in-order packet are: 2, 0, 1
	 */
	struct rte_mbuf *frag_pkts[3] =  { 0 };
	uint16_t frag_sizes[3] = { 400, 400, 8 };
	int rc;

	pkt_UDP.l3_src = "10.0.1.3";
	test_pak = dp_test_v4_pkt_from_desc(&pkt_UDP);

	rc = dp_test_ipv4_fragment_packet(test_pak, frag_pkts,
					  ARRAY_SIZE(frag_pkts),
					  frag_sizes, 0);
	rte_pktmbuf_free(test_pak);

	dp_test_fail_unless(rc == ARRAY_SIZE(frag_pkts),
			    "dp_test_ipv4_fragment_packet failed: %d", rc);

	/* frag_pkts[2] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[2]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_pak_receive(frag_pkts[2], "dp1T0", exp);

	/* frag_pkts[0] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[0]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_pak_receive(frag_pkts[0], "dp1T0", exp);

	/* frag_pkts[1] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[1]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_pak_receive(frag_pkts[1], "dp1T0", exp);

	/*
	 * 2nd fragmented packet.  Source address does match drop ACL so
	 * packet should be dropped.
	 */
	pkt_UDP.l3_src = "10.0.1.2";
	test_pak = dp_test_v4_pkt_from_desc(&pkt_UDP);

	rc = dp_test_ipv4_fragment_packet(test_pak, frag_pkts,
					  ARRAY_SIZE(frag_pkts),
					  frag_sizes, 0);
	rte_pktmbuf_free(test_pak);

	dp_test_fail_unless(rc == ARRAY_SIZE(frag_pkts),
			    "dp_test_ipv4_fragment_packet failed: %d", rc);

	/* frag_pkts[2] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[2]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(frag_pkts[2], "dp1T0", exp);

	/* frag_pkts[0] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[0]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(frag_pkts[0], "dp1T0", exp);

	/* frag_pkts[1] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[1]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(frag_pkts[1], "dp1T0", exp);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT21 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;

/*
 * acl9 - v6 drop acl on output, fragmented packet
 */
DP_DECL_TEST_CASE(npf_acl, acl9, acl_setup, acl_teardown);
DP_START_TEST(acl9, test)
{
	dp_test_npf_cmd("npf-ut add acl:v6test 0 family=inet6", false);

	/* Drop TCP */
	dp_test_npf_cmd("npf-ut add acl:v6test 30 "
			"fragment=y "
			"src-addr=2001:1:1::2 "
			"dst-addr=2002:2:2::1 "
			"proto-base=44 "
			"proto-final=17 "
			"action=drop", false);

	dp_test_npf_cmd("npf-ut attach interface:dpT21 acl-out acl:v6test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 800;

	struct dp_test_pkt_desc_t pkt_UDP = {
		.text       = "IPv6 UDP",
		.len        = len,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:1:1::3",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 30123,
				.dport = 22143
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/*
	 * 1st fragmented packet.  Source address does not match drop ACL so
	 * packet should be forwarded.
	 *
	 * First fragment is last in the array. Array indices to get an
	 * in-order packet are: 2, 0, 1
	 */
	struct rte_mbuf *frag_pkts[3] =  { 0 };
	uint16_t frag_sizes[3] = { 400, 400, 8 };
	int rc;

	pkt_UDP.l3_src = "2001:1:1::3";
	test_pak = dp_test_v6_pkt_from_desc(&pkt_UDP);

	rc = dp_test_ipv6_fragment_packet(test_pak, frag_pkts,
					  ARRAY_SIZE(frag_pkts),
					  frag_sizes, 0);
	rte_pktmbuf_free(test_pak);

	dp_test_fail_unless(rc == ARRAY_SIZE(frag_pkts),
			    "dp_test_ipv6_fragment_packet failed: %d", rc);

	/* frag_pkts[2] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[2]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_pak_receive(frag_pkts[2], "dp1T0", exp);

	/* frag_pkts[0] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[0]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_pak_receive(frag_pkts[0], "dp1T0", exp);

	/* frag_pkts[1] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[1]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_pak_receive(frag_pkts[1], "dp1T0", exp);

	/*
	 * 2nd fragmented packet.  Source address does match drop ACL so
	 * packet should be dropped.
	 */
	pkt_UDP.l3_src = "2001:1:1::2";
	test_pak = dp_test_v6_pkt_from_desc(&pkt_UDP);

	rc = dp_test_ipv6_fragment_packet(test_pak, frag_pkts,
					  ARRAY_SIZE(frag_pkts),
					  frag_sizes, 0);
	rte_pktmbuf_free(test_pak);

	dp_test_fail_unless(rc == ARRAY_SIZE(frag_pkts),
			    "dp_test_ipv6_fragment_packet failed: %d", rc);

	/* frag_pkts[2] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[2]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(frag_pkts[2], "dp1T0", exp);

	/* frag_pkts[0] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[0]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(frag_pkts[0], "dp1T0", exp);

	/* frag_pkts[1] */
	exp = dp_test_exp_create_m(NULL, 1);
	dp_test_exp_set_pak_m(exp, 0, frag_pkts[1]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(frag_pkts[1], "dp1T0", exp);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT21 acl-out acl:v6test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v6test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;


/*
 * acl10 - IPv4 egress ACL on a pppoe interface.
 *
 * Two packets are sent over a pppoe session.  First one is permitted by the
 * ACL, and second one is blocked.
 *
 * (based on dp_test_ppp.c, TEST(ppp_traffic, ppp_traffic_1))
 */

static struct rte_mbuf *
npf_acl_pppoe_pkt(int len, const char *d_mac, const char *s_mac,
		  uint16_t ether_type)
{
	struct rte_mbuf *test_pak;

	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak, d_mac, s_mac, ether_type);

	return test_pak;
}

static struct dp_test_expected *
npf_acl_pppoe_exp(int len, struct rte_mbuf *test_pak, const char *oif,
		  const char *dst_mac, uint16_t session_id)
{
	struct dp_test_expected *exp;
	struct pppoe_packet *ppp_hdr;

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);

	dp_test_exp_set_oif_name(exp, oif);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	ppp_hdr = dp_test_ipv4_pktmbuf_ppp_prepend(
		dp_test_exp_get_pak(exp),
		dst_mac,
		dp_test_intf_name2mac_str(oif),
		len + 20 + 8,
		session_id);
	dp_test_fail_unless(ppp_hdr, "Could not prepend ppp header");

	return exp;
}

DP_DECL_TEST_CASE(npf_acl, acl10, NULL, NULL);
DP_START_TEST(acl10, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	const char *dst_mac = "aa:bb:cc:dd:ee:ff";
	uint16_t session_id = 3;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	dp_test_create_pppoe_session("pppoe0", "dp2T1", session_id,
				     dp_test_intf_name2mac_str("dp2T1"),
				     dst_mac);

	dp_test_netlink_add_route("10.73.2.0/24 nh int:pppoe0");

	/*
	 * Add egress ACL to *allow* traffic on pppoe interface
	 */
	dp_test_npf_cmd("npf-ut add acl:v4test 10 "
			"src-addr=1.1.1.1 "
			"proto-base=17 "
			"action=accept", false);
	dp_test_npf_cmd("npf-ut attach interface:pppoe0 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut commit", false);

	/* Ingress dp1T0 */
	test_pak = npf_acl_pppoe_pkt(len, dp_test_intf_name2mac_str("dp1T0"),
				     DP_TEST_INTF_DEF_SRC_MAC,
				     RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = npf_acl_pppoe_exp(len, test_pak, "dp2T1", dst_mac, session_id);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Change egress ACL to *block* traffic on pppoe interface
	 */
	dp_test_npf_cmd("npf-ut add acl:v4test 10 "
			"src-addr=1.1.1.1 "
			"proto-base=17 "
			"action=drop", false);
	dp_test_npf_cmd("npf-ut commit", false);

	test_pak = npf_acl_pppoe_pkt(len, dp_test_intf_name2mac_str("dp1T0"),
				     DP_TEST_INTF_DEF_SRC_MAC,
				     RTE_ETHER_TYPE_IPV4);

	/* Create pak we do *not* expect to receive on the tx ring */
	exp = npf_acl_pppoe_exp(len, test_pak, "dp2T1", dst_mac, session_id);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Cleanup */
	dp_test_npf_cmd("npf-ut detach interface:pppoe0 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

	dp_test_netlink_del_route("10.73.2.0/24 nh int:pppoe0");
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

} DP_END_TEST;

/*
 * acl11 - IPv4 egress ACL on a bridge interface.
 */
DP_DECL_TEST_CASE(npf_acl, acl11, NULL, NULL);
DP_START_TEST(acl11, test)
{
	struct rte_mbuf *test_pak;
	struct dp_test_expected *exp;
	int len = 20;

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

	/* Setup v4 interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.0.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("br1", "20.0.2.1/24");

	dp_test_netlink_add_neigh("dp1T0", "10.0.1.2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("br1", "20.0.2.2", "aa:bb:cc:dd:2:b1");

	/*
	 * Add egress ACL to br1 interface
	 */
	dp_test_npf_cmd("npf-ut add acl:v4test 10 "
			"src-addr=10.0.1.2 "
			"proto-base=17 "
			"action=drop", false);
	dp_test_npf_cmd("npf-ut attach interface:br1 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut commit", false);

	/*
	 * Packet #1.  Does not match 'drop' ACL, and is forwarded
	 */
	test_pak = dp_test_create_ipv4_pak("10.0.1.3", "20.0.2.2",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str("dp1T0"),
				 "aa:bb:cc:dd:1:a1", RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 "aa:bb:cc:dd:2:b1",
				 dp_test_intf_name2mac_str("br1"),
				 RTE_ETHER_TYPE_IPV4);

	dp_test_pak_receive(test_pak, "dp1T0", exp);


	/*
	 * Packet #2.  Matches 'drop' ACL, and is dropped
	 */
	test_pak = dp_test_create_ipv4_pak("10.0.1.2", "20.0.2.2",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str("dp1T0"),
				 "aa:bb:cc:dd:1:a1", RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 "aa:bb:cc:dd:2:b1",
				 dp_test_intf_name2mac_str("br1"),
				 RTE_ETHER_TYPE_IPV4);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T0", exp);


	/* Cleanup */
	dp_test_npf_cmd("npf-ut detach interface:br1 acl-out acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

	dp_test_netlink_del_neigh("dp1T0", "10.0.1.2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("br1", "20.0.2.2", "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("br1", "20.0.2.1/24");

	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_del("br1");

} DP_END_TEST;
