/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT NAT tests
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
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_npf_sess_lib.h"

DP_DECL_TEST_SUITE(nat);

DP_DECL_TEST_CASE(nat, dnat, NULL, NULL);

DP_START_TEST(dnat, test_dnat)
{
	const char *client_ip, *server_ip, *local_dnat_ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str_1; /* nh on dp1T0 (towards client) */
	const char *nh_mac_str_2; /* nh on dp2T1 (towards server) */
	int len = 20;

	/*
	 * Dest Nat test
	 *
	 * TCP port 80 client 100.0.100.100 DNAT to web server 10.0.10.10
	 *
	 * 100.0.100.100 -> dp1T0(1.1.1.1) -> DNAT 10.0.10.10
	 *                                               -> dp2T1(2.2.2.2) ->
	 *               <-             <-                 <-         <- reply
	 */
	client_ip = "100.0.100.100";
	server_ip = "10.0.10.10";
	local_dnat_ip = "1.1.1.1"; /* DNAT is applied inbound */

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	/* Add the route / nh arp for the client to server flow */
	dp_test_netlink_add_route("10.0.10.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str_2 = "aa:bb:cc:dd:ee:a2";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str_2);

	/* Add the route / nh arp for the server to client flow */
	dp_test_netlink_add_route("100.0.100.0/24 nh 1.1.1.2 int:dp1T0");
	nh_mac_str_1 = "aa:bb:cc:dd:ee:a1";
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2", nh_mac_str_1);

	/* Add the dnat rule */
	dp_test_cmd_replace_dnat(10, "dp1T0", client_ip, server_ip, IPPROTO_TCP,
				 80);
	/*
	 * Test initial packet flow, outside to inside
	 */
	/* Create pak to match the client connection to server */
	test_pak = dp_test_create_tcp_ipv4_pak(client_ip, local_dnat_ip,
					       49152, 80, TH_SYN,
					       0, 0, 5840, NULL, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str_2,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);

	/* Expect the DNAT to have occurred */
	dp_test_set_iphdr(dp_test_exp_get_pak(exp), client_ip, server_ip);
	dp_test_set_tcphdr(dp_test_exp_get_pak(exp), 49152, 80);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test reply packet flow, inside to outside
	 */
	/* Create pak to match the server reply to the client */
	test_pak = dp_test_create_tcp_ipv4_pak(server_ip, client_ip,
					       80, 49152,
					       TH_SYN | TH_ACK, 0, 1, 5840,
					       NULL, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp2T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str_1,
				       dp_test_intf_name2mac_str("dp1T0"),
				       ETHER_TYPE_IPv4);

	/* Expect the reverse DNAT to have occurred */
	dp_test_set_iphdr(dp_test_exp_get_pak(exp), local_dnat_ip, client_ip);
	dp_test_set_tcphdr(dp_test_exp_get_pak(exp), 80, 49152);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", exp);

	/*
	 * Clean up
	 */
	dp_test_cmd_delete_dnat(10, "dp1T0", client_ip, IPPROTO_TCP);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str_2);
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2", nh_mac_str_1);
	dp_test_netlink_del_route("100.0.100.0/24 nh 1.1.1.2 int:dp1T0");
	dp_test_netlink_del_route("10.0.10.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

struct dp_test_variable_snat_params {
	struct dp_test_port_range *range;
	uint16_t port_used;
	validate_cb saved_cb;
};

static void
dp_test_variable_snat_port(struct rte_mbuf *m, struct ifnet *ifp,
			   struct dp_test_expected *expected,
			   enum dp_test_fwd_result_e fwd_result)
{
	struct dp_test_variable_snat_params *params =
		dp_test_exp_get_validate_ctx(expected);
	struct iphdr *ip = iphdr(m);
	struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

	/* fetch source port (offset 34) */
	params->port_used = ntohs(tcp->source);

	if (params->range) {
		/* if port out of range, leave pak as-is */
		if (params->port_used < params->range->start ||
		    params->port_used > params->range->end)
			goto done;
	}

	struct rte_mbuf *exp_pak = dp_test_exp_get_pak(expected);

	/* update expected pak with source port */
	ip = iphdr(exp_pak);
	tcp = (struct tcphdr *)(ip + 1);

	/* update source port (offset 34) */
	tcp->source = htons(params->port_used);

	/* update tcp checksum */
	tcp->check = 0;
	tcp->check = dp_test_calc_udptcp_chksum(dp_test_exp_get_pak(expected));

done:
	/* call saved check routine */
	(params->saved_cb)(m, ifp, expected, fwd_result);
}

DP_DECL_TEST_CASE(nat, snat, NULL, NULL);
DP_START_TEST(snat, test_snat)
{
	const char *client_ip, *server_ip, *local_snat_ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str_1; /* nh on dp1T0 (towards client) */
	const char *nh_mac_str_2; /* nh on dp2T1 (towards server) */
	int len = 20;

	/*
	 * Source Nat test
	 *
	 * TCP port 80 client 10.0.100.100 SNAT to web server 20.0.10.10
	 *
	 * 10.0.100.100 -> dp1T0(1.1.1.1) -> SNAT 100.0.10.10 ->
	 *                                                    dp2T1(2.2.2.2) ->
	 *               <-               <-                 <-         <- reply
	 */
	client_ip = "10.0.100.100";
	server_ip = "20.0.10.10";
	local_snat_ip = "2.2.2.2"; /* SNAT is applied outbound */

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	/* Add the route / nh arp for the client to server flow */
	dp_test_netlink_add_route("20.0.10.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str_2 = "aa:bb:cc:dd:ee:a2";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str_2);

	/* Add the route / nh arp for the server to client flow */
	dp_test_netlink_add_route("10.0.100.0/24 nh 1.1.1.2 int:dp1T0");
	nh_mac_str_1 = "aa:bb:cc:dd:ee:a1";
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2", nh_mac_str_1);

	/*
	 * Test initial packet flow, inside to outside
	 */
	/* Create pak to match the client connection to server */
#define SOURCE_PORT_NUMBER 49153
	test_pak = dp_test_create_tcp_ipv4_pak(client_ip, server_ip,
					       SOURCE_PORT_NUMBER, 80,
					       TH_SYN, 0, 0, 5840,
					       NULL, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str_2,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);

	/* Expect the SNAT to have occurred */
	dp_test_set_iphdr(dp_test_exp_get_pak(exp), local_snat_ip, server_ip);
	dp_test_set_tcphdr(dp_test_exp_get_pak(exp), SOURCE_PORT_NUMBER, 80);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	struct dp_test_port_range range = { .start = 4096, .end = 8191 };

	/* Add the snat rule */
	dp_test_cmd_replace_snat(20, "dp2T1", client_ip, local_snat_ip, &range);

	/* setup params for handling varying pak */
	struct dp_test_variable_snat_params params = { .range = &range };

	params.saved_cb =
		dp_test_exp_set_validate_cb(exp,
					    dp_test_variable_snat_port);
	dp_test_exp_set_validate_ctx(exp, &params, false);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Test reply packet flow, outside to inside
	 */
	/* Create pak to match the server reply to client */
	test_pak = dp_test_create_tcp_ipv4_pak(server_ip, local_snat_ip,
					       80, params.port_used,
					       TH_SYN | TH_ACK, 0, 1, 5840,
					       NULL, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp2T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp), nh_mac_str_1,
				       dp_test_intf_name2mac_str("dp1T0"),
				       ETHER_TYPE_IPv4);

	/* Expect the SNAT to have been undone */
	dp_test_set_iphdr(dp_test_exp_get_pak(exp), server_ip, client_ip);
	dp_test_set_tcphdr(dp_test_exp_get_pak(exp), 80, SOURCE_PORT_NUMBER);
#undef SOURCE_PORT_NUMBER

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", exp);

	/* Cleanup */
	dp_test_cmd_delete_snat(20, "dp2T1", client_ip);
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str_2);
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2", nh_mac_str_1);
	dp_test_netlink_del_route("20.0.10.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_netlink_del_route("10.0.100.0/24 nh 1.1.1.2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;
