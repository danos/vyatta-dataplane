/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <stdbool.h>

#include <netinet/in.h>
#include <linux/xfrm.h>
#include <arpa/inet.h>

#include "ip_funcs.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_crypto_utils.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_npf_lib.h"
/*
 *                    +-----------+  dp2T2
 *                    |           |
 *             dp1T1  |           +-------+  2.2.2.2/24
 *                    |           |
 *              +-----+    UUT    |
 *                    |           |
 *        1.1.1.2/24  |           +-------+  3.3.3.2/24
 *                    |           |
 *                    +-----------+  dp3T3
 */

#define SOURCE_IP_ADDR  "1.1.1.1"
#define SOURCE_MAC_ADDR "aa:bb:cc:dd:1:1"

/*
 * Tunnel 1 parameters
 */
#define TUN_1_LOCAL_IP_ADDR   "2.2.2.2"
#define TUN_1_REMOTE_IP_ADDR  "2.2.2.3"
#define TUN_1_REMOTE_MAC_ADDR "aa:bb:cc:dd:2:3"
#define TUN_1_LOCAL_PREFIX "1.1.1.0/24"
#define TUN_1_REMOTE_PREFIX "8.8.8.0/24"
#define TUN_1_SINK_IP_ADDR  "8.8.8.8"
#define TUN_1_IN_SA_SPI   0x22223333
#define TUN_1_OUT_SA_SPI  0x33332222
#define TUN_1_REQID       0x1111

/*
 * Tunnel 2 parameters
 */
#define TUN_2_LOCAL_IP_ADDR  "3.3.3.2"
#define TUN_2_REMOTE_IP_ADDR "3.3.3.4"
#define TUN_2_REMOTE_MAC_ADDR "aa:bb:cc:dd:3:4"
#define TUN_2_LOCAL_PREFIX  "1.1.1.0/24"
#define TUN_2_REMOTE_PREFIX "9.9.9.0/24"
#define TUN_2_SINK_IP_ADDR  "9.9.9.9"
#define TUN_2_IN_SA_SPI   0x22224444
#define TUN_2_OUT_SA_SPI  0x44442222
#define TUN_2_REQID       0x2222

/*
 * Tunnel 3 parameters
 *
 * Note that tunnel 3 uses the same remote peer
 * as tunnel 1, but has a different reqid and
 * remote prefix.
 */
#define TUN_3_LOCAL_IP_ADDR   TUN_1_LOCAL_IP_ADDR
#define TUN_3_REMOTE_IP_ADDR  TUN_1_REMOTE_IP_ADDR
#define TUN_3_REMOTE_MAC_ADDR TUN_1_REMOTE_MAC_ADDR
#define TUN_3_LOCAL_PREFIX    TUN_1_LOCAL_PREFIX
#define TUN_3_REMOTE_PREFIX "10.10.10.0/24"
#define TUN_3_SINK_IP_ADDR  "10.10.10.10"
#define TUN_3_IN_SA_SPI   0x22331010
#define TUN_3_OUT_SA_SPI  0x10102233
#define TUN_3_REQID       0x3333

#define TUN_3_EXTRA_OUT_SA_SPI 0x10002000

DP_DECL_TEST_SUITE(crypto_multi_tunnel);

/*
 * setup()
 *
 * Setup the interfaces, address and ARP neighbours which are common
 * to all test cases in this module.
 */
static void setup(void)
{
	/* Set up local addresses and ARP cache entries for neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.0/24");
	dp_test_netlink_add_neigh("dp1T1", SOURCE_IP_ADDR, SOURCE_MAC_ADDR);

	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.0/24");
	dp_test_netlink_add_neigh("dp2T2", TUN_1_REMOTE_IP_ADDR,
				  TUN_1_REMOTE_MAC_ADDR);

	dp_test_nl_add_ip_addr_and_connected("dp3T3", "3.3.3.0/24");
	dp_test_netlink_add_neigh("dp3T3", TUN_2_REMOTE_IP_ADDR,
				  TUN_2_REMOTE_MAC_ADDR);
}

/*
 * teardown()
 *
 * Tear down the interfaces, address and ARP neighbours which are common
 * to all test cases in this module.
 */
static void teardown(void)
{
	/* Remove local addresses and ARP cache entries for neighbours */
	dp_test_netlink_del_neigh("dp3T3", TUN_2_REMOTE_IP_ADDR,
				  TUN_2_REMOTE_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "3.3.3.0/24");
	dp_test_netlink_del_neigh("dp2T2", TUN_1_REMOTE_IP_ADDR,
				  TUN_1_REMOTE_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.0/24");
	dp_test_netlink_del_neigh("dp1T1", SOURCE_IP_ADDR, SOURCE_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.0/24");
}

/*
 * create_expected_packet()
 *
 * This function creates an expectation for an encrypted
 * packet. Only the IP header and ESP header are verified,
 * the encrypted payload is not checked.
 */
static struct dp_test_expected *create_expected_packet(const char *src,
						       const char *dst,
						       const char *dst_mac,
						       uint32_t spi,
						       int payload_len,
						       const char *ifname)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *pak;
	char *payload;

	/*
	 * We limit validation to the IP header and the following
	 * ESP header, so a zero filled buffer of the right length
	 * is sufficient for our needs.
	 */
	payload = calloc(payload_len, 1);
	pak = dp_test_create_esp_ipv4_pak(src, dst, 1,
					  &payload_len, payload,
					  spi, 1, 0, 255,
					  NULL, /* udp/esp */
					  NULL /* transport_hdr*/);
	(void)dp_test_pktmbuf_eth_init(pak, dst_mac,
				       dp_test_intf_name2mac_str(ifname),
				       RTE_ETHER_TYPE_IPV4);
	exp = dp_test_exp_create(pak);
	dp_test_exp_set_oif_name(exp, ifname);

	/*
	 * Validate just the L2 header, IP header and the eight
	 * bytes of the ESP header (including the SPI).
	 */
	dp_test_exp_set_check_len(exp, (dp_pktmbuf_l2_len(pak) +
					sizeof(struct iphdr) + 8));
	rte_pktmbuf_free(pak);
	free(payload);

	return exp;
}

DP_DECL_TEST_CASE(crypto_multi_tunnel, multi_s2s_tunnel, setup, teardown);

/*
 * Tunnel 1 IPsec policies and SAs
 *
 *   1.1.1.0/2 -[2.2.2.2]========[2.2.2.3] -- 8.8.8.0/24
 */
static const struct dp_test_crypto_policy tun_1_in_policy = {
	.d_prefix = TUN_1_LOCAL_PREFIX,
	.s_prefix = TUN_1_REMOTE_PREFIX,
	.proto = 0,
	.dst = TUN_1_LOCAL_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUN_1_REQID,
	.priority = 1000,
	.rule_no = 1,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_policy tun_1_out_policy = {
	.d_prefix = TUN_1_REMOTE_PREFIX,
	.s_prefix = TUN_1_LOCAL_PREFIX,
	.proto = 0,
	.dst = TUN_1_REMOTE_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUN_1_REQID,
	.priority = 1000,
	.rule_no = 2,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_1_in_sa = {
	.spi = TUN_1_IN_SA_SPI,
	.d_addr = TUN_1_LOCAL_IP_ADDR,
	.s_addr = TUN_1_REMOTE_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_1_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_1_out_sa = {
	.spi = TUN_1_OUT_SA_SPI,
	.d_addr = TUN_1_REMOTE_IP_ADDR,
	.s_addr = TUN_1_LOCAL_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_1_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

/*
 * Tunnel 2 IPsec policies and SAs
 *
 *   1.1.1.0/2 -[3.3.3.2]========[3.3.3.4] -- 9.9.9.0/24
 *
 */
static const struct dp_test_crypto_policy tun_2_in_policy = {
	.d_prefix = TUN_2_LOCAL_PREFIX,
	.s_prefix = TUN_2_REMOTE_PREFIX,
	.proto = 0,
	.dst = TUN_2_LOCAL_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUN_2_REQID,
	.priority = 1000,
	.rule_no = 3,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_policy tun_2_out_policy = {
	.d_prefix = TUN_2_REMOTE_PREFIX,
	.s_prefix = TUN_2_LOCAL_PREFIX,
	.proto = 0,
	.dst = TUN_2_REMOTE_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUN_2_REQID,
	.priority = 1000,
	.rule_no = 4,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_2_in_sa = {
	.spi = TUN_2_IN_SA_SPI,
	.d_addr = TUN_2_LOCAL_IP_ADDR,
	.s_addr = TUN_2_REMOTE_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_2_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_2_out_sa = {
	.spi = TUN_2_OUT_SA_SPI,
	.d_addr = TUN_2_REMOTE_IP_ADDR,
	.s_addr = TUN_2_LOCAL_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_2_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

/*
 * setup_two_tunnels_two_peers()
 *
 * Set up policies and SAs specific to the test case.
 */
static void setup_two_tunnels_two_peers(void)
{
	/*
	 * Setup the input and output policies for Tunnel1:
	 *
	 * Traffic from 1.1.1.0/24 to 8.8.8.0/24 is sent over
	 * tunnel1 from 2.2.2.2 (UUT) to 2.2.2.3 (PEER1) on dp2T2.
	 */
	dp_test_crypto_create_policy(&tun_1_in_policy);
	dp_test_crypto_create_policy(&tun_1_out_policy);

	dp_test_crypto_create_sa(&tun_1_in_sa);
	dp_test_crypto_create_sa(&tun_1_out_sa);

	/*
	 * Setup the input and output policies for Tunnel2:
	 *
	 * Traffic from 1.1.1.0/24 to 9.9.9.0/24 is sent over
	 * tunnel2 from 3.3.3.2 (UUT) to 3.3.3.3 (PEER2) on dp3T3.
	 */
	dp_test_crypto_create_policy(&tun_2_in_policy);
	dp_test_crypto_create_policy(&tun_2_out_policy);

	dp_test_crypto_create_sa(&tun_2_in_sa);
	dp_test_crypto_create_sa(&tun_2_out_sa);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 4);
}

/*
 * teardow_two_tunnels_two_peers()
 *
 * Set up policies and SAs specific to the test case.
 */
static void teardown_two_tunnels_two_peers(void)
{
	/* Tear down Tunnel 1 */
	dp_test_crypto_delete_policy(&tun_1_in_policy);
	dp_test_crypto_delete_policy(&tun_1_out_policy);

	dp_test_crypto_delete_sa(&tun_1_in_sa);
	dp_test_crypto_delete_sa(&tun_1_out_sa);

	/* Tear down Tunnel 2 */
	dp_test_crypto_delete_policy(&tun_2_in_policy);
	dp_test_crypto_delete_policy(&tun_2_out_policy);

	dp_test_crypto_delete_sa(&tun_2_in_sa);
	dp_test_crypto_delete_sa(&tun_2_out_sa);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);
	dp_test_npf_cleanup();
}

/*
 * TESTCASE: two_tunnels_two_peers
 *
 * This test creates tunnels to two different IPsec peers on different
 * interfaces, with one policy and one SA per peer. It then receives
 * two ICMP packets, one that matches the input policy for each tunnel,
 * and checks that each packet is encapsulated using the correct SA and
 * sent towards the correct peer.
 *
 * NOTE this test only checks that the correct policy is matched and SA
 * is used based on the IP and ESP headers of the encrypted packet. It
 * does NOT check that the packet is correctly encrypted.
 */
DP_START_TEST_FULL_RUN(multi_s2s_tunnel, two_tunnels_two_peers)
{
	struct dp_test_expected *exp1, *exp2;
	struct rte_mbuf *pkt_tun1, *pkt_tun2;
	const uint8_t payload[32] = {0};
	int payload_len = sizeof(payload);
	struct icmphdr *icmp;
	struct iphdr *ip;

	setup_two_tunnels_two_peers();

	/* Create a packet that should go over Tunnel 1. */
	pkt_tun1 = dp_test_create_icmp_ipv4_pak(SOURCE_IP_ADDR,
						TUN_1_SINK_IP_ADDR,
						ICMP_ECHO,
						0 /* no code */,
						DPT_ICMP_ECHO_DATA(0, 0),
						1 /* one mbuf please */,
						&payload_len, payload,
						&ip, &icmp);
	(void)dp_test_pktmbuf_eth_init(pkt_tun1,
				       dp_test_intf_name2mac_str("dp1T1"),
				       SOURCE_MAC_ADDR,
				       RTE_ETHER_TYPE_IPV4);

	/* Expect an ESP packet to TUN_1_REMOTE_IP_ADDR on dp2T2 */
	exp1 = create_expected_packet(TUN_1_LOCAL_IP_ADDR,
				      TUN_1_REMOTE_IP_ADDR,
				      TUN_1_REMOTE_MAC_ADDR,
				      TUN_1_OUT_SA_SPI,
				      92, "dp2T2");

	/*
	 * Receive the packet from 1.1.1.1 to 8.8.8.8. This should
	 * be encrypted and sent out of dp2T2.
	 */
	dp_test_pak_receive(pkt_tun1, "dp1T1", exp1);

	/* Create a packet that should go over Tunnel 2. */
	pkt_tun2 = dp_test_create_icmp_ipv4_pak(SOURCE_IP_ADDR,
						TUN_2_SINK_IP_ADDR,
						ICMP_ECHO,
						0 /* no code */,
						DPT_ICMP_ECHO_DATA(0, 0),
						1 /* one mbuf please */,
						&payload_len, payload,
						&ip, &icmp);
	(void)dp_test_pktmbuf_eth_init(pkt_tun2,
				       dp_test_intf_name2mac_str("dp1T1"),
				       SOURCE_MAC_ADDR,
				       RTE_ETHER_TYPE_IPV4);

	/* Expect an ESP packet to TUN_2_REMOTE_IP_ADDR on dp3T3 */
	exp2 = create_expected_packet(TUN_2_LOCAL_IP_ADDR,
				      TUN_2_REMOTE_IP_ADDR,
				      TUN_2_REMOTE_MAC_ADDR,
				      TUN_2_OUT_SA_SPI,
				      92, "dp3T3");

	dp_test_pak_receive(pkt_tun2, "dp1T1", exp2);

	teardown_two_tunnels_two_peers();

} DP_END_TEST;

/*
 * Tunnel 3 IPsec policies and SAs
 *
 *   1.1.1.0/2 -[2.2.2.2]========[2.2.2.3] -- 10.10.10.0/24
 *
 */
static const struct dp_test_crypto_policy tun_3_in_policy = {
	.d_prefix = TUN_3_LOCAL_PREFIX,
	.s_prefix = TUN_3_REMOTE_PREFIX,
	.proto = 0,
	.dst = TUN_3_LOCAL_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUN_3_REQID,
	.priority = 1000,
	.rule_no = 5,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_policy tun_3_out_policy = {
	.d_prefix = TUN_3_REMOTE_PREFIX,
	.s_prefix = TUN_3_LOCAL_PREFIX,
	.proto = 0,
	.dst = TUN_3_REMOTE_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUN_3_REQID,
	.priority = 1000,
	.rule_no = 6,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_3_in_sa = {
	.spi = TUN_3_IN_SA_SPI,
	.d_addr = TUN_3_LOCAL_IP_ADDR,
	.s_addr = TUN_3_REMOTE_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_3_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_3_out_sa = {
	.spi = TUN_3_OUT_SA_SPI,
	.d_addr = TUN_3_REMOTE_IP_ADDR,
	.s_addr = TUN_3_LOCAL_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_3_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

/*
 * setup_two_tunnels_one_peer()
 *
 * Set up policies and SAs specific to the test case.
 */
static void setup_two_tunnels_one_peer(void)
{
	/*
	 * Setup the input and output policies for Tunnel1:
	 *
	 * Traffic from 1.1.1.0/24 to 8.8.8.0/24 is sent over
	 * tunnel1 from 2.2.2.2 (UUT) to 2.2.2.3 (PEER1) on dp2T2.
	 */
	dp_test_crypto_create_policy(&tun_1_in_policy);
	dp_test_crypto_create_policy(&tun_1_out_policy);

	dp_test_crypto_create_sa(&tun_1_in_sa);
	dp_test_crypto_create_sa(&tun_1_out_sa);

	/*
	 * Setup the input and output policies for Tunnel3:
	 *
	 * Traffic from 1.1.1.0/24 to 10.10.10.0/24 is sent over
	 * tunnel3 from 2.2.2.2 (UUT) to 2.2.2.3 (PEER1) on dp2T2.
	 */
	dp_test_crypto_create_policy(&tun_3_in_policy);
	dp_test_crypto_create_policy(&tun_3_out_policy);

	dp_test_crypto_create_sa(&tun_3_in_sa);
	dp_test_crypto_create_sa(&tun_3_out_sa);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 4);
}

/*
 * teardown_two_tunnels_one_peer()
 *
 * Set up policies and SAs specific to the test case.
 */
static void teardown_two_tunnels_one_peer(void)
{
	/* Tear down Tunnel 1 */
	dp_test_crypto_delete_policy(&tun_1_in_policy);
	dp_test_crypto_delete_policy(&tun_1_out_policy);

	dp_test_crypto_delete_sa(&tun_1_in_sa);
	dp_test_crypto_delete_sa(&tun_1_out_sa);

	/* Tear down Tunnel 3 */
	dp_test_crypto_delete_policy(&tun_3_in_policy);
	dp_test_crypto_delete_policy(&tun_3_out_policy);

	dp_test_crypto_delete_sa(&tun_3_in_sa);
	dp_test_crypto_delete_sa(&tun_3_out_sa);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);
	dp_test_npf_cleanup();
}

/*
 * TESTCASE: two_tunnels_one_peer
 *
 * This test creates two tunnels to the same IPsec peer, with different
 * remote selectors, but the same local selector. It then receives
 * two ICMP packets, one that matches the input policy for each tunnel,
 * and checks that each packet is encapsulated using the correct SA and
 * sent towards the correct peer.
 *
 * NOTE this test only checks that the correct policy is matched and SA
 * is used based on the IP and ESP headers of the encrypted packet. It
 * does NOT check that the packet is correctly encrypted.
 */
DP_START_TEST_FULL_RUN(multi_s2s_tunnel, two_tunnels_one_peer)
{
	struct rte_mbuf *pkt_tun1, *pkt_tun3;
	struct dp_test_expected *exp1, *exp3;
	const uint8_t payload[32] = {0};
	int payload_len = sizeof(payload);
	struct icmphdr *icmp;
	struct iphdr *ip;

	setup_two_tunnels_one_peer();

	/* Create a packet that should go over Tunnel 1. */
	pkt_tun1 = dp_test_create_icmp_ipv4_pak(SOURCE_IP_ADDR,
						TUN_1_SINK_IP_ADDR,
						ICMP_ECHO,
						0 /* no code */,
						DPT_ICMP_ECHO_DATA(0, 0),
						1 /* one mbuf please */,
						&payload_len, payload,
						&ip, &icmp);
	(void)dp_test_pktmbuf_eth_init(pkt_tun1,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/* Expect an ESP packet to TUN_1_REMOTE_IP_ADD on dp2T2 */
	exp1 = create_expected_packet(TUN_1_LOCAL_IP_ADDR,
				      TUN_1_REMOTE_IP_ADDR,
				      TUN_1_REMOTE_MAC_ADDR,
				      TUN_1_OUT_SA_SPI,
				      92, "dp2T2");

	/*
	 * Receive the packet from 1.1.1.1 to 8.8.8.8. This should
	 * be encrypted and sent out of dp2T2.
	 */
	dp_test_pak_receive(pkt_tun1, "dp1T1", exp1);

	/* Create a packet that should go over Tunnel 3. */
	pkt_tun3 = dp_test_create_icmp_ipv4_pak(SOURCE_IP_ADDR,
						TUN_3_SINK_IP_ADDR,
						ICMP_ECHO,
						0 /* no code */,
						DPT_ICMP_ECHO_DATA(0, 0),
						1 /* one mbuf please */,
						&payload_len, payload,
						&ip, &icmp);
	(void)dp_test_pktmbuf_eth_init(pkt_tun3,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	exp3 = create_expected_packet(TUN_3_LOCAL_IP_ADDR,
				      TUN_3_REMOTE_IP_ADDR,
				      TUN_3_REMOTE_MAC_ADDR,
				      TUN_3_OUT_SA_SPI,
				      92, "dp2T2");

	/*
	 * Receive the packet from 1.1.1.1 to 10.10.10.10. This should
	 * be encrypted and sent out of dp2T2.
	 */
	dp_test_pak_receive(pkt_tun3, "dp1T1", exp3);

	teardown_two_tunnels_one_peer();

} DP_END_TEST;

/*
 * Additional OUT SA for Tunnel 3
 */
static const struct dp_test_crypto_sa tun_3_extra_out_sa = {
	.spi = TUN_3_EXTRA_OUT_SA_SPI,
	.d_addr = TUN_3_REMOTE_IP_ADDR,
	.s_addr = TUN_3_LOCAL_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_3_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

/*
 * setup_two_tunnels_one_peer()
 *`<
 * Set up policies and SAs specific to the test case.
 */
static void setup_more_than_one_sa_for_tunnel(void)
{
	/*
	 * Setup the input and output policies for Tunnel3:
	 *
	 * Traffic from 1.1.1.0/24 to 10.10.10.0/24 is sent over
	 * tunnel3 from 2.2.2.2 (UUT) to 2.2.2.3 (PEER1) on dp2T2.
	 */
	dp_test_crypto_create_policy(&tun_3_in_policy);
	dp_test_crypto_create_policy(&tun_3_out_policy);

	dp_test_crypto_create_sa(&tun_3_in_sa);
	dp_test_crypto_create_sa(&tun_3_out_sa);
	dp_test_crypto_create_sa(&tun_3_extra_out_sa);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 3);
}

/*
 * teardown_two_tunnels_one_peer()
 *
 * Set up policies and SAs specific to the test case.
 */
static void teardown_more_than_one_sa_for_tunnel(void)
{
	/* Tear down Tunnel 3 */
	dp_test_crypto_delete_policy(&tun_3_in_policy);
	dp_test_crypto_delete_policy(&tun_3_out_policy);

	dp_test_crypto_delete_sa(&tun_3_in_sa);
	dp_test_crypto_delete_sa(&tun_3_out_sa);
	dp_test_crypto_delete_sa(&tun_3_extra_out_sa);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);
}

/*
 * TESTCASE: more_than_one_sa_for_tunnel
 *
 * This test creates a single tunnel to an IPsec peer, but with
 * two output SAs with different SPIs.  It then receives an ICMP
 * and checks that the packet is forwarded the more recent of
 * the two SAs.
 *
 * NOTE this test only checks that the correct policy is matched and SA
 * is used based on the IP and ESP headers of the encrypted packet. It
 * does NOT check that the packet is correctly encrypted.
 */
DP_START_TEST_FULL_RUN(multi_s2s_tunnel, more_than_one_sa_for_tunnel)
{
	struct dp_test_expected *exp3;
	struct rte_mbuf *pkt_tun3;
	const uint8_t payload[32] = {0};
	int payload_len = sizeof(payload);
	struct icmphdr *icmp;
	struct iphdr *ip;

	setup_more_than_one_sa_for_tunnel();

	/* Create a packet that should go over Tunnel 3. */
	pkt_tun3 = dp_test_create_icmp_ipv4_pak(SOURCE_IP_ADDR,
						TUN_3_SINK_IP_ADDR,
						ICMP_ECHO,
						0 /* no code */,
						DPT_ICMP_ECHO_DATA(0, 0),
						1 /* one mbuf please */,
						&payload_len, payload,
						&ip, &icmp);
	(void)dp_test_pktmbuf_eth_init(pkt_tun3,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Expect an ESP packet to TUN_3_REMOTE_IP_ADD on dp2T2.
	 * Note that we expect the SPI the packet's ESP header to
	 * be TUN_3_EXTRA_OUT_SA_SPI rather than TUN_3_OUT_SA_SPI
	 */
	exp3 = create_expected_packet(TUN_3_LOCAL_IP_ADDR,
				      TUN_3_REMOTE_IP_ADDR,
				      TUN_3_REMOTE_MAC_ADDR,
				      TUN_3_EXTRA_OUT_SA_SPI,
				      92, "dp2T2");

	/*
	 * Receive the packet from 1.1.1.1 to 10.10.10.10. This should
	 * be encrypted and sent out of dp2T2.
	 */
	dp_test_pak_receive(pkt_tun3, "dp1T1", exp3);

	teardown_more_than_one_sa_for_tunnel();

} DP_END_TEST;
