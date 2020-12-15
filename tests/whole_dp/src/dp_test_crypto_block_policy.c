/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <stdbool.h>

#include <netinet/in.h>
#include <linux/xfrm.h>
#include <arpa/inet.h>
#include <netinet/udp.h>

#include "ip_funcs.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_crypto_utils.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_macros.h"


/*
 * The tests in this module check the operation of IPsec BLOCK policies
 *
 * Topology:
 *
 *           10.10.1.0/24        10.10.2.0/24        10.10.3.0/24
 *           (WEST net)          (TRANSIT net)        (EAST net)
 #
 * +----------+        +---------+          +--------+         +----------+
 * |          |.1    .2|         | .2    .3 |        | .3   .4 |          |
 * |  Source  +--------+  LOCAL  +==========+  PEER  +---------+  Dest'n  |
 * |          |        |         |          |        |         |          |
 * +----------+        +---------+          +--------+         +----------+
 *
 * The tests check how the dataplane in the vRouter LOCAL in the diagram
 * would handle traffic sent from the host Source to Destination.
 */

#define WEST_PREFIX          "10.10.1.0/24"

#define SOURCE_ADDRESS       "10.10.1.1"
#define SOURCE_MAC_ADDRESS   "aa:bb:cc:dd:1:1"

#define LOCAL_ADDRESS_WEST   "10.10.1.2"
#define LOCAL_PREFIX_WEST    LOCAL_ADDRESS_WEST "/24"
#define LOCAL_PREFIX_TRANSIT "10.10.2.2/24"

#define LOCAL_ADDRESS_TRANSIT "10.10.2.2"
#define PEER_ADDRESS          "10.10.2.3"
#define PEER_MAC_ADDRESS      "aa:bb:cc:dd:2:3"

#define EAST_PREFIX           "10.10.3.0/24"
#define DESTINATION_ADDRESS   "10.10.3.4"

#define SPI_OUTBOUND 0xd43d87c7
#define TUNNEL_REQID 1234

DP_DECL_TEST_SUITE(crypto_block_policy);

/*
 * Crypto policy definitions used by the tests in this module
 */
struct dp_test_crypto_policy output_policy;

/*
 * Crypto SA definition used by the tests in this module
 */
static struct xfrm_encap_tmpl encap_tmpl = {
	.encap_type = UDP_ENCAP_ESPINUDP,
};

static const struct dp_test_crypto_sa output_sa = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_OUTBOUND,
	.d_addr = PEER_ADDRESS,
	.s_addr = LOCAL_ADDRESS_TRANSIT,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.encap_tmpl = &encap_tmpl,
	.vrfid = VRF_DEFAULT_ID
};

static struct udphdr udp;
/*
 * generate_source_packet()
 *
 * This generates the source ICMP packet that the local dataplane will
 * be expected to either encrypt or drop depending on the policy.
 */
static struct rte_mbuf *generate_source_packet(int *plen)
{
	static const uint8_t payload[] = {
		0x2c, 0x57, 0xba, 0x55, 0x00, 0x00, 0x00, 0x00,
		0xd9, 0xe9, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04};
	int payload_len = sizeof(payload);
	struct rte_mbuf *pkt;
	struct iphdr *ip;

	if (plen != NULL)
		*plen = payload_len;

	pkt = dp_test_create_icmp_ipv4_pak(SOURCE_ADDRESS,
					   DESTINATION_ADDRESS,
					   ICMP_ECHO,
					   0, /* no code */
					   DPT_ICMP_ECHO_DATA(0xac9, 1),
					   1, /* one mbuf please */
					   &payload_len, payload,
					   &ip, NULL);
	if (!pkt)
		return NULL;

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_IP_ID, 0xea53);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);
	return pkt;
}

/*
 * generate_expectation()
 *
 * This generates an test infra expectation either for the
 * encrypted packet that we should forward, or one indicating
 * that we expect to drop the packet
 */
static struct dp_test_expected *
generate_expectation(bool forward, struct udphdr *udphdr)
{
	struct dp_test_expected *expectation;
	static const char payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6,
		0xb1, 0x0c, 0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3,
		0x44, 0x6c, 0xbe, 0x0e, 0x1f, 0xa5, 0x93, 0xca,
		0xcd, 0x67, 0x6d, 0x61, 0xa6, 0x5d, 0x12, 0xa2,
		0x51, 0xe5, 0xd7, 0x20, 0x9a, 0xd7, 0x88, 0xa8,
		0x68, 0x26, 0x8b, 0xfa, 0x4b, 0xac, 0x67, 0xab,
		0x63, 0xf6, 0x65, 0x07, 0x63, 0xa6, 0x52, 0xa3,
		0xf8, 0xa1, 0x91, 0x5a, 0x60, 0x87, 0x07, 0x8e,
		0x7e, 0xd0, 0x15, 0xab, 0x13, 0x92, 0x18, 0xbe,
		0x16, 0x9f, 0x08, 0xd6, 0xa8, 0xf1, 0x09, 0x33,
		0xc0, 0x54, 0x0b, 0x72, 0x80, 0xc6, 0x35, 0xfb,
		0x08, 0xab, 0x35, 0xa1, 0xe3, 0x7c, 0x29, 0xc2,
		0x9b, 0x88, 0xf1, 0xc0, 0xcf, 0x04, 0xd3, 0x43,
		0x83, 0x78, 0xb9, 0xeb, 0xaf, 0xda, 0xd4, 0x83,
		0x56, 0xc5, 0xe9, 0xd1, 0x03, 0x41, 0xec, 0xbc,
		0x99, 0xa5, 0x9d, 0xaf};
	int payload_len = sizeof(payload);
	struct rte_mbuf *pkt;

	if (forward) {
		pkt = dp_test_create_esp_ipv4_pak(LOCAL_ADDRESS_TRANSIT,
						  PEER_ADDRESS,
						  1, &payload_len,
						  payload, SPI_OUTBOUND,
						  1, /* seq no */
						  0, /* ip ID */
						  255  /* ttl */,
						  udphdr, /* udp/esp */
						  NULL /* transport_hdr*/);
		dp_test_set_pak_ip_field(iphdr(pkt), DP_TEST_SET_DF, 1);
		(void)dp_test_pktmbuf_eth_init(
			pkt, PEER_MAC_ADDRESS,
			dp_test_intf_name2mac_str("dp2T2"),
			RTE_ETHER_TYPE_IPV4);
		expectation = dp_test_exp_create(pkt);
		rte_pktmbuf_free(pkt);
		dp_test_exp_set_oif_name(expectation, "dp2T2");
	} else {
		expectation = dp_test_exp_create(NULL);
		dp_test_exp_set_fwd_status(expectation, DP_TEST_FWD_DROPPED);
	}

	return expectation;
}

/*
 * setup()
 *
 * Setup the interfaces, address and ARP neighbours which are common
 * to all test cases in this module. It also initialises the input
 * and output structures to known values, creates the SAs and
 * initialises the expected and source packets.
 */
static void setup(void)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T1", LOCAL_PREFIX_WEST);
	dp_test_netlink_add_neigh("dp1T1", SOURCE_ADDRESS, SOURCE_MAC_ADDRESS);

	dp_test_nl_add_ip_addr_and_connected("dp2T2", LOCAL_PREFIX_TRANSIT);
	dp_test_netlink_add_neigh("dp2T2", PEER_ADDRESS, PEER_MAC_ADDRESS);

	encap_tmpl.encap_sport = htons(4501);
	encap_tmpl.encap_dport = htons(4500);
	dp_test_crypto_create_sa(&output_sa);

	/* Checkup the udp recevier ports expected */
	udp.source = encap_tmpl.encap_sport;
	udp.dest = encap_tmpl.encap_dport;

	/*
	 * Initialise the common parts of the policy description, but do not
	 * create it yet. This allows the test case to change it.
	 */
	output_policy.d_prefix = EAST_PREFIX;
	output_policy.s_prefix = WEST_PREFIX;
	output_policy.proto = 0;
	output_policy.dst = PEER_ADDRESS;
	output_policy.dst_family = AF_INET;
	output_policy.dir = XFRM_POLICY_OUT;
	output_policy.family = AF_INET;
	output_policy.reqid = TUNNEL_REQID;
	output_policy.priority = 200000;
	output_policy.mark = 0;
	output_policy.vrfid = VRF_DEFAULT_ID;
	output_policy.rule_no = 0;

	/*
	 * Add a route to the EAST network. This is to make sure
	 * that if the DP does not encrypt the packet, it will be
	 * sent in the clear on dp2T2 and the test will fail.
	 */
	dp_test_netlink_add_route(EAST_PREFIX " nh " PEER_ADDRESS " int:dp2T2");
}

/*
 * teardown()
 *
 * Tear down the interfaces, address and ARP neighbours which are common
 * to all test cases in this module.
 */
static void teardown(void)
{
	dp_test_netlink_del_route(EAST_PREFIX " nh " PEER_ADDRESS " int:dp2T2");
	dp_test_netlink_del_neigh("dp2T2", PEER_ADDRESS, PEER_MAC_ADDRESS);
	dp_test_nl_del_ip_addr_and_connected("dp2T2", LOCAL_PREFIX_TRANSIT);
	dp_test_netlink_del_neigh("dp1T1", SOURCE_ADDRESS, SOURCE_MAC_ADDRESS);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", LOCAL_PREFIX_WEST);

	dp_test_crypto_delete_sa(&output_sa);
}

DP_DECL_TEST_CASE(crypto_block_policy, single_policy, setup, teardown);

/*
 * TEST CASE: single_allow_policy
 *
 *
 * This checks that a packet is correctly encrypted when it
 * matches a policy with an action of ALLOW
 */
DP_START_TEST(single_policy, single_allow_policy)
{
	struct dp_test_expected *expectation;
	struct rte_mbuf *input_pkt;

	output_policy.rule_no++;
	output_policy.action = XFRM_POLICY_ALLOW;
	dp_test_crypto_create_policy(&output_policy);

	input_pkt = generate_source_packet(NULL);
	/* Expect the packet to be encrypted and forwarded */
	expectation = generate_expectation(true, &udp);

	(void)dp_test_pktmbuf_eth_init(input_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	dp_test_pak_receive(input_pkt, "dp1T1", expectation);

	dp_test_crypto_delete_policy(&output_policy);

} DP_END_TEST;

/*
 * TEST CASE: single_block_policy
 *
 * This checks that a packet is correctly encrypted when it
 * matches a policy with an action of ALLOW
 */
DP_START_TEST_FULL_RUN(single_policy, single_block_policy)
{
	struct dp_test_expected *expectation;
	struct rte_mbuf *input_pkt;
	int payload_len;

	output_policy.rule_no++;
	output_policy.action = XFRM_POLICY_BLOCK;
	dp_test_crypto_create_policy(&output_policy);

	input_pkt = generate_source_packet(&payload_len);

	/* Expect the packet to be blocked and dropped with ICMP Unreachable */
	expectation = generate_exp_unreachable(input_pkt, payload_len,
					       LOCAL_ADDRESS_WEST,
					       SOURCE_ADDRESS,
					       "dp1T1", SOURCE_MAC_ADDRESS);

	(void)dp_test_pktmbuf_eth_init(input_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	dp_test_pak_receive(input_pkt, "dp1T1", expectation);

	dp_test_crypto_delete_policy(&output_policy);

} DP_END_TEST;

/*
 * TEST CASE: modify_allow_to_block
 *
 * This checks that a policy can be modified from ALLOW
 * to BLOCK and that traffic is no longer forwarded.
 */
DP_START_TEST_FULL_RUN(single_policy, modfy_allow_to_block)
{
	struct dp_test_expected *expectation;
	struct rte_mbuf *input_pkt;
	int payload_len;

	output_policy.rule_no++;
	output_policy.action = XFRM_POLICY_ALLOW;
	dp_test_crypto_create_policy(&output_policy);

	input_pkt = generate_source_packet(NULL);
	/* Expect the packet to be encrypted and forwarded */
	expectation = generate_expectation(true, &udp);

	(void)dp_test_pktmbuf_eth_init(input_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	dp_test_pak_receive(input_pkt, "dp1T1", expectation);

	/* Update the policy so that it's now a block policy*/
	output_policy.action = XFRM_POLICY_BLOCK;
	dp_test_crypto_update_policy(&output_policy);

	input_pkt = generate_source_packet(&payload_len);

	/* Expect the packet to be blocked and dropped with ICMP Unreachable */
	expectation = generate_exp_unreachable(input_pkt, payload_len,
					       LOCAL_ADDRESS_WEST,
					       SOURCE_ADDRESS,
					       "dp1T1", SOURCE_MAC_ADDRESS);

	(void)dp_test_pktmbuf_eth_init(input_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	dp_test_pak_receive(input_pkt, "dp1T1", expectation);

	dp_test_crypto_delete_policy(&output_policy);

} DP_END_TEST;

/*
 * TEST CASE: modify_block_to_allow
 *
 * This checks that a policy can be modified from BLOCK
 * to ALLOW and that traffic is then encrypted and forwarded.
 */
DP_START_TEST_FULL_RUN(single_policy, modfy_block_to_allow)
{
	struct dp_test_expected *expectation;
	struct rte_mbuf *input_pkt;
	int payload_len;

	output_policy.rule_no++;
	output_policy.action = XFRM_POLICY_BLOCK;
	dp_test_crypto_create_policy(&output_policy);

	input_pkt = generate_source_packet(&payload_len);

	/* Expect the packet to be blocked and dropped with ICMP Unreachable */
	expectation = generate_exp_unreachable(input_pkt, payload_len,
					       LOCAL_ADDRESS_WEST,
					       SOURCE_ADDRESS,
					       "dp1T1", SOURCE_MAC_ADDRESS);

	(void)dp_test_pktmbuf_eth_init(input_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	dp_test_pak_receive(input_pkt, "dp1T1", expectation);

	/* Update the policy so that it's now an allow policy */
	output_policy.action = XFRM_POLICY_ALLOW;
	dp_test_crypto_update_policy(&output_policy);

	input_pkt = generate_source_packet(NULL);
	/* Expect the packet to be encrypted and forwarded */
	expectation = generate_expectation(true, &udp);

	(void)dp_test_pktmbuf_eth_init(input_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	dp_test_pak_receive(input_pkt, "dp1T1", expectation);

	dp_test_crypto_delete_policy(&output_policy);

} DP_END_TEST;
