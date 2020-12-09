/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane Zone Firewall tests for virtual tunnel interfaces
 */

#include <libmnl/libmnl.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "crypto/vti.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_crypto_utils.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_nat_lib.h"


DP_DECL_TEST_SUITE(npf_vti_suite);

#define SPI_OUTBOUND 0xd43d87c7
#define SPI_INBOUND 0x10203040
#define VTI_TUN_REQID 1234

#define NETWORK_WEST  "10.10.1.0"
#define CLIENT_LOCAL  "10.10.1.1"
#define NETWORK_LOCAL "10.10.1.0"
#define PORT_WEST     "10.10.1.2"
#define CLIENT_LOCAL_MAC_ADDR "aa:bb:cc:dd:1:1"

#define NETWORK_WEST6  "2001:1::"
#define CLIENT_LOCAL6  "2001:1::1"
#define PORT_WEST6     "2001:1::2"

#define NETWORK_EAST   "10.10.2.0"
#define PEER           "10.10.2.3"
#define PEER_MAC_ADDR  "aa:bb:cc:dd:2:3"
#define PORT_EAST      "10.10.2.2"
#define NETWORK_REMOTE "10.10.3.0"

#define NETWORK_EAST6   "2001:2::"
#define PEER6           "2001:2::3"
#define PORT_EAST6      "2001:2::2"
#define NETWORK_REMOTE6 "2001:3::"

#define OUTPUT_MARK 100
#define INPUT_MARK  100

#define CLIENT_REMOTE  "10.10.3.4"
#define CLIENT_REMOTE6  "2001:3::4"

#define TEST_VRF_ID 55

/*
 * Crypto policy definitions used by the tests in this module
 */
static struct dp_test_crypto_policy output_policy = {
	.d_prefix = "0.0.0.0/0",
	.s_prefix = "0.0.0.0/0",
	.proto = 0,
	.dst = PEER,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = VTI_TUN_REQID,
	.priority = 0,
	.mark = OUTPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy input_policy = {
	.d_prefix = "0.0.0.0/0",
	.s_prefix = "0.0.0.0/0",
	.proto = 0,
	.dst = PORT_EAST,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = VTI_TUN_REQID + 1,
	.priority = 0,
	.mark = INPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

/*
 * Crypto SA definitions used by the tests in this module
 */
static struct dp_test_crypto_sa output_sa = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_OUTBOUND,
	.d_addr = PEER,
	.s_addr = PORT_EAST,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = VTI_TUN_REQID,
	.mark = OUTPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa input_sa = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_INBOUND,
	.d_addr = PORT_EAST,
	.s_addr = PEER,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = VTI_TUN_REQID + 1,
	.mark = INPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

static void vti_setup_policies_and_sas(vrfid_t vrfid)
{
	input_policy.vrfid = vrfid;
	output_policy.vrfid = vrfid;
	dp_test_crypto_create_policy(&input_policy);
	dp_test_crypto_create_policy(&output_policy);

	input_sa.vrfid = vrfid;
	output_sa.vrfid = vrfid;
	dp_test_crypto_create_sa(&input_sa);
	dp_test_crypto_create_sa(&output_sa);
}

static void vti_teardown_sas_and_policy(void)
{
	dp_test_crypto_delete_policy(&input_policy);
	dp_test_crypto_delete_policy(&output_policy);

	dp_test_crypto_delete_sa(&input_sa);
	dp_test_crypto_delete_sa(&output_sa);
}

static void vti_setup_tunnel(vrfid_t vrf_id, uint16_t mark_out)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	if (vrf_id != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrf_id, 1);

	/* Input interface and connected route is in the requested VRF */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1",
						 "10.10.1.2/24", vrf_id);
	dp_test_netlink_add_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR);

	/* Output interface and connected route are in default VRF */
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "10.10.2.2/24");
	dp_test_netlink_add_neigh("dp2T2", PEER, PEER_MAC_ADDR);

	dp_test_intf_vti_create("vti0", PORT_EAST, PEER, mark_out, vrf_id);
	dp_test_netlink_add_ip_address_vrf("vti0", "5.5.5.5/24", vrf_id);
	snprintf(route_name, sizeof(route_name), "vrf:%d %s nh %s int:vti0",
		 vrf_id, "10.10.3.0/24", PEER);
	dp_test_netlink_add_route(route_name);

	dp_test_crypto_check_sa_count(vrf_id, 0);
}

static void vti_teardown_tunnel(vrfid_t vrf_id)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	snprintf(route_name, sizeof(route_name), "vrf:%d %s nh %s int:vti0",
		 vrf_id, "10.10.3.0/24", PEER);
	dp_test_netlink_del_route(route_name);

	dp_test_netlink_del_ip_address_vrf("vti0", "5.5.5.5/24", vrf_id);
	dp_test_intf_vti_delete("vti0", PORT_EAST, PEER, 10, vrf_id);
	dp_test_netlink_del_neigh("dp2T2", PEER, PEER_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "10.10.2.2/24");
	dp_test_netlink_del_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "10.10.1.2/24",
						 vrf_id);

	if (vrf_id != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrf_id, 0);
}

static void vti_count(struct ifnet *ifp, void *arg)
{
	int *count = (int *)arg;

	if (ifp->if_type == IFT_TUNNEL_VTI)
		(*count)++;
}

static int vti_count_of_vtis(void)
{
	int count = 0;

	dp_ifnet_walk(vti_count, &count);
	return count;
}

/*
 * build_input_icmp_packet()
 *
 * This helper function builds an input ICMP packet that
 * corresponds to the encrypted payload in the ESP packet
 * built by build_expected_esp_packet().
 */
static struct rte_mbuf *build_input_icmp_packet(void)
{
	struct iphdr *ip;
	struct rte_mbuf *packet;
	const uint8_t payload[] = {
		0x2c, 0x57, 0xba, 0x55, 0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04
	};
	int payload_len = sizeof(payload);

	packet  = dp_test_create_icmp_ipv4_pak(CLIENT_LOCAL, CLIENT_REMOTE,
					       ICMP_ECHO /* echo request */,
					       0 /* no code */,
					       DPT_ICMP_ECHO_DATA(0xac9, 1),
					       1 /* one mbuf */,
					       &payload_len,
					       payload,
					       &ip, NULL);
	if (!packet)
		return NULL;

	/*
	 * The resulting ICMP packet isn't exactly as
	 * we want, so tickle a few bits into shape
	 */
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_IP_ID, 0xea53);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	return packet;
}

/*
 * build_expected_esp_packet()
 *
 * This helper function creates an output ESP packet containing the
 * encrypted ICMP ping packet built by build_input_icmp_packet().
 */
static struct rte_mbuf *build_expected_esp_packet(int *payload_len)
{
	const char encrypted_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6, 0xb1, 0x0c,
		0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3, 0x7c, 0xe1, 0x9e, 0x7e,
		0x65, 0x4c, 0xfd, 0x34, 0xfd, 0x9d, 0x64, 0xab, 0x31, 0x2c,
		0x3a, 0x08, 0x4d, 0x75, 0xb5, 0x86, 0x27, 0x50, 0xaf, 0x0e,
		0x47, 0xc0, 0x0e, 0x55, 0x56, 0x13, 0x97, 0xe0, 0xef, 0xc2,
		0x68, 0xf2, 0xdf, 0xb2, 0xfc, 0xf7, 0xd7, 0x70, 0xc9, 0x35,
		0xf5, 0xb1, 0xa8, 0x12, 0x23, 0x6c, 0xa9, 0xe3, 0xd3, 0xe0,
		0x41, 0xef, 0x9f, 0xf0, 0xfe, 0x99, 0x89, 0x88, 0x7d, 0x2c,
		0xdf, 0xf1, 0x7a, 0x85, 0x28, 0xf4, 0x0c, 0x99, 0x36, 0xa5,
		0x34, 0x3e, 0xde, 0xf8, 0xa6, 0x84, 0x40, 0xf3, 0x6f, 0xc5,
		0x07, 0xee, 0xde, 0x55, 0xcf, 0x9d, 0xaf, 0xda, 0x9e, 0x7b,
		0x8c, 0x98, 0xf6, 0xf8, 0x59, 0x0f, 0xd7, 0xbd, 0xc9, 0x24,
		0x01, 0xcd, 0x42, 0x38
	};

	*payload_len = sizeof(encrypted_payload);

	return dp_test_create_esp_ipv4_pak(PORT_EAST, PEER, 1,
					   payload_len,
					   encrypted_payload,
					   SPI_OUTBOUND,
					   1 /* seq no */,
					   0 /* ip ID */,
					   255 /* ttl */,
					   NULL /* udp/esp */,
					   NULL /* transport_hdr*/);
}


/*
 * build_encrypted_input_packet()
 *
 * This helper function creates an input ESP packet containing
 * an encrypted ICMP ping packet from 10.10.3.4 to 10.10.1.1.
 */
static struct rte_mbuf *build_encrypted_input_packet(void)
{
	int payload_len;
	const char encrypted_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6, 0xb1, 0x0c,
		0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3, 0xe4, 0xac, 0x69, 0xfb,
		0x6e, 0xf2, 0x98, 0x2c, 0x4e, 0x19, 0xd6, 0x8f, 0xd1, 0x72,
		0xfb, 0x67, 0x3c, 0x14, 0xc8, 0x00, 0x34, 0x4a, 0x08, 0x3d,
		0xe6, 0x3d, 0xeb, 0x3b, 0xeb, 0x90, 0xd8, 0xe1, 0x28, 0xa5,
		0xd2, 0x1b, 0xa1, 0xb1, 0xcf, 0xf4, 0xf4, 0x3e, 0x1d, 0x6b,
		0xa2, 0x8d, 0xb2, 0x2c, 0x5e, 0x60, 0x7f, 0x81, 0x3b, 0x79,
		0xb5, 0x10, 0xe2, 0x78, 0x7c, 0xd7, 0x19, 0xcf, 0x14, 0x80,
		0xca, 0x31, 0xa8, 0x4d, 0xf8, 0xde, 0x31, 0x3d, 0x61, 0x4d,
		0x5d, 0xed, 0x02, 0x1a, 0x91, 0x5d, 0x7c, 0x36, 0x9d, 0xce,
		0x2f, 0x1c, 0x57, 0x75, 0x8b, 0xe2, 0xa1, 0xdc, 0xf9, 0x4a,
		0x33, 0x97, 0x2a, 0x71, 0x7b, 0x16, 0x88, 0x59, 0x3d, 0x09,
		0xc8, 0x89, 0xa8, 0x31
	};

	payload_len = sizeof(encrypted_payload);

	return dp_test_create_esp_ipv4_pak(PEER, PORT_EAST, 1,
					   &payload_len,
					   encrypted_payload,
					   SPI_INBOUND,
					   1 /* seq no */,
					   0 /* ip ID */,
					   63 /* ttl */,
					   NULL /* udp/esp */,
					   NULL /* transport_hdr*/);
}

/*
 * build_expected_icmp_packet()
 *
 * This helper function builds an output ICMP packet that
 * corresponds to the encrypted payload in the ESP packet
 * built by build_encrypted_input_packet().
 */
static struct rte_mbuf *build_expected_icmp_packet(int *payload_len)
{
	struct iphdr *ip;
	struct rte_mbuf *packet;
	const uint8_t payload[] = {
		0x2c, 0x57, 0xba, 0x55, 0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04
	};

	*payload_len = sizeof(payload);

	packet = dp_test_create_icmp_ipv4_pak(CLIENT_REMOTE, CLIENT_LOCAL,
					      ICMP_ECHO /* echo request */,
					      0 /* no code */,
					      DPT_ICMP_ECHO_DATA(0xac9, 1),
					      1 /* one mbuf */,
					      payload_len,
					      payload,
					      &ip, NULL);

	/*
	 * The resulting ICMP packet isn't exactly as
	 * we want, so tickle a few bits into shape
	 */
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_IP_ID, 0xea53);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 2);

	return packet;
}

/*
 * TEST: npf_vti_encrypt1
 *
 * This check tests that when an ICMP ping packet is received that
 * should be routed over a VTI tunnel the correct encrypted ESP
 * packet is transmitted.
 *
 * Baseline test.  No npf configuration.
 *
 *              Packet ---->
 *                                   vti0
 *                                   ========================== tunnel
 *                                   10.10.2.2        10.10.2.3
 *                      +---------+
 *                dp1T1 |         | dp2T2
 *  --------------------+         +---------------
 *            10.10.1.2 |         | 10.10.2.2
 *                      +---------+
 *
 */
DP_DECL_TEST_CASE(npf_vti_suite, npf_vti_encrypt1, NULL, NULL);
DP_START_TEST(npf_vti_encrypt1, test)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int encrypted_payload_len;

	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas(VRF_DEFAULT_ID);

	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	input_packet = build_input_icmp_packet();
	(void)dp_test_pktmbuf_eth_init(input_packet,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	output_packet = build_expected_esp_packet(&encrypted_payload_len);

	dp_test_set_pak_ip_field(iphdr(output_packet), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(output_packet,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(output_packet);
	rte_pktmbuf_free(output_packet);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(input_packet, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(VRF_DEFAULT_ID, 1, 84);

	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();

	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

/*
 * TEST: npf_vti_decrypt1
 *
 * Baseline test.  No npf configuration.
 *
 * This test checks that an encrypted packet received on a
 * VTI interface is correctly decrypted and and forwarded.
 *
 *                             <-----  Packet
 *
 *                                   vti0
 *                                   ========================== tunnel
 *                                   10.10.2.2        10.10.2.3
 *                      +---------+
 *                dp1T1 |         | dp2T2
 *   -------------------+         +---------------
 *            10.10.1.2 |         | 10.10.2.2
 *                      +---------+
 *
 */
DP_DECL_TEST_CASE(npf_vti_suite, npf_vti_decrypt1, NULL, NULL);
DP_START_TEST(npf_vti_decrypt1, test)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int decrypted_payload_len;

	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas(VRF_DEFAULT_ID);
	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	/*
	 * Create the input encrypted packet.
	 */
	input_packet = build_encrypted_input_packet();
	(void)dp_test_pktmbuf_eth_init(input_packet,
				       dp_test_intf_name2mac_str("dp2T2"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Ceate the expected decrypted ping packet
	 */
	output_packet = build_expected_icmp_packet(&decrypted_payload_len);
	(void)dp_test_pktmbuf_eth_init(output_packet,
				       CLIENT_LOCAL_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Create an expectation for the decypted ICMP ping packet on dp1T1.
	 */
	exp = dp_test_exp_create(output_packet);
	rte_pktmbuf_free(output_packet);

	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(input_packet, "dp2T2", exp);
	dp_test_crypto_check_sad_packets(VRF_DEFAULT_ID, 1, 84);

	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();
	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

/*
 * TEST: npf_vti_encrypt2
 *
 * Rx interface dp1T1 in zone EAST, tx interface vti0 in zone WEST, pass rule
 * for EAST to WEST traffic.
 *
 *      Zone "EAST"                   Zone "WEST"
 *
 *              Packet ---->
 *                                   vti0
 *                                   ========================== tunnel
 *                                   10.10.2.2        10.10.2.3
 *                      +---------+
 *                dp1T1 |         | dp2T2
 *  --------------------+         +---------------
 *            10.10.1.2 |         | 10.10.2.2
 *                      +---------+
 *
 */
DP_DECL_TEST_CASE(npf_vti_suite, npf_vti_encrypt2, NULL, NULL);
DP_START_TEST(npf_vti_encrypt2, test)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int encrypted_payload_len;

	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas(VRF_DEFAULT_ID);

	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	/*
	 * Add zones config
	 */
	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "EAST",
			.intf = { "dp1T1", NULL, NULL },
			.local = false,
		},
		.public = {
			.name = "WEST",
			.intf = { "vti0", NULL, NULL },
			.local = false,
		},
		.local = { 0 },
		.priv_to_pub = {
			.name		= "EAST_TO_WEST",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.pub_to_priv = {
			.name		= "WEST_TO_EAST",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, false);

	/*
	 * Create the input packet.
	 */
	input_packet = build_input_icmp_packet();
	(void)dp_test_pktmbuf_eth_init(input_packet,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	output_packet = build_expected_esp_packet(&encrypted_payload_len);

	dp_test_set_pak_ip_field(iphdr(output_packet), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(output_packet,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(output_packet);
	rte_pktmbuf_free(output_packet);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(input_packet, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(VRF_DEFAULT_ID, 1, 84);

	/*
	 * Remove zones config
	 */
	dpt_zone_cfg(&cfg, false, false);

	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();

	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

/*
 * TEST: npf_vti_decrypt2
 *
 * Tx interface dp1T1 in zone EAST, rx interface vti0 in zone WEST, pass rule
 * for WEST to EAST traffic.
 *
 *      Zone "EAST"                   Zone "WEST"
 *
 *                             <-----  Packet
 *
 *                                   vti0
 *                                   ========================== tunnel
 *                                   10.10.2.2        10.10.2.3
 *                      +---------+
 *                dp1T1 |         | dp2T2
 *   -------------------+         +---------------
 *            10.10.1.2 |         | 10.10.2.2
 *                      +---------+
 *
 */
DP_DECL_TEST_CASE(npf_vti_suite, npf_vti_decrypt2, NULL, NULL);
DP_START_TEST(npf_vti_decrypt2, test)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int decrypted_payload_len;

	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas(VRF_DEFAULT_ID);
	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	/*
	 * Add zones config
	 */
	/*
	 * Add zones config
	 */
	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "EAST",
			.intf = { "dp1T1", NULL, NULL },
			.local = false,
		},
		.public = {
			.name = "WEST",
			.intf = { "vti0", NULL, NULL },
			.local = false,
		},
		.local = { 0 },
		.priv_to_pub = {
			.name		= "EAST_TO_WEST",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.pub_to_priv = {
			.name		= "WEST_TO_EAST",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, false);

	/*
	 * Create the input encrypted packet.
	 */
	input_packet = build_encrypted_input_packet();
	(void)dp_test_pktmbuf_eth_init(input_packet,
				       dp_test_intf_name2mac_str("dp2T2"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Ceate the expected decrypted ping packet
	 */
	output_packet = build_expected_icmp_packet(&decrypted_payload_len);
	(void)dp_test_pktmbuf_eth_init(output_packet,
				       CLIENT_LOCAL_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Create an expectation for the decypted ICMP ping packet on dp1T1.
	 */
	exp = dp_test_exp_create(output_packet);
	rte_pktmbuf_free(output_packet);

	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(input_packet, "dp2T2", exp);
	dp_test_crypto_check_sad_packets(VRF_DEFAULT_ID, 1, 84);

	/*
	 * Remove zones config
	 */
	dpt_zone_cfg(&cfg, false, false);

	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();

	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;


/*
 * TEST: npf_vti_encrypt3
 *
 * Rx interface dp1T1 in zone EAST, tx interface vti0 not in a zone.
 *
 *      Zone "EAST"
 *
 *              Packet ---->
 *                                   vti0
 *                                   ========================== tunnel
 *                                   10.10.2.2        10.10.2.3
 *                      +---------+
 *                dp1T1 |         | dp2T2
 *  --------------------+         +---------------
 *            10.10.1.2 |         | 10.10.2.2
 *                      +---------+
 *
 */
DP_DECL_TEST_CASE(npf_vti_suite, npf_vti_encrypt3, NULL, NULL);
DP_START_TEST(npf_vti_encrypt3, test)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int encrypted_payload_len;

	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas(VRF_DEFAULT_ID);

	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	/*
	 * Add zones config
	 */
	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "EAST",
			.intf = { "dp1T1", NULL, NULL },
			.local = false,
		},
		.public = { NULL, { NULL, NULL, NULL }, false },
		.local = { 0 },
		.pub_to_priv = { 0 },
		.priv_to_pub = { 0 },
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, false);

	/*
	 * Create the input packet.
	 */
	input_packet = build_input_icmp_packet();
	(void)dp_test_pktmbuf_eth_init(input_packet,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	output_packet = build_expected_esp_packet(&encrypted_payload_len);

	dp_test_set_pak_ip_field(iphdr(output_packet), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(output_packet,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(output_packet);
	rte_pktmbuf_free(output_packet);

	dp_test_exp_set_oif_name(exp, "dp2T2");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(input_packet, "dp1T1", exp);

	/*
	 * Remove zones config
	 */
	dpt_zone_cfg(&cfg, false, false);

	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();

	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

/*
 * TEST: npf_vti_decrypt3
 *
 * Tx interface dp1T1 in zone EAST, rx interface vti0 not in a zone.
 *
 *      Zone "EAST"
 *
 *                             <-----  Packet
 *
 *                                   vti0
 *                                   ========================== tunnel
 *                                   10.10.2.2        10.10.2.3
 *                      +---------+
 *                dp1T1 |         | dp2T2
 *   -------------------+         +---------------
 *            10.10.1.2 |         | 10.10.2.2
 *                      +---------+
 *
 */
DP_DECL_TEST_CASE(npf_vti_suite, npf_vti_decrypt3, NULL, NULL);
DP_START_TEST(npf_vti_decrypt3, test)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int decrypted_payload_len;

	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas(VRF_DEFAULT_ID);
	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	/*
	 * Add zones config
	 */
	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "EAST",
			.intf = { "dp1T1", NULL, NULL },
			.local = false,
		},
		.public = { NULL, { NULL, NULL, NULL }, false },
		.local = { 0 },
		.pub_to_priv = { 0 },
		.priv_to_pub = { 0 },
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, false);

	/*
	 * Create the input encrypted packet.
	 */
	input_packet = build_encrypted_input_packet();
	(void)dp_test_pktmbuf_eth_init(input_packet,
				       dp_test_intf_name2mac_str("dp2T2"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Ceate the expected decrypted ping packet
	 */
	output_packet = build_expected_icmp_packet(&decrypted_payload_len);
	(void)dp_test_pktmbuf_eth_init(output_packet,
				       CLIENT_LOCAL_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Create an expectation for the decypted ICMP ping packet on dp1T1.
	 */
	exp = dp_test_exp_create(output_packet);
	rte_pktmbuf_free(output_packet);

	dp_test_exp_set_oif_name(exp, "dp1T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(input_packet, "dp2T2", exp);

	/*
	 * Remove zones config
	 */
	dpt_zone_cfg(&cfg, false, false);

	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();

	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

