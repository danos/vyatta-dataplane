/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * VTI tests.
 */

#include <errno.h>
#include <time.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "crypto/vti.h"
#include "vrf_internal.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_crypto_utils.h"
#include "dp_test_lib_exp.h"

DP_DECL_TEST_SUITE(vti_suite);

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

static struct dp_test_crypto_policy output_policy6 = {
	.d_prefix = "::/0",
	.s_prefix = "::/0",
	.proto = 0,
	.dst = PEER6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET6,
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
	.reqid = VTI_TUN_REQID,
	.priority = 0,
	.mark = INPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy input_policy6 = {
	.d_prefix = "::/0",
	.s_prefix = "::/0",
	.proto = 0,
	.dst = PORT_EAST6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET6,
	.reqid = VTI_TUN_REQID,
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

static struct dp_test_crypto_sa output_sa6 = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_OUTBOUND,
	.d_addr = PEER6,
	.s_addr = PORT_EAST6,
	.family = AF_INET6,
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
	.reqid = VTI_TUN_REQID,
	.mark = INPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa input_sa6 = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_INBOUND,
	.d_addr = PORT_EAST6,
	.s_addr = PEER6,
	.family = AF_INET6,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = VTI_TUN_REQID,
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

static void vti_setup_policies_and_sas6(vrfid_t vrfid)
{
	input_policy6.vrfid = vrfid;
	output_policy6.vrfid = vrfid;
	dp_test_crypto_create_policy(&input_policy6);
	dp_test_crypto_create_policy(&output_policy6);

	input_sa6.vrfid = vrfid;
	output_sa6.vrfid = vrfid;
	dp_test_crypto_create_sa(&input_sa6);
	dp_test_crypto_create_sa(&output_sa6);
}

static void vti_teardown_sas_and_policy(void)
{
	dp_test_crypto_delete_policy(&input_policy);
	dp_test_crypto_delete_policy(&output_policy);

	dp_test_crypto_delete_sa(&input_sa);
	dp_test_crypto_delete_sa(&output_sa);
}

static void vti_teardown_sas_and_policy6(void)
{
	dp_test_crypto_delete_policy(&input_policy6);
	dp_test_crypto_delete_policy(&output_policy6);

	dp_test_crypto_delete_sa(&input_sa6);
	dp_test_crypto_delete_sa(&output_sa6);
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

static void vti_setup_tunnel6(vrfid_t vrf_id, uint16_t mark_out)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	if (vrf_id != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrf_id, 1);

	/* Input interface and connected route is in the requested VRF */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1",
						 "2001:1::2/64", vrf_id);
	dp_test_netlink_add_neigh("dp1T1", CLIENT_LOCAL6,
				  CLIENT_LOCAL_MAC_ADDR);

	/* Output interface and connected route are in default VRF */
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2001:2::2/64");
	dp_test_netlink_add_neigh("dp2T2", PEER6, PEER_MAC_ADDR);

	dp_test_intf_vti_create("vti1", PORT_EAST6, PEER6, mark_out, vrf_id);
	dp_test_netlink_add_ip_address_vrf("vti1", "2001:5::5/64", vrf_id);
	snprintf(route_name, sizeof(route_name), "vrf:%d %s nh %s int:vti1",
		 vrf_id, "2001:3::/64", PEER6);
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

static void vti_teardown_tunnel6(vrfid_t vrf_id)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	dp_test_netlink_del_ip_address_vrf("vti1", "2001:5::5/64", vrf_id);
	snprintf(route_name, sizeof(route_name), "vrf:%d %s nh %s int:vti1",
		 vrf_id, "2001:3::/64", PEER6);
	dp_test_netlink_del_route(route_name);
	dp_test_intf_vti_delete("vti1", PORT_EAST6, PEER6, 10, vrf_id);
	dp_test_netlink_del_neigh("dp2T2", PEER6, PEER_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2001:2::2/64");
	dp_test_netlink_del_neigh("dp1T1", CLIENT_LOCAL6,
				  CLIENT_LOCAL_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2001:1::2/64",
						 vrf_id);

	if (vrf_id != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrf_id, 0);
}

DP_DECL_TEST_CASE(vti_suite, vti, NULL, NULL);

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
 * TEST: vti
 *
 * Check that we can create and destroy a VTI tunnel.
 */
DP_START_TEST(vti, vti)
{
	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	dp_test_fail_unless((vti_count_of_vtis() == 1),
			"Expected VTI to be created");
	vti_teardown_tunnel(VRF_DEFAULT_ID);
	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

DP_START_TEST(vti, vti6)
{
	vti_setup_tunnel6(VRF_DEFAULT_ID, OUTPUT_MARK);
	dp_test_fail_unless((vti_count_of_vtis() == 1),
			"Expected VTI to be created");
	vti_teardown_tunnel6(VRF_DEFAULT_ID);
	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;


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
 * build_expected_esp_icmp_unreach_packet()
 *
 * This helper function creates an output ESP packet containing an
 * encrypted ICMP unreachable packet.
 */
static struct rte_mbuf *build_expected_esp_icmp_unreach_packet(int *payload_len)
{
	const char encrypted_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6, 0xb1, 0x0c,
		0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3, 0xae, 0x78, 0x67, 0x31,
		0x71, 0x81, 0x55, 0x53, 0xf1, 0x93, 0x8b, 0x2d, 0xf8, 0x7e,
		0x01, 0x7a, 0xc4, 0x1b, 0xd9, 0xa8, 0xd8, 0x6d, 0xd4, 0xc2,
		0xe1, 0xcb, 0x39, 0x0f, 0xc5, 0x2d, 0x8a, 0xf6, 0x3b, 0x81,
		0xad, 0x59, 0xc7, 0x48, 0xfc, 0x43, 0xeb, 0xa3, 0x83, 0x79,
		0x0b, 0x06, 0xd5, 0x12, 0x6e, 0xb0, 0xee, 0x9a, 0x50, 0x1b,
		0x6f, 0x00, 0xeb, 0x90, 0xb1, 0xd0, 0xbc, 0xd0, 0x18, 0x7a,
		0x9d, 0xd0, 0xb3, 0x9c, 0x1b, 0xaa, 0xd1, 0xde, 0x88, 0x18,
		0x7f, 0xe6, 0xc3, 0x36, 0xd3, 0x81, 0x7f, 0x33, 0xc6, 0x36,
		0x87, 0xa6, 0x93, 0x03, 0xb5, 0xef, 0x9f, 0x6a, 0xbe, 0x08,
		0x1f, 0x6e, 0x21, 0x57, 0x93, 0x07, 0xe2, 0x3e, 0x98, 0x2f,
		0x25, 0x66, 0x0d, 0x8f, 0xf6, 0x2d, 0x80, 0x6c, 0xb4, 0x29,
		0xea, 0xae, 0x74, 0xf3, 0x2d, 0x7b, 0x9e, 0x20, 0x67, 0xd3,
		0x99, 0x94, 0x0e, 0x10, 0x15, 0x18, 0x7c, 0xf5, 0x67, 0x98,
		0xfb, 0x24, 0x30, 0x1f, 0x40, 0xf0
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
 * TEST: encrypt_a_packet
 *
 * This check tests that when an ICMP ping packet is received that
 * should be routed over a VTI tunnel the correct encrypted ESP
 * packet is transmitted.
 */
DP_START_TEST(vti, encrypt_a_packet)
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
 * Check we generate an ICMP6 "Too Big" on an outsize
 * packet
 */
DP_DECL_TEST_CASE(vti_suite, vti_toobig, NULL, NULL);

DP_START_TEST(vti_toobig, vti_toobig)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *icmp_pak;
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *ip6, *in6_inner;
	int len = 1572;
	int icmplen;

	vti_setup_tunnel6(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas6(VRF_DEFAULT_ID);

	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	/*
	 * Construct oversize packet
	 */
	test_pak = dp_test_create_ipv6_pak(CLIENT_LOCAL6, CLIENT_REMOTE6,
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T1"),
				 CLIENT_LOCAL_MAC_ADDR, RTE_ETHER_TYPE_IPV6);

	/*
	 * Expected ICMP response
	 * Note that VTI sets MTU based on policy effective block size
	 */
	icmplen = 1280 - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
	icmp_pak = dp_test_create_icmp_ipv6_pak(PORT_WEST6, CLIENT_LOCAL6,
						ICMP6_PACKET_TOO_BIG,
						0, /* code */
						1426 /* mtu */,
						1, &icmplen,
						ip6hdr(test_pak),
						&ip6, &icmp6);

	/*
	 * Tweak the expected packet
	 * Account for hop limit having been decremented
	 */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       CLIENT_LOCAL_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV6);

	in6_inner = (struct ip6_hdr *)(icmp6 + 1);
	in6_inner->ip6_hlim--;

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(icmp_pak, ip6, icmp6);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	vti_teardown_tunnel6(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy6();

	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

/*
 * TEST: encrypt_a_packet_vrf
 *
 * This check tests that when an ICMP ping packet is received
 * in the overlay TEST_VRF that should be routed over a VTI tunnel
 * the correct encrypted ESP packet is transmitted in the default
 * (transport) VRF.
 */
DP_START_TEST(vti, encrypt_a_packet_vrf)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int encrypted_payload_len;

	vti_setup_tunnel(TEST_VRF_ID, OUTPUT_MARK);
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

	vti_teardown_tunnel(TEST_VRF_ID);
	vti_teardown_sas_and_policy();

	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

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
 * TEST: return_enc_icmp
 *
 * This test checks that an ICMP error generated as a result of processing
 * a packet received on a VTI interface will be returned.
 */
DP_START_TEST(vti, return_enc_icmp)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int encrypted_payload_len = 0;
	struct iphdr *ip;

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
	 * Expect an ICMP Unreachable
	 */
	output_packet = build_expected_esp_icmp_unreach_packet(
		&encrypted_payload_len);
	ip = dp_pktmbuf_mtol3(output_packet, struct iphdr *);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS, 0xc0);
	(void)dp_test_pktmbuf_eth_init(output_packet,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(output_packet);
	dp_test_exp_set_oif_name(exp, "dp2T2");
	rte_pktmbuf_free(output_packet);

	/* Set low MTU on outif to provoke unreachable */
	dp_test_netlink_set_interface_mtu("dp1T1", 64);

	dp_test_pak_receive(input_packet, "dp2T2", exp);
	dp_test_crypto_check_sad_packets(VRF_DEFAULT_ID, 1, 84);

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);
	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();
	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

/*
 * TEST: decrypt_a_packet
 *
 * This test checks that an encrypted packet received on a
 * VTI interface is correctly decrypted and and forwarded.
 */
DP_START_TEST(vti, decrypt_a_packet)
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
 * TEST: decrypt_a_packet_vrf
 *
 * This test checks that an encrypted packet received
 * in the default (transport) VRF is correctly decrypted
 * and forwarded in the the overlay VRF.
 */
DP_START_TEST(vti, decrypt_a_packet_vrf)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int decrypted_payload_len;

	/*
	 * Create the VTI tunnel so it is in the TEST overlay VRF
	 * and uses default VRF as the transport VRF.
	 */
	vti_setup_tunnel(TEST_VRF_ID, OUTPUT_MARK);
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

	vti_teardown_tunnel(TEST_VRF_ID);
	vti_teardown_sas_and_policy();
	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;

/*
 * TEST: encrypt_a_packet_bind_dp2
 *
 * This check tests that when an ICMP ping packet is received that
 * should be routed over a VTI tunnel the correct encrypted ESP
 * packet is transmitted.
 */
DP_START_TEST(vti, encrypt_a_packet_bind_dp2)
{
	struct rte_mbuf *output_pak;
	struct rte_mbuf *input_pak;
	struct dp_test_expected *exp;
	int encrypted_payload_len;

	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas(VRF_DEFAULT_ID);

	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	input_pak = build_input_icmp_packet();
	(void)dp_test_pktmbuf_eth_init(input_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	output_pak = build_expected_esp_packet(&encrypted_payload_len);
	dp_test_set_pak_ip_field(iphdr(output_pak), DP_TEST_SET_DF, 1);
	(void)dp_test_pktmbuf_eth_init(output_pak,
						PEER_MAC_ADDR,
						dp_test_intf_name2mac_str
						("dp2T2"),
						RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(output_pak);
	rte_pktmbuf_free(output_pak);

	dp_test_exp_set_oif_name(exp, "dp2T2");
	dp_test_pak_receive(input_pak, "dp1T1", exp);

	dp_test_crypto_check_sad_packets(VRF_DEFAULT_ID, 1, 84);

	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();

	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");
} DP_END_TEST;
