/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Site-to-Site crypto tests
 */

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_crypto_utils.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_crypto_lib.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_npf_lib.h"

#include "main.h"
#include "in_cksum.h"
#include "ip_funcs.h"
#include "ip6_funcs.h"

#include "crypto/crypto.h"
#include "crypto/crypto_forward.h"
#include "crypto/crypto_internal.h"

/*
 *                      +----------+          +---------+
 * +-----------+        |          |          |         |         +----------+
 * |           |        |          |          |         |         |          |
 * |Client     +--------+  UUT     +----------+  PEER   + - - - - + Client   |
 * |   local   |        |          |          |         |         |  remote  |
 * |           |        |          |          |         |         |          |
 * +-----------+        |          |          |         |         +----------+
 *                      +----------+          +---------+
 *
 *     WEST<<<<<<<<<<<<<<         >>>>>>>>>>>>>>EAST
 */

#define PREFIX_LOCAL  "10.10.1.224"
#define PREFIXLEN_LOCAL "/27"
#define NETWORK_LOCAL (PREFIX_LOCAL PREFIXLEN_LOCAL)

#define PREFIX_REMOTE  "10.10.1.192"
#define NETWORK_REMOTE PREFIX_REMOTE "/26"
#define CLIENT_REMOTE  "10.10.1.193"
#define CLIENT_REMOTE_B (0x0a, 0x0a, 0x01, 0xc1)

#define NETWORK_WEST  NETWORK_LOCAL
#define CLIENT_LOCAL  "10.10.1.226"
#define CLIENT_LOCAL_B (0x0a, 0x0a, 0x01, 0xe2)
#define PORT_WEST     "10.10.1.227"
#define IF_WEST        (PORT_WEST PREFIXLEN_LOCAL)

#define PREFIXLEN_EAST "/24"
#define NETWORK_EAST   "10.10.2.0/24"
#define PEER           "10.10.2.3"
#define PORT_EAST      "10.10.2.2"
#define IF_EAST        (PORT_EAST PREFIXLEN_EAST)

#define PREFIX_LOCAL6  "10:10:10:10:e000::"
#define PREFIXLEN_LOCAL6 "/67"
#define NETWORK_LOCAL6 (PREFIX_LOCAL6 PREFIXLEN_LOCAL6)

#define PREFIX_REMOTE6  "10:10:10:10:c000::"
#define NETWORK_REMOTE6 PREFIX_REMOTE6 "/66"
#define CLIENT_REMOTE6  "10:10:10:10:c000::A2"

#define NETWORK_WEST6  NETWORK_LOCAL6
#define CLIENT_LOCAL6  "10:10:10:10:e000::1"
#define PORT_WEST6     "10:10:10:10:e000::2"
#define IF_WEST6        (PORT_WEST6 PREFIXLEN_LOCAL6)

#define PREFIXLEN_EAST6 "/64"
#define NETWORK_EAST6   "11:10:10:10:e000::"
#define PEER6           "11:10:10:10:e000::1"
#define PORT_EAST6      "11:10:10:10:e000::2"
#define IF_EAST6        (PORT_EAST6 PREFIXLEN_EAST6)

#define CLIENT_LOCAL_MAC_ADDR "aa:bb:cc:dd:1:1"
#define PEER_MAC_ADDR  "aa:bb:cc:dd:2:3"

#define SPI_OUTBOUND 0xd43d87c7
#define SPI_OUTBOUND6 0x89752ac5
#define SPI_INBOUND 0x10
#define TUNNEL_REQID 1234
#define TEST_VRF 42

#define LINK_LOCAL  "169.254.0.1/32"
#define LINK_LOCAL6 "fe80::1/128"

/*
 * Crypto policy definitions used by the tests in this module
 */
static struct dp_test_crypto_policy output_policy = {
	.d_prefix = NETWORK_REMOTE,
	.s_prefix = NETWORK_LOCAL,
	.proto = 0,
	.dst = PEER,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUNNEL_REQID,
	.priority = 3000,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy output_passthru_policy = {
	.d_prefix = NETWORK_LOCAL,
	.s_prefix = NETWORK_LOCAL,
	.proto = 0,
	.dst = PEER,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUNNEL_REQID,
	.priority = 1000,
	.mark = 0,
	.action = XFRM_POLICY_ALLOW,
	.vrfid = VRF_DEFAULT_ID,
	.passthrough = TRUE
};

static struct dp_test_crypto_policy output_policy6 = {
	.d_prefix = NETWORK_REMOTE6,
	.s_prefix = NETWORK_LOCAL6,
	.proto = 0,
	.dst = PEER6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET6,
	.reqid = TUNNEL_REQID,
	.priority = 3000,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy output_passthru_policy6 = {
	.d_prefix = NETWORK_LOCAL6,
	.s_prefix = NETWORK_LOCAL6,
	.proto = 0,
	.dst = PEER6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET6,
	.reqid = TUNNEL_REQID,
	.priority = 1000,
	.mark = 0,
	.action = XFRM_POLICY_ALLOW,
	.vrfid = VRF_DEFAULT_ID,
	.passthrough = TRUE
};

static struct dp_test_crypto_policy input_policy = {
	.d_prefix = NETWORK_LOCAL,
	.s_prefix = NETWORK_REMOTE,
	.proto = 0,
	.dst = PORT_EAST,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUNNEL_REQID,
	.priority = 3000,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy input_passthru_policy = {
	.d_prefix = NETWORK_LOCAL,
	.s_prefix = NETWORK_LOCAL,
	.proto = 0,
	.dst = PORT_EAST,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUNNEL_REQID,
	.priority = 1000,
	.mark = 0,
	.action = XFRM_POLICY_ALLOW,
	.vrfid = VRF_DEFAULT_ID,
	.passthrough = TRUE
};

static struct dp_test_crypto_policy input_policy6 = {
	.d_prefix = NETWORK_LOCAL6,
	.s_prefix = NETWORK_REMOTE6,
	.proto = 0,
	.dst = PORT_EAST6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET6,
	.reqid = TUNNEL_REQID,
	.priority = 3000,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy input_passthru_policy6 = {
	.d_prefix = NETWORK_LOCAL6,
	.s_prefix = NETWORK_LOCAL6,
	.proto = 0,
	.dst = PORT_EAST6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET6,
	.reqid = TUNNEL_REQID,
	.priority = 1000,
	.mark = 0,
	.action = XFRM_POLICY_ALLOW,
	.vrfid = VRF_DEFAULT_ID,
	.passthrough = TRUE

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
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa output_sa6 = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_OUTBOUND6,
	.d_addr = PEER6,
	.s_addr = PORT_EAST6,
	.family = AF_INET6,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa input_sa = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_INBOUND,
	.d_addr = PORT_EAST,
	.s_addr = PEER,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa input_sa6 = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_INBOUND,
	.d_addr = PORT_EAST6,
	.s_addr = PEER6,
	.family = AF_INET6,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static void _s2s_setup_interfaces(vrfid_t vrfid,
				  const char *file, const char *func,
				  int line)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];
	bool verify = true;
	bool incomplete = false;

	if (vrfid != VRF_DEFAULT_ID)
		_dp_test_netlink_add_vrf(vrfid, 1, file, line);

	_dp_test_netlink_set_interface_vrf("dp1T1", vrfid, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected("dp1T1", IF_WEST,
					      vrfid, file, func, line);
	_dp_test_netlink_add_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR,
				   verify, file, func, line);
	/* At the moment dp2 is the transport vrf, and always in default */
	_dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected("dp2T2", IF_EAST,
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_add_neigh("dp2T2", PEER, PEER_MAC_ADDR, verify,
				   file, func, line);

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE, PEER, "dp2T2");

	_dp_test_netlink_add_route(route_name, verify, incomplete,
				   file, func, line);
}
#define s2s_setup_interfaces(vrfid)	\
	_s2s_setup_interfaces(vrfid,	\
			       __FILE__, __func__, __LINE__)

static void _s2s_setup_interfaces6(vrfid_t vrfid,
				   const char *file, const char *func, int line)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];
	bool verify = true;
	bool incomplete = false;

	if (vrfid != VRF_DEFAULT_ID)
		_dp_test_netlink_add_vrf(vrfid, 1, file, line);

	_dp_test_netlink_set_interface_vrf("dp1T1", vrfid, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected("dp1T1", IF_WEST6,
					      vrfid, file, func, line);
	_dp_test_netlink_add_neigh("dp1T1", CLIENT_LOCAL6,
				   CLIENT_LOCAL_MAC_ADDR, verify,
				   file, func, line);
	/* At the moment dp2 is the transport vrf, and always in default */
	_dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected("dp2T2", IF_EAST6,
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_add_neigh("dp2T2", PEER6, PEER_MAC_ADDR, verify,
				   file, func, line);

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE6, PEER6, "dp2T2");

	_dp_test_netlink_add_route(route_name, verify, incomplete,
				   file, func, line);
}
#define s2s_setup_interfaces6(vrfid) \
	_s2s_setup_interfaces6(vrfid, __FILE__, __func__, __LINE__)


static void _s2s_teardown_interfaces(vrfid_t vrfid,
				     bool leave_vrf,
				     const char *file, const char *func,
				     int line)
{
	bool verify = true;
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE, PEER, "dp2T2");
	_dp_test_netlink_del_route(route_name, verify,
				   file, func, line);
	_dp_test_netlink_del_neigh("dp2T2", PEER, PEER_MAC_ADDR, verify,
				   file, func, line);
	_dp_test_nl_del_ip_addr_and_connected("dp2T2", IF_EAST,
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_del_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR,
				   verify, file, func, line);
	_dp_test_nl_del_ip_addr_and_connected("dp1T1", IF_WEST,
					      vrfid, file, func, line);
	_dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID, verify,
					   file, func, line);
	_dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID, verify,
					   file, func, line);
	if (!leave_vrf && (vrfid != VRF_DEFAULT_ID))
		_dp_test_netlink_del_vrf(vrfid, 0, file, line);
}
#define s2s_teardown_interfaces(vrfid) \
	_s2s_teardown_interfaces(vrfid, false, \
				 __FILE__, __func__, __LINE__)

#define s2s_teardown_interfaces_leave_vrf(vrfid) \
	_s2s_teardown_interfaces(vrfid, true,	   \
				 __FILE__, __func__, __LINE__)

static void _s2s_teardown_interfaces6(vrfid_t vrfid,
				     const char *file, const char *func,
				     int line)
{
	bool verify = true;
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	_dp_test_netlink_del_neigh("dp2T2", PEER6, PEER_MAC_ADDR, verify,
				   file, func, line);
	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE6, PEER6, "dp2T2");
	_dp_test_netlink_del_route(route_name, verify, file, func, line);
	_dp_test_nl_del_ip_addr_and_connected("dp2T2", IF_EAST6,
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_del_neigh("dp1T1", CLIENT_LOCAL6,
				   CLIENT_LOCAL_MAC_ADDR, verify,
				   file, func, line);
	_dp_test_nl_del_ip_addr_and_connected("dp1T1", IF_WEST6,
					      vrfid, file, func, line);

	_dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID, verify,
					   file, func, line);
	_dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID, verify,
					   file, func, line);
	if (vrfid != VRF_DEFAULT_ID)
		_dp_test_netlink_del_vrf(vrfid, 0, file, line);
}
#define s2s_teardown_interfaces6(vrfid) \
	_s2s_teardown_interfaces6(vrfid, \
				  __FILE__, __func__, __LINE__)

static void s2s_common_setup(vrfid_t vrfid,
			     enum dp_test_crypo_cipher_algo cipher_algo,
			     enum dp_test_crypo_auth_algo auth_algo,
			     struct dp_test_crypto_policy *ipolicy,
			     struct dp_test_crypto_policy *opolicy,
				 uint8_t npols,
			     unsigned int mode)
{
	struct dp_test_crypto_policy *ipol, *opol;
	bool verify = true;
	int i;

	/* If no policies were supplied use defaults */
	ipol = ipolicy ? ipolicy : &input_policy;
	opol = opolicy ? opolicy : &output_policy;
	if (!ipolicy)
		npols = 1;

	/***************************************************
	 * Configure underlying topology
	 */
	s2s_setup_interfaces(vrfid);

	ipol->vrfid = vrfid;
	opol->vrfid = vrfid;

	for (i = 0; i < npols; i++) {
		dp_test_crypto_create_policy_verify(&ipol[i], verify);
		dp_test_crypto_create_policy_verify(&opol[i], verify);
	}

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);

	input_sa.auth_algo = auth_algo;
	input_sa.cipher_algo = cipher_algo;
	output_sa.auth_algo = auth_algo;
	output_sa.cipher_algo = cipher_algo;

	input_sa.mode = mode;
	output_sa.mode = mode;
	input_sa.vrfid = vrfid;
	output_sa.vrfid = vrfid;

	dp_test_crypto_create_sa_verify(&input_sa, verify);
	dp_test_crypto_create_sa_verify(&output_sa, verify);
}

static void s2s_common_setup6(vrfid_t vrfid,
			      enum dp_test_crypo_cipher_algo cipher_algo,
			      enum dp_test_crypo_auth_algo auth_algo,
			      struct dp_test_crypto_policy *ipolicy,
			      struct dp_test_crypto_policy *opolicy,
				  uint8_t npols,
			      unsigned int mode)
{
	struct dp_test_crypto_policy *ipol, *opol;
	int i;

	/* If no policies were supplied use defaults */
	ipol = ipolicy ? ipolicy : &input_policy6;
	opol = opolicy ? opolicy : &output_policy6;
	if (!ipolicy)
		npols = 1;

	/***************************************************
	 * Configure underlying topology
	 */
	s2s_setup_interfaces6(vrfid);

	ipol->vrfid = vrfid;
	opol->vrfid = vrfid;

	for (i = 0; i < npols; i++) {
		dp_test_crypto_create_policy(&ipol[i]);
		dp_test_crypto_create_policy(&opol[i]);
	}

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);

	input_sa6.auth_algo = auth_algo;
	input_sa6.cipher_algo = cipher_algo;
	output_sa6.auth_algo = auth_algo;
	output_sa6.cipher_algo = cipher_algo;
	input_sa6.mode = mode;
	output_sa6.mode = mode;
	input_sa6.vrfid = vrfid;
	output_sa6.vrfid = vrfid;

	dp_test_crypto_create_sa(&input_sa6);
	dp_test_crypto_create_sa(&output_sa6);
}

static void s2s_common_teardown(vrfid_t vrfid,
				struct dp_test_crypto_policy *ipolicy,
				struct dp_test_crypto_policy *opolicy,
				uint8_t npols)

{
	struct dp_test_crypto_policy *ipol, *opol;
	int i;

	dp_test_crypto_delete_sa(&input_sa);
	dp_test_crypto_delete_sa(&output_sa);

	/* If no policies were supplied use defaults */
	ipol = ipolicy ? ipolicy : &input_policy;
	opol = opolicy ? opolicy : &output_policy;
	if (!ipolicy)
		npols = 1;

	for (i = 0; i < npols; i++) {
		dp_test_crypto_delete_policy(&ipol[i]);
		dp_test_crypto_delete_policy(&opol[i]);
	}

	dp_test_npf_cleanup();

	/***************************************************
	 * Tear down topology
	 */
	s2s_teardown_interfaces(vrfid);
}

static void s2s_common_teardown6(vrfid_t vrfid,
				 struct dp_test_crypto_policy *ipolicy,
				 struct dp_test_crypto_policy *opolicy,
				 uint8_t npols)

{
	struct dp_test_crypto_policy *ipol, *opol;
	int i;

	dp_test_crypto_delete_sa(&input_sa6);
	dp_test_crypto_delete_sa(&output_sa6);

	/* If no policies were supplied use defaults */
	ipol = ipolicy ? ipolicy : &input_policy6;
	opol = opolicy ? opolicy : &output_policy6;
	if (!ipolicy)
		npols = 1;

	for (i = 0; i < npols; i++) {
		dp_test_crypto_delete_policy(&ipol[i]);
		dp_test_crypto_delete_policy(&opol[i]);
	}

	dp_test_npf_cleanup();

	/***************************************************
	 * Tear down topology
	 */
	s2s_teardown_interfaces6(vrfid);
}

static void encrypt_main(vrfid_t vrfid)
{
	const char expected_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6,
		0xb1, 0x0c, 0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3,
		0xd8, 0x23, 0x4c, 0x74, 0x94, 0x1e, 0x37, 0x1d,
		0x7b, 0x1f, 0x3c, 0x40, 0x76, 0x2b, 0x9d, 0x6c,
		0x6c, 0xbc, 0x55, 0x21, 0x8f, 0xd2, 0x36, 0x0d,
		0x8b, 0x13, 0xc7, 0x1b, 0xfa, 0xe4, 0x68, 0x36,
		0x3f, 0x5b, 0x24, 0xa7, 0x66, 0x4d, 0x31, 0x52,
		0x84, 0x9a, 0xdf, 0x5a, 0x72, 0xa0, 0x23, 0xd9,
		0xbd, 0x56, 0x96, 0x3b, 0xfe, 0xc4, 0x55, 0x6e,
		0xd7, 0xd1, 0xb4, 0x42, 0xf3, 0x72, 0x3b, 0xcc,
		0x09, 0xfb, 0x08, 0xad, 0x8b, 0x77, 0xf5, 0xac,
		0x93, 0x81, 0x61, 0xac, 0xc4, 0xad, 0xc9, 0x74,
		0xb9, 0x77, 0x5a, 0xa6, 0x81, 0x6b, 0x9e, 0x0f,
		0xa2, 0x11, 0x86, 0x5f, 0x27, 0xbf, 0x3e, 0xad,
		0x03, 0x5c, 0x3a, 0x59, 0x32, 0xd5, 0x8f, 0xfc,
		0xcf, 0x4c, 0xa5, 0xfe
	};
	struct if_data start_stats_dp1T1, start_stats_dp2T2;
	struct if_data stats_dp1T1, stats_dp2T2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;

	s2s_common_setup(vrfid, CRYPTO_CIPHER_AES_CBC,
			 CRYPTO_AUTH_HMAC_SHA1,
			 NULL, NULL, 0,
			 XFRM_MODE_TUNNEL);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(CLIENT_LOCAL, CLIENT_REMOTE);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(PORT_EAST, PEER, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_intf_initial_stats_for_if("dp1T1", &start_stats_dp1T1);
	dp_test_intf_initial_stats_for_if("dp2T2", &start_stats_dp2T2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	dp_test_intf_delta_stats_for_if("dp1T1", &start_stats_dp1T1,
					&stats_dp1T1);

	dp_test_assert_internal(stats_dp1T1.ifi_ipackets == 1);
	dp_test_assert_internal(stats_dp1T1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp1T1) == 0);

	dp_test_intf_delta_stats_for_if("dp2T2", &start_stats_dp2T2,
					&stats_dp2T2);
	dp_test_assert_internal(stats_dp2T2.ifi_ipackets == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_opackets == 1);
	dp_test_assert_internal(stats_dp2T2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp2T2) == 0);

	s2s_common_teardown(vrfid, NULL, NULL, 0);
}

static void encrypt6_main(vrfid_t vrfid)
{
	const char expected_payload[] = {
		0x64, 0xc8,
		0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6, 0xb1, 0x0c,
		0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3, 0xa6, 0x71,
		0xa1, 0x72, 0x20, 0x5b, 0xe9, 0x44, 0xcf, 0xf7,
		0x5f, 0x41, 0xf1, 0x94, 0xbe, 0xfe, 0x52, 0x2f,
		0xfc, 0xd2, 0xe5, 0x1f, 0x1d, 0x50, 0xcb, 0xa0,
		0x65, 0x52, 0xb1, 0x44, 0x92, 0xc0, 0xe9, 0xc7,
		0x36, 0xf2, 0xac, 0x05, 0xdc, 0x9a, 0x7f, 0x6d,
		0xfb, 0x9b, 0x51, 0xff, 0xe7, 0x0c, 0xa6, 0x5e,
		0x75, 0x53, 0x7e, 0x3b, 0x74, 0x7e, 0x08, 0x45,
		0x92, 0x96, 0x1f, 0x56, 0xfa, 0xc3, 0xd8, 0xc4,
		0x70, 0x73, 0xb1, 0x0f, 0xca, 0xf5, 0x55, 0x66,
		0xc3, 0xfd, 0xfb, 0x85, 0x93, 0x37, 0x36, 0x2f,
		0xfc, 0xdc, 0x21, 0xa6, 0x0a, 0x8f, 0x58, 0x8a,
		0x03, 0x57, 0x1a, 0xbd, 0x1c, 0xde, 0xe5, 0x7c,
		0xb4, 0x61, 0x1b, 0x90, 0xf7, 0x36, 0xbd, 0xa5,
		0xec, 0x70, 0x38, 0xcf, 0x2c, 0x3a, 0x90, 0x8f,
		0xdd, 0xea, 0xaa, 0xc5, 0xad, 0x98, 0x2b, 0x43,
		0x46, 0x85,
	};
	struct if_data start_stats_dp1T1, start_stats_dp2T2;
	struct if_data stats_dp1T1, stats_dp2T2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_AES_CBC,
			  CRYPTO_AUTH_HMAC_SHA1,
			  NULL, NULL, 0,
			  XFRM_MODE_TUNNEL);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet6(CLIENT_LOCAL6, CLIENT_REMOTE6);
	dp_test_assert_internal(ping_pkt != NULL);

	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv6_pak(PORT_EAST6, PEER6, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND6,
						    1 /* seq no */,
						    0 /* ip ID */,
						    64 /* hlim */,
						    NULL /* transport_hdr*/);
	dp_test_assert_internal(encrypted_pkt != NULL);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_intf_initial_stats_for_if("dp1T1", &start_stats_dp1T1);
	dp_test_intf_initial_stats_for_if("dp2T2", &start_stats_dp2T2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	dp_test_intf_delta_stats_for_if("dp1T1", &start_stats_dp1T1,
					&stats_dp1T1);

	dp_test_assert_internal(stats_dp1T1.ifi_ipackets == 1);
	dp_test_assert_internal(stats_dp1T1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp1T1) == 0);

	dp_test_intf_delta_stats_for_if("dp2T2", &start_stats_dp2T2,
					&stats_dp2T2);
	dp_test_assert_internal(stats_dp2T2.ifi_ipackets == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_opackets == 1);
	dp_test_assert_internal(stats_dp2T2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp2T2) == 0);

	s2s_common_teardown6(vrfid, NULL, NULL, 0);
}

static void
receive_packet(vrfid_t vrfid,
	       const char *ifout,
	       const char *ifin,
	       struct if_data *exp_stats_ifout,
	       struct if_data *exp_stats_ifin,
	       struct dp_test_crypto_policy *ipol,
	       struct dp_test_crypto_policy *opol,
	       uint8_t npols,
	       const char *saddr,
	       const char *daddr,
	       uint16_t udp_port,
	       int exp_status)
{
	struct if_data start_stats_ifout, start_stats_ifin;
	struct if_data stats_ifout, stats_ifin;
	struct dp_test_expected *exp;
	struct rte_mbuf *pkt;
	int len = 512;
	int dis, del, inp;
	int dis2, del2, inp2;

	s2s_common_setup(vrfid,
			 CRYPTO_CIPHER_AES_CBC,
			 CRYPTO_AUTH_HMAC_SHA1,
			 ipol, opol, npols,
			 XFRM_MODE_TUNNEL);

	pkt = dp_test_create_udp_ipv4_pak(saddr, daddr, udp_port, udp_port,
					  1, &len);
	(void)dp_test_pktmbuf_eth_init(pkt,
				       dp_test_intf_name2mac_str(ifin),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * The packet may need to be dropped because it is received
	 * in plain text but matches an input policy, indicating that
	 * it should have been encrypted.
	 */
	if (exp_status != DP_TEST_FWD_DROPPED) {
		exp = dp_test_exp_create(pkt);
		dp_test_exp_set_oif_name(exp, ifout);
		dp_test_exp_set_fwd_status(exp, exp_status);
	} else {
		exp = generate_exp_unreachable(pkt, len, PORT_WEST, saddr,
					       ifin, CLIENT_LOCAL_MAC_ADDR);
	}

	dp_test_intf_initial_stats_for_if(ifout, &start_stats_ifout);
	dp_test_intf_initial_stats_for_if(ifin, &start_stats_ifin);

	dis = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INNOROUTES);
	del = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INDELIVERS);
	inp = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INPKTS);

	dp_test_pak_receive(pkt, ifin, exp);

	dp_test_crypto_check_sad_packets(vrfid, 0, 0);

	dp_test_intf_delta_stats_for_if(ifout, &start_stats_ifout,
					&stats_ifout);
	dp_test_intf_delta_stats_for_if(ifin, &start_stats_ifin,
					&stats_ifin);

	dp_test_validate_if_stats(&stats_ifout, exp_stats_ifout);
	dp_test_validate_if_stats(&stats_ifin, exp_stats_ifin);
	dis2 = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INNOROUTES);
	del2 = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INDELIVERS);
	inp2 = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INPKTS);
	dp_test_verify_vrf_stats(inp, inp2, dis, dis2, del, del2, exp_status);

	s2s_common_teardown(vrfid, ipol, opol, npols);
}

static void
receive_packet6(vrfid_t vrfid,
		const char *ifout,
		const char *ifin,
		struct if_data *exp_stats_ifout,
		struct if_data *exp_stats_ifin,
		struct dp_test_crypto_policy *ipol,
		struct dp_test_crypto_policy *opol,
		uint8_t npols,
		const char *saddr,
		const char *daddr,
		uint16_t udp_port,
		int exp_status)
{
	struct if_data start_stats_ifout, start_stats_ifin;
	struct if_data stats_ifout, stats_ifin;
	struct dp_test_expected *exp;
	struct rte_mbuf *pkt;
	int dis, del, inp;
	int dis2, del2, inp2;
	int    len = 512;

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_AES_CBC,
			  CRYPTO_AUTH_HMAC_SHA1,
			  ipol, opol, npols,
			  XFRM_MODE_TUNNEL);

	pkt = dp_test_create_udp_ipv6_pak(saddr, daddr, udp_port, udp_port,
					  1, &len);
	dp_test_assert_internal(pkt != NULL);
	(void)dp_test_pktmbuf_eth_init(pkt,
				       dp_test_intf_name2mac_str(ifin),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * The packet should be dropped because it is received in
	 * plain text but matches an input policy, indicating that
	 * it should have been encrypted.
	 */
	if (exp_status != DP_TEST_FWD_DROPPED) {
		exp = dp_test_exp_create(pkt);
		dp_test_exp_set_oif_name(exp, ifout);
		dp_test_exp_set_fwd_status(exp, exp_status);
	} else {
		exp = generate_exp_unreachable6(pkt, len, PORT_WEST6, saddr,
						ifin, CLIENT_LOCAL_MAC_ADDR);
	}

	dp_test_intf_initial_stats_for_if(ifout, &start_stats_ifout);
	dp_test_intf_initial_stats_for_if(ifin, &start_stats_ifin);
	dis = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INNOROUTES);
	del = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INDELIVERS);
	inp = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INPKTS);

	dp_test_pak_receive(pkt, ifin, exp);

	dp_test_crypto_check_sad_packets(vrfid, 0, 0);

	dp_test_intf_delta_stats_for_if(ifout, &start_stats_ifout,
					&stats_ifout);
	dp_test_intf_delta_stats_for_if(ifin, &start_stats_ifin,
					&stats_ifin);
	dp_test_validate_if_stats(&stats_ifout, exp_stats_ifout);
	dp_test_validate_if_stats(&stats_ifin, exp_stats_ifin);
	dis2 = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INNOROUTES);
	del2 = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INDELIVERS);
	inp2 = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INPKTS);
	dp_test_verify_vrf_stats(inp, inp2, dis, dis2, del, del2, exp_status);

	s2s_common_teardown6(vrfid, ipol, opol, npols);
}

static void rx_pkt_on_int(vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};

	struct dp_test_crypto_policy my_ipols[2];
	struct dp_test_crypto_policy my_opols[2];

	my_ipols[0] = input_policy;
	my_ipols[1] = input_passthru_policy;
	my_opols[0] = output_policy;
	my_opols[1] = output_passthru_policy;

	exp_stats_ifin.ifi_ipackets = 1;
	exp_stats_ifin.ifi_opackets = 1;

	my_ipols[0].proto = 0;
	my_ipols[0].s_prefix = NETWORK_REMOTE;
	my_ipols[0].d_prefix = NETWORK_WEST;

	my_opols[0].proto = 0;
	my_opols[0].s_prefix = NETWORK_WEST;
	my_opols[0].d_prefix = NETWORK_REMOTE;

	/*
	 * With no passthrough policy (npols = 1), verify that a locally
	 * terminating packet which matches the outgoing crypto policy
	 * is dropped. Expect opackets == 1 for ICMP Unreachable.
	 */
	receive_packet(vrfid,
		       "dp2T2", "dp1T1",
		       &exp_stats_ifout,
		       &exp_stats_ifin,
		       my_ipols, my_opols, 1,
		       CLIENT_LOCAL,
		       PORT_WEST,
		       0,
		       DP_TEST_FWD_DROPPED);

	/*
	 * Add the passthrough policies (npols = 2) and verify that a locally
	 * terminating packet which matches the outgoing crypto policy is not
	 * dropped. Expect opackets = 0 for no ICMP Unreachable.
	 */
	exp_stats_ifin.ifi_opackets = 0;
	receive_packet(vrfid,
		       "dp2T2", "dp1T1",
		       &exp_stats_ifout,
		       &exp_stats_ifin,
		       my_ipols, my_opols, 2,
		       CLIENT_LOCAL,
		       PORT_WEST,
		       0,
		       DP_TEST_FWD_LOCAL);
}

static void rx_pkt_on_int6(vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};

	struct dp_test_crypto_policy my_ipols[2];
	struct dp_test_crypto_policy my_opols[2];

	my_ipols[0] = input_policy6;
	my_ipols[1] = input_passthru_policy6;
	my_opols[0] = output_policy6;
	my_opols[1] = output_passthru_policy6;

	exp_stats_ifin.ifi_ipackets = 1;

	/* Any proto but ICMPV6 to ensure we don't match policy */
	my_ipols[0].proto = 0;
	my_ipols[0].s_prefix = NETWORK_REMOTE6;
	my_ipols[0].d_prefix = NETWORK_WEST6;

	my_opols[0].proto = 0;
	my_opols[0].s_prefix = NETWORK_WEST6;
	my_opols[0].d_prefix = NETWORK_REMOTE6;

	exp_stats_ifin.ifi_opackets = 1;

	receive_packet6(vrfid,
			"dp2T2", "dp1T1",
			&exp_stats_ifout,
			&exp_stats_ifin,
			my_ipols, my_opols, 1,
			CLIENT_LOCAL6,
			PORT_WEST6,
			0,
			DP_TEST_FWD_DROPPED);

	exp_stats_ifin.ifi_opackets = 0;

	receive_packet6(vrfid,
			"dp2T2", "dp1T1",
			&exp_stats_ifout,
			&exp_stats_ifin,
			my_ipols, my_opols, 2,
			CLIENT_LOCAL6,
			PORT_WEST6,
			0,
			DP_TEST_FWD_LOCAL);
}

DP_DECL_TEST_SUITE(site_to_site_suite);

DP_DECL_TEST_CASE(site_to_site_suite, passthrough, NULL, NULL);

DP_START_TEST_FULL_RUN(passthrough, encrypt)
{
	encrypt_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(passthrough, encrypt_vrf)
{
	encrypt_main(TEST_VRF);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(passthrough, rx_pkt_on_int)
{
	rx_pkt_on_int(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(passthrough, encrypt6)
{
	encrypt6_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(passthrough, encrypt6_vrf)
{
	encrypt6_main(TEST_VRF);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(passthrough, rx_pkt_on_int6)
{
	rx_pkt_on_int6(VRF_DEFAULT_ID);
} DP_END_TEST;

