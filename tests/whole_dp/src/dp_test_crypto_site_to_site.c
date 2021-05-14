/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Site-to-Site crypto tests
 */

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_crypto_utils.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_npf_lib.h"
#include "dp_test_xfrm_server.h"

#include "main.h"
#include "in_cksum.h"
#include "ip_funcs.h"
#include "ip6_funcs.h"

#include "crypto/crypto.h"
#include "crypto/crypto_forward.h"
#include "crypto/crypto_internal.h"

/*
 * The test configuration is centred around UUT. It has two ports, one
 * on 10.10.1.0/24, and the other on 10.10.2.0/24. It has a
 * site-to-site configuration on the 10.10.2.0 network with .3 as its
 * peer. It has routing setup so that packets destined for 10.10.3.4
 * go via 10.10.2.3 and should be encrypted. It is directly connected
 * to the client 10.10.1.1.
 *
 *
 *            2001:1::/64          2001:2::/64           2001:3::/64
 *            10.10.1.0/24         10.10.2.0/24          10.10.3.0
 *                      +----------+          +---------+
 * +-----------+        |          |          |         |         +----------+
 * |           |.1    .2|          | .2   .3  |         |      .4 |          |
 * |Client     +--------+  UUT     +----------+  PEER   + - - - - + Client   |
 * |   local   |        |          |          |         |         |  remote  |
 * |           |        |          |          |         |         |          |
 * +-----------+        |          |          |         |         +----------+
 *                      +----------+          +---------+
 *
 *     WEST<<<<<<<<<<<<<<         >>>>>>>>>>>>>>EAST
 */

#define SPI_OUTBOUND	0xd43d87c7
#define SPI_OUTBOUND6	0x89752ac5
#define SPI_INBOUND	0x10
#define TUNNEL_REQID	1234
#define TEST_VRF	42
#define RULE_PRIORITY	1

/*
 * Null encrypted ICMP packet with no authentication.
 * The trailing 4 bytes  made up two bytes of padding
 * (0x01, 0x02), pad count (0x02) and protocol (0x04)
 */
const char payload_v4_icmp_null_enc[] = {
	0x45, 0x00, 0x00, 0x54, 0xea, 0x53, 0x40, 0x00,
	0x40, 0x01, 0x38, 0x3d, 0x0a, 0x0a, 0x01, 0x01,
	0x0a, 0x0a, 0x03, 0x04, 0x08, 0x00, 0xfc, 0x62,
	0x0a, 0xc9, 0x00, 0x01, 0x2c, 0x57, 0xba, 0x55,
	0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9, 0x08, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x02, 0x04
};

/*
 * Null encrypted ICMP packet with no authentication.
 * The trailing 4 bytes  made up two bytes of padding
 * (0x01, 0x02), pad count (0x02) and protocol (0x04)
 *
 * this is a packet going from the remote to the
 * local site.
 */
const char payload_v4_icmp_null_enc_rem_to_loc[] = {
	0x45, 0x00, 0x00, 0x54, 0xea, 0x53, 0x40, 0x00,
	0x40, 0x01, 0x38, 0x3d, 0x0a, 0x0a, 0x03, 0x04,
	0x0a, 0x0a, 0x01, 0x01, 0x08, 0x00, 0xfc, 0x62,
	0x0a, 0xc9, 0x00, 0x01, 0x2c, 0x57, 0xba, 0x55,
	0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9, 0x08, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x02, 0x04
};

/*
 * Null encrypted ICMP6 packet with no authentication.
 * The trailing 8 bytes made up of six bytes of padding
 * (0x01, ..0x06), pad count (0x06) and protocol (0x29)
 */
const char payload_v6_icmp_null_enc[] = {
	0x60, 0x03, 0xa8, 0x69, 0x00, 0x40, 0x3a, 0x40,
	0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
	0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
	0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x29
};

/*
 * Null encrypted ICMP6 packet with no authentication.
 * The trailing 8 bytes made up of six bytes of padding
 * (0x01, ..0x06), pad count (0x06) and protocol (0x29)
 *
 * this is a packet going from the remote to the
 * local site.
 */
const char payload_v6_icmp_null_enc_rem_to_loc[] = {
	0x60, 0x03, 0xa8, 0x69, 0x00, 0x40, 0x3a, 0x40,
	0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
	0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
	0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x29
};

static void s2s_default_conf(struct dp_test_s2s_config *conf, vrfid_t vrfid)
{
	conf->mode = XFRM_MODE_TRANSPORT;
	conf->out_of_order = VRF_XFRM_IN_ORDER;

	conf->vrfid = vrfid;
	conf->cipher_algo = CRYPTO_CIPHER_NULL;
	conf->auth_algo = CRYPTO_AUTH_NULL;
	conf->iface1 = "dp1T1";
	conf->client_local_mac = "aa:bb:cc:dd:1:1";
	conf->iface2 = "dp2T2";
	conf->peer_mac = "aa:bb:cc:dd:2:3";
	conf->with_vfp = VFP_FALSE;
	conf->iface_vfp = "vfp1";
	conf->vfp_out_of_order = false;

	/* default policies */
	conf->ipolicy = &(conf->def_ipolicy);
	conf->nipols = 1;
	conf->opolicy = &(conf->def_opolicy);
	conf->nopols = 1;

	memset(conf->ipolicy, 0, sizeof(*conf->ipolicy));

	conf->ipolicy->d_prefix = conf->network_local_ip_with_mask;
	conf->ipolicy->s_prefix = conf->network_remote_ip_with_mask;
	conf->ipolicy->proto = 0;
	conf->ipolicy->dst = conf->port_east_ip;
	conf->ipolicy->family = conf->af;
	conf->ipolicy->dst_family = conf->af;
	conf->ipolicy->dir = XFRM_POLICY_IN,
	conf->ipolicy->priority = RULE_PRIORITY;
	conf->ipolicy->reqid = TUNNEL_REQID;
	conf->ipolicy->mark = 0;
	conf->ipolicy->vrfid = VRF_DEFAULT_ID;

	memset(conf->opolicy, 0, sizeof(*conf->opolicy));

	conf->opolicy->d_prefix = conf->network_remote_ip_with_mask;
	conf->opolicy->s_prefix = conf->network_local_ip_with_mask;
	conf->opolicy->dst = conf->peer_ip;
	conf->opolicy->family = conf->af;
	conf->opolicy->dst_family = conf->af;
	conf->opolicy->dir = XFRM_POLICY_OUT;
	conf->opolicy->priority = RULE_PRIORITY;
	conf->opolicy->reqid = TUNNEL_REQID;
	conf->opolicy->mark = 0;
	conf->opolicy->vrfid = VRF_DEFAULT_ID;

	/* Set-up default fields in input and output SAs */

	memset(&(conf->input_sa), 0, sizeof(conf->input_sa));

	conf->input_sa.d_addr = conf->port_east_ip;
	conf->input_sa.s_addr = conf->peer_ip;
	conf->input_sa.family = conf->af;
	conf->input_sa.reqid = TUNNEL_REQID;
	conf->input_sa.mark = 0;

	memset(&(conf->output_sa), 0, sizeof(conf->output_sa));

	conf->output_sa.d_addr = conf->peer_ip;
	conf->output_sa.s_addr = conf->port_east_ip;
	conf->output_sa.family = conf->af;
	conf->output_sa.reqid = TUNNEL_REQID;
	conf->output_sa.mark = 0;
}

static void s2s_ipv4_default_conf(struct dp_test_s2s_config *conf,
				  vrfid_t vrfid)
{
	conf->af = AF_INET;

	conf->iface1_ip_with_mask = "10.10.1.2/24";
	conf->client_local_ip = "10.10.1.1";
	conf->network_local_ip_with_mask = "10.10.1.0/24";
	conf->network_local_ip = "10.10.1.0";
	conf->network_local_mask = 24;
	conf->port_west_ip = "10.10.1.2";

	conf->iface2_ip_with_mask = "10.10.2.2/24";
	conf->peer_ip = "10.10.2.3";
	conf->network_east_ip_with_mask = "10.10.2.0/24";
	conf->port_east_ip = "10.10.2.2";

	conf->network_remote_ip_with_mask = "10.10.3.0/24";
	conf->network_remote_ip = "10.10.3.0";
	conf->network_remote_mask = 24;
	conf->client_remote_ip = "10.10.3.4";

	conf->iface_vfp_ip = "169.254.0.1/32";

	s2s_default_conf(conf, vrfid);

	conf->ipolicy->rule_no = 5;
	conf->opolicy->rule_no = 1;

	conf->input_sa.spi = SPI_INBOUND;
	conf->output_sa.spi = SPI_OUTBOUND;
}

static void s2s_ipv6_default_conf(struct dp_test_s2s_config *conf,
				  vrfid_t vrfid)
{
	conf->af = AF_INET6;

	conf->iface1_ip_with_mask = "2001:1::2/64";
	conf->client_local_ip = "2001:1::1";
	conf->network_local_ip_with_mask = "2001:1::/64";
	conf->network_local_ip = "2001:1::0";
	conf->network_local_mask = 64;
	conf->port_west_ip = "2001:1::2";

	conf->iface2_ip_with_mask = "2001:2::2/64";
	conf->peer_ip = "2001:2::3";
	conf->network_east_ip_with_mask = "2001:2::/64";
	conf->port_east_ip = "2001:2::2";

	conf->network_remote_ip_with_mask = "2001:3::/64";
	conf->network_remote_ip = "2001:3::0";
	conf->network_remote_mask = 64;
	conf->client_remote_ip = "2001:3::4";

	conf->iface_vfp_ip = "fe80::1/128";

	s2s_default_conf(conf, vrfid);

	conf->ipolicy->rule_no = 6;
	conf->opolicy->rule_no = 2;

	conf->input_sa.spi = SPI_INBOUND;
	conf->output_sa.spi = SPI_OUTBOUND6;
}


static void _setup_policies(struct dp_test_s2s_config *conf,
			    const char *file, int line)
{
	bool verify = true;
	bool update = false;
	int i;

	dp_test_console_request_reply("debug rldb-acl", true);
	dp_test_console_request_reply("debug crypto", true);

	for (i = 0; i < conf->nipols; i++) {
		conf->ipolicy[i].vrfid = conf->vrfid;
		_dp_test_crypto_create_policy(file, line, &(conf->ipolicy[i]),
					      verify, update);
	}

	for (i = 0; i < conf->nopols; i++) {
		conf->opolicy[i].vrfid = conf->vrfid;
		_dp_test_crypto_create_policy(file, line, &(conf->opolicy[i]),
					      verify, update);
	}
}
#define setup_policies(conf) \
	_setup_policies(conf, __FILE__, __LINE__)

static void _teardown_policies(struct dp_test_s2s_config *conf,
			       const char *file, int line)
{
	int i;

	dp_test_console_request_reply("debug rldb-acl", true);
	dp_test_console_request_reply("debug crypto", true);

	for (i = 0; i < conf->nipols; i++) {
		_dp_test_crypto_delete_policy(file, line, &(conf->ipolicy[i]),
					      true);
	}

	for (i = 0; i < conf->nopols; i++) {
		_dp_test_crypto_delete_policy(file, line, &(conf->opolicy[i]),
					      true);
	}
}
#define teardown_policies(conf) \
	_teardown_policies(conf, __FILE__, __LINE__)

static void _setup_sas(struct dp_test_s2s_config *conf,
		       const char *file, const char *func,
		       int line)
{
	bool verify = true;

	conf->input_sa.auth_algo = conf->auth_algo;
	conf->input_sa.cipher_algo = conf->cipher_algo;
	conf->input_sa.mode = conf->mode;
	conf->input_sa.vrfid = conf->vrfid;

	conf->output_sa.auth_algo = conf->auth_algo;
	conf->output_sa.cipher_algo = conf->cipher_algo;
	conf->output_sa.mode = conf->mode;
	conf->output_sa.vrfid = conf->vrfid;

	_dp_test_crypto_create_sa(file, func, line, &(conf->input_sa), verify);
	_dp_test_crypto_create_sa(file, func, line, &(conf->output_sa), verify);
}
#define setup_sas(conf)	\
	_setup_sas(conf,  __FILE__, __func__, __LINE__)

static void _teardown_sas(struct dp_test_s2s_config *conf,
			  const char *file, const char *func,
			  int line)
{
	_dp_test_crypto_delete_sa_verify(file, line, &(conf->input_sa), true);
	_dp_test_crypto_delete_sa_verify(file, line, &(conf->output_sa), true);
}

#define teardown_sas(conf) \
	_teardown_sas(conf, __FILE__, __func__, __LINE__)

static void _build_pak_and_expected_encrypt(struct rte_mbuf **ping_pkt_p,
					    struct dp_test_expected **exp_p,
					    const char *rx_intf,
					    const char *tx_intf,
					    const char *local,
					    const char *remote,
					    const char *src_addr,
					    const char *dst_addr,
					    const char *peer_mac,
					    char expected_payload[],
					    int payload_len,
					    vrfid_t transport_vrf,
					    uint8_t in_tos,
					    uint8_t exp_tos,
					    const char *file, const char *func,
					    int line)
{
	struct rte_mbuf *ping_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_addr inner_addr;
	struct dp_test_addr outer_addr;

	/* Construct the input ICMP ping packet. */
	dp_test_addr_str_to_addr(local, &inner_addr);
	if (inner_addr.family == AF_INET) {
		uint16_t cksum;

		ping_pkt = build_input_packet(local, remote);
		dp_test_set_pak_ip_field(iphdr(ping_pkt), DP_TEST_SET_TOS,
					 in_tos);

		/* TOS is the 2nd byte of an ip hdr */
		expected_payload[1] = in_tos;
		/* Fixup checksum too, bytes 11,12*/
		expected_payload[11] = 0;
		expected_payload[12] = 0;
		cksum = dp_in_cksum_hdr((struct iphdr *)&expected_payload[0]);
		*((uint16_t *)&expected_payload[11]) = htons(cksum);
	} else {
		ping_pkt = build_input_packet6(local, remote);
		dp_test_set_pak_ip6_field(ip6hdr(ping_pkt), DP_TEST_SET_TOS,
					  in_tos);

		/* Traffic class is bits 5..12 of an ipv6 header */
		expected_payload[0] &= 0xf0;
		expected_payload[1] &= 0x0f;
		expected_payload[0] |= ((in_tos & 0xf0) >> 4);
		expected_payload[1] |= ((in_tos & 0x0f) << 4);
	}
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(rx_intf),
				       NULL,
				       inner_addr.family == AF_INET ?
					       RTE_ETHER_TYPE_IPV4 :
					       RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet. If src/dst are v4
	 * build a v4 packet, else build v6
	 */
	dp_test_addr_str_to_addr(src_addr, &outer_addr);
	if (outer_addr.family == AF_INET) {
		encrypted_pkt = dp_test_create_esp_ipv4_pak(
			src_addr, dst_addr, 1,
			&payload_len,
			expected_payload,
			SPI_OUTBOUND,
			1 /* seq no */,
			0 /* ip ID */,
			255 /* ttl */,
			NULL, /* udp/esp */
			NULL /* transport_hdr*/);

		dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_TOS,
					 exp_tos);
	} else {
		encrypted_pkt = dp_test_create_esp_ipv6_pak(
			src_addr, dst_addr, 1,
			&payload_len,
			expected_payload,
			SPI_OUTBOUND6,
			1 /* seq no */,
			0 /* ip ID */,
			64 /* hlim */,
			NULL /* transport_hdr*/);

		dp_test_set_pak_ip6_field(ip6hdr(encrypted_pkt),
					  DP_TEST_SET_TOS, exp_tos);
	}
	dp_test_assert_internal(encrypted_pkt != NULL);
	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       peer_mac,
				       dp_test_intf_name2mac_str(tx_intf),
				       outer_addr.family == AF_INET ?
					       RTE_ETHER_TYPE_IPV4 :
					       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);

	dp_test_exp_set_oif_name(exp, tx_intf);

	*exp_p = exp;
	*ping_pkt_p = ping_pkt;
}
#define build_pak_and_expected_encrypt(ping_pkt, exp, rx_intf, tx_intf, \
				       local, remote, src_addr, dest_addr, \
				       peer_mac, exp_payload, payload_len,  \
				       transport_vrf, in_tos, exp_tos)	\
	_build_pak_and_expected_encrypt(ping_pkt, exp, rx_intf, tx_intf, \
					local, remote, src_addr, dest_addr, \
					peer_mac, exp_payload, payload_len, \
					transport_vrf, in_tos, exp_tos,	\
					__FILE__, __func__, __LINE__)

static void _build_pak_and_expected_decrypt(struct rte_mbuf **enc_pkt_p,
					    struct dp_test_expected **exp_p,
					    const char *rx_intf,
					    const char *tx_intf,
					    const char *local,
					    const char *remote,
					    const char *src_addr,
					    const char *dst_addr,
					    const char *local_mac,
					    const char *peer_mac,
					    char transmit_payload[],
					    int payload_len,
					    vrfid_t transport_vrf,
					    const char *file, const char *func,
					    int line)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *encrypted_pkt;
	struct rte_mbuf *expected_pkt;
	struct dp_test_addr inner_addr;
	struct dp_test_addr outer_addr;

	/* Construct the output ICMP ping packet. */
	dp_test_addr_str_to_addr(local, &inner_addr);
	if (inner_addr.family == AF_INET) {
		expected_pkt = build_input_packet(local, remote);
		dp_test_set_pak_ip_field(iphdr(expected_pkt),
					 DP_TEST_SET_TTL, 0x3f);
	} else {
		expected_pkt = build_input_packet6(local, remote);
		dp_test_ipv6_decrement_ttl(expected_pkt);
	}

	(void)dp_test_pktmbuf_eth_init(expected_pkt, local_mac,
				       dp_test_intf_name2mac_str(tx_intf),
				       inner_addr.family == AF_INET ?
					       RTE_ETHER_TYPE_IPV4 :
					       RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet. If src/dst are v4
	 * build a v4 packet, else build v6
	 */
	dp_test_addr_str_to_addr(src_addr, &outer_addr);
	if (outer_addr.family == AF_INET) {
		encrypted_pkt =
			dp_test_create_esp_ipv4_pak(src_addr, dst_addr, 1,
						    &payload_len,
						    transmit_payload,
						    SPI_INBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);

	} else {
		encrypted_pkt =
			dp_test_create_esp_ipv6_pak(src_addr, dst_addr, 1,
						    &payload_len,
						    transmit_payload,
						    SPI_INBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* transport_hdr*/);
	}
	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       dp_test_intf_name2mac_str(rx_intf),
				       peer_mac,
				       outer_addr.family == AF_INET ?
					       RTE_ETHER_TYPE_IPV4 :
					       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(expected_pkt);
	rte_pktmbuf_free(expected_pkt);
	dp_test_exp_set_oif_name(exp, tx_intf);

	*exp_p = exp;
	*enc_pkt_p = encrypted_pkt;
}

#define build_pak_and_expected_decrypt(ping_pkt, exp, rx_intf, tx_intf, \
				       local, remote, src_addr, dest_addr, \
				       local_mac, peer_mac,		\
				       exp_payload, payload_len,	\
				       transport_vrf)			\
	_build_pak_and_expected_decrypt(ping_pkt, exp, rx_intf, tx_intf, \
					local, remote, src_addr, dest_addr, \
				       local_mac, peer_mac,		\
					exp_payload, payload_len,	\
					transport_vrf, __FILE__,	\
					__func__, __LINE__)

static void null_encrypt_transport_main(vrfid_t vrfid)
{
	/*
	 * Null encrypted ICMP packet with no authentication.
	 * The trailing 4 bytes  made up two bytes of padding
	 * (0x01, 0x02), pad count (0x02) and protocol (0x04)
	 */
	const char expected_payload[] = {
		0x08, 0x00, 0xfc, 0x62, 0x0a, 0xc9, 0x00, 0x01,
		0x2c, 0x57, 0xba, 0x55, 0x00, 0x00, 0x00, 0x00,
		0xd9, 0xe9, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x02, 0xe0
	};
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	struct iphdr  *trans_mode_hdr;
	int payload_len;
	struct dp_test_s2s_config conf;

	s2s_ipv4_default_conf(&conf, vrfid);

	dp_test_s2s_common_setup(&conf);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(conf.client_local_ip,
				      conf.client_remote_ip);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(conf.iface1),
				       NULL, RTE_ETHER_TYPE_IPV4);
	dp_test_set_pak_ip_field(iphdr(ping_pkt), DP_TEST_SET_PROTOCOL, 224);

	/*
	 * Construct the expected encrypted packet
	 */
	trans_mode_hdr = dp_pktmbuf_mtol3(ping_pkt, struct iphdr *);
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(conf.port_east_ip,
						    conf.peer_ip, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    trans_mode_hdr);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt, conf.peer_mac,
				       dp_test_intf_name2mac_str(conf.iface2),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, conf.iface2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, conf.iface1, exp);
	dp_test_crypto_check_sad_packets(conf.vrfid, 1, 64);

	dp_test_s2s_common_teardown(&conf);
}

static void encrypt_aesgcm_main(vrfid_t vrfid)
{
		const char expected_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45,
		0x54, 0xd6, 0x58, 0x24, 0x68, 0x3a, 0xb5, 0xaf,
		0xde, 0xb5, 0xd3, 0x1d, 0x42, 0xd5, 0x9d, 0x6d,
		0xfe, 0x60, 0x20, 0x5a, 0x42, 0xa7, 0x34, 0xa4,
		0xb4, 0xd7, 0x75, 0x62, 0xa8, 0x41, 0x57, 0x35,
		0x18, 0xb8, 0x9b, 0xe3, 0xfc, 0x8c, 0xc3, 0xe2,
		0x38, 0x2c, 0xad, 0xeb, 0x2d, 0x2f, 0x39, 0x4c,
		0x36, 0x83, 0xea, 0x2f, 0x10, 0xc5, 0x21, 0x94,
		0xc5, 0x04, 0x88, 0x58, 0xad, 0x43, 0x86, 0x1c,
		0x2c, 0xf4, 0x7a, 0x05, 0xde, 0x61, 0x24, 0x64,
		0x16, 0x43, 0x7e, 0x2c, 0xba, 0x60, 0xb3, 0x26,
		0x28, 0x20, 0x85, 0xca, 0xf3, 0xe5, 0x07, 0xfd,
		0x61, 0x9d, 0x59, 0xe6, 0x55, 0xde, 0x9e, 0x26,
		0xb7, 0x8e, 0x56, 0x28, 0x89, 0x73, 0x21, 0x48,
		0x38, 0x21
	};
	struct if_data start_stats_iface1, start_stats_iface2;
	struct if_data stats_iface1, stats_iface2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;
	struct dp_test_s2s_config conf;

	s2s_ipv4_default_conf(&conf, vrfid);

	conf.mode = XFRM_MODE_TUNNEL;
	conf.cipher_algo = CRYPTO_CIPHER_AES128GCM;
	conf.auth_algo = CRYPTO_AUTH_HMAC_SHA1;

	dp_test_s2s_common_setup(&conf);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(conf.client_local_ip,
				      conf.client_remote_ip);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(conf.iface1),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(conf.port_east_ip,
						    conf.peer_ip, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL, /* udp/esp */
						    NULL /* transport_hdr*/);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt, conf.peer_mac,
				       dp_test_intf_name2mac_str(conf.iface2),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, conf.iface2);

	dp_test_intf_initial_stats_for_if(conf.iface1, &start_stats_iface1);
	dp_test_intf_initial_stats_for_if(conf.iface2, &start_stats_iface2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, conf.iface1, exp);
	dp_test_crypto_check_sad_packets(conf.vrfid, 1, 84);

	dp_test_intf_delta_stats_for_if(conf.iface1, &start_stats_iface1,
					&stats_iface1);

	dp_test_assert_internal(stats_iface1.ifi_ipackets == 1);
	dp_test_assert_internal(stats_iface1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_opackets == 0);
	dp_test_assert_internal(stats_iface1.ifi_opackets == 0);
	dp_test_assert_internal(stats_iface1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_iface1) == 0);

	dp_test_intf_delta_stats_for_if(conf.iface2, &start_stats_iface2,
					&stats_iface2);
	dp_test_assert_internal(stats_iface2.ifi_ipackets == 0);
	dp_test_assert_internal(stats_iface2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_opackets == 1);
	dp_test_assert_internal(stats_iface2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_iface2) == 0);

	dp_test_s2s_common_teardown(&conf);
}

static void encrypt_main(vrfid_t vrfid, enum vrf_and_xfrm_order out_of_order)
{
	const char expected_payload[] = {
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
		0x99, 0xa5, 0x9d, 0xaf
	};
	struct if_data start_stats_iface1, start_stats_iface2;
	struct if_data stats_iface1, stats_iface2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;
	struct dp_test_s2s_config conf;

	s2s_ipv4_default_conf(&conf, vrfid);

	conf.mode = XFRM_MODE_TUNNEL;
	conf.cipher_algo = CRYPTO_CIPHER_AES_CBC;
	conf.auth_algo = CRYPTO_AUTH_HMAC_SHA1;
	conf.out_of_order = out_of_order;

	dp_test_s2s_common_setup(&conf);

	if (out_of_order) {
		dp_test_s2s_common_teardown(&conf);
		return;
	}
	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(conf.client_local_ip,
				      conf.client_remote_ip);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(conf.iface1),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(conf.port_east_ip,
						    conf.peer_ip, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt, conf.peer_mac,
				       dp_test_intf_name2mac_str(conf.iface2),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, conf.iface2);

	dp_test_intf_initial_stats_for_if(conf.iface1, &start_stats_iface1);
	dp_test_intf_initial_stats_for_if(conf.iface2, &start_stats_iface2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, conf.iface1, exp);
	dp_test_crypto_check_sad_packets(conf.vrfid, 1, 84);

	dp_test_intf_delta_stats_for_if(conf.iface1, &start_stats_iface1,
					&stats_iface1);

	dp_test_assert_internal(stats_iface1.ifi_ipackets == 1);
	dp_test_assert_internal(stats_iface1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_opackets == 0);
	dp_test_assert_internal(stats_iface1.ifi_opackets == 0);
	dp_test_assert_internal(stats_iface1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_iface1) == 0);

	dp_test_intf_delta_stats_for_if(conf.iface2, &start_stats_iface2,
					&stats_iface2);
	dp_test_assert_internal(stats_iface2.ifi_ipackets == 0);
	dp_test_assert_internal(stats_iface2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_opackets == 1);
	dp_test_assert_internal(stats_iface2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_iface2) == 0);

	dp_test_s2s_common_teardown(&conf);
}

static void encrypt6_main(vrfid_t vrfid)
{
	const char expected_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6,
		0xb1, 0x0c, 0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3,
		0xaf, 0x25, 0xfa, 0x8e, 0x71, 0x62, 0xcc, 0xc0,
		0x77, 0xc3, 0x61, 0x7a, 0xcc, 0x72, 0x31, 0x4b,
		0x38, 0x64, 0x75, 0xb5, 0x2d, 0x24, 0x3a, 0x79,
		0x1b, 0x74, 0x4e, 0x94, 0xbd, 0xe2, 0xe8, 0x72,
		0x74, 0x26, 0x5e, 0x2e, 0x21, 0x36, 0x7a, 0xee,
		0x6c, 0xdf, 0x22, 0xc5, 0x9c, 0xe5, 0x4f, 0x4e,
		0xfb, 0x85, 0x13, 0x61, 0x3c, 0xb1, 0xc0, 0x11,
		0x5f, 0xe3, 0xf0, 0xe4, 0xfe, 0x7f, 0x2f, 0x93,
		0x73, 0xf7, 0xea, 0xad, 0x8c, 0xc8, 0xbd, 0xd0,
		0xea, 0x91, 0x34, 0xeb, 0x2a, 0xe4, 0x38, 0x69,
		0x4c, 0xe2, 0x60, 0x1d, 0x48, 0xdb, 0x24, 0x1d,
		0x3b, 0x61, 0x87, 0x16, 0x05, 0x59, 0x36, 0xcf,
		0xca, 0x88, 0x66, 0xf9, 0x30, 0x2a, 0xbd, 0xc3,
		0x87, 0xd1, 0xd8, 0x16, 0xf1, 0xd3, 0xf9, 0x68,
		0xd0, 0xac, 0xec, 0xd0, 0xf4, 0xe9, 0x06, 0x3a,
		0xe0, 0x6d, 0x0e, 0x13
	};
	struct if_data start_stats_iface1, start_stats_iface2;
	struct if_data stats_iface1, stats_iface2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;
	struct dp_test_s2s_config conf;

	s2s_ipv6_default_conf(&conf, vrfid);

	conf.mode = XFRM_MODE_TUNNEL;
	conf.cipher_algo = CRYPTO_CIPHER_AES_CBC;
	conf.auth_algo = CRYPTO_AUTH_HMAC_SHA1;

	dp_test_s2s_common_setup(&conf);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet6(conf.client_local_ip,
				       conf.client_remote_ip);
	dp_test_assert_internal(ping_pkt != NULL);

	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(conf.iface1),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv6_pak(conf.port_east_ip,
						    conf.peer_ip, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND6,
						    1 /* seq no */,
						    0 /* ip ID */,
						    64 /* hlim */,
						    NULL /* transport_hdr*/);
	dp_test_assert_internal(encrypted_pkt != NULL);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt, conf.peer_mac,
				       dp_test_intf_name2mac_str(conf.iface2),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, conf.iface2);

	dp_test_intf_initial_stats_for_if(conf.iface1, &start_stats_iface1);
	dp_test_intf_initial_stats_for_if(conf.iface2, &start_stats_iface2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, conf.iface1, exp);
	dp_test_crypto_check_sad_packets(conf.vrfid, 1, 104);

	dp_test_intf_delta_stats_for_if(conf.iface1, &start_stats_iface1,
					&stats_iface1);

	dp_test_assert_internal(stats_iface1.ifi_ipackets == 1);
	dp_test_assert_internal(stats_iface1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_opackets == 0);
	dp_test_assert_internal(stats_iface1.ifi_opackets == 0);
	dp_test_assert_internal(stats_iface1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_iface1) == 0);

	dp_test_intf_delta_stats_for_if(conf.iface2, &start_stats_iface2,
					&stats_iface2);
	dp_test_assert_internal(stats_iface2.ifi_ipackets == 0);
	dp_test_assert_internal(stats_iface2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_opackets == 1);
	dp_test_assert_internal(stats_iface2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_iface2) == 0);

	dp_test_s2s_common_teardown(&conf);
}

static void bad_hash_algorithm_main(vrfid_t vrfid)
{
	struct dp_test_expected *exp = dp_test_exp_create(NULL);
	struct rte_mbuf *ping;
	struct dp_test_s2s_config conf;

	s2s_ipv4_default_conf(&conf, vrfid);

	conf.mode = XFRM_MODE_TUNNEL;
	conf.cipher_algo = CRYPTO_CIPHER_AES_CBC;
	conf.auth_algo = CRYPTO_AUTH_HMAC_XCBC;

	dp_test_s2s_common_setup(&conf);

	ping = build_input_packet(conf.client_local_ip, conf.client_remote_ip);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(ping, conf.iface1, exp);

	dp_test_s2s_common_teardown(&conf);
}

static void bad_hash_algorithm6_main(vrfid_t vrfid)
{
	struct dp_test_expected *exp = dp_test_exp_create(NULL);
	struct rte_mbuf *ping;
	struct dp_test_s2s_config conf;

	s2s_ipv6_default_conf(&conf, vrfid);

	conf.mode = XFRM_MODE_TUNNEL;
	conf.cipher_algo = CRYPTO_CIPHER_AES_CBC;
	conf.auth_algo = CRYPTO_AUTH_HMAC_XCBC;

	dp_test_s2s_common_setup(&conf);

	ping = build_input_packet6(conf.client_local_ip, conf.client_remote_ip);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(ping, conf.iface1, exp);

	dp_test_s2s_common_teardown(&conf);
}

static void null_encrypt_main(vrfid_t vrfid, enum vfp_presence with_vfp)
{
	char expected_payload_novfp[sizeof(payload_v4_icmp_null_enc)];

	/* Using a vfp (correctly) decrements ttl */
	const char expected_payload_vfp[] = {
		0x45, 0x00, 0x00, 0x54, 0xea, 0x53, 0x40, 0x00,
		0x3f, 0x01, 0x39, 0x3d, 0x0a, 0x0a, 0x01, 0x01,
		0x0a, 0x0a, 0x03, 0x04, 0x08, 0x00, 0xfc, 0x62,
		0x0a, 0xc9, 0x00, 0x01, 0x2c, 0x57, 0xba, 0x55,
		0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x02, 0x04
	};
	const char *expected_payload = with_vfp ? expected_payload_vfp :
		expected_payload_novfp;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;
	struct dp_test_s2s_config conf;

	memcpy(expected_payload_novfp, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));

	s2s_ipv4_default_conf(&conf, vrfid);

	conf.with_vfp = with_vfp;
	conf.vfp_out_of_order = true;	/* will be in order for IPv6 test */
	conf.mode = XFRM_MODE_TUNNEL;

	dp_test_s2s_common_setup(&conf);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(conf.client_local_ip,
				      conf.client_remote_ip);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(conf.iface1),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload_novfp);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(conf.port_east_ip,
						    conf.peer_ip, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt, conf.peer_mac,
				       dp_test_intf_name2mac_str(conf.iface2),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, conf.iface2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, conf.iface1, exp);
	dp_test_crypto_check_sad_packets(conf.vrfid, 1, 84);
	if (conf.with_vfp == VFP_TRUE) {
		char vfp_cmd[100];
		snprintf(vfp_cmd, sizeof(vfp_cmd), "ifconfig %s",
			 conf.iface_vfp);
		dp_test_check_state_show(vfp_cmd, "tx_packets\": 1", false);
	}

	dp_test_s2s_common_teardown(&conf);
}

static void null_encrypt6_transport_main(vrfid_t vrfid)
{
	/*
	 * Null encrypted ICMP packet with no authentication.
	 */
	const char expected_payload[] = {
		0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
		0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
		0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x3a
	};
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	struct ip6_hdr  *trans_mode_hdr;
	int payload_len;
	struct dp_test_s2s_config conf;

	s2s_ipv6_default_conf(&conf, vrfid);

	dp_test_s2s_common_setup(&conf);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet6(conf.client_local_ip,
				       conf.client_remote_ip);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(conf.iface1),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet
	 */
	trans_mode_hdr = dp_pktmbuf_mtol3(ping_pkt, struct ip6_hdr *);
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv6_pak(conf.port_east_ip,
						    conf.peer_ip, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND6,
						    1 /* seq no */,
						    0 /* ip ID */,
						    64 /* ttl */,
						    trans_mode_hdr);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt, conf.peer_mac,
				       dp_test_intf_name2mac_str(conf.iface2),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, conf.iface2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, conf.iface1, exp);
	dp_test_crypto_check_sad_packets(conf.vrfid, 1, 64);

	dp_test_s2s_common_teardown(&conf);
}

static void null_encrypt6_main(vrfid_t vrfid, enum vfp_presence with_vfp)
{
	/*
	 * Null encrypted ICMP packet with no authentication.
	 */
	const char expected_payload_novfp[] = {
		0x60, 0x03, 0xa8, 0x69, 0x00, 0x40, 0x3a, 0x40,
		0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
		0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
		0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x29
	};
	/* Using a vfp (correctly) decrements hop limit */
	const char expected_payload_vfp[] = {
		0x60, 0x03, 0xa8, 0x69, 0x00, 0x40, 0x3a, 0x3f,
		0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
		0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
		0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x29
	};
	const char *expected_payload = with_vfp ? expected_payload_vfp :
		expected_payload_novfp;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;
	struct dp_test_s2s_config conf;

	s2s_ipv6_default_conf(&conf, vrfid);

	conf.with_vfp = with_vfp;
	conf.mode = XFRM_MODE_TUNNEL;

	dp_test_s2s_common_setup(&conf);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet6(conf.client_local_ip,
				       conf.client_remote_ip);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(conf.iface1),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload_novfp);
	encrypted_pkt = dp_test_create_esp_ipv6_pak(conf.port_east_ip,
						    conf.peer_ip, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND6,
						    1 /* seq no */,
						    0 /* ip ID */,
						    64 /* ttl */,
						    NULL /* transport_hdr*/);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt, conf.peer_mac,
				       dp_test_intf_name2mac_str(conf.iface2),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, conf.iface2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, conf.iface1, exp);
	dp_test_crypto_check_sad_packets(conf.vrfid, 1, 104);

	if (conf.with_vfp == VFP_TRUE) {
		char vfp_cmd[100];
		snprintf(vfp_cmd, sizeof(vfp_cmd), "ifconfig %s",
			 conf.iface_vfp);
		dp_test_check_state_show(vfp_cmd, "tx_packets\": 1", false);
	}

	dp_test_s2s_common_teardown(&conf);
}

static void s2s_toobig6_main(vrfid_t vrfid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *icmp_pak;
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *ip6;
	int len = 1572;
	int icmplen;
	struct dp_test_s2s_config conf;

	s2s_ipv6_default_conf(&conf, vrfid);

	conf.mode = XFRM_MODE_TUNNEL;
	conf.cipher_algo = CRYPTO_CIPHER_AES_CBC;
	conf.auth_algo = CRYPTO_AUTH_HMAC_SHA1;

	dp_test_s2s_common_setup(&conf);

	/*
	 * Construct oversize packet
	 */
	test_pak = dp_test_create_ipv6_pak(conf.client_local_ip,
					   conf.client_remote_ip, 1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str(conf.iface1),
				 conf.client_local_mac, RTE_ETHER_TYPE_IPV6);

	/*
	 *  Expected ICMP response
	 *  Note that s2s sets MTU based on policy effective block size
	 */
	icmplen = 1280 - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
	icmp_pak = dp_test_create_icmp_ipv6_pak(conf.port_west_ip,
						conf.client_local_ip,
						ICMP6_PACKET_TOO_BIG,
						0, /* code */
						1422, /* mtu */
						1, &icmplen,
						ip6hdr(test_pak),
						&ip6, &icmp6);

	/*
	 * Tweak the expected packet
	 */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       conf.client_local_mac,
				       dp_test_intf_name2mac_str(conf.iface1),
				       RTE_ETHER_TYPE_IPV6);

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(icmp_pak, ip6, icmp6);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, conf.iface1);

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, conf.iface1, exp);

	dp_test_s2s_common_teardown(&conf);
}

static void null_decrypt_main(vrfid_t vrfid, enum inner_validity valid)
{
	struct if_data start_stats_iface1, start_stats_iface2;
	struct if_data stats_iface1, stats_iface2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pkt;
	int payload_len;
	struct dp_test_s2s_config conf;

	s2s_ipv4_default_conf(&conf, vrfid);

	conf.mode = XFRM_MODE_TUNNEL;

	dp_test_s2s_common_setup(&conf);

	/*
	 * Construct the output ICMP ping packet. We need to reduce
	 * ttl by 1 to allow for switching.
	 */
	if (valid == INNER_LOCAL) {
		expected_pkt = build_input_packet(conf.client_remote_ip,
						  conf.port_west_ip);

		dp_test_pktmbuf_eth_init(expected_pkt,
					 dp_test_intf_name2mac_str(conf.iface2),
					 conf.peer_mac,
					 RTE_ETHER_TYPE_IPV4);
	} else {
		expected_pkt = build_input_packet(conf.client_remote_ip,
						  conf.client_local_ip);

		if (valid == INNER_INVALID)
			/* Make the checksum wrong */
			iphdr(expected_pkt)->check++;

		dp_test_pktmbuf_eth_init(expected_pkt, conf.client_local_mac,
					 dp_test_intf_name2mac_str(conf.iface1),
					 RTE_ETHER_TYPE_IPV4);
	}

	/*
	 * Construct the encrypted packet to inject
	 */

	/*
	 * Add padding to make modulo of blocksize for the cipher plus
	 * padding length and next proto
	 */
	char *trailer = rte_pktmbuf_append(expected_pkt, 4);
	trailer[0] = 1;
	trailer[1] = 2;
	trailer[2] = 2 /* padding length */;
	trailer[3] = IPPROTO_IPIP;

	payload_len = ntohs(iphdr(expected_pkt)->tot_len) + 4;
	encrypted_pkt = dp_test_create_esp_ipv4_pak(conf.peer_ip,
						    conf.port_east_ip, 1,
						    &payload_len,
						    (char *)iphdr(expected_pkt),
						    SPI_INBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);

	rte_pktmbuf_trim(expected_pkt, 4);
	if (valid != INNER_LOCAL) {
		dp_test_set_pak_ip_field(iphdr(expected_pkt),
					 DP_TEST_SET_TTL, 0x3f);
	}

	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       dp_test_intf_name2mac_str(conf.iface2),
				       conf.peer_mac,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pkt);
	rte_pktmbuf_free(expected_pkt);
	if (valid == INNER_LOCAL)
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	else if (valid == INNER_INVALID)
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	else
		dp_test_exp_set_oif_name(exp, conf.iface1);

	dp_test_intf_initial_stats_for_if(conf.iface1, &start_stats_iface1);
	dp_test_intf_initial_stats_for_if(conf.iface2, &start_stats_iface2);

	/* transmit the encrypted packet and await the result */
	dp_test_pak_receive(encrypted_pkt, conf.iface2, exp);

	dp_test_intf_delta_stats_for_if(conf.iface1, &start_stats_iface1,
					&stats_iface1);
	dp_test_intf_delta_stats_for_if(conf.iface2, &start_stats_iface2,
					&stats_iface2);

	if (valid == INNER_INVALID) {
		dp_test_crypto_check_sad_packets(conf.vrfid, 0, 0);
	} else {
		dp_test_crypto_check_sad_packets(conf.vrfid, 1, 84);
	}

	dp_test_assert_internal(stats_iface1.ifi_ipackets == 0);
	dp_test_assert_internal(stats_iface1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_idropped == 0);
	if (valid == INNER_INVALID || valid == INNER_LOCAL)
		dp_test_assert_internal(stats_iface1.ifi_opackets == 0);
	else
		dp_test_assert_internal(stats_iface1.ifi_opackets == 1);
	dp_test_assert_internal(ifi_odropped(&stats_iface1) == 0);
	dp_test_assert_internal(stats_iface2.ifi_ipackets == 1);
	dp_test_assert_internal(stats_iface2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_opackets == 0);
	dp_test_assert_internal(stats_iface2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_iface2) == 0);

	dp_test_s2s_common_teardown(&conf);
}

static void null_decrypt_main6(vrfid_t vrfid, enum inner_validity valid)
{
	struct if_data start_stats_iface1, start_stats_iface2;
	struct if_data stats_iface1, stats_iface2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pkt;
	int payload_len;
	struct dp_test_s2s_config conf;

	s2s_ipv6_default_conf(&conf, vrfid);

	conf.mode = XFRM_MODE_TUNNEL;

	dp_test_s2s_common_setup(&conf);

	if (valid == INNER_LOCAL) {
		expected_pkt = build_input_packet6(conf.client_remote_ip,
						   conf.port_west_ip);

		dp_test_pktmbuf_eth_init(expected_pkt,
					 dp_test_intf_name2mac_str(conf.iface2),
					 conf.peer_mac,
					 RTE_ETHER_TYPE_IPV6);
	} else {
		/*
		 * Construct the output ICMP ping packet. We need to reduce
		 * ttl by 1 to allow for switching.
		 */
		expected_pkt = build_input_packet6(conf.client_remote_ip,
						   conf.client_local_ip);

		dp_test_pktmbuf_eth_init(expected_pkt,
					 conf.client_local_mac,
					 dp_test_intf_name2mac_str(conf.iface1),
					 RTE_ETHER_TYPE_IPV6);
	}

	/*
	 * Construct the encrypted packet to inject
	 */

	/*
	 * Add padding to make modulo of blocksize for the cipher plus
	 * padding length and next proto
	 */
	char *trailer = rte_pktmbuf_append(expected_pkt, 8);
	trailer[0] = 1;
	trailer[1] = 2;
	trailer[2] = 3;
	trailer[3] = 4;
	trailer[4] = 5;
	trailer[5] = 6;
	trailer[6] = 6 /* padding length */;
	trailer[7] = IPPROTO_IPV6;

	payload_len = ntohs(ip6hdr(expected_pkt)->ip6_plen) +
		sizeof(struct ip6_hdr) + 8;

	if (valid == INNER_INVALID)
		/* Make the length longer than the mbuf length */
		ip6hdr(expected_pkt)->ip6_plen = htons(0xff00);

	encrypted_pkt = dp_test_create_esp_ipv6_pak(
		conf.peer_ip, conf.port_east_ip, 1, &payload_len,
		(char *)ip6hdr(expected_pkt),
		SPI_INBOUND, 1 /* seq no */, 0 /* ip ID */,
		255 /* ttl */, NULL /* transport_hdr*/);
	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       dp_test_intf_name2mac_str(conf.iface2),
				       conf.peer_mac,
				       RTE_ETHER_TYPE_IPV6);

	rte_pktmbuf_trim(expected_pkt, 8);
	if (valid != INNER_LOCAL)
		dp_test_ipv6_decrement_ttl(expected_pkt);

	exp = dp_test_exp_create(expected_pkt);
	rte_pktmbuf_free(expected_pkt);
	if (valid == INNER_LOCAL)
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	else if (valid == INNER_INVALID)
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	else
		dp_test_exp_set_oif_name(exp, conf.iface1);

	dp_test_intf_initial_stats_for_if(conf.iface1, &start_stats_iface1);
	dp_test_intf_initial_stats_for_if(conf.iface2, &start_stats_iface2);

	/* transmit the encrypted packet and await the result */
	dp_test_pak_receive(encrypted_pkt, conf.iface2, exp);

	dp_test_intf_delta_stats_for_if(conf.iface1, &start_stats_iface1,
					&stats_iface1);
	dp_test_intf_delta_stats_for_if(conf.iface2, &start_stats_iface2,
					&stats_iface2);

	if (valid == INNER_INVALID || valid == INNER_LOCAL)
		dp_test_crypto_check_sad_packets(conf.vrfid, 0, 0);
	else
		dp_test_crypto_check_sad_packets(conf.vrfid, 1, 104);

	dp_test_assert_internal(stats_iface1.ifi_ipackets == 0);
	dp_test_assert_internal(stats_iface1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface1.ifi_idropped == 0);
	if (valid == INNER_INVALID || valid == INNER_LOCAL)
		dp_test_assert_internal(stats_iface1.ifi_opackets == 0);
	else
		dp_test_assert_internal(stats_iface1.ifi_opackets == 1);

	dp_test_assert_internal(ifi_odropped(&stats_iface1) == 0);

	dp_test_assert_internal(stats_iface2.ifi_ipackets == 1);
	dp_test_assert_internal(stats_iface2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_opackets == 0);
	dp_test_assert_internal(stats_iface2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_iface2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_iface2) == 0);

	dp_test_s2s_common_teardown(&conf);
}

static void
test_plaintext_packet_matching_input_policy(struct dp_test_s2s_config *conf,
					    const char *ifout,
					    const char *ifin,
					    struct if_data *exp_stats_ifout,
					    struct if_data *exp_stats_ifin,
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
	uint16_t ether_type;

	conf->mode = XFRM_MODE_TUNNEL;
	conf->cipher_algo = CRYPTO_CIPHER_AES_CBC;
	conf->auth_algo = CRYPTO_AUTH_HMAC_SHA1;

	dp_test_s2s_common_setup(conf);

	if (conf->af == AF_INET6) {
		pkt = dp_test_create_udp_ipv6_pak(saddr, daddr, udp_port,
						  udp_port, 1, &len);
		ether_type = RTE_ETHER_TYPE_IPV6;
	} else {
		pkt = dp_test_create_udp_ipv4_pak(saddr, daddr, udp_port,
						  udp_port, 1, &len);
		ether_type = RTE_ETHER_TYPE_IPV4;
	}
	(void)dp_test_pktmbuf_eth_init(pkt,
				       dp_test_intf_name2mac_str(ifin),
				       NULL, ether_type);

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
		if (conf->af == AF_INET6)
			exp = generate_exp_unreachable6(pkt, len,
							conf->port_east_ip,
							saddr, ifin,
							conf->peer_mac);
		else
			exp = generate_exp_unreachable(pkt, len,
						       conf->port_east_ip,
						       saddr, ifin,
						       conf->peer_mac);
	}

	dp_test_intf_initial_stats_for_if(ifout, &start_stats_ifout);
	dp_test_intf_initial_stats_for_if(ifin, &start_stats_ifin);

	dis = dp_test_get_vrf_stat(conf->vrfid,
				   conf->af, IPSTATS_MIB_INNOROUTES);
	del = dp_test_get_vrf_stat(conf->vrfid,
				   conf->af, IPSTATS_MIB_INDELIVERS);
	inp = dp_test_get_vrf_stat(conf->vrfid, conf->af, IPSTATS_MIB_INPKTS);

	dp_test_pak_receive(pkt, ifin, exp);

	dp_test_crypto_check_sad_packets(conf->vrfid, 0, 0);

	dp_test_intf_delta_stats_for_if(ifout, &start_stats_ifout,
					&stats_ifout);
	dp_test_intf_delta_stats_for_if(ifin, &start_stats_ifin,
					&stats_ifin);

	dp_test_validate_if_stats(&stats_ifout, exp_stats_ifout);
	dp_test_validate_if_stats(&stats_ifin, exp_stats_ifin);
	dis2 = dp_test_get_vrf_stat(conf->vrfid, conf->af,
				    IPSTATS_MIB_INNOROUTES);
	del2 = dp_test_get_vrf_stat(conf->vrfid, conf->af,
				    IPSTATS_MIB_INDELIVERS);
	inp2 = dp_test_get_vrf_stat(conf->vrfid, conf->af,
				    IPSTATS_MIB_INPKTS);
	dp_test_verify_vrf_stats(inp, inp2, dis, dis2, del, del2, exp_status);

	dp_test_s2s_common_teardown(conf);
}

static void drop_plaintext_packet_matching_input_policy_main(int af,
							     vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};
	struct dp_test_s2s_config conf;

	if (af == AF_INET6)
		s2s_ipv6_default_conf(&conf, vrfid);
	else
		s2s_ipv4_default_conf(&conf, vrfid);

	exp_stats_ifin.ifi_ipackets = 1;
	exp_stats_ifin.ifi_opackets = 1;

	test_plaintext_packet_matching_input_policy(&conf,
						    conf.iface1,
						    conf.iface2,
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    conf.client_remote_ip,
						    conf.client_local_ip,
						    0,
						    DP_TEST_FWD_DROPPED);
}

static void drop_plaintext_local_pkt_match_inpolicy(int af, vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};
	struct dp_test_s2s_config conf;

	exp_stats_ifin.ifi_ipackets = 1;
	exp_stats_ifin.ifi_opackets = 1;
	exp_stats_ifin.ifi_idropped = 0;

	if (af == AF_INET6)
		s2s_ipv6_default_conf(&conf, vrfid);
	else
		s2s_ipv4_default_conf(&conf, vrfid);

	conf.ipolicy[0].proto = IPPROTO_UDP;
	conf.ipolicy[0].s_prefix = conf.network_remote_ip_with_mask;
	conf.ipolicy[0].d_prefix = conf.network_east_ip_with_mask;

	conf.opolicy[0].proto = IPPROTO_UDP;
	conf.opolicy[0].s_prefix = conf.network_east_ip_with_mask;
	conf.opolicy[0].d_prefix = conf.network_remote_ip_with_mask;

	test_plaintext_packet_matching_input_policy(&conf,
						    conf.iface1,
						    conf.iface2,
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    conf.client_remote_ip,
						    conf.port_east_ip,
						    0,
						    DP_TEST_FWD_DROPPED);

	/*
	 * UDP port 500 (IKE) is a special case as we must not drop
	 * these terminating packets.
	 */
	exp_stats_ifin.ifi_idropped = 0;
	exp_stats_ifin.ifi_opackets = 0;
	test_plaintext_packet_matching_input_policy(&conf,
						    conf.iface1,
						    conf.iface2,
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    conf.client_remote_ip,
						    conf.port_east_ip,
						    500, /* IKE port */
						    DP_TEST_FWD_LOCAL);
}

static void rx_plaintext_local_pkt_notmatch_inpolicy(int af, vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};
	struct dp_test_s2s_config conf;

	exp_stats_ifin.ifi_ipackets = 1;

	if (af == AF_INET6)
		s2s_ipv4_default_conf(&conf, vrfid);
	else
		s2s_ipv6_default_conf(&conf, vrfid);

	/* Any proto but ICMP to ensure we don't match policy */

	conf.ipolicy[0].proto = IPPROTO_TCP;
	conf.ipolicy[0].s_prefix = conf.network_remote_ip_with_mask;
	conf.ipolicy[0].d_prefix = conf.network_local_ip_with_mask;

	conf.opolicy[0].proto = IPPROTO_TCP;
	conf.opolicy[0].s_prefix = conf.network_local_ip_with_mask;
	conf.opolicy[0].d_prefix = conf.network_remote_ip_with_mask;

	test_plaintext_packet_matching_input_policy(&conf,
						    conf.iface2,
						    conf.iface1,
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    conf.client_remote_ip,
						    conf.port_west_ip,
						    0,
						    DP_TEST_FWD_LOCAL);
}

static void rx_match_policy_proto(int af, vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};
	struct dp_test_s2s_config conf;

	exp_stats_ifin.ifi_ipackets = 1;

	if (af == AF_INET6)
		s2s_ipv6_default_conf(&conf, vrfid);
	else
		s2s_ipv4_default_conf(&conf, vrfid);

	/*
	 * Add multiple policies to verify that we don't wrongly
	 * match a policy with the wrong protocol.
	 */
	struct dp_test_crypto_policy my_ipol[3] = {
		{
		.d_prefix = conf.network_local_ip_with_mask,
		.s_prefix = conf.network_remote_ip_with_mask,
		.proto = IPPROTO_UDP - 1,
		.dst = conf.port_east_ip,
		.dst_family = conf.af,
		.dir = XFRM_POLICY_IN,
		.family = conf.af,
		.reqid = TUNNEL_REQID,
		.priority = RULE_PRIORITY,
		.rule_no = 1,
		.mark = 0,
		.vrfid = VRF_DEFAULT_ID,
		.action = XFRM_POLICY_BLOCK,
		},
		{
		.d_prefix = conf.network_local_ip_with_mask,
		.s_prefix = conf.network_remote_ip_with_mask,
		.proto = IPPROTO_UDP,
		.dst = conf.port_east_ip,
		.dst_family = conf.af,
		.dir = XFRM_POLICY_IN,
		.family = conf.af,
		.reqid = TUNNEL_REQID,
		.priority = RULE_PRIORITY,
		.rule_no = 2,
		.mark = 0,
		.vrfid = VRF_DEFAULT_ID,
		.action = XFRM_POLICY_ALLOW,
		.passthrough = true
		},
		{
		.d_prefix = conf.network_local_ip_with_mask,
		.s_prefix = conf.network_remote_ip_with_mask,
		.proto = IPPROTO_UDP + 1,
		.dst = conf.port_east_ip,
		.dst_family = conf.af,
		.dir = XFRM_POLICY_IN,
		.family = conf.af,
		.reqid = TUNNEL_REQID,
		.priority = RULE_PRIORITY,
		.rule_no = 3,
		.mark = 0,
		.vrfid = VRF_DEFAULT_ID,
		.action = XFRM_POLICY_BLOCK,
		},
	};
	conf.ipolicy = my_ipol;
	conf.nipols = 3;

	conf.opolicy[0].proto = IPPROTO_TCP;
	conf.opolicy[0].s_prefix = conf.network_local_ip_with_mask;
	conf.opolicy[0].d_prefix = conf.network_remote_ip_with_mask;

	test_plaintext_packet_matching_input_policy(&conf,
						    conf.iface2,
						    conf.iface1,
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    conf.client_remote_ip,
						    conf.port_west_ip,
						    0,
						    DP_TEST_FWD_LOCAL);
}

DP_DECL_TEST_SUITE(site_to_site_suite);

DP_DECL_TEST_CASE(site_to_site_suite, encryption, NULL, NULL);

/*
 * can we encrypt a packet?
 *
 */
/*
 * TEST: null_encrypt_transport
 *
 * "encrypt" a packet using null encryption and null authentication
 * in transport mode.
 */
DP_START_TEST_FULL_RUN(encryption, null_encrypt_transport)
{
	null_encrypt_transport_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt_transport_vrf)
{
	null_encrypt_transport_main(TEST_VRF);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt_aesgcm)
{
	encrypt_aesgcm_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt_aesgcm_vrf)
{
	encrypt_aesgcm_main(TEST_VRF);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt)
{
	encrypt_main(VRF_DEFAULT_ID, VRF_XFRM_IN_ORDER);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt_vrf)
{
	encrypt_main(TEST_VRF, VRF_XFRM_IN_ORDER);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt_vrf_out_of_order)
{
	encrypt_main(TEST_VRF, VRF_XFRM_OUT_OF_ORDER);
}  DP_END_TEST;

DP_START_TEST(encryption, encrypt6)
{
	encrypt6_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt6_vrf)
{
	encrypt6_main(TEST_VRF);
}  DP_END_TEST;

/* test that an SA with an unrecognised algorithm will block traffic */
DP_START_TEST_FULL_RUN(encryption, bad_hash_algorithm)
{
	bad_hash_algorithm_main(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, bad_hash_algorithm_vrf)
{
	bad_hash_algorithm_main(TEST_VRF);
} DP_END_TEST;

/* test that an SA with an unrecognised algorithm will block traffic */
DP_START_TEST_FULL_RUN(encryption, bad_hash_algorithm6)
{
	bad_hash_algorithm6_main(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, bad_hash_algorithm6_vrf)
{
	bad_hash_algorithm6_main(TEST_VRF);
} DP_END_TEST;

/*
 * TEST: null_encrypt
 *
 * "encrypt" a packet using null encryption and null authentication.
 */
DP_START_TEST_FULL_RUN(encryption, null_encrypt)
{
	null_encrypt_main(VRF_DEFAULT_ID, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt_vfp)
{
	null_encrypt_main(VRF_DEFAULT_ID, VFP_TRUE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt_vrf)
{
	null_encrypt_main(TEST_VRF, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6_transport)
{
	null_encrypt6_transport_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6_transport_vrf)
{
	null_encrypt6_transport_main(TEST_VRF);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6)
{
	null_encrypt6_main(VRF_DEFAULT_ID, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6_vfp)
{
	null_encrypt6_main(VRF_DEFAULT_ID, VFP_TRUE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6_vrf)
{
	null_encrypt6_main(TEST_VRF, VFP_FALSE);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, s2s_toobig6, NULL, NULL);

DP_START_TEST_FULL_RUN(s2s_toobig6, s2s_toobig6)
{
	s2s_toobig6_main(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(s2s_toobig6, s2s_toobig6_vrf)
{
	s2s_toobig6_main(TEST_VRF);
} DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, decryption, NULL, NULL);

DP_START_TEST_FULL_RUN(decryption, decrypt_null)
{
	null_decrypt_main(VRF_DEFAULT_ID, INNER_VALID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, decrypt_null_invalid)
{
	null_decrypt_main(VRF_DEFAULT_ID, INNER_INVALID);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, decryption_local, NULL, NULL);

DP_START_TEST_FULL_RUN(decryption_local, decrypt_null_local)
{
	null_decrypt_main(VRF_DEFAULT_ID, INNER_LOCAL);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, decrypt_null_vrf)
{
	null_decrypt_main(TEST_VRF, INNER_VALID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, decrypt_null6)
{
	null_decrypt_main6(VRF_DEFAULT_ID, INNER_VALID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, decrypt_null_invalid6)
{
	null_decrypt_main6(VRF_DEFAULT_ID, INNER_INVALID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption_local, decrypt_null_local6)
{
	null_decrypt_main6(VRF_DEFAULT_ID, INNER_LOCAL);
}  DP_END_TEST;

/*
 * if a packet matches an input policy, then it must be ESP. If it is
 * plaintext, then it might be a spoof and must be dropped with
 * prejudice.
 */
DP_START_TEST_FULL_RUN(decryption, drop_plaintext_packet_matching_input_policy)
{
	drop_plaintext_packet_matching_input_policy_main(AF_INET,
							 VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, drop_plaintext_local_pkt_match_inpolicy)
{
	drop_plaintext_local_pkt_match_inpolicy(AF_INET, VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, rx_plaintext_local_pkt_notmatch_inpolicy)
{
	rx_plaintext_local_pkt_notmatch_inpolicy(AF_INET, VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, rx_match_policy_proto)
{
	rx_match_policy_proto(AF_INET, VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, rx_match_policy_proto_vrf)
{
	rx_match_policy_proto(AF_INET, TEST_VRF);
} DP_END_TEST;

DP_START_TEST(decryption, rx_match_policy_proto6)
{
	rx_match_policy_proto(AF_INET6, VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(decryption, rx_match_policy_proto6_vrf)
{
	rx_match_policy_proto(AF_INET6, TEST_VRF);
} DP_END_TEST;

/*
 * This test no longer works with overlay vrf support with the underlay in
 * default because the following happens.
 * Packet arrives unencrypted, but the dest address (10.10.1.1) is in the
 * TEST_VRF, not the default, so the route lookup does not find it. There is
 * no route, so an icmp is sent.
 *
 * I don't see a good way to detect that the packet should have been encrypted
 * as we would have to check all policies that have the transport in this vrf.
 * At the moment the check is once we have decided it is local, but we can not
 * even use that as the trigger. So, lets leave this test out.
 */
DP_START_TEST_DONT_RUN(decryption,
		       drop_plaintext_packet_matching_input_policy_vrf)
{
	drop_plaintext_packet_matching_input_policy_main(AF_INET, TEST_VRF);
} DP_END_TEST;

/*
 * This test no longer works with overlay vrf support with the underlay in
 * default because the following happens.
 * Packet arrives unencrypted, but the dest address (10.10.1.1) is in the
 * TEST_VRF, not the default, so the route lookup does not find it. There is
 * no route, so an icmp is sent.
 *
 * I don't see a good way to detect that the packet should have been encrypted
 * as we would have to check all policies that have the transport in this vrf.
 * At the moment the check is once we have decided it is local, but we can not
 * even use that as the trigger. So, lets leave this test out.
 */
DP_START_TEST_DONT_RUN(decryption,
		       drop_plaintext_local_pkt_match_inpolicy_vrf)
{
	drop_plaintext_local_pkt_match_inpolicy(AF_INET, TEST_VRF);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, rx_plaintext_local_pkt_notmatch_inpolicy_vrf)
{
	rx_plaintext_local_pkt_notmatch_inpolicy(AF_INET, TEST_VRF);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, drop_plaintext_packet_matching_input_policy6)
{
	drop_plaintext_packet_matching_input_policy_main(AF_INET6,
							 VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, drop_plaintext_local_pkt_match_inpolicy6)
{
	drop_plaintext_local_pkt_match_inpolicy(AF_INET6, VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, rx_plaintext_local_pkt_notmatch_inpolicy6)
{
	rx_plaintext_local_pkt_notmatch_inpolicy(AF_INET6, VRF_DEFAULT_ID);
} DP_END_TEST;

/*
 * This test no longer works with overlay vrf support with the underlay in
 * default because the following happens.
 * Packet arrives unencrypted, but the dest address  is in the
 * TEST_VRF, not the default, so the route lookup does not find it. There is
 * no route, so an icmp is sent.
 *
 * I don't see a good way to detect that the packet should have been encrypted
 * as we would have to check all policies that have the transport in this vrf.
 * At the moment the check is once we have decided it is local, but we can not
 * even use that as the trigger. So, lets leave this test out.
 */
DP_START_TEST_DONT_RUN(decryption,
		       drop_plaintext_packet_matching_input_policy6_vrf)
{
	drop_plaintext_packet_matching_input_policy_main(AF_INET6, TEST_VRF);
} DP_END_TEST;

/*
 * This test no longer works with overlay vrf support with the underlay in
 * default because the following happens.
 * Packet arrives unencrypted, but the dest address is in the
 * TEST_VRF, not the default, so the route lookup does not find it. There is
 * no route, so an icmp is sent.
 *
 * I don't see a good way to detect that the packet should have been encrypted
 * as we would have to check all policies that have the transport in this vrf.
 * At the moment the check is once we have decided it is local, but we can not
 * even use that as the trigger. So, lets leave this test out.
 */
DP_START_TEST_DONT_RUN(decryption,
		       drop_plaintext_local_pkt_match_inpolicy6_vrf)
{
	drop_plaintext_local_pkt_match_inpolicy(AF_INET6, TEST_VRF);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption,
		       rx_plaintext_local_pkt_notmatch_inpolicy6_vrf)
{
	rx_plaintext_local_pkt_notmatch_inpolicy(AF_INET6, TEST_VRF);
} DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, encryption46, NULL, NULL);

static void encrypt46_test(vrfid_t vrfid, uint8_t in_tos, uint8_t exp_tos,
			   uint32_t sa_flags, uint32_t sa_extra_flags)
{
	char expected_payload[sizeof(payload_v4_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	struct dp_test_s2s_config v4_conf;
	struct dp_test_s2s_config v6_conf;

	memcpy(expected_payload, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));

	s2s_ipv4_default_conf(&v4_conf, vrfid);
	s2s_ipv6_default_conf(&v6_conf, vrfid);

	/* input == decrypt, so the dst_family is actually the arrival one */
	v4_conf.ipolicy[0].family = v6_conf.ipolicy[0].family;
	v4_conf.ipolicy[0].d_prefix = v6_conf.ipolicy[0].d_prefix;
	v4_conf.ipolicy[0].s_prefix = v6_conf.ipolicy[0].s_prefix;
	v4_conf.ipolicy[0].rule_no = 8;

	v4_conf.opolicy[0].dst = v6_conf.opolicy[0].dst;
	v4_conf.opolicy[0].dst_family = v6_conf.opolicy[0].dst_family;
	v4_conf.opolicy[0].rule_no = 3;

	v4_conf.mode = XFRM_MODE_TUNNEL;

	v4_conf.input_sa.family = v6_conf.input_sa.family;
	v4_conf.input_sa.d_addr = v6_conf.input_sa.d_addr;
	v4_conf.input_sa.s_addr = v6_conf.input_sa.s_addr;
	v4_conf.input_sa.flags = sa_flags;
	v4_conf.input_sa.extra_flags = sa_extra_flags;

	v4_conf.output_sa.family = v6_conf.output_sa.family;
	v4_conf.output_sa.d_addr = v6_conf.output_sa.d_addr;
	v4_conf.output_sa.s_addr = v6_conf.output_sa.s_addr;
	v4_conf.output_sa.spi = v6_conf.output_sa.spi;
	v4_conf.output_sa.flags = sa_flags;
	v4_conf.output_sa.extra_flags = sa_extra_flags;

	dp_test_s2s_setup_interfaces(&v4_conf);
	dp_test_s2s_setup_interfaces(&v6_conf);
	setup_policies(&v4_conf);
	setup_sas(&v4_conf);

	v4_conf.input_sa.flags = 0;
	v4_conf.input_sa.extra_flags = 0;
	v4_conf.output_sa.flags = 0;
	v4_conf.output_sa.extra_flags = 0;

	build_pak_and_expected_encrypt(&ping_pkt, &exp, v4_conf.iface1,
				       v4_conf.iface2, v4_conf.client_local_ip,
				       v4_conf.client_remote_ip,
				       v6_conf.port_east_ip, v6_conf.peer_ip,
				       v4_conf.peer_mac, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, v4_conf.iface1, exp);
	dp_test_crypto_check_sad_packets(v4_conf.vrfid, 1, 84);

	teardown_sas(&v4_conf);
	teardown_policies(&v4_conf);
	if (v4_conf.vrfid == VRF_DEFAULT_ID)
		dp_test_s2s_teardown_interfaces(&v4_conf);
	else
		dp_test_s2s_teardown_interfaces_leave_vrf(&v4_conf);
	dp_test_s2s_teardown_interfaces(&v6_conf);
}

DP_START_TEST_FULL_RUN(encryption46, encrypt46_tunnel)
{
	encrypt46_test(VRF_DEFAULT_ID, 0 /* in TOS */, 0 /* expected TOS */,
		       0 /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_ecn_ect)
{
	encrypt46_test(VRF_DEFAULT_ID, 1 /* in TOS */, 1 /* expected TOS */,
		       0 /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_ecn_ce)
{
	encrypt46_test(VRF_DEFAULT_ID, 3 /* in TOS */, 2 /* expected TOS */,
		       0 /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_no_ecn)
{
	encrypt46_test(VRF_DEFAULT_ID, 7 /* in TOS */, 4 /* expected TOS */,
		       XFRM_STATE_NOECN /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

/* ecn3 is modified to ecn2, and dscp 1 is dropped */
DP_START_TEST_FULL_RUN(encryption46, encrypt46_no_dscp)
{
	encrypt46_test(VRF_DEFAULT_ID, 7 /* in TOS */, 2 /* expected TOS */,
		       0 /* SA flags */,
		       XFRM_SA_XFLAG_DONT_ENCAP_DSCP /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_no_dscp_no_ecn)
{
	encrypt46_test(VRF_DEFAULT_ID, 7 /* in TOS */, 0 /* expected TOS */,
		       XFRM_STATE_NOECN /* SA flags */,
		       XFRM_SA_XFLAG_DONT_ENCAP_DSCP /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_tunnel_test_vrf)
{
	encrypt46_test(TEST_VRF, 4 /* in TOS */, 4 /* expected TOS */,
		       0 /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, encryption64, NULL, NULL);

static void encrypt64_test(vrfid_t vrfid, uint8_t in_tos, uint8_t exp_tos,
			   uint32_t sa_flags, uint32_t sa_extra_flags)
{
	char expected_payload[sizeof(payload_v6_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	struct dp_test_s2s_config v4_conf;
	struct dp_test_s2s_config v6_conf;

	memcpy(expected_payload, payload_v6_icmp_null_enc,
	       sizeof(payload_v6_icmp_null_enc));

	s2s_ipv4_default_conf(&v4_conf, vrfid);
	s2s_ipv6_default_conf(&v6_conf, vrfid);

	/* input == decrypt, so the dst_family is actually the arrival one */
	v6_conf.ipolicy[0].family = v4_conf.ipolicy[0].family;
	v6_conf.ipolicy[0].d_prefix = v4_conf.ipolicy[0].d_prefix;
	v6_conf.ipolicy[0].s_prefix = v4_conf.ipolicy[0].s_prefix;
	v6_conf.ipolicy[0].rule_no = 7;

	v6_conf.opolicy[0].dst = v4_conf.opolicy[0].dst;
	v6_conf.opolicy[0].dst_family = v4_conf.opolicy[0].dst_family;
	v6_conf.opolicy[0].rule_no = 4;

	v6_conf.mode = XFRM_MODE_TUNNEL;

	v6_conf.input_sa.family = v4_conf.input_sa.family;
	v6_conf.input_sa.d_addr = v4_conf.input_sa.d_addr;
	v6_conf.input_sa.s_addr = v4_conf.input_sa.s_addr;
	v6_conf.input_sa.flags = sa_flags;
	v6_conf.input_sa.extra_flags = sa_extra_flags;

	v6_conf.output_sa.family = v4_conf.output_sa.family;
	v6_conf.output_sa.d_addr = v4_conf.output_sa.d_addr;
	v6_conf.output_sa.s_addr = v4_conf.output_sa.s_addr;
	v6_conf.output_sa.spi = v4_conf.output_sa.spi;
	v6_conf.output_sa.flags = sa_flags;
	v6_conf.output_sa.extra_flags = sa_extra_flags;

	dp_test_s2s_setup_interfaces(&v4_conf);
	dp_test_s2s_setup_interfaces(&v6_conf);
	setup_policies(&v6_conf);
	setup_sas(&v6_conf);

	v6_conf.input_sa.flags = 0;
	v6_conf.input_sa.extra_flags = 0;
	v6_conf.output_sa.flags = 0;
	v6_conf.output_sa.extra_flags = 0;

	build_pak_and_expected_encrypt(&ping_pkt, &exp, v6_conf.iface1,
				       v6_conf.iface2, v6_conf.client_local_ip,
				       v6_conf.client_remote_ip,
				       v4_conf.port_east_ip, v4_conf.peer_ip,
				       v6_conf.peer_mac, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, v6_conf.iface1, exp);
	dp_test_crypto_check_sad_packets(v6_conf.vrfid, 1, 104);

	teardown_sas(&v6_conf);
	teardown_policies(&v6_conf);
	if (v4_conf.vrfid == VRF_DEFAULT_ID)
		dp_test_s2s_teardown_interfaces(&v4_conf);
	else
		dp_test_s2s_teardown_interfaces_leave_vrf(&v4_conf);
	dp_test_s2s_teardown_interfaces(&v6_conf);
}

DP_START_TEST_FULL_RUN(encryption64, encrypt64)
{
	encrypt64_test(VRF_DEFAULT_ID, 0 /* in TOS */, 0 /* expected TOS */,
		       0 /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_ecn_ect)
{
	encrypt64_test(VRF_DEFAULT_ID, 1 /* in TOS */, 1 /* expected TOS */,
		       0 /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_ecn_ce)
{
	encrypt64_test(VRF_DEFAULT_ID, 3 /* in TOS */, 2 /* expected TOS */,
		       0 /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_no_ecn)
{
	encrypt64_test(VRF_DEFAULT_ID, 7 /* in TOS */, 4 /* expected TOS */,
		       XFRM_STATE_NOECN /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

/* ecn3 is modified to ecn2, and dscp 1 is dropped */
DP_START_TEST_FULL_RUN(encryption64, encrypt64_no_dscp)
{
	encrypt64_test(VRF_DEFAULT_ID, 7 /* in TOS */, 2 /* expected TOS */,
		       0 /* SA flags */,
		       XFRM_SA_XFLAG_DONT_ENCAP_DSCP /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_no_dscp_no_ecn)
{
	encrypt64_test(VRF_DEFAULT_ID, 7 /* in TOS */, 0 /* expected TOS */,
		       XFRM_STATE_NOECN /* SA flags */,
		       XFRM_SA_XFLAG_DONT_ENCAP_DSCP /* SA extra flags */);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_tunnel_test_vrf)
{
	encrypt64_test(TEST_VRF, 4 /* in TOS */, 4 /* expected TOS */,
		       0 /* SA flags */, 0 /* SA extra flags */);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, decryption64, NULL, NULL);

static void decrypt64_test(vrfid_t vrfid)
{
	char transmit_payload[sizeof(payload_v4_icmp_null_enc_rem_to_loc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_s2s_config v4_conf;
	struct dp_test_s2s_config v6_conf;

	memcpy(transmit_payload, payload_v4_icmp_null_enc_rem_to_loc,
	       sizeof(payload_v4_icmp_null_enc_rem_to_loc));

	s2s_ipv4_default_conf(&v4_conf, vrfid);
	s2s_ipv6_default_conf(&v6_conf, vrfid);

	/* input == decrypt, so the dst_family is actually the arrival one */
	v6_conf.ipolicy[0].family = v4_conf.ipolicy[0].family;
	v6_conf.ipolicy[0].d_prefix = v4_conf.ipolicy[0].d_prefix;
	v6_conf.ipolicy[0].s_prefix = v4_conf.ipolicy[0].s_prefix;
	v6_conf.ipolicy[0].rule_no = 7;

	v6_conf.opolicy[0].dst = v4_conf.opolicy[0].dst;
	v6_conf.opolicy[0].dst_family = v4_conf.opolicy[0].dst_family;
	v6_conf.opolicy[0].rule_no = 4;

	v6_conf.mode = XFRM_MODE_TUNNEL;

	dp_test_s2s_setup_interfaces(&v4_conf);
	dp_test_s2s_setup_interfaces(&v6_conf);
	setup_policies(&v6_conf);
	setup_sas(&v6_conf);

	build_pak_and_expected_decrypt(&encrypted_pkt, &exp, v6_conf.iface2,
				       v6_conf.iface1, v4_conf.client_remote_ip,
				       v4_conf.client_local_ip,
				       v6_conf.peer_ip, v6_conf.port_east_ip,
				       v6_conf.client_local_mac,
				       v6_conf.peer_mac,
				       transmit_payload,
				       sizeof(transmit_payload),
				       VRF_DEFAULT_ID);

	/* transmit the ping and await the result */
	dp_test_pak_receive(encrypted_pkt, v6_conf.iface2, exp);
	dp_test_crypto_check_sad_packets(v6_conf.vrfid, 1, 84);

	teardown_sas(&v6_conf);
	teardown_policies(&v6_conf);
	if (v4_conf.vrfid == VRF_DEFAULT_ID)
		dp_test_s2s_teardown_interfaces(&v4_conf);
	else
		dp_test_s2s_teardown_interfaces_leave_vrf(&v4_conf);
	dp_test_s2s_teardown_interfaces(&v6_conf);
}

DP_START_TEST_FULL_RUN(decryption64, decrypt64_tunnel)
{
	decrypt64_test(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption64, decrypt64_tunnel_test_vrf)
{
	decrypt64_test(TEST_VRF);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, decryption46, NULL, NULL);

static void decrypt46_test(vrfid_t vrfid)
{
	char transmit_payload[sizeof(payload_v6_icmp_null_enc_rem_to_loc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_s2s_config v4_conf;
	struct dp_test_s2s_config v6_conf;

	memcpy(transmit_payload, payload_v6_icmp_null_enc_rem_to_loc,
	       sizeof(payload_v6_icmp_null_enc_rem_to_loc));

	s2s_ipv4_default_conf(&v4_conf, vrfid);
	s2s_ipv6_default_conf(&v6_conf, vrfid);

	/* input == decrypt, so the dst_family is actually the arrival one */
	v4_conf.ipolicy[0].family = v6_conf.ipolicy[0].family;
	v4_conf.ipolicy[0].d_prefix = v6_conf.ipolicy[0].d_prefix;
	v4_conf.ipolicy[0].s_prefix = v6_conf.ipolicy[0].s_prefix;
	v4_conf.ipolicy[0].rule_no = 8;

	v4_conf.opolicy[0].dst = v6_conf.opolicy[0].dst;
	v4_conf.opolicy[0].dst_family = v6_conf.opolicy[0].dst_family;
	v4_conf.opolicy[0].rule_no = 3;

	v4_conf.mode = XFRM_MODE_TUNNEL;

	dp_test_s2s_setup_interfaces(&v4_conf);
	dp_test_s2s_setup_interfaces(&v6_conf);
	setup_policies(&v4_conf);
	setup_sas(&v4_conf);

	build_pak_and_expected_decrypt(&encrypted_pkt, &exp, v4_conf.iface2,
				       v4_conf.iface1, v6_conf.client_remote_ip,
				       v6_conf.client_local_ip,
				       v4_conf.peer_ip, v4_conf.port_east_ip,
				       v4_conf.client_local_mac,
				       v4_conf.peer_mac,
				       transmit_payload,
				       sizeof(transmit_payload),
				       VRF_DEFAULT_ID);

	/* transmit the ping and await the result */
	dp_test_pak_receive(encrypted_pkt, v4_conf.iface2, exp);
	dp_test_crypto_check_sad_packets(v4_conf.vrfid, 1, 104);

	teardown_sas(&v4_conf);
	teardown_policies(&v4_conf);
	if (v4_conf.vrfid == VRF_DEFAULT_ID)
		dp_test_s2s_teardown_interfaces(&v4_conf);
	else
		dp_test_s2s_teardown_interfaces_leave_vrf(&v4_conf);
	dp_test_s2s_teardown_interfaces(&v6_conf);
}

DP_START_TEST_FULL_RUN(decryption46, decrypt46_tunnel)
{
	decrypt46_test(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption46, decrypt46_tunnel_test_vrf)
{
	decrypt46_test(TEST_VRF);
}  DP_END_TEST;
