/*-
 * Copyright (c) 2019-2021, AT&T Intellectual Property. All rights reserved.
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

#define SPI_OUTBOUND	0xd43d87c7
#define SPI_OUTBOUND6	0x89752ac5
#define SPI_INBOUND	0x10
#define TUNNEL_REQID	1234
#define TEST_VRF	42
#define NORMAL_PRI	1000
#define PASS_THRU_PRI	3000

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
	conf->ipolicy->priority = NORMAL_PRI;
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
	conf->opolicy->priority = NORMAL_PRI;
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

	conf->iface1_ip_with_mask = "10.10.1.227/27";
	conf->client_local_ip = "10.10.1.226";
	conf->network_local_ip_with_mask = "10.10.1.224/27";
	conf->network_local_ip = "10.10.1.224";
	conf->network_local_mask = 27;
	conf->port_west_ip = "10.10.1.227";

	conf->iface2_ip_with_mask = "10.10.2.2/24";
	conf->peer_ip = "10.10.2.3";
	conf->network_east_ip_with_mask = "10.10.2.0/24";
	conf->port_east_ip = "10.10.2.2";

	conf->network_remote_ip_with_mask = "10.10.1.192/26";
	conf->network_remote_ip = "10.10.1.192";
	conf->network_remote_mask = 26;
	conf->client_remote_ip = "10.10.1.193";

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

	conf->iface1_ip_with_mask = "10:10:10:10:e000::2/67";
	conf->client_local_ip = "10:10:10:10:e000::1";
	conf->network_local_ip_with_mask = "10:10:10:10:e000::/67";
	conf->network_local_ip = "10:10:10:10:e000::";
	conf->network_local_mask = 67;
	conf->port_west_ip = "10:10:10:10:e000::2";

	conf->iface2_ip_with_mask = "11:10:10:10:e000::2/64";
	conf->peer_ip = "11:10:10:10:e000::1";
	conf->network_east_ip_with_mask = "11:10:10:10:e000::/64";
	conf->port_east_ip = "11:10:10:10:e000::2";

	conf->network_remote_ip_with_mask = "10:10:10:10:c000::/66";
	conf->network_remote_ip = "10:10:10:10:c000::";
	conf->network_remote_mask = 66;
	conf->client_remote_ip = "10:10:10:10:c000::A2";

	conf->iface_vfp_ip = "fe80::1/128";

	s2s_default_conf(conf, vrfid);

	conf->ipolicy->rule_no = 6;
	conf->opolicy->rule_no = 2;

	conf->input_sa.spi = SPI_INBOUND;
	conf->output_sa.spi = SPI_OUTBOUND6;
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
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

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
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

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

static void
receive_packet(struct dp_test_s2s_config *conf,
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
	 * The packet may need to be dropped because it is received
	 * in plain text but matches an input policy, indicating that
	 * it should have been encrypted.
	 */
	if (exp_status != DP_TEST_FWD_DROPPED) {
		exp = dp_test_exp_create(pkt);
		dp_test_exp_set_oif_name(exp, ifout);
		dp_test_exp_set_fwd_status(exp, exp_status);
	} else {
		if (conf->af == AF_INET6)
			exp = generate_exp_unreachable6(pkt, len,
							conf->port_west_ip,
							saddr, ifin,
							conf->client_local_mac);
		else
			exp = generate_exp_unreachable(pkt, len,
						       conf->port_west_ip,
						       saddr, ifin,
						       conf->client_local_mac);
	}

	dp_test_intf_initial_stats_for_if(ifout, &start_stats_ifout);
	dp_test_intf_initial_stats_for_if(ifin, &start_stats_ifin);

	dis = dp_test_get_vrf_stat(conf->vrfid, conf->af,
				   IPSTATS_MIB_INNOROUTES);
	del = dp_test_get_vrf_stat(conf->vrfid, conf->af,
				   IPSTATS_MIB_INDELIVERS);
	inp = dp_test_get_vrf_stat(conf->vrfid, conf->af,
				   IPSTATS_MIB_INPKTS);

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
	inp2 = dp_test_get_vrf_stat(conf->vrfid, conf->af, IPSTATS_MIB_INPKTS);
	dp_test_verify_vrf_stats(inp, inp2, dis, dis2, del, del2, exp_status);

	dp_test_s2s_common_teardown(conf);
}

static void rx_pkt_on_int(int af, vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};
	struct dp_test_s2s_config conf;

	struct dp_test_crypto_policy my_ipols[2];
	struct dp_test_crypto_policy my_opols[2];

	if (af == AF_INET6)
		s2s_ipv6_default_conf(&conf, vrfid);
	else
		s2s_ipv4_default_conf(&conf, vrfid);

	my_ipols[0] = conf.def_ipolicy;
	my_ipols[1] = conf.def_ipolicy;
	my_opols[0] = conf.def_opolicy;
	my_opols[1] = conf.def_opolicy;

	/* Change input/output policy on index 1 to be pass-thru */
	my_ipols[1].s_prefix = my_ipols[1].d_prefix;
	my_ipols[1].priority = PASS_THRU_PRI;
	if (af == AF_INET6)
		my_ipols[1].rule_no = 8;
	else
		my_ipols[1].rule_no = 6;
	my_ipols[1].action = XFRM_POLICY_ALLOW;
	my_ipols[1].passthrough = true;

	my_opols[1].d_prefix = my_opols[1].s_prefix;
	my_opols[1].priority = PASS_THRU_PRI;
	if (af == AF_INET6)
		my_opols[1].rule_no = 4;
	else
		my_opols[1].rule_no = 2;
	my_opols[1].action = XFRM_POLICY_ALLOW;
	my_opols[1].passthrough = true;

	conf.ipolicy = my_ipols;
	conf.opolicy = my_opols;

	/* Change addresses on policy 0 - normal one  */
	my_ipols[0].s_prefix = conf.network_remote_ip_with_mask;
	my_ipols[0].d_prefix = conf.network_local_ip_with_mask;

	my_opols[0].s_prefix = conf.network_local_ip_with_mask;
	my_opols[0].d_prefix = conf.network_remote_ip_with_mask;

	exp_stats_ifin.ifi_ipackets = 1;
	exp_stats_ifin.ifi_opackets = 1;

	/*
	 * With no passthrough policy (nipols/nopols = 1), verify that a
	 * locally terminating packet which matches the outgoing crypto
	 * policy is dropped. Expect opackets == 1 for ICMP Unreachable.
	 */

	conf.nipols = 1;
	conf.nopols = 1;

	receive_packet(&conf,
		       conf.iface2,
		       conf.iface1,
		       &exp_stats_ifout,
		       &exp_stats_ifin,
		       conf.client_local_ip,
		       conf.port_west_ip,
		       0,
		       DP_TEST_FWD_DROPPED);

	/*
	 * Add the passthrough policies (nipols/nipols = 2) and verify that
	 * a locally terminating packet which matches the outgoing crypto
	 * policy is not dropped. Expect opackets = 0 for no ICMP Unreachable.
	 */
	exp_stats_ifin.ifi_opackets = 0;

	conf.nipols = 2;
	conf.nopols = 2;

	receive_packet(&conf,
		       conf.iface2,
		       conf.iface1,
		       &exp_stats_ifout,
		       &exp_stats_ifin,
		       conf.client_local_ip,
		       conf.port_west_ip,
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
	rx_pkt_on_int(AF_INET, VRF_DEFAULT_ID);
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
	rx_pkt_on_int(AF_INET6, VRF_DEFAULT_ID);
} DP_END_TEST;
