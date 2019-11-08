/*-
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Gre tests.
 */

#include <errno.h>
#include <time.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "gre.h"
#include "iptun_common.h"
#include "netinet6/ip6_funcs.h"
#include "compat.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state.h"
#include "dp_test_cmd_check.h"
#include "dp_test_lib.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_exp.h"

/*
 * Start with a simple topology, 2 interfaces both with addresses, and
 * there is a tunnel endpoint on one of them.
 *
 *   R1--------------------------UUT----------------------------------R3
 *   1:1:1::1/64  1:1:1::2/64 dp1   dp2 1:1:2::1/64          1:1:2::2/64
 *                                 tun1------------------------tun1
 *                                    2:2:2::2/64     2:2:2::3/64
 *
 *   route: 10:0:0::0/8 via 2:2:2::3 tun1
 *
 *   encap:
 *      s=1:1:1::1, d=10:0:0::1  -> s = 1:1:2::1, d=1:1:2::2
 *
 *   decap:
 *      s=1:1:2::2, d=1:1:2::1   -> s = 10:0:0::1, d=1:1:1::2
 */

DP_DECL_TEST_SUITE(gre6_suite);

static struct rte_mbuf *
gre_test_create_pak(const char *outer_sip, const char *outer_dip,
		    const struct ip6_hdr *payload, struct ip6_hdr **inner,
		    struct ip6_hdr **outer)
{
	int len = ntohs(payload->ip6_plen) + sizeof(*payload);
	struct ip6_hdr *inner_ip;
	struct rte_mbuf *m;
	void *gre_payload;

	m = dp_test_create_gre_ipv6_pak(outer_sip, outer_dip, 1, &len,
					ETH_P_IPV6, 0, 0, &gre_payload);
	if (!m)
		return NULL;

	memcpy(gre_payload, payload, len);

	/* even though encapsulation isn't dependent on payload,
	 * finalize payload before encapsulating it.
	 */
	inner_ip = gre_payload;
	inner_ip->ip6_hlim = DP_TEST_PAK_DEFAULT_TTL - 1;

	*outer = ip6hdr(m);
	*inner = inner_ip;

	return m;
}

static void
gre_test_build_expected_pak(struct dp_test_expected **expected,
			    struct ip6_hdr *payload,
			    struct ip6_hdr *outer)
{
	struct dp_test_expected *exp;
	struct ip6_hdr *inner;
	struct rte_mbuf *m;

	m = gre_test_create_pak(
		"1:1:2::1", "1:1:2::2",
		payload, &inner, &outer);
	dp_test_pktmbuf_eth_init(m,
				 "aa:bb:cc:dd:ee:ff",
				 dp_test_intf_name2mac_str("dp2T2"),
				 ETHER_TYPE_IPv6);
	/* currently doing hlim propagation */
	outer->ip6_hlim = inner->ip6_hlim;

	exp = dp_test_exp_create_with_packet(m);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T2");
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_FORWARDED);

	*expected = exp;
}

static void
dp_test_gre6_setup_tunnel(uint32_t vrfid, const char *tun_src,
			 const char *tun_dst)
{
	const char *nh_mac_str;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	dp_test_netlink_set_interface_vrf("dp1T1", vrfid);
	dp_test_netlink_add_ip_address_vrf("dp1T1", "1:1:1::1/64", vrfid);
	snprintf(route1, sizeof(route1), "vrf:%d 1:1:1::0/64 nh int:dp1T1",
		 vrfid);
	dp_test_netlink_add_route(route1);

	dp_test_netlink_add_ip_address("dp2T2", "1:1:2::1/64");
	dp_test_netlink_add_route("1:1:2::0/64 nh int:dp2T2");

	dp_test_intf_gre_create("tun1", tun_src, tun_dst, 0, vrfid);
	dp_test_netlink_add_ip_address_vrf("tun1", "2:2:2::2/64", vrfid);

	snprintf(route2, sizeof(route2),
		 "vrf:%d 10:0:0::0/64 nh 2:2:2::3 int:tun1", vrfid);
	dp_test_netlink_add_route(route2);
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "1:1:2::2", nh_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1:1:1::2", nh_mac_str);
}

static void
dp_test_gre6_teardown_tunnel(uint32_t vrfid, const char *tun_src,
			    const char *tun_dst)
{
	const char *nh_mac_str;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_del_neigh("dp2T2", "1:1:2::2", nh_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1:1:1::2", nh_mac_str);
	snprintf(route2, sizeof(route2),
		 "vrf:%d 10:0:0::0/64 nh 2:2:2::3 int:tun1", vrfid);
	dp_test_netlink_del_route(route2);
	dp_test_netlink_del_route("1:1:2::0/64 nh int:dp2T2");
	snprintf(route1, sizeof(route1), "vrf:%d 1:1:1::0/64 nh int:dp1T1",
		 vrfid);
	dp_test_netlink_del_route(route1);

	dp_test_netlink_del_ip_address_vrf("dp1T1", "1:1:1::1/64", vrfid);
	dp_test_netlink_del_ip_address("dp2T2", "1:1:2::1/64");
	dp_test_netlink_del_ip_address_vrf("tun1", "2:2:2::2/64", vrfid);

	dp_test_intf_gre_delete("tun1", tun_src, tun_dst, 0,
				vrfid);
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);
}

DP_DECL_TEST_CASE(gre6_suite, gre6_encap, NULL, NULL);

DP_START_TEST(gre6_encap, simple_encap_6O6)
{
	struct rte_mbuf *m;
	struct dp_test_expected *exp;
	struct ip6_hdr *inner_ip;
	struct ip6_hdr *exp_ip_outer = NULL;
	int len = 32;

	dp_test_gre6_setup_tunnel(VRF_DEFAULT_ID, "1:1:2::1", "1:1:2::2");

	m = dp_test_create_ipv6_pak("1:1:1::2", "10:0:0::1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv6);
	inner_ip = ip6hdr(m);
	gre_test_build_expected_pak(&exp, inner_ip,
				    exp_ip_outer);
	dp_test_pak_receive(m, "dp1T1", exp);

	dp_test_gre6_teardown_tunnel(VRF_DEFAULT_ID, "1:1:2::1", "1:1:2::2");
} DP_END_TEST;


static struct dp_test_expected *gre6_test_build_expected_decapped_pak(
	struct rte_mbuf **exp_mbuf_p)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *exp_mbuf;
	struct ip6_hdr *ip6;
	int len = 32;

	exp_mbuf = dp_test_create_ipv6_pak("10:0:0::1", "1:1:1::2",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(exp_mbuf,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv6);
	ip6 = ip6hdr(exp_mbuf);
	ip6->ip6_hlim -= 2;

	exp = dp_test_exp_create_m(NULL, 1);
	exp->exp_pak[0] = exp_mbuf;
	dp_test_exp_set_oif_name(exp, "dp1T1");
	exp->check_start[0] = sizeof(struct ether_hdr);
	exp->check_len[0] =
		rte_pktmbuf_data_len(exp_mbuf) - exp->check_start[0];
	*exp_mbuf_p = exp_mbuf;

	return exp;
}

static struct rte_mbuf *
dp_test_gre6_build_encapped_pak(const struct ip6_hdr *payload_ip,
			       struct ip6_hdr **outer_ip,
			       struct ip6_hdr **inner_ip)
{
	struct rte_mbuf *m;

	m = gre_test_create_pak("1:1:2::2", "1:1:2::1",
				payload_ip, inner_ip, outer_ip);
	(void)dp_test_pktmbuf_eth_init(m,
				       dp_test_intf_name2mac_str("dp2T2"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv6);
	return m;
}

DP_DECL_TEST_CASE(gre6_suite, gre6_decap, NULL, NULL);

DP_START_TEST(gre6_decap, simple_decap_6O6)
{
	struct rte_mbuf *e;
	struct rte_mbuf *m;
	struct dp_test_expected *exp;
	struct ip6_hdr *inner_ip;
	struct ip6_hdr *outer_ip;

	dp_test_gre6_setup_tunnel(VRF_DEFAULT_ID, "1:1:2::1", "1:1:2::2");

	exp = gre6_test_build_expected_decapped_pak(&e);
	m = dp_test_gre6_build_encapped_pak(ip6hdr(e), &outer_ip, &inner_ip);

	dp_test_pak_receive(m, "dp2T2", exp);

	dp_test_gre6_teardown_tunnel(VRF_DEFAULT_ID, "1:1:2::1", "1:1:2::2");
} DP_END_TEST;

