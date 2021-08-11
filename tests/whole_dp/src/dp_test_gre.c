/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
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
#include "if/gre.h"
#include "if_var.h"
#include "main.h"
#include "iptun_common.h"
#include "netinet6/ip6_funcs.h"
#include "compat.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test/dp_test_gre.h"


/*
 * Start with a simple topology, 2 interfaces both with addresses, and
 * there is a tunnel endpoint on one of them.
 *
 *   R1------------------------UUT----------------------------------R3
 *   1.1.1.2/24  1.1.1.1/24 dp1   dp2 1.1.2.1/24          1.1.2.2/24
 *                                 tun1------------------------tun1
 *                                    2.2.2.2/24     2.2.2.3/24
 *
 *   route: 10.0.0.0/8 via 2.2.2.3 tun1
 *
 *   encap:
 *      s=1.1.1.1, d=10.0.0.1  -> s = 1.1.2.1, d=1.1.2.2
 *
 *   decap:
 *      s=1.1.2.2, d=1.1.2.1   -> s = 10.0.0.1, d=1.1.1.2
 */

DP_DECL_TEST_SUITE(gre_suite);

static struct rte_mbuf *
gre_test_create_pak(const char *outer_sip, const char *outer_dip,
		    const struct iphdr *payload, struct iphdr **inner,
		    struct iphdr **outer)
{
	int len = ntohs(payload->tot_len);
	struct iphdr *outer_ip;
	struct iphdr *inner_ip;
	struct rte_mbuf *m;
	void *gre_payload;

	m = dp_test_create_gre_ipv4_pak(outer_sip, outer_dip, 1, &len,
					ETH_P_IP, 0, 0, &gre_payload);
	if (!m)
		return NULL;

	memcpy(gre_payload, payload, len);

	/* even though encapsulation isn't dependent on payload,
	 * finalize payload before encapsulating it.
	 */
	inner_ip = gre_payload;
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	outer_ip = iphdr(m);
	/* PMTU disc on, so DF bit gets set */
	dp_test_set_pak_ip_field(outer_ip, DP_TEST_SET_DF, 1);
	dp_test_set_pak_ip_field(outer_ip, DP_TEST_SET_TTL, inner_ip->ttl);
	*outer = outer_ip;

	*inner = inner_ip;

	return m;
}

void
gre_test_build_expected_pak(struct dp_test_expected **expected,
			    struct iphdr *payload[],
			    struct iphdr *outer[],
			    int num_paks)
{
	int i;
	struct dp_test_expected *exp;
	struct iphdr *inner;
	struct rte_mbuf *m;

	*expected = NULL;
	exp = dp_test_exp_create_m(NULL, num_paks);

	for (i = 0; i < num_paks; i++) {
		m = gre_test_create_pak(
			"1.1.2.1", "1.1.2.2",
			payload[i], &inner, &outer[i]);
		if (!m)
			return;
		dp_test_pktmbuf_eth_init(m,
					 "aa:bb:cc:dd:ee:ff",
					 dp_test_intf_name2mac_str("dp2T2"),
					 RTE_ETHER_TYPE_IPV4);

		dp_test_exp_set_pak_m(exp, i, m);

		dp_test_exp_set_oif_name_m(exp, i, "dp2T2");
		dp_test_exp_set_fwd_status_m(exp, i, DP_TEST_FWD_FORWARDED);
	}

	*expected = exp;
}

static struct rte_mbuf *
gre_test_create_pak_ipv6(const char *outer_sip, const char *outer_dip,
			 const struct ip6_hdr *payload, struct ip6_hdr **inner,
			 struct iphdr **outer)
{
	int len = ntohs(payload->ip6_plen) + sizeof(*payload);
	struct iphdr *outer_ip;
	struct ip6_hdr *inner_ip;
	struct rte_mbuf *m;
	void *gre_payload;

	m = dp_test_create_gre_ipv4_pak(outer_sip, outer_dip, 1, &len,
					ETH_P_IPV6, 0, 0, &gre_payload);
	if (!m)
		return NULL;

	memcpy(gre_payload, payload, len);

	/* even though encapsulation isn't dependent on payload,
	 * finalize payload before encapsulating it.
	 */
	inner_ip = gre_payload;
	inner_ip->ip6_hlim = DP_TEST_PAK_DEFAULT_TTL - 1;

	outer_ip = iphdr(m);
	/* PMTU disc on, so DF bit gets set */
	dp_test_set_pak_ip_field(outer_ip, DP_TEST_SET_DF, 1);
	dp_test_set_pak_ip_field(outer_ip, DP_TEST_SET_TTL, inner_ip->ip6_hlim);
	*outer = outer_ip;

	*inner = inner_ip;

	return m;
}

static void
gre_test_build_expected_pak_ipv6(struct dp_test_expected **expected,
				 struct ip6_hdr *payload[],
				 struct iphdr *outer[],
				 int num_paks)
{
	int i;
	struct dp_test_expected *exp;
	struct ip6_hdr *inner;

	dp_test_fail_unless((num_paks <= DP_TEST_MAX_EXPECTED_PAKS),
			    "too many paks wanted");
	exp = dp_test_exp_create_m(NULL, num_paks);
	exp->exp_num_paks = num_paks;

	for (i = 0; i < num_paks; i++) {

		exp->exp_pak[i] = gre_test_create_pak_ipv6(
			"1.1.2.1", "1.1.2.2",
			payload[i], &inner, &outer[i]);

		exp->oif_name[i] = "dp2T2";
		exp->fwd_result[i] = DP_TEST_FWD_FORWARDED;
		/* Jump over the L2 hdr before checking. */
		/* FIXME: Currently set check_len using pak 0,
		 * subsequent exp paks are not set up correctly for the full
		 * data len.
		 */
		exp->check_start[i] = dp_pktmbuf_l2_len(exp->exp_pak[i]);
		exp->check_len[i] = rte_pktmbuf_data_len(exp->exp_pak[0]) -
			exp->check_start[i];
	}

	*expected = exp;
}

static void
gre_test_build_expected_icmp_pak(struct dp_test_expected **exp,
				 struct iphdr *payload[],
				 struct iphdr *outer[],
				 int num_paks,
				 int len)
{
	struct icmphdr *icmp;
	int i;
	struct dp_test_expected *expected;

	dp_test_fail_unless((num_paks <= DP_TEST_MAX_EXPECTED_PAKS),
			    "too many paks wanted");
	expected = dp_test_exp_create_m(NULL, num_paks);

	for (i = 0; i < num_paks; i++) {
		/* Jump over the ether hdr before checking. */
		expected->check_start[i] = sizeof(struct rte_ether_hdr);

		expected->exp_pak[i] = dp_test_create_icmp_ipv4_pak(
			"1.1.1.1", "1.1.1.2", ICMP_DEST_UNREACH,
			ICMP_FRAG_NEEDED, DPT_ICMP_FRAG_DATA(1476),
			1, &len, payload[i], &outer[i],
			&icmp);

		dp_test_set_pak_ip_field((struct iphdr *)(icmp + 1),
					 DP_TEST_SET_TTL,
					 DP_TEST_PAK_DEFAULT_TTL - 1);

		expected->oif_name[i] = "dp1T1";
		expected->fwd_result[i] = DP_TEST_FWD_FORWARDED;
		expected->check_len[i] =
			rte_pktmbuf_data_len(expected->exp_pak[i]) -
			expected->check_start[i];
	}
	*exp = expected;
}

void
dp_test_gre_setup_tunnel(uint32_t vrfid, const char *tun_src,
			 const char *tun_dst)
{
	const char *nh_mac_str;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	dp_test_netlink_set_interface_vrf("dp1T1", vrfid);
	dp_test_netlink_add_ip_address_vrf("dp1T1", "1.1.1.1/24", vrfid);
	snprintf(route1, sizeof(route1), "vrf:%d 1.1.1.0/24 nh int:dp1T1",
		 vrfid);
	dp_test_netlink_add_route(route1);

	dp_test_netlink_add_ip_address("dp2T2", "1.1.2.1/24");
	dp_test_netlink_add_route("1.1.2.0/24 nh int:dp2T2");

	dp_test_intf_gre_create("tun1", tun_src, tun_dst, 0, vrfid);
	dp_test_netlink_add_ip_address_vrf("tun1", "2.2.2.2/24", vrfid);

	snprintf(route2, sizeof(route2),
		 "vrf:%d 10.0.0.0/8 nh 2.2.2.3 int:tun1", vrfid);
	dp_test_netlink_add_route(route2);
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "1.1.2.2", nh_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str);
}

void
dp_test_gre_teardown_tunnel(uint32_t vrfid, const char *tun_src,
			    const char *tun_dst)
{
	const char *nh_mac_str;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_del_neigh("dp2T2", "1.1.2.2", nh_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str);
	snprintf(route2, sizeof(route2),
		 "vrf:%d 10.0.0.0/8 nh 2.2.2.3 int:tun1", vrfid);
	dp_test_netlink_del_route(route2);
	dp_test_netlink_del_route("1.1.2.0/24 nh int:dp2T2");
	snprintf(route1, sizeof(route1), "vrf:%d 1.1.1.0/24 nh int:dp1T1",
		 vrfid);
	dp_test_netlink_del_route(route1);

	dp_test_netlink_del_ip_address_vrf("dp1T1", "1.1.1.1/24", vrfid);
	dp_test_netlink_del_ip_address("dp2T2", "1.1.2.1/24");
	dp_test_netlink_del_ip_address_vrf("tun1", "2.2.2.2/24", vrfid);

	dp_test_intf_gre_delete("tun1", tun_src, tun_dst, 0,
				vrfid);
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);
}

DP_DECL_TEST_CASE(gre_suite, gre_encap, NULL, NULL);

DP_START_TEST(gre_encap, simple_encap)
{
	struct rte_mbuf *m;
	struct dp_test_expected *exp_no_frag;
	struct dp_test_expected *exp_frag;
	struct dp_test_expected *exp_icmp;
	struct iphdr *inner_ip;
	struct iphdr *exp_ip_outer[DP_TEST_MAX_EXPECTED_PAKS] = { 0 };
	int len = 32;

	dp_test_gre_setup_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");

	/*
	 * There are a number of encap tests to be run with various
	 * modifications made. As far as possible write the tests in
	 * a way such that we don't need to rewrite them for each of
	 * the variations below.
	 *
	 *   ECN variations
	 *   DF bit set on inner pak
	 *   gre key added - need netlink changes
	 *   outgoing MTU variations - need netlink changes
	 *
	 */

	/* ECN encap
	 *
	 * RFC 3168, section 9.1.1 full functionality.
	 * Copy the ECN codepoint of the inside header to the outside header
	 * on encapsulation if the inside header is not-ECT or ECT, and to
	 * set the ECN codepoint of the outside header to ECT(0) if the ECN
	 * codepoint of the inside header is CE.
	 *
	 * ECN_NOT_ECT = 0  => 0
	 * ECN_ECT_1   = 1  => 1
	 * ECN_ECT_0   = 2  => 2
	 * ECN_CE      = 3  => 2
	 */

	/* inside 00 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_IP_ECN,
				 IPTOS_ECN_NOT_ECT);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_assert_internal(exp_ip_outer[0] != NULL);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 01 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_IP_ECN,
				 IPTOS_ECN_ECT1);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 10 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 11 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_IP_ECN,
				 IPTOS_ECN_CE);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/*
	 * Fragmentation and ICMP generation:
	 *
	 * Loop through the following, but do it via copy paste
	 * so that it is easier to follow what is happenning and
	 * what is expected than it would be with real loops.
	 *
	 * input size: 1400, 1476, 1477
	 * DF:         set, unset
	 */

	/* Expected paks when we fragment into a tunnel. */
	struct iphdr *frag_outer[2];
	struct rte_mbuf *frag_payload_m[2];
	struct iphdr *frag_payload[2];

	/*
	 * Looping through input sizes.
	 */
	/* 1400 */
	len = 1400 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1476 */
	len = 1476 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1477 */
	len = 1477 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	/*
	 * Set frag 0 which is the last x bytes of the pak,
	 * then frag 1 which is the first 'mtu' bytes
	 */
	uint16_t frag_sizes[2] = {
		1,
		1476 - sizeof(struct iphdr),
	};
	int ret;
	ret = dp_test_ipv4_fragment_packet(m, frag_payload_m, 2, frag_sizes, 0);
	dp_test_fail_unless(ret == 2,
			    "dp_test_ipv4_fragment_packet failed: %s",
			    strerror(-ret));

	frag_payload[0] = iphdr(frag_payload_m[0]);
	frag_payload[1] = iphdr(frag_payload_m[1]);
	gre_test_build_expected_pak(&exp_frag, frag_payload, frag_outer, 2);
	dp_test_assert_internal(exp_frag != NULL);
	rte_pktmbuf_free(frag_payload_m[0]);
	rte_pktmbuf_free(frag_payload_m[1]);

	dp_test_pak_receive(m, "dp1T1", exp_frag);


	/*
	 * Set the DF bit then go through the lengths again.
	 */
	/* 1400 */
	len = 1400 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0], DP_TEST_SET_DF, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1476 */
	len = 1476 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0], DP_TEST_SET_DF, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1477 Expect an icmp generated here. */
	len = 1477 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);

	/* Expected paks when we generate an icmp. */
	struct iphdr *icmp_outer;

	gre_test_build_expected_icmp_pak(&exp_icmp, &inner_ip, &icmp_outer, 1,
					 sizeof(struct iphdr) + 576);
	dp_test_set_pak_ip_field(icmp_outer, DP_TEST_SET_TOS, 0xc0);
	exp_icmp->oif_name[0] = "dp1T1";

	dp_test_pak_receive(m, "dp1T1", exp_icmp);

	/* And now clean up all the state we added. */
	dp_test_gre_teardown_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");
} DP_END_TEST;

DP_START_TEST(gre_encap, simple_encap_ipv6)
{
	struct rte_mbuf *m;
	struct dp_test_expected *exp_no_frag;
	struct dp_test_expected *exp_icmp;
	struct ip6_hdr *inner_ip;
	struct icmp6_hdr *icmp6;
	struct iphdr *exp_ip_outer[DP_TEST_MAX_EXPECTED_PAKS];
	int len = 32;

	dp_test_gre_setup_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");

	dp_test_nl_add_ip_addr_and_connected("tun1", "2:2:2::2/64");
	dp_test_netlink_add_route("10::/64 nh 2:2:2::3 int:tun1");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1:1:1::1/64");
	dp_test_netlink_add_neigh("dp1T1", "1:1:1::2", "aa:bb:cc:dd:ee:ff");

	/* inside 00 */
	m = dp_test_create_ipv6_pak("1:1:1::2", "10::1", 1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	inner_ip = ip6hdr(m);
	ip6_ver_tc_flow_hdr(inner_ip, IPTOS_ECN_NOT_ECT, 0);
	gre_test_build_expected_pak_ipv6(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 01 */
	m = dp_test_create_ipv6_pak("1:1:1::2", "10::1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	inner_ip = ip6hdr(m);
	ip6_ver_tc_flow_hdr(inner_ip, IPTOS_ECN_ECT1, 0);
	gre_test_build_expected_pak_ipv6(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 10 */
	m = dp_test_create_ipv6_pak("1:1:1::2", "10::1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	inner_ip = ip6hdr(m);
	ip6_ver_tc_flow_hdr(inner_ip, IPTOS_ECN_ECT0, 0);
	gre_test_build_expected_pak_ipv6(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 11 */
	m = dp_test_create_ipv6_pak("1:1:1::2", "10::1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	inner_ip = ip6hdr(m);
	ip6_ver_tc_flow_hdr(inner_ip, IPTOS_ECN_CE, 0);
	gre_test_build_expected_pak_ipv6(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/*
	 * Fragmentation and ICMP generation:
	 *
	 * Loop through the following, but do it via copy paste
	 * so that it is easier to follow what is happenning and
	 * what is expected than it would be with real loops.
	 *
	 * input size: 1400, 1476, 1477
	 */

	/*
	 * Looping through input sizes.
	 */
	/* 1400 */
	len = 1400 - sizeof(struct ip6_hdr);
	m = dp_test_create_ipv6_pak("1:1:1::2", "10::1",
				    1, &len);
	dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV6);
	inner_ip = ip6hdr(m);
	gre_test_build_expected_pak_ipv6(&exp_no_frag, &inner_ip,
					 exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1476 */
	len = 1476 - sizeof(struct ip6_hdr);
	m = dp_test_create_ipv6_pak("1:1:1::2", "10::1",
				    1, &len);
	dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV6);
	inner_ip = ip6hdr(m);
	gre_test_build_expected_pak_ipv6(&exp_no_frag, &inner_ip,
					 exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1477 */
	len = 1477 - sizeof(struct ip6_hdr);
	m = dp_test_create_ipv6_pak("1:1:1::2", "10::1",
				    1, &len);
	dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV6);
	inner_ip = ip6hdr(m);
	exp_icmp = dp_test_exp_create_m(NULL, 1);

	len = 1280 - sizeof(struct icmp6_hdr) - sizeof(struct ip6_hdr);
	dp_test_exp_set_pak_m(
		exp_icmp, 0, dp_test_create_icmp_ipv6_pak(
			"1:1:1::1", "1:1:1::2",	ICMP6_PACKET_TOO_BIG,
			0, 1476, 1, &len, inner_ip, NULL, &icmp6)
		);
	inner_ip = (struct ip6_hdr *)(icmp6 + 1);
	inner_ip->ip6_hlim--;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(
		exp_icmp->exp_pak[0], ip6hdr(exp_icmp->exp_pak[0]),
		icmp6);
	dp_test_pktmbuf_eth_init(exp_icmp->exp_pak[0], "aa:bb:cc:dd:ee:ff",
				 dp_test_intf_name2mac_str("dp1T1"),
				 RTE_ETHER_TYPE_IPV6);
	dp_test_exp_set_oif_name(exp_icmp, "dp1T1");
	dp_test_exp_set_fwd_status(exp_icmp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(m, "dp1T1", exp_icmp);

	/* And now clean up all the state we added. */
	dp_test_netlink_del_neigh("dp1T1", "1:1:1::2", "aa:bb:cc:dd:ee:ff");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("tun1", "2:2:2::2/64");
	dp_test_netlink_del_route("10::/64 nh 2:2:2::3 int:tun1");
	dp_test_gre_teardown_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");
} DP_END_TEST;

DP_START_TEST(gre_encap, ignore_df)
{
	struct rte_mbuf *m;
	struct dp_test_expected *exp_no_frag;
	struct dp_test_expected *exp_frag;
	struct iphdr *inner_ip;
	struct iphdr *exp_ip_outer[DP_TEST_MAX_EXPECTED_PAKS];
	int len;

	dp_test_set_gre_ignore_df(true);

	dp_test_gre_setup_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");

	/*
	 * There are a number of encap tests to be run with various
	 * modifications made. As far as possible write the tests in
	 * a way such that we don't need to rewrite them for each of
	 * the variations below.
	 *
	 *   DF bit set on inner pak
	 *   outgoing MTU variations - need netlink changes
	 *
	 */

	/*
	 * Fragmentation and ICMP generation:
	 *
	 * Loop through the following, but do it via copy paste
	 * so that it is easier to follow what is happenning and
	 * what is expected than it would be with real loops.
	 *
	 * input size: 1400, 1476, 1477
	 * DF:         set, unset
	 * tunnel MTU: 1476, 1376
	 * output MTU: 1500, 1400
	 * PMTU:       on, off
	 * Key:        set, unset
	 */

	/* Expected paks when we fragment into a tunnel. */
	struct iphdr *frag_outer[2];
	struct rte_mbuf *frag_payload_m[2];
	struct iphdr *frag_payload[2];

	/*
	 * Looping through input sizes.
	 */
	/* 1400 */
	len = 1400 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_assert_internal(exp_no_frag != NULL);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1476 */
	len = 1476 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1477 */
	len = 1477 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);

	/*
	 * Set frag 0 which is the last x bytes of the pak,
	 * then frag 1 which is the first 'mtu' bytes
	 */
	uint16_t frag_sizes[2] = {
		1,
		1476 - sizeof(struct iphdr),
	};
	int ret;
	ret = dp_test_ipv4_fragment_packet(m, frag_payload_m, 2, frag_sizes, 0);
	dp_test_fail_unless(ret == 2,
			    "dp_test_ipv4_fragment_packet failed: %s",
			    strerror(-ret));

	frag_payload[0] = iphdr(frag_payload_m[0]);
	frag_payload[1] = iphdr(frag_payload_m[1]);
	gre_test_build_expected_pak(&exp_frag, frag_payload, frag_outer, 2);
	dp_test_assert_internal(exp_frag != NULL);
	rte_pktmbuf_free(frag_payload_m[0]);
	rte_pktmbuf_free(frag_payload_m[1]);

	dp_test_pak_receive(m, "dp1T1", exp_frag);

	/* And now clean up all the state we added. */
	dp_test_gre_teardown_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");

	dp_test_reset_gre_ignore_df();
} DP_END_TEST;

static inline void dp_test_gre_tos_encap(bool inherit, uint8_t val)
{
	struct rte_mbuf *m;
	struct dp_test_expected *exp;
	struct iphdr *inner_ip;
	struct iphdr *exp_ip_outer[DP_TEST_MAX_EXPECTED_PAKS] = { 0 };
	int len = 32;

	/* Tos 0 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_TOS,
				 0);
	gre_test_build_expected_pak(&exp, &inner_ip, exp_ip_outer, 1);
	dp_test_assert_internal(exp_ip_outer[0] != NULL);
	dp_test_set_pak_ip_field(exp_ip_outer[0], DP_TEST_SET_TOS,
				 0);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* Tos 0xc0 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_TOS,
				 0xc0);
	gre_test_build_expected_pak(&exp, &inner_ip, exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0], DP_TEST_SET_TOS,
				 inherit ? 0xc0 : val);
	dp_test_pak_receive(m, "dp1T1", exp);
}

DP_START_TEST(gre_encap, tos_inherit_encap)
{
	/* inherit, then repeat having changed to don't */
	dp_test_set_gre_tos(1);
	dp_test_gre_setup_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");
	dp_test_gre_tos_encap(true, 1);
	dp_test_reset_gre_tos();
	dp_test_intf_gre_create("tun1", "1.1.2.1", "1.1.2.2", 0,
				VRF_DEFAULT_ID);
	dp_test_gre_tos_encap(false, 0);
	dp_test_gre_teardown_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");

	/* don't inherit then repeat having changed to inherit */
	dp_test_gre_setup_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");
	dp_test_gre_tos_encap(false, 0);
	dp_test_set_gre_tos(1);
	dp_test_intf_gre_create("tun1", "1.1.2.1", "1.1.2.2", 0,
				VRF_DEFAULT_ID);
	dp_test_gre_tos_encap(true, 1);
	dp_test_gre_teardown_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");
	dp_test_reset_gre_tos();

} DP_END_TEST;

DP_START_TEST(gre_encap, no_route)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 32;

	/*
	 * Set up the tunnel with a route out of it, but no route for
	 * the tunnel destination.
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str);
	dp_test_intf_gre_create("tun1", "1.1.1.1", "1.1.2.1", 0,
				VRF_DEFAULT_ID);
	dp_test_nl_add_ip_addr_and_connected("tun1", "2.2.2.2/24");

	/*
	 * Send a packet via the tunnel
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T1"),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV4);

	/*
	 * Expect the packet to be dropped - an ICMP might attempt to
	 * be generated, but it won't be sent back to the sender due
	 * to it being destined for-us.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_nl_del_ip_addr_and_connected("tun1", "2.2.2.2/24");
	dp_test_intf_gre_delete("tun1", "1.1.1.1", "1.1.2.1", 0,
				VRF_DEFAULT_ID);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
} DP_END_TEST;


struct rte_mbuf *
dp_test_gre_build_encapped_pak(const struct iphdr *payload_ip,
			       struct iphdr **outer_ip,
			       struct iphdr **inner_ip)
{
	struct rte_mbuf *m;

	m = gre_test_create_pak("1.1.2.2", "1.1.2.1",
				payload_ip, inner_ip, outer_ip);
	(void)dp_test_pktmbuf_eth_init(m,
				       dp_test_intf_name2mac_str("dp2T2"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	return m;
}



DP_DECL_TEST_CASE(gre_suite, gre_decap, NULL, NULL);


struct dp_test_expected *dp_test_gre_build_expected_ecn_pak(
	struct rte_mbuf **exp_mbuf_p)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *exp_mbuf;
	int len = 32;

	exp_mbuf = dp_test_create_ipv4_pak("10.0.0.1", "1.1.1.2",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(exp_mbuf,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	dp_test_set_pak_ip_field(iphdr(exp_mbuf), DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 2);
	exp = dp_test_exp_create_m(NULL, 1);
	exp->exp_pak[0] = exp_mbuf;
	dp_test_exp_set_oif_name(exp, "dp1T1");
	exp->check_start[0] = sizeof(struct rte_ether_hdr);
	exp->check_len[0] =
		rte_pktmbuf_data_len(exp_mbuf) - exp->check_start[0];
	*exp_mbuf_p = exp_mbuf;

	return exp;
}

DP_START_TEST(gre_decap, ecn_decap)
{
	struct rte_mbuf *e;
	struct rte_mbuf *m;
	struct dp_test_expected *exp;
	struct iphdr *inner_ip;
	struct iphdr *outer_ip;

	dp_test_gre_setup_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");

	/* ECN decap
	 *
	 * RFC 6040
	 *
	 * To decapsulate the inner header at the tunnel egress, a compliant
	 * tunnel egress MUST set the outgoing ECN field to the codepoint at the
	 * intersection of the appropriate arriving inner header (row) and outer
	 * header (column) in Figure 4 (the IPv4 header checksum also changes
	 * whenever the ECN field is changed).  There is no need for more than
	 * one mode of decapsulation, as these rules cater for all known
	 * requirements.
	 *
	 *          +---------+------------------------------------------------+
	 *          |Arriving |            Arriving Outer Header               |
	 *          |   Inner +---------+------------+------------+------------+
	 *          |  Header | Not-ECT | ECT(0)     | ECT(1)     |     CE     |
	 *          +---------+---------+------------+------------+------------+
	 *          | Not-ECT | Not-ECT |Not-ECT(!!!)|Not-ECT(!!!)| <drop>(!!!)|
	 *          |  ECT(0) |  ECT(0) | ECT(0)     | ECT(1)     |     CE     |
	 *          |  ECT(1) |  ECT(1) | ECT(1) (!) | ECT(1)     |     CE     |
	 *          |    CE   |      CE |     CE     |     CE(!!!)|     CE     |
	 *          +---------+---------+------------+------------+------------+
	 */

	/* loop through all inners for outer 00 */
	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_assert_internal(outer_ip != NULL);
	dp_test_assert_internal(inner_ip != NULL);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_pak_receive(m, "dp2T2", exp);



	/* loop through all inners for outer 01 */
	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_pak_receive(m, "dp2T2", exp);


	/* loop through all inners for outer 02 */
	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_pak_receive(m, "dp2T2", exp);

	/* loop through all inners for outer 03 */
	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);
	/* This case causes us to drop the pak */
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	exp->exp_num_paks = 1;
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_pak_receive(m, "dp2T2", exp);


	exp = dp_test_gre_build_expected_ecn_pak(&e);
	m = dp_test_gre_build_encapped_pak(iphdr(e), &outer_ip, &inner_ip);
	dp_test_set_pak_ip_field(outer_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_set_pak_ip_field(iphdr(e),
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_CE);
	dp_test_pak_receive(m, "dp2T2", exp);

	/* And now clean up all the state we added. */
	dp_test_gre_teardown_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");
} DP_END_TEST;

DP_START_TEST(gre_decap, invalid_paks)
{
	struct rte_mbuf *m;
	struct dp_test_expected *exp;
	struct gre_hdr *gre;
	int len;

	dp_test_gre_setup_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");

	/* Boundary condition 1: only enough space for IPv4 header */
	len = 0;
	m = dp_test_create_raw_ipv4_pak("1.1.2.2", "1.1.2.1",
					IPPROTO_GRE, 1, &len);
	dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV4);
	exp = dp_test_exp_create(m);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* Boundary condition 2: one byte short of GRE header, no flags set */
	len = sizeof(struct gre_hdr) - 1;
	m = dp_test_create_raw_ipv4_pak("1.1.2.2", "1.1.2.1",
					IPPROTO_GRE, 1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	gre = (struct gre_hdr *)(iphdr(m) + 1);
	memset(gre, 0, sizeof(struct gre_hdr) - 1);
	exp = dp_test_exp_create(m);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* Boundary condition 3: one byte short with GRE_CSUM set */
	len = sizeof(struct gre_hdr) - 1;
	m = dp_test_create_raw_ipv4_pak("1.1.2.2", "1.1.2.1",
					IPPROTO_GRE, 1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	gre = (struct gre_hdr *)(iphdr(m) + 1);
	memset(gre, 0, sizeof(struct gre_hdr) + 4 - 1);
	gre->flags |= GRE_CSUM;
	exp = dp_test_exp_create(m);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* Boundary condition 4: one byte short with GRE_KEY set */
	len = sizeof(struct gre_hdr) - 1;
	m = dp_test_create_raw_ipv4_pak("1.1.2.2", "1.1.2.1",
					IPPROTO_GRE, 1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	gre = (struct gre_hdr *)(iphdr(m) + 1);
	memset(gre, 0, sizeof(struct gre_hdr) + 4 - 1);
	gre->flags |= GRE_KEY;
	exp = dp_test_exp_create(m);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* Boundary condition 5: one byte short with GRE_SEQ set */
	len = sizeof(struct gre_hdr) - 1;
	m = dp_test_create_raw_ipv4_pak("1.1.2.2", "1.1.2.1",
					IPPROTO_GRE, 1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	gre = (struct gre_hdr *)(iphdr(m) + 1);
	memset(gre, 0, sizeof(struct gre_hdr) + 4 - 1);
	gre->flags |= GRE_SEQ;
	exp = dp_test_exp_create(m);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(m, "dp1T1", exp);

	dp_test_gre_teardown_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "1.1.2.2");
} DP_END_TEST;

DP_DECL_TEST_CASE(gre_suite, mgre_encap, NULL, NULL);

DP_START_TEST(mgre_encap, simple_encap)
{
	struct rte_mbuf *m;
	struct dp_test_expected *exp;
	struct iphdr *exp_ip_outer;
	struct iphdr *ip_inner;
	int len = 32;

	/* mGRE hub */
	dp_test_gre_setup_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "0.0.0.0");

	/* No neighbour yet, so we expect packet to turn up on slow path */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);
	exp = dp_test_exp_create(m);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* Add a neighbour then try to send the pak again */
	dp_test_netlink_add_neigh("tun1", "2.2.2.3", "1.1.2.2");
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);
	ip_inner = iphdr(m);
	gre_test_build_expected_pak(&exp, &ip_inner,
				    &exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* Add another neighbour then try to send the pak again */
	dp_test_netlink_add_neigh("tun1", "2.2.2.4", "1.1.2.3");
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);
	ip_inner = iphdr(m);
	gre_test_build_expected_pak(&exp, &ip_inner,
				    &exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* Remove the neighbours  so expect a local packet*/
	dp_test_netlink_del_neigh("tun1", "2.2.2.4", "1.1.2.3");
	dp_test_netlink_del_neigh("tun1", "2.2.2.3", "1.1.2.2");
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);
	exp = dp_test_exp_create(m);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	dp_test_pak_receive(m, "dp1T1", exp);

	/* And now clean up all the state we added. */
	dp_test_gre_teardown_tunnel(VRF_DEFAULT_ID, "1.1.2.1", "0.0.0.0");
} DP_END_TEST;

DP_DECL_TEST_CASE(gre_suite, gre_vrf_encap, NULL, NULL);

/* TODO: MR change to non-default VRF after v4 plumbing */
#define TEST_VRF 55

DP_START_TEST(gre_vrf_encap, simple_vrf_encap)
{
	struct rte_mbuf *m;
	struct dp_test_expected *exp_no_frag;
	struct dp_test_expected *exp_frag;
	struct dp_test_expected *exp_icmp;
	struct iphdr *inner_ip;
	struct iphdr *exp_ip_outer[DP_TEST_MAX_EXPECTED_PAKS] = { 0 };
	int len = 32;

	dp_test_gre_setup_tunnel(TEST_VRF, "1.1.2.1", "1.1.2.2");

	/*
	 * There are a number of encap tests to be run with various
	 * modifications made. As far as possible write the tests in
	 * a way such that we don't need to rewrite them for each of
	 * the variations below.
	 *
	 *   ECN variations
	 *   DF bit set on inner pak
	 *   gre key added - need netlink changes
	 *   outgoing MTU variations - need netlink changes
	 *
	 */

	/* ECN encap
	 *
	 * RFC 3168, section 9.1.1 full functionality.
	 * Copy the ECN codepoint of the inside header to the outside header
	 * on encapsulation if the inside header is not-ECT or ECT, and to
	 * set the ECN codepoint of the outside header to ECT(0) if the ECN
	 * codepoint of the inside header is CE.
	 *
	 * ECN_NOT_ECT = 0  => 0
	 * ECN_ECT_1   = 1  => 1
	 * ECN_ECT_0   = 2  => 2
	 * ECN_CE      = 3  => 2
	 */

	/* inside 00 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_IP_ECN,
				 IPTOS_ECN_NOT_ECT);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_assert_internal(exp_ip_outer[0] != NULL);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_NOT_ECT);

	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 01 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_IP_ECN,
				 IPTOS_ECN_ECT1);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 10 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip,
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* inside 11 */
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_IP_ECN,
				 IPTOS_ECN_CE);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0],
				 DP_TEST_SET_IP_ECN, IPTOS_ECN_ECT0);
		dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/*
	 * Fragmentation and ICMP generation:
	 *
	 * Loop through the following, but do it via copy paste
	 * so that it is easier to follow what is happenning and
	 * what is expected than it would be with real loops.
	 *
	 * input size: 1400, 1476, 1477
	 * DF:         set, unset
	 * tunnel MTU: 1476, 1376
	 * output MTU: 1500, 1400
	 * PMTU:       on, off
	 * Key:        set, unset
	 */

	/* Expected paks when we fragment into a tunnel. */
	struct iphdr *frag_outer[2];
	struct iphdr *frag_payload[2];
	struct rte_mbuf *frag_payload_m[2];

	/*
	 * Looping through input sizes.
	 */
	/* 1400 */
	len = 1400 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1476 */
	len = 1476 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1477 */
	len = 1477 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	/*
	 * Set frag 0 which is the last x bytes of the pak,
	 * then frag 1 which is the first 'mtu' bytes
	 */
	uint16_t frag_sizes[2] = {
		1,
		1476 - sizeof(struct iphdr),
	};
	int ret;
	ret = dp_test_ipv4_fragment_packet(m, frag_payload_m, 2, frag_sizes, 0);
	dp_test_fail_unless(ret == 2,
			    "dp_test_ipv4_fragment_packet failed: %s",
			    strerror(-ret));

	frag_payload[0] = iphdr(frag_payload_m[0]);
	frag_payload[1] = iphdr(frag_payload_m[1]);
	gre_test_build_expected_pak(&exp_frag, frag_payload, frag_outer, 2);
	dp_test_assert_internal(exp_frag != NULL);
	rte_pktmbuf_free(frag_payload_m[0]);
	rte_pktmbuf_free(frag_payload_m[1]);

	dp_test_pak_receive(m, "dp1T1", exp_frag);

	/*
	 * Set the DF bit then go through the lengths again.
	 */
	/* 1400 */
	len = 1400 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m, dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0], DP_TEST_SET_DF, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1476 */
	len = 1476 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);
	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);
	gre_test_build_expected_pak(&exp_no_frag, &inner_ip,
				    exp_ip_outer, 1);
	dp_test_set_pak_ip_field(exp_ip_outer[0], DP_TEST_SET_DF, 1);
	dp_test_pak_receive(m, "dp1T1", exp_no_frag);

	/* 1477 Expect an icmp generated here. */
	len = 1477 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("1.1.1.2", "10.0.0.1",
				    1, &len);
	(void)dp_test_pktmbuf_eth_init(m,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	inner_ip = iphdr(m);
	dp_test_set_pak_ip_field(inner_ip, DP_TEST_SET_DF, 1);

	/* Expected paks when we generate an icmp. */
	struct iphdr *icmp_outer;

	gre_test_build_expected_icmp_pak(&exp_icmp, &inner_ip, &icmp_outer, 1,
					 sizeof(struct iphdr) + 576);
	dp_test_set_pak_ip_field(icmp_outer, DP_TEST_SET_TOS, 0xc0);
	exp_icmp->oif_name[0] = "dp1T1";

	dp_test_pak_receive(m, "dp1T1", exp_icmp);

	/* And now clean up all the state we added. */
	dp_test_gre_teardown_tunnel(TEST_VRF, "1.1.2.1", "1.1.2.2");
} DP_END_TEST;
