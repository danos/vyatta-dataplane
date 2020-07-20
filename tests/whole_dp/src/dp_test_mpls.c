/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Dataplane MPLS unit tests
 */

#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "in_cksum.h"
#include "mpls/mpls_forward.h"
#include "ecmp.h"
#include "commands.h"

#include "dp_test/dp_test_macros.h"
#include "dp_test_console.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_npf_fw_lib.h"

#define TEST_VRF 50

static void mpls_ttl_default_config(void)
{
	dp_test_console_request_reply("mpls ipttlpropagate enable", false);
	dp_test_console_request_reply("mpls defaultttl -1", false);
}

DP_DECL_TEST_SUITE(mpls);

DP_DECL_TEST_CASE(mpls, mpls_config,
		  NULL, NULL);

DP_START_TEST(mpls_config, imp_route_add_del)
{
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an labelled route entry */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo lbls 122");
	/* Remove it */
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo lbls 122");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

/*
 * Test add/remove of a multipath IP route with out labels.  Note: we
 * may well never configure multipath routes with single outlabels in
 * real life as for IGP routes we will probably just have a single
 * path + outlabel which identifies the corresponding lswap which will
 * do the actual loadbalancing. However for BGP VPN multipath we will
 * has multiple paths, each with 2 out labels where the bottom label
 * will identify a different via for each path.
 */
DP_START_TEST(mpls_config, imp_ecmp_route_add_del)
{
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an labelled route entry */
	dp_test_netlink_add_route("10.73.2.0/24 "
				  " nh int:lo lbls 122"
				  " nh int:lo lbls 133");
	/* Remove it */
	dp_test_netlink_del_route("10.73.2.0/24"
				  " nh int:lo lbls 122"
				  " nh int:lo lbls 133");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST(mpls_config, lswap_route_add_del)
{
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an labelled route entry */
	dp_test_netlink_add_route("222 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 122");
	/* Remove it */
	dp_test_netlink_del_route("222 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 122");
	/* Re-add but modified  */
	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp3T3 lbls 133");
	/* Remove again */
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp3T3 lbls 133");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST(mpls_config, lswap_route6_add_del)
{
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an labelled route entry */
	dp_test_netlink_add_route(
		"222 mpt:ipv6 nh 2002::2:2:1 int:dp2T2 lbls 122");
	/* Remove it */
	dp_test_netlink_del_route(
		"222 mpt:ipv6 nh 2002::2:2:1 int:dp2T2 lbls 122");
	/* Re-add but modified  */
	dp_test_netlink_add_route(
		"222 mpt:ipv6 nh 2003::3:3:1 int:dp3T3 lbls 133");
	/* Remove again */
	dp_test_netlink_del_route(
		"222 mpt:ipv6 nh 2003::3:3:1 int:dp3T3 lbls 133");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST(mpls_config, lswap_ecmp_route_add_del)
{
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an labelled route entry */
	dp_test_netlink_add_route("222 mpt:ipv4"
				  " nh 2.2.2.1 int:dp2T2 lbls 122"
				  " nh 3.3.3.1 int:dp3T3 lbls 133");
	/* Remove it */
	dp_test_netlink_del_route("222 mpt:ipv4"
				  " nh 2.2.2.1 int:dp2T2 lbls 122"
				  " nh 3.3.3.1 int:dp3T3 lbls 133");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST(mpls_config, lswap_ecmp_route6_add_del)
{
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an labelled route entry */
	dp_test_netlink_add_route("222 mpt:ipv6"
				  " nh 2002::2:2:1 int:dp2T2 lbls 122"
				  " nh 2003::3:3:1 int:dp3T3 lbls 133");
	/* Remove it */
	dp_test_netlink_del_route("222 mpt:ipv6"
				  " nh 2002::2:2:1 int:dp2T2 lbls 122"
				  " nh 2003::3:3:1 int:dp3T3 lbls 133");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, lswap_fwd_simple, NULL, NULL);
DP_START_TEST(lswap_fwd_simple, simple)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	label_t labels[2];
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 222;
	test_pak = dp_test_create_mpls_pak(
		1, labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL},
		payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;

	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	rte_pktmbuf_free(payload_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str);

} DP_END_TEST;

DP_START_TEST(lswap_fwd_simple, multilabel)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	label_t labels[DP_TEST_MAX_LBLS];
	uint8_t ttls[DP_TEST_MAX_LBLS];
	int len = 22;
	int i, nlbls;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str);

	for (nlbls = 2; nlbls <= DP_TEST_MAX_LBLS; nlbls++) {

		/* Create ip packet to be payload */
		payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
						      1, &len);

		/* Create the mpls packet that encapsulates it */
		for  (i = 0; i < nlbls; i++) {
			labels[i] = 222 + i;
			ttls[i] = DP_TEST_PAK_DEFAULT_TTL;
		}
		test_pak = dp_test_create_mpls_pak(nlbls, labels,
						   ttls, payload_pak);

		(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

		/*
		 * Expected packet
		 */
		labels[0] = 22;
		ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;

		expected_pak = dp_test_create_mpls_pak(nlbls, labels,
						       ttls, payload_pak);
		(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

		exp = dp_test_exp_create(expected_pak);
		rte_pktmbuf_free(expected_pak);
		rte_pktmbuf_free(payload_pak);
		dp_test_exp_set_oif_name(exp, "dp2T2");

		/* now send test pak and check we get expected back */
		dp_test_pak_receive(test_pak, "dp1T1", exp);
	}

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str);

} DP_END_TEST;

DP_START_TEST(lswap_fwd_simple, nondp_intf)
{
	struct rte_mbuf *payload_pak;
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	label_t labels[DP_TEST_MAX_LBLS];
	uint8_t ttls[DP_TEST_MAX_LBLS];
	const char *nh_mac_str;
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */
	dp_test_intf_nondp_create("nondp1");
	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:nondp1 lbls 22");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 222;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	test_pak = dp_test_create_mpls_pak(1, labels,
					   ttls, payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:nondp1 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str);
	dp_test_intf_nondp_delete("nondp1");

} DP_END_TEST;

DP_START_TEST(lswap_fwd_simple, noroute)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	test_pak = dp_test_create_mpls_pak(
		1, (label_t []){222},
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL}, payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST(lswap_fwd_simple, fwding_disabled)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");
	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	test_pak = dp_test_create_mpls_pak(
		1, (label_t []){222},
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL}, payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str);
} DP_END_TEST;

DP_START_TEST(lswap_fwd_simple, simple6)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	label_t labels[2];
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route(
		"222 mpt:ipv6 nh 2003:3:3::1 int:dp2T2 lbls 22");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2003:3:3::1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 222;
	test_pak = dp_test_create_mpls_pak(
		1, labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL},
		payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;

	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	rte_pktmbuf_free(payload_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"222 mpt:ipv6 nh 2003:3:3::1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "2003:3:3::1", nh_mac_str);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, lswap_fwd_expnull, NULL, NULL);
DP_START_TEST(lswap_fwd_expnull, simple)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	label_t labels[2];
	uint8_t ttls[2];
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 0;
	labels[1] = 222;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = 10;

	test_pak =
		dp_test_create_mpls_pak(2, labels, ttls, payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;

	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	rte_pktmbuf_free(payload_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, pop_lbl_fwd, NULL, NULL);
DP_START_TEST(pop_lbl_fwd, simple)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	label_t labels[2];
	uint8_t ttls[2];
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route(
		"666 nh 3.3.3.1 int:dp2T2 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 666;
	labels[1] = 33;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;

	test_pak =
		dp_test_create_mpls_pak(2, labels, ttls, payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 33;

	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(payload_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"666 nh 3.3.3.1 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str);

} DP_END_TEST;

DP_START_TEST(pop_lbl_fwd, unlabeled_nh)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	label_t labels[2];
	uint8_t ttls[2];
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("666 nh 3.3.3.1 int:dp2T2");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 666;
	labels[1] = 33;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;

	test_pak =
		dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route("666 nh 3.3.3.1 int:dp2T2");
	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, imp_fwd_simple, NULL, NULL);
DP_START_TEST(imp_fwd_simple, simple)
{
	struct iphdr *ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo lbls 122");

	/*
	 * Test packet
	 */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;
	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1},
		test_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	ip = dp_test_get_mpls_pak_payload(expected_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo lbls 122");
	dp_test_netlink_del_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

} DP_END_TEST;

DP_START_TEST(imp_fwd_simple, twolabels)
{
	struct iphdr *ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	uint8_t ttls[2];
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo "
				  "lbls 122 222");

	/*
	 * Test packet
	 */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;
	expected_labels[1] = 222;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL - 1;
	expected_pak = dp_test_create_mpls_pak(2, expected_labels, ttls,
					       test_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	ip = dp_test_get_mpls_pak_payload(expected_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo "
				  "lbls 122 222");
	dp_test_netlink_del_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

} DP_END_TEST;

DP_START_TEST(imp_fwd_simple, threelabels)
{
	struct iphdr *ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	label_t expected_labels[3];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	uint8_t ttls[3];
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo "
				  "lbls 122 222 333");

	/*
	 * Test packet
	 */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;
	expected_labels[1] = 222;
	expected_labels[2] = 333;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL - 1;
	ttls[2] = DP_TEST_PAK_DEFAULT_TTL - 1;
	expected_pak = dp_test_create_mpls_pak(3, expected_labels, ttls,
					       test_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	ip = dp_test_get_mpls_pak_payload(expected_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo "
				  "lbls 122 222 333");
	dp_test_netlink_del_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

} DP_END_TEST;

DP_START_TEST(imp_fwd_simple, nlabels)
{
	struct iphdr *ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	label_t expected_labels[DP_TEST_MAX_LBLS];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	uint8_t ttls[DP_TEST_MAX_LBLS];
	int i, nlbls, len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	for (nlbls = 2; nlbls <= DP_TEST_MAX_LBLS; nlbls++) {
		char lstack_str[TEST_MAX_CMD_LEN + 1] = {'\0'};
		char label_str[TEST_MAX_CMD_LEN + 1];
		char route1[TEST_MAX_CMD_LEN + 1];

		for (i = 0; i < nlbls; i++) {
			snprintf(label_str, sizeof(label_str), " %d", 122 + i);
			strncat(lstack_str, label_str, TEST_MAX_CMD_LEN);
			expected_labels[i] = 122 + i;
			ttls[i] = DP_TEST_PAK_DEFAULT_TTL - 1;
		}

		/* Add the route / nh arp we want the packet to follow */
		expected_labels[0] = 22;
		snprintf(route1, TEST_MAX_CMD_LEN,
			 "10.73.2.0/24 nh int:lo lbls %s", lstack_str);
		dp_test_netlink_add_route(route1);

		/*
		 * Test packet
		 */
		test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
						   1, &len);
		(void)dp_test_pktmbuf_eth_init(
			test_pak,
			dp_test_intf_name2mac_str("dp1T1"),
			NULL, RTE_ETHER_TYPE_IPV4);

		/*
		 * Expected packet
		 */
		expected_pak = dp_test_create_mpls_pak(nlbls, expected_labels,
						       ttls, test_pak);
		(void)dp_test_pktmbuf_eth_init(
			expected_pak,
			nh_mac_str,
			dp_test_intf_name2mac_str("dp2T2"),
			RTE_ETHER_TYPE_MPLS);

		ip = dp_test_get_mpls_pak_payload(expected_pak);
		dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
					 DP_TEST_PAK_DEFAULT_TTL - 1);

		exp = dp_test_exp_create(expected_pak);
		rte_pktmbuf_free(expected_pak);
		dp_test_exp_set_oif_name(exp, "dp2T2");

		dp_test_pak_receive(test_pak, "dp1T1", exp);

		/* Clean up */
		dp_test_netlink_del_route(route1);
	}

	/* Clean up */
	dp_test_netlink_del_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

} DP_END_TEST;

DP_START_TEST(imp_fwd_simple, unlabeled)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route(
		"123 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls imp-null");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo lbls 123");

	/*
	 * Test packet
	 */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo lbls 123");
	dp_test_netlink_del_route(
		"123 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

} DP_END_TEST;

DP_START_TEST(imp_fwd_simple, nondp_intf)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_intf_nondp_create("nondp1");
	dp_test_netlink_add_route(
		"123 mpt:ipv4 nh 2.2.2.1 int:nondp1 lbls imp-null");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo lbls 123");

	/*
	 * Test packet
	 */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo lbls 123");
	dp_test_netlink_del_route(
		"123 mpt:ipv4 nh 2.2.2.1 int:nondp1 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_intf_nondp_delete("nondp1");
} DP_END_TEST;

DP_START_TEST(imp_fwd_simple, drop)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo lbls 123");

	/*
	 * Add a label route - we don't use it, but need it to create
	 * the label table
	 */
	dp_test_netlink_add_route("124 nh 2.2.2.1 int:dp2T2 lbls imp-null");

	/*
	 * Test 1: no route for internal label 123, packet should be dropped.
	 */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 2: deag by using exp-null label, packet should be dropped.
	 */
	dp_test_netlink_replace_route("10.73.2.0/24 nh int:lo lbls 0");
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("124 nh 2.2.2.1 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo lbls 0");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, imp_ipv6_fwd_simple, NULL, NULL);
DP_START_TEST(imp_ipv6_fwd_simple, simple)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[1];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_netlink_set_mpls_forwarding("dp1T2", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route("122 mpt:ipv6 nh 2.2.2.1 int:dp1T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T2", "2.2.2.1", nh_mac_str);

	/* Add an route entry for the local label we are about to use */
	dp_test_netlink_add_route("2088:88::/48 nh int:lo lbls 122");

	/* Create ip packet to be payload */
	test_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	/*
	 * Expected packet
	 */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					      1, &len);
	dp_test_ipv6_decrement_ttl(payload_pak);
	expected_labels[0] = 22;
	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T2"),
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(payload_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("2088:88::/48 nh int:lo lbls 122");
	dp_test_netlink_del_route("122 mpt:ipv6 nh 2.2.2.1 int:dp1T2 lbls 22");
	dp_test_netlink_del_neigh("dp1T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T2", false);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
} DP_END_TEST;

DP_START_TEST(imp_ipv6_fwd_simple, twolabels)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	uint8_t ttls[2];
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_netlink_set_mpls_forwarding("dp1T2", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route("122 mpt:ipv6 nh 2.2.2.1 int:dp1T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T2", "2.2.2.1", nh_mac_str);

	/* Add an route entry for the local label we are about to use */
	dp_test_netlink_add_route("2077:77::/48 nh int:lo lbls 122 223");
	dp_test_netlink_add_route("2088:88::/48 nh int:lo lbls 122 222");

	/* Create ip packet to be payload */
	test_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	/*
	 * Expected packet
	 */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					      1, &len);
	dp_test_ipv6_decrement_ttl(payload_pak);
	expected_labels[0] = 22;
	expected_labels[1] = 222;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL - 1;
	expected_pak = dp_test_create_mpls_pak(
		2, expected_labels, ttls, payload_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T2"),
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(payload_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("2077:77::/48 nh int:lo lbls 122 223");
	dp_test_netlink_del_route("2088:88::/48 nh int:lo lbls 122 222");
	dp_test_netlink_del_route("122 mpt:ipv6 nh 2.2.2.1 int:dp1T2 lbls 22");
	dp_test_netlink_del_neigh("dp1T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T2", false);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
} DP_END_TEST;

DP_START_TEST(imp_ipv6_fwd_simple, threelabels)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[3];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	uint8_t ttls[3];
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_netlink_set_mpls_forwarding("dp1T2", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route("122 mpt:ipv6 nh 2.2.2.1 int:dp1T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T2", "2.2.2.1", nh_mac_str);

	/* Add an route entry for the local label we are about to use */
	dp_test_netlink_add_route("2077:77::/48 nh int:lo lbls 122 222 444");
	dp_test_netlink_add_route("2088:88::/48 nh int:lo lbls 122 222 333");

	/* Create ip packet to be payload */
	test_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	/*
	 * Expected packet
	 */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					      1, &len);
	dp_test_ipv6_decrement_ttl(payload_pak);
	expected_labels[0] = 22;
	expected_labels[1] = 222;
	expected_labels[2] = 333;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL - 1;
	ttls[2] = DP_TEST_PAK_DEFAULT_TTL - 1;
	expected_pak = dp_test_create_mpls_pak(
		3, expected_labels, ttls, payload_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T2"),
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(payload_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T2");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("2077:77::/48 nh int:lo lbls 122 222 444");
	dp_test_netlink_del_route("2088:88::/48 nh int:lo lbls 122 222 333");
	dp_test_netlink_del_route("122 mpt:ipv6 nh 2.2.2.1 int:dp1T2 lbls 22");
	dp_test_netlink_del_neigh("dp1T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T2", false);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
} DP_END_TEST;

DP_START_TEST(imp_ipv6_fwd_simple, nlabels)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	label_t expected_labels[DP_TEST_MAX_LBLS];
	struct rte_mbuf *test_pak, *payload_pak;
	const char *nh_mac_str;
	uint8_t ttls[DP_TEST_MAX_LBLS];
	int i, nlbls, len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_netlink_set_mpls_forwarding("dp1T2", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route("122 mpt:ipv6 nh 2.2.2.1 int:dp1T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T2", "2.2.2.1", nh_mac_str);

	for (nlbls = 2; nlbls <= DP_TEST_MAX_LBLS; nlbls++) {
		char lstack_str[TEST_MAX_CMD_LEN + 1] = {'\0'};
		char label_str[TEST_MAX_CMD_LEN + 1];
		char route1[TEST_MAX_CMD_LEN + 1];

		for (i = 0; i < nlbls; i++) {
			snprintf(label_str, sizeof(label_str), " %d", 122 + i);
			strncat(lstack_str, label_str, TEST_MAX_CMD_LEN);
			expected_labels[i] = 122 + i;
			ttls[i] = DP_TEST_PAK_DEFAULT_TTL - 1;
		}

		/* Add an route entry for the local label we are about to use */
		expected_labels[0] = 22;
		snprintf(route1, TEST_MAX_CMD_LEN,
			 "2088:88::/48 nh int:lo lbls %s", lstack_str);
		dp_test_netlink_add_route(route1);

		/*
		 * Test packet
		 */
		test_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
						   1, &len);
		(void)dp_test_pktmbuf_eth_init(
			test_pak,
			dp_test_intf_name2mac_str("dp1T1"),
			DP_TEST_INTF_DEF_SRC_MAC,
			RTE_ETHER_TYPE_IPV6);

		/*
		 * Expected packet
		 */
		payload_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
						      1, &len);
		dp_test_ipv6_decrement_ttl(payload_pak);

		expected_pak = dp_test_create_mpls_pak(nlbls, expected_labels,
						       ttls, payload_pak);
		(void)dp_test_pktmbuf_eth_init(
			expected_pak,
			nh_mac_str,
			dp_test_intf_name2mac_str("dp1T2"),
			RTE_ETHER_TYPE_MPLS);

		exp = dp_test_exp_create(expected_pak);
		rte_pktmbuf_free(payload_pak);
		rte_pktmbuf_free(expected_pak);
		dp_test_exp_set_oif_name(exp, "dp1T2");

		dp_test_pak_receive(test_pak, "dp1T1", exp);

		/* Clean up */
		dp_test_netlink_del_route(route1);
	}

	/* Clean up */
	dp_test_netlink_del_route("122 mpt:ipv6 nh 2.2.2.1 int:dp1T2 lbls 22");
	dp_test_netlink_del_neigh("dp1T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T2", false);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");

} DP_END_TEST;

DP_START_TEST(imp_ipv6_fwd_simple, unlabeled)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_netlink_set_mpls_forwarding("dp1T2", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route("122 mpt:ipv6 nh 5::2 int:dp1T2 "
				  "lbls imp-null");
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp1T2", "5::2", nh_mac_str);

	/* Add an route entry for the local label we are about to use */
	dp_test_netlink_add_route("2088:88::/48 nh int:lo lbls 122");

	/* Create ip packet to be payload */
	test_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	/*
	 * Expected packet
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T2");

	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));
	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T2"),
				       RTE_ETHER_TYPE_IPV6);

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("2088:88::/48 nh int:lo lbls 122");
	dp_test_netlink_del_route("122 mpt:ipv6 nh 5::2 int:dp1T2 "
				  "lbls imp-null");
	dp_test_netlink_del_neigh("dp1T2", "5::2", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T2", false);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
} DP_END_TEST;

DP_START_TEST(imp_ipv6_fwd_simple, nondp_intf)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_netlink_set_mpls_forwarding("dp1T2", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_intf_nondp_create("nondp1");
	dp_test_netlink_add_route("122 mpt:ipv6 nh 5::2 int:nondp1 "
				  "lbls imp-null");
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp1T2", "5::2", nh_mac_str);

	/* Add an route entry for the local label we are about to use */
	dp_test_netlink_add_route("2088:88::/48 nh int:lo lbls 122");

	/* Create ip packet to be payload */
	test_pak = dp_test_create_ipv6_pak("2099:99::", "2088:88::",
					   1, &len);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	/*
	 * Expected packet
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("2088:88::/48 nh int:lo lbls 122");
	dp_test_netlink_del_route("122 mpt:ipv6 nh 5::2 int:nondp1 "
				  "lbls imp-null");
	dp_test_netlink_del_neigh("dp1T2", "5::2", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T2", false);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_intf_nondp_delete("nondp1");
} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, disp_fwd_expnull, NULL, NULL);
DP_START_TEST(disp_fwd_expnull, simple)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	label_t labels[2];
	int len = 22;

	/*
	 * Add firewall rule to test that IP features aren't run for
	 * traffic arriving as MPLS
	 */
	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "5000",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "dst-addr=10.99.0.0/24",
		},
		NULL_RULE
	};
	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1",
		.enable = 1,
		.attach_point = "dp1T1",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/*
	 * Set up the input interface address - currently
	 * we need this to prevent the pkt from being dropped when
	 * it is reswitched as IP.
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/* Set up the output interface address for realism */
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* IP route that our packet will match */
	dp_test_netlink_add_route("10.99.0.0/24 nh 5.0.0.2 int:dp2T2");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 dp_test_intf_name2mac_str("dp1T1"),
				 NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Test that the firewall rule is working
	 */
	test_pak = dp_test_cp_pak(payload_pak);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* test packet is payload encapsulated with explicit null ipv4 */
	labels[0] = 0;
	test_pak =
		dp_test_create_mpls_pak(1, labels,
					(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as payload packet except
	 *  TTL will have been decremented and it has an ether header
	 * from the uut..
	 */
	expected_pak = payload_pak;
	dp_test_ipv4_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_npf_fw_del(&fw, false);
	dp_test_netlink_del_neigh("dp2T2", "5.0.0.2", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route("10.99.0.0/24 nh 5.0.0.2 int:dp2T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

} DP_END_TEST;

/* Packet with exp-null label with invalid packets */
DP_START_TEST(disp_fwd_expnull, invalid_paks)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	struct iphdr *ip;
	int len = 22;
	int newlen;

	/*
	 * Set up the input interface address - currently
	 * we need this to prevent the pkt from being dropped when
	 * it is reswitched as IP.
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* IP route that our packet will match */
	dp_test_netlink_add_route("10.99.0.0/24 nh 5.0.0.2 int:dp2T2");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);

	/* test packet is payload encapsulated with explicit null ipv4 */
	test_pak = dp_test_create_mpls_pak(1, (label_t[]){0},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/*
	 * Test 1 - check that the payload packet without errors is
	 * forwarded OK (i.e. that we haven't cocked up any of the
	 * parameters above and that we're testing what we think we're
	 * testing).
	 */
	expected_pak = dp_test_cp_pak(payload_pak);

	dp_test_ipv4_decrement_ttl(expected_pak);
	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 2 - truncate the payload and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(1, (label_t[]){0},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	/*
	 * set the packet length so that it only includes 1 byte of
	 * payload IP packet
	 */
	newlen = (char *)ip - rte_pktmbuf_mtod(test_pak, char *) + 1;
	rte_pktmbuf_trim(test_pak, test_pak->pkt_len - newlen);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 3 - make the ip hdr len too small and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(1, (label_t[]){0},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ip->ihl = DP_TEST_PAK_DEFAULT_IHL - 1;
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 4 - make the checksum invalid and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(1, (label_t[]){0},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ip->check = 0xdead;
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 5 - make the IP packet length too big and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(1, (label_t[]){0},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ip->tot_len = htons(2000);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 6 - make the IP packet length smaller than the header
	 * length and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(1, (label_t[]){0},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ip->tot_len = htons(sizeof(struct iphdr) - 1);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 7 - packet destined to loopback address - check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(1, (label_t[]){0},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ck_assert_msg(inet_pton(AF_INET, "127.0.0.1", &ip->daddr) == 1,
		      "Couldn't parse ip address");
	ip->tot_len = htons(sizeof(struct iphdr) - 1);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	rte_pktmbuf_free(payload_pak);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_neigh("dp2T2", "5.0.0.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_netlink_del_route("10.99.0.0/24 nh 5.0.0.2 int:dp2T2");
} DP_END_TEST;

/* Packet with exp-null label destined to a local address */
DP_START_TEST(disp_fwd_expnull, local)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	label_t labels[2];
	int len = 22;

	/*
	 * Set up the input interface address - currently
	 * we need this to prevent the pkt from being dropped when
	 * it is reswitched as IP.
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "1.1.1.1",
					      1, &len);

	/* test packet is payload encapsulated with explicit null ipv4 */
	labels[0] = 0;
	test_pak =
	  dp_test_create_mpls_pak(1, labels,
				  (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
				  payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/*
	 * Decapsulated ip packet will be same as payload packet -
	 * EXCEPT for TTL which will have been decremented.
	 * (TTL is decremented by MPLS when it switches on exp-null
	 * and then propagated to IP).
	 */
	expected_pak = payload_pak;
	dp_test_ipv4_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	/* This should be a no-op */
	dp_test_netlink_set_mpls_forwarding("dp2T2", false);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, disp_fwd_ipv4, NULL, NULL);
DP_START_TEST(disp_fwd_ipv4, simple)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route(
		"52 mpt:ipv4 nh 5.0.0.2 int:dp2T2 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);

	test_pak = dp_test_create_mpls_pak(1, (label_t []){52},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as test packet except
	 *  TTL will have been decremented.
	 */
	expected_pak = payload_pak;

	dp_test_ipv4_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"52 mpt:ipv4 nh 5.0.0.2 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "5.0.0.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

} DP_END_TEST;

DP_START_TEST(disp_fwd_ipv4, invalid_pak)
{
	struct rte_mbuf *test_pak, *payload_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	struct iphdr *ip;
	int len = 22;
	int newlen;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route(
		"52 mpt:ipv4 nh 5.0.0.2 int:dp2T2 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);
	(void)dp_test_pktmbuf_eth_init(payload_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	test_pak = dp_test_create_mpls_pak(1, (label_t []){52},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	ip = dp_test_get_mpls_pak_payload(test_pak);
	/*
	 * set the packet length so that it only includes 1 byte of
	 * payload IP packet
	 */
	newlen = (char *)ip - rte_pktmbuf_mtod(test_pak, char *) + 1;
	rte_pktmbuf_trim(test_pak, test_pak->pkt_len - newlen);

	exp = dp_test_exp_create(payload_pak);
	rte_pktmbuf_free(payload_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"52 mpt:ipv4 nh 5.0.0.2 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "5.0.0.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

} DP_END_TEST;

DP_START_TEST(disp_fwd_ipv4, deag)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	label_t labels[2];
	int len = 22;

	/*
	 * Set up the input interface address
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_netlink_add_route(
		"122 mpt:ipv4 nh 0.0.0.0 int:lo lbls imp-null");

	/* Set up the output interface address */
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

	/* IP route that our packet will match */
	dp_test_netlink_add_route("10.99.0.0/24 nh 5.0.0.2 int:dp2T2");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 dp_test_intf_name2mac_str("dp1T1"),
				 NULL, RTE_ETHER_TYPE_IPV4);

	/* test packet is payload encapsulated with local label */
	labels[0] = 122;
	test_pak =
		dp_test_create_mpls_pak(1, labels,
					(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as payload packet except
	 * TTL will have been decremented and it has an ether header
	 * from the uut..
	 */
	expected_pak = payload_pak;
	dp_test_ipv4_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route("10.99.0.0/24 nh 5.0.0.2 int:dp2T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "5.0.0.1/24");
	dp_test_netlink_del_route(
		"122 mpt:ipv4 nh 0.0.0.0 int:lo lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "5.0.0.2", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);

} DP_END_TEST;

DP_START_TEST(disp_fwd_ipv4, forus)
{
	unsigned int i;
	char ttl_buf[30];
	struct {
		bool ipttlpropagate;
	} test_data[] = {
		{ true }, { false },
	};

	/*
	 * Set up the input interface address
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_netlink_add_route(
		"122 mpt:ipv4 nh 0.0.0.0 int:lo lbls imp-null");

	/* Set up the output interface address */
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
		struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
		struct dp_test_expected *exp;
		label_t labels[2];
		int len = 22;

		/* Configure ttl propagation */
		snprintf(ttl_buf, sizeof(ttl_buf), "mpls ipttlpropagate %sable",
			 test_data[i].ipttlpropagate ? "en" : "dis");
		dp_test_console_request_reply(ttl_buf, false);

		/* Create ip packet to be payload */
		payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "1.1.1.1",
						      1, &len);
		dp_test_pktmbuf_eth_init(payload_pak,
					 dp_test_intf_name2mac_str("dp1T1"),
					 NULL, RTE_ETHER_TYPE_IPV4);

		/* Test packet is payload encapsulated with local label */
		labels[0] = 122;
		test_pak = dp_test_create_mpls_pak(
			1, labels,
			(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL}, payload_pak);

		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T1"),
					 NULL,
					 RTE_ETHER_TYPE_MPLS);

		expected_pak = payload_pak;
		if (test_data[i].ipttlpropagate) {
			dp_test_set_pak_ip_field(iphdr(expected_pak),
						 DP_TEST_SET_TTL,
						 DP_TEST_PAK_DEFAULT_TTL - 1);
		} else {
			dp_test_set_pak_ip_field(iphdr(expected_pak),
						 DP_TEST_SET_TTL,
						 DP_TEST_PAK_DEFAULT_TTL);
		}
		exp = dp_test_exp_create(expected_pak);
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
		dp_test_pak_receive(test_pak, "dp1T1", exp);

		rte_pktmbuf_free(payload_pak);
	}

	/* Clean up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "5.0.0.1/24");
	dp_test_netlink_del_route(
		"122 mpt:ipv4 nh 0.0.0.0 int:lo lbls imp-null");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	mpls_ttl_default_config();

} DP_END_TEST;

DP_START_TEST(disp_fwd_ipv4, no_payload_type)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route(
		"52 nh 5.0.0.2 int:dp2T2 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);

	test_pak = dp_test_create_mpls_pak(1, (label_t []){52},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as test packet except
	 *  TTL will have been decremented.
	 */
	expected_pak = payload_pak;

	dp_test_ipv4_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"52 nh 5.0.0.2 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "5.0.0.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "5.0.0.1/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, disp_fwd_vpnv4, NULL, NULL);
DP_START_TEST(disp_fwd_vpnv4, simple)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	int len = 22;

	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "5.0.0.1/24",
						 TEST_VRF);

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route(
		"52 mpt:ipv4 nh 5.0.0.2 int:dp1T0 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp1T0", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);

	test_pak = dp_test_create_mpls_pak(1, (label_t []){52},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as test packet except
	 *  TTL will have been decremented.
	 */
	expected_pak = payload_pak;

	dp_test_ipv4_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"52 mpt:ipv4 nh 5.0.0.2 int:dp1T0 lbls imp-null");
	dp_test_netlink_del_neigh("dp1T0", "5.0.0.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "5.0.0.1/24",
						 TEST_VRF);
	dp_test_netlink_del_vrf(TEST_VRF, 0);

} DP_END_TEST;

DP_START_TEST(disp_fwd_vpnv4, deag)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	label_t labels[2];
	int len = 22;
	char route1[TEST_MAX_CMD_LEN + 1];
	char route2[TEST_MAX_CMD_LEN + 1];
	char lord[IFNAMSIZ + 1];

	dp_test_netlink_add_vrf(TEST_VRF, 1);
	dp_test_upstream_vrf_lookup_db(TEST_VRF, lord, NULL);

	/*
	 * Set up the input interface address
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	snprintf(route1, TEST_MAX_CMD_LEN,
		"122 mpt:ipv4 nh 0.0.0.0 int:%s lbls imp-null", lord);
	dp_test_netlink_add_route(route1);

	/* Set up the output interface address */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "5.0.0.1/24",
						 TEST_VRF);

	/* IP route that our packet will match */
	snprintf(route2, TEST_MAX_CMD_LEN,
		 "vrf:%d 10.99.0.0/24 nh 5.0.0.2 int:dp1T0", TEST_VRF);
	dp_test_netlink_add_route(route2);

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp1T0", "5.0.0.2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 dp_test_intf_name2mac_str("dp1T1"),
				 NULL, RTE_ETHER_TYPE_IPV4);

	/* test packet is payload encapsulated with local label */
	labels[0] = 122;
	test_pak =
		dp_test_create_mpls_pak(1, labels,
					(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as payload packet except
	 * TTL will have been decremented and it has an ether header
	 * from the uut..
	 */
	expected_pak = payload_pak;
	dp_test_ipv4_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route(route1);
	dp_test_netlink_del_route(route2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "5.0.0.1/24",
						 TEST_VRF);
	dp_test_netlink_del_neigh("dp1T0", "5.0.0.2", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_vrf(TEST_VRF, 0);

} DP_END_TEST;

DP_START_TEST(disp_fwd_vpnv4, forus)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	label_t labels[2];
	int len = 22;
	char route1[TEST_MAX_CMD_LEN + 1];
	char lord[IFNAMSIZ + 1];

	dp_test_netlink_add_vrf(TEST_VRF, 1);
	dp_test_upstream_vrf_lookup_db(TEST_VRF, lord, NULL);

	/*
	 * Set up the input interface address
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	snprintf(route1, TEST_MAX_CMD_LEN,
		 "122 mpt:ipv4 nh 0.0.0.0 int:%s lbls imp-null", lord);
	dp_test_netlink_add_route(route1);

	/* Set up the output interface address */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "5.0.0.1/24",
						 TEST_VRF);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "5.0.0.1",
					      1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 dp_test_intf_name2mac_str("dp1T1"),
				 NULL, RTE_ETHER_TYPE_IPV4);

	/* Test packet is payload encapsulated with local label */
	labels[0] = 122;
	test_pak =
		dp_test_create_mpls_pak(1, labels,
					(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* Expect test packet to be punted to kernel */
	expected_pak = test_pak;
	exp = dp_test_exp_create(expected_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route(route1);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "5.0.0.1/24",
						  TEST_VRF);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_vrf(TEST_VRF, 0);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, disp_fwd_ipv6, NULL, NULL);
DP_START_TEST(disp_fwd_ipv6, simple)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2005::1/64");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route(
		"52 mpt:ipv6 nh 2005::2 int:dp2T2 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "2005::2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2010:99::10",
					      1, &len);

	test_pak = dp_test_create_mpls_pak(1, (label_t []){52},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as test packet except
	 *  TTL will have been decremented.
	 */
	expected_pak = payload_pak;

	dp_test_ipv6_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"52 mpt:ipv6 nh 2005::2 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "2005::2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2005::1/64");
} DP_END_TEST;

DP_START_TEST(disp_fwd_ipv6, invalid_pak)
{
	struct rte_mbuf *test_pak, *payload_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	struct ip6_hdr *ip6;
	int len = 22;
	int newlen;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2005::1/64");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route(
		"52 mpt:ipv6 nh 5::2 int:dp2T2 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "5::2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2010:99::10",
					      1, &len);
	(void)dp_test_pktmbuf_eth_init(payload_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV6);

	test_pak = dp_test_create_mpls_pak(1, (label_t []){52},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	ip6 = dp_test_get_mpls_pak_payload(test_pak);
	/*
	 * set the packet length so that it only includes 1 byte of
	 * payload IPv6 packet
	 */
	newlen = (char *)ip6 - rte_pktmbuf_mtod(test_pak, char *) + 1;
	rte_pktmbuf_trim(test_pak, test_pak->pkt_len - newlen);

	exp = dp_test_exp_create(payload_pak);
	rte_pktmbuf_free(payload_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"52 mpt:ipv6 nh 5::2 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "5::2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2005::1/64");
} DP_END_TEST;

DP_START_TEST(disp_fwd_ipv6, no_payload_type)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2005::1/64");

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route(
		"52 nh 2005::2 int:dp2T2 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp2T2", "2005::2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2010:99::10",
					      1, &len);

	test_pak = dp_test_create_mpls_pak(1, (label_t []){52},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as test packet except
	 *  TTL will have been decremented.
	 */
	expected_pak = payload_pak;

	dp_test_ipv6_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"52 nh 2005::2 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_neigh("dp2T2", "2005::2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2005::1/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, disp_fwd_vpnv6, NULL, NULL);
DP_START_TEST(disp_fwd_vpnv6, simple)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	int len = 22;
	char lord[IFNAMSIZ + 1];

	/* Set up lord for the vrf */
	dp_test_netlink_add_vrf(TEST_VRF, 1);
	dp_test_upstream_vrf_lookup_db(TEST_VRF, lord, NULL);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "2005::1/64",
						 TEST_VRF);

	/*
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route(
		"52 mpt:ipv6 nh 2005::2 int:dp1T0 lbls imp-null");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp1T0", "2005::2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2010:99::10",
					      1, &len);

	test_pak = dp_test_create_mpls_pak(1, (label_t []){52},
					   (uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					   payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as test packet except
	 *  TTL will have been decremented.
	 */
	expected_pak = payload_pak;

	dp_test_ipv6_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route(
		"52 mpt:ipv6 nh 2005::2 int:dp1T0 lbls imp-null");
	dp_test_netlink_del_neigh("dp1T0", "2005::2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "2005::1/64",
						 TEST_VRF);
	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;

DP_START_TEST(disp_fwd_vpnv6, deag)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	const char *nh_mac_str;
	label_t labels[2];
	int len = 22;
	char route1[TEST_MAX_CMD_LEN + 1];
	char route2[TEST_MAX_CMD_LEN + 1];
	char lord[IFNAMSIZ + 1];

	/* Set up lord for the vrf */
	dp_test_netlink_add_vrf(TEST_VRF, 1);
	dp_test_upstream_vrf_lookup_db(TEST_VRF, lord, NULL);

	/*
	 * Set up the input interface address
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	snprintf(route1, TEST_MAX_CMD_LEN,
		"122 mpt:ipv6 nh 0.0.0.0 int:%s lbls imp-null", lord);
	dp_test_netlink_add_route(route1);

	/* Set up the output interface address */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "2005::1/64",
						 TEST_VRF);

	/* IP route that our packet will match */
	snprintf(route2, TEST_MAX_CMD_LEN,
		 "vrf:%d 1099:99::/64 nh 2005::2 int:dp1T0", TEST_VRF);
	dp_test_netlink_add_route(route2);

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:11";
	dp_test_netlink_add_neigh("dp1T0", "2005::2", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "1099:99::10",
					      1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 dp_test_intf_name2mac_str("dp1T1"),
				 NULL, RTE_ETHER_TYPE_IPV6);

	/* test packet is payload encapsulated with local label */
	labels[0] = 122;
	test_pak =
		dp_test_create_mpls_pak(1, labels,
					(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* encapsulated ip packet will be same as payload packet except
	 * TTL will have been decremented and it has an ether header
	 * from the uut..
	 */
	expected_pak = payload_pak;
	dp_test_ipv6_decrement_ttl(expected_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route(route1);
	dp_test_netlink_del_route(route2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "2005::1/64",
						 TEST_VRF);
	dp_test_netlink_del_neigh("dp1T0", "2005::2", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_vrf(TEST_VRF, 0);

} DP_END_TEST;

DP_START_TEST(disp_fwd_vpnv6, forus)
{
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	struct dp_test_expected *exp;
	label_t labels[2];
	int len = 22;
	char route1[TEST_MAX_CMD_LEN + 1];
	char lord[IFNAMSIZ + 1];

	/* Set up lord for the vrf */
	dp_test_netlink_add_vrf(TEST_VRF, 1);
	dp_test_upstream_vrf_lookup_db(TEST_VRF, lord, NULL);

	/*
	 * Set up the input interface address
	 * enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	snprintf(route1, TEST_MAX_CMD_LEN,
		 "122 mpt:ipv6 nh 0.0.0.0 int:%s lbls imp-null", lord);
	dp_test_netlink_add_route(route1);

	/* Set up the output interface address */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp2T2", "2005::1/64",
						 TEST_VRF);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv6_pak("2099:99::", "2005::1",
					      1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 dp_test_intf_name2mac_str("dp1T1"),
				 NULL, RTE_ETHER_TYPE_IPV6);

	/* Test packet is payload encapsulated with local label */
	labels[0] = 122;
	test_pak =
		dp_test_create_mpls_pak(1, labels,
					(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL},
					payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	/* Expect test packet to be punted to kernel */
	expected_pak = test_pak;
	exp = dp_test_exp_create(expected_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_route(route1);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected_vrf("dp2T2", "2005::1/64",
						  TEST_VRF);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_vrf(TEST_VRF, 0);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, imp_fwd_ecmp_simple, NULL, NULL);
DP_START_TEST(imp_fwd_ecmp_simple, ecmp)
{
	struct iphdr *ip;
	struct dp_test_expected *exp1, *exp2;
	struct rte_mbuf *expected_pak1, *expected_pak2;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak1, *test_pak2;
	const char *nh_mac_str1, *nh_mac_str2;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "3.3.3.3/24");

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the internal label we are about to use */

	dp_test_netlink_add_route("122 "
				  "nh 2.2.2.1 int:dp2T2 lbls 22 "
				  "nh 3.3.3.1 int:dp3T3 lbls 33 ");
	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str1);
	nh_mac_str2 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T3", "3.3.3.1", nh_mac_str2);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo lbls 122");

	/*
	 * Test packet
	 */
	test_pak1 = dp_test_create_ipv4_pak("10.73.0.1", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak1,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet1
	 */
	expected_labels[0] = 22;
	expected_pak1 = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL - 1},
		test_pak1);
	(void)dp_test_pktmbuf_eth_init(expected_pak1,
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	ip = dp_test_get_mpls_pak_payload(expected_pak1);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp1 = dp_test_exp_create(expected_pak1);
	rte_pktmbuf_free(expected_pak1);
	dp_test_exp_set_oif_name(exp1, "dp2T2");

	dp_test_pak_receive(test_pak1, "dp1T1", exp1);

	/*
	 *  Test packet2
	 */
	test_pak2 = dp_test_create_ipv4_pak("10.73.0.9", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak2,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);
	/*
	 * Expected packet2
	 */
	expected_labels[0] = 33;
	expected_pak2 = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL - 1},
		test_pak2);
	(void)dp_test_pktmbuf_eth_init(expected_pak2,
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_MPLS);

	ip = dp_test_get_mpls_pak_payload(expected_pak2);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp2 = dp_test_exp_create(expected_pak2);
	rte_pktmbuf_free(expected_pak2);
	dp_test_exp_set_oif_name(exp2, "dp3T3");

	dp_test_pak_receive(test_pak2, "dp1T1", exp2);

	/* Clean up */
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo lbls 122");
	dp_test_netlink_del_route("122 "
				  "nh 2.2.2.1 int:dp2T2 lbls 22 "
				  "nh 3.3.3.1 int:dp3T3 lbls 33 ");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp3T3", "3.3.3.1", nh_mac_str2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "3.3.3.3/24");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST(imp_fwd_ecmp_simple, ecmp_ipv6)
{
	struct dp_test_expected *exp1, *exp2;
	struct rte_mbuf *expected_pak1, *expected_pak2;
	struct rte_mbuf *payload_pak1, *payload_pak2;
	label_t expected_labels[1];
	struct rte_mbuf *test_pak1, *test_pak2;
	const char *nh_mac_str1, *nh_mac_str2;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "3.3.3.3/24");

	dp_test_netlink_set_mpls_forwarding("dp2T2", true);
	dp_test_netlink_set_mpls_forwarding("dp3T3", true);

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route("122 "
				  "nh 2002:2:2::1 int:dp2T2 lbls 22 "
				  "nh 3.3.3.1 int:dp3T3 lbls 33 ");

	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2002:2:2::1", nh_mac_str1);

	nh_mac_str2 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T3", "3.3.3.1", nh_mac_str2);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("2088:88::/48 nh int:lo lbls 122");

	/*
	 * Test packet
	 */
	test_pak1 = dp_test_create_udp_ipv6_pak("2099:99::", "2088:88::",
						1001, 1002, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak1,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);

	/*
	 * Expected packet1
	 */
	payload_pak1 = dp_test_create_udp_ipv6_pak("2099:99::", "2088:88::",
						   1001, 1002, 1, &len);
	dp_test_ipv6_decrement_ttl(payload_pak1);
	expected_labels[0] = 22;
	expected_pak1 = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak1);
	(void)dp_test_pktmbuf_eth_init(expected_pak1,
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	exp1 = dp_test_exp_create(expected_pak1);
	rte_pktmbuf_free(payload_pak1);
	rte_pktmbuf_free(expected_pak1);
	dp_test_exp_set_oif_name(exp1, "dp2T2");

	dp_test_pak_receive(test_pak1, "dp1T1", exp1);

	/*
	 *  Test packet2
	 */
	test_pak2 = dp_test_create_udp_ipv6_pak("2099:99::", "2088:88::",
						1111, 1005, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak2,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV6);
	/*
	 * Expected packet2
	 */
	payload_pak2 = dp_test_create_udp_ipv6_pak("2099:99::", "2088:88::",
						   1111, 1005, 1, &len);
	dp_test_ipv6_decrement_ttl(payload_pak2);
	expected_labels[0] = 33;
	expected_pak2 = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak2);
	(void)dp_test_pktmbuf_eth_init(expected_pak2,
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_MPLS);

	exp2 = dp_test_exp_create(expected_pak2);
	rte_pktmbuf_free(payload_pak2);
	rte_pktmbuf_free(expected_pak2);
	dp_test_exp_set_oif_name(exp2, "dp3T3");

	dp_test_pak_receive(test_pak2, "dp1T1", exp2);

	/* Clean up */
	dp_test_netlink_del_route("2088:88::/48 nh int:lo lbls 122");
	dp_test_netlink_del_route("122 "
				  "nh 2002:2:2::1 int:dp2T2 lbls 22 "
				  "nh 3.3.3.1 int:dp3T3 lbls 33 ");
	dp_test_netlink_del_neigh("dp2T2", "2002:2:2::1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp3T3", "3.3.3.1", nh_mac_str2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "3.3.3.3/24");

	dp_test_netlink_set_mpls_forwarding("dp2T2", false);
	dp_test_netlink_set_mpls_forwarding("dp3T3", false);
} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, lswap_fwd_ecmp_simple, NULL, NULL);
DP_START_TEST(lswap_fwd_ecmp_simple, ecmp)
{
	struct dp_test_expected *exp1, *exp2;
	struct rte_mbuf *expected_pak1, *expected_pak2;
	struct rte_mbuf *payload_pak1, *payload_pak2;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak1, *test_pak2;
	const char *nh_mac_str1, *nh_mac_str2;
	label_t labels[2];
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 "
				  "nh 3.3.3.1 int:dp2T2 lbls 22 "
				  "nh 4.4.4.1 int:dp3T3 lbls 33 ");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str1 = "aa:bb:cc:dd:ee:1";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str1);
	nh_mac_str2 = "aa:bb:cc:dd:ee:2";
	dp_test_netlink_add_neigh("dp3T3", "4.4.4.1", nh_mac_str2);

	/* Create ip packet to be payload */
	payload_pak1 = dp_test_create_ipv4_pak("99.59.12.42", "88.88.17.63",
					       1, &len);
	payload_pak2 = dp_test_create_ipv4_pak("99.99.0.1", "88.88.0.3",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 222;
	test_pak1 = dp_test_create_mpls_pak(
		1, labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL},
		payload_pak1);

	test_pak2 = dp_test_create_mpls_pak(
		1, labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL},
		payload_pak2);

	(void)dp_test_pktmbuf_eth_init(test_pak1,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);
	(void)dp_test_pktmbuf_eth_init(test_pak2,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);
	/*
	 * expected paks
	 */
	expected_labels[0] = 22;
	expected_pak1 = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak1);
	(void)dp_test_pktmbuf_eth_init(expected_pak1,
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);
	expected_labels[0] = 33;
	expected_pak2 = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1},
		payload_pak2);
	(void)dp_test_pktmbuf_eth_init(expected_pak2,
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_MPLS);

	exp1 = dp_test_exp_create(expected_pak1);
	dp_test_exp_set_oif_name(exp1, "dp2T2");

	exp2 = dp_test_exp_create(expected_pak2);
	dp_test_exp_set_oif_name(exp2, "dp3T3");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak1, "dp1T1", exp1);
	dp_test_pak_receive(test_pak2, "dp1T1", exp2);

	/* Clean up */
	rte_pktmbuf_free(payload_pak1);
	rte_pktmbuf_free(expected_pak1);
	rte_pktmbuf_free(payload_pak2);
	rte_pktmbuf_free(expected_pak2);

	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp3T3", "4.4.4.1", nh_mac_str2);

	dp_test_netlink_del_route("222 "
				  "nh 3.3.3.1 int:dp2T2 lbls 22 "
				  "nh 4.4.4.1 int:dp3T3 lbls 33 ");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

struct flow_fields {
	/*
	 * series control fields
	 */
	bool fix_dest;
	bool fix_labels;
	uint32_t count;
	/*
	 * resulting flow fields
	 * label stack
	 */
	uint32_t num_labels;
	label_t labels[DP_TEST_MAX_LBLS];
	char label_str[DP_TEST_MAX_LBLS][DP_TEST_MAX_PREFIX_STRING_LEN];
	/* ipv4 hdr */
	struct in_addr ip_src;
	struct in_addr ip_dst;
	char ip_src_str[DP_TEST_MAX_PREFIX_STRING_LEN];
	char ip_dst_str[DP_TEST_MAX_PREFIX_STRING_LEN];
	/* udp ports */
	uint16_t udp_src;
	uint16_t udp_dst;
	char udp_src_str[DP_TEST_MAX_PREFIX_STRING_LEN];
	char udp_dst_str[DP_TEST_MAX_PREFIX_STRING_LEN];
	/* string describing whole flow */
	char string[1000];
};

/*
 * Generate a series of flow field values
 * flow->count should be zero on the first call.
 * Returns false if the series has ended
 */
static bool
get_next_flow_field_combo(struct flow_fields *value)
{
	uint32_t i;

	if (value->count == 0) {
		if (!value->fix_labels)
			value->num_labels = 0;
		strcpy(value->ip_src_str, "10.0.0.1");
		if (!value->fix_dest)
			strcpy(value->ip_dst_str, "99.0.0.1");
		inet_pton(AF_INET, value->ip_src_str, &value->ip_src.s_addr);
		inet_pton(AF_INET, value->ip_dst_str, &value->ip_dst.s_addr);
		value->udp_src  = 27;
		value->udp_dst = 333;
	} else if (value->count <= 0xFFFF) {
		value->ip_src.s_addr = (uint32_t)(((value->count) & 0xFFFF) +
						  (value->count << 16));
		if (IN_LOOPBACK(value->ip_src.s_addr))
			value->ip_src.s_addr &= 0x0fffffff;

		if (!value->fix_dest) {
			value->ip_dst.s_addr =
				(uint32_t)(value->count +
					   (((value->count) & 0xFFFF) << 16));
			if (IN_LOOPBACK(value->ip_dst.s_addr))
				value->ip_dst.s_addr &= 0x0fffffff;
		}

		inet_ntop(AF_INET, &value->ip_src,
			  value->ip_src_str, sizeof(value->ip_src_str));
		inet_ntop(AF_INET, &value->ip_dst,
			  value->ip_dst_str, sizeof(value->ip_dst_str));


		value->udp_src += value->count;
		value->udp_dst += value->count;
		snprintf(value->udp_src_str, sizeof(value->udp_src_str), "%d",
			 value->udp_src);
		snprintf(value->udp_dst_str, sizeof(value->udp_dst_str), "%d",
			 value->udp_dst);

		if (!value->fix_labels) {
			uint32_t new_num_labels =
				(value->count * DP_TEST_MAX_LBLS) / 0x10000;

			if (new_num_labels > value->num_labels) {
				value->num_labels = new_num_labels;
				value->labels[value->num_labels-1] = 20;
			}

			for (i = 0; i < value->num_labels; i++)
				value->labels[i]++;
		}
	} else {
		return false;
	}
	/*
	 * Increment count and update description string
	 */
	value->count += 73;

	unsigned int written  = 0;

	for (i = 0; i < value->num_labels; i++)
		written += snprintf(value->string + written,
				    sizeof(value->string) - written,
				    "%u, ", value->labels[i]);
	/* lose the trailing ',' and ' ' */
	if (value->num_labels)
		written -= 2;

	written += snprintf(value->string + written,
			    sizeof(value->string) - written,
			    ": %s, %s: %d,%d",
			    value->ip_src_str, value->ip_dst_str,
			    value->udp_src, value->udp_dst);
	return true;
}



/*
 * A partial implementation of the label swap forwarding logic that we
 * can use to construct the expected pkt given an mpls pkt (and its
 * interesting constituent parts) and the lswap that it will match on.
 * Returns the expected struct (pkt, oif), hash value and nh_idx
 */
static struct dp_test_expected *
label_swap_monitor(const struct rte_mbuf *mpls_pak,
		   unsigned int num_labels,
		   const label_t *labels, uint8_t *ttls,
		   const uint16_t payload_ethertype,
		   struct rte_mbuf *payload_pak,
		   const struct dp_test_route *lswap,
		   char **nh_mac_str,
		   unsigned int *ret_hash_val,
		   unsigned int *ret_nh_idx)
{
	unsigned int hash_val, nh_idx;
	const char *expected_oif = NULL;
	struct rte_mbuf *expected_pak;
	unsigned int i;


	/*
	 * hash the packet
	 */
	hash_val = mpls_ecmp_hash(mpls_pak);
	nh_idx = ecmp_lookup(lswap->nh_cnt, hash_val);
	expected_oif = lswap->nh[nh_idx].nh_int;

	/*
	 * Now construct expected pak.
	 */
	if ((num_labels == 1) &&
	    (!lswap->nh[nh_idx].num_labels ||
	     lswap->nh[nh_idx].labels[0] == 3)) {
		/*
		 * Disposition to the payload pak
		 * lswap has imp-null outlabel and
		 * test pak has only 1 label.
		 * Propagate TTL from rx label to payload.
		 */
		expected_pak = dp_test_cp_pak(payload_pak);

		struct iphdr *ip = iphdr(expected_pak);
		dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
					 ttls[0] - 1);

		(void)dp_test_pktmbuf_eth_init(
			expected_pak,
			nh_mac_str[nh_idx],
			dp_test_intf_name2mac_str(lswap->nh[nh_idx].nh_int),
			RTE_ETHER_TYPE_IPV4);

	} else if ((num_labels > 1) &&
		   (!lswap->nh[nh_idx].num_labels ||
		    lswap->nh[nh_idx].labels[0] == 3)) {
		/*
		 * Disposition to mpls - pop top label
		 * propagate ttl from top label downwards.
		 */
		label_t new_labels[num_labels];
		uint8_t new_ttls[num_labels];

		for (i = 0; i < num_labels-1; i++) {
			new_labels[i] = labels[i+1];
			new_ttls[i] = ttls[i+1];
		}
		new_ttls[0] = ttls[0] - 1;
		expected_pak =
			_dp_test_create_mpls_pak(
				num_labels - 1,
				new_labels,
				new_ttls,
				payload_pak);

		(void)dp_test_pktmbuf_eth_init(
			expected_pak,
			nh_mac_str[nh_idx],
			dp_test_intf_name2mac_str(lswap->nh[nh_idx].nh_int),
			RTE_ETHER_TYPE_MPLS);
	} else if (num_labels > 1 || lswap->nh[nh_idx].num_labels) {
		/* label swap - top label is outlabel for nh */

		label_t new_labels[num_labels - 1 +
				   lswap->nh[nh_idx].num_labels];
		uint8_t new_ttls[num_labels - 1 +
				   lswap->nh[nh_idx].num_labels];

		/* new label stack consists of the nh's labels */
		for (i = 0; i < lswap->nh[nh_idx].num_labels; i++) {
			new_labels[i] =
				lswap->nh[nh_idx].labels[i];
			new_ttls[i] = ttls[0] - 1;
		}
		/* followed by all but the top label of the pkt */
		for (i = 0; i < num_labels - 1; i++) {
			new_labels[i + lswap->nh[nh_idx].num_labels] =
				labels[i + 1];
			new_ttls[i + lswap->nh[nh_idx].num_labels] =
				ttls[i + 1];
		}
		expected_pak =
			_dp_test_create_mpls_pak(
				num_labels - 1 +
				lswap->nh[nh_idx].num_labels,
				new_labels,
				new_ttls,
				payload_pak);

		(void)dp_test_pktmbuf_eth_init(
			expected_pak,
			nh_mac_str[nh_idx],
			dp_test_intf_name2mac_str(lswap->nh[nh_idx].nh_int),
			RTE_ETHER_TYPE_MPLS);
	} else {
		/* Unsupported combination */
		assert(0);
	}
	struct dp_test_expected *exp;

	exp = dp_test_exp_create(expected_pak);
	/* expected has a copy of the expected pak */
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, expected_oif);

	*ret_nh_idx = nh_idx;
	*ret_hash_val = hash_val;
	return exp;
}

static struct dp_test_expected *
label_imp_monitor(const struct rte_mbuf *ip_pak,
		  const struct dp_test_route *lswap,
		  char **nh_mac_str,
		  unsigned int *ret_hash_val,
		  unsigned int *ret_nh_idx)
{
	unsigned int hash_val, nh_idx;
	const char *expected_oif = NULL;
	struct rte_mbuf *expected_pak, *payload_pak;
	unsigned int i;
	uint8_t ttls[1];
	struct iphdr *ip;


	/*
	 * various conditions cause the ip packet to
	 * be dropped instead.
	 */
	ip = dp_pktmbuf_mtol3(ip_pak, struct iphdr *);
	if (IN_LOOPBACK(ntohl(ip->daddr)) ||
	    IN_LOOPBACK(ntohl(ip->saddr))) {
		struct dp_test_expected *exp;

		exp = dp_test_exp_create((struct rte_mbuf *)ip_pak);
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
		*ret_hash_val = 0;
		*ret_nh_idx = 0;
		return exp;
	}


	/*
	 * construct the internal mpls pak - it will have
	 * a copy of the ip pak with its ttl decremented.
	 */
	payload_pak = dp_test_cp_pak((struct rte_mbuf *)ip_pak);
	dp_test_ipv4_decrement_ttl(payload_pak);

	/* ttl propagated from ip */
	ttls[0] = iphdr(payload_pak)->ttl;

	/*
	 * hash the mpls packet
	 */
	hash_val = ecmp_mbuf_hash(payload_pak, RTE_ETHER_TYPE_IPV4);
	nh_idx = ecmp_lookup(lswap->nh_cnt, hash_val);
	expected_oif = lswap->nh[nh_idx].nh_int;

	/*
	 * Now construct expected pak - which is the internal mpls pak
	 * with its labels swapped and its ttl decremented.
	 */
	if (lswap->nh[nh_idx].num_labels) {
		/* label swap - top label is outlabel for nh */

		label_t new_labels[lswap->nh[nh_idx].num_labels];
		uint8_t new_ttls[lswap->nh[nh_idx].num_labels];

		/* new label stack consists of the nh's labels */
		for (i = 0; i < lswap->nh[nh_idx].num_labels; i++) {
			new_labels[i] =
				lswap->nh[nh_idx].labels[i];
			new_ttls[i] = ttls[0];
		}
		expected_pak =
			_dp_test_create_mpls_pak(
				lswap->nh[nh_idx].num_labels,
				new_labels,
				new_ttls,
				payload_pak);

		(void)dp_test_pktmbuf_eth_init(
			expected_pak,
			nh_mac_str[nh_idx],
			dp_test_intf_name2mac_str(lswap->nh[nh_idx].nh_int),
			RTE_ETHER_TYPE_MPLS);
	} else {
		/* Unsupported combination */
		assert(0);
	}
	struct dp_test_expected *exp;

	exp = dp_test_exp_create(expected_pak);
	/* expected has a copy of the expected pak */
	rte_pktmbuf_free(expected_pak);
	rte_pktmbuf_free(payload_pak);
	dp_test_exp_set_oif_name(exp, expected_oif);

	*ret_nh_idx = nh_idx;
	*ret_hash_val = hash_val;
	return exp;
}

static struct rte_mbuf *
dp_test_mpls_test_pkt(struct flow_fields *flow,
		      unsigned int non_flow_variation,
		      struct dp_test_route *lswap,
		      struct rte_mbuf **ret_payload_pak,
		      label_t *labels,
		      uint8_t *ttls)
{
	struct rte_mbuf *payload_pak, *mpls_pak;
	struct udphdr *udp;
	unsigned int i;
	int len;
	uint32_t *data;


	len = 22 + non_flow_variation;
	/*
	 * construct the payload packet - complete with
	 * ether header because we inject this for
	 * imposition tests.
	 */
	payload_pak =
		dp_test_create_ipv4_pak(flow->ip_src_str,
					flow->ip_dst_str,
					1, &len);
	dp_test_pktmbuf_udp_init(payload_pak,
				 flow->udp_src,
				 flow->udp_dst, true);
	*ret_payload_pak = payload_pak;
	(void)dp_test_pktmbuf_eth_init(payload_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);
	/*
	 * also set the l4 payload
	 */
	udp = dp_pktmbuf_mtol4(payload_pak, struct udphdr *);
	data = (uint32_t *)(udp + 1);
	*data = non_flow_variation;

	/*
	 * Now build the encapsulating mpls packet
	 *
	 * top label matches our lswap
	 */
	labels[0] = mpls_ls_get_label(lswap->prefix.addr.addr.mpls);
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL - non_flow_variation;
	for (i = 0; i < flow->num_labels; i++) {
		labels[i+1] = flow->labels[i];
		ttls[i+1] = DP_TEST_PAK_DEFAULT_TTL - non_flow_variation;
	}

	mpls_pak = _dp_test_create_mpls_pak(flow->num_labels+1, labels,
					    ttls,
					    payload_pak);
	(void)dp_test_pktmbuf_eth_init(mpls_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);
	return mpls_pak;
}

/*
 * construct an IP packet from a flow
 */
static struct rte_mbuf *
dp_test_mpls_test_ip_pkt(struct flow_fields *flow,
			 unsigned int non_flow_variation)
{
	struct rte_mbuf *ip_pak;
	struct udphdr *udp;
	int len;
	uint32_t *data;

	len = 22 + non_flow_variation;
	/*
	 * construct the payload packet - complete with
	 * ether header because we inject this for
	 * imposition tests.
	 */
	ip_pak =
		dp_test_create_ipv4_pak(flow->ip_src_str,
					flow->ip_dst_str,
					1, &len);
	dp_test_pktmbuf_udp_init(ip_pak,
				 flow->udp_src,
				 flow->udp_dst, true);
	(void)dp_test_pktmbuf_eth_init(ip_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);
	/*
	 * also set the l4 payload
	 */
	udp = dp_pktmbuf_mtol4(ip_pak, struct udphdr *);
	data = (uint32_t *)(udp + 1);
	*data = non_flow_variation;

	return ip_pak;
}


DP_DECL_TEST_CASE(mpls, imp_fwd_ecmp, NULL, NULL);

DP_START_TEST_FULL_RUN(imp_fwd_ecmp, payloadv4)
{
	/*
	 * Create an ECP label swap
	 */
	const char *lbl_swap_str =
		"255 "
		"nh 2.0.0.1 int:dp2T0 lbls 22 "
		"nh 3.0.0.1 int:dp2T1 lbls 33 "
		"nh 4.0.0.1 int:dp2T2 lbls 44 "
		"nh 5.0.0.1 int:dp2T3 lbls 55 "
		"nh 6.0.0.1 int:dp3T0 lbls 66 "
		"nh 7.0.0.1 int:dp3T1 lbls 77 "
		"nh 8.0.0.1 int:dp3T2 lbls 88 "
		"nh 10.0.0.1 int:dp3T3 lbls 99 ";
	struct dp_test_route *lswap = dp_test_parse_route(lbl_swap_str);

	/*
	 * for imposition the IP route simply has 1 path with the
	 * label as its out label the interface and nh should not
	 * really matter but interface may be set to a special mpls ip
	 * interface eventually.
	 */
	dp_test_netlink_add_route("11.0.0.0/24 nh int:lo lbls 255");

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/* Add an lswitch entry for the local label we are about to use */
	dp_test_netlink_add_route(lbl_swap_str);

	/*
	 * Setup a NH ipstring, macstring and static arp for each nh
	 * in our lbl swap
	 */
	const char *base_mac_str = "aa:bb:cc:dd:ee:0";
	char nh_ip_str[DP_TEST_MAX_NHS][DP_TEST_MAX_PREFIX_STRING_LEN];
	char *nh_mac_str[DP_TEST_MAX_NHS];
	unsigned int nh_pkts[DP_TEST_MAX_NHS];
	unsigned int i;

	for (i = 0; i < lswap->nh_cnt; i++) {

		nh_mac_str[i] = strdup(base_mac_str);
		sprintf(nh_mac_str[i], "aa:bb:cc:dd:ee:%x", i);

		inet_ntop(AF_INET, &lswap->nh[i].nh_addr.addr.ipv4,
			  nh_ip_str[i], sizeof(nh_ip_str[i]));

		dp_test_netlink_add_neigh(lswap->nh[i].nh_int,
					       nh_ip_str[i],
					       nh_mac_str[i]);
		nh_pkts[i] = 0;
	}

	/*
	 * Send lots of packets and check that they go where we expect
	 */
	struct flow_fields flow;

	flow.count = 0;
	flow.num_labels = 0;

	flow.fix_dest = true;
	flow.fix_labels = true;
	strcpy(flow.ip_dst_str, "11.0.0.1");
	/*
	 * change various values that affect ecmp hash
	 */
	while (get_next_flow_field_combo(&flow)) {
		/* now create different paks with same flow to verify that these
		 * diffs do NOT affect the ECMP decision.
		 */
		unsigned int j;
		for (j = 0; j < 4; j++) {

			struct rte_mbuf *test_pak;
			uint32_t hash_val, nh_idx;

			/*
			 * Because imposition is
			 * mapped to imposing the internal label then
			 * using the lswap on that we can use the
			 * lswap funcs to build the mpls packet and
			 * give that to the monitor to construct the
			 * output pkt. We can then inject the ip
			 * payload pkt into the dataplane.
			 */
			test_pak = dp_test_mpls_test_ip_pkt(&flow, j);
			/*
			 * trick is that we have to decrement the ttl on
			 * the payload in the IP packet.
			 */
			struct dp_test_expected *exp;

			exp = label_imp_monitor(test_pak, lswap, nh_mac_str,
						&hash_val, &nh_idx);
			dp_test_pak_rx_for(test_pak, "dp1T1", exp,
					   "for flow %d %s j=%d --> %d %s %s",
					   flow.count, flow.string, j,
					   nh_idx, nh_ip_str[nh_idx],
					   lswap->nh[nh_idx].nh_int);

			nh_pkts[nh_idx]++;
		}
	}

	/*
	 * Check that the balance is reasonable - which we define as
	 * being within 30% of the mean.
	 */
	unsigned int total_pkts = 0;

	for (i = 0; i < lswap->nh_cnt; i++)
		total_pkts += nh_pkts[i];

	unsigned int upper_bound = (total_pkts * 13) / (lswap->nh_cnt * 10);
	unsigned int lower_bound = (total_pkts * 7) / (lswap->nh_cnt * 10);
	unsigned int ave = (total_pkts * 10) / (lswap->nh_cnt * 10);

	for (i = 0; i < lswap->nh_cnt; i++)
		dp_test_fail_unless((nh_pkts[i] < upper_bound &&
				     nh_pkts[i] > lower_bound),
				    "Loadbalancing unequal for nh %d - got %d packets where ave %d (%d)",
				    i, nh_pkts[i], ave,
				    (int)((((int)nh_pkts[i] - (int)ave) * 100) /
				    (int)ave));

	/*
	 * Cleanup
	 */
	for (i = 0; i < lswap->nh_cnt; i++) {
		dp_test_netlink_del_neigh(lswap->nh[i].nh_int,
					       nh_ip_str[i],
					       nh_mac_str[i]);
		free(nh_mac_str[i]);
	}

	dp_test_netlink_del_route(lbl_swap_str);
	dp_test_netlink_del_route("11.0.0.0/24 nh int:lo lbls 255");

	dp_test_free_route(lswap);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, disp_fwd_ecmp, NULL, NULL);

DP_START_TEST_FULL_RUN(disp_fwd_ecmp, payloadv4)
{
	/*
	 * Create an ECP label swap
	 */
	const char *lbl_swap_str =
		"255 mpt:ipv4 "
		"nh 2.0.0.1 int:dp2T0 lbls imp-null "
		"nh 3.0.0.1 int:dp2T1 lbls imp-null "
		"nh 4.0.0.1 int:dp2T2 lbls imp-null "
		"nh 5.0.0.1 int:dp2T3 lbls imp-null "
		"nh 6.0.0.1 int:dp3T0 lbls imp-null "
		"nh 7.0.0.1 int:dp3T1 lbls imp-null "
		"nh 8.0.0.1 int:dp3T2 lbls imp-null "
		"nh 10.0.0.1 int:dp3T3 lbls imp-null ";

	struct dp_test_route *lswap = dp_test_parse_route(lbl_swap_str);

	/* enable mpls on the input interface.
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route(lbl_swap_str);

	/*
	 * Setup a NH ipstring, macstring and static arp for each nh
	 * in our lbl swap
	 */
	const char *base_mac_str = "aa:bb:cc:dd:ee:0";
	char nh_ip_str[DP_TEST_MAX_NHS][DP_TEST_MAX_PREFIX_STRING_LEN];
	char *nh_mac_str[DP_TEST_MAX_NHS];
	unsigned int nh_pkts[DP_TEST_MAX_NHS];
	unsigned int i;

	for (i = 0; i < lswap->nh_cnt; i++) {

		nh_mac_str[i] = strdup(base_mac_str);
		sprintf(nh_mac_str[i], "aa:bb:cc:dd:ee:%x", i);

		inet_ntop(AF_INET, &lswap->nh[i].nh_addr.addr.ipv4,
			  nh_ip_str[i], sizeof(nh_ip_str[i]));

		dp_test_netlink_add_neigh(lswap->nh[i].nh_int,
					       nh_ip_str[i],
					       nh_mac_str[i]);
		nh_pkts[i] = 0;
	}

	/*
	 * Send lots of packets and check that they go where we expect
	 */
	struct flow_fields flow;

	flow.count = 0;
	flow.fix_dest = false;
	flow.fix_labels = false;

	/*
	 * change various values that affect ecmp hash
	 */
	while (get_next_flow_field_combo(&flow)) {
		/* now create different paks with same flow to verify that these
		 * diffs do NOT affect the ECMP decision.
		 */
		unsigned int j;

		for (j = 0; j < 4; j++) {

			struct rte_mbuf *test_pak, *payload_pak;
			/* top lbl is extra */
			int num_labels = flow.num_labels + 1;
			label_t labels[num_labels];
			uint8_t ttls[num_labels];
			uint32_t hash_val, nh_idx;

			test_pak = dp_test_mpls_test_pkt(&flow, j, lswap,
							 &payload_pak, labels,
							 ttls);
			struct dp_test_expected *exp;

			exp = label_swap_monitor(test_pak, flow.num_labels+1,
						 labels, ttls,
						 RTE_ETHER_TYPE_IPV4,
						 payload_pak, lswap, nh_mac_str,
						 &hash_val, &nh_idx);
			dp_test_pak_rx_for(test_pak, "dp1T1", exp,
					   "for flow %d %s j=%d --> %d %s %s",
					   flow.count, flow.string, j,
					   nh_idx, nh_ip_str[nh_idx],
					   lswap->nh[nh_idx].nh_int);
			rte_pktmbuf_free(payload_pak);

			nh_pkts[nh_idx]++;
		}
	}
	/*
	 * Check that the balance is reasonable - which we define as
	 * being within 20% of the mean.
	 */

	unsigned int total_pkts = 0;

	for (i = 0; i < lswap->nh_cnt; i++)
		total_pkts += nh_pkts[i];

	unsigned int upper_bound = (total_pkts * 12) / (lswap->nh_cnt * 10);
	unsigned int lower_bound = (total_pkts * 8) / (lswap->nh_cnt * 10);
	unsigned int ave = (total_pkts * 10) / (lswap->nh_cnt * 10);

	for (i = 0; i < lswap->nh_cnt; i++)
		dp_test_fail_unless((nh_pkts[i] < upper_bound &&
				     nh_pkts[i] > lower_bound),
				    "Loadbalancing unequal for nh %d - got %d packets where ave %d (%i%%)",
				    i, nh_pkts[i], ave,
				    (((int)nh_pkts[i] - (int)ave) * 100) /
				    (int)ave);
	/*
	 * Cleanup
	 */
	for (i = 0; i < lswap->nh_cnt; i++) {
		dp_test_netlink_del_neigh(lswap->nh[i].nh_int,
					  nh_ip_str[i],
					  nh_mac_str[i]);
		free(nh_mac_str[i]);
	}

	dp_test_netlink_del_route(lbl_swap_str);

	dp_test_free_route(lswap);

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, lswap_fwd_ecmp, NULL, NULL);
DP_START_TEST_FULL_RUN(lswap_fwd_ecmp, payloadv4)
{
	/*
	 * Create an ECP label swap
	 */
	const char *lbl_swap_str =
		"255 mpt:ipv4 "
		"nh 2.0.0.1 int:dp2T0 lbls 22 "
		"nh 3.0.0.1 int:dp2T1 lbls 33 "
		"nh 4.0.0.1 int:dp2T2 lbls 44 "
		"nh 5.0.0.1 int:dp2T3 lbls 55 "
		"nh 6.0.0.1 int:dp3T0 lbls 66 "
		"nh 7.0.0.1 int:dp3T1 lbls 76 "
		"nh 8.0.0.1 int:dp3T2 lbls 86 "
		"nh 10.0.0.1 int:dp3T3 lbls 96 ";

	struct dp_test_route *lswap = dp_test_parse_route(lbl_swap_str);

	/* enable mpls on the input interface
	 */
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route(lbl_swap_str);

	/*
	 * Setup a NH ipstring, macstring and static arp for each nh
	 * in our lbl swap
	 */
	const char *base_mac_str = "aa:bb:cc:dd:ee:0";
	char nh_ip_str[DP_TEST_MAX_NHS][DP_TEST_MAX_PREFIX_STRING_LEN];
	char *nh_mac_str[DP_TEST_MAX_NHS];
	unsigned int nh_pkts[DP_TEST_MAX_NHS];
	unsigned int i;

	for (i = 0; i < lswap->nh_cnt; i++) {

		nh_mac_str[i] = strdup(base_mac_str);
		sprintf(nh_mac_str[i], "aa:bb:cc:dd:ee:%x", i);

		inet_ntop(AF_INET, &lswap->nh[i].nh_addr.addr.ipv4,
			  nh_ip_str[i], sizeof(nh_ip_str[i]));

		dp_test_netlink_add_neigh(lswap->nh[i].nh_int,
					       nh_ip_str[i],
					       nh_mac_str[i]);
		nh_pkts[i] = 0;
	}

	/*
	 * Send lots of packets and check that they go where we expect
	 */
	struct flow_fields flow;

	flow.count = 0;
	flow.fix_dest = false;
	flow.fix_labels = false;

	/*
	 * change various values that affect ecmp hash
	 */
	while (get_next_flow_field_combo(&flow)) {
		/* now create different paks with same flow to verify that these
		 * diffs do NOT affect the ECMP decision.
		 */
		unsigned int j;

		for (j = 0; j < 4; j++) {
			struct rte_mbuf *test_pak, *payload_pak;
			/* top lbl is extra */
			int num_labels = flow.num_labels + 1;
			label_t labels[num_labels];
			uint8_t ttls[num_labels];
			uint32_t hash_val, nh_idx;

			test_pak = dp_test_mpls_test_pkt(&flow, j, lswap,
							 &payload_pak, labels,
							 ttls);
			struct dp_test_expected *exp;

			exp = label_swap_monitor(test_pak, flow.num_labels+1,
						 labels, ttls,
						 RTE_ETHER_TYPE_IPV4,
						 payload_pak, lswap, nh_mac_str,
						 &hash_val, &nh_idx);
			dp_test_pak_receive(test_pak, "dp1T1", exp);
			rte_pktmbuf_free(payload_pak);

			nh_pkts[nh_idx]++;
		}
	}
	/*
	 * Check that the balance is reasonable - which we define as
	 * being within 20% of the mean.
	 */

	unsigned int total_pkts = 0;

	for (i = 0; i < lswap->nh_cnt; i++)
		total_pkts += nh_pkts[i];

	unsigned int upper_bound = (total_pkts * 12) / (lswap->nh_cnt * 10);
	unsigned int lower_bound = (total_pkts * 8) / (lswap->nh_cnt * 10);
	unsigned int ave = (total_pkts * 10) / (lswap->nh_cnt * 10);

	for (i = 0; i < lswap->nh_cnt; i++)
		dp_test_fail_unless((nh_pkts[i] < upper_bound &&
				     nh_pkts[i] > lower_bound),
				    "Loadbalancing unequal for nh %d "
				    "- got %d packets where ave %d (%i%%)",
				    i, nh_pkts[i], ave,
				    (((int)nh_pkts[i] - (int)ave) * 100) /
				    (int)ave);
	/*
	 * Cleanup
	 */
	for (i = 0; i < lswap->nh_cnt; i++) {
		dp_test_netlink_del_neigh(lswap->nh[i].nh_int,
					       nh_ip_str[i],
					       nh_mac_str[i]);
		free(nh_mac_str[i]);
	}

	dp_test_netlink_del_route(lbl_swap_str);

	dp_test_free_route(lswap);

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, rx_router_alert, NULL, NULL);
DP_START_TEST(rx_router_alert, simple)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	label_t labels[2];
	uint8_t ttls[2];
	int len = 22;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add a spurious lswitch entry (shouldn't be used but lets be sure) */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "3.3.3.1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 1;
	labels[1] = 222;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;

	test_pak =
		dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);
	/*
	 * Expected packet - looks *exactly* the same as test packet
	 * including ttls.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_neigh("dp2T2", "3.3.3.1", nh_mac_str);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, mpls_ttl, NULL, NULL);

DP_START_TEST(mpls_ttl, config)
{
	json_object *expected_json;

	/* enable propagation */
	dp_test_console_request_reply("mpls ipttlpropagate enable", false);

	/* check it is enabled */
	expected_json = dp_test_json_create("{ "
					    "  \"config\":"
					    "  {"
					    "    \"ipttlpropagate\":1"
					    "  }"
					    "}");
	dp_test_check_json_state("mpls show config",
				 expected_json,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected_json);

	/* disable propagation */
	dp_test_console_request_reply("mpls ipttlpropagate disable", false);

	/* check it is disabled */
	expected_json = dp_test_json_create("{ "
					    "  \"config\":"
					    "  {"
					    "    \"ipttlpropagate\":0"
					    "  }"
					    "}");
	dp_test_check_json_state("mpls show config",
				 expected_json,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected_json);

	/* set default ttl */
	dp_test_console_request_reply("mpls defaultttl 59", false);

	/* check it is set */
	expected_json = dp_test_json_create("{ "
					    "  \"config\":"
					    "  {"
					    "    \"defaultttl\":59"
					    "  }"
					    "}");
	dp_test_check_json_state("mpls show config",
				 expected_json,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected_json);

	/* Clean up */
	mpls_ttl_default_config();
} DP_END_TEST;

DP_START_TEST(mpls_ttl, imposition)
{
	struct iphdr *ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	label_t expected_label = 22;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	char ttl_buf[30];
	int len = 22;
	unsigned int i;
	struct {
		bool ipttlpropagate;
		int defaultttl;
		uint8_t mplsttl;
	} test_data[] = {
		{ true, 25, DP_TEST_PAK_DEFAULT_TTL - 1 },	/* propagate */
		{ false, 25, 25 },				/* default */
		{ false, -1, 255 },				/* max */
	};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo lbls 122");

	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
		/* configure ttl propagation */
		snprintf(ttl_buf, sizeof(ttl_buf), "mpls ipttlpropagate %sable",
			test_data[i].ipttlpropagate ? "en" : "dis");
		dp_test_console_request_reply(ttl_buf, false);

		/* configure default ttl */
		snprintf(ttl_buf, sizeof(ttl_buf), "mpls defaultttl %d",
			 test_data[i].defaultttl);
		dp_test_console_request_reply(ttl_buf, false);

		/*
		 * Test packet
		 */
		test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
						   1, &len);
		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T1"),
					 NULL, RTE_ETHER_TYPE_IPV4);

		/*
		 * Expected packet
		 */
		expected_pak = dp_test_create_mpls_pak(1, &expected_label,
						       &test_data[i].mplsttl,
						       test_pak);
		dp_test_pktmbuf_eth_init(expected_pak,
					 nh_mac_str,
					 dp_test_intf_name2mac_str("dp2T2"),
					 RTE_ETHER_TYPE_MPLS);

		ip = dp_test_get_mpls_pak_payload(expected_pak);
		ip->ttl = DP_TEST_PAK_DEFAULT_TTL - 1;
		ip->check = 0;
		ip->check = dp_in_cksum_hdr(ip);

		exp = dp_test_exp_create(expected_pak);
		rte_pktmbuf_free(expected_pak);
		dp_test_exp_set_oif_name(exp, "dp2T2");

		dp_test_pak_receive(test_pak, "dp1T1", exp);
	}

	/* Clean up */
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo lbls 122");
	dp_test_netlink_del_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	mpls_ttl_default_config();

} DP_END_TEST;

DP_START_TEST(mpls_ttl, pop)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	label_t expected_label = 22;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	label_t labels[2];
	char ttl_buf[30];
	uint8_t ttls[2];
	int len = 22;
	unsigned int i;
	struct {
		bool ipttlpropagate;
		int defaultttl;
		uint8_t mplsttl;
	} test_data[] = {
		{ true, 25, DP_TEST_PAK_DEFAULT_TTL - 1 }, /* propagate */
		{ false, 25, DP_TEST_PAK_DEFAULT_TTL - 1 }, /* default */
		{ false, -1, DP_TEST_PAK_DEFAULT_TTL - 1 }, /* max */
	};

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry for the internal label we are about to use */
	dp_test_netlink_add_route(
		"122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls imp-null");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 nh int:lo lbls 122");

	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
		/* configure ttl propagation */
		snprintf(ttl_buf, sizeof(ttl_buf), "mpls ipttlpropagate %sable",
			 test_data[i].ipttlpropagate ? "en" : "dis");
		dp_test_console_request_reply(ttl_buf, false);

		/* configure default ttl */
		snprintf(ttl_buf, sizeof(ttl_buf), "mpls defaultttl %d",
			 test_data[i].defaultttl);
		dp_test_console_request_reply(ttl_buf, false);

		/*
		 * Test packet
		 */
		payload_pak = dp_test_create_ipv4_pak("10.73.0.0",
						      "10.73.2.0",
						      1, &len);
		labels[0] = 122;
		labels[1] = 22;
		ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
		ttls[1] = 25;
		test_pak = dp_test_create_mpls_pak(2, labels, ttls,
						   payload_pak);
		(void)dp_test_pktmbuf_eth_init(
			test_pak,
			dp_test_intf_name2mac_str("dp1T1"),
			NULL, RTE_ETHER_TYPE_MPLS);

		/*
		 * Expected packet
		 */
		expected_pak = dp_test_create_mpls_pak(
			1, &expected_label, &test_data[i].mplsttl,
			payload_pak);
		(void)dp_test_pktmbuf_eth_init(
			expected_pak, nh_mac_str,
			dp_test_intf_name2mac_str("dp2T2"),
			RTE_ETHER_TYPE_MPLS);

		exp = dp_test_exp_create(expected_pak);
		rte_pktmbuf_free(expected_pak);
		rte_pktmbuf_free(payload_pak);
		dp_test_exp_set_oif_name(exp, "dp2T2");

		dp_test_pak_receive(test_pak, "dp1T1", exp);
	}

	/* Clean up */
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("10.73.2.0/24 nh int:lo lbls 122");
	dp_test_netlink_del_route(
		"122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls imp-null");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	mpls_ttl_default_config();

} DP_END_TEST;

DP_START_TEST(mpls_ttl, v4_disposition)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1;
	const char *nh_mac_str2;
	struct iphdr *ip;
	char ttl_buf[30];
	label_t label;
	uint8_t ttl;
	int icmplen;
	int len = 22;
	unsigned int i;
	struct {
		bool ipttlpropagate;
		bool php;
		label_t inlabel;
		uint8_t mplsttl;
		uint8_t ipttl;
		uint8_t expttl;
		const char *oif;
	} test_data[] = {
		/* uniform, php */
		{ true, true, 122, 25, DP_TEST_PAK_DEFAULT_TTL, 24, "dp2T2" },
		/* uniform, pop */
		{ true, false, 222, 25, DP_TEST_PAK_DEFAULT_TTL, 24, "dp2T2", },
		{ true, false, 322, 25, DP_TEST_PAK_DEFAULT_TTL, 24, "dp2T2", },
		/* pipe, php */
		{ false, true, 122, 25, DP_TEST_PAK_DEFAULT_TTL,
		  DP_TEST_PAK_DEFAULT_TTL, "dp2T2" },
		{ false, true, 122, 25, 1, 1, "dp2T2" },
		/* pipe, pop */
		{ false, false, 222, 25, DP_TEST_PAK_DEFAULT_TTL,
		  DP_TEST_PAK_DEFAULT_TTL - 1, "dp2T2" },
		{ false, false, 222, 25, 1, DP_TEST_PAK_DEFAULT_TTL, "dp1T1" },
		{ false, false, 322, 25, DP_TEST_PAK_DEFAULT_TTL,
		  DP_TEST_PAK_DEFAULT_TTL - 1, "dp2T2" },
		{ false, false, 322, 25, 1, DP_TEST_PAK_DEFAULT_TTL, "dp1T1" },
	};

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add lswitch entries for the internal labels we are about to use */
	dp_test_netlink_add_route(
		"122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls imp-null");
	dp_test_netlink_add_route(
		"222 mpt:ipv4 nh 2.2.2.1 int:dp2T2");
	dp_test_netlink_add_route(
		"322 mpt:ipv4 nh 0.0.0.0 int:lo");
	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str1);
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str2);

	/* Deag route */
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T2");

	/* Route back for ICMP error */
	dp_test_netlink_add_route("10.73.0.0/24 nh 1.1.1.2 int:dp1T1");

	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
		/* configure ttl propagation */
		snprintf(ttl_buf, sizeof(ttl_buf), "mpls ipttlpropagate %sable",
			 test_data[i].ipttlpropagate ? "en" : "dis");
		dp_test_console_request_reply(ttl_buf, false);

		/*
		 * Test packet
		 */
		payload_pak = dp_test_create_ipv4_pak("10.73.0.0",
						      "10.73.2.0",
						      1, &len);
		dp_test_set_pak_ip_field(iphdr(payload_pak), DP_TEST_SET_TTL,
					 test_data[i].ipttl);

		label = test_data[i].inlabel;
		ttl = test_data[i].mplsttl;
		test_pak = dp_test_create_mpls_pak(1, &label, &ttl,
						   payload_pak);
		(void)dp_test_pktmbuf_eth_init(
			test_pak,
			dp_test_intf_name2mac_str("dp1T1"),
			NULL, RTE_ETHER_TYPE_MPLS);

		/*
		 * Expected packet
		 */
		if (!test_data[i].ipttlpropagate && !test_data[i].php &&
		    test_data[i].ipttl == 1) {
			icmplen = sizeof(struct iphdr) +
				  sizeof(struct udphdr) + len;
			expected_pak = dp_test_create_icmp_ipv4_pak(
				"1.1.1.1", "10.73.0.0", ICMP_TIME_EXCEEDED,
				ICMP_EXC_TTL, 0, 1, &icmplen,
				iphdr(payload_pak), &ip, NULL);
			(void)dp_test_pktmbuf_eth_init(
				expected_pak, nh_mac_str1,
				dp_test_intf_name2mac_str(test_data[i].oif),
				RTE_ETHER_TYPE_IPV4);
			dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
						 IPTOS_PREC_INTERNETCONTROL);
			exp = dp_test_exp_create(expected_pak);
			rte_pktmbuf_free(payload_pak);
		} else {
			expected_pak = payload_pak;
			dp_test_set_pak_ip_field(iphdr(expected_pak),
						 DP_TEST_SET_TTL,
						 test_data[i].expttl);
			(void)dp_test_pktmbuf_eth_init(
				expected_pak, nh_mac_str2,
				dp_test_intf_name2mac_str(test_data[i].oif),
				RTE_ETHER_TYPE_IPV4);
			exp = dp_test_exp_create(expected_pak);
		}
		rte_pktmbuf_free(expected_pak);
		dp_test_exp_set_oif_name(exp, test_data[i].oif);

		dp_test_pak_receive(test_pak, "dp1T1", exp);
	}

	/* Clean up */
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T2");
	dp_test_netlink_del_route("10.73.0.0/24 nh 1.1.1.2 int:dp1T1");
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str1);
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str2);
	dp_test_netlink_del_route(
		"122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_route(
		"222 mpt:ipv4 nh 2.2.2.1 int:dp2T2");
	dp_test_netlink_del_route(
		"322 mpt:ipv4 nh 0.0.0.0 int:lo");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	mpls_ttl_default_config();

} DP_END_TEST;

DP_START_TEST(mpls_ttl, v6_disposition)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1;
	const char *nh_mac_str2;
	struct ip6_hdr *ip6;
	char ttl_buf[30];
	label_t label;
	uint8_t ttl;
	int icmplen;
	int len = 22;
	unsigned int i;
	struct {
		bool ipttlpropagate;
		bool php;
		label_t inlabel;
		uint8_t mplsttl;
		uint8_t ipttl;
		uint8_t expttl;
		const char *oif;
	} test_data[] = {
		/* uniform, php */
		{ true, true, 122, 25, DP_TEST_PAK_DEFAULT_TTL, 24, "dp2T2" },
		/* uniform, pop */
		{ true, false, 222, 25, DP_TEST_PAK_DEFAULT_TTL, 24, "dp2T2", },
		{ true, false, 322, 25, DP_TEST_PAK_DEFAULT_TTL, 24, "dp2T2", },
		/* pipe, php */
		{ false, true, 122, 25, DP_TEST_PAK_DEFAULT_TTL,
		  DP_TEST_PAK_DEFAULT_TTL, "dp2T2" },
		{ false, true, 122, 25, 1, 1, "dp2T2" },
		/* pipe, pop */
		{ false, false, 222, 25, DP_TEST_PAK_DEFAULT_TTL,
		  DP_TEST_PAK_DEFAULT_TTL - 1, "dp2T2" },
		{ false, false, 222, 25, 1, DP_TEST_PAK_DEFAULT_TTL, "dp1T1" },
		{ false, false, 322, 25, DP_TEST_PAK_DEFAULT_TTL,
		  DP_TEST_PAK_DEFAULT_TTL - 1, "dp2T2" },
		{ false, false, 322, 25, 1, DP_TEST_PAK_DEFAULT_TTL, "dp1T1" },
	};

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2:2:2::2/64");

	/* Add lswitch entries for the internal labels we are about to use */
	dp_test_netlink_add_route(
		"122 mpt:ipv6 nh 2:2:2::1 int:dp2T2 lbls imp-null");
	dp_test_netlink_add_route(
		"222 mpt:ipv6 nh 2:2:2::1 int:dp2T2");
	dp_test_netlink_add_route(
		"322 mpt:ipv6 nh :: int:lo");
	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	dp_test_netlink_add_neigh("dp1T1", "1:1:1::2", nh_mac_str1);
	dp_test_netlink_add_neigh("dp2T2", "2:2:2::1", nh_mac_str2);

	/* Deag route */
	dp_test_netlink_add_route("10:73:2::/64 nh 2:2:2::1 int:dp2T2");

	/* Route back for ICMP error */
	dp_test_netlink_add_route("10:73:0::/64 nh 1:1:1::2 int:dp1T1");

	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
		/* configure ttl propagation */
		snprintf(ttl_buf, sizeof(ttl_buf), "mpls ipttlpropagate %sable",
			 test_data[i].ipttlpropagate ? "en" : "dis");
		dp_test_console_request_reply(ttl_buf, false);

		/*
		 * Test packet
		 */
		payload_pak = dp_test_create_ipv6_pak("10:73:0::1",
						      "10:73:2::1",
						      1, &len);
		ip6 = ip6hdr(payload_pak);
		ip6->ip6_hlim = test_data[i].ipttl;

		label = test_data[i].inlabel;
		ttl = test_data[i].mplsttl;
		test_pak = dp_test_create_mpls_pak(1, &label, &ttl,
						   payload_pak);
		(void)dp_test_pktmbuf_eth_init(
			test_pak,
			dp_test_intf_name2mac_str("dp1T1"),
			NULL, RTE_ETHER_TYPE_MPLS);

		/*
		 * Expected packet
		 */
		if (!test_data[i].ipttlpropagate && !test_data[i].php &&
		    test_data[i].ipttl == 1) {
			icmplen = sizeof(struct ip6_hdr) + len;
			expected_pak = dp_test_create_icmp_ipv6_pak(
				"1:1:1::1", "10:73:0::1", ICMP6_TIME_EXCEEDED,
				ICMP6_TIME_EXCEED_TRANSIT, 0, 1, &icmplen,
				ip6hdr(payload_pak), NULL, NULL);
			(void)dp_test_pktmbuf_eth_init(
				expected_pak, nh_mac_str1,
				dp_test_intf_name2mac_str(test_data[i].oif),
				RTE_ETHER_TYPE_IPV6);
			exp = dp_test_exp_create(expected_pak);
			rte_pktmbuf_free(payload_pak);
		} else {
			expected_pak = payload_pak;
			ip6 = ip6hdr(expected_pak);
			ip6->ip6_hlim = test_data[i].expttl;
			(void)dp_test_pktmbuf_eth_init(
				expected_pak, nh_mac_str2,
				dp_test_intf_name2mac_str(test_data[i].oif),
				RTE_ETHER_TYPE_IPV6);
			exp = dp_test_exp_create(expected_pak);
		}
		rte_pktmbuf_free(expected_pak);
		dp_test_exp_set_oif_name(exp, test_data[i].oif);

		dp_test_pak_receive(test_pak, "dp1T1", exp);
	}

	/* Clean up */
	dp_test_netlink_del_route("10:73:2::/64 nh 2:2:2::1 int:dp2T2");
	dp_test_netlink_del_route("10:73:0::/64 nh 1:1:1::2 int:dp1T1");
	dp_test_netlink_del_neigh("dp1T1", "1:1:1::2", nh_mac_str1);
	dp_test_netlink_del_neigh("dp2T2", "2:2:2::1", nh_mac_str2);
	dp_test_netlink_del_route(
		"122 mpt:ipv6 nh 2:2:2::1 int:dp2T2 lbls imp-null");
	dp_test_netlink_del_route(
		"222 mpt:ipv6 nh 2:2:2::1 int:dp2T2");
	dp_test_netlink_del_route(
		"322 mpt:ipv6 nh :: int:lo");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2:2:2::2/64");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	mpls_ttl_default_config();

} DP_END_TEST;


struct mpls_icmp_subcase {
	int nlabels;
	label_t labels[4];
	uint8_t ttl[4];
	int plen;
	int exp_nlabels;
	label_t exp_labels[4];
	uint8_t exp_ttl[4];
};

/*
 * helper function to print summary of each subcase
 */
static int
mpls_icmp_subcase_string(struct mpls_icmp_subcase *tc,
			 char *descr, unsigned int sz)
{
	int written = 0;
	int i;

	written += spush(descr + written, sz - written,
			 "pkt_len = %d lbl:(ttl) = [ ", tc->plen);
	for (i = 0; i < tc->nlabels; i++)
		written += spush(descr + written, sz - written,
				 "%d:(%d), ", tc->labels[i], tc->ttl[i]);
	/* lose trailing ', '  */
	if (tc->nlabels)
		written -= 2;

	written += spush(descr + written, sz - written,
			 "] --> [");

	for (i = 0; i < tc->exp_nlabels; i++)
		written += spush(descr + written, sz - written,
				 "%d:(%d), ",
				 tc->exp_labels[i], tc->exp_ttl[i]);
	/* lose trailing ', '  */
	if (tc->nlabels)
		written -= 2;
	written += spush(descr + written, sz - written,
			 "]");
	return written;
}

DP_DECL_TEST_CASE(mpls, mpls_icmp, NULL, NULL);
DP_START_TEST(mpls_icmp, ttl_v4)
{
	struct iphdr *ip, *copy_from;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	struct icmphdr *icph;
	int icmplen, icmpextlen;
	unsigned int i;
	char *cp;
	struct mpls_icmp_subcase test_data[] = {
		{ 1, {122,}, {1,}, 22, 1, {22,}, {64,} },
		{ 2, {122, 100,}, {1, 64,}, 22, 2, {22, 100,}, {64, 64,} },
		{ 2, {0, 122,}, {1, 1,}, 60, 1, {22,}, {64,} },
		{ 3, {122, 16, 17,}, {1, 64, 99,}, 60,
		  3, {22, 16, 17,}, {64, 64, 64,} },
		{ 1, {124,}, {1,}, 22, 0, {}, {} },
		{ 1, {0,}, {1,}, 32, 1, {23,}, {64,} },
	};
	char subcase_descr[200];

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add lswitch entries */
	dp_test_netlink_add_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_netlink_add_route("123 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 23");
	dp_test_netlink_add_route("124 mpt:ipv4 nh 2.2.2.1 int:dp2T2");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
		/*
		 * If hitting a deag label (IPv4 Explicit NULL) then
		 * all labels will be popped and it will be forwarded
		 * as IP, so we need a return path.
		 */
		if (test_data[i].nlabels == 1 &&
		    test_data[i].labels[0] == 0)
			dp_test_netlink_add_route(
				"10.73.0.0/24 nh int:lo lbls 123");

		/* Create ip packet to be payload */
		payload_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
						      1, &test_data[i].plen);

		/* Create the mpls packet that encapsulates it */
		test_pak = dp_test_create_mpls_pak(test_data[i].nlabels,
						   test_data[i].labels,
						   test_data[i].ttl,
						   payload_pak);
		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T1"),
					 NULL, RTE_ETHER_TYPE_MPLS);

		copy_from = dp_pktmbuf_mtol3(payload_pak, struct iphdr *);

		/*
		 * Create expected icmp packet
		 * BEWARE: assumes original packet will fit within 128 offset
		 * on top of that we add 8 bytes for mpls extension header and
		 * another 4 per label.
		 */
		icmpextlen = 8 + (test_data[i].nlabels * 4);
		icmplen = 128 + icmpextlen;
		icmp_pak =
			dp_test_create_icmp_ipv4_pak("1.1.1.1", "10.73.0.0",
						     ICMP_TIME_EXCEEDED,
						     ICMP_EXC_TTL,
						     0,
						     1, &icmplen,
						     NULL,
						     &ip,
						     &icph);
		dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
					 IPTOS_PREC_INTERNETCONTROL);
		/* aliases the length field */
		icph->un.echo.id = htons((icmplen - icmpextlen) / 4);

		unsigned int total_payload_len = test_data[i].plen +
			sizeof(struct iphdr) + sizeof(struct udphdr);
		/* Original IP header goes in next */
		memcpy(icph + 1, copy_from, total_payload_len);

		/* Pad out with zeroes up to 128 bytes */
		memset((char *)(icph + 1) + total_payload_len, 0,
		       128 - total_payload_len);

		/* Now the MPLS extended header */
		cp = (char *)(icph + 1) + icmplen - icmpextlen;
		cp[0] = 0x20;		/* ieh_version=ICMP_EXT_HDR_VERSION */
		cp[1] = 0;		/* ieh_res=0 */
		cp[2] = cp[3] = 0;	/* ieh_cksum=0 */
		cp[4] = 0;		/* ieo_length=4 + label stack length */
		cp[5] = 4 + (test_data[i].nlabels * 4);
		cp[6] = 1;		/* ieo_cnum=ICMP_EXT_MPLS */
		cp[7] = 1;		/* ieo_ctype=ICMP_EXT_MPLS_INCOMING */

		/* The incoming label stack */
		memcpy(&cp[8], dp_pktmbuf_mtol3(test_pak, char *),
		       test_data[i].nlabels * 4);

		/* Finally the ICMP checksum fields */
		*(uint16_t *)(cp + 2) = in_cksum(cp, 4 + cp[5]);
		icph->checksum = 0;
		icph->checksum = dp_test_ipv4_icmp_cksum(icmp_pak, icph);
		if (test_data[i].exp_nlabels) {
			/* Create expected mpls packet */
			expected_pak = dp_test_create_mpls_pak(
				test_data[i].exp_nlabels,
				test_data[i].exp_labels,
				test_data[i].exp_ttl,
				icmp_pak);
			rte_pktmbuf_free(icmp_pak);
			dp_test_pktmbuf_eth_init(
				expected_pak,
				nh_mac_str,
				dp_test_intf_name2mac_str("dp2T2"),
				RTE_ETHER_TYPE_MPLS);
		} else {
			expected_pak = icmp_pak;
			dp_test_pktmbuf_eth_init(
				expected_pak,
				nh_mac_str,
				dp_test_intf_name2mac_str("dp2T2"),
				RTE_ETHER_TYPE_IPV4);
		}

		exp = dp_test_exp_create(expected_pak);
		rte_pktmbuf_free(expected_pak);
		dp_test_exp_set_oif_name(exp, "dp2T2");

		mpls_icmp_subcase_string(&test_data[i],
					 subcase_descr,
					 sizeof(subcase_descr));

		dp_test_pak_rx_for(test_pak, "dp1T1", exp,
				   "for subcase %d : %s",
				   i, subcase_descr);
		rte_pktmbuf_free(payload_pak);

		/*
		 * Remove route added with same conditions above.
		 */
		if (test_data[i].nlabels == 1 &&
		    test_data[i].labels[0] == 0)
			dp_test_netlink_del_route(
				"10.73.0.0/24 nh int:lo lbls 123");
	}

	/* Clean up */
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_route("123 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 23");
	dp_test_netlink_del_route("124 mpt:ipv4 nh 2.2.2.1 int:dp2T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);

} DP_END_TEST;

DP_START_TEST(mpls_icmp, invalid_paks)
{
	struct iphdr *ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add an lswitch entry */
	dp_test_netlink_add_route("144 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/*
	 * Test 1 - no payload
	 */
	test_pak = dp_test_create_mpls_pak(1,
					   (label_t []){144},
					   (uint8_t []){1},
					   NULL);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 2 - IP payload with invalid length
	 */
	len = 64;
	payload_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					      1, &len);
	ip = dp_pktmbuf_mtol3(payload_pak, struct iphdr *);
	ip->tot_len = htons(sizeof(struct iphdr) + 1500);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	test_pak = dp_test_create_mpls_pak(1,
					   (label_t []){144},
					   (uint8_t []){1},
					   payload_pak);
	rte_pktmbuf_free(payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 3 - IP payload with invalid header length
	 */
	len = 64;
	payload_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					      1, &len);
	ip = dp_pktmbuf_mtol3(payload_pak, struct iphdr *);
	ip->ihl = DP_TEST_PAK_DEFAULT_IHL - 1;
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	test_pak = dp_test_create_mpls_pak(1,
					   (label_t []){144},
					   (uint8_t []){1},
					   payload_pak);
	rte_pktmbuf_free(payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 4 - IP payload with invalid checksum
	 */
	len = 64;
	payload_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					      1, &len);
	ip = dp_pktmbuf_mtol3(payload_pak, struct iphdr *);
	ip->check = htons(0xdead);
	test_pak = dp_test_create_mpls_pak(1,
					   (label_t []){144},
					   (uint8_t []){1},
					   payload_pak);
	rte_pktmbuf_free(payload_pak);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean up */
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("144 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);

} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, mpls_icmpv6, NULL, NULL);
DP_START_TEST(mpls_icmpv6, ttl_v6)
{
	struct dp_test_expected *exp;
	struct mpls_icmp_subcase test_data[] = {
		{ 1, {122,}, {1,}, 22, 1, {22,}, {64,} },
		{ 2, {122, 100,}, {1, 64,}, 22, 2, {22, 100,}, {64, 64,} },
		{ 2, {2, 122,}, {1, 1,}, 60, 1, {22,}, {64,} },
		{ 3, {122, 16, 17,}, {1, 64, 99,}, 60,
		  3, {22, 16, 17,}, {64, 64, 64,} },
		{ 1, {124,}, {1,}, 22, 0, {}, {} },
		{ 1, {2,}, {1,}, 32, 1, {23,}, {64,} },
	};
	const char *nh_mac_str;
	unsigned int i;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

       /* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2002:2:2::2/64");

	/* Add lswitch entries */
	dp_test_netlink_add_route("122 mpt:ipv6 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_netlink_add_route("123 mpt:ipv6 nh 2.2.2.1 int:dp2T2 lbls 23");
	dp_test_netlink_add_route("124 mpt:ipv6 nh 2002:2:2::10 int:dp2T2");

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_add_neigh("dp2T2", "2002:2:2::10", nh_mac_str);

	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
		struct ip6_hdr *ip6, *copy_from;
		struct rte_mbuf *expected_pak;
		struct rte_mbuf *payload_pak;
		struct rte_mbuf *icmp6_pak;
		struct rte_mbuf *test_pak;
		struct icmp6_hdr *icmpv6;
		int icmplen, icmpextlen;
		char subcase_descr[200];
		char *cp;

		/*
		 * If hitting a deag label (IPv6 Explicit NULL) then
		 * all labels will be popped and it will be forwarded
		 * as IP, so we need a return path.
		 */
		if (test_data[i].nlabels == 1 &&
		    test_data[i].labels[0] == 2)
			dp_test_netlink_add_route(
				"2099:99::/64 mpt:ipv6 nh int:lo lbls 123");

		/* Create ip packet to be payload */
		payload_pak = dp_test_create_udp_ipv6_pak("2099:99::9",
							  "2088:88::8",
							  1001, 1002, 1,
							  &test_data[i].plen);

		/* Create the mpls packet that encapsulates it */
		test_pak = dp_test_create_mpls_pak(test_data[i].nlabels,
						   test_data[i].labels,
						   test_data[i].ttl,
						   payload_pak);
		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T1"),
					 NULL, RTE_ETHER_TYPE_MPLS);

		copy_from = dp_pktmbuf_mtol3(payload_pak, struct ip6_hdr *);

		/*
		 * Create expected icmp packet
		 * BEWARE: assumes original packet will fit within 128 offset
		 * on top of that we add 8 bytes for mpls extension header and
		 * another 4 per label.
		 */
		icmpextlen = 8 + (test_data[i].nlabels * 4);
		icmplen = 128 + icmpextlen;
		icmp6_pak = dp_test_create_icmp_ipv6_pak(
					"2001:1:1::1",
					"2099:99::9",
					ICMP6_TIME_EXCEEDED,
					ICMP6_TIME_EXCEED_TRANSIT,
					0, 1, &icmplen, NULL,
					&ip6, &icmpv6);

		/* aliases the length field */
		icmpv6->icmp6_id = htons((icmplen - icmpextlen) / 4);

		unsigned int total_payload_len = test_data[i].plen +
			sizeof(struct ip6_hdr) + sizeof(struct udphdr);

		/* Original IP header goes in next */
		memcpy(icmpv6 + 1, copy_from, total_payload_len);

		/* Pad out with zeroes up to 128 bytes */
		memset((char *)(icmpv6 + 1) + total_payload_len, 0,
			128 - total_payload_len);

		/* Now the MPLS extended header */
		cp = (char *)(icmpv6 + 1) + icmplen - icmpextlen;
		cp[0] = 0x20;		/* ieh_version=ICMP_EXT_HDR_VERSION */
		cp[1] = 0;		/* ieh_res=0 */
		cp[2] = cp[3] = 0;	/* ieh_cksum=0 */
		cp[4] = 0;		/* ieo_length=4 + label stack length */
		cp[5] = 4 + (test_data[i].nlabels * 4);
		cp[6] = 1;		/* ieo_cnum=ICMP_EXT_MPLS */
		cp[7] = 1;		/* ieo_ctype=ICMP_EXT_MPLS_INCOMING */

		/* The incoming label stack */
		memcpy(&cp[8], dp_pktmbuf_mtol3(test_pak, char *),
		       test_data[i].nlabels * 4);

		/* Checksum */
		*(uint16_t *)(cp + 2) = in_cksum(cp, 4 + cp[5]);
		icmpv6->icmp6_cksum = 0;
		icmpv6->icmp6_cksum = dp_test_ipv6_icmp_cksum(icmp6_pak, ip6,
							      icmpv6);

		if (test_data[i].exp_nlabels) {
			/* Create expected mpls packet */
			expected_pak = dp_test_create_mpls_pak(
				test_data[i].exp_nlabels,
				test_data[i].exp_labels,
				test_data[i].exp_ttl,
				icmp6_pak);
			rte_pktmbuf_free(icmp6_pak);
			dp_test_pktmbuf_eth_init(
				expected_pak,
				nh_mac_str,
				dp_test_intf_name2mac_str("dp2T2"),
				RTE_ETHER_TYPE_MPLS);
		} else {
			expected_pak = icmp6_pak;
			dp_test_pktmbuf_eth_init(
				expected_pak,
				nh_mac_str,
				dp_test_intf_name2mac_str("dp2T2"),
				RTE_ETHER_TYPE_IPV6);
		}

		exp = dp_test_exp_create(expected_pak);
		rte_pktmbuf_free(expected_pak);
		dp_test_exp_set_oif_name(exp, "dp2T2");

		mpls_icmp_subcase_string(&test_data[i],
					 subcase_descr,
					 sizeof(subcase_descr));

		dp_test_pak_rx_for(test_pak, "dp1T1", exp,
				   "for subcase %d : %s",
				   i, subcase_descr);
		rte_pktmbuf_free(payload_pak);

		/*
		 * Remove route added with same conditions above.
		 */
		if (test_data[i].nlabels == 1 &&
		    test_data[i].labels[0] == 2)
			dp_test_netlink_del_route(
				"2099:99::/64 mpt:ipv6 nh int:lo lbls 123");
	}

	/* Clean up */
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_neigh("dp2T2", "2002:2:2::10", nh_mac_str);
	dp_test_netlink_del_route("122 mpt:ipv6 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_netlink_del_route("123 mpt:ipv6 nh 2.2.2.1 int:dp2T2 lbls 23");
	dp_test_netlink_del_route("124 mpt:ipv6 nh 2002:2:2::10 int:dp2T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2002:2:2::2/64");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, mpls_fragment, NULL, NULL);
DP_START_TEST(mpls_fragment, ip_imposition)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *test_pak;
	label_t expected_labels[2];
	struct iphdr *ip;
	struct iphdr *ip_payload;
	const char *nh_mac_str;
	int len = 1472;
	struct rte_mbuf *m;
	char byte;
	char *data_ptr;
	int i;

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_set_mpls_forwarding("dp1T0", true);
	dp_test_netlink_set_interface_mtu("dp1T0", 1400);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "3.3.3.2/24");

	/* Add an lswitch entry for the local label we are about to use */
	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_add_route("88.88.0.0/24 mpt:ipv4 nh int:lo lbls 222");

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T0", "3.3.3.1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("99.99.0.1", "88.88.0.1",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;

	exp = dp_test_exp_create_m(NULL, 2);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/*
	 * We had a 1500 byte packet, so it looked like:
	 *  ip = 20  udp = 8  payload = 1472
	 * the frags are:
	 *  0  ip + 104 = 124   FO = 1378/8 = 172.
	 *  1  ip(20) + 1376 (udp hdr + udp data start) = 1396
	 */

	/* First pak out is the fragment with the end of the datagram */
	len = 124;
	m = dp_test_create_mbuf_chain(1, &len, 0);
	dp_test_pktmbuf_ip_init(m, "99.99.0.1", "88.88.0.1",
				IPPROTO_UDP);
	ip = iphdr(m);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_OFFSET, 172);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);
	/* Ip fields set - now we need to set the 104 bytes of payload */
	data_ptr = (char *)(ip + 1);
	byte = 0x58;
	for (i = 0; i < 104; i++) {
		*data_ptr = byte++;
		data_ptr++;
	}
	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1}, m);
	dp_test_pktmbuf_eth_init(expected_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_MPLS);
	rte_pktmbuf_free(m);
	exp->exp_pak[0] = expected_pak;

	/* And the last pak out has the start of the initial packet */
	len = 1396 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("99.99.0.1", "88.88.0.1",
				    1, &len);
	ip = iphdr(m);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_MORE, 1);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);
	/* copy udp header from test_pak */
	ip_payload = iphdr(test_pak);
	memcpy(ip + 1, ip_payload + 1, sizeof(struct udphdr));
	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1}, m);
	rte_pktmbuf_free(m);
	dp_test_pktmbuf_eth_init(expected_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_MPLS);
	exp->exp_pak[1] = expected_pak;

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "3.3.3.2/24");
	dp_test_netlink_del_route("88.88.0.0/24 mpt:ipv4 nh int:lo lbls 222");
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_del_neigh("dp1T0", "3.3.3.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T0", false);
	dp_test_netlink_set_interface_mtu("dp1T0", 1500);
} DP_END_TEST;

DP_START_TEST(mpls_fragment, fragmentv4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[2];
	struct iphdr *ip;
	const char *nh_mac_str;
	int len = 1472;
	struct rte_mbuf *m;
	label_t labels[2];
	uint8_t ttls[2];
	char byte;
	char *data_ptr;
	int i;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_set_interface_mtu("dp1T0", 1400);

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T0", "3.3.3.1", nh_mac_str);

	/* Create pak to match the route added above */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 0;
	labels[1] = 222;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;

	test_pak = dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_MPLS);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;

	exp = dp_test_exp_create_m(NULL, 2);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/*
	 * We had a 1500 byte packet, so it looked like:
	 *  ip = 20  udp = 8  payload = 1472
	 * the frags are:
	 *  0  ip + 104 = 124   FO = 1378/8 = 172.
	 *  1  ip(20) + 1376 (udp hdr + udp data start) = 1396
	 */

	/* First pak out is the fragment with the end of the datagram */
	len = 124;
	m = dp_test_create_mbuf_chain(1, &len, 0);
	dp_test_pktmbuf_ip_init(m, "99.99.0.0", "88.88.0.0",
				IPPROTO_UDP);
	ip = iphdr(m);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_OFFSET, 172);
	/* Ip fields set - now we need to set the 104 bytes of payload */
	data_ptr = (char *)(ip + 1);
	byte = 0x58;
	for (i = 0; i < 104; i++) {
		*data_ptr = byte++;
		data_ptr++;
	}
	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1}, m);
	dp_test_pktmbuf_eth_init(expected_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_MPLS);
	rte_pktmbuf_free(m);
	exp->exp_pak[0] = expected_pak;

	/* And the last pak out has the start of the initial packet */
	len = 1396 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
				    1, &len);
	ip = iphdr(m);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_MORE, 1);
	/* copy udp header from test_pak */
	memcpy(ip + 1,
	       (struct iphdr *)dp_test_get_mpls_pak_payload(test_pak) + 1,
	       sizeof(struct udphdr));
	expected_pak = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t []){DP_TEST_PAK_DEFAULT_TTL - 1}, m);
	rte_pktmbuf_free(m);
	dp_test_pktmbuf_eth_init(expected_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_MPLS);
	exp->exp_pak[1] = expected_pak;

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_del_neigh("dp1T0", "3.3.3.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_set_interface_mtu("dp1T0", 1500);
} DP_END_TEST;

DP_START_TEST(mpls_fragment, lswitch_three_labels)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[3];
	struct iphdr *ip;
	const char *nh_mac_str;
	int len = 1472;
	struct rte_mbuf *m;
	label_t labels[3];
	uint8_t ttls[3];
	char byte;
	char *data_ptr;
	int i;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_set_interface_mtu("dp1T0", 1400);

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T0", "3.3.3.1", nh_mac_str);

	/* Create pak to match the route added above */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 0;
	labels[1] = 222;
	labels[2] = 123;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[2] = DP_TEST_PAK_DEFAULT_TTL;

	test_pak = dp_test_create_mpls_pak(3, labels, ttls, payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_MPLS);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;
	expected_labels[1] = 123;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;

	exp = dp_test_exp_create_m(NULL, 2);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/*
	 * We had a 1500 byte packet, so it looked like:
	 *  ip = 20  udp = 8  payload = 1472
	 * the frags are:
	 *  0  ip(20) + 104 = 124   FO = 1378/8 = 172.
	 *  1  ip(20) + 1376 (udp hdr + udp data start) = 1396
	 */

	/* First pak out is the fragment with the end of the datagram */
	len = 124;
	m = dp_test_create_mbuf_chain(1, &len, 0);
	dp_test_pktmbuf_ip_init(m, "99.99.0.0", "88.88.0.0",
				IPPROTO_UDP);
	ip = iphdr(m);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_OFFSET, 172);
	/* Ip fields set - now we need to set the 104 bytes of payload */
	data_ptr = (char *)(ip + 1);
	byte = 0x58;
	for (i = 0; i < 104; i++) {
		*data_ptr = byte++;
		data_ptr++;
	}
	expected_pak = dp_test_create_mpls_pak(2, expected_labels, ttls, m);
	dp_test_pktmbuf_eth_init(expected_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_MPLS);
	rte_pktmbuf_free(m);
	exp->exp_pak[0] = expected_pak;

	/* And the last pak out has the start of the initial packet */
	len = 1396 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
				    1, &len);
	ip = iphdr(m);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_MORE, 1);
	/* copy udp header from test_pak */
	memcpy(ip + 1,
	       (struct iphdr *)dp_test_get_mpls_pak_payload(test_pak) + 1,
	       sizeof(struct udphdr));
	expected_pak = dp_test_create_mpls_pak(2, expected_labels, ttls, m);
	rte_pktmbuf_free(m);
	dp_test_pktmbuf_eth_init(expected_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_MPLS);
	exp->exp_pak[1] = expected_pak;

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_del_neigh("dp1T0", "3.3.3.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_set_interface_mtu("dp1T0", 1500);
} DP_END_TEST;

DP_START_TEST(mpls_fragment, lswitch_four_labels)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[3];
	struct iphdr *ip;
	const char *nh_mac_str;
	int len = 1472;
	struct rte_mbuf *m;
	label_t labels[4];
	uint8_t ttls[4];
	char byte;
	char *data_ptr;
	int i;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_set_interface_mtu("dp1T0", 1400);

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T0", "3.3.3.1", nh_mac_str);

	/* Create pak to match the route added above */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 0;
	labels[1] = 222;
	labels[2] = 456;
	labels[3] = 789;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[2] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[3] = DP_TEST_PAK_DEFAULT_TTL;

	test_pak = dp_test_create_mpls_pak(4, labels, ttls, payload_pak);
	rte_pktmbuf_free(payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_MPLS);

	/*
	 * Expected packet
	 */
	expected_labels[0] = 22;
	expected_labels[1] = 456;
	expected_labels[2] = 789;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[2] = DP_TEST_PAK_DEFAULT_TTL;

	exp = dp_test_exp_create_m(NULL, 2);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/*
	 * We had a 1500 byte packet, so it looked like:
	 *  ip = 20  udp = 8  payload = 1472
	 * the frags are:
	 *  0  ip(20) + 112 = 132   FO = 1368/8 = 171.
	 *  1  ip(20) + 1368 (udp hdr + udp data start) = 1388
	 */

	/* First pak out is the fragment with the end of the datagram */
	len = 132;
	m = dp_test_create_mbuf_chain(1, &len, 0);
	dp_test_pktmbuf_ip_init(m, "99.99.0.0", "88.88.0.0",
				IPPROTO_UDP);
	ip = iphdr(m);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_OFFSET, 171);
	/* Ip fields set - now we need to set the 104 bytes of payload */
	data_ptr = (char *)(ip + 1);
	byte = 0x50;
	for (i = 0; i < 112; i++) {
		*data_ptr = byte++;
		data_ptr++;
	}
	expected_pak = dp_test_create_mpls_pak(3, expected_labels, ttls, m);
	dp_test_pktmbuf_eth_init(expected_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_MPLS);
	rte_pktmbuf_free(m);
	exp->exp_pak[0] = expected_pak;

	/* And the last pak out has the start of the initial packet */
	len = 1388 - sizeof(struct udphdr) - sizeof(struct iphdr);
	m = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
				    1, &len);
	ip = iphdr(m);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_FRAG_MORE, 1);
	/* copy udp header from test_pak */
	memcpy(ip + 1,
	       (struct iphdr *)dp_test_get_mpls_pak_payload(test_pak) + 1,
	       sizeof(struct udphdr));
	expected_pak = dp_test_create_mpls_pak(3, expected_labels, ttls, m);
	rte_pktmbuf_free(m);
	dp_test_pktmbuf_eth_init(expected_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T0"),
				 RTE_ETHER_TYPE_MPLS);
	exp->exp_pak[1] = expected_pak;

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route("222 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_del_neigh("dp1T0", "3.3.3.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_set_interface_mtu("dp1T0", 1500);
} DP_END_TEST;

DP_START_TEST(mpls_icmp, frag_needed_v4_lswitch)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *payload_pak;
	label_t expected_labels[2];
	struct iphdr *ip, *copy_from;
	const char *nh_mac_str;
	int len = 1472;
	uint8_t expected_ttl = 64 /* IPDEFTTL */;
	label_t labels[2];
	uint8_t ttls[2];
	struct icmphdr *icph;
	unsigned int offset;
	int icmplen, icmpextlen;
	char *cp;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "3.3.3.2/24");

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_set_interface_mtu("dp1T0", 1400);

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T0", "3.3.3.1", nh_mac_str);

	/* Create pak to match the route added above */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);
	dp_test_set_pak_ip_field(iphdr(payload_pak), DP_TEST_SET_DF, 1);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 0;
	labels[1] = 222;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;

	test_pak = dp_test_create_mpls_pak(2, labels, ttls, payload_pak);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_MPLS);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmpextlen = 8 + 2 * 4;
	icmplen = sizeof(struct iphdr) + 576 + icmpextlen;
	icmp_pak = dp_test_create_icmp_ipv4_pak("3.3.3.2", "99.99.0.0",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						0, 1, &icmplen, NULL, &ip,
						&icph);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	/* calculate the original ip payload being copied */
	offset = RTE_MAX(128, icmplen - icmpextlen);

	/* Craft the expected icmp packet contents */

	/* aliases the length field */
	icph->un.echo.id = htons(offset / 4);
	icph->un.frag.mtu = htons(1400);

	/* Truncated original packet goes in next */
	copy_from = dp_pktmbuf_mtol3(payload_pak, struct iphdr *);
	memcpy(icph + 1, copy_from, icmplen - icmpextlen);

	/* Now the MPLS extended header */
	cp = (char *)(icph + 1) + offset;
	cp[0] = 0x20;		/* ieh_version=ICMP_EXT_HDR_VERSION */
	cp[1] = 0;		/* ieh_res=0 */
	cp[2] = cp[3] = 0;	/* ieh_cksum=0 */
	cp[4] = 0;		/* ieo_length=4 + label stack length */
	cp[5] = 4 + 8;
	cp[6] = 1;		/* ieo_cnum=ICMP_EXT_MPLS */
	cp[7] = 1;		/* ieo_ctype=ICMP_EXT_MPLS_INCOMING */

	/* The incoming label stack */
	memcpy(&cp[8], dp_pktmbuf_mtol3(test_pak, char *),
	       2 * 4);

	/* Finally the ICMP checksum fields */
	*(uint16_t *)(cp + 2) = in_cksum(cp, 4 + cp[5]);
	icph->checksum = 0;
	icph->checksum = in_cksum(icph,
				  ntohs(ip->tot_len) - icmp_pak->l3_len);

	expected_labels[0] = 22;
	expected_pak =
		dp_test_create_mpls_pak(1, expected_labels,
					&expected_ttl, icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	(void)dp_test_pktmbuf_eth_init(expected_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	rte_pktmbuf_free(payload_pak);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T0", "3.3.3.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "3.3.3.2/24");
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_set_interface_mtu("dp1T0", 1500);
} DP_END_TEST;

DP_START_TEST(mpls_icmp, frag_needed_v4_imp)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	struct icmphdr *icph;
	struct iphdr *ip;
	int len = 1472;
	int icmplen;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "3.3.3.2/24");

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_set_interface_mtu("dp1T0", 1400);

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T0", "3.3.3.1", nh_mac_str);

	dp_test_netlink_add_route("10.73.2.0/24 mpt:ipv4 nh int:lo lbls 222");

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("3.3.3.1", "10.73.2.1",
					   1, &len);
	dp_test_set_pak_ip_field(iphdr(test_pak), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("3.3.3.2", "3.3.3.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						0,
						1, &icmplen,
						iphdr(test_pak), &ip,
						&icph);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	icph->un.frag.mtu = htons(1400);

	/*
	 * The TTL allowed to be changed from the original. From RFC
	 * 1812 s4.3.2.3:
	 *   The returned IP header (and user data) MUST be identical to
	 *   that which was received, except that the router is not
	 *   required to undo any modifications to the IP header that are
	 *   normally performed in forwarding that were performed before
	 *   the error was detected (e.g., decrementing the TTL, or
	 *   updating options)
	*/
	dp_test_set_pak_ip_field((struct iphdr *)(icph + 1),
				 DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	/* Finally the ICMP checksum fields */
	icph->checksum = 0;
	icph->checksum = in_cksum(icph,
				  ntohs(ip->tot_len) - icmp_pak->l3_len);

	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route("10.73.2.0/24 mpt:ipv4 nh int:lo lbls 222");
	dp_test_netlink_del_neigh("dp1T0", "3.3.3.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "3.3.3.2/24");
	dp_test_netlink_del_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_set_interface_mtu("dp1T0", 1500);
} DP_END_TEST;

static void mpls_fragment_v4_invalid_paks(bool df)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *payload_pak;
	struct iphdr *ip;
	const char *nh_mac_str;
	int len = 1472;
	int newlen;
	label_t labels[2];
	uint8_t ttls[2];

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Add an lswitch entry for the local label we are about to use */

	dp_test_netlink_add_route("222 mpt:ipv4 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_set_interface_mtu("dp1T0", 1400);

	/* Add the nh arp we want the packet to follow */
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T0", "3.3.3.1", nh_mac_str);

	/* Create pak to match the route added above */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "88.88.0.0",
					      1, &len);
	if (df)
		dp_test_set_pak_ip_field(iphdr(payload_pak), DP_TEST_SET_DF,
					 1);

	/* Create the mpls packet that encapsulates it */
	labels[0] = 0;
	labels[1] = 222;
	ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
	ttls[1] = DP_TEST_PAK_DEFAULT_TTL;

	/*
	 * Test 1 - truncate the payload and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	/*
	 * set the packet length so that it only includes 1 byte of
	 * payload IP packet
	 */
	newlen = (char *)ip - rte_pktmbuf_mtod(test_pak, char *) + 1;
	rte_pktmbuf_trim(test_pak, test_pak->pkt_len - newlen);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 2 - make the ip hdr len too small and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ip->ihl = DP_TEST_PAK_DEFAULT_IHL - 1;
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 3 - make the checksum invalid and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ip->check = 0xdead;
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 4 - make the IP packet length too big and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ip->tot_len = htons(2000);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 5 - make the IP packet length smaller than the header
	 * length and check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ip->tot_len = htons(sizeof(struct iphdr) - 1);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Test 6 - packet destined to loopback address - check it's dropped.
	 */
	test_pak = dp_test_create_mpls_pak(2, labels, ttls, payload_pak);
	ip = dp_test_get_mpls_pak_payload(test_pak);
	ck_assert_msg(inet_pton(AF_INET, "127.0.0.1", &ip->daddr) == 1,
		      "Couldn't parse ip address");
	ip->tot_len = htons(sizeof(struct iphdr) - 1);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_MPLS);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Clean Up */
	rte_pktmbuf_free(payload_pak);
	dp_test_netlink_del_route("222 nh 3.3.3.1 int:dp1T0 lbls 22");
	dp_test_netlink_del_neigh("dp1T0", "3.3.3.1", nh_mac_str);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
	dp_test_netlink_set_interface_mtu("dp1T0", 1500);
}

DP_START_TEST(mpls_fragment, dfv4_invalid_paks)
{
	mpls_fragment_v4_invalid_paks(true);
} DP_END_TEST;

DP_START_TEST(mpls_fragment, fragment_invalid_paks)
{
	mpls_fragment_v4_invalid_paks(false);
} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, mpls_size, NULL, NULL);

DP_START_TEST(mpls_size, config)
{
	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	dp_test_console_request_reply("mpls labeltablesize 1000", false);

	dp_test_netlink_add_route("665 nh 3.3.3.1 int:dp2T2");
	dp_test_netlink_add_route("666 nh 3.3.3.1 int:dp2T2");
	dp_test_netlink_add_route("667 nh 3.3.3.1 int:dp2T2");

	/*
	 * Resize the label table and expect the labels >= new max to
	 * be removed.
	 */
	dp_test_console_request_reply("mpls labeltablesize 666", false);
	dp_test_wait_for_route_gone("666 nh 3.3.3.1 int:dp2T2", false,
				    __FILE__, __func__, __LINE__);
	dp_test_wait_for_route_gone("667 nh 3.3.3.1 int:dp2T2", false,
				    __FILE__, __func__, __LINE__);

	/*
	 * Add a label beyond max label table size. This succeeds by
	 * design as we want to avoid the race between label table
	 * size being increased and labels being added.
	 */
	dp_test_netlink_add_route("667 nh 3.3.3.1 int:dp2T2");

	/*
	 * Clean up
	 */
	dp_test_netlink_del_route("667 nh 3.3.3.1 int:dp2T2");
	dp_test_netlink_del_route("665 nh 3.3.3.1 int:dp2T2");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, mpls_oam, NULL, NULL);

DP_START_TEST(mpls_oam, v4_ecmp)
{
	const char *cmd_string = "mpls oam --labelspace=0 "
				"--source_ip=1.1.1.1 --dest_ip=127.0.1.0 "
				"--port_source=7555 --port_dest=3503 "
				"--in_label=222 --bitmask=ffffffff "
				"--masklen=32";
	const char * const expected_json_tmpl = "{ \"mpls oam\": "
	"[ "
	"  {"
	"    \"addresses\": ["
	"       {"
	"           \"broadcast\": \"%s\","
	"           \"inet\": \"%s\""
	"       }"
	"     ],"
	"     \"bitmask hi\": %u,"
	"     \"bitmask lo\": %u,"
	"     \"downstream inet\": \"%s\","
	"     \"inlabel\": %d,"
	"     \"masklen\": %d,"
	"     \"outlabels\": [ %d ]"
	"  }"
	"] }";
	json_object *expected_json;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "3.3.3.2/24");

	/* Add an labelled route entry */
	dp_test_netlink_add_route("222 mpt:ipv4 "
				  "nh 2.2.2.1 int:dp2T2 lbls 122 "
				  "nh 3.3.3.1 int:dp3T3 lbls 133");

	expected_json = dp_test_json_create(expected_json_tmpl,
			"2.2.2.255", "2.2.2.2/24", 0x0, 0x6269BBAD,
			"2.2.2.1", 222, 32, 122);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* two paths where bitmask of second is complement of first */
	expected_json = dp_test_json_create(expected_json_tmpl,
			"3.3.3.255", "3.3.3.2/24", 0x0, ~0x6269BBAD,
			"3.3.3.1", 222, 32, 133);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* Remove it */
	dp_test_netlink_del_route("222 mpt:ipv4 "
				  "nh 2.2.2.1 int:dp2T2 lbls 122 "
				  "nh 3.3.3.1 int:dp3T3 lbls 133");

	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "3.3.3.2/24");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(mpls_oam, v4_ecmp_eight_paths)
{
	const char *cmd_string = "mpls oam --labelspace=0 "
				"--source_ip=1.1.1.1 --dest_ip=127.0.1.0 "
				"--port_source=7555 --port_dest=3503 "
				"--in_label=222 --bitmask=ffff --masklen=16";
	const char * const expected_json_tmpl = "{ \"mpls oam\": "
	"[ "
	"  {"
	"    \"addresses\": ["
	"       {"
	"           \"broadcast\": \"%s\","
	"           \"inet\": \"%s\""
	"       }"
	"     ],"
	"     \"bitmask hi\": %u,"
	"     \"bitmask lo\": %u,"
	"     \"downstream inet\": \"%s\","
	"     \"inlabel\": %d,"
	"     \"masklen\": %d,"
	"     \"outlabels\": [ %d ]"
	"  }"
	"] }";
	json_object *expected_json;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T0", "2.0.0.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "3.0.0.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "4.0.0.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T3", "5.0.0.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T0", "6.0.0.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "7.0.0.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T2", "8.0.0.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "10.0.0.2/24");

	/* Add an labelled route entry */
	dp_test_netlink_add_route("222 mpt:ipv4 "
				  "nh 2.0.0.1 int:dp2T0 lbls 22 "
				  "nh 3.0.0.1 int:dp2T1 lbls 33 "
				  "nh 4.0.0.1 int:dp2T2 lbls 44 "
				  "nh 5.0.0.1 int:dp2T3 lbls 55 "
				  "nh 6.0.0.1 int:dp3T0 lbls 66 "
				  "nh 7.0.0.1 int:dp3T1 lbls 77 "
				  "nh 8.0.0.1 int:dp3T2 lbls 88 "
				  "nh 10.0.0.1 int:dp3T3 lbls 99");

	expected_json = dp_test_json_create(expected_json_tmpl,
			"2.0.0.255", "2.0.0.2/24", 0x0, 0x1,
			"2.0.0.1", 222, 16, 22);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"3.0.0.255", "3.0.0.2/24", 0x0, 0x9094,
			"3.0.0.1", 222, 16, 33);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"4.0.0.255", "4.0.0.2/24", 0x0, 0x2200,
			"4.0.0.1", 222, 16, 44);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"5.0.0.255", "5.0.0.2/24", 0x0, 0x800,
			"5.0.0.1", 222, 16, 55);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"6.0.0.255", "6.0.0.2/24", 0x0, 0x4008,
			"6.0.0.1", 222, 16, 66);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"7.0.0.255", "7.0.0.2/24", 0x0, 0x100,
			"7.0.0.1", 222, 16, 77);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"8.0.0.255", "8.0.0.2/24", 0x0, 0x60,
			"8.0.0.1", 222, 16, 88);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"10.0.0.255", "10.0.0.2/24", 0x0, 0x402,
			"10.0.0.1", 222, 16, 99);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* Remove it */
	dp_test_netlink_del_route("222 mpt:ipv4 "
				  "nh 2.0.0.1 int:dp2T0 lbls 22 "
				  "nh 3.0.0.1 int:dp2T1 lbls 33 "
				  "nh 4.0.0.1 int:dp2T2 lbls 44 "
				  "nh 5.0.0.1 int:dp2T3 lbls 55 "
				  "nh 6.0.0.1 int:dp3T0 lbls 66 "
				  "nh 7.0.0.1 int:dp3T1 lbls 77 "
				  "nh 8.0.0.1 int:dp3T2 lbls 88 "
				  "nh 10.0.0.1 int:dp3T3 lbls 99");

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T0", "2.0.0.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "3.0.0.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "4.0.0.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T3", "5.0.0.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T0", "6.0.0.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "7.0.0.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T2", "8.0.0.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "10.0.0.2/24");
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(mpls_oam, v4_ecmp_lswitch)
{
	const char *nh_mac_str1, *nh_mac_str2;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	struct dp_test_expected *exp;
	label_t expected_labels[1];
	label_t labels[1];
	uint8_t ttls[1];
	int i, j, len = 22;
	uint64_t bitmask;
	const char *cmd_string = "mpls oam --labelspace=0 "
				"--source_ip=1.1.1.1 --dest_ip=127.0.1.0 "
				"--port_source=7555 --port_dest=3503 "
				"--in_label=222 "
				"--bitmask=ffffffffffffffff --masklen=64";
	const char * const expected_json_tmpl = "{ \"mpls oam\": "
	"[ "
	"  {"
	"    \"addresses\": ["
	"       {"
	"           \"broadcast\": \"%s\","
	"           \"inet\": \"%s\""
	"       }"
	"     ],"
	"     \"bitmask hi\": %u,"
	"     \"bitmask lo\": %u,"
	"     \"downstream inet\": \"%s\","
	"     \"inlabel\": %d,"
	"     \"masklen\": %d,"
	"     \"outlabels\": [ %d ]"
	"  }"
	"] }";
	json_object *expected_json;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "3.3.3.2/24");

	/* Add an labelled route entry */
	dp_test_netlink_add_route("222 mpt:ipv4 "
				  "nh 2.2.2.1 int:dp2T2 lbls 122 "
				  "nh 3.3.3.1 int:dp3T3 lbls 133");

	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str1);

	nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	dp_test_netlink_add_neigh("dp3T3", "3.3.3.1", nh_mac_str2);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"2.2.2.255", "2.2.2.2/24", 0x6269BBAD,
			0xA4DF33EB, "2.2.2.1", 222, 64, 122);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* two paths where bitmask of second is complement of first */
	expected_json = dp_test_json_create(expected_json_tmpl,
			"3.3.3.255", "3.3.3.2/24", ~0x6269BBAD,
			~0xA4DF33EB, "3.3.3.1", 222, 64, 133);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* Check corresponding packets follow expected path */
	bitmask = (uint64_t)0xA4DF33EB;
	bitmask |= ((uint64_t)0x6269BBAD << 32);

	for (i = 0, j = (64 - 1); j >= 0; i++, j--) {
		char dest[INET_ADDRSTRLEN];
		bool first_path;

		snprintf(dest, sizeof(dest), "127.0.1.%d", i);
		payload_pak = dp_test_create_udp_ipv4_pak("1.1.1.1", dest,
							  7555, 3503, 1, &len);
		labels[0] = 222;
		ttls[0] = DP_TEST_PAK_DEFAULT_TTL;

		test_pak = dp_test_create_mpls_pak(1, labels, ttls,
						   payload_pak);
		(void)dp_test_pktmbuf_eth_init(test_pak,
					dp_test_intf_name2mac_str("dp1T1"),
					NULL, RTE_ETHER_TYPE_MPLS);

		first_path = (bitmask & ((uint64_t)1 << j));

		/*
		 * Expected packet
		 */
		expected_labels[0] = first_path ? 122 : 133;
		ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
		expected_pak = dp_test_create_mpls_pak(1, expected_labels, ttls,
						       payload_pak);
		if (first_path) {
			(void)dp_test_pktmbuf_eth_init(expected_pak,
					nh_mac_str1,
					dp_test_intf_name2mac_str("dp2T2"),
					RTE_ETHER_TYPE_MPLS);

			exp = dp_test_exp_create(expected_pak);
			dp_test_exp_set_oif_name(exp, "dp2T2");
		} else {
			(void)dp_test_pktmbuf_eth_init(expected_pak,
					nh_mac_str2,
					dp_test_intf_name2mac_str("dp3T3"),
					RTE_ETHER_TYPE_MPLS);

			exp = dp_test_exp_create(expected_pak);
			dp_test_exp_set_oif_name(exp, "dp3T3");
		}

		/* now send test pak and check we get expected back */
		dp_test_pak_receive(test_pak, "dp1T1", exp);

		rte_pktmbuf_free(payload_pak);
		rte_pktmbuf_free(expected_pak);
	}

	/* Clean Up */
	dp_test_netlink_del_route("222 mpt:ipv4 "
				  "nh 2.2.2.1 int:dp2T2 lbls 122 "
				  "nh 3.3.3.1 int:dp3T3 lbls 133");

	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "3.3.3.2/24");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp3T3", "3.3.3.1", nh_mac_str2);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(mpls_oam, v4_ecmp_lswitch_two_labels)
{
	const char *nh_mac_str1, *nh_mac_str2;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	struct dp_test_expected *exp;
	label_t expected_labels[2];
	label_t labels[2];
	uint8_t ttls[2];
	int i, j, len = 22;
	uint64_t bitmask;
	const char *cmd_string = "mpls oam --labelspace=0 "
				"--source_ip=1.1.1.1 --dest_ip=127.0.1.0 "
				"--port_source=7555 --port_dest=3503 "
				"--in_label=222 --in_label=123 "
				"--bitmask=ffffffffffffffff --masklen=64";
	const char * const expected_json_tmpl = "{ \"mpls oam\": "
	"[ "
	"  {"
	"    \"addresses\": ["
	"       {"
	"           \"broadcast\": \"%s\","
	"           \"inet\": \"%s\""
	"       }"
	"     ],"
	"     \"bitmask hi\": %u,"
	"     \"bitmask lo\": %u,"
	"     \"downstream inet\": \"%s\","
	"     \"inlabel\": %d,"
	"     \"masklen\": %d,"
	"     \"outlabels\": [ %d ]"
	"  }"
	"] }";
	json_object *expected_json;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "3.3.3.2/24");

	/* Add an labelled route entry */
	dp_test_netlink_add_route("222 mpt:ipv4 "
				  "nh 2.2.2.1 int:dp2T2 lbls 122 "
				  "nh 3.3.3.1 int:dp3T3 lbls 133");

	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str1);

	nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	dp_test_netlink_add_neigh("dp3T3", "3.3.3.1", nh_mac_str2);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"2.2.2.255", "2.2.2.2/24", 0x43E0D532,
			0xECB0ECF7, "2.2.2.1", 222, 64, 122);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* two paths where bitmask of second is complement of first */
	expected_json = dp_test_json_create(expected_json_tmpl,
			"3.3.3.255", "3.3.3.2/24", ~0x43E0D532,
			~0xECB0ECF7, "3.3.3.1", 222, 64, 133);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* Check corresponding packets follow expected path */
	bitmask = (uint64_t)0xECB0ECF7;
	bitmask |= ((uint64_t)0x43E0D532 << 32);

	for (i = 0, j = (64 - 1); j >= 0; i++, j--) {
		char dest[INET_ADDRSTRLEN];
		bool first_path;

		snprintf(dest, sizeof(dest), "127.0.1.%d", i);
		payload_pak = dp_test_create_udp_ipv4_pak("1.1.1.1", dest,
							  7555, 3503, 1, &len);
		labels[0] = 222;
		labels[1] = 123;
		ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
		ttls[1] = DP_TEST_PAK_DEFAULT_TTL;

		test_pak = dp_test_create_mpls_pak(2, labels, ttls,
						   payload_pak);
		(void)dp_test_pktmbuf_eth_init(test_pak,
					dp_test_intf_name2mac_str("dp1T1"),
					NULL, RTE_ETHER_TYPE_MPLS);

		first_path = (bitmask & ((uint64_t)1 << j));

		/*
		 * Expected packet
		 */
		expected_labels[0] = first_path ? 122 : 133;
		expected_labels[1] = 123;
		ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
		ttls[1] = DP_TEST_PAK_DEFAULT_TTL;
		expected_pak = dp_test_create_mpls_pak(2, expected_labels, ttls,
						       payload_pak);
		if (first_path) {
			(void)dp_test_pktmbuf_eth_init(expected_pak,
					nh_mac_str1,
					dp_test_intf_name2mac_str("dp2T2"),
					RTE_ETHER_TYPE_MPLS);

			exp = dp_test_exp_create(expected_pak);
			dp_test_exp_set_oif_name(exp, "dp2T2");
		} else {
			(void)dp_test_pktmbuf_eth_init(expected_pak,
					nh_mac_str2,
					dp_test_intf_name2mac_str("dp3T3"),
					RTE_ETHER_TYPE_MPLS);

			exp = dp_test_exp_create(expected_pak);
			dp_test_exp_set_oif_name(exp, "dp3T3");
		}

		/* now send test pak and check we get expected back */
		dp_test_pak_receive(test_pak, "dp1T1", exp);

		rte_pktmbuf_free(payload_pak);
		rte_pktmbuf_free(expected_pak);
	}

	/* Clean Up */
	dp_test_netlink_del_route("222 mpt:ipv4 "
				  "nh 2.2.2.1 int:dp2T2 lbls 122 "
				  "nh 3.3.3.1 int:dp3T3 lbls 133");

	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "3.3.3.2/24");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp3T3", "3.3.3.1", nh_mac_str2);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_START_TEST(mpls_oam, v4_ecmp_lswitch_three_labels)
{
	const char *nh_mac_str1, *nh_mac_str2;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	struct dp_test_expected *exp;
	label_t expected_labels[3];
	label_t labels[3];
	uint8_t ttls[3];
	int i, j, len = 22;
	uint64_t bitmask;
	const char *cmd_string = "mpls oam --labelspace=0 "
				"--source_ip=1.1.1.1 --dest_ip=127.0.1.0 "
				"--port_source=7555 --port_dest=3503 "
				"--in_label=222 --in_label=123 --in_label=456 "
				"--bitmask=ffffffffffffffff --masklen=64";
	const char * const expected_json_tmpl = "{ \"mpls oam\": "
	"[ "
	"  {"
	"    \"addresses\": ["
	"       {"
	"           \"broadcast\": \"%s\","
	"           \"inet\": \"%s\""
	"       }"
	"     ],"
	"     \"bitmask hi\": %u,"
	"     \"bitmask lo\": %u,"
	"     \"downstream inet\": \"%s\","
	"     \"inlabel\": %d,"
	"     \"masklen\": %d,"
	"     \"outlabels\": [ %d ]"
	"  }"
	"] }";
	json_object *expected_json;

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "3.3.3.2/24");

	/* Add an labelled route entry */
	dp_test_netlink_add_route("222 mpt:ipv4 "
				  "nh 2.2.2.1 int:dp2T2 lbls 122 "
				  "nh 3.3.3.1 int:dp3T3 lbls 133");

	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str1);

	nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	dp_test_netlink_add_neigh("dp3T3", "3.3.3.1", nh_mac_str2);

	expected_json = dp_test_json_create(expected_json_tmpl,
			"2.2.2.255", "2.2.2.2/24", 0x8D16D23D,
			0x58F6C7E3, "2.2.2.1", 222, 64, 122);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* two paths where bitmask of second is complement of first */
	expected_json = dp_test_json_create(expected_json_tmpl,
			"3.3.3.255", "3.3.3.2/24", ~0x8D16D23D,
			~0x58F6C7E3, "3.3.3.1", 222, 64, 133);

	dp_test_check_json_state(cmd_string, expected_json,
				 DP_TEST_JSON_CHECK_SUBSET, false);

	json_object_put(expected_json);

	/* Check corresponding packets follow expected path */
	bitmask = (uint64_t)0x58F6C7E3;
	bitmask |= ((uint64_t)0x8D16D23D << 32);

	for (i = 0, j = (64 - 1); j >= 0; i++, j--) {
		char dest[INET_ADDRSTRLEN];
		bool first_path;

		snprintf(dest, sizeof(dest), "127.0.1.%d", i);
		payload_pak = dp_test_create_udp_ipv4_pak("1.1.1.1", dest,
							  7555, 3503, 1, &len);
		labels[0] = 222;
		labels[1] = 123;
		labels[2] = 456;
		ttls[0] = DP_TEST_PAK_DEFAULT_TTL;
		ttls[1] = DP_TEST_PAK_DEFAULT_TTL;
		ttls[2] = DP_TEST_PAK_DEFAULT_TTL;

		test_pak = dp_test_create_mpls_pak(3, labels, ttls,
						   payload_pak);
		(void)dp_test_pktmbuf_eth_init(test_pak,
					dp_test_intf_name2mac_str("dp1T1"),
					NULL, RTE_ETHER_TYPE_MPLS);

		first_path = (bitmask & ((uint64_t)1 << j));

		/*
		 * Expected packet
		 */
		expected_labels[0] = first_path ? 122 : 133;
		expected_labels[1] = 123;
		expected_labels[2] = 456;
		ttls[0] = DP_TEST_PAK_DEFAULT_TTL - 1;
		ttls[1] = DP_TEST_PAK_DEFAULT_TTL;
		ttls[2] = DP_TEST_PAK_DEFAULT_TTL;
		expected_pak = dp_test_create_mpls_pak(3, expected_labels, ttls,
						       payload_pak);
		if (first_path) {
			(void)dp_test_pktmbuf_eth_init(expected_pak,
					nh_mac_str1,
					dp_test_intf_name2mac_str("dp2T2"),
					RTE_ETHER_TYPE_MPLS);

			exp = dp_test_exp_create(expected_pak);
			dp_test_exp_set_oif_name(exp, "dp2T2");
		} else {
			(void)dp_test_pktmbuf_eth_init(expected_pak,
					nh_mac_str2,
					dp_test_intf_name2mac_str("dp3T3"),
					RTE_ETHER_TYPE_MPLS);

			exp = dp_test_exp_create(expected_pak);
			dp_test_exp_set_oif_name(exp, "dp3T3");
		}

		/* now send test pak and check we get expected back */
		dp_test_pak_receive(test_pak, "dp1T1", exp);

		rte_pktmbuf_free(payload_pak);
		rte_pktmbuf_free(expected_pak);
	}

	/* Clean Up */
	dp_test_netlink_del_route("222 mpt:ipv4 "
				  "nh 2.2.2.1 int:dp2T2 lbls 122 "
				  "nh 3.3.3.1 int:dp3T3 lbls 133");

	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "3.3.3.2/24");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp3T3", "3.3.3.1", nh_mac_str2);
	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;

DP_DECL_TEST_CASE(mpls, imp_fwd_outlabels, NULL, NULL);

DP_START_TEST(imp_fwd_outlabels, v4_single)
{
	struct iphdr *ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	label_t expected_labels[DP_TEST_MAX_LBLS];
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	uint8_t ttls[DP_TEST_MAX_LBLS];
	int i, nlbls, len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_netlink_set_mpls_forwarding("dp1T2", true);

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	for (nlbls = 1; nlbls <= DP_TEST_MAX_LBLS; nlbls++) {
		char lstack_str[TEST_MAX_CMD_LEN + 1] = {'\0'};
		char label_str[TEST_MAX_CMD_LEN + 1];
		char route1[TEST_MAX_CMD_LEN + 1];

		for (i = 0; i < nlbls; i++) {
			snprintf(label_str, sizeof(label_str), " %d", 122 + i);
			strncat(lstack_str, label_str, TEST_MAX_CMD_LEN);
			expected_labels[i] = 122 + i;
			ttls[i] = DP_TEST_PAK_DEFAULT_TTL - 1;
		}

		/* Add the route / nh arp we want the packet to follow */
		snprintf(route1, TEST_MAX_CMD_LEN,
			 "10.73.2.0/24 nh 2.2.2.1 int:dp2T2 lbls %s",
			 lstack_str);
		dp_test_netlink_add_route(route1);

		/*
		 * Test packet
		 */
		test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
						   1, &len);
		(void)dp_test_pktmbuf_eth_init(
			test_pak,
			dp_test_intf_name2mac_str("dp1T1"),
			NULL, RTE_ETHER_TYPE_IPV4);

		/*
		 * Expected packet
		 */
		expected_pak = dp_test_create_mpls_pak(nlbls, expected_labels,
						       ttls, test_pak);
		(void)dp_test_pktmbuf_eth_init(
			expected_pak,
			nh_mac_str,
			dp_test_intf_name2mac_str("dp2T2"),
			RTE_ETHER_TYPE_MPLS);

		ip = dp_test_get_mpls_pak_payload(expected_pak);
		dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
					 DP_TEST_PAK_DEFAULT_TTL - 1);

		exp = dp_test_exp_create(expected_pak);
		rte_pktmbuf_free(expected_pak);
		dp_test_exp_set_oif_name(exp, "dp2T2");

		dp_test_pak_receive(test_pak, "dp1T1", exp);

		/* Clean up */
		dp_test_netlink_del_route(route1);
	}

	/* Clean up */
	dp_test_netlink_set_mpls_forwarding("dp1T2", false);
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

} DP_END_TEST;

DP_START_TEST(imp_fwd_outlabels, v4_ecmp)
{
	struct iphdr *ip;
	struct dp_test_expected *exp1, *exp2;
	struct rte_mbuf *expected_pak1, *expected_pak2;
	label_t expected_labels[2];
	struct rte_mbuf *test_pak1, *test_pak2;
	const char *nh_mac_str1, *nh_mac_str2;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "3.3.3.3/24");

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str1);
	nh_mac_str2 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp3T3", "3.3.3.1", nh_mac_str2);

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("10.73.2.0/24 "
				  "nh 2.2.2.1 int:dp2T2 lbls 22 "
				  "nh 3.3.3.1 int:dp3T3 lbls 33 ");

	/*
	 * Test packet
	 */
	test_pak1 = dp_test_create_ipv4_pak("10.73.0.1", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak1,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet1
	 */
	expected_labels[0] = 22;
	expected_pak1 = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL - 1},
		test_pak1);
	(void)dp_test_pktmbuf_eth_init(expected_pak1,
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_MPLS);

	ip = dp_test_get_mpls_pak_payload(expected_pak1);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp1 = dp_test_exp_create(expected_pak1);
	rte_pktmbuf_free(expected_pak1);
	dp_test_exp_set_oif_name(exp1, "dp2T2");

	dp_test_pak_receive(test_pak1, "dp1T1", exp1);

	/*
	 *  Test packet2
	 */
	test_pak2 = dp_test_create_ipv4_pak("10.73.0.9", "10.73.2.0",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak2,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL,
				       RTE_ETHER_TYPE_IPV4);
	/*
	 * Expected packet2
	 */
	expected_labels[0] = 33;
	expected_pak2 = dp_test_create_mpls_pak(
		1, expected_labels,
		(uint8_t[]){DP_TEST_PAK_DEFAULT_TTL - 1},
		test_pak2);
	(void)dp_test_pktmbuf_eth_init(expected_pak2,
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_MPLS);

	ip = dp_test_get_mpls_pak_payload(expected_pak2);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp2 = dp_test_exp_create(expected_pak2);
	rte_pktmbuf_free(expected_pak2);
	dp_test_exp_set_oif_name(exp2, "dp3T3");

	dp_test_pak_receive(test_pak2, "dp1T1", exp2);

	/* Clean up */
	dp_test_netlink_del_route("10.73.2.0/24 "
				  "nh 2.2.2.1 int:dp2T2 lbls 22 "
				  "nh 3.3.3.1 int:dp3T3 lbls 33 ");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp3T3", "3.3.3.1", nh_mac_str2);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "3.3.3.3/24");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
} DP_END_TEST;
