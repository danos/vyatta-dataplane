/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * dataplane UT slow path tests
 */

#include "if_var.h"
#include "ip_funcs.h"
#include "main.h"
#include "shadow.h"
#include "if/gre.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_crypto_utils.h"

DP_DECL_TEST_SUITE(slow_suite);


DP_DECL_TEST_CASE(slow_suite, slow_dp_pkt, NULL, NULL);

/*
 * This is from-us traffic from the controller kernel to the dataplane.
 *
 * VR: The kernel fully forms the pak, including specifying the output interface
 * and the L2 header.  The dataplane just arps for the L2 dest out of the given
 * interface and sends the pak.
 */
DP_START_TEST(slow_dp_pkt, test_shadow_ipv4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	const char *dest_addrs[3] = {"1.1.1.2",    /* directly connected */
				     "5.5.5.2",    /* via nh */
				     "224.0.0.5"}; /* multicast */
	int len = 22;
	int i;

	/* Create pak to send on shadow interface
	 */
	for (i = 0; i < 3; i++) {
		const char *dst_mac_str;
		const char *exp_mac_str;

		/* VR passes eth encapped by kernel */
		dst_mac_str = exp_mac_str = nh_mac_str;

		test_pak = dp_test_create_ipv4_pak("10.73.0.10", dest_addrs[i],
					   1, &len);
		dp_test_pktmbuf_eth_init(test_pak, dst_mac_str,
					 dp_test_intf_name2mac_str("dp1T0"),
					 RTE_ETHER_TYPE_IPV4);

		/* Create pak we expect to receive on the tx ring */
		exp = dp_test_exp_create(test_pak);
		dp_test_exp_set_oif_name(exp, "dp1T0");
		dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
					 exp_mac_str,
					 dp_test_intf_name2mac_str("dp1T0"),
					 RTE_ETHER_TYPE_IPV4);

		dp_test_send_slowpath_pkt(test_pak, exp);
	}
} DP_END_TEST;

/*
 */
DP_START_TEST(slow_dp_pkt, test_shadow_ipv6)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	const char *dest_addrs[3] = {"2001:1:1::2",  /* directly connected */
				     "2002:1:1::2",  /* via nh */
				     "ff02::5"};     /* multicast */
	int len = 22;
	int i;

	/* Create pak to send on shadow interface
	 */
	for (i = 0; i < 3; i++) {
		const char *dst_mac_str;
		const char *exp_mac_str;

		/* VR passes eth encapped by kernel */
		dst_mac_str = exp_mac_str = nh_mac_str;

		test_pak = dp_test_create_ipv6_pak("2010:73::10", dest_addrs[i],
						   1, &len);
		dp_test_pktmbuf_eth_init(test_pak, dst_mac_str,
					 dp_test_intf_name2mac_str("dp1T0"),
					 RTE_ETHER_TYPE_IPV6);

		/* Create pak we expect to receive on the tx ring */
		exp = dp_test_exp_create(test_pak);
		dp_test_exp_set_oif_name(exp, "dp1T0");
		dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
					 exp_mac_str,
					 dp_test_intf_name2mac_str("dp1T0"),
					 RTE_ETHER_TYPE_IPV6);

		dp_test_send_slowpath_pkt(test_pak, exp);
	}
} DP_END_TEST;

DP_START_TEST(slow_dp_pkt, test_spath_gre)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *nh_mac_str;
	struct rte_mbuf *test_pak, *payload_pak;
	int len = 64;
	int gre_pl_len;
	void *gre_payload;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";
	nh_mac_str = "aa:bb:cc:dd:ee:ff";

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.2.1/24");
	dp_test_netlink_add_neigh("dp1T1", "1.1.2.2", nh_mac_str);

	dp_test_intf_gre_l2_create("tun1", "1.1.2.1", "1.1.2.2", 0);

	/*
	 * Create frame from mac_a to mac_b
	 */
	payload_pak = dp_test_create_l2_pak(mac_b, mac_a,
					    DP_TEST_ET_BANYAN, 1, &len);
	gre_pl_len = rte_pktmbuf_data_len(payload_pak);
	test_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.1", "1.1.2.2", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(payload_pak,
				const struct rte_ether_hdr *), gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(test_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(test_pak,
				 nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T1"),
				 RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	rte_pktmbuf_free(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");
	dp_test_send_spath_pkt(payload_pak, "tun1", exp);

	/*
	 * Case 2
	 */
	payload_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(payload_pak, nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T1"),
				 RTE_ETHER_TYPE_IPV4);

	gre_pl_len = rte_pktmbuf_data_len(payload_pak);

	test_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.1", "1.1.2.2", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(payload_pak,
				const struct rte_ether_hdr *), gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(test_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(test_pak,
				 nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T1"),
				 RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	rte_pktmbuf_free(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");
	dp_test_send_spath_pkt(payload_pak, "tun1", exp);

	/*
	 * Clean up
	 */

	dp_test_intf_gre_l2_delete("tun1", "1.1.2.1", "1.1.2.2", 0);

	dp_test_netlink_del_neigh("dp1T1", "1.1.2.2", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.2.1/24");

} DP_END_TEST;
