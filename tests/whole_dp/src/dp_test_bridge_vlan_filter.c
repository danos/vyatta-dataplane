/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT Bridge tests
 */

#include "dp_test.h"
#include "dp_test_lib.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"

#include "ip_funcs.h"

DP_DECL_TEST_SUITE(bridge_vlan_filter_suite);

/*Test netlink handlers for vlan aware bridging*/
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	bridge_create_vlan_filter, NULL, NULL);
DP_START_TEST(bridge_create_vlan_filter, bridge_create_vlan_filter)
{
	dp_test_intf_bridge_create("br0");
	dp_test_intf_bridge_enable_vlan_filter("br0");
	dp_test_intf_bridge_add_port("br0", "dp1T0");
	dp_test_intf_bridge_add_port("br0", "dp2T1");
	dp_test_intf_bridge_remove_port("br0", "dp1T0");
	dp_test_intf_bridge_remove_port("br0", "dp2T1");
	dp_test_intf_bridge_del("br0");
} DP_END_TEST;

DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	bridge_add_allowed_vlan, NULL, NULL);
DP_START_TEST(bridge_add_allowed_vlan, bridge_add_allowed_vlan)
{
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(allowed_vlans, 1);
	bridge_vlan_set_add(allowed_vlans, 10);
	dp_test_intf_bridge_create("br0");
	dp_test_intf_bridge_enable_vlan_filter("br0");

	dp_test_intf_bridge_add_port("br0", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br0", "dp1T0",
		0, allowed_vlans, NULL);

	dp_test_intf_bridge_add_port("br0", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("br0", "dp2T1",
		0, allowed_vlans, NULL);

	dp_test_intf_bridge_remove_port("br0", "dp1T0");
	dp_test_intf_bridge_remove_port("br0", "dp2T1");
	dp_test_intf_bridge_del("br0");
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

/*
 * Test L2 forwarding to a unicast destination on a vlan
 *
 * Test mac_a can reach mac_b, where;
 * mac_a -> dp1T0 br1 dp2T1 -> mac_b
 */
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	bridge_vlan_filter_unicast, NULL, NULL);
DP_START_TEST(bridge_vlan_filter_unicast, bridge_vlan_filter_unicast)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(allowed_vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, allowed_vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp2T1",
		0, allowed_vlans, NULL);

	/*
	 * mac_a -> mac_b
	 */

	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * mac_b -> mac_a
	 */

	/* Create frame from mac_b to mac_a */
	test_pak = dp_test_create_8021q_l2_pak(mac_a, mac_b, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp2T1", exp);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

/*
 * Test L2 forwarding to an unknown unicast destination.
 * Bridge has 3 ports, so frame should be flooded out of the 2 remote ports.
 */
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	br_vlan_filter_uni_flood, NULL, NULL);
DP_START_TEST(br_vlan_filter_uni_flood, br_vlan_filter_uni_flood)
{
	struct dp_test_expected *exp;
	const char *mac_c, *mac_d;
	struct rte_mbuf *test_pak;
	int len = 64;

	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(allowed_vlans, 10);

	mac_c = "00:00:a4:00:00:cc";
	mac_d = "00:00:a4:00:00:dd";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");

	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, allowed_vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp2T1",
		0, allowed_vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp3T2");
	dp_test_intf_bridge_port_set_vlans("br1", "dp3T2",
		0, allowed_vlans, NULL);

	/* Create frame from mac_c to mac_d */
	test_pak = dp_test_create_8021q_l2_pak(mac_d, mac_c, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp3T2");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_remove_port("br1", "dp3T2");
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

/*
 * Test L2 forwarding to a broadcast destination.
 *
 * Test mac_a can send initial packet to a L2 bcast;
 * mac_a -> dp1T0 br1  , mac_b-> dp1T0 br1, 2 member ports in bridge
 */
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	broadcast_vlan_filter_2port, NULL, NULL);

DP_START_TEST(broadcast_vlan_filter_2port, bridge_vlan_filter_broadcast_2port)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_bcast;
	struct rte_mbuf *test_pak;
	int len = 64;

	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(allowed_vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_bcast = "ff:ff:ff:ff:ff:ff";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_vif_create("br1.10", "br1", 10);
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, allowed_vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp2T1",
		0, allowed_vlans, NULL);

	/*
	 * mac_a -> mac_bcast
	 *
	 * Only Spanning Tree and ARP multi/broadcast and, conditionally, IPv4
	 * and IPv6 are sent upstream.
	 */

	/* Create frame from mac_a to mac_bcast */
	test_pak = dp_test_create_8021q_l2_pak(mac_bcast, mac_a, 10,
					       ETH_P_8021Q,
					       ETH_P_8021Q,
					       1, &len);


	exp = dp_test_exp_create_m(test_pak, 1);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 0, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Reply from mac_b
	 * mac_b -> mac_a
	 */

	/* Create frame from mac_b to mac_a, reply will be L2 unicast */
	test_pak = dp_test_create_8021q_l2_pak(mac_a, mac_b, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);


	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp2T1", exp);
	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_vif_del("br1.10", 10);
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

/*
 * Test L2 forwarding to a broadcast destination ipv4 payload.
 *
 * The type of payload being IPv4 should not matter, since we are bridging
 * however we have had bugs where frames containing IPv4 has been treated
 * differently than other L2 traffic.
 */
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	broadcast_vlan_filter_2port_ipv4, NULL, NULL);
DP_START_TEST(broadcast_vlan_filter_2port_ipv4,
	broadcast_vlan_filter_2port_ipv4)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_bcast;
	struct rte_mbuf *test_pak;
	int len = 64;

	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(allowed_vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_bcast = "ff:ff:ff:ff:ff:ff";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_vif_create("br1.10", "br1", 10);
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, allowed_vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp2T1",
		0, allowed_vlans, NULL);

	/*
	 * mac_a -> mac_bcast, ethertype Banyan
	 *
	 * Only Spanning Tree and ARP multi/broadcast and, conditionally, IPv4
	 * and IPv6 are sent upstream.
	 */

	/* Create frame from mac_a to mac_bcast */
	test_pak = dp_test_create_ipv4_pak("10.73.0.1", "3.3.3.3",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak, mac_bcast, mac_a,
				       ETHER_TYPE_IPv4);
	dp_test_pktmbuf_vlan_init(test_pak, 10);

	/* We expect the dataplane to flood to member ports and to slowpath */
	exp = dp_test_exp_create_m(test_pak, 2);

	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Reply from mac_b
	 * mac_b -> mac_a
	 */

	/* Create frame from mac_b to mac_a, reply will be L2 unicast */
	test_pak = dp_test_create_ipv4_pak("3.3.3.3", "10.73.0.1", 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak, mac_a, mac_b,
				       ETHER_TYPE_IPv4);
	dp_test_pktmbuf_vlan_init(test_pak, 10);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp2T1", exp);
	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_vif_del("br1.10", 10);
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

/*
 * Test L2 forwarding to a broadcast destination ipv6 payload.
 *
 * The type of payload being IPv4 should not matter, since we are bridging.
 */
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	broadcast_vlan_filter_2port_ipv6, NULL, NULL);
DP_START_TEST(broadcast_vlan_filter_2port_ipv6,
	broadcast_vlan_filter_2port_ipv6)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_bcast;
	struct rte_mbuf *test_pak;
	int len = 64;
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(allowed_vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_bcast = "ff:ff:ff:ff:ff:ff";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_vif_create("br1.10", "br1", 10);
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, allowed_vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp2T1",
		0, allowed_vlans, NULL);

	/*
	 * mac_a -> mac_bcast, ethertype Banyan
	 *
	 * Only Spanning Tree and ARP multi/broadcast and, conditionally, IPv4
	 * and IPv6 are sent upstream.
	 */

	/* Create frame from mac_a to mac_bcast */
	test_pak = dp_test_create_ipv6_pak("2001:1:1::2", "2002:2:2::2",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak, mac_bcast, mac_a,
				       ETHER_TYPE_IPv6);
	dp_test_pktmbuf_vlan_init(test_pak, 10);

	/* We expect the dataplane to flood to member ports and to slowpath */
	exp = dp_test_exp_create_m(test_pak, 2);

	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Reply from mac_b
	 * mac_b -> mac_a
	 */

	/* Create frame from mac_b to mac_a, reply will be L2 unicast */
	test_pak = dp_test_create_ipv6_pak("2002:2:2::2", "2001:1:1::2",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak, mac_a, mac_b,
				       ETHER_TYPE_IPv6);
	dp_test_pktmbuf_vlan_init(test_pak, 10);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp2T1", exp);
	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_vif_del("br1.10", 10);
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

/*
 * Test L2 forwarding to a broadcast destination ipv4 multicast payload.
 *
 * The type of payload being IPv4 multicast should not matter, since we
 * are bridging we should not even look at L3 payload.
 */
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	broadcast_vlan_filter_2port_ipv4_multi, NULL, NULL);
DP_START_TEST(broadcast_vlan_filter_2port_ipv4_multi,
	broadcast_vlan_filter_2port_ipv4_multi)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_multi, *ipv4_multi;
	struct rte_mbuf *test_pak;
	int len = 64;
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(allowed_vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_multi = "01:00:5e:01:02:03";
	ipv4_multi = "224.1.2.3";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_vif_create("br1.10", "br1", 10);
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, allowed_vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp2T1",
		0, allowed_vlans, NULL);

	/* Create frame from mac_a to mac_multi */
	test_pak = dp_test_create_ipv4_pak(ipv4_multi, "3.3.3.3",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak, mac_multi, mac_a,
				       ETHER_TYPE_IPv4);
	dp_test_pktmbuf_vlan_init(test_pak, 10);

	/* We expect the dataplane to flood to member ports and to slowpath */
	exp = dp_test_exp_create_m(test_pak, 2);

	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_vif_del("br1.10", 10);
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

/*
 * Test L2 forwarding to a unicast destination on a vlan with pvids
 *
 * Test mac_a can reach mac_b, where;
 * mac_a -> dp1T0 br1 dp1T1 -> mac_b
 */
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	bridge_pvid_unicast, NULL, NULL);
DP_START_TEST(bridge_pvid_unicast, bridge_pvid_unicast)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	struct bridge_vlan_set *vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		10, vlans, vlans);
	dp_test_intf_bridge_add_port("br1", "dp1T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T1",
		10, vlans, vlans);

	/*
	 * mac_a -> mac_b
	 */

	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
		DP_TEST_ET_LLDP, 1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * mac_b -> mac_a
	 */

	/* Create frame from mac_b to mac_a */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b,
		DP_TEST_ET_LLDP, 1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp1T1");
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(vlans);
} DP_END_TEST;

/*
 * Test L2 forwarding to a unicast destination on a vlan with pvids
 *
 * Test mac_a can reach mac_b, where;
 * mac_a -> dp1T0 br1 dp1T1 -> mac_b
 */
DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	bridge_pvid_transition_unicast, NULL, NULL);
DP_START_TEST(bridge_pvid_transition_unicast,
	bridge_pvid_transition_unicast)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak, *test_pak_exp;
	int len = 64;

	struct bridge_vlan_set *vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp1T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T1",
		10, vlans, vlans);

	/*
	 * mac_a -> mac_b
	 */

	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	test_pak_exp = dp_test_create_l2_pak(mac_b, mac_a,
		DP_TEST_ET_LLDP, 1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak_exp);
	rte_pktmbuf_free(test_pak_exp);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * mac_b -> mac_a
	 */

	/* Create frame from mac_b to mac_a */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b,
		DP_TEST_ET_LLDP, 1, &len);
	test_pak_exp = dp_test_create_8021q_l2_pak(mac_a, mac_b, 10,
						   ETH_P_8021Q,
						   DP_TEST_ET_LLDP,
						   1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak_exp);
	rte_pktmbuf_free(test_pak_exp);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp1T1");
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(vlans);
} DP_END_TEST;

DP_DECL_TEST_CASE(bridge_vlan_filter_suite,
	bridge_tag_transition_empty, NULL, NULL);
DP_START_TEST(bridge_tag_transition_empty,
	      bridge_tag_transition_empty)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	struct bridge_vlan_set *vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, vlans, NULL);
	dp_test_intf_bridge_add_port("br1", "dp1T1");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T1",
		0, vlans, NULL);

	/*
	 * mac_a -> mac_b
	 */

	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Now remove the allowed vlan from dp1T1 and check that the
	 * packet is dropped.
	 */
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, NULL, NULL);

	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp1T1");
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(vlans);
} DP_END_TEST;
