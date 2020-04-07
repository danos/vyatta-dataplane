/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT Bridge tests
 */

#include "dp_test.h"
#include "dp_test_console.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"

#include "ip_funcs.h"
#include "in_cksum.h"

DP_DECL_TEST_SUITE(bridge_suite);

/*
 * Test L2 forwarding to a unicast destination.
 *
 * Test mac_a can reach mac_b, where;
 * mac_a -> dp1T0 br1 dp2T1 -> mac_b
 */
DP_DECL_TEST_CASE(bridge_suite, bridge_unicast, NULL, NULL);

DP_START_TEST(bridge_unicast, bridge_unicast)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

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
	dp_test_exp_set_oif_name(exp, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * mac_b -> mac_a
	 */

	/* Create frame from mac_b to mac_a */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
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
} DP_END_TEST;

/*
 * Test L2 forwarding to an unknown unicast destination.
 * Bridge has 3 ports, so frame should be flooded out of the 2 remote ports.
 */
DP_DECL_TEST_CASE(bridge_suite, br_uni_flood, NULL, NULL);
DP_START_TEST(br_uni_flood, br_uni_flood)
{
	struct dp_test_expected *exp;
	const char *mac_c, *mac_d;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_c = "00:00:a4:00:00:cc";
	mac_d = "00:00:a4:00:00:dd";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");
	dp_test_intf_bridge_add_port("br1", "dp3T2");

	/* Create frame from mac_c to mac_d */
	test_pak = dp_test_create_l2_pak(mac_d, mac_c,
					 DP_TEST_ET_LLDP, 1, &len);

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
} DP_END_TEST;

/*
 * Test L2 forwarding to a broadcast destination.
 *
 * Test mac_a can send initial packet to a L2 bcast;
 * mac_a -> dp1T0 br1  , mac_b-> dp1T0 br1, 2 member ports in bridge
 */
DP_DECL_TEST_CASE(bridge_suite, broadcast_2port, NULL, NULL);

DP_START_TEST(broadcast_2port, bridge_broadcast_2port)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_bcast;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_bcast = "ff:ff:ff:ff:ff:ff";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

	/*
	 * mac_a -> mac_bcast, ethertype Banyan
	 *
	 * Only Spanning Tree and ARP multi/broadcast and, conditionally, IPv4
	 * and IPv6 are sent upstream.
	 */

	/* Create frame from mac_a to mac_bcast */
	test_pak = dp_test_create_l2_pak(mac_bcast, mac_a, DP_TEST_ET_LLDP,
					 1, &len);

	/* We expect the dataplane to flood to member ports and to
	 * slowpath in VR
	 */
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
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
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
} DP_END_TEST;

/*
 * Test L2 forwarding to a broadcast destination ipv4 payload.
 *
 * The type of payload being IPv4 should not matter, since we are bridging
 * however we have had bugs where frames containing IPv4 has been treated
 * differently than other L2 traffic.
 */
DP_DECL_TEST_CASE(bridge_suite, broadcast_2port_ipv4, NULL, NULL);
DP_START_TEST(broadcast_2port_ipv4, broadcast_2port_ipv4)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_bcast;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_bcast = "ff:ff:ff:ff:ff:ff";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

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
} DP_END_TEST;

/*
 * Test L2 forwarding to a broadcast destination ipv6 payload.
 *
 * The type of payload being IPv4 should not matter, since we are bridging.
 */
DP_DECL_TEST_CASE(bridge_suite, broadcast_2port_ipv6, NULL, NULL);
DP_START_TEST(broadcast_2port_ipv6, broadcast_2port_ipv6)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_bcast;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_bcast = "ff:ff:ff:ff:ff:ff";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

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
} DP_END_TEST;

/*
 * Test L2 forwarding to a broadcast destination ipv4 multicast payload.
 *
 * The type of payload being IPv4 multicast should not matter, since we
 * are bridging we should not even look at L3 payload.
 */
DP_DECL_TEST_CASE(bridge_suite, broadcast_2port_ipv4_multi, NULL, NULL);
DP_START_TEST(broadcast_2port_ipv4_multi, broadcast_2port_ipv4_multi)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_multi, *ipv4_multi;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_multi = "01:00:5e:01:02:03";
	ipv4_multi = "224.1.2.3";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

	/* Create frame from mac_a to mac_multi */
	test_pak = dp_test_create_ipv4_pak(ipv4_multi, "3.3.3.3",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak, mac_multi, mac_a,
				       ETHER_TYPE_IPv4);

	/* We expect the dataplane to flood to member ports and to slowpath */
	exp = dp_test_exp_create_m(test_pak, 2);

	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_del("br1");
} DP_END_TEST;

/*
 * Test bridging for vif
 */
DP_DECL_TEST_CASE(bridge_suite, bridge_2port_1vif, NULL, NULL);
DP_START_TEST(bridge_2port_1vif, 1vif_bcast_ucast)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_bcast;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	/* Test setup */
	dp_test_intf_vif_create("dp1T1.10", "dp1T1", 10);
	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp2T2");
	dp_test_intf_bridge_add_port("br1", "dp1T1.10");

	/* Flow 1
	 * mac_a -> mac_bcast
	 */
	mac_bcast = "ff:ff:ff:ff:ff:ff";

	/* Create frame from mac_a to mac_bcast */
	test_pak = dp_test_create_8021q_l2_pak(mac_bcast, mac_a, 10,
							ETH_P_8021Q,
							DP_TEST_ET_LLDP,
							1, &len);

	/*
	 * We expect the dataplane to flood to member ports
	 * and to slowpath, with the flood to member port not
	 * being a tagged packet.
	 */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_pak_m(exp, 1,
					dp_test_create_l2_pak(mac_bcast,
							mac_a,
							DP_TEST_ET_LLDP,
							1, &len));
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Flow  2
	 * mac_a -> mac_b
	 * Unknown unicast
	 */
	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical minus
	 * vlan tag.
	 */
	expected_pak = dp_test_create_l2_pak(mac_b, mac_a, DP_TEST_ET_LLDP,
					     1, &len);
	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	/* Unknown unicast should be flooded , should be seen on Tx */
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Flow 3
	 * Reply from mac_b
	 * mac_b -> mac_a
	 * Known unicast
	 */
	/* Create frame from mac_b to mac_a, reply will be L2 unicast */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
					 1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Interface should be set correctly for unicast packet
	 */
	exp = dp_test_exp_create(test_pak);

	dp_test_exp_set_oif_name(exp, "dp1T1");
	dp_test_exp_set_vlan_tci(exp, 10);
	dp_test_pak_receive(test_pak, "dp2T2", exp);

	/* Post test cleanup */
	dp_test_intf_bridge_remove_port("br1", "dp2T2");
	dp_test_intf_bridge_remove_port("br1", "dp1T1.10");
	dp_test_intf_vif_del("dp1T1.10", 10);
	dp_test_intf_bridge_del("br1");

} DP_END_TEST;

/*
 * Test bridging for vif
 */
DP_DECL_TEST_CASE(bridge_suite, bridge_2port_2vif, NULL, NULL);
DP_START_TEST(bridge_2port_2vif, 2vif_bcast_ucast)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_bcast;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_bcast = "ff:ff:ff:ff:ff:ff";
	mac_b = "00:00:a4:00:00:bb";

	/* Test setup */
	dp_test_intf_vif_create("dp1T1.10", "dp1T1", 10);
	dp_test_intf_vif_create("dp3T2.10", "dp3T2", 10);
	dp_test_intf_bridge_create("br10");
	dp_test_intf_bridge_add_port("br10", "dp3T2.10");
	dp_test_intf_bridge_add_port("br10", "dp1T1.10");

	/* Flow 1
	 * mac_a -> mac_bcast
	 */
	/* Create frame from mac_a to mac_bcast */
	test_pak = dp_test_create_8021q_l2_pak(mac_bcast, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	/* We expect the dataplane to flood to member ports and to
	 * slowpath in VR
	 */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, "dp3T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);


	/* Flow 2
	 * mac_a -> mac_b
	 * Unknown unicast
	 */
	/* Create frame from mac_a to mac_bcast */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	/* Unknown unicast should be flooded , should be seen on Tx */

	dp_test_exp_set_oif_name(exp, "dp3T2");
	dp_test_exp_set_vlan_tci(exp, 10);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Flow 3
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
	 * Interface should be set correctly for unicast packet
	 */
	exp = dp_test_exp_create(test_pak);

	dp_test_exp_set_oif_name(exp, "dp1T1");
	dp_test_exp_set_vlan_tci(exp, 10);
	dp_test_pak_receive(test_pak, "dp3T2", exp);

	/* Post test cleanup */
	dp_test_intf_bridge_remove_port("br10", "dp3T2.10");
	dp_test_intf_bridge_remove_port("br10", "dp1T1.10");
	dp_test_intf_vif_del("dp1T1.10", 10);
	dp_test_intf_vif_del("dp3T2.10", 10);
	dp_test_intf_bridge_del("br10");

} DP_END_TEST;

/*
 * Test bridging with various combinations of 802.1q and non 802.1q
 * interfaces.
 *
 * This includes testing in situations where both a parent and child interface
 * (e.g. dp1T1 and dp1T1.10) are in the same bridge group.
 */
DP_DECL_TEST_CASE(bridge_suite, bridge_2port_2vif_comb, NULL, NULL);

DP_START_TEST(bridge_2port_2vif_comb, 2vif_comb_ucast)
{
	const char *mac_a, *mac_b;
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak, *exp_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	/* Test setup */
	dp_test_intf_vif_create("dp1T1.10", "dp1T1", 10);
	dp_test_intf_vif_create("dp1T2.10", "dp1T2", 10);
	dp_test_intf_bridge_create("br10");
	dp_test_intf_bridge_add_port("br10", "dp1T1.10");
	dp_test_intf_bridge_add_port("br10", "dp1T2.10");

	/*
	 * Flow 1.  802.1q to 802.1q
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	exp = dp_test_exp_create(test_pak);

	dp_test_exp_set_oif_name(exp, "dp1T2");
	dp_test_exp_set_vlan_tci(exp, 10);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 2.  802.1q to eth
	 */
	dp_test_intf_bridge_remove_port("br10", "dp1T2.10");
	dp_test_intf_vif_del("dp1T2.10", 10);
	dp_test_intf_bridge_add_port("br10", "dp1T2");

	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp_pak = dp_test_create_l2_pak(mac_b, mac_a,
					DP_TEST_ET_LLDP, 1, &len);

	exp = dp_test_exp_create(exp_pak);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_oif_name(exp, "dp1T2");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 3.  802.1q (dp1T1.10) to eth (dp1T1 and dp1T2).
	 *
	 * This tests receiving an 802.1Q tagged packet on an interface where
	 * both the vlan interface and parent interface are in the same bridge
	 * group.
	 */
	dp_test_intf_bridge_add_port("br10", "dp1T1");

	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp_pak = dp_test_create_l2_pak(mac_b, mac_a,
					DP_TEST_ET_LLDP, 1, &len);

	exp = dp_test_exp_create_m(exp_pak, 2);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_oif_name_m(exp, 0, "dp1T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp1T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 4. 802.1q to local
	 */
	dp_test_nl_add_ip_addr_and_connected("br10", "10.0.1.1/24");
	dp_test_netlink_add_neigh("br10", "10.0.1.2", "0:0:a4:0:0:aa");

	struct dp_test_pkt_desc_t pktA = {
		.text       = "Neighbour 1 -> Bridge IP address",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "0:0:a4:0:0:aa",
		.l3_dst     = "10.0.1.1",
		.l2_dst     = NULL,
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "br10",
		.tx_intf    = "dp1T1"
	};
	test_pak = dp_test_rt_pkt_from_desc(&pktA);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, pktA.tx_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	/* Set the vlan in the test pak after we have created the exp pak */
	dp_test_pktmbuf_vlan_init(test_pak, 10);

	dp_test_exp_set_vlan_tci(exp, 10);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	dp_test_netlink_del_neigh("br10", "10.0.1.2", "0:0:a4:0:0:aa");
	dp_test_nl_del_ip_addr_and_connected("br10", "10.0.1.1/24");

	/*
	 * Flow 5.  eth (dp1T1) to 802.1q (dp1T2.10).
	 */
	dp_test_intf_bridge_remove_port("br10", "dp1T1.10");
	dp_test_intf_bridge_remove_port("br10", "dp1T2");
	dp_test_intf_vif_del("dp1T1.10", 10);
	dp_test_intf_vif_create("dp1T2.10", "dp1T2", 10);
	dp_test_intf_bridge_add_port("br10", "dp1T2.10");

	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
					 DP_TEST_ET_LLDP, 1, &len);
	exp_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					      ETH_P_8021Q,
					      DP_TEST_ET_LLDP,
					      1, &len);
	exp = dp_test_exp_create(exp_pak);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_oif_name(exp, "dp1T2");
	dp_test_exp_set_vlan_tci(exp, 10);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 6.  eth (dp1T1) to 802.1q (dp1T1.10 and dp1T2.10).
	 *
	 * This tests receiving an ethernet (not 802.1Q) packet on an
	 * interface which also has a child vlan interface in the same bridge
	 * group.
	 */
	dp_test_intf_vif_create("dp1T1.10", "dp1T1", 10);
	dp_test_intf_bridge_add_port("br10", "dp1T1.10");

	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
					 DP_TEST_ET_LLDP, 1, &len);
	exp_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					      ETH_P_8021Q,
					      DP_TEST_ET_LLDP,
					      1, &len);
	exp = dp_test_exp_create_m(exp_pak, 2);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_oif_name_m(exp, 0, "dp1T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp1T2");

	dp_test_exp_set_vlan_tci(exp, 10);
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 7. eth to local
	 */
	dp_test_nl_add_ip_addr_and_connected("br10", "10.0.1.1/24");
	dp_test_netlink_add_neigh("br10", "10.0.1.2", "0:0:a4:0:0:aa");

	test_pak = dp_test_rt_pkt_from_desc(&pktA);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, pktA.tx_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	dp_test_netlink_del_neigh("br10", "10.0.1.2", "0:0:a4:0:0:aa");
	dp_test_nl_del_ip_addr_and_connected("br10", "10.0.1.1/24");


	/* Post test cleanup */
	dp_test_intf_bridge_remove_port("br10", "dp1T1");
	dp_test_intf_bridge_remove_port("br10", "dp1T2.10");
	dp_test_intf_bridge_remove_port("br10", "dp1T1.10");
	dp_test_intf_bridge_del("br10");
	dp_test_intf_vif_del("dp1T1.10", 10);
	dp_test_intf_vif_del("dp1T2.10", 10);

} DP_END_TEST;

/*
 * Test bridging with various combinations of 802.1q and non 802.1q
 * interfaces with a non-default vlan proto.
 */
DP_START_TEST(bridge_2port_2vif_comb, 2vif_comb_ucast_vlan_proto)
{
	const char *mac_a, *mac_b;
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak, *exp_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	/* Test setup */
	dp_test_intf_vif_create_tag_proto("dp1T1.10", "dp1T1", 10,
					  ETH_P_8021AD);
	dp_test_intf_vif_create_tag_proto("dp1T2.20", "dp1T2", 20,
					  ETH_P_8021AD);
	dp_test_intf_bridge_create("br10");
	dp_test_intf_bridge_add_port("br10", "dp1T1.10");
	dp_test_intf_bridge_add_port("br10", "dp1T2.20");

	/*
	 * Flow 1.  802.1q to 802.1q
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021AD,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 20,
					      ETH_P_8021AD,
					      DP_TEST_ET_LLDP,
					      1, &len);

	exp = dp_test_exp_create(exp_pak);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_oif_name(exp, "dp1T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 2.  802.1q to eth
	 */
	dp_test_intf_bridge_remove_port("br10", "dp1T2.20");
	dp_test_intf_vif_del_tag_proto("dp1T2.20", 20, ETH_P_8021AD);
	dp_test_intf_bridge_add_port("br10", "dp1T2");

	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021AD,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp_pak = dp_test_create_l2_pak(mac_b, mac_a,
					DP_TEST_ET_LLDP, 1, &len);

	exp = dp_test_exp_create(exp_pak);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_oif_name(exp, "dp1T2");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 3.  802.1q (dp1T1.10) to eth (dp1T1 and dp1T2).
	 *
	 * This tests receiving an 802.1Q tagged packet on an interface where
	 * both the vlan interface and parent interface are in the same bridge
	 * group.
	 */
	dp_test_intf_bridge_add_port("br10", "dp1T1");

	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021AD,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp_pak = dp_test_create_l2_pak(mac_b, mac_a,
					DP_TEST_ET_LLDP, 1, &len);

	exp = dp_test_exp_create_m(exp_pak, 2);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_oif_name_m(exp, 0, "dp1T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp1T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 4. 802.1q to local
	 */
	dp_test_nl_add_ip_addr_and_connected("br10", "10.0.1.1/24");
	dp_test_netlink_add_neigh("br10", "10.0.1.2", "0:0:a4:0:0:aa");

	struct dp_test_pkt_desc_t pktA = {
		.text       = "Neighbour 1 -> Bridge IP address",
		.len        = 20,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.0.1.2",
		.l2_src     = "0:0:a4:0:0:aa",
		.l3_dst     = "10.0.1.1",
		.l2_dst     = NULL,
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 41000,
				.dport = 1000,
				.flags = 0
			}
		},
		.rx_intf    = "br10",
		.tx_intf    = "dp1T1"
	};
	test_pak = dp_test_rt_pkt_from_desc(&pktA);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, pktA.tx_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	/* Set the vlan in the test pak after we have created the exp pak */
	dp_test_insert_8021q_hdr(test_pak, 10, ETH_P_8021AD,
				 ETHER_TYPE_IPv4);
	dp_test_exp_set_vlan_tci(exp, 10);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	dp_test_netlink_del_neigh("br10", "10.0.1.2", "0:0:a4:0:0:aa");
	dp_test_nl_del_ip_addr_and_connected("br10", "10.0.1.1/24");

	/*
	 * Flow 5.  eth (dp1T1) to 802.1q (dp1T2.10).
	 */
	dp_test_intf_bridge_remove_port("br10", "dp1T1.10");
	dp_test_intf_bridge_remove_port("br10", "dp1T2");
	dp_test_intf_vif_del_tag_proto("dp1T1.10", 10, ETH_P_8021AD);
	dp_test_intf_vif_create_tag_proto("dp1T2.10", "dp1T2", 10,
					  ETH_P_8021AD);
	dp_test_intf_bridge_add_port("br10", "dp1T2.10");

	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
					 DP_TEST_ET_LLDP, 1, &len);
	exp_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					      ETH_P_8021AD,
					      DP_TEST_ET_LLDP,
					      1, &len);
	exp = dp_test_exp_create(exp_pak);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_oif_name(exp, "dp1T2");
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 6.  eth (dp1T1) to 802.1q (dp1T1.10 and dp1T2.10).
	 *
	 * This tests receiving an ethernet (not 802.1Q) packet on an
	 * interface which also has a child vlan interface in the same bridge
	 * group.
	 */
	dp_test_intf_vif_create_tag_proto("dp1T1.10", "dp1T1", 10,
					  ETH_P_8021AD);
	dp_test_intf_bridge_add_port("br10", "dp1T1.10");

	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
					 DP_TEST_ET_LLDP, 1, &len);
	exp_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					      ETH_P_8021AD,
					      DP_TEST_ET_LLDP,
					      1, &len);
	exp = dp_test_exp_create_m(exp_pak, 2);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_oif_name_m(exp, 0, "dp1T1");
	dp_test_exp_set_oif_name_m(exp, 1, "dp1T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 7. eth to local
	 */
	dp_test_nl_add_ip_addr_and_connected("br10", "10.0.1.1/24");
	dp_test_netlink_add_neigh("br10", "10.0.1.2", "0:0:a4:0:0:aa");

	test_pak = dp_test_rt_pkt_from_desc(&pktA);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, pktA.tx_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	dp_test_netlink_del_neigh("br10", "10.0.1.2", "0:0:a4:0:0:aa");
	dp_test_nl_del_ip_addr_and_connected("br10", "10.0.1.1/24");


	/* Post test cleanup */
	dp_test_intf_bridge_remove_port("br10", "dp1T1");
	dp_test_intf_bridge_remove_port("br10", "dp1T2.10");
	dp_test_intf_bridge_remove_port("br10", "dp1T1.10");
	dp_test_intf_bridge_del("br10");
	dp_test_intf_vif_del_tag_proto("dp1T1.10", 10, ETH_P_8021AD);
	dp_test_intf_vif_del_tag_proto("dp1T2.10", 10, ETH_P_8021AD);

} DP_END_TEST;

/*
 * Tests forwarding to multiple vif ports
 */
DP_DECL_TEST_CASE(bridge_suite, bridge_3port_2vif_fwd, NULL, NULL);

/* Rx on non-vif, forward to two vif interfaces */
DP_START_TEST(bridge_3port_2vif_fwd, 2vif_fwd1)
{
	const char *mac_a, *mac_b;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	/* Test setup */
	dp_test_intf_vif_create("dp1T2.11", "dp1T2", 11);
	dp_test_intf_vif_create("dp1T3.12", "dp1T3", 12);
	dp_test_intf_bridge_create("br10");
	dp_test_intf_bridge_add_port("br10", "dp1T1");
	dp_test_intf_bridge_add_port("br10", "dp1T2.11");
	dp_test_intf_bridge_add_port("br10", "dp1T3.12");

	/*
	 * Flow 1.  Unknown unicast rcvd on dp0T1, forwarded to two different
	 * 802.1q interfaces (dp1T2.11 and dp1T3.12).
	 *
	 */
	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
					 DP_TEST_ET_LLDP,
					 1, &len);
	exp = dp_test_exp_create_m(test_pak, 2);

	dp_test_exp_set_oif_name_m(exp, 0, "dp1T2");
	dp_test_exp_set_vlan_tci_m(exp, 0, 11);

	dp_test_exp_set_oif_name_m(exp, 1, "dp1T3");
	dp_test_exp_set_vlan_tci_m(exp, 1, 12);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Flow 2.  Known unicast rcvd on dp1T2.11, forwarded to dp1T1
	 * only
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_a, mac_b, 11,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	expected_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
					     1, &len);
	exp = dp_test_exp_create_m(expected_pak, 1);
	rte_pktmbuf_free(expected_pak);

	dp_test_exp_set_oif_name_m(exp, 0, "dp1T1");

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T2", exp);

	/* Post test cleanup */
	dp_test_intf_bridge_remove_port("br10", "dp1T1");
	dp_test_intf_bridge_remove_port("br10", "dp1T2.11");
	dp_test_intf_bridge_remove_port("br10", "dp1T3.12");
	dp_test_intf_bridge_del("br10");
	dp_test_intf_vif_del("dp1T2.11", 11);
	dp_test_intf_vif_del("dp1T3.12", 12);

} DP_END_TEST;

/* Rx on vif, forward to one vif and one non-vif interfaces */
DP_START_TEST(bridge_3port_2vif_fwd, 2vif_fwd2)
{
	const char *mac_a, *mac_b;
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak; //, *exp_pak0, *exp_pak1;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	/* Test setup */
	dp_test_intf_vif_create("dp1T2.11", "dp1T2", 11);
	dp_test_intf_vif_create("dp1T3.12", "dp1T3", 12);
	dp_test_intf_bridge_create("br10");
	dp_test_intf_bridge_add_port("br10", "dp1T1");
	dp_test_intf_bridge_add_port("br10", "dp1T2.11");
	dp_test_intf_bridge_add_port("br10", "dp1T3.12");

	/*
	 * Flow 1.  802.1q (dp1T2.11) to different 802.1q (dp1T3.12)
	 * and non-vif (dp1T1).
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 11,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	exp = dp_test_exp_create_m(test_pak, 2);

	dp_test_exp_set_oif_name_m(exp, 0, "dp1T1");
	dp_test_exp_set_pak_m(exp, 0,
			      dp_test_create_l2_pak(mac_b, mac_a,
						    DP_TEST_ET_LLDP,
						    1, &len));

	dp_test_exp_set_oif_name_m(exp, 1, "dp1T3");
	dp_test_exp_set_vlan_tci_m(exp, 1, 12);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T2", exp);

	/* Post test cleanup */
	dp_test_intf_bridge_remove_port("br10", "dp1T1");
	dp_test_intf_bridge_remove_port("br10", "dp1T2.11");
	dp_test_intf_bridge_remove_port("br10", "dp1T3.12");
	dp_test_intf_bridge_del("br10");
	dp_test_intf_vif_del("dp1T2.11", 11);
	dp_test_intf_vif_del("dp1T3.12", 12);

} DP_END_TEST;


DP_DECL_TEST_CASE(bridge_suite, bridge_gre, NULL, NULL);

DP_START_TEST(bridge_gre, unicast)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_c, *mac_ip_neigh;
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	int len = 64, max_len = 1462;
	int gre_pl_len;
	void *gre_payload;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";
	mac_c = "00:00:a4:00:00:cc";
	mac_ip_neigh = "aa:bb:cc:dd:ee:ff";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.2.1/24");
	dp_test_netlink_add_neigh("dp1T1", "1.1.2.2", mac_ip_neigh);

	dp_test_intf_gre_l2_create("tun1", "1.1.2.1", "1.1.2.2", 0);

	dp_test_intf_bridge_add_port("br1", "tun1");

	/*
	 * mac_a -> mac_b (flood)
	 */

	/* Create frame from mac_a to mac_b */
	payload_pak = dp_test_create_l2_pak(mac_b, mac_a,
					    DP_TEST_ET_LLDP, 1, &len);
	gre_pl_len = rte_pktmbuf_data_len(payload_pak);
	test_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.2", "1.1.2.1", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(payload_pak,
					     const struct ether_hdr *),
	       gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(test_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T1"),
				 mac_ip_neigh,
				 ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(payload_pak);
	rte_pktmbuf_free(payload_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * mac_b -> mac_a
	 */

	/* Create frame from mac_b to mac_a */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
					 1, &len);

	gre_pl_len = rte_pktmbuf_data_len(test_pak);
	expected_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.1", "1.1.2.2", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(test_pak,
					     const struct ether_hdr *),
	       gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(expected_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(expected_pak, mac_ip_neigh,
				 dp_test_intf_name2mac_str("dp1T1"),
				 ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);
	rte_pktmbuf_free(expected_pak);

	/*
	 * (BRIDGE FLOODING in to GRE scenario, mac_c is unknown)
	 * Ensure frames with size matching up to MTU are still flooded
	 */
	test_pak = dp_test_create_l2_pak(mac_c, mac_b, DP_TEST_ET_LLDP,
					 1, &max_len);
	gre_pl_len = rte_pktmbuf_data_len(test_pak);
	expected_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.1", "1.1.2.2", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload,
	       rte_pktmbuf_mtod(test_pak, const struct ether_hdr *),
	       gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(expected_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(expected_pak, mac_ip_neigh,
				 dp_test_intf_name2mac_str("dp1T1"),
				 ETHER_TYPE_IPv4);
	exp = dp_test_exp_create(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);
	rte_pktmbuf_free(expected_pak);

	/*
	 * mac_a -> mac_b (unicast)
	 */

	/* Create frame from mac_a to mac_b */
	payload_pak = dp_test_create_l2_pak(mac_b, mac_a,
					    DP_TEST_ET_LLDP, 1, &len);
	gre_pl_len = rte_pktmbuf_data_len(payload_pak);
	test_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.2", "1.1.2.1", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(payload_pak,
					     const struct ether_hdr *),
	       gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(test_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T1"),
				 mac_ip_neigh,
				 ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(payload_pak);
	rte_pktmbuf_free(payload_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * (BRIDGE UNICAST in to GRE scenario, mac_a is known)
	 * Ensure frames with size matching up to MTU are still flooded
	 */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
					 1, &max_len);

	gre_pl_len = rte_pktmbuf_data_len(test_pak);
	expected_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.1", "1.1.2.2", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(test_pak,
					     const struct ether_hdr *),
	       gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(expected_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(expected_pak, mac_ip_neigh,
				 dp_test_intf_name2mac_str("dp1T1"),
				 ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);
	rte_pktmbuf_free(expected_pak);
	/*
	 * Clean up
	 */
	dp_test_intf_bridge_remove_port("br1", "tun1");

	dp_test_intf_gre_l2_delete("tun1", "1.1.2.1", "1.1.2.2", 0);

	dp_test_netlink_del_neigh("dp1T1", "1.1.2.2", mac_ip_neigh);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.2.1/24");

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_del("br1");
} DP_END_TEST;

DP_START_TEST(bridge_gre, frag)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_ip_neigh;
	struct rte_mbuf *payload_pak;
	struct iphdr *ip;
	int len = 1463 - sizeof(struct udphdr) - sizeof(struct iphdr);
	int ret;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";
	mac_ip_neigh = "aa:bb:cc:dd:ee:ff";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.2.1/24");
	dp_test_netlink_add_neigh("dp1T1", "1.1.2.2", mac_ip_neigh);

	dp_test_intf_gre_l2_create("tun1", "1.1.2.1", "1.1.2.2", 0);

	dp_test_intf_bridge_add_port("br1", "tun1");

	/* Test 1 - good packet */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					   1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 mac_b,
				 mac_a,
				 ETHER_TYPE_IPv4);

	struct rte_mbuf *frag_payload[2];
	uint16_t frag_sizes[2] = {
		3, 1440
	};
	ret = dp_test_ipv4_fragment_packet(payload_pak, frag_payload,
					   2, frag_sizes, 0);
	dp_test_fail_unless(ret == 2,
			    "dp_test_ipv4_fragment_packet failed: %s",
			    strerror(-ret));

	dp_test_pktmbuf_gre_prepend(frag_payload[0], ETH_P_TEB, 0);
	dp_test_pktmbuf_ip_prepend(frag_payload[0], "1.1.2.1", "1.1.2.2",
				   IPPROTO_GRE);
	dp_test_set_pak_ip_field(iphdr(frag_payload[0]), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_prepend(frag_payload[0], mac_ip_neigh,
				    dp_test_intf_name2mac_str("dp1T1"),
				    ETHER_TYPE_IPv4);
	dp_test_pktmbuf_gre_prepend(frag_payload[1], ETH_P_TEB, 0);
	dp_test_pktmbuf_ip_prepend(frag_payload[1], "1.1.2.1", "1.1.2.2",
				   IPPROTO_GRE);
	dp_test_set_pak_ip_field(iphdr(frag_payload[1]), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_prepend(frag_payload[1], mac_ip_neigh,
				    dp_test_intf_name2mac_str("dp1T1"),
				    ETHER_TYPE_IPv4);

	exp = dp_test_exp_create_m(NULL, 2);

	dp_test_exp_set_pak_m(exp, 0, frag_payload[0]);
	dp_test_exp_set_oif_name_m(exp, 0, "dp1T1");

	dp_test_exp_set_pak_m(exp, 1, frag_payload[1]);
	dp_test_exp_set_oif_name_m(exp, 1, "dp1T1");

	dp_test_pak_receive(payload_pak, "dp1T0", exp);

	/* Test 2 - total length field too big for packet size */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 mac_b,
				 mac_a,
				 ETHER_TYPE_IPv4);
	ip = iphdr(payload_pak);
	ip->tot_len = htons(2000);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	exp = dp_test_exp_create(payload_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(payload_pak, "dp1T0", exp);

	/* Test 3 - invalid header length */
	payload_pak = dp_test_create_ipv4_pak("99.99.0.0", "10.99.0.10",
					      1, &len);
	dp_test_pktmbuf_eth_init(payload_pak,
				 mac_b,
				 mac_a,
				 ETHER_TYPE_IPv4);
	ip = iphdr(payload_pak);
	ip->ihl = 0;

	exp = dp_test_exp_create(payload_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(payload_pak, "dp1T0", exp);

	/*
	 * Clean up
	 */
	dp_test_intf_bridge_remove_port("br1", "tun1");

	dp_test_intf_gre_l2_delete("tun1", "1.1.2.1", "1.1.2.2", 0);

	dp_test_netlink_del_neigh("dp1T1", "1.1.2.2", mac_ip_neigh);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.2.1/24");

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_del("br1");
} DP_END_TEST;

DP_START_TEST(bridge_gre, vlan)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b, *mac_ip_neigh;
	struct rte_mbuf *test_pak, *payload_pak, *expected_pak;
	int len = 64;
	int gre_pl_len;
	void *gre_payload;
	struct bridge_vlan_set *vlans = bridge_vlan_set_create();
	bridge_vlan_set_add(vlans, 10);

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";
	mac_ip_neigh = "aa:bb:cc:dd:ee:ff";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_enable_vlan_filter("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_port_set_vlans("br1", "dp1T0",
		0, vlans, NULL);

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.2.1/24");
	dp_test_netlink_add_neigh("dp1T1", "1.1.2.2", mac_ip_neigh);

	dp_test_intf_gre_l2_create("tun1", "1.1.2.1", "1.1.2.2", 0);

	dp_test_intf_bridge_add_port("br1", "tun1");

	/* Create vlan-tagged frame from mac_a to mac_b */
	payload_pak = dp_test_create_l2_pak(mac_b, mac_a,
					    DP_TEST_ET_LLDP, 1, &len);
	dp_test_insert_8021q_hdr(payload_pak, 10, ETH_P_8021Q, DP_TEST_ET_LLDP);
	gre_pl_len = rte_pktmbuf_data_len(payload_pak);
	test_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.2", "1.1.2.1", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(payload_pak,
					     const struct ether_hdr *),
	       gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(test_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T1"),
				 mac_ip_neigh,
				 ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(payload_pak);
	rte_pktmbuf_free(payload_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/*
	 * Create vlan-tagged frame from mac_b to mac_a - should have
	 * vlan header added to GRE encapsulated packet, but currently
	 * just ignored
	 */
	test_pak = dp_test_create_8021q_l2_pak(
		mac_a, mac_b, 10, ETH_P_8021Q, DP_TEST_ET_LLDP, 1,
		&len);

	gre_pl_len = rte_pktmbuf_data_len(test_pak);
	expected_pak = dp_test_create_gre_ipv4_pak(
		"1.1.2.1", "1.1.2.2", 1, &gre_pl_len, ETH_P_TEB, 0, 0,
		&gre_payload);
	memcpy(gre_payload, rte_pktmbuf_mtod(test_pak,
					     const struct ether_hdr *),
	       gre_pl_len);
	dp_test_set_pak_ip_field(iphdr(expected_pak), DP_TEST_SET_DF, 1);
	dp_test_pktmbuf_eth_init(expected_pak, mac_ip_neigh,
				 dp_test_intf_name2mac_str("dp1T1"),
				 ETHER_TYPE_IPv4);

	exp = dp_test_exp_create(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);
	rte_pktmbuf_free(expected_pak);

	/*
	 * Clean up
	 */
	dp_test_intf_bridge_remove_port("br1", "tun1");

	dp_test_intf_gre_l2_delete("tun1", "1.1.2.1", "1.1.2.2", 0);

	dp_test_netlink_del_neigh("dp1T1", "1.1.2.2", mac_ip_neigh);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.2.1/24");

	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	dp_test_intf_bridge_del("br1");
	bridge_vlan_set_free(vlans);
} DP_END_TEST;

/*
 * Check that the flush code can delete entries safely at the same time as
 * they are removed from the master thread.
 */
DP_DECL_TEST_CASE(bridge_suite, bridge_flush, NULL, NULL);
DP_START_TEST(bridge_flush, bridge_flush)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:00:aa";
	mac_b = "00:00:a4:00:00:bb";

	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T0");
	dp_test_intf_bridge_add_port("br1", "dp2T1");

	/* Send a packet to get a bridge entry created */
	test_pak = dp_test_create_l2_pak(mac_b, mac_a,
					 DP_TEST_ET_LLDP, 1, &len);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * remove the port from the bridge, which removes the entry from
	 * the bridge (this is async)
	 */
	dp_test_intf_bridge_remove_port("br1", "dp1T0");
	/* Flush the bridge entries, this is synchronous */
	dp_test_console_request_reply("bridge br1 macs clear", false);
	dp_test_intf_bridge_remove_port("br1", "dp2T1");
	dp_test_intf_bridge_del("br1");
} DP_END_TEST;
