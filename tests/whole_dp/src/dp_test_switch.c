/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2018 ATT, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane switch port UT Switch tests
 */

#include <dlfcn.h>
#include "ether.h"
#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "fal_plugin_framer.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "fal.h"

static int (*fal_plugin_add_hdr)(const char *name, struct rte_mbuf *mbuf);
static int (*fal_plugin_rx_qdirect)(const char *name, struct rte_mbuf *mbuf);
static bool (*fal_plugin_enable_rx_framer)(bool enabled);

static int (*fal_plugin_bp_from_swport)(const char *name, uint16_t *dpdk_port);

static void dp_test_load_fal_plugin(void)
{
	void *lib = dlopen(platform_cfg.fal_plugin, RTLD_LAZY);

	dp_test_assert_internal(lib);
	fal_plugin_add_hdr = dlsym(lib, "fal_plugin_add_ut_framer_hdr");
	fal_plugin_rx_qdirect = dlsym(lib, "fal_plugin_queue_rx_direct");
	fal_plugin_enable_rx_framer =
		dlsym(lib, "fal_plugin_ut_enable_rx_framer");
	fal_plugin_bp_from_swport = dlsym(lib,
					  "fal_plugin_backplane_from_sw_port");
}

static void
dp_test_edsa_tag_insert(struct rte_mbuf *pak, const char *port_name, bool tx)
{

	fal_plugin_add_hdr(port_name, pak);

	if (tx)
		return;

	struct rte_ether_hdr *eh = ethhdr(pak);
	struct  edsa_hdr *edsa = (struct edsa_hdr *)&eh->ether_type;

	DSA_SET_TAG_TYPE(edsa, DSA_TAG_TYPE_FORWARD);
}

static void
dp_test_switch_insert_vlan_hdr(struct rte_mbuf *exp_pak)
{
	struct rte_mbuf *test_pak = exp_pak;

	rte_vlan_insert(&test_pak);
	assert(exp_pak == test_pak);
}


static const char *
dp_test_bp_intf_from_switch_port(const char *port_name)
{
	uint16_t dpdk_port;
	struct ifnet *ifp;

	assert(fal_plugin_bp_from_swport(port_name,
					 &dpdk_port) == 0);
	ifp = ifnet_byport(dpdk_port);

	assert(ifp != NULL);

	return ifp->if_name;
}


DP_DECL_TEST_SUITE(switch_suite);

/*
 * Test L2 forwarding to a unicast destination.
 *
 * Test mac_b can reach mac_a, where;
 * mac_b -> dp2T1 SW sw_port_0 -> mac_b (carrier dp1T0)
 */
DP_DECL_TEST_CASE(switch_suite, switch_unicast, NULL, NULL);

DP_START_TEST(switch_unicast, switch_unicast_tx)
{

	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	dp_test_load_fal_plugin();

	mac_a = "00:00:a4:00:33:aa";
	mac_b = "00:00:a4:00:44:bb";

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

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
	dp_test_edsa_tag_insert(dp_test_exp_get_pak(exp), "dp1sw_port_0_0", 1);
	dp_test_exp_set_oif_name(exp,
				 dp_test_bp_intf_from_switch_port(
					 "dp1sw_port_0_0"));

	dp_test_pak_receive(test_pak, "dp2T1", exp);

	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");
} DP_END_TEST;

DP_START_TEST(switch_unicast, switch_unicast_rx_port_0)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:33:dd";
	mac_b = "00:00:a4:00:44:cc";
	fal_plugin_enable_rx_framer(true);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	/*
	 * mac_a -> mac_b
	 */

	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b,
					 DP_TEST_ET_LLDP, 1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_edsa_tag_insert(test_pak, "dp1sw_port_0_0", 0);

	dp_test_exp_set_oif_name(exp, "dp2T1");

	/*
	 * Inject Packet onto Backplane
	 */
	dp_test_pak_receive(test_pak,
			    dp_test_bp_intf_from_switch_port(
				    "dp1sw_port_0_0"), exp);

	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	fal_plugin_enable_rx_framer(false);
} DP_END_TEST;

DP_START_TEST(switch_unicast, switch_unicast_tx_tagged)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();

	bridge_vlan_set_add(allowed_vlans, 10);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_bridge_enable_vlan_filter("switch0");

	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_bridge_port_set_vlans("switch0", "dp1sw_port_0_0",
		0, allowed_vlans, NULL);
	dp_test_intf_switch_add_port("switch0", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("switch0", "dp2T1",
		0, allowed_vlans, NULL);
	/*
	 * mac_a -> mac_b
	 */
	mac_a = "00:00:a4:00:33:aa";
	mac_b = "00:00:a4:00:44:bb";

	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect the core pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);

	dp_test_switch_insert_vlan_hdr(dp_test_exp_get_pak(exp));
	dp_test_edsa_tag_insert(dp_test_exp_get_pak(exp), "dp1sw_port_0_0", 1);

	dp_test_exp_set_oif_name(exp,
				 dp_test_bp_intf_from_switch_port(
					 "dp1sw_port_0_0"));

	exp->exp_pak[0]->vlan_tci = 0;
	dp_test_pak_receive(test_pak, "dp2T1", exp);

	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

DP_START_TEST(switch_unicast, switch_unicast_rx_tagged)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();

	fal_plugin_enable_rx_framer(true);

	bridge_vlan_set_add(allowed_vlans, 10);

	mac_a = "00:00:a4:00:33:dd";
	mac_b = "00:00:a4:00:44:cc";

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_bridge_enable_vlan_filter("switch0");

	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_bridge_port_set_vlans("switch0", "dp1sw_port_0_0",
					   0, allowed_vlans, NULL);
	dp_test_intf_switch_add_port("switch0", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("switch0", "dp2T1",
					   0, allowed_vlans, NULL);
	/*
	 * mac_a -> mac_b
	 */

	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_8021q_l2_pak(mac_a, mac_b, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	/*
	 * Create pak we expect to receive on the tx ring. The exp pak
	 * should to be identical to the currect test_pak.
	 */
	exp = dp_test_exp_create(test_pak);

	/*
	 * Add the vlan header and the edsa tag to mock a pak received from
	 * the switch.
	 */
	dp_test_switch_insert_vlan_hdr(test_pak);
	dp_test_edsa_tag_insert(test_pak, "dp1sw_port_0_0", 0);

	dp_test_exp_set_oif_name(exp, "dp2T1");

	/*
	 * Inject Packet onto Backplane
	 */
	dp_test_pak_receive(test_pak,
			    dp_test_bp_intf_from_switch_port(
				    "dp1sw_port_0_0"), exp);

	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");
	bridge_vlan_set_free(allowed_vlans);

	fal_plugin_enable_rx_framer(false);
} DP_END_TEST;

DP_START_TEST(switch_unicast, switch_unicast_rx_port_7)
{
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	mac_a = "00:00:a4:00:33:dd";
	mac_b = "00:00:a4:00:44:cc";

	dp_test_netlink_set_interface_l2("dp1sw_port_0_7");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_7");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	/*
	 * mac_a -> mac_b
	 */

	/* Create frame from mac_a to mac_b */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b,
					 DP_TEST_ET_LLDP, 1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);

	fal_plugin_rx_qdirect("dp1sw_port_0_7", test_pak);

	dp_test_exp_set_oif_name(exp, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1sw_port_0_7", exp);

	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_7");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");
} DP_END_TEST;
