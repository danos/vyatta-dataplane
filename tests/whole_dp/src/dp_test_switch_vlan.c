/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "dp_test.h"
#include "dp_test_console.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"

#include "if/bridge/bridge.h"
#include "ip_funcs.h"

#define dp_test_clear_vlan_stats(name) \
	_dp_test_clear_vlan_stats(name, __FILE__, __func__, __LINE__)
static void _dp_test_clear_vlan_stats(const char *name,
				      const char *file,
				      const char *func, int line)
{
	char clear_stats_cmd[100];

	snprintf(clear_stats_cmd, sizeof(clear_stats_cmd),
		 "switch %s vlan clear stats",
		 name);
	dp_test_console_request_reply(clear_stats_cmd, false);
}

#define dp_test_verify_vlan_stats(name, vlan, stats)			\
	_dp_test_verify_vlan_stats(name, vlan, stats, __FILE__, __func__, \
				   __LINE__)
static void _dp_test_verify_vlan_stats(const char *name,
				       int vlan,
				       struct bridge_vlan_stats *stats,
				       const char *file,
				       const char *func, int line)
{
	char show_stats_cmd[100];
	json_object *jexp;

	snprintf(show_stats_cmd, sizeof(show_stats_cmd),
		 "switch %s vlan show stats",
		 name);
	jexp = dp_test_json_create(
		"{ "
		"  \"vlan_stats\": "
		"    [ "
		"      { \"vlan\": %d, "
		"        \"rx_bytes\": %lu, "
		"        \"rx_pkts\": %lu, "
		"        \"rx_ucast_pkts\": %lu, "
		"        \"rx_nucast_pkts\": %lu, "
		"        \"rx_drops\": %lu, "
		"        \"rx_errors\": %lu, "
		"        \"tx_bytes\": %lu, "
		"        \"tx_pkts\": %lu, "
		"        \"tx_ucast_pkts\": %lu, "
		"        \"tx_nucast_pkts\": %lu, "
		"        \"tx_drops\": %lu, "
		"        \"tx_errors\": %lu, "
		"      } "
		"    ] "
		"} ", vlan,
		stats->rx_octets,
		stats->rx_pkts,
		stats->rx_ucast_pkts,
		stats->rx_nucast_pkts,
		stats->rx_drops,
		stats->rx_errors,
		stats->tx_octets,
		stats->tx_pkts,
		stats->tx_ucast_pkts,
		stats->tx_nucast_pkts,
		stats->tx_drops,
		stats->tx_errors);

	_dp_test_check_json_poll_state(show_stats_cmd, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file,
				       func, line);
	json_object_put(jexp);
}

DP_DECL_TEST_SUITE(switch_vlan_stats);

DP_DECL_TEST_CASE(switch_vlan_stats,
		  switch_vlan_stats, NULL, NULL);

DP_START_TEST(switch_vlan_stats, switch_vlan_stats)
{
	/* The FAL automatically fills in these values */
	static struct bridge_vlan_stats sw_stats = { .rx_octets = 10000,
						     .rx_pkts = 10,
						     .rx_ucast_pkts = 9,
						     .rx_nucast_pkts  = 1,
						     .rx_drops = 0,
						     .rx_errors = 0,
						     .tx_octets = 20000,
						     .tx_pkts = 20,
						     .tx_ucast_pkts = 18,
						     .tx_nucast_pkts = 2,
						     .tx_drops = 0,
						     .tx_errors = 0 };
	static struct bridge_vlan_stats sw_stats_zero = { 0 };
	static struct bridge_vlan_stats sw_stats_inc = { 0 };
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	struct dp_test_expected *exp;
	const char *mac_a, *mac_b;
	struct rte_mbuf *test_pak;
	int len = 64;

	bridge_vlan_set_add(allowed_vlans, 10);
	dp_test_intf_switch_create("sw0");
	dp_test_intf_bridge_enable_vlan_filter("sw0");

	dp_test_intf_switch_add_port("sw0", "dp2T2");
	dp_test_intf_bridge_port_set_vlans("sw0", "dp2T2",
					   0, allowed_vlans, NULL);
	dp_test_intf_switch_add_port("sw0", "dp2T1");
	dp_test_intf_bridge_port_set_vlans("sw0", "dp2T1",
					   0, allowed_vlans, NULL);

	dp_test_verify_vlan_stats("sw0", 10, &sw_stats);
	dp_test_clear_vlan_stats("sw0");
	dp_test_verify_vlan_stats("sw0", 10, &sw_stats_zero);
	dp_test_verify_vlan_stats("sw0", 10, &sw_stats);

	/* Create frame from mac_a to mac_b */
	mac_a = "00:00:a4:00:33:dd";
	mac_b = "00:00:a4:00:44:cc";
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_pak_receive(test_pak, "dp2T1", exp);
	sw_stats_inc = sw_stats;
	sw_stats_inc.rx_octets += 78;
	sw_stats_inc.rx_pkts++;
	sw_stats_inc.tx_octets += 78;
	sw_stats_inc.tx_pkts++;
	dp_test_verify_vlan_stats("sw0", 10, &sw_stats_inc);

	dp_test_intf_switch_remove_port("sw0", "dp2T2");
	dp_test_intf_switch_remove_port("sw0", "dp2T1");
	dp_test_intf_switch_del("sw0");
	bridge_vlan_set_free(allowed_vlans);

} DP_END_TEST;
