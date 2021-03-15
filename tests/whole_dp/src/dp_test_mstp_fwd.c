/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>

#include "if/bridge/bridge.h"

#include <linux/if_bridge.h> // conflicts with netinet/in.h

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_json_utils.h"
#include "dp_test_netlink_state_internal.h"

#define MSTI_CHECK_VLAN_STATE(_expst, _port, _vlan)			\
	do {enum bridge_ifstate state;					\
		state = bridge_port_get_state_vlan(			\
			(_port)->if_brport, (_vlan));			\
		dp_test_fail_unless(					\
			state == (_expst),				\
			"bridge_port_get_state_vlan(%s %d) failed: %s", \
			(_port)->if_name, (_vlan),			\
			bridge_get_ifstate_string(state));		\
	} while (0)

static char test_mstp_cmd[DP_TEST_TMP_BUF];

static void
mstp_switch_create(const char *sw, const char *p1, const char *p2,
		   const char *p3, struct bridge_vlan_set *allowed_vlans)
{
	dp_test_intf_bridge_create(sw);
	dp_test_intf_bridge_enable_vlan_filter(sw);

	dp_test_intf_bridge_add_port(sw, p1);
	dp_test_intf_bridge_port_set_vlans_state(sw, p1, 0, allowed_vlans,
						 NULL, BR_STATE_BLOCKING);

	dp_test_intf_bridge_add_port(sw, p2);
	dp_test_intf_bridge_port_set_vlans_state(sw, p2, 0, allowed_vlans,
						 NULL, BR_STATE_BLOCKING);

	dp_test_intf_bridge_add_port(sw, p3);
	dp_test_intf_bridge_port_set_vlans_state(sw, p3, 0, allowed_vlans,
						 NULL, BR_STATE_BLOCKING);
	dp_test_send_config_src(
		dp_test_cont_src_get(),
		"mstp %s config action update region name UT1 revision 0",
		sw);
}

static void
mstp_switch_delete(const char *sw, const char *p1, const char *p2,
		   const char *p3)
{
	dp_test_send_config_src(
		dp_test_cont_src_get(),
		"mstp %s config action delete region name UT1",
		sw);
	/*
	 * Test verification for bridge port remove assumes the STP
	 * state hasn't changed since the port was first created!
	 */
	dp_test_intf_bridge_port_set_vlans_state(sw, p1, 0, NULL,
						 NULL, BR_STATE_FORWARDING);
	dp_test_intf_bridge_port_set_vlans_state(sw, p2, 0, NULL,
						 NULL, BR_STATE_FORWARDING);
	dp_test_intf_bridge_port_set_vlans_state(sw, p3, 0, NULL,
						 NULL, BR_STATE_FORWARDING);
	dp_test_intf_bridge_remove_port(sw, p1);
	dp_test_intf_bridge_remove_port(sw, p2);
	dp_test_intf_bridge_remove_port(sw, p3);
	dp_test_intf_bridge_del(sw);
}

static void
_mstp_msti_set_state(const char *sw, int state, struct ifnet *port, int mstid,
		     bool check, const char *file, const char *func, int line)
{
	dp_test_send_config_src(
		dp_test_cont_src_get(),
		"mstp %s config action update state %d port %s msti %u",
		sw, state, port->if_name, mstid);

	if (!check)
		return;

	json_object *expected = dp_test_json_create(
		"{ \"vlan-list\" : [{"
		"\"mstid\" : %d,"
		"\"switch-ports\" : ["
		"{\"state\" : \"%s\","
		"\"port\" : \"%s\"},"
		"]}]}",
		mstid, bridge_get_ifstate_string(state), port->if_name);

	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "mstp-op %s show state", sw);
	_dp_test_check_json_state(test_mstp_cmd, expected, NULL,
				  DP_TEST_JSON_CHECK_SUBSET, false,
				  false, file, func, line);
	json_object_put(expected);
}

#define MSTP_MSTI_SET_STATE(_sw, _st, _port, _msti) \
	_mstp_msti_set_state(_sw, _st, _port, _msti, true, \
			     __FILE__, __func__, __LINE__)
#define MSTP_MSTI_SET_STATE_NO_CHECK(_sw, _st, _port, _msti) \
	_mstp_msti_set_state(_sw, _st, _port, _msti, false, \
			     __FILE__, __func__, __LINE__)

static void
mstp_msti_add(const char *sw, int mstid, const char *vlans)
{
	dp_test_send_config_src(
		dp_test_cont_src_get(),
		"mstp %s config action update msti %d vlans %s",
		sw, mstid, vlans);
}

static void
mstp_msti_remove(const char *sw, int mstid)
{
	dp_test_send_config_src(
		dp_test_cont_src_get(),
		"mstp %s config action delete msti %d",
		sw, mstid);
}

DP_DECL_TEST_SUITE(mstp_fwd_suite);

DP_DECL_TEST_CASE(mstp_fwd_suite, mstp_fwd_1, NULL, NULL);

DP_START_TEST(mstp_fwd_1, mstp_fwd_vlan_state)
{
	const char *p1 = "dp1T0";
	const char *p2 = "dp2T1";
	const char *p3 = "dp3T2";
	char port1_name[IFNAMSIZ];
	char port2_name[IFNAMSIZ];
	json_object *expected;
	const char *sw = "sw0";
	const int msti = 99;
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();

	bridge_vlan_set_add(allowed_vlans, 10);
	bridge_vlan_set_add(allowed_vlans, 1000);
	mstp_switch_create(sw, p1, p2, p3, allowed_vlans);

	dp_test_intf_real(p1, port1_name);
	dp_test_intf_real(p2, port2_name);
	struct ifnet *port1 = dp_ifnet_byifname(port1_name);
	struct ifnet *port2 = dp_ifnet_byifname(port2_name);

	mstp_msti_add(sw, msti, "10:1000");

	expected = dp_test_json_create(
		"{ \"vlan-list\" : [{"
		"\"vlanid\" : 10, \"mstid\" : %d,"
		"\"switch-ports\" : ["
		"{\"state\" : \"%s\","
		"\"port\" : \"%s\"},"
		"{\"state\" : \"%s\","
		"\"port\" : \"%s\"}"
		"]}]}",
		msti,
		bridge_get_ifstate_string(BR_STATE_DISABLED), port1_name,
		bridge_get_ifstate_string(BR_STATE_DISABLED), port2_name
		);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "mstp-op %s show state", sw);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	MSTP_MSTI_SET_STATE_NO_CHECK(sw, BR_STATE_FORWARDING, port1, msti);
	MSTP_MSTI_SET_STATE_NO_CHECK(sw, BR_STATE_LEARNING, port2, msti);

	expected = dp_test_json_create(
		"{ \"vlan-list\" : [{"
		"\"vlanid\" : 10, \"mstid\" : %d,"
		"\"switch-ports\" : ["
		"{\"state\" : \"%s\","
		"\"port\" : \"%s\"},"
		"{\"state\" : \"%s\","
		"\"port\" : \"%s\"}"
		"]}]}",
		msti,
		bridge_get_ifstate_string(STP_IFSTATE_FORWARDING), port1_name,
		bridge_get_ifstate_string(STP_IFSTATE_LEARNING), port2_name
		);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "mstp-op %s show state", sw);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_FORWARDING, port1, 10);
	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_FORWARDING, port1, 1000);
	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_LEARNING, port2, 10);
	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_LEARNING, port2, 1000);
	MSTP_MSTI_SET_STATE(sw, BR_STATE_FORWARDING, port2, msti);
	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_FORWARDING, port2, 10);
	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_FORWARDING, port2, 1000);

	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_BLOCKING, port1, 0);
	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_BLOCKING, port1, 100);
	MSTI_CHECK_VLAN_STATE(STP_IFSTATE_BLOCKING, port1, 4094);

	mstp_msti_remove(sw, msti);
	mstp_switch_delete(sw, p1, p2, p3);
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

DP_START_TEST(mstp_fwd_1, mstp_fwd_vlan_drop)
{
	const char *p1 = "dp1T0";
	const char *p2 = "dp2T1";
	const char *p3 = "dp3T2";
	char port1_name[IFNAMSIZ];
	char port2_name[IFNAMSIZ];
	json_object *expected;
	const char *sw = "sw0";
	const int msti = 99;
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	const char *mac_a = "0:0:a4:0:0:aa";
	const char *mac_b = "0:0:a4:0:0:bb";
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 64;

	bridge_vlan_set_add(allowed_vlans, 10);
	mstp_switch_create(sw, p1, p2, p3, allowed_vlans);

	dp_test_intf_real(p1, port1_name);
	dp_test_intf_real(p2, port2_name);
	struct ifnet *port1 = dp_ifnet_byifname(port1_name);
	struct ifnet *port2 = dp_ifnet_byifname(port2_name);

	mstp_msti_add(sw, msti, "10");
	MSTP_MSTI_SET_STATE(sw, BR_STATE_LEARNING, port1, msti);
	MSTP_MSTI_SET_STATE(sw, BR_STATE_LEARNING, port2, msti);

	/*
	 * mac_a -> mac_b
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	/*
	 * Create pak we expect to receive on the tx ring
	 * Transparent bridging so we expect pak to be identical.
	 */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, p1, exp);

	expected = dp_test_json_create(
		"{\"name\" : \"%s\",\"mac_table\" : ["
		"{\"vlan\" : \"%d\","
		"\"port\" : \"%s\","
		"\"ageing\" : 0,"
		"\"dynamic\" : true,"
		"\"static\" : false,"
		"\"local\" : false,"
		"\"mac\" : \"%s\""
		"}]}",
		sw, 10, port1_name, mac_a);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "bridge %s macs show port %s", sw, port1_name);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	expected = dp_test_json_create(
		"{\"name\" : \"%s\",\"mac_table\" : []}", sw);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "bridge %s macs show port %s", sw, port2_name);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	/*
	 * mac_b -> mac_a
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_a, mac_b, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, p2, exp);

	expected = dp_test_json_create(
		"{\"name\" : \"%s\",\"mac_table\" : ["
		"{\"vlan\" : \"%d\","
		"\"port\" : \"%s\","
		"\"ageing\" : 0,"
		"\"dynamic\" : true,"
		"\"static\" : false,"
		"\"local\" : false,"
		"\"mac\" : \"%s\""
		"}]}",
		sw, 10, port2_name, mac_b);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "bridge %s macs show port %s", sw, port2_name);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	mstp_msti_remove(sw, msti);
	mstp_switch_delete(sw, p1, p2, p3);
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

DP_START_TEST(mstp_fwd_1, mstp_fwd_vlan)
{
	const char *p1 = "dp1T0";
	const char *p2 = "dp2T1";
	const char *p3 = "dp3T2";
	char port1_name[IFNAMSIZ];
	char port2_name[IFNAMSIZ];
	char port3_name[IFNAMSIZ];
	json_object *expected;
	const char *sw = "sw0";
	const int msti = 99;
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	const char *mac_a = "0:0:a4:0:0:aa";
	const char *mac_b = "0:0:a4:0:0:bb";
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 64;

	bridge_vlan_set_add(allowed_vlans, 10);
	mstp_switch_create(sw, p1, p2, p3, allowed_vlans);

	dp_test_intf_real(p1, port1_name);
	dp_test_intf_real(p2, port2_name);
	dp_test_intf_real(p3, port3_name);
	struct ifnet *port1 = dp_ifnet_byifname(port1_name);
	struct ifnet *port2 = dp_ifnet_byifname(port2_name);
	struct ifnet *port3 = dp_ifnet_byifname(port3_name);

	mstp_msti_add(sw, msti, "10");
	MSTP_MSTI_SET_STATE(sw, BR_STATE_FORWARDING, port1, msti);
	MSTP_MSTI_SET_STATE(sw, BR_STATE_FORWARDING, port2, msti);
	MSTP_MSTI_SET_STATE(sw, BR_STATE_FORWARDING, port3, msti);

	/*
	 * mac_a -> mac_b
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);

	/*
	 * Packet should be flooded from P1 to P2 and P3
	 */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_oif_name_m(exp, 0, p2);
	dp_test_exp_set_oif_name_m(exp, 1, p3);

	dp_test_exp_set_vlan_tci(exp, 10);
	dp_test_pak_receive(test_pak, p1, exp);

	expected = dp_test_json_create(
		"{\"name\" : \"%s\",\"mac_table\" : ["
		"{\"vlan\" : \"%d\","
		"\"port\" : \"%s\","
		"\"ageing\" : 0,"
		"\"dynamic\" : true,"
		"\"static\" : false,"
		"\"local\" : false,"
		"\"mac\" : \"%s\""
		"}]}",
		sw, 10, port1_name, mac_a);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "bridge %s macs show port %s", sw, port1_name);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	expected = dp_test_json_create(
		"{\"name\" : \"%s\",\"mac_table\" : []}", sw);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "bridge %s macs show port %s", sw, port2_name);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	expected = dp_test_json_create(
		"{\"name\" : \"%s\",\"mac_table\" : []}", sw);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "bridge %s macs show port %s", sw, port3_name);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	mstp_msti_remove(sw, msti);
	mstp_switch_delete(sw, p1, p2, p3);
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;

DP_START_TEST(mstp_fwd_1, mstp_fwd_vlan_flush)
{
	const char *p1 = "dp1T0";
	const char *p2 = "dp2T1";
	const char *p3 = "dp3T2";
	char port1_name[IFNAMSIZ];
	char port2_name[IFNAMSIZ];
	json_object *expected;
	const char *sw = "sw0";
	const int msti = 99;
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();
	const char *mac_a = "0:0:a4:0:0:aa";
	const char *mac_b = "0:0:a4:0:0:bb";
	const char *mac_c = "0:0:a4:0:0:cc";
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 64;

	bridge_vlan_set_add(allowed_vlans, 10);
	bridge_vlan_set_add(allowed_vlans, 1000);
	mstp_switch_create(sw, p1, p2, p3, allowed_vlans);

	dp_test_intf_real(p1, port1_name);
	dp_test_intf_real(p2, port2_name);
	struct ifnet *port1 = dp_ifnet_byifname(port1_name);
	struct ifnet *port2 = dp_ifnet_byifname(port2_name);

	mstp_msti_add(sw, msti, "10:1000");
	MSTP_MSTI_SET_STATE(sw, BR_STATE_FORWARDING, port1, msti);
	MSTP_MSTI_SET_STATE(sw, BR_STATE_FORWARDING, port2, msti);

	/*
	 * mac_a -> mac_b (VLAN 10)
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_a, 10,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, p2);
	dp_test_exp_set_vlan_tci(exp, 10);
	dp_test_pak_receive(test_pak, p1, exp);

	/*
	 * mac_c -> mac_b (VLAN 1000)
	 */
	test_pak = dp_test_create_8021q_l2_pak(mac_b, mac_c, 1000,
					       ETH_P_8021Q,
					       DP_TEST_ET_LLDP,
					       1, &len);
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, p2);
	dp_test_exp_set_vlan_tci(exp, 1000);
	dp_test_pak_receive(test_pak, p1, exp);

	expected = dp_test_json_create(
		"{\"name\" : \"%s\",\"mac_table\" : ["
		"{\"vlan\" : \"%d\","
		"\"port\" : \"%s\","
		"\"ageing\" : 0,"
		"\"dynamic\" : true,"
		"\"static\" : false,"
		"\"local\" : false,"
		"\"mac\" : \"%s\"},"
		"{\"vlan\" : \"%d\","
		"\"port\" : \"%s\","
		"\"ageing\" : 0,"
		"\"dynamic\" : true,"
		"\"static\" : false,"
		"\"local\" : false,"
		"\"mac\" : \"%s\"}"
		"]}",
		sw, 10, port1_name, mac_a, 1000, port1_name, mac_c);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "bridge %s macs show port %s", sw, port1_name);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "mstp-op %s clear macs port %s msti %d",
		 sw, port1_name, msti);
	dp_test_console_request_reply(test_mstp_cmd, false);
	snprintf(test_mstp_cmd, sizeof(test_mstp_cmd),
		 "bridge %s macs show port %s", sw, port1_name);
	expected = dp_test_json_create(
		"{\"name\" : \"%s\",\"mac_table\" : []}", sw);
	dp_test_check_json_state(test_mstp_cmd, expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	mstp_msti_remove(sw, msti);
	mstp_switch_delete(sw, p1, p2, p3);
	bridge_vlan_set_free(allowed_vlans);
} DP_END_TEST;
