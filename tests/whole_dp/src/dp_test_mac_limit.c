/*
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <dlfcn.h>
#include "dp_test/dp_test_macros.h"
#include "util.h"
#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_console.h"
#include "dp_test_lib_intf_internal.h"
#include "bridge_vlan_set.h"
#include "fal_plugin_test.h"
#include "protobuf/MacLimitConfig.pb-c.h"

#define INT1 "dpT10"
#define INT2 "dpT11"

#define ALL "all"
#define NONE "none"

#define LOG(l, t, ...)						\
	rte_log(RTE_LOG_ ## l,					\
		RTE_LOGTYPE_USER1, # t ": " __VA_ARGS__)

#define DEBUG(...)						\
	do {							\
		if (dp_test_debug_get() == 2)			\
			LOG(DEBUG, MAC_LIMIT, __VA_ARGS__);	\
	} while (0)

static void _show_mac_limit_info(const char *intf, uint16_t vlan,
				 const char *profile, uint32_t limit,
				 bool present, const char *file, int line)
{
	json_object *jexp;
	char cmd_str[50];

	sprintf(cmd_str, "mac-limit dump %s %d %s",
		intf, vlan, profile);

	/*
	 * Expected JSON depends on whether an intf is specified
	 * and if so, whether is it assigned a profile.
	 */
	if (present) {
		if (strcmp(intf, NONE) != 0) {
			jexp = dp_test_json_create(
				"{ "
				"\"mac-limit\": "
				"{ "
				"\"instance\": "
				"[ { "
				"\"interface\": \"%s\", "
				"\"vlan\": %d, "
				"\"profile\": \"%s\" "
				"} ], "
				"\"profile\":"
				"[ { "
				"\"name\": \"%s\","
				"\"limit\":%d"
				"} ] "
				"} " "} ", intf, vlan, profile, profile, limit);
		} else {
			jexp = dp_test_json_create(
				"{ "
				"\"mac-limit\": "
				"{ "
				"\"profile\":"
				"[ { "
				"\"name\": \"%s\","
				"\"limit\":%d"
				"} ] "
				"} " "} ", profile, limit);
		}
	} else {
		jexp = dp_test_json_create(
			"{ "
			"\"mac-limit\": "
			"{ } }");
	}

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file,
				       "", line);
	json_object_put(jexp);
}

#define show_mac_limit_info(intf, vlan, profile, limit, present)  \
	_show_mac_limit_info(intf, vlan, profile, limit, present, \
			     __FILE__, __LINE__)

static void _verify_plugin_limit(const char *intf, uint16_t vlan,
				 uint32_t explimit,
				 const char *file, int line)
{
	json_object *jexp;
	char cmd_str[50];

	sprintf(cmd_str, "mac-limit show status %s %d",
		intf, vlan);
	jexp = dp_test_json_create(
		"{ "
		"\"statistics\": "
		"{ "
		"\"limit\":%d,"
		"\"count\":0"
		"} " "} ", explimit);

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, __FILE__,
				       "", __LINE__);
	json_object_put(jexp);
}

#define verify_plugin_limit(intf, vlan, explimit) \
	_verify_plugin_limit(intf, vlan, explimit, __FILE__, __LINE__)

static void mac_limit_wrap_and_send(MacLimitConfig *ml_cfg)
{
	void *buf;
	int len;

	len = mac_limit_config__get_packed_size(ml_cfg);

	buf = malloc(len);
	dp_test_assert_internal(buf);

	mac_limit_config__pack(ml_cfg, buf);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:maclimit", buf, len);
}

static void set_profile(const char *profile_name, int limit)
{
	MacLimitConfig__MacLimitProfileConfig profile_cfg =
		MAC_LIMIT_CONFIG__MAC_LIMIT_PROFILE_CONFIG__INIT;
	MacLimitConfig ml_cfg = MAC_LIMIT_CONFIG__INIT;

	DEBUG("Set profile %s limit %d\n",
	      profile_name, limit);

	ml_cfg.mtype_case = MAC_LIMIT_CONFIG__MTYPE_PROFILE;
	ml_cfg.profile = &profile_cfg;
	profile_cfg.has_action = true;
	profile_cfg.action = MAC_LIMIT_CONFIG__ACTION__SET;
	profile_cfg.profile = (char *)profile_name;
	profile_cfg.has_limit = true;
	profile_cfg.limit = limit;

	mac_limit_wrap_and_send(&ml_cfg);
}

static void del_profile(const char *profile_name)
{
	MacLimitConfig__MacLimitProfileConfig profile_cfg =
		MAC_LIMIT_CONFIG__MAC_LIMIT_PROFILE_CONFIG__INIT;
	MacLimitConfig ml_cfg = MAC_LIMIT_CONFIG__INIT;

	DEBUG("Delete profile %s limit\n",
	      profile_name);

	ml_cfg.mtype_case = MAC_LIMIT_CONFIG__MTYPE_PROFILE;
	ml_cfg.profile = &profile_cfg;
	profile_cfg.has_action = true;
	profile_cfg.action = MAC_LIMIT_CONFIG__ACTION__DELETE;
	profile_cfg.profile = (char *)profile_name;

	mac_limit_wrap_and_send(&ml_cfg);
}

static void assign_profile(const char *profile_name, uint16_t vlan,
						   const char *intf)
{
	MacLimitConfig__MacLimitIfVLANConfig ifvlan_cfg =
		MAC_LIMIT_CONFIG__MAC_LIMIT_IF_VLANCONFIG__INIT;
	MacLimitConfig ml_cfg = MAC_LIMIT_CONFIG__INIT;

	DEBUG("Assign profile %s to interface %s vlan %d\n",
	      profile_name, intf, vlan);

	ml_cfg.mtype_case = MAC_LIMIT_CONFIG__MTYPE_IFVLAN;
	ml_cfg.ifvlan = &ifvlan_cfg;
	ifvlan_cfg.has_action = true;
	ifvlan_cfg.action = MAC_LIMIT_CONFIG__ACTION__SET;
	ifvlan_cfg.ifname = (char *)intf;
	ifvlan_cfg.has_vlan = true;
	ifvlan_cfg.vlan = vlan;
	ifvlan_cfg.profile = (char *)profile_name;

	mac_limit_wrap_and_send(&ml_cfg);
}

static void unassign_profile(const char *profile_name, uint16_t vlan,
			     const char *intf)
{
	MacLimitConfig__MacLimitIfVLANConfig ifvlan_cfg =
		MAC_LIMIT_CONFIG__MAC_LIMIT_IF_VLANCONFIG__INIT;
	MacLimitConfig ml_cfg = MAC_LIMIT_CONFIG__INIT;

	DEBUG("Unassign profile %s from interface %s\n",
	      profile_name, intf);

	ml_cfg.mtype_case = MAC_LIMIT_CONFIG__MTYPE_IFVLAN;
	ml_cfg.ifvlan = &ifvlan_cfg;
	ifvlan_cfg.has_action = true;
	ifvlan_cfg.action = MAC_LIMIT_CONFIG__ACTION__DELETE;
	ifvlan_cfg.ifname = (char *)intf;
	ifvlan_cfg.has_vlan = true;
	ifvlan_cfg.vlan = vlan;

	mac_limit_wrap_and_send(&ml_cfg);
}

DP_DECL_TEST_SUITE(mac_limit);

DP_DECL_TEST_CASE(mac_limit, limit, NULL, NULL);

DP_START_TEST(limit, test1)
{
	uint32_t lim1 = 1, lim2 = 2, lim3 = 3, lim4 = 4;

	dp_test_send_config_src(dp_test_cont_src_get(),
				"switchport dpT10 hw-switching enable");
	dp_test_send_config_src(dp_test_cont_src_get(),
				"switchport dpT11 hw-switching enable");

	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();

	/*
	 * Set up some profiles.
	 */
	set_profile("p1", lim1);
	show_mac_limit_info(NONE, 0, "p1", lim1, true);

	set_profile("p2", lim2);
	show_mac_limit_info(NONE, 0, "p2", lim2, true);

	set_profile("p3", lim3);
	show_mac_limit_info(NONE, 0, "p3", lim3, true);

	set_profile("p4", lim4);
	show_mac_limit_info(NONE, 0, "p4", lim4, true);

	/*
	 * Assign the profile to a port+vlan before the vlan
	 * has been created.
	 */
	assign_profile("p1", 1, INT1);
	show_mac_limit_info(INT1, 1, "p1", lim1, true);

	bridge_vlan_set_add(allowed_vlans, 1);
	bridge_vlan_set_add(allowed_vlans, 2);

	dp_test_intf_switch_create("switch0");
	dp_test_intf_bridge_enable_vlan_filter("switch0");

	dp_test_intf_switch_add_port("switch0", INT1);
	dp_test_intf_bridge_port_set_vlans("switch0", INT1,
					   0, allowed_vlans, NULL);

	dp_test_intf_switch_add_port("switch0", INT2);
	dp_test_intf_bridge_port_set_vlans("switch0", INT2,
					   0, allowed_vlans, NULL);

	/*
	 * Vlan created. Verify limit was applied.
	 */
	verify_plugin_limit(INT1, 1, lim1);

	/*
	 * Delete the limit from the profile while it is still
	 * assigned
	 */

	/*
	 * Assign same profile to another interface
	 */
	assign_profile("p1", 1, INT2);
	verify_plugin_limit(INT2, 1, lim1);

	/*
	 * Increase the profile limit and verify that all
	 * instances to which it is assigned are updated.
	 */
	lim1 = 120;
	set_profile("p1", lim1);
	show_mac_limit_info(INT1, 1, "p1", lim1, true);
	show_mac_limit_info(INT2, 1, "p1", lim1, true);
	verify_plugin_limit(INT1, 1, lim1);
	verify_plugin_limit(INT2, 1, lim1);

	/*
	 * Set different limits on same port and different vlan.
	 */
	assign_profile("p3", 2, INT1);
	assign_profile("p4", 2, INT2);
	show_mac_limit_info(INT1, 2, "p3", lim3, true);
	show_mac_limit_info(INT2, 2, "p4", lim4, true);
	verify_plugin_limit(INT1, 2, lim3);
	verify_plugin_limit(INT2, 2, lim4);

	/*
	 * Recheck vlan 1 to ensure unaffected.
	 * All checks are for "lim1" as INT1 and INT2 vlan 1
	 * are using the same profile.
	 */
	show_mac_limit_info(INT1, 1, "p1", lim1, true);
	show_mac_limit_info(INT2, 1, "p1", lim1, true);
	verify_plugin_limit(INT1, 1, lim1);
	verify_plugin_limit(INT2, 1, lim1);

	unassign_profile("p1", 1, INT2);
	unassign_profile("p3", 2, INT1);
	unassign_profile("p4", 2, INT2);

	/*
	 * Verfy no active instances for these.
	 */
	show_mac_limit_info(INT2, 1, "none", 0, false);
	show_mac_limit_info(INT1, 2, "none", 0, false);
	show_mac_limit_info(INT2, 2, "none", 0, false);

	/*
	 * INT1+vlan1 has profile "p1". Assign another profile
	 * without unassigning the first and verify update.
	 */
	set_profile("p2", lim2);
	assign_profile("p2", 1, INT1);
	show_mac_limit_info(INT1, 1, "p2", lim2, true);
	verify_plugin_limit(INT1, 1, lim2);

	unassign_profile("p2", 1, INT1);

	/*
	 * There should be no active instances now.
	 */
	show_mac_limit_info(INT1, 1, "none", 0, false);

	/*
	 * Verify all profiles still exist although unassigned.
	 */
	show_mac_limit_info(NONE, 0, "p1", lim1, true);
	show_mac_limit_info(NONE, 0, "p2", lim2, true);
	show_mac_limit_info(NONE, 0, "p3", lim3, true);
	show_mac_limit_info(NONE, 0, "p4", lim4, true);

	DEBUG("Delete profiles\n");
	del_profile("p1");
	del_profile("p2");
	del_profile("p3");
	del_profile("p4");

	/*
	 * Verify profiles no longer exist
	 */
	show_mac_limit_info(NONE, 0, "p1", lim1, false);
	show_mac_limit_info(NONE, 0, "p2", lim2, false);
	show_mac_limit_info(NONE, 0, "p3", lim3, false);
	show_mac_limit_info(NONE, 0, "p4", lim4, false);

	DEBUG("MAC_LIMIT: End\n");

	dp_test_intf_switch_remove_port("switch0", INT1);
	dp_test_intf_switch_remove_port("switch0", INT2);
	dp_test_intf_switch_del("switch0");
	bridge_vlan_set_free(allowed_vlans);

	dp_test_send_config_src(dp_test_cont_src_get(),
				"switchport dpT10 hw-switching disable");
	dp_test_send_config_src(dp_test_cont_src_get(),
				"switchport dpT11 hw-switching disable");
} DP_END_TEST;

