/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "dp_test_macros.h"
#include "util.h"
#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_console.h"
#include "dp_test_lib_intf.h"
#include "bridge_vlan_set.h"

DP_DECL_TEST_SUITE(storm_ctl);

DP_DECL_TEST_CASE(storm_ctl, add_profile, NULL, NULL);

static void
_dp_test_verify_storm_ctl_profile(const char *name, bool set,
				  const char *file, const char *func, int line)
{
	char cmd[100];
	char expected[100];

	snprintf(expected, sizeof(expected), "\"profile_name\": \"%s\"", name);

	snprintf(cmd, 30, "storm-ctl show");

	if (set)
		_dp_test_check_state_show(file, line, cmd, expected, false,
					  DP_TEST_CHECK_STR_SUBSET);
	else
		_dp_test_check_state_gone_show(file, line, cmd, expected, false,
					       DP_TEST_CHECK_STR_SUBSET);
}
#define dp_test_verify_storm_ctl_profile(profile_name, set)	   \
	_dp_test_verify_storm_ctl_profile(profile_name, set,       \
					  __FILE__, __func__,      \
					  __LINE__)

/*
 * traffic is a array of traffic types (unicast, ...) with each member being
 * a 2 value array of the traffic type within, only one of which can be set.
 */
static void
_dp_test_verify_storm_ctl_profile_state(const char *profile_name,
					int recovery_interval,
					int shutdown,
					int traffic[3][2],
					const char *file,
					const char *function,
					int line)
{
	json_object *jexp;
	char cmd_str[30];
	enum fal_traffic_type i;
	int *tr_arr;
	char traffic_str[200] = { 0 };
	int start = 0;

	/* Build the expected traffic bandwidth string */
	for (i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
		tr_arr = traffic[i];
		if (tr_arr[0])
			start += snprintf(
				traffic_str + start, 200 - start,
				"        \"%s\": { \"bw_level\": %d }, ",
				storm_ctl_traffic_type_to_str(i),
				tr_arr[0]);
		else if (tr_arr[1])
			start += snprintf(traffic_str + start, 200 - start,
					  "        \"%s\": { \"bw_percent\": %g }, ",
					  storm_ctl_traffic_type_to_str(i),
					  (float)tr_arr[1] / 100);
	}

	snprintf(cmd_str, 30, "storm-ctl show profile");
	jexp = dp_test_json_create(
		"{ "
		"  \"profile_table\": "
		"    [ "
		"      { "
		"        \"profile_name\": \"%s\", "
		"        \"recovery_interval\": %d, "
		"        \"shutdown\": %d, "
		"%s"
		"      }"
		"    ] "
		"} ",
		profile_name, recovery_interval, shutdown, traffic_str);

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file,
				       function, line);
	json_object_put(jexp);
}

#define dp_test_verify_storm_ctl_profile_state(profile_name,		\
					       recovery,		\
					       shutdown,		\
					       traffic)			\
	_dp_test_verify_storm_ctl_profile_state(profile_name, recovery,	\
						shutdown, traffic,	\
						__FILE__, __func__,	\
						__LINE__)

#define SC_ACTION_NO_SHUT 0
#define SC_ACTION_SHUT 1

/* When we ask the test fal for a rate it always bumps it by this amount */
#define FAL_BUMPS_RATE_BY 10

static void
_dp_test_verify_storm_ctl_state(bool monitoring, int count,
				const char *interface,
				int vlan,
				uint32_t cfg_rate[3],
				uint64_t stats[3],
				const char *profile_name,
				bool negate_match,
				const char *file,
				const char *function, int line)
{
	char cmd_str[100];
	json_object *jexp;
	char interface_tbl_str[1000];
	char interface_state_str[1000];
	char rate_str[1000];
	enum fal_traffic_type i;
	int start = 0;

	rate_str[0] = '\0';
	for (i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
		if (cfg_rate[i]) {
			start += snprintf(rate_str + start, 1000 - start,
					  "               \"%s\": { "
					  "               \"cfg_rate\": %u,"
					  "               \"max_rate_kbps\": %u,"
					  "               \"pkts_accepted\": %lu,"
					  "               },",
					  storm_ctl_traffic_type_to_str(i),
					  cfg_rate[i],
					  cfg_rate[i] + FAL_BUMPS_RATE_BY,
					  stats[i]);
		}
	}

	if (interface) {
		snprintf(cmd_str, 100, "storm-ctl show %s", interface);
		snprintf(interface_tbl_str, 1000,
			 "     \"intfs\": [{"
			 "        \"ifname\": \"%s\", "
			 "            \"vlan_table\": [{ "
			 "                \"vlan\": %d, "
			 "                \"profile\": \"%s\","
			 "%s"
			 "                }"
			 "              ]"
			 "          }"
			 "       ]",
			 interface, vlan, profile_name, rate_str);
	} else {
		snprintf(cmd_str, 100, "storm-ctl show");
		interface_tbl_str[0] = '\0';
	}

	/* For a negate we only want to check the vlan bindings */
	if (negate_match)
		interface_state_str[0] = '\0';
	else
		snprintf(interface_state_str, 1000,
			 "    \"detection_running\": %d, "
			 "    \"applied_count\": %d, ",
			 monitoring, count);

	jexp = dp_test_json_create(
		"{ "
		"  \"storm_ctl_state\": "
		"  { "
		" %s "
		" %s "
		"  }, "
		"} ",
		interface_state_str, interface_tbl_str);

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       negate_match, 0, file,
				       function, line);
	json_object_put(jexp);
}

uint32_t zero_rate[3] = { 0 };
uint64_t zero_stats[3] = { 0 };

#define dp_test_verify_storm_ctl_state(monitoring, count)		\
	_dp_test_verify_storm_ctl_state(monitoring, count, NULL, 0,	\
					zero_rate, zero_stats, NULL,	\
					false, __FILE__, __func__, __LINE__)

#define dp_test_verify_storm_ctl_intf_state(monitoring, count, intf, vlan, \
					    profile, cfg_rate, stats)	\
	_dp_test_verify_storm_ctl_state(monitoring, count, intf, vlan,	\
					cfg_rate, stats,		\
					profile, false,			\
					__FILE__, __func__, __LINE__)

#define dp_test_verify_storm_ctl_no_intf_state(intf, vlan, profile)	\
	_dp_test_verify_storm_ctl_state(0, 0, intf, vlan, zero_rate,	\
					zero_stats, profile, true,	\
					__FILE__, __func__, __LINE__)

#define SC_MON_OFF 0
#define SC_MON_ON 1

/*
 * Verify we can create and delete a profile
 *
 * Bandwidth percents are stored as percentage * 100, so we need to factor
 * that in when setting the expected values for percentages.
 */
DP_START_TEST(add_profile, profile_dump)
{
	int bandwidth[3][2] = { {0, 0},
				{0, 0},
				{0, 0}, };

	/* Set recovery interval */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile test1 recovery-interval 10");
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_NO_SHUT,
					       bandwidth);

	/* Set shutdown action */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile test1 shutdown shutdown");
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_SHUT,
					       bandwidth);

	/* Set unicast bandwidth level */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile test1 unicast bandwidth-level 100");
	bandwidth[0][0] = 100;
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_SHUT,
					       bandwidth);

	/* Set multicast bandwidth level */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile test1 multicast bandwidth-percent 50");
	bandwidth[1][1] = 5000;
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_SHUT,
					       bandwidth);

	/* Set broadcast bandwidth level */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile test1 broadcast bandwidth-percent 10.25");
	bandwidth[2][1] = 1025;
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_SHUT,
					       bandwidth);

	/* Clear shutdown action */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile test1 shutdown");
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_NO_SHUT,
					       bandwidth);

	/* Delete broadcast bandwidth level */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile test1 broadcast bandwidth-percent");
	bandwidth[2][1] = 0;
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_NO_SHUT,
					       bandwidth);

	/* Clear multicast bandwidth level */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile test1 multicast bandwidth-percent");
	bandwidth[1][1] = 0;
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_NO_SHUT,
					       bandwidth);

	/* Clear unicast bandwidth level */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile test1 unicast bandwidth-level");
	bandwidth[0][0] = 0;
	dp_test_verify_storm_ctl_profile_state("test1", 10, SC_ACTION_NO_SHUT,
					       bandwidth);

	/* Clear recovery interval */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile test1 recovery-interval");
	dp_test_verify_storm_ctl_profile("test1", false);

} DP_END_TEST;

/*
 * Create a profile, and verify the behaviour for setting it on the interface
 * is the same as for setting the fields directly on the interface
 */
DP_START_TEST(add_profile, profile_for_intf)
{
	int bandwidth[3][2] = { {0, 0},
				{0, 0},
				{0, 0}, };

	/* Set unicast bandwidth-level */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR1 unicast bandwidth-level 10000000");
	bandwidth[0][0] = 10000000;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth);

	/* Set multicast bandwidth-percent */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR1 multicast bandwidth-percent 100");
	bandwidth[1][1] = 10000;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth);

	/* Bind to interface */
	dp_test_verify_storm_ctl_state(SC_MON_OFF, 0);
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET dpT10 profile PR1");

	/* Resend the same config */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET dpT10 profile PR1");

	/* Modify the unicast traffic */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR1 unicast bandwidth-level 2000000");
	bandwidth[0][0] = 2000000;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth);

	/* Modify unicast again - to match set of transitions FAL expects */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR1 unicast bandwidth-level 500000");
	bandwidth[0][0] = 500000;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth);

	/* Modify the multicast traffic */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR1 multicast bandwidth-percent 20");
	bandwidth[1][1] = 2000;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth);

	/* Modify mcast traffic - to match set of transitions FAL expects */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR1 multicast bandwidth-percent 5");
	bandwidth[1][1] = 500;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth);

	/* Unbind from interface */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE dpT10 profile PR1");

	/* Delete unicast bandwidth-level */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile PR1 unicast bandwidth-level");
	bandwidth[0][0] = 0;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth);

	/* Delete multicast bandwidth-percent */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile PR1 multicast bandwidth-percent");
	bandwidth[1][1] = 0;
	dp_test_verify_storm_ctl_profile("PR1", false);

} DP_END_TEST;

DP_START_TEST(add_profile, profile_for_vlan)
{
	int bandwidth1[3][2] = { {0, 0},
				 {0, 0},
				 {0, 0}, };
	int bandwidth2[3][2] = { {0, 0},
				 {0, 0},
				 {0, 0}, };
	uint32_t cfg_rate1[3] = { 0 };
	uint32_t cfg_rate2[3] = { 0 };
	uint64_t stats[3] = { 10, 10, 10 };  /* Always have 10 pkts accepted */

	/* Set unicast bandwidth-level on PR1 */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR1 unicast bandwidth-level 250");
	bandwidth1[0][0] = 250;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth1);

	/* Set multicast bandwidth-percent on PR1*/
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR1 multicast bandwidth-percent 50");
	bandwidth1[1][1] = 5000;
	dp_test_verify_storm_ctl_profile_state("PR1", 0,
					       SC_ACTION_NO_SHUT, bandwidth1);

	/* Set multicast bandwidth-percent on PR2*/
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET profile PR2 multicast bandwidth-percent 30");
	bandwidth2[1][1] = 3000;
	dp_test_verify_storm_ctl_profile_state("PR2", 0,
					       SC_ACTION_NO_SHUT, bandwidth2);


	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();

	bridge_vlan_set_add(allowed_vlans, 1);
	bridge_vlan_set_add(allowed_vlans, 200);
	bridge_vlan_set_add(allowed_vlans, 300);

	dp_test_intf_switch_create("switch0");
	dp_test_intf_bridge_enable_vlan_filter("switch0");

	dp_test_intf_switch_add_port("switch0", "dpT10");
	dp_test_intf_bridge_port_set_vlans("switch0", "dpT10",
					   0, allowed_vlans, NULL);

	/* Apply PR1 to vlan 1 and verify it is there */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET dpT10 vlan 1 profile PR1");
	cfg_rate1[0] = 250;
	/*
	 * rate stored as percent * 100 in DP, but in fal is converted to kbps
	 * based on a link speed of 10G
	 */
	cfg_rate1[1] = 5000 * 1000;
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 1, "dpT10", 1, "PR1",
					    cfg_rate1, stats);

	/* Apply PR2 to vlan 200 and verify it is there */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET dpT10 vlan 200 profile PR2");
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 2, "dpT10", 1, "PR1",
					    cfg_rate1, stats);
	cfg_rate2[1] = 3000 * 1000;
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 2, "dpT10", 200, "PR2",
					    cfg_rate2, stats);

	/* Apply PR2 to vlan 300 and verify it is there */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl SET dpT10 vlan 300 profile PR2");
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 3, "dpT10", 1, "PR1",
					    cfg_rate1, stats);
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 3, "dpT10", 200, "PR2",
					    cfg_rate2, stats);
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 3, "dpT10", 300, "PR2",
					    cfg_rate2, stats);

	/* Remove PR1 from vlan 1 and verify it is gone */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE dpT10 vlan 1");
	dp_test_verify_storm_ctl_no_intf_state("dpT10", 2, "PR1");
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 2, "dpT10", 200, "PR2",
					    cfg_rate2, stats);
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 2, "dpT10", 300, "PR2",
					    cfg_rate2, stats);

	/* Remove PR2 from vlan 200 and verify it is gone */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE dpT10 vlan 200");
	dp_test_verify_storm_ctl_no_intf_state("dpT10", 1, "PR1");
	dp_test_verify_storm_ctl_no_intf_state("dpT10", 200, "PR2");
	dp_test_verify_storm_ctl_intf_state(SC_MON_ON, 1, "dpT10", 300, "PR2",
					    cfg_rate2, stats);

	/* Remove PR2 from vlan 300 and verify it is gone */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE dpT10 vlan 300");
	dp_test_verify_storm_ctl_no_intf_state("dpT10", 1, "PR1");
	dp_test_verify_storm_ctl_no_intf_state("dpT10", 200, "PR2");
	dp_test_verify_storm_ctl_no_intf_state("dpT10", 300, "PR2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile PR1 multicast bandwidth-percent");
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile PR1 unicast bandwidth-level");
	dp_test_send_config_src(dp_test_cont_src_get(),
				"storm-ctl DELETE profile PR2 multicast bandwidth-percent");

	dp_test_verify_storm_ctl_profile("PR1", false);
	dp_test_verify_storm_ctl_profile("PR2", false);
	dp_test_verify_storm_ctl_state(SC_MON_OFF, 0);

	dp_test_intf_switch_remove_port("switch0", "dpT10");
	dp_test_intf_switch_del("switch0");
	bridge_vlan_set_free(allowed_vlans);

} DP_END_TEST;
