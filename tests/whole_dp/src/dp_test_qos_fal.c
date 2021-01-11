/**
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * @file dp_test_qos_fal.h
 * @brief Basic QoS FAL unit-tests
 */

#include <libmnl/libmnl.h>
#include <rte_sched.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "fal_plugin.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"

#include "dp_test_qos_lib.h"

DP_DECL_TEST_SUITE(qos_fal);

DP_DECL_TEST_CASE(qos_fal, qos_fal_basic, NULL, NULL);

static int
dp_test_qos_fal_hw_switch_if(const char *if_name, bool enable)
{
	char real_if_name[IFNAMSIZ];
	struct ifnet *ifp;
	int ret = 0;

	/* Convert the test if-name into a real if-name */
	dp_test_intf_real(if_name, real_if_name);

	ifp = dp_ifnet_byifname(real_if_name);
	if (ifp)
		ifp->hw_forwarding = enable;
	else
		ret = -1;

	return ret;
}

/*
 * fal_basic uses a minimal QoS configuration
 *
 * fal_basic_cmds generate from:
 *
 *  set interfaces dataplane dp0s5 policy qos 'trunk-egress'
 *  set policy qos name trunk-egress shaper default 'global-profile'
 *  set policy qos profile global-profile bandwidth '100Mbit'
 */

const char *fal_basic_cmds[] = {
	"port subports 1 pipes 1 profiles 2 overhead 24 ql_bytes",
	"subport 0 rate 1250000000 size 100000 period 40000",
	"subport 0 queue 0 rate 1250000000 size 100000", // size N/A
	"subport 0 queue 1 rate 1250000000 size 100000", // size N/A
	"subport 0 queue 2 rate 1250000000 size 100000", // size N/A
	"subport 0 queue 3 rate 1250000000 size 100000", // size N/A
	"vlan 0 0",
	"profile 0 percent 1 size 50000 period 10000",
	"profile 0 queue 0 rate 12500000 size 50000", // size N/A
	"profile 0 queue 1 percent 100 size 50000",   // size N/A
	"profile 0 queue 2 rate 12500000 size 50000", // size N/A
	"profile 0 queue 3 rate 12500000 size 50000", // size N/A
	"pipe 0 0 0",
	"enable"
};

struct des_dp_pair default_dscp_map[] = {
	/* des drop-precedence */
	{ 0, 0 },   /* DSCP = 0 */
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },   /* DSCP = 15 */
	{ 1, 0 },   /* DSCP = 16 */
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },   /* DSCP = 31 */
	{ 2, 0 },   /* DSCP = 32 */
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },   /* DSCP = 47 */
	{ 3, 0 },   /* DSCP = 48 */
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 }    /* DSCP = 63 */
};

DP_START_TEST(qos_fal_basic, fal_basic)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	json_object *j_sched_obj;
	json_object *j_obj;
	uint32_t level;
	uint32_t subport = 0;    /* Only one subport with id = 0 */
	uint32_t pipe = 0;       /* Only one pipe with id = 0 */
	uint32_t tc;             /* The normal four traffic-classes */
	uint32_t queue = 0;      /* A single queue per TC with id = 0 */
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	dp_test_qos_attach_config_to_if("dp2T1", fal_basic_cmds, debug);

	/*
	 * Start of the hardware configuration verification checks
	 * Check the port-level
	 */
	level = FAL_QOS_SCHED_GROUP_LEVEL_PORT;
	j_obj = dp_test_qos_hw_get_json_sched_group(level, "dp2T1", 0, 0, 0,
						    debug);
	dp_test_qos_hw_check_sched_group(j_obj, level, 1, 1, 0, debug);
	j_sched_obj = dp_test_qos_hw_get_json_child(j_obj, "scheduler", debug);
	dp_test_qos_hw_check_scheduler(j_sched_obj, "Weighted Round-Robin",
				       "Bytes Per Second", 1, 1250000000, 0,
				       24, debug);
	json_object_put(j_sched_obj);
	json_object_put(j_obj);

	/*
	 * Check the subport-level
	 */
	level = FAL_QOS_SCHED_GROUP_LEVEL_SUBPORT;
	j_obj = dp_test_qos_hw_get_json_sched_group(level, "dp2T1", subport, 0,
						    0, debug);
	dp_test_qos_hw_check_sched_group(j_obj, level, 1, 1, 0, debug);
	j_sched_obj = dp_test_qos_hw_get_json_child(j_obj, "scheduler", debug);
	dp_test_qos_hw_check_scheduler(j_sched_obj, "Weighted Round-Robin",
				       "Bytes Per Second", 1, 1250000000,
				       100000, 24, debug);
	json_object_put(j_sched_obj);
	json_object_put(j_obj);

	/*
	 * Check the pipe-level
	 */
	level = FAL_QOS_SCHED_GROUP_LEVEL_PIPE;
	j_obj = dp_test_qos_hw_get_json_sched_group(level, "dp2T1", subport,
						    pipe, 0, debug);
	dp_test_qos_hw_check_sched_group(j_obj, level, 4, 4, 0, debug);
	j_sched_obj = dp_test_qos_hw_get_json_child(j_obj, "scheduler", debug);
	dp_test_qos_hw_check_scheduler(j_sched_obj, "Strict Priority",
				       "Bytes Per Second", -1, 12500000, 50000,
				       24, debug);

	json_object_put(j_sched_obj);
	json_object_put(j_obj);

	/*
	 * Check the four TCs
	 */
	level = FAL_QOS_SCHED_GROUP_LEVEL_TC;
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		j_obj = dp_test_qos_hw_get_json_sched_group(level, "dp2T1",
							    subport, pipe, tc,
							    debug);
		dp_test_qos_hw_check_sched_group(j_obj, level, 1, 1, 0, debug);
		j_sched_obj = dp_test_qos_hw_get_json_child(j_obj, "scheduler",
							    debug);
		dp_test_qos_hw_check_scheduler(j_sched_obj,
					       "Weighted Round-Robin",
					       "Bytes Per Second", 1, 12500000,
					       50000, 24, debug);
		json_object_put(j_sched_obj);
		json_object_put(j_obj);
	}

	/*
	 * Each TC should have a single queue with id = 0
	 */
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		j_obj = dp_test_qos_hw_get_json_queue("dp2T1", subport, pipe,
						      tc, queue, debug);
		dp_test_qos_hw_check_queue(j_obj, queue, 64, 0, 0, debug);
		j_sched_obj = dp_test_qos_hw_get_json_child(j_obj, "scheduler",
							    debug);
		dp_test_qos_hw_check_scheduler(j_sched_obj,
					       "Weighted Round-Robin",
					       "Bytes Per Second", 1, 0, 0,
					       0, debug);
		json_object_put(j_sched_obj);
		json_object_put(j_obj);
	}

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * fal_wred introduces a WRED queue
 *
 * fal_wred_cmds generated from:
 *
 * set interfaces dataplane dp0s5 policy qos 'trunk-egress'
 * set policy qos name trunk-egress shaper bandwidth '100Mbit'
 * set policy qos name trunk-egress shaper default 'default-profile'
 * set policy qos name trunk-egress shaper profile 'default-profile'
 * set policy qos name trunk-egress shaper traffic-class 0 queue-limit '4096'
 * set policy qos name trunk-egress shaper traffic-class 0 random-detect
 *     filter-weight '6'
 * set policy qos name trunk-egress shaper traffic-class 0 random-detect
 *     mark-probability '34'
 * set policy qos name trunk-egress shaper traffic-class 0 random-detect
 *     max-threshold '4095'
 * set policy qos name trunk-egress shaper traffic-class 0 random-detect
 *     min-threshold '2048'
 */

const char *fal_wred_cmds[] = {
	"port subports 1 pipes 1 profiles 1 overhead 24 ql_bytes",
	"subport 0 rate 12500000 size 50000 period 40000",
	"subport 0 queue 0 rate 12500000 size 50000",
	"param 0 limit packets 4096 red 0 packets 2048 4095 34 6",
	"subport 0 queue 1 rate 12500000 size 50000",
	"subport 0 queue 2 rate 12500000 size 50000",
	"subport 0 queue 3 rate 12500000 size 50000",
	"vlan 0 0",
	"profile 0 rate 12500000 size 50000 period 10000",
	"profile 0 queue 0 rate 12500000 size 50000",
	"profile 0 queue 1 rate 12500000 size 50000",
	"profile 0 queue 2 rate 12500000 size 50000",
	"profile 0 queue 3 rate 12500000 size 50000",
	"pipe 0 0 0",
	"enable"
};

DP_START_TEST(qos_fal_basic, fal_wred)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	json_object *j_wred_obj;
	json_object *j_obj;
	uint32_t subport = 0;    /* Only one subport with id = 0 */
	uint32_t pipe = 0;       /* Only one pipe with id = 0 */
	uint32_t tc;             /* The normal four traffic-classes */
	uint32_t queue = 0;      /* A single queue per TC with id = 0 */
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", fal_wred_cmds, debug);

	/*
	 * No need to check the port, subport, pipe and TCs, they are
	 * the same as the qos_fal_basic test.
	 *
	 * Each TC should have a single queue with id = 0
	 */
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		j_obj = dp_test_qos_hw_get_json_queue("dp2T1", subport, pipe,
						      tc, queue, debug);

		if (tc != 0) {
			/*
			 * Non TC-0 queues have default queue-limits of 64
			 */
			dp_test_qos_hw_check_queue(j_obj, queue, 64, 0, 0,
						   debug);
		} else {
			/*
			 * Check for 4k queue-limit and WRED queue on TC-0
			 */
			dp_test_qos_hw_check_queue(j_obj, queue, 4096, 0,
						   0, debug);
			j_wred_obj = dp_test_qos_hw_get_json_child(j_obj,
								   "wred",
								   debug);
			dp_test_qos_hw_check_wred_colour(j_wred_obj, "green",
							 true, 2048, 4095, 34,
							 6, debug);
			json_object_put(j_wred_obj);
		}
		json_object_put(j_obj);
	}

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();
} DP_END_TEST;

/*
 * fal_said_npf_cmds and fal_said_qos_cmds created from:
 *
 *   set resource group dscp-group synch-group dscp 56
 *
 *   set resource group dscp-group real-time-group dscp 48
 *   set resource group dscp-group real-time-group dscp 47
 *   set resource group dscp-group real-time-group dscp 46
 *   set resource group dscp-group real-time-group dscp 40
 *
 *   set resource group dscp-group priority-group-high-drop dscp 34
 *   set resource group dscp-group priority-group-high-drop dscp 32
 *   set resource group dscp-group priority-group-high-drop dscp 26
 *   set resource group dscp-group priority-group-high-drop dscp 24
 *
 *   set resource group dscp-group priority-group-low-drop dscp 39
 *   set resource group dscp-group priority-group-low-drop dscp 38
 *   set resource group dscp-group priority-group-low-drop dscp 37
 *   set resource group dscp-group priority-group-low-drop dscp 36
 *   set resource group dscp-group priority-group-low-drop dscp 35
 *   set resource group dscp-group priority-group-low-drop dscp 33
 *   set resource group dscp-group priority-group-low-drop dscp 31
 *   set resource group dscp-group priority-group-low-drop dscp 30
 *   set resource group dscp-group priority-group-low-drop dscp 29
 *   set resource group dscp-group priority-group-low-drop dscp 28
 *   set resource group dscp-group priority-group-low-drop dscp 27
 *   set resource group dscp-group priority-group-low-drop dscp 25
 *
 *   set resource group dscp-group default-group-high-drop dscp 18
 *   set resource group dscp-group default-group-high-drop dscp 16
 *   set resource group dscp-group default-group-high-drop dscp 10
 *   set resource group dscp-group default-group-high-drop dscp 8
 *
 *   set resource group dscp-group default-group-low-drop dscp 63
 *   set resource group dscp-group default-group-low-drop dscp 62
 *   set resource group dscp-group default-group-low-drop dscp 61
 *   set resource group dscp-group default-group-low-drop dscp 60
 *   set resource group dscp-group default-group-low-drop dscp 59
 *   set resource group dscp-group default-group-low-drop dscp 58
 *   set resource group dscp-group default-group-low-drop dscp 57
 *   set resource group dscp-group default-group-low-drop dscp 55
 *   set resource group dscp-group default-group-low-drop dscp 54
 *   set resource group dscp-group default-group-low-drop dscp 53
 *   set resource group dscp-group default-group-low-drop dscp 52
 *   set resource group dscp-group default-group-low-drop dscp 51
 *   set resource group dscp-group default-group-low-drop dscp 50
 *   set resource group dscp-group default-group-low-drop dscp 49
 *   set resource group dscp-group default-group-low-drop dscp 45
 *   set resource group dscp-group default-group-low-drop dscp 44
 *   set resource group dscp-group default-group-low-drop dscp 43
 *   set resource group dscp-group default-group-low-drop dscp 42
 *   set resource group dscp-group default-group-low-drop dscp 41
 *   set resource group dscp-group default-group-low-drop dscp 23
 *   set resource group dscp-group default-group-low-drop dscp 22
 *   set resource group dscp-group default-group-low-drop dscp 21
 *   set resource group dscp-group default-group-low-drop dscp 20
 *   set resource group dscp-group default-group-low-drop dscp 19
 *   set resource group dscp-group default-group-low-drop dscp 17
 *   set resource group dscp-group default-group-low-drop dscp 15
 *   set resource group dscp-group default-group-low-drop dscp 14
 *   set resource group dscp-group default-group-low-drop dscp 13
 *   set resource group dscp-group default-group-low-drop dscp 12
 *   set resource group dscp-group default-group-low-drop dscp 11
 *   set resource group dscp-group default-group-low-drop dscp 9
 *   set resource group dscp-group default-group-low-drop dscp 7
 *   set resource group dscp-group default-group-low-drop dscp 6
 *   set resource group dscp-group default-group-low-drop dscp 5
 *   set resource group dscp-group default-group-low-drop dscp 4
 *   set resource group dscp-group default-group-low-drop dscp 3
 *   set resource group dscp-group default-group-low-drop dscp 2
 *   set resource group dscp-group default-group-low-drop dscp 1
 *   set resource group dscp-group default-group-low-drop dscp 0
 *
 *   set interfaces dataplane dp0s5 policy qos 'trunk-policy'
 *   set interfaces dataplane dp0s5 vif 10 policy qos 'vlan-policy-50M'
 *   set interfaces dataplane dp0s5 vif 20 policy qos 'vlan-policy-50M'
 *   set policy qos name trunk-policy shaper default 'trunk-profile'
 *   set policy qos name trunk-policy shaper frame-overhead '22'
 *   set policy qos name trunk-policy shaper profile trunk-profile bandwidth
 *       '2mbit'
 *   set policy qos name trunk-policy shaper traffic-class 0 queue-limit '512'
 *   set policy qos name trunk-policy shaper traffic-class 1 queue-limit '1024'
 *   set policy qos name trunk-policy shaper traffic-class 2 queue-limit '1024'
 *   set policy qos name trunk-policy shaper traffic-class 3 queue-limit '1'
 *   set policy qos mark-map hw-egress-map dscp-group synch-group
 *       pcp-mark 7
 *   set policy qos mark-map hw-egress-map dscp-group real-time-group
 *       pcp-mark 5
 *   set policy qos mark-map hw-egress-map dscp-group
 *       priority-group-high-drop pcp-mark 4
 *   set policy qos mark-map hw-egress-map dscp-group
 *       priority-group-low-drop pcp-mark 3
 *   set policy qos mark-map hw-egress-map dscp-group
 *       default-group-high-drop pcp-mark 2
 *   set policy qos mark-map hw-egress-map dscp-group
 *       default-group-low-drop pcp-mark 1
 *   set policy qos name vlan-policy-50M shaper mark-map hw-egress-map
 *   set policy qos name vlan-policy-50M shaper default 'default-prof'
 *   set policy qos profile default-prof bandwidth '2mbit'
 *   set policy qos profile vlan-profile-50M bandwidth '50mbit'
 *   set policy qos profile vlan-profile-50M burst '30000'
 *   set policy qos profile vlan-profile-50M map dscp 0-23,41-45,49-55,57-63
 *       to '9'
 *   set policy qos profile vlan-profile-50M map dscp 24-39 to '8'
 *   set policy qos profile vlan-profile-50M map dscp 40,46,47,48 to '4'
 *   set policy qos profile vlan-profile-50M map dscp 56 to '0'
 *   set policy qos profile vlan-profile-50M period '5'
 *   set policy qos profile vlan-profile-50M queue 0 traffic-class '0'
 *   set policy qos profile vlan-profile-50M queue 4 traffic-class '1'
 *   set policy qos profile vlan-profile-50M queue 8 traffic-class '2'
 *   set policy qos profile vlan-profile-50M queue 8 weight '60'
 *   set policy qos profile vlan-profile-50M queue 9 traffic-class '2'
 *   set policy qos profile vlan-profile-50M queue 9 weight '40'
 *   set policy qos profile vlan-profile-50M traffic-class 0 bandwidth '50%'
 *   set policy qos profile vlan-profile-50M traffic-class 1 bandwidth '50%'
 */

const char *fal_hw_npf_cmds[] = {
	"npf-cfg delete dscp-group:synch-group",
	"npf-cfg delete dscp-group:real-time-group",
	"npf-cfg delete dscp-group:priority-group-high-drop",
	"npf-cfg delete dscp-group:priority-group-low-drop",
	"npf-cfg delete dscp-group:default-group-high-drop",
	"npf-cfg delete dscp-group:default-group-low-drop",
	"npf-cfg add dscp-group:synch-group 0 56",
	"npf-cfg add dscp-group:real-time-group 0 40;46;47;48",
	"npf-cfg add dscp-group:priority-group-high-drop 0 24;26;32;34",
	"npf-cfg add dscp-group:priority-group-low-drop 0 "
	    "25;27;28;29;30;31;33;35;36;37;38;39",
	"npf-cfg add dscp-group:default-group-high-drop 0 8;10;16;18",
	"npf-cfg add dscp-group:default-group-low-drop 0 "
	    "0;1;2;3;4;5;6;7;9;11;12;13;14;15;17;19;20;21;22;23;"
	    "41;42;43;44;45;49;50;51;52;53;54;55;57;58;59;60;61;62;63",
	"npf-cfg commit",
};

const char *fal_hw_npf_delete_cmds[] = {
	"npf-cfg delete dscp-group:synch-group",
	"npf-cfg delete dscp-group:real-time-group",
	"npf-cfg delete dscp-group:priority-group-high-drop",
	"npf-cfg delete dscp-group:priority-group-low-drop",
	"npf-cfg delete dscp-group:default-group-high-drop",
	"npf-cfg delete dscp-group:default-group-low-drop",
	"npf-cfg commit",
};

const char *fal_hw_qos_glb_cmds[] = {
	"qos global-object-cmd mark-map hw-egress-map dscp-group default-group-low-drop "
	     "pcp 1",
	"qos global-object-cmd mark-map hw-egress-map dscp-group default-group-high-drop "
	     "pcp 2",
	"qos global-object-cmd mark-map hw-egress-map dscp-group priority-group-low-drop "
	     "pcp 3",
	"qos global-object-cmd mark-map hw-egress-map dscp-group priority-group-high-drop "
	     "pcp 4",
	"qos global-object-cmd mark-map hw-egress-map dscp-group real-time-group pcp 5",
	"qos global-object-cmd mark-map hw-egress-map dscp-group synch-group pcp 7"
};

const char *fal_hw_qos_glb_delete_cmds[] = {
	"qos global-object-cmd mark-map hw-egress-map delete"
};

const char *fal_hw_qos_cmds[] = {
	"port subports 3 pipes 2 profiles 5 overhead 22 ql_bytes",

	/*
	 * 100% rate = 1250000000 bytes/sec.
	 * 1 msec burst = 1250000 bytes squashed
	 * to max burst of 130048 bytes
	 */
	"subport 0 percent 100 msec 1 period 40000",

	"subport 0 queue 0 rate 1250000000 size 100000", // size N/A
	"param 0 limit packets 512",
	"subport 0 queue 1 rate 1250000000 size 100000", // size N/A
	"param 1 limit packets 1024",
	"subport 0 queue 2 rate 1250000000 size 100000", // size N/A
	"param 2 limit packets 1024",
	"subport 0 queue 3 rate 1250000000 size 100000", // size N/A
	"param 3 limit packets 1",
	"vlan 0 0",
	"profile 3 rate 250000 msec 20 period 10000",// burst size = 5000
	"profile 3 queue 0 percent 100 size 1000",   // size N/A
	"profile 3 queue 1 rate 250000 size 1000",   // size N/A
	"profile 3 queue 2 rate 250000 size 1000",   // size N/A
	"profile 3 queue 3 rate 250000 size 1000",   // size N/A
	"profile 0 rate 6250000 size 30000 period 5000",
	"profile 0 queue 0 percent 50 size 12500",  // rate = 3125000, size N/A
	"profile 0 queue 1 rate 3125000 size 12500", // size N/A
	"profile 0 queue 2 percent 100 size 25000", // rate = 6250000, size N/A
	"profile 0 queue 3 rate 6250000 size 25000", // size N/A
	"profile 0 dscp 0 0x6",
	"profile 0 dscp 1 0x6",
	"profile 0 dscp 2 0x6",
	"profile 0 dscp 3 0x6",
	"profile 0 dscp 4 0x6",
	"profile 0 dscp 5 0x6",
	"profile 0 dscp 6 0x6",
	"profile 0 dscp 7 0x6",
	"profile 0 dscp 8 0x6",
	"profile 0 dscp 9 0x6",
	"profile 0 dscp 10 0x6",
	"profile 0 dscp 11 0x6",
	"profile 0 dscp 12 0x6",
	"profile 0 dscp 13 0x6",
	"profile 0 dscp 14 0x6",
	"profile 0 dscp 15 0x6",
	"profile 0 dscp 16 0x6",
	"profile 0 dscp 17 0x6",
	"profile 0 dscp 18 0x6",
	"profile 0 dscp 19 0x6",
	"profile 0 dscp 20 0x6",
	"profile 0 dscp 21 0x6",
	"profile 0 dscp 22 0x6",
	"profile 0 dscp 23 0x6",
	"profile 0 dscp 24 0x2",
	"profile 0 dscp 25 0x2",
	"profile 0 dscp 26 0x2",
	"profile 0 dscp 27 0x2",
	"profile 0 dscp 28 0x2",
	"profile 0 dscp 29 0x2",
	"profile 0 dscp 30 0x2",
	"profile 0 dscp 31 0x2",
	"profile 0 dscp 32 0x2",
	"profile 0 dscp 33 0x2",
	"profile 0 dscp 34 0x2",
	"profile 0 dscp 35 0x2",
	"profile 0 dscp 36 0x2",
	"profile 0 dscp 37 0x2",
	"profile 0 dscp 38 0x2",
	"profile 0 dscp 39 0x2",
	"profile 0 dscp 40 0x1",
	"profile 0 dscp 41 0x6",
	"profile 0 dscp 42 0x6",
	"profile 0 dscp 43 0x6",
	"profile 0 dscp 44 0x6",
	"profile 0 dscp 45 0x6",
	"profile 0 dscp 46 0x1",
	"profile 0 dscp 47 0x1",
	"profile 0 dscp 48 0x1",
	"profile 0 dscp 49 0x6",
	"profile 0 dscp 50 0x6",
	"profile 0 dscp 51 0x6",
	"profile 0 dscp 52 0x6",
	"profile 0 dscp 53 0x6",
	"profile 0 dscp 54 0x6",
	"profile 0 dscp 55 0x6",
	"profile 0 dscp 56 0x0",
	"profile 0 dscp 57 0x6",
	"profile 0 dscp 58 0x6",
	"profile 0 dscp 59 0x6",
	"profile 0 dscp 60 0x6",
	"profile 0 dscp 61 0x6",
	"profile 0 dscp 62 0x6",
	"profile 0 dscp 63 0x6",
	"profile 0 queue 0 wrr-weight 1 0",
	"profile 0 queue 0x1 wrr-weight 1 4",
	"profile 0 queue 0x2 wrr-weight 60 8",
	"profile 0 queue 0x6 wrr-weight 40 9",
	"profile 1 rate 250000 msec 4 period 10000",  // size = 1000 (1540 MTU)
	"profile 1 queue 0 rate 250000 size 1000", // size N/A
	"profile 1 queue 1 rate 250000 size 1000", // size N/A
	"profile 1 queue 2 rate 250000 size 1000", // size N/A
	"profile 1 queue 3 rate 250000 size 1000", // size N/A
	"pipe 0 0 3",
	"subport 1 rate 1250000000 size 100000 period 40000",
	"subport 1 queue 0 rate 1250000000 size 100000", // size N/A
	"subport 1 queue 1 rate 1250000000 size 100000", // size N/A
	"subport 1 queue 2 rate 1250000000 size 100000", // size N/A
	"subport 1 queue 3 rate 1250000000 size 100000", // size N/A
	"subport 1 mark-map hw-egress-map",
	"vlan 10 1",
	"pipe 1 0 1",
	"pipe 1 1 0",
	"subport 2 rate 1250000000 size 100000 period 40000",
	"subport 2 queue 0 rate 1250000000 size 100000", // size N/A
	"subport 2 queue 1 rate 1250000000 size 100000", // size N/A
	"subport 2 queue 2 rate 1250000000 size 100000", // size N/A
	"subport 2 queue 3 rate 1250000000 size 100000", // size N/A
	"subport 2 mark-map hw-egress-map",
	"vlan 20 2",
	"pipe 2 0 1",
	"pipe 2 1 0",
	"enable"
};

uint8_t hw_dot1p_map[] = {
     /* 0  1  2  3  4  5  6  7  8  9 */
	1, 1, 1, 1, 1, 1, 1, 1, 2, 1,   /* DSCP 0-9 */
	2, 1, 1, 1, 1, 1, 2, 1, 2, 1,   /* DSCP 10-19 */
	1, 1, 1, 1, 4, 3, 4, 3, 3, 3,   /* DSCP 20-29 */
	3, 3, 4, 3, 4, 3, 3, 3, 3, 3,   /* DSCP 30-39 */
	5, 1, 1, 1, 1, 1, 5, 5, 5, 1,   /* DSCP 40-49 */
	1, 1, 1, 1, 1, 1, 7, 1, 1, 1,   /* DSCP 50-59 */
	1, 1, 1, 1                      /* DSCP 60-63 */
};

struct des_dp_pair hw_dscp_map[] = {
	/* des drop-precedence */
	{ 0, 0 },   /* DSCP = 0 */
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },   /* DSCP = 15 */
	{ 0, 0 },   /* DSCP = 16 */
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },   /* DSCP = 31 */
	{ 1, 0 },   /* DSCP = 32 */
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 2, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 2, 0 },
	{ 2, 0 },   /* DSCP = 47 */
	{ 2, 0 },   /* DSCP = 48 */
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 3, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 }    /* DSCP = 63 */
};

struct qos_fal_ut_sched_group_result {
	/* identifiers */
	uint32_t level;
	const char *ifname;
	uint32_t subport;
	uint32_t pipe;
	uint32_t tc;
	/* sched-group expected results */
	uint32_t max_children;
	uint32_t current_children;
	/* associated scheduler expected results */
	const char *sched_type;
	uint32_t weight;
	uint64_t max_bandwidth;
	uint32_t max_burst;
	int8_t overhead;
};

static struct qos_fal_ut_sched_group_result hw_poc_sched_group_results[] = {
	/* ----identifiers----  sched-group  --------scheduler------- */
	{ 1, "dp2T1", 0, 0, 0,    3, 3,     "Weighted Round-Robin", 1,
	  1250000000, 0, 22 },
	{ 2, "dp2T1", 0, 0, 0,    1, 1,     "Weighted Round-Robin", 1,
	  1250000000, 130048, 22 },
	{ 3, "dp2T1", 0, 0, 0,    4, 4,     "Strict Priority", -1,
	  250000, 5000, 22 },
	{ 4, "dp2T1", 0, 0, 0,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 5000, 22 },
	{ 4, "dp2T1", 0, 0, 1,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 5000, 22 },
	{ 4, "dp2T1", 0, 0, 2,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 5000, 22 },
	{ 4, "dp2T1", 0, 0, 3,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 5000, 22 },
	{ 2, "dp2T1", 1, 0, 0,    2, 2,     "Weighted Round-Robin", 1,
	  1250000000, 100000, 22 },
	{ 3, "dp2T1", 1, 0, 0,    4, 4,     "Strict Priority", -1,
	  250000, 1540, 22 },
	{ 4, "dp2T1", 1, 0, 0,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 1540, 22 },
	{ 4, "dp2T1", 1, 0, 1,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 1540, 22 },
	{ 4, "dp2T1", 1, 0, 2,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 1540, 22 },
	{ 4, "dp2T1", 1, 0, 3,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 1540, 22 },
	{ 3, "dp2T1", 1, 1, 0,    4, 3,     "Strict Priority", -1,
	  6250000, 30000, 22 },
	{ 4, "dp2T1", 1, 1, 0,    1, 1,     "Weighted Round-Robin", 1,
	  3125000, 30000, 22 },
	{ 4, "dp2T1", 1, 1, 1,    1, 1,     "Weighted Round-Robin", 1,
	  3125000, 30000, 22 },
	{ 4, "dp2T1", 1, 1, 2,    2, 2,     "Weighted Round-Robin", 1,
	  6250000, 30000, 22 },
	{ 2, "dp2T1", 2, 0, 0,    2, 2,     "Weighted Round-Robin", 1,
	  1250000000, 100000, 22 },
	{ 3, "dp2T1", 2, 0, 0,    4, 4,     "Strict Priority", -1,
	  250000, 1540, 22 },
	{ 4, "dp2T1", 2, 0, 0,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 1540, 22 },
	{ 4, "dp2T1", 2, 0, 1,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 1540, 22 },
	{ 4, "dp2T1", 2, 0, 2,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 1540, 22 },
	{ 4, "dp2T1", 2, 0, 3,    1, 1,     "Weighted Round-Robin", 1,
	  250000, 1540, 22 },
	{ 3, "dp2T1", 2, 1, 0,    4, 3,     "Strict Priority", -1,
	  6250000, 30000, 22 },
	{ 4, "dp2T1", 2, 1, 0,    1, 1,     "Weighted Round-Robin", 1,
	  3125000, 30000, 22 },
	{ 4, "dp2T1", 2, 1, 1,    1, 1,     "Weighted Round-Robin", 1,
	  3125000, 30000, 22 },
	{ 4, "dp2T1", 2, 1, 2,    2, 2,     "Weighted Round-Robin", 1,
	  6250000, 30000, 22 },
};

struct qos_fal_ut_map_results {
	/* identifiers */
	const char *ifname;
	uint32_t subport;
	uint32_t pipe;
	/* expected results */
	uint32_t ingress_map_type;
	struct des_dp_pair *ingress_map_list;
	uint32_t egress_map_type;
	uint8_t *egress_map_list;
};

static struct qos_fal_ut_map_results hw_poc_map_results[] = {
	/* identifiers  | results */
	{ "dp2T1", 0, 0, FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR, default_dscp_map,
			 0, NULL },
	{ "dp2T1", 1, 0, FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR, default_dscp_map,
			 FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P, hw_dot1p_map },
	{ "dp2T1", 1, 1, FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR, hw_dscp_map,
			 FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P, hw_dot1p_map },
	{ "dp2T1", 2, 0, FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR, default_dscp_map,
			 FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P, hw_dot1p_map },
	{ "dp2T1", 2, 1, FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR, hw_dscp_map,
			 FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P, hw_dot1p_map },
};

struct qos_fal_ut_queue_results {
	/* identifiers */
	uint32_t subport;
	uint32_t pipe;
	uint32_t tc;
	uint32_t queue;
	/* expected results */
	uint32_t queue_limit;
	uint32_t weight;
};

static struct qos_fal_ut_queue_results hw_poc_queue_results[] = {
	/* identifiers | results */
	{  0, 0, 0, 0,   512,  1 },
	{  0, 0, 1, 0,  1024,  1 },
	{  0, 0, 2, 0,  1024,  1 },
	{  0, 0, 3, 0,     1,  1 },
	{  1, 0, 0, 0,   512,  1 },
	{  1, 0, 1, 0,  1024,  1 },
	{  1, 0, 2, 0,  1024,  1 },
	{  1, 0, 3, 0,     1,  1 },
	{  2, 0, 0, 0,   512,  1 },
	{  2, 0, 1, 0,  1024,  1 },
	{  2, 0, 2, 0,  1024,  1 },
	{  2, 0, 3, 0,     1,  1 },
	{  2, 1, 0, 0,   512,  1 },
	{  2, 1, 1, 0,  1024,  1 },
	{  2, 1, 2, 0,  1024, 60 },
	{  2, 1, 2, 1,  1024, 40 }
};

DP_START_TEST(qos_fal_basic, fal_said_poc)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	json_object *j_sched_obj;
	json_object *j_map_obj;
	json_object *j_obj;
	const char *ifname;
	uint32_t level;
	uint32_t subport;
	uint32_t pipe;
	uint32_t tc;
	uint32_t queue;
	uint32_t queue_limit;
	uint32_t weight;
	uint32_t i;
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	/* Add NPF config */
	for (i = 0; i < ARRAY_SIZE(fal_hw_npf_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_hw_npf_cmds[i]);

	/* Add QoS global config */
	for (i = 0; i < ARRAY_SIZE(fal_hw_qos_glb_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_hw_qos_glb_cmds[i]);

	/* Add QoS interface config */
	dp_test_qos_attach_config_to_if("dp2T1", fal_hw_qos_cmds, debug);

	/*
	 * Start of the hardware configuration verification checks.
	 * Check the hierarchy of sched-group objects and their associated
	 * scheduler objects.
	 */
	for (i = 0; i < ARRAY_SIZE(hw_poc_sched_group_results); i++) {
		uint32_t max_children;
		uint32_t current_children;
		const char *sched_type;
		uint64_t max_bandwidth;
		uint32_t max_burst;
		int8_t overhead;

		/* Get the identifiers */
		level = hw_poc_sched_group_results[i].level;
		ifname = hw_poc_sched_group_results[i].ifname;
		subport = hw_poc_sched_group_results[i].subport;
		pipe = hw_poc_sched_group_results[i].pipe;
		tc = hw_poc_sched_group_results[i].tc;

		/* Get the expected results */
		max_children = hw_poc_sched_group_results[i].max_children;
		current_children =
			hw_poc_sched_group_results[i].current_children;
		sched_type = hw_poc_sched_group_results[i].sched_type;
		weight = hw_poc_sched_group_results[i].weight;
		max_bandwidth = hw_poc_sched_group_results[i].max_bandwidth;
		max_burst = hw_poc_sched_group_results[i].max_burst;
		overhead = hw_poc_sched_group_results[i].overhead;

		j_obj = dp_test_qos_hw_get_json_sched_group(level, ifname,
							    subport, pipe, tc,
							    debug);

		dp_test_qos_hw_check_sched_group(j_obj, level, max_children,
						 current_children, 0, debug);

		j_sched_obj = dp_test_qos_hw_get_json_child(j_obj, "scheduler",
							    debug);
		if (level == FAL_QOS_SCHED_GROUP_LEVEL_QUEUE)
			overhead = -1;
		dp_test_qos_hw_check_scheduler(j_sched_obj, sched_type,
					       "Bytes Per Second", weight,
					       max_bandwidth, max_burst,
					       overhead, debug);
		json_object_put(j_sched_obj);
		json_object_put(j_obj);
	}

	/*
	 * Check that the pipe-level sched-group objects have the correct
	 * mapping-tables.
	 */
	for (i = 0; i < ARRAY_SIZE(hw_poc_map_results); i++) {
		uint32_t map_type;
		uint8_t *egress_map_list;

		/* Get the identifiers */
		level = FAL_QOS_SCHED_GROUP_LEVEL_PIPE;
		ifname = hw_poc_map_results[i].ifname;
		subport = hw_poc_map_results[i].subport;
		pipe = hw_poc_map_results[i].pipe;

		j_obj = dp_test_qos_hw_get_json_sched_group(level, ifname,
							    subport, pipe, 0,
							    debug);

		/* Get the expected egress map results */
		map_type = hw_poc_map_results[i].egress_map_type;
		egress_map_list = hw_poc_map_results[i].egress_map_list;
		if (egress_map_list != NULL) {
			j_map_obj = dp_test_qos_hw_get_json_child(j_obj,
								  "egress-map",
								  debug);
			dp_test_qos_hw_check_egress_map(j_map_obj, map_type,
							egress_map_list, debug);
			json_object_put(j_map_obj);
		}

		json_object_put(j_obj);
	}

	/*
	 * Finally check that the queues that are the leaves of the
	 * scheduling hierarchy have all the expected values.
	 */
	for (i = 0; i < ARRAY_SIZE(hw_poc_queue_results); i++) {
		subport = hw_poc_queue_results[i].subport;
		pipe = hw_poc_queue_results[i].pipe;
		tc = hw_poc_queue_results[i].tc;
		queue = hw_poc_queue_results[i].queue;
		queue_limit = hw_poc_queue_results[i].queue_limit;
		weight = hw_poc_queue_results[i].weight;

		j_obj = dp_test_qos_hw_get_json_queue("dp2T1", subport, pipe,
						      tc, queue, debug);
		dp_test_qos_hw_check_queue(j_obj, queue, queue_limit, queue,
					   0, debug);

		j_sched_obj = dp_test_qos_hw_get_json_child(j_obj, "scheduler",
							    debug);
		dp_test_qos_hw_check_scheduler(j_sched_obj,
					       "Weighted Round-Robin",
					       "Bytes Per Second", weight, 0,
					       0, 0, debug);
		json_object_put(j_sched_obj);
		json_object_put(j_obj);
	}

	/* QoS cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	for (i = 0; i < ARRAY_SIZE(fal_hw_qos_glb_delete_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_hw_qos_glb_delete_cmds[i]);

	/* NPF cleanup */
	for (i = 0; i < ARRAY_SIZE(fal_hw_npf_delete_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_hw_npf_delete_cmds[i]);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	/* Cleanup the ports */
	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();
} DP_END_TEST;

/*
 * fal_local_priority_cmds created from:
 *
 *   set interfaces dataplane dp0s5 policy qos 'policy-3'
 *   set policy qos name policy-3 shaper bandwidth '1Gbit'
 *   set policy qos name policy-3 shaper default 'profile-1'
 *   set policy qos name policy-3 shaper profile profile-1 queue 31
 *       'priority-local'
 *   set policy qos name policy-3 shaper profile profile-1 queue 31
 *       traffic-class '1'
 */

const char *fal_local_priority_cmds[] = {
	"port subports 1 pipes 1 profiles 1 overhead 24 ql_bytes",
	"subport 0 rate 125000000 size 50000 period 40000",
	"subport 0 queue 0 rate 125000000 size 50000",
	"subport 0 queue 1 rate 125000000 size 50000",
	"subport 0 queue 2 rate 125000000 size 50000",
	"subport 0 queue 3 rate 125000000 size 50000",
	"vlan 0 0",
	"profile 0 rate 125000000 size 50000 period 10000",
	"profile 0 queue 0 rate 125000000 size 50000",
	"profile 0 queue 1 rate 125000000 size 50000",
	"profile 0 queue 2 rate 125000000 size 50000",
	"profile 0 queue 3 rate 125000000 size 50000",
	"profile 0 queue 0x5 wrr-weight 1 31 prio-loc",
	"pipe 0 0 0",
	"enable"
};

DP_START_TEST(qos_fal_basic, fal_local_priority_queue)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	json_object *j_obj;
	uint32_t level;
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	/* Add QoS config */
	dp_test_qos_attach_config_to_if("dp2T1", fal_local_priority_cmds,
					debug);

	/*
	 * Test verification code here - check that the ingress map has
	 * its local-priority queue set.
	 */
	level = FAL_QOS_SCHED_GROUP_LEVEL_PIPE;
	j_obj = dp_test_qos_hw_get_json_sched_group(level, "dp2T1", 0, 0, 0,
						    debug);
	dp_test_qos_hw_check_sched_group(j_obj, level, 4, 4, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 0, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 1, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 1, 1, debug);
	dp_test_qos_hw_check_queue(j_obj, 1, 64, 1, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 2, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 3, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	/* QoS cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	/* Cleanup the ports */
	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();
} DP_END_TEST;

/*
 * fal_egress_map_npf_cmds and fal_egress_map_qos_cmds created from:
 *
 *   set resources group dscp-group dscp7-0 dscp 0
 *   set resources group dscp-group dscp7-0 dscp 1
 *   set resources group dscp-group dscp7-0 dscp 2
 *   set resources group dscp-group dscp7-0 dscp 3
 *   set resources group dscp-group dscp7-0 dscp 4
 *   set resources group dscp-group dscp7-0 dscp 5
 *   set resources group dscp-group dscp7-0 dscp 6
 *   set resources group dscp-group dscp7-0 dscp 7
 *   set resources group dscp-group dscp15-8 dscp 8
 *   set resources group dscp-group dscp15-8 dscp 9
 *   set resources group dscp-group dscp15-8 dscp 10
 *   set resources group dscp-group dscp15-8 dscp 11
 *   set resources group dscp-group dscp15-8 dscp 12
 *   set resources group dscp-group dscp15-8 dscp 13
 *   set resources group dscp-group dscp15-8 dscp 14
 *   set resources group dscp-group dscp15-8 dscp 15
 *   set resources group dscp-group dscp23-16 dscp 16
 *   set resources group dscp-group dscp23-16 dscp 17
 *   set resources group dscp-group dscp23-16 dscp 18
 *   set resources group dscp-group dscp23-16 dscp 19
 *   set resources group dscp-group dscp23-16 dscp 20
 *   set resources group dscp-group dscp23-16 dscp 21
 *   set resources group dscp-group dscp23-16 dscp 22
 *   set resources group dscp-group dscp23-16 dscp 23
 *   set resources group dscp-group dscp31-24 dscp 24
 *   set resources group dscp-group dscp31-24 dscp 25
 *   set resources group dscp-group dscp31-24 dscp 26
 *   set resources group dscp-group dscp31-24 dscp 27
 *   set resources group dscp-group dscp31-24 dscp 28
 *   set resources group dscp-group dscp31-24 dscp 29
 *   set resources group dscp-group dscp31-24 dscp 30
 *   set resources group dscp-group dscp31-24 dscp 31
 *   set resources group dscp-group dscp39-32 dscp 32
 *   set resources group dscp-group dscp39-32 dscp 33
 *   set resources group dscp-group dscp39-32 dscp 34
 *   set resources group dscp-group dscp39-32 dscp 35
 *   set resources group dscp-group dscp39-32 dscp 36
 *   set resources group dscp-group dscp39-32 dscp 37
 *   set resources group dscp-group dscp39-32 dscp 38
 *   set resources group dscp-group dscp39-32 dscp 39
 *   set resources group dscp-group dscp47-40 dscp 40
 *   set resources group dscp-group dscp47-40 dscp 41
 *   set resources group dscp-group dscp47-40 dscp 42
 *   set resources group dscp-group dscp47-40 dscp 43
 *   set resources group dscp-group dscp47-40 dscp 44
 *   set resources group dscp-group dscp47-40 dscp 45
 *   set resources group dscp-group dscp47-40 dscp 46
 *   set resources group dscp-group dscp47-40 dscp 47
 *   set resources group dscp-group dscp55-48 dscp 48
 *   set resources group dscp-group dscp55-48 dscp 49
 *   set resources group dscp-group dscp55-48 dscp 50
 *   set resources group dscp-group dscp55-48 dscp 51
 *   set resources group dscp-group dscp55-48 dscp 52
 *   set resources group dscp-group dscp55-48 dscp 53
 *   set resources group dscp-group dscp55-48 dscp 54
 *   set resources group dscp-group dscp55-48 dscp 55
 *   set resources group dscp-group dscp63-56 dscp 56
 *   set resources group dscp-group dscp63-56 dscp 57
 *   set resources group dscp-group dscp63-56 dscp 58
 *   set resources group dscp-group dscp63-56 dscp 59
 *   set resources group dscp-group dscp63-56 dscp 60
 *   set resources group dscp-group dscp63-56 dscp 61
 *   set resources group dscp-group dscp63-56 dscp 62
 *   set resources group dscp-group dscp63-56 dscp 63
 *
 *   set policy qos mark-map egress-pcp-map dscp-group dscp63-56 pcp-mark 7
 *   set policy qos mark-map egress-pcp-map dscp-group dscp55-48 pcp-mark 6
 *   set policy qos mark-map egress-pcp-map dscp-group dscp47-40 pcp-mark 5
 *   set policy qos mark-map egress-pcp-map dscp-group dscp39-32 pcp-mark 4
 *   set policy qos mark-map egress-pcp-map dscp-group dscp31-24 pcp-mark 3
 *   set policy qos mark-map egress-pcp-map dscp-group dscp23-16 pcp-mark 2
 *   set policy qos mark-map egress-pcp-map dscp-group dscp15-8 pcp-mark 1
 *   set policy qos mark-map egress-pcp-map dscp-group dscp7-0 pcp-mark 0
 *
 *   set policy qos name trunk-policy shaper default profile-1
 *   set policy qos name trunk-policy shaper profile profile-1 bandwidth 100Mbit
 *   set interface dataplane dp0s5 policy qos trunk-policy
 *
 *   set policy qos name vlan-policy shaper mark-map egress-pcp-map
 *   set policy qos name vlan-policy shaper profile profile-2 bandwidth 200Mbit
 *   set policy qos name vlan-policy shaper default profile-2
 *   set interface dataplane dp0s5 vif 10 policy qos vlan-policy
 */

const char *fal_egress_map_npf_cmds[] = {
	"npf-cfg add dscp-group:dscp7-0 0 0;1;2;3;4;5;6;7",
	"npf-cfg add dscp-group:dscp15-8 0 8;9;10;11;12;13;14;15",
	"npf-cfg add dscp-group:dscp23-16 0 16;17;18;19;20;21;22;23",
	"npf-cfg add dscp-group:dscp31-24 0 24;25;26;27;28;29;30;31",
	"npf-cfg add dscp-group:dscp39-32 0 32;33;34;35;36;37;38;39",
	"npf-cfg add dscp-group:dscp47-40 0 40;41;42;43;44;45;46;47",
	"npf-cfg add dscp-group:dscp55-48 0 48;49;50;51;52;53;54;55",
	"npf-cfg add dscp-group:dscp63-56 0 56;57;58;59;60;61;62;63",
	"npf-cfg commit"
};

const char *fal_egress_map_npf_delete_cmds[] = {
	"npf-cfg delete dscp-group:dscp7-0",
	"npf-cfg delete dscp-group:dscp15-8",
	"npf-cfg delete dscp-group:dscp23-16",
	"npf-cfg delete dscp-group:dscp31-24",
	"npf-cfg delete dscp-group:dscp39-32",
	"npf-cfg delete dscp-group:dscp47-40",
	"npf-cfg delete dscp-group:dscp55-48",
	"npf-cfg delete dscp-group:dscp63-56",
	"npf-cfg commit"
};

const char *fal_egress_map_qos_glb_cmds[] = {
	"qos global-object-cmd mark-map egress-pcp-map dscp-group dscp7-0 pcp 0",
	"qos global-object-cmd mark-map egress-pcp-map dscp-group dscp15-8 pcp 1",
	"qos global-object-cmd mark-map egress-pcp-map dscp-group dscp23-16 pcp 2",
	"qos global-object-cmd mark-map egress-pcp-map dscp-group dscp31-24 pcp 3",
	"qos global-object-cmd mark-map egress-pcp-map dscp-group dscp39-32 pcp 4",
	"qos global-object-cmd mark-map egress-pcp-map dscp-group dscp47-40 pcp 5",
	"qos global-object-cmd mark-map egress-pcp-map dscp-group dscp55-48 pcp 6",
	"qos global-object-cmd mark-map egress-pcp-map dscp-group dscp63-56 pcp 7"
};

const char *fal_egress_map_qos_glb_delete_cmds[] = {
	"qos global-object-cmd mark-map egress-pcp-map delete"
};

const char *fal_egress_map_qos_int_cmds[] = {
	"port subports 2 pipes 1 profiles 2 overhead 24 ql_bytes",
	"subport 0 rate 1250000000 size 100000 period 40000",
	"subport 0 queue 0 rate 1250000000 size 100000",
	"subport 0 queue 1 rate 1250000000 size 100000",
	"subport 0 queue 2 rate 1250000000 size 100000",
	"subport 0 queue 3 rate 1250000000 size 100000",
	"vlan 0 0",
	"profile 0 rate 12500000 size 50000 period 10000",
	"profile 0 queue 0 rate 12500000 size 50000",
	"profile 0 queue 1 rate 12500000 size 50000",
	"profile 0 queue 2 rate 12500000 size 50000",
	"profile 0 queue 3 rate 12500000 size 50000",
	"pipe 0 0 0",
	"subport 1 rate 1250000000 size 100000 period 40000",
	"subport 1 queue 0 rate 1250000000 size 100000",
	"subport 1 queue 1 rate 1250000000 size 100000",
	"subport 1 queue 2 rate 1250000000 size 100000",
	"subport 1 queue 3 rate 1250000000 size 100000",
	"subport 1 mark-map egress-pcp-map",
	"vlan 10 1",
	"profile 1 rate 25000000 size 100000 period 10000",
	"profile 1 queue 0 rate 25000000 size 100000",
	"profile 1 queue 1 rate 25000000 size 100000",
	"profile 1 queue 2 rate 25000000 size 100000",
	"profile 1 queue 3 rate 25000000 size 100000",
	"pipe 1 0 1",
	"enable"
};

int8_t fal_egress_map_expected_pcp_values[] = {
	0, 0, 0, 0, 0, 0, 0, 0,   /* DSCP 0-7 */
	1, 1, 1, 1, 1, 1, 1, 1,   /* DSCP 8-15 */
	2, 2, 2, 2, 2, 2, 2, 2,   /* DSCP 16-23 */
	3, 3, 3, 3, 3, 3, 3, 3,   /* DSCP 24-31 */
	4, 4, 4, 4, 4, 4, 4, 4,   /* DSCP 32-39 */
	5, 5, 5, 5, 5, 5, 5, 5,   /* DSCP 40-47 */
	6, 6, 6, 6, 6, 6, 6, 6,   /* DSCP 48-55 */
	7, 7, 7, 7, 7, 7, 7, 7    /* DSCP 56-63 */
};

DP_START_TEST(qos_fal_basic, fal_egress_map)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	uint32_t i;
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	/* Add NPF config */
	for (i = 0; i < ARRAY_SIZE(fal_egress_map_npf_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_egress_map_npf_cmds[i]);

	/* Add QoS config */
	for (i = 0; i < ARRAY_SIZE(fal_egress_map_qos_glb_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_egress_map_qos_glb_cmds[i]);

	dp_test_qos_attach_config_to_if("dp2T1", fal_egress_map_qos_int_cmds,
					debug);

	/*
	 * Test verification code here
	 */
	dp_test_qos_check_mark_map("egress-pcp-map",
				   fal_egress_map_expected_pcp_values,
				   debug);

	/* QoS cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	for (i = 0; i < ARRAY_SIZE(fal_egress_map_qos_glb_delete_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_egress_map_qos_glb_delete_cmds[i]);

	/* NPF cleanup */
	for (i = 0; i < ARRAY_SIZE(fal_egress_map_npf_delete_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_egress_map_npf_delete_cmds[i]);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	/* Cleanup the ports */
	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();
} DP_END_TEST;

/*
 * fal_egress_map_cmds and fal_egress_map_qos_cmds2 created from:
 *
 *   set policy qos mark-map des-mark designation 0 drop-precedence green
 *       pcp-mark 7
 *   set policy qos mark-map des-mark designation 0 drop-precedence yellow
 *       pcp-mark 7
 *   set policy qos mark-map des-mark designation 0 drop-precedence red
 *       pcp-mark 7
 *   set policy qos mark-map des-mark designation 1 drop-precedence green
 *       pcp-mark  6
 *   set policy qos mark-map des-mark designation 2 drop-precedence green
 *       pcp-mark  5
 *   set policy qos mark-map des-mark designation 3 drop-precedence green
 *       pcp-mark  4
 *   set policy qos mark-map des-mark designation 4 drop-precedence green
 *       pcp-mark  3
 *   set policy qos mark-map des-mark designation 5 drop-precedence green
 *       pcp-mark 2
 *   set policy qos mark-map des-mark designation 5 drop-precedence yellow
 *       pcp-mark 2
 *   set policy qos mark-map des-mark designation 6 drop-precedence green
 *       pcp-mark 1
 *   set policy qos mark-map des-mark designation 7 drop-precedence green
 *       pcp-mark 0
 *
 *   set policy qos name trunk-policy shaper default profile-1
 *   set policy qos name trunk-policy shaper profile profile-1 bandwidth 100Mbit
 *   set interface dataplane dp0s5 policy qos trunk-policy
 *
 *   set policy qos name vlan-policy shaper mark-map des-mark
 *   set policy qos name vlan-policy shaper profile profile-2 bandwidth 200Mbit
 *   set policy qos name vlan-policy shaper default profile-2
 *   set interface dataplane dp0s5 vif 10 policy qos vlan-policy
 */

const char *fal_egress_map_qos_glb_cmds2[] = {
	"qos global-object-cmd mark-map des-mark designation 0 drop-prec green pcp 7",
	"qos global-object-cmd mark-map des-mark designation 0 drop-prec yellow pcp 7",
	"qos global-object-cmd mark-map des-mark designation 0 drop-prec red pcp 7",
	"qos global-object-cmd mark-map des-mark designation 1 drop-prec green pcp 6",
	"qos global-object-cmd mark-map des-mark designation 2 drop-prec green pcp 5",
	"qos global-object-cmd mark-map des-mark designation 3 drop-prec green pcp 4",
	"qos global-object-cmd mark-map des-mark designation 4 drop-prec green pcp 3",
	"qos global-object-cmd mark-map des-mark designation 5 drop-prec green pcp 2",
	"qos global-object-cmd mark-map des-mark designation 5 drop-prec yellow pcp 2",
	"qos global-object-cmd mark-map des-mark designation 6 drop-prec green pcp 1",
	"qos global-object-cmd mark-map des-mark designation 7 drop-prec green pcp 0",
};

const char *fal_egress_map_qos_glb_delete_cmds2[] = {
	"qos global-object-cmd mark-map des-mark delete"
};

const char *fal_egress_map_qos_int_cmds2[] = {
	"port subports 2 pipes 1 profiles 2 overhead 24 ql_bytes",
	"subport 0 rate 1250000000 size 100000 period 40000",
	"subport 0 queue 0 rate 1250000000 size 100000",
	"subport 0 queue 1 rate 1250000000 size 100000",
	"subport 0 queue 2 rate 1250000000 size 100000",
	"subport 0 queue 3 rate 1250000000 size 100000",
	"vlan 0 0",
	"profile 0 rate 12500000 size 50000 period 10000",
	"profile 0 queue 0 rate 12500000 size 50000",
	"profile 0 queue 1 rate 12500000 size 50000",
	"profile 0 queue 2 rate 12500000 size 50000",
	"profile 0 queue 3 rate 12500000 size 50000",
	"pipe 0 0 0",
	"subport 1 rate 1250000000 size 100000 period 40000",
	"subport 1 queue 0 rate 1250000000 size 100000",
	"subport 1 queue 1 rate 1250000000 size 100000",
	"subport 1 queue 2 rate 1250000000 size 100000",
	"subport 1 queue 3 rate 1250000000 size 100000",
	"subport 1 mark-map des-mark",
	"vlan 10 1",
	"profile 1 rate 25000000 size 100000 period 10000",
	"profile 1 queue 0 rate 25000000 size 100000",
	"profile 1 queue 1 rate 25000000 size 100000",
	"profile 1 queue 2 rate 25000000 size 100000",
	"profile 1 queue 3 rate 25000000 size 100000",
	"pipe 1 0 1",
	"enable"
};

int8_t fal_egress_map_expected_pcp_values2[] = {
						/* designation 0-7  x dp 0-2*/
						7, 7, 7,
						6, 0, 0,
						5, 0, 0,
						4, 0, 0,
						3, 0, 0,
						2, 2, 0,
						1, 0, 0,
						0, 0, 0,
};

DP_START_TEST(qos_fal_basic, fal_egress_map2)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	uint32_t i;
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	/* Add QoS config */
	for (i = 0; i < ARRAY_SIZE(fal_egress_map_qos_glb_cmds2); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_egress_map_qos_glb_cmds2[i]);

	dp_test_qos_attach_config_to_if("dp2T1", fal_egress_map_qos_int_cmds2,
					debug);

	/*
	 * Test verification code here
	 */
	dp_test_qos_check_mark_map("des-mark",
				   fal_egress_map_expected_pcp_values2,
				   debug);

	/* QoS cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	for (i = 0; i < ARRAY_SIZE(fal_egress_map_qos_glb_delete_cmds2); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_egress_map_qos_glb_delete_cmds2[i]);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	/* Cleanup the ports */
	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();
} DP_END_TEST;

/*
 * fal_egress_map_cmds and fal_egress_map_qos_cmds2 created from:
 *
 *   set policy qos mark-map des-mark designation 0 drop-precedence green
 *       pcp-mark 2
 *   set policy qos mark-map des-mark designation 3 drop-precedence yellow
 *       pcp-mark 4
 *   set policy qos mark-map des-mark designation 6 drop-precedence red
 *       pcp-mark 7
 *
 *   set policy qos name trunk-policy shaper default profile-1
 *   set policy qos name trunk-policy shaper profile profile-1 bandwidth 100Mbit
 *   set interface dataplane dp0s5 policy qos trunk-policy
 *
 *   set policy qos name vlan-policy shaper mark-map des-mark
 *   set policy qos name vlan-policy shaper profile profile-2 bandwidth 200Mbit
 *   set policy qos name vlan-policy shaper default profile-2
 *   set interface dataplane dp0s5 vif 10 policy qos vlan-policy
 */

const char *fal_egress_map_qos_glb_cmds3[] = {
	"qos global-object-cmd mark-map des-mark designation 0 drop-prec green pcp 2",
	"qos global-object-cmd mark-map des-mark designation 3 drop-prec yellow pcp 4",
	"qos global-object-cmd mark-map des-mark designation 6 drop-prec red pcp 7",
};

int8_t fal_egress_map_expected_pcp_values3[] = {
						/*
						 * des/dp
						 * 0/green,
						 * 3/yellow,
						 * 6/red
						 */
						2, 0, 0,
						0, 0, 0,
						0, 0, 0,
						0, 4, 0,
						0, 0, 0,
						0, 0, 0,
						0, 0, 7,
						0, 0, 0,
};

DP_START_TEST(qos_fal_basic, fal_egress_map3)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	uint32_t i;
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	/* Add QoS config */
	for (i = 0; i < ARRAY_SIZE(fal_egress_map_qos_glb_cmds3); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_egress_map_qos_glb_cmds3[i]);

	dp_test_qos_attach_config_to_if("dp2T1", fal_egress_map_qos_int_cmds2,
					debug);

	/*
	 * Test verification code here
	 */
	dp_test_qos_check_mark_map("des-mark",
				   fal_egress_map_expected_pcp_values3,
				   debug);

	/* QoS cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	for (i = 0; i < ARRAY_SIZE(fal_egress_map_qos_glb_delete_cmds2); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_egress_map_qos_glb_delete_cmds2[i]);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	/* Cleanup the ports */
	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();
} DP_END_TEST;

/*
 * fal_wred_map_npf_cmds and fal_wred_map_qos_cmds created from:
 *
 *   set resources group dscp-group dscp-55-48 dscp 48
 *   set resources group dscp-group dscp-55-48 dscp 49
 *   set resources group dscp-group dscp-55-48 dscp 50
 *   set resources group dscp-group dscp-55-48 dscp 51
 *   set resources group dscp-group dscp-55-48 dscp 52
 *   set resources group dscp-group dscp-55-48 dscp 53
 *   set resources group dscp-group dscp-55-48 dscp 54
 *   set resources group dscp-group dscp-55-48 dscp 55
 *   set resources group dscp-group dscp-63-56 dscp 56
 *   set resources group dscp-group dscp-63-56 dscp 57
 *   set resources group dscp-group dscp-63-56 dscp 58
 *   set resources group dscp-group dscp-63-56 dscp 59
 *   set resources group dscp-group dscp-63-56 dscp 60
 *   set resources group dscp-group dscp-63-56 dscp 61
 *   set resources group dscp-group dscp-63-56 dscp 62
 *   set resources group dscp-group dscp-63-56 dscp 63
 *
 *   set policy qos name policy-1 shaper default profile-1
 *   set policy qos name policy-1 shaper profile profile-1 bandwidth 1Mbit
 *   set policy qos name policy-1 shaper profile profile-1 queue 0
 *       traffic-class 0
 *   set policy qos name policy-1 shaper profile profile-1 queue 0 wred-map
 *       dscp-group dscp-55-48 mark-probability 20
 *   set policy qos name policy-1 shaper profile profile-1 queue 0 wred-map
 *       dscp-group dscp-55-48 max-threshold 63
 *   set policy qos name policy-1 shaper profile profile-1 queue 0 wred-map
 *       dscp-group dscp-55-48 min-threshold 32
 *   set policy qos name policy-1 shaper profile profile-1 queue 0 wred-map
 *       dscp-group dscp-63-56 mark-probability 50
 *   set policy qos name policy-1 shaper profile profile-1 queue 0 wred-map
 *       dscp-group dscp-63-56 max-threshold 40
 *   set policy qos name policy-1 shaper profile profile-1 queue 0 wred-map
 *       dscp-group dscp-63-56 min-threshold 20
 *   set policy qos name policy-1 shaper profile profile-1 queue 0 wred-map
 *       filter-weight 5
 *   set interfaces dataplane dp0s5 policy qos policy-1
 */

const char *fal_wred_map_npf_cmds[] = {
	"npf-cfg delete dscp-group:dscp-55-48",
	"npf-cfg delete dscp-group:dscp-63-56",
	"npf-cfg add dscp-group:dscp-55-48 0 48,49,50,51,52,53,54,55",
	"npf-cfg add dscp-group:dscp-63-56 0 56,57,58,59,60,61,62,63",
	"npf-cfg commit",
};

const char *fal_wred_map_npf_delete_cmds[] = {
	"npf-cfg delete dscp-group:dscp-55-48",
	"npf-cfg delete dscp-group:dscp-63-56",
	"npf-cfg commit",
};

const char *fal_wred_map_qos_cmds[] = {
	"port subports 1 pipes 1 profiles 1 overhead 24 ql_bytes",
	"subport 0 rate 1250000000 size 100000 period 40000",
	"subport 0 queue 0 rate 1250000000 size 100000",
	"subport 0 queue 1 rate 1250000000 size 100000",
	"subport 0 queue 2 rate 1250000000 size 100000",
	"subport 0 queue 3 rate 1250000000 size 100000",
	"vlan 0 0",
	"profile 0 rate 125000 size 500 period 10000",
	"profile 0 queue 0 rate 125000 size 500",
	"profile 0 queue 1 rate 125000 size 500",
	"profile 0 queue 2 rate 125000 size 500",
	"profile 0 queue 3 rate 125000 size 500",
	"profile 0 dscp 0 0x3",
	"profile 0 dscp 1 0x3",
	"profile 0 dscp 2 0x3",
	"profile 0 dscp 3 0x3",
	"profile 0 dscp 4 0x3",
	"profile 0 dscp 5 0x3",
	"profile 0 dscp 6 0x3",
	"profile 0 dscp 7 0x3",
	"profile 0 dscp 8 0x3",
	"profile 0 dscp 9 0x3",
	"profile 0 dscp 10 0x3",
	"profile 0 dscp 11 0x3",
	"profile 0 dscp 12 0x3",
	"profile 0 dscp 13 0x3",
	"profile 0 dscp 14 0x3",
	"profile 0 dscp 15 0x3",
	"profile 0 dscp 16 0x2",
	"profile 0 dscp 17 0x2",
	"profile 0 dscp 18 0x2",
	"profile 0 dscp 19 0x2",
	"profile 0 dscp 20 0x2",
	"profile 0 dscp 21 0x2",
	"profile 0 dscp 22 0x2",
	"profile 0 dscp 23 0x2",
	"profile 0 dscp 24 0x2",
	"profile 0 dscp 25 0x2",
	"profile 0 dscp 26 0x2",
	"profile 0 dscp 27 0x2",
	"profile 0 dscp 28 0x2",
	"profile 0 dscp 29 0x2",
	"profile 0 dscp 30 0x2",
	"profile 0 dscp 31 0x2",
	"profile 0 dscp 32 0x1",
	"profile 0 dscp 33 0x1",
	"profile 0 dscp 34 0x1",
	"profile 0 dscp 35 0x1",
	"profile 0 dscp 36 0x1",
	"profile 0 dscp 37 0x1",
	"profile 0 dscp 38 0x1",
	"profile 0 dscp 39 0x1",
	"profile 0 dscp 40 0x1",
	"profile 0 dscp 41 0x1",
	"profile 0 dscp 42 0x1",
	"profile 0 dscp 43 0x1",
	"profile 0 dscp 44 0x1",
	"profile 0 dscp 45 0x1",
	"profile 0 dscp 46 0x1",
	"profile 0 dscp 47 0x1",
	"profile 0 dscp 48 0x0",
	"profile 0 dscp 49 0x0",
	"profile 0 dscp 50 0x0",
	"profile 0 dscp 51 0x0",
	"profile 0 dscp 52 0x0",
	"profile 0 dscp 53 0x0",
	"profile 0 dscp 54 0x0",
	"profile 0 dscp 55 0x0",
	"profile 0 dscp 56 0x20",
	"profile 0 dscp 57 0x20",
	"profile 0 dscp 58 0x20",
	"profile 0 dscp 59 0x20",
	"profile 0 dscp 60 0x20",
	"profile 0 dscp 61 0x20",
	"profile 0 dscp 62 0x20",
	"profile 0 dscp 63 0x20",
	"profile 0 queue 0 wrr-weight 1",
	"profile 0 queue 0 dscp-group dscp-55-48 bytes 630 320 20",
	"profile 0 queue 0 dscp-group dscp-63-56 bytes 400 200 50",
	"profile 0 queue 0 wred-weight 5",
	"pipe 0 0 0",
	"enable"
};

struct des_dp_pair wred_map_dscp_map[] = {
	/* des discard-index */
	{ 0, 0 },   /* DSCP = 0 */
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },
	{ 0, 0 },   /* DSCP = 15 */
	{ 1, 0 },   /* DSCP = 16 */
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },
	{ 1, 0 },   /* DSCP = 31 */
	{ 2, 0 },   /* DSCP = 32 */
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },
	{ 2, 0 },   /* DSCP = 47 */
	{ 3, 0 },   /* DSCP = 48 */
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },
	{ 3, 0 },   /* DSCP = 55 */
	{ 3, 1 },   /* DSCP = 56 */
	{ 3, 1 },
	{ 3, 1 },
	{ 3, 1 },
	{ 3, 1 },
	{ 3, 1 },
	{ 3, 1 },
	{ 3, 1 }    /* DSCP = 63 */
};

DP_START_TEST(qos_fal_basic, fal_wred_map)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	json_object *j_sched_obj;
	json_object *j_wred_obj;
	json_object *j_obj;
	uint32_t level;
	uint32_t subport = 0;    /* Only one subport with id = 0 */
	uint32_t pipe = 0;       /* Only one pipe with id = 0 */
	uint32_t i;
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	/* Add NPF config */
	i = 0;
	while (!strstr(fal_wred_map_npf_cmds[i], "npf-cfg commit")) {
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_wred_map_npf_cmds[i++]);
	}
	dp_test_send_config_src(dp_test_cont_src_get(), "%s",
				fal_wred_map_npf_cmds[i++]);

	/* Add QoS config */
	dp_test_qos_attach_config_to_if("dp2T1", fal_wred_map_qos_cmds, debug);

	/*
	 * Check the pipe-level, and in particular the map object
	 */
	level = FAL_QOS_SCHED_GROUP_LEVEL_PIPE;
	j_obj = dp_test_qos_hw_get_json_sched_group(level, "dp2T1", subport,
						    pipe, 0, debug);
	dp_test_qos_hw_check_sched_group(j_obj, level, 4, 4, 0, debug);
	j_sched_obj = dp_test_qos_hw_get_json_child(j_obj, "scheduler", debug);
	dp_test_qos_hw_check_scheduler(j_sched_obj, "Strict Priority",
				       "Bytes Per Second", -1, 125000, 1542,
				       24, debug);

	json_object_put(j_sched_obj);
	json_object_put(j_obj);

	/*
	 * Check that the one queue that has multiple wred-maps configured
	 * on it has all the expected values.
	 */
	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 0, 0, debug);

	j_wred_obj = dp_test_qos_hw_get_json_child(j_obj, "wred", debug);
	dp_test_qos_hw_check_wred_colour(j_wred_obj, "green", true, 320, 630,
					20, 5, debug);

	dp_test_qos_hw_check_wred_colour(j_wred_obj, "yellow", true, 200, 400,
					50, 5, debug);

	dp_test_qos_hw_check_wred_colour(j_wred_obj, "red", false, -1, -1, -1,
					 5, debug);

	json_object_put(j_wred_obj);
	json_object_put(j_obj);

	/* QoS cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	/* NPF cleanup */
	for (i = 0; i < ARRAY_SIZE(fal_wred_map_npf_delete_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_wred_map_npf_delete_cmds[i]);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	/* Cleanup the ports */
	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();
} DP_END_TEST;

/*
 * fal_hw_wred_map_npf_cmds and fal_hw_wred_map_qos_cmds created from:
 *
 *    set resources group dscp-group default-group-high-drop dscp 8
 *    set resources group dscp-group default-group-high-drop dscp 10
 *    set resources group dscp-group default-group-high-drop dscp 16
 *    set resources group dscp-group default-group-high-drop dscp 18
 *    set resources group dscp-group default-group-low-drop dscp 0
 *    set resources group dscp-group default-group-low-drop dscp 1
 *    set resources group dscp-group default-group-low-drop dscp 2
 *    set resources group dscp-group default-group-low-drop dscp 3
 *    set resources group dscp-group default-group-low-drop dscp 4
 *    set resources group dscp-group default-group-low-drop dscp 5
 *    set resources group dscp-group default-group-low-drop dscp 6
 *    set resources group dscp-group default-group-low-drop dscp 7
 *    set resources group dscp-group default-group-low-drop dscp 9
 *    set resources group dscp-group default-group-low-drop dscp 11
 *    set resources group dscp-group default-group-low-drop dscp 12
 *    set resources group dscp-group default-group-low-drop dscp 13
 *    set resources group dscp-group default-group-low-drop dscp 14
 *    set resources group dscp-group default-group-low-drop dscp 15
 *    set resources group dscp-group default-group-low-drop dscp 17
 *    set resources group dscp-group default-group-low-drop dscp 19
 *    set resources group dscp-group default-group-low-drop dscp 20
 *    set resources group dscp-group default-group-low-drop dscp 21
 *    set resources group dscp-group default-group-low-drop dscp 22
 *    set resources group dscp-group default-group-low-drop dscp 23
 *    set resources group dscp-group default-group-low-drop dscp 41
 *    set resources group dscp-group default-group-low-drop dscp 42
 *    set resources group dscp-group default-group-low-drop dscp 43
 *    set resources group dscp-group default-group-low-drop dscp 44
 *    set resources group dscp-group default-group-low-drop dscp 45
 *    set resources group dscp-group default-group-low-drop dscp 49
 *    set resources group dscp-group default-group-low-drop dscp 50
 *    set resources group dscp-group default-group-low-drop dscp 51
 *    set resources group dscp-group default-group-low-drop dscp 52
 *    set resources group dscp-group default-group-low-drop dscp 53
 *    set resources group dscp-group default-group-low-drop dscp 54
 *    set resources group dscp-group default-group-low-drop dscp 55
 *    set resources group dscp-group default-group-low-drop dscp 57
 *    set resources group dscp-group default-group-low-drop dscp 58
 *    set resources group dscp-group default-group-low-drop dscp 59
 *    set resources group dscp-group default-group-low-drop dscp 60
 *    set resources group dscp-group default-group-low-drop dscp 61
 *    set resources group dscp-group default-group-low-drop dscp 62
 *    set resources group dscp-group default-group-low-drop dscp 63
 *    set resources group dscp-group priority-group-high-drop dscp 24
 *    set resources group dscp-group priority-group-high-drop dscp 26
 *    set resources group dscp-group priority-group-high-drop dscp 32
 *    set resources group dscp-group priority-group-high-drop dscp 34
 *    set resources group dscp-group priority-group-low-drop dscp 25
 *    set resources group dscp-group priority-group-low-drop dscp 27
 *    set resources group dscp-group priority-group-low-drop dscp 28
 *    set resources group dscp-group priority-group-low-drop dscp 29
 *    set resources group dscp-group priority-group-low-drop dscp 30
 *    set resources group dscp-group priority-group-low-drop dscp 31
 *    set resources group dscp-group priority-group-low-drop dscp 33
 *    set resources group dscp-group priority-group-low-drop dscp 35
 *    set resources group dscp-group priority-group-low-drop dscp 36
 *    set resources group dscp-group priority-group-low-drop dscp 37
 *    set resources group dscp-group priority-group-low-drop dscp 38
 *    set resources group dscp-group priority-group-low-drop dscp 39
 *    set resources group dscp-group real-time-group dscp 40
 *    set resources group dscp-group real-time-group dscp 46
 *    set resources group dscp-group real-time-group dscp 47
 *    set resources group dscp-group real-time-group dscp 48
 *    set resources group dscp-group synch-group dscp 56
 *
 *    set policy qos name vlan-policy-50M shaper default vlan-profile-50M
 *    set policy qos name vlan-policy-50M shaper traffic-class 0
 *         queue-limit 1024
 *    set policy qos name vlan-policy-50M shaper traffic-class 1
 *         queue-limit 64
 *    set policy qos name vlan-policy-50M shaper traffic-class 2
 *         queue-limit 4096
 *    set policy qos profile default-prof bandwidth 2mbit
 *    set policy qos profile vlan-profile-50M bandwidth 50mbit
 *    set policy qos profile vlan-profile-50M burst 30000
 *    set policy qos profile vlan-profile-50M map dscp-group
 *         default-group-high-drop to 9
 *    set policy qos profile vlan-profile-50M map dscp-group
 *         default-group-low-drop to 9
 *    set policy qos profile vlan-profile-50M map dscp-group
 *         priority-group-high-drop to 8
 *    set policy qos profile vlan-profile-50M map dscp-group
 *         priority-group-low-drop to 8
 *    set policy qos profile vlan-profile-50M map dscp-group
 *         real-time-group to 4
 *    set policy qos profile vlan-profile-50M map dscp-group synch-group to 0
 *    set policy qos profile vlan-profile-50M period 5
 *    set policy qos profile vlan-profile-50M queue 0 traffic-class 0
 *    set policy qos profile vlan-profile-50M queue 0 wred-map-bytes dscp-group
 *         synch-group mark-probability 50
 *    set policy qos profile vlan-profile-50M queue 0 wred-map-bytes dscp-group
 *         synch-group max-threshold 1023
 *    set policy qos profile vlan-profile-50M queue 0 wred-map-bytes dscp-group
 *         synch-group min-threshold 512
 *    set policy qos profile vlan-profile-50M queue 0 wred-map-bytes
 *         filter-weight 4
 *    set policy qos profile vlan-profile-50M queue 4 traffic-class 1
 *    set policy qos profile vlan-profile-50M queue 4 wred-map-bytes dscp-group
 *         real-time-group mark-probability 1
 *    set policy qos profile vlan-profile-50M queue 4 wred-map-bytes dscp-group
 *         real-time-group max-threshold 63
 *    set policy qos profile vlan-profile-50M queue 4 wred-map-bytes dscp-group
 *         real-time-group min-threshold 32
 *    set policy qos profile vlan-profile-50M queue 4 wred-map-bytes
 *         filter-weight 6
 *    set policy qos profile vlan-profile-50M queue 8 traffic-class 2
 *    set policy qos profile vlan-profile-50M queue 8 weight 60
 *    set policy qos profile vlan-profile-50M queue 8 wred-map-bytes dscp-group
 *         priority-group-high-drop mark-probability 30
 *    set policy qos profile vlan-profile-50M queue 8 wred-map-bytes dscp-group
 *         priority-group-high-drop max-threshold 2027
 *    set policy qos profile vlan-profile-50M queue 8 wred-map-bytes dscp-group
 *         priority-group-high-drop min-threshold 1024
 *    set policy qos profile vlan-profile-50M queue 8 wred-map-bytes dscp-group
 *         priority-group-low-drop mark-probability 75
 *    set policy qos profile vlan-profile-50M queue 8 wred-map-bytes dscp-group
 *         priority-group-low-drop max-threshold 4095
 *    set policy qos profile vlan-profile-50M queue 8 wred-map-bytes dscp-group
 *         priority-group-low-drop min-threshold 2048
 *    set policy qos profile vlan-profile-50M queue 8 wred-map-bytes
 *        filter-weight 8
 *    set policy qos profile vlan-profile-50M queue 9 traffic-class 2
 *    set policy qos profile vlan-profile-50M queue 9 weight 40
 *    set policy qos profile vlan-profile-50M queue 9 wred-map-bytes dscp-group
 *         default-group-high-drop mark-probability 50
 *    set policy qos profile vlan-profile-50M queue 9 wred-map-bytes dscp-group
 *         default-group-high-drop max-threshold 1023
 *    set policy qos profile vlan-profile-50M queue 9 wred-map-bytes dscp-group
 *         default-group-high-drop min-threshold 512
 *    set policy qos profile vlan-profile-50M queue 9 wred-map-bytes dscp-group
 *         default-group-low-drop mark-probability 100
 *    set policy qos profile vlan-profile-50M queue 9 wred-map-bytes dscp-group
 *         default-group-low-drop max-threshold 2048
 *    set policy qos profile vlan-profile-50M queue 9 wred-map-bytes dscp-group
 *         default-group-low-drop min-threshold 1024
 *    set policy qos profile vlan-profile-50M queue 9 wred-map-bytes
 *         filter-weight 10
 *    set policy qos profile vlan-profile-50M traffic-class 0 bandwidth 50%
 *    set policy qos profile vlan-profile-50M traffic-class 1 bandwidth 50%
 *    set interface dataplane dp0s5 policy qos vlan-policy-50M
 */

const char *fal_hw_wred_map_npf_cmds[] = {
	"npf-cfg delete dscp-group:default-group-high-drop",
	"npf-cfg delete dscp-group:default-group-low-drop",
	"npf-cfg delete dscp-group:priority-group-high-drop",
	"npf-cfg delete dscp-group:priority-group-low-drop",
	"npf-cfg delete dscp-group:real-time-group",
	"npf-cfg delete dscp-group:synch-group",
	"npf-cfg add dscp-group:default-group-high-drop 0 8;10;16;18",
	"npf-cfg add dscp-group:default-group-low-drop 0 0;1;2;3;4;5;6;7;9;"
	"11;12;13;14;15;17;19;20;21;22;23;41;42;43;44;45;49;50;51;52;53;54;"
	"55;57;58;59;60;61;62;63",
	"npf-cfg add dscp-group:priority-group-high-drop 0 24;26;32;34",
	"npf-cfg add dscp-group:priority-group-low-drop 0 25;27;28;29;30;31;"
	"33;35;36;37;38;39",
	"npf-cfg add dscp-group:real-time-group 0 40;46;47;48",
	"npf-cfg add dscp-group:synch-group 0 56",
	"npf-cfg commit"
};

const char *fal_hw_wred_map_npf_delete_cmds[] = {
	"npf-cfg delete dscp-group:default-group-high-drop",
	"npf-cfg delete dscp-group:default-group-low-drop",
	"npf-cfg delete dscp-group:priority-group-high-drop",
	"npf-cfg delete dscp-group:priority-group-low-drop",
	"npf-cfg delete dscp-group:real-time-group",
	"npf-cfg delete dscp-group:synch-group",
	"npf-cfg commit"
};

const char *fal_hw_wred_map_qos_cmds[] = {
	"port subports 1 pipes 1 profiles 3 overhead 24 ql_bytes",
	"subport 0 rate 1250000000 size 100000 period 40000",
	"subport 0 queue 0 rate 1250000000 size 100000",
	"param subport 0 0 limit packets 1024",
	"subport 0 queue 1 rate 1250000000 size 100002",
	"param subport 0 1 limit packets 64",
	"subport 0 queue 2 rate 1250000000 size 100000",
	"param subport 0 2 limit packets 4096",
	"subport 0 queue 3 rate 1250000000 size 100000",
	"vlan 0 0",
	"profile 0 rate 250000 size 1000 period 10000",
	"profile 0 queue 0 rate 250000 size 1000",
	"profile 0 queue 1 rate 250000 size 1000",
	"profile 0 queue 2 rate 250000 size 1000",
	"profile 0 queue 3 rate 250000 size 1000",
	"profile 1 rate 6250000 size 30000 period 5000",
	"profile 1 queue 0 rate 3125000 size 12500",
	"profile 1 queue 1 rate 3125000 size 12500",
	"profile 1 queue 2 rate 6250000 size 25000",
	"profile 1 queue 3 rate 6250000 size 25000",
	"profile 1 dscp 0 0x26",
	"profile 1 dscp 1 0x26",
	"profile 1 dscp 2 0x26",
	"profile 1 dscp 3 0x26",
	"profile 1 dscp 4 0x26",
	"profile 1 dscp 5 0x26",
	"profile 1 dscp 6 0x26",
	"profile 1 dscp 7 0x26",
	"profile 1 dscp 8 0x6",
	"profile 1 dscp 9 0x26",
	"profile 1 dscp 10 0x6",
	"profile 1 dscp 11 0x26",
	"profile 1 dscp 12 0x26",
	"profile 1 dscp 13 0x26",
	"profile 1 dscp 14 0x26",
	"profile 1 dscp 15 0x26",
	"profile 1 dscp 16 0x6",
	"profile 1 dscp 17 0x26",
	"profile 1 dscp 18 0x6",
	"profile 1 dscp 19 0x26",
	"profile 1 dscp 20 0x26",
	"profile 1 dscp 21 0x26",
	"profile 1 dscp 22 0x26",
	"profile 1 dscp 23 0x26",
	"profile 1 dscp 24 0x2",
	"profile 1 dscp 25 0x22",
	"profile 1 dscp 26 0x2",
	"profile 1 dscp 27 0x22",
	"profile 1 dscp 28 0x22",
	"profile 1 dscp 29 0x22",
	"profile 1 dscp 30 0x22",
	"profile 1 dscp 31 0x22",
	"profile 1 dscp 32 0x2",
	"profile 1 dscp 33 0x22",
	"profile 1 dscp 34 0x2",
	"profile 1 dscp 35 0x22",
	"profile 1 dscp 36 0x22",
	"profile 1 dscp 37 0x22",
	"profile 1 dscp 38 0x22",
	"profile 1 dscp 39 0x22",
	"profile 1 dscp 40 0x1",
	"profile 1 dscp 41 0x26",
	"profile 1 dscp 42 0x26",
	"profile 1 dscp 43 0x26",
	"profile 1 dscp 44 0x26",
	"profile 1 dscp 45 0x26",
	"profile 1 dscp 46 0x1",
	"profile 1 dscp 47 0x1",
	"profile 1 dscp 48 0x1",
	"profile 1 dscp 49 0x26",
	"profile 1 dscp 50 0x26",
	"profile 1 dscp 51 0x26",
	"profile 1 dscp 52 0x26",
	"profile 1 dscp 53 0x26",
	"profile 1 dscp 54 0x26",
	"profile 1 dscp 55 0x26",
	"profile 1 dscp 56 0x0",
	"profile 1 dscp 57 0x26",
	"profile 1 dscp 58 0x26",
	"profile 1 dscp 59 0x26",
	"profile 1 dscp 60 0x26",
	"profile 1 dscp 61 0x26",
	"profile 1 dscp 62 0x26",
	"profile 1 dscp 63 0x26",
	"profile 1 queue 0 wrr-weight 1",
	"profile 1 queue 0 dscp-group synch-group bytes 1023 512 50",
	"profile 1 queue 0 wred-weight 4",
	"profile 1 queue 0x1 wrr-weight 1",
	"profile 1 queue 0x1 dscp-group real-time-group bytes 630 320 100",
	"profile 1 queue 0x1 wred-weight 6",
	"profile 1 queue 0x2 wrr-weight 60",
	"profile 1 queue 0x2 dscp-group priority-group-low-drop bytes 4095 2048 75",
	"profile 1 queue 0x2 dscp-group priority-group-high-drop bytes 2027 1024 30",
	"profile 1 queue 0x2 wred-weight 8",
	"profile 1 queue 0x6 wrr-weight 40",
	"profile 1 queue 0x6 dscp-group default-group-high-drop bytes 1023 512 50",
	"profile 1 queue 0x6 dscp-group default-group-low-drop bytes 2048 1024 100",
	"profile 1 queue 0x6 wred-weight 10",
	"pipe 0 0 1",
	"enable"
};

struct wred_colour_results {
	const char *colour;
	bool enabled;
	int32_t min_th;
	int32_t max_th;
	int32_t prob;
};

struct wred_map_results {
	uint32_t tc;
	uint32_t queue;
	int32_t qlen;
	int8_t fw;
	struct wred_colour_results colour[FAL_PACKET_COLOUR_RED + 1];
};

struct wred_map_results hw_wred_results[] = {
	// tc, q, qlen, filter-weight
	{ 0, 0, 1024, 4,
		{
			{ "green", true, 512, 1023, 50 },
			{ "yellow", false, -1, -1, -1 },
			{ "red", false, -1, -1, -1 }
		}
	},
	{ 1, 0, 64, 6,
		{
			{ "green", true, 320, 630, 100 },
			{ "yellow", false, -1, -1, -1 },
			{ "red", false, -1, -1, -1 }
		}
	},
	{ 2, 0, 4096, 8,
		{
			{ "green", true, 2048, 4095, 75 },
			{ "yellow", true, 1024, 2027, 30 },
			{ "red", false, -1, -1, -1 }
		}
	},
	{ 2, 1, 4096, 10,
		{
			{ "green", true, 512, 1023, 50 },
			{ "yellow", true, 1024, 2048, 100 },
			{ "red", false, -1, -1, -1 }
		}
	}
};

DP_START_TEST(qos_fal_basic, fal_hw_wred_map)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	json_object *j_wred_obj;
	json_object *j_obj;
	uint32_t subport = 0;    /* Only one subport with id = 0 */
	uint32_t pipe = 0;       /* Only one pipe with id = 0 */
	uint32_t tc;
	uint32_t queue;
	uint32_t i;
	uint32_t j;
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("dp1sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	/* Add NPF config */
	for (i = 0; i < ARRAY_SIZE(fal_hw_wred_map_npf_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_hw_wred_map_npf_cmds[i]);

	/* Add QoS config */
	dp_test_qos_attach_config_to_if("dp2T1", fal_hw_wred_map_qos_cmds,
					debug);

	/*
	 * Check the queue level, and in particular the wred objects
	 */
	for (i = 0; i < ARRAY_SIZE(hw_wred_results); i++) {
		int32_t filter_weight;
		int32_t qlen;

		tc = hw_wred_results[i].tc;
		queue = hw_wred_results[i].queue;
		qlen = hw_wred_results[i].qlen;
		filter_weight = hw_wred_results[i].fw;

		j_obj = dp_test_qos_hw_get_json_queue("dp2T1", subport, pipe,
						      tc, queue, debug);
		dp_test_qos_hw_check_queue(j_obj, queue, qlen, queue,
					   0, debug);

		for (j = FAL_PACKET_COLOUR_GREEN;
		     j <= FAL_PACKET_COLOUR_RED; j++) {
			struct wred_colour_results *colour_results;
			const char *colour;
			int32_t min_th;
			int32_t max_th;
			bool enabled;
			int32_t prob;

			colour_results = &hw_wred_results[i].colour[j];
			colour = colour_results->colour;
			enabled = colour_results->enabled;
			min_th = colour_results->min_th;
			max_th = colour_results->max_th;
			prob = colour_results->prob;

			j_wred_obj = dp_test_qos_hw_get_json_child(j_obj,
								   "wred",
								   debug);
			dp_test_qos_hw_check_wred_colour(j_wred_obj, colour,
							 enabled, min_th,
							 max_th, prob,
							 filter_weight, debug);
			json_object_put(j_wred_obj);
		}
		json_object_put(j_obj);
	}

	/* QoS cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);

	/* NPF cleanup */
	for (i = 0; i < ARRAY_SIZE(fal_hw_wred_map_npf_delete_cmds); i++)
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					fal_hw_wred_map_npf_delete_cmds[i]);

	ret = dp_test_qos_fal_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	/* Cleanup the ports */
	dp_test_intf_switch_remove_port("switch0", "dp1sw_port_0_0");
	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_del("switch0");

	dp_test_netlink_del_interface_l2("dp1sw_port_0_0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();
} DP_END_TEST;
