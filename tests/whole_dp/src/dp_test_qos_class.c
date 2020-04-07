/**
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 *
 * @file dp_test_qos_class.c
 * @brief Basic QoS classification tests
 *
 * SPDX-License-Identifier: LGPL-2.1-only
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

DP_DECL_TEST_SUITE(qos_class);

DP_DECL_TEST_CASE(qos_class, qos_class_basic, NULL, NULL);

static int
dp_test_qos_class_hw_switch_if(const char *if_name, bool enable)
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
 * class_basic uses a minimal QoS configuration
 *
 * class_basic_cmds generate from:
 *
 *  set policy qos ingress-map in-map-1 pcp 0 designation 0 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 1 designation 1 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 2 designation 2 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 3 designation 3 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 4 designation 4 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 5 designation 5 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 6 designation 6 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 7 designation 7 drop-prec green
 *  set interface dataplane dpX switch-group port-parameters
 *						 policy ingress-map  in-map-1
 */

const char *ingress_map_cmds[] = {
	"ingress-map in-map-1 pcp 0 designation 0 drop-prec green",
	"ingress-map in-map-1 pcp 1 designation 1 drop-prec green",
	"ingress-map in-map-1 pcp 2 designation 2 drop-prec green",
	"ingress-map in-map-1 pcp 3 designation 3 drop-prec green",
	"ingress-map in-map-1 pcp 4 designation 4 drop-prec green",
	"ingress-map in-map-1 pcp 5 designation 5 drop-prec green",
	"ingress-map in-map-1 pcp 6 designation 6 drop-prec green",
	"ingress-map in-map-1 pcp 7 designation 7 drop-prec green",
	"ingress-map in-map-1 complete",
};

DP_START_TEST(qos_class_basic, class_basic)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_class_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	dp_test_qos_send_config(ingress_map_cmds, 9, debug);
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-1 vlan 0", debug);

	/* Cleanup */
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-1 vlan 0 delete",
				debug);
	dp_test_qos_send_cmd("ingress-map in-map-1 delete", debug);

	ret = dp_test_qos_class_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_remove_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_del("switch0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * class_multi_maps uses several 2 ingress maps
 *
 * cmds generate from:
 *
 *  set policy qos ingress-map in-map-1 pcp 0 designation 0 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 1 designation 1 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 2 designation 2 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 3 designation 4 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 4 designation 4 drop-prec yellow
 *  set policy qos ingress-map in-map-1 pcp 5 designation 5 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 6 designation 7 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 7 designation 7 drop-prec yellow
 *  set interface dataplane dpX switch-group port-parameters
 *						 policy ingress-map in-map-1
 *  set resources group dscp-group rt dscp 38
 *  set resources group dscp-group voice dscp 46
 *  set resources group dscp-group control dscp 48
 *  set resources group dscp-group data1 dscp 24
 *  set resources group dscp-group data2 dscp 0
 *  set policy qos ingress-map in-map-2 dscp-group rt designation 0
 *                                                        drop-prec green
 *  set policy qos ingress-map in-map-2 dscp-group voice designation 1
 *                                                        drop-prec green
 *  set policy qos ingress-map in-map-2 dscp-group control designation 2
 *                                                        drop-prec green
 *  set policy qos ingress-map in-map-2 dscp-group data1 designation 3
 *                                                        drop-prec green
 *  set policy qos ingress-map in-map-2 dscp-group data2 designation 4
 *                                                        drop-prec green
 *  set interface dataplane dpX switch-group port-parameters
 *						 policy ingress-map in-map-2
 */

const char *ingress_multi_map_cmds[] = {
	"ingress-map in-map-1 pcp 0 designation 0 drop-prec green",
	"ingress-map in-map-1 pcp 1 designation 1 drop-prec green",
	"ingress-map in-map-1 pcp 2 designation 2 drop-prec green",
	"ingress-map in-map-1 pcp 3 designation 4 drop-prec green",
	"ingress-map in-map-1 pcp 4 designation 4 drop-prec yellow",
	"ingress-map in-map-1 pcp 5 designation 5 drop-prec green",
	"ingress-map in-map-1 pcp 6 designation 7 drop-prec green",
	"ingress-map in-map-1 pcp 7 designation 7 drop-prec yellow",
	"ingress-map in-map-1 complete",
	"ingress-map in-map-2 dscp-group rt designation 0 drop-prec green",
	"ingress-map in-map-2 dscp-group voice designation 1 drop-prec green",
	"ingress-map in-map-2 dscp-group control designation 2 drop-prec green",
	"ingress-map in-map-2 dscp-group data1 designation 3 drop-prec green",
	"ingress-map in-map-2 dscp-group data2 designation 4 drop-prec green",
	"ingress-map in-map-2 complete",
};

const char *ingress_rg_add_cmds[] = {
	"npf-cfg add dscp-group:rt 0 38;39;40;41;42;43;44;45",
	"npf-cfg add dscp-group:voice 0 46;47",
	"npf-cfg add dscp-group:control 0 48;49;50;51;52;53;54;55;56;57;58;59;60;61;62;63",
	"npf-cfg add dscp-group:data1 0 24;25;26;27;28;29;30;31;32;33;34;35;36;37",
	"npf-cfg add dscp-group:data2 0 0;1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17;18;19;20;21;22;23",
	"npf-cfg commit"
};

const char *ingress_rg_del_cmds[] = {
	"npf-cfg delete dscp-group:rt",
	"npf-cfg delete dscp-group:voice",
	"npf-cfg delete dscp-group:control",
	"npf-cfg delete dscp-group:data1",
	"npf-cfg delete dscp-group:data2",
	"npf-cfg commit"
};

DP_START_TEST(qos_class_basic, class_multimaps)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	int ret, i;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_class_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	i = 0;
	while (!strstr(ingress_rg_add_cmds[i], "npf-cfg commit")) {
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					ingress_rg_add_cmds[i++]);
	}
	dp_test_send_config_src(dp_test_cont_src_get(), "%s",
				ingress_rg_add_cmds[i++]);
	dp_test_qos_send_config(ingress_multi_map_cmds, 15, debug);
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-1 vlan 0", debug);
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-2 vlan 10", debug);

	/* Cleanup */
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-1 vlan 10 delete",
				debug);
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-1 vlan 0 delete",
				debug);
	dp_test_qos_send_cmd("ingress-map in-map-1 delete", debug);
	dp_test_qos_send_cmd("ingress-map in-map-2 delete", debug);
	i = 0;
	while (!strstr(ingress_rg_del_cmds[i], "npf-cfg commit")) {
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					ingress_rg_del_cmds[i++]);
	}
	dp_test_send_config_src(dp_test_cont_src_get(), "%s",
				ingress_rg_del_cmds[i++]);

	ret = dp_test_qos_class_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_remove_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_del("switch0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * class_map_multi_dps uses a minimal QoS configuration
 *
 * class_map_multi_dps generate from:
 *
 *  set policy qos ingress-map in-map-1 pcp 0 designation 0 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 1 designation 1 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 2 designation 1 drop-prec yellow
 *  set policy qos ingress-map in-map-1 pcp 3 designation 3 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 4 designation 3 drop-prec yellow
 *  set policy qos ingress-map in-map-1 pcp 5 designation 5 drop-prec green
 *  set policy qos ingress-map in-map-1 pcp 6 designation 5 drop-prec yellow
 *  set policy qos ingress-map in-map-1 pcp 7 designation 5 drop-prec red
 *  set interface dataplane dpX switch-group port-parameters
 *						 policy ingress-map  in-map-1
 */

const char *ingress_map_dp_cmds[] = {
	"ingress-map in-map-1 pcp 0 designation 0 drop-prec green",
	"ingress-map in-map-1 pcp 1 designation 1 drop-prec green",
	"ingress-map in-map-1 pcp 2 designation 2 drop-prec green",
	"ingress-map in-map-1 pcp 3 designation 3 drop-prec green",
	"ingress-map in-map-1 pcp 4 designation 3 drop-prec yellow",
	"ingress-map in-map-1 pcp 5 designation 5 drop-prec green",
	"ingress-map in-map-1 pcp 6 designation 5 drop-prec yellow",
	"ingress-map in-map-1 pcp 7 designation 5 drop-prec red",
	"ingress-map in-map-1 complete",
};

DP_START_TEST(qos_class_basic, class_map_multi_dps)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	int ret;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_class_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	dp_test_qos_send_config(ingress_map_dp_cmds, 9, debug);
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-1 vlan 0", debug);

	/* Cleanup */
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-1 vlan 0 delete",
				debug);
	dp_test_qos_send_cmd("ingress-map in-map-1 delete", debug);

	ret = dp_test_qos_class_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_remove_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_del("switch0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * class_single_sysdef uses a minimal QoS configuration
 *
 * class_single_sysdef generate from:
 *
 *  set policy qos ingress-map in-map-1 pcp 0 designation 0
 *  set policy qos ingress-map in-map-1 system-default
 *  set policy qos ingress-map in-map-2 pcp 3 designation 3
 *  set policy qos ingress-map in-map-2 system-default
 */

const char *ingress_sysdef1[] = {
	"ingress-map in-map-1 pcp 0 designation 0 drop-prec green",
	"ingress-map in-map-1 pcp 1 designation 0 drop-prec yellow",
	"ingress-map in-map-1 pcp 2 designation 0 drop-prec red",
	"ingress-map in-map-1 pcp 3 designation 1 drop-prec green",
	"ingress-map in-map-1 pcp 4 designation 1 drop-prec yellow",
	"ingress-map in-map-1 pcp 5 designation 1 drop-prec red",
	"ingress-map in-map-1 pcp 6 designation 2 drop-prec green",
	"ingress-map in-map-1 pcp 7 designation 2 drop-prec yellow",
	"ingress-map in-map-1 system-default",
	"ingress-map in-map-1 complete"
};

const char *ingress_sysdef2[] = {
	"ingress-map in-map-2 pcp 0 designation 2 drop-prec green",
	"ingress-map in-map-2 pcp 1 designation 2 drop-prec yellow",
	"ingress-map in-map-2 pcp 2 designation 2 drop-prec red",
	"ingress-map in-map-2 pcp 3 designation 3 drop-prec green",
	"ingress-map in-map-2 pcp 4 designation 3 drop-prec yellow",
	"ingress-map in-map-2 pcp 5 designation 3 drop-prec red",
	"ingress-map in-map-2 pcp 6 designation 4 drop-prec green",
	"ingress-map in-map-2 pcp 7 designation 4 drop-prec yellow",
	"ingress-map in-map-2 system-default",
	"ingress-map in-map-2 complete"
};

DP_START_TEST(qos_class_basic, class_single_sysdef)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_qos_send_config(ingress_sysdef1, 10, debug);
	/* Second system-default should fail */
	dp_test_set_config_err(-EINVAL);
	dp_test_qos_send_config(ingress_sysdef2, 10, debug);

	dp_test_qos_send_cmd("ingress-map in-map-1 delete", debug);
	/* Now it should succeed */
	dp_test_qos_send_cmd("ingress-map in-map-2 system-default", debug);
	dp_test_qos_send_cmd("ingress-map in-map-2 complete", debug);

	/* Cleanup */
	dp_test_qos_send_cmd("ingress-map in-map-2 delete", debug);

	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * class_map_to_policy setup an ingress map and matching policy
 *
 * cmds generate from:
 *
 *  set resources group dscp-group rt dscp 38
 *  set resources group dscp-group voice dscp 46
 *  set resources group dscp-group control dscp 48
 *  set resources group dscp-group data1 dscp 24
 *  set resources group dscp-group data2 dscp 0
 *  set policy qos ingress-map in-map-2 dscp-group rt designation 0
 *                                                      drop-prec green
 *  set policy qos ingress-map in-map-2 dscp-group voice designation 1
 *                                                      drop-prec green
 *  set policy qos ingress-map in-map-2 dscp-group control designation 2
 *                                                      drop-prec green
 *  set policy qos ingress-map in-map-2 dscp-group data1 designation 3
 *                                                      drop-prec green
 *  set policy qos ingress-map in-map-2 dscp-group data2 designation 4
 *                                                      drop-prec green
 *  set interface dataplane dpX switch-group port-parameters
 *						 policy ingress-map in-map-2
 *  set policy qos name foo shaper default def
 *  set policy qos name foo shaper profile def map designation 0 to 0
 *  set policy qos name foo shaper profile def map designation 1 to 2
 *  set policy qos name foo shaper profile def map designation 2 to 5
 *  set policy qos name foo shaper profile def map designation 3 to 6
 *  set policy qos name foo shaper profile def map designation 4 to 7
 *  set policy qos name foo shaper profile def queue 0 traffic-class 0
 *  set policy qos name foo shaper profile def queue 2 traffic-class 1
 *  set policy qos name foo shaper profile def queue 5 traffic-class 2
 *  set policy qos name foo shaper profile def queue 6 traffic-class 3
 *  set policy qos name foo shaper profile def queue 7 traffic-class 3
 *  set interface dataplane dpX switch-group port-parameters
 *						 policy qos foo
 */

const char *ingress_map_2_pol_cmds[] = {
	"ingress-map in-map-2 dscp-group rt designation 0 drop-prec green",
	"ingress-map in-map-2 dscp-group voice designation 1 drop-prec green",
	"ingress-map in-map-2 dscp-group control designation 2 drop-prec green",
	"ingress-map in-map-2 dscp-group data1 designation 3 drop-prec green",
	"ingress-map in-map-2 dscp-group data2 designation 4 drop-prec green",
	"ingress-map in-map-2 complete",
};

const char *ingress_policy_cmds[] = {
	"port subports 1 pipes 1 profiles 1 overhead 24 ql_bytes",
	"subport 0 rate 1250000000 size 0 period 40",
	"subport 0 queue 0 percent 100 size 0",
	"param subport 0 0",
	"subport 0 queue 1 percent 100 size 0",
	"param subport 0 1",
	"subport 0 queue 2 percent 100 size 0",
	"param subport 0 2",
	"subport 0 queue 3 percent 100 size 0",
	"param subport 0 3",
	"vlan 0 0",
	"profile 0 percent 100 size 0 period 10",
	"profile 0 queue 0 percent 100 size 0",
	"profile 0 queue 2 percent 100 size 0",
	"profile 0 queue 5 percent 100 size 0",
	"profile 0 queue 6 percent 100 size 0",
	"profile 0 queue 7 percent 100 size 0",
	"profile 0 queue 0 wrr-weight 1 0",
	"profile 0 queue 0x1 wrr-weight 1 2",
	"profile 0 queue 0x2 wrr-weight 1 5",
	"profile 0 queue 0x3 wrr-weight 1 6",
	"profile 0 queue 0x7 wrr-weight 1 7",
	"profile 0 designation 0 queue 0",
	"profile 0 designation 1 queue 0x1",
	"profile 0 designation 2 queue 0x2",
	"profile 0 designation 3 queue 0x3",
	"profile 0 designation 4 queue 0x7",
	"pipe 0 0 0",
	"enable",
};

DP_START_TEST(qos_class_basic, class_map_to_policy)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	int ret, i;
	json_object *j_obj;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");
	dp_test_intf_switch_add_port("switch0", "dp2T2");

	ret = dp_test_qos_class_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	ret = dp_test_qos_class_hw_switch_if("dp2T2", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T2\n");

	i = 0;
	while (!strstr(ingress_rg_add_cmds[i], "npf-cfg commit")) {
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					ingress_rg_add_cmds[i++]);
	}
	dp_test_send_config_src(dp_test_cont_src_get(), "%s",
				ingress_rg_add_cmds[i++]);
	dp_test_qos_send_config(ingress_map_2_pol_cmds, 6, debug);
	dp_test_qos_attach_config_to_if("dp2T2", ingress_policy_cmds, debug);

	/*
	 * Check the designator values in the queue objects match the
	 * configured values
	 *
	 * Although a designation value of 0 is valid we use to indicate
	 * that the value be ignored for testing purposes so skip.
	 */
	j_obj = dp_test_qos_hw_get_json_queue("dp2T2", 0, 0, 0, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T2", 0, 0, 1, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 1, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T2", 0, 0, 2, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 2, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T2", 0, 0, 3, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 3, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T2", 0, 0, 3, 1, debug);
	dp_test_qos_hw_check_queue(j_obj, 1, 64, 1, 4, debug);
	json_object_put(j_obj);

	/* Cleanup */
	dp_test_qos_send_if_cmd("dp2T1", "ingress-map in-map-1 vlan 0 delete",
				debug);
	dp_test_qos_send_if_cmd("dp2T2", "disable", debug);
	dp_test_qos_send_cmd("ingress-map in-map-2 delete", debug);
	i = 0;
	while (!strstr(ingress_rg_del_cmds[i], "npf-cfg commit")) {
		dp_test_send_config_src(dp_test_cont_src_get(), "%s",
					ingress_rg_del_cmds[i++]);
	}
	dp_test_send_config_src(dp_test_cont_src_get(), "%s",
				ingress_rg_del_cmds[i++]);

	ret = dp_test_qos_class_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	ret = dp_test_qos_class_hw_switch_if("dp2T2", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T2\n");

	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_remove_port("switch0", "dp2T2");
	dp_test_intf_switch_remove_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_del("switch0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * class_policy_skip_des Don't use consecutive designations
 *
 * cmds generate from:
 *
 *  set policy qos name foo shaper default def
 *  set policy qos name foo shaper profile def map designation 0 to 0
 *  set policy qos name foo shaper profile def map designation 2 to 2
 *  set policy qos name foo shaper profile def map designation 5 to 5
 *  set policy qos name foo shaper profile def map designation 7 to 6
 *  set policy qos name foo shaper profile def queue 0 traffic-class 0
 *  set policy qos name foo shaper profile def queue 2 traffic-class 1
 *  set policy qos name foo shaper profile def queue 5 traffic-class 2
 *  set policy qos name foo shaper profile def queue 6 traffic-class 3
 *  set interface dataplane dpX switch-group port-parameters
 *						 policy qos foo
 */

const char *ingress_policy_skip_des_cmds[] = {
	"port subports 1 pipes 1 profiles 1 overhead 24 ql_bytes",
	"subport 0 rate 1250000000 size 0 period 40",
	"subport 0 queue 0 percent 100 size 0",
	"param subport 0 0",
	"subport 0 queue 1 percent 100 size 0",
	"param subport 0 1",
	"subport 0 queue 2 percent 100 size 0",
	"param subport 0 2",
	"subport 0 queue 3 percent 100 size 0",
	"param subport 0 3",
	"vlan 0 0",
	"profile 0 percent 100 size 0 period 10",
	"profile 0 queue 0 percent 100 size 0",
	"profile 0 queue 2 percent 100 size 0",
	"profile 0 queue 5 percent 100 size 0",
	"profile 0 queue 6 percent 100 size 0",
	"profile 0 queue 0 wrr-weight 1 0",
	"profile 0 queue 0x1 wrr-weight 1 2",
	"profile 0 queue 0x2 wrr-weight 1 5",
	"profile 0 queue 0x3 wrr-weight 1 6",
	"profile 0 designation 0 queue 0",
	"profile 0 designation 2 queue 0x1",
	"profile 0 designation 5 queue 0x2",
	"profile 0 designation 7 queue 0x3",
	"pipe 0 0 0",
	"enable",
};

DP_START_TEST(qos_class_basic, class_policy_skip_des)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	int ret;
	json_object *j_obj;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_class_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	dp_test_qos_attach_config_to_if("dp2T1", ingress_policy_skip_des_cmds,
					debug);

	/*
	 * Check the designator values in the queue objects match the
	 * configured values
	 */
	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 0, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 1, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 2, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 2, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 5, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 3, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 7, debug);
	json_object_put(j_obj);

	/* Cleanup */
	dp_test_qos_send_if_cmd("dp2T1", "disable", debug);

	ret = dp_test_qos_class_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_remove_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_del("switch0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * class_policy_vci A test policy used for VCI
 *
 * cmds generate from:
 *
 *  set policy qos name pol-1 shaper default profile-1
 *  set policy qos name pol-1 shaper profile profile-1
 *  set interface dataplane dpX switch-group port-parameters
 *						 policy qos pol-1
 */

const char *class_policy_vci[] = {
	"port subports 1 pipes 1 profiles 1 overhead 24 ql_bytes",
	"subport 0 rate 1250000000 size 16000 period 40",
	"subport 0 queue 0 percent 100 size 0",
	"param subport 0 0 limit packets 64",
	"subport 0 queue 1 percent 100 size 0",
	"param subport 0 1 limit packets 64",
	"subport 0 queue 2 percent 100 size 0",
	"param subport 0 2 limit packets 64",
	"subport 0 queue 3 percent 100 size 0",
	"param subport 0 3 limit packets 64",
	"vlan 0 0",
	"profile 0 percent 100 size 16000 period 10",
	"profile 0 queue 0 percent 100 size 0",
	"profile 0 queue 1 percent 100 size 0",
	"profile 0 queue 2 percent 100 size 0",
	"profile 0 queue 3 percent 100 size 0",
	"pipe 0 0 0",
	"enable",
};

DP_START_TEST(qos_class_basic, class_policy_vci)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	int ret;
	json_object *j_obj;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	dp_test_netlink_set_interface_l2("sw_port_0_0");

	dp_test_intf_switch_create("switch0");
	dp_test_intf_switch_add_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_add_port("switch0", "dp2T1");

	ret = dp_test_qos_class_hw_switch_if("dp2T1", true);
	dp_test_fail_unless((ret == 0),
			    "failed to set hw-switching on dp2T1\n");

	dp_test_qos_attach_config_to_if("dp2T1", class_policy_vci,
					debug);

	/*
	 * Check the designator values in the queue objects match the
	 * configured values
	 */
	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 0, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 1, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 2, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	j_obj = dp_test_qos_hw_get_json_queue("dp2T1", 0, 0, 3, 0, debug);
	dp_test_qos_hw_check_queue(j_obj, 0, 64, 0, 0, debug);
	json_object_put(j_obj);

	/* Cleanup */
	dp_test_qos_send_if_cmd("dp2T1", "disable", debug);

	ret = dp_test_qos_class_hw_switch_if("dp2T1", false);
	dp_test_fail_unless((ret == 0),
			    "failed to clear hw-switching on dp2T1\n");

	dp_test_intf_switch_remove_port("switch0", "dp2T1");
	dp_test_intf_switch_remove_port("switch0", "sw_port_0_0");
	dp_test_intf_switch_del("switch0");

	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;
