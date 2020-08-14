/**
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2018 by AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * @file dp_test_qos_basic.h
 * @brief Basic QoS dataplane unit-tests
 */

#include <libmnl/libmnl.h>
#include <rte_sched.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

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

DP_DECL_TEST_SUITE(qos_basic);

DP_DECL_TEST_CASE(qos_basic, qos_basic_ipv4, NULL, NULL);

/*
 * Simple QoS test-setup
 *
 * +-----+1.1.1.11         1.1.1.1+-----+2.2.2.2         2.2.2.11+-----+
 * |     |                   dp1T0|     |dp2T1                   |     |
 * | src |------------------------| uut |------------------------| dst |
 * |     |aa:bb:cc:dd:01:a1       |     |       aa:bb:cc:dd:02:b1|     |
 * +-----+       00:00:a4:00:00:64+-----+00:00:a4:00:00:6a       +-----+
 *
 * QoS is configured on dp2T1.  Packets are received on dp1T0 and routed
 * out of dp2T1 where they receive the "QoS treatment".
 */

/*
 * qos_lib_selftest uses a minimal QoS configuration and calls most of the
 * dp_test_qos_get_json library functions to check that they can return the
 * appropriate results.
 *
 * This is essentially a unit-test for various dp_test_qos library functions.
 *
 * qos_lib_selftest_cmds generate from:
 *
 *  set interfaces dataplane dp0s5 policy qos 'trunk-egress'
 *  set policy qos name trunk-egress shaper default 'global-profile'
 *  set policy qos profile global-profile bandwidth '100Mbit'
 */

const char *qos_lib_selftest_cmds[] = {
	"port subports 1 pipes 1 profiles 2 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"vlan 0 0",
	"profile 0 rate 12500000 size 50000 period 10",
	"profile 0 queue 0 rate 12500000 size 50000",
	"profile 0 queue 1 rate 12500000 size 50000",
	"profile 0 queue 2 rate 12500000 size 50000",
	"profile 0 queue 3 rate 12500000 size 50000",
	"pipe 0 0 0",
	"enable"
};

/*
 * The following constants represent various values specified as parameters
 * in the vyatta qos configuration commands shown above.
 */
#define QOS_LIB_SELFTEST_PROFILE_RATE 12500000
#define QOS_LIB_SELFTEST_PROFILE_SIZE 50000
#define QOS_LIB_SELFTEST_PROFILE_PERIOD 10

/* 99.6% of QOS_LIB_SELFTEST_PROFILE_RATE */
#define	QOS_LIB_SELFTEST_PROFILE_QUEUE_ACTUAL_RATE 12450000

DP_START_TEST(qos_basic_ipv4, qos_lib_selftest)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	json_object *j_obj;
	uint tc;
	uint queue;
	uint dscp;
	uint pcp;
	int value;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", qos_lib_selftest_cmds, debug);

	/*
	 * The rest of this test is ordered as various JSON object tags appear
	 * in the output of the VPLSH "qos show" command.
	 *
	 * First, can we find the shaper object?
	 */
	j_obj = dp_test_qos_get_json_shaper("dp2T1", debug);
	dp_test_fail_unless(j_obj != NULL, "failed to find shaper\n");
	json_object_put(j_obj);

	/*
	 * Second, can we find a vlan?
	 * No - as no vlans are configured in this test.
	 * Vlans will be covered in a later test.
	 */

	/* Can we find the subports object ? */
	j_obj = dp_test_qos_get_json_subports("dp2T1", debug);
	dp_test_fail_unless(j_obj != NULL, "failed to find subports\n");
	json_object_put(j_obj);

	/* Can we find the subport 0's tcs? */
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		j_obj = dp_test_qos_get_json_subport_tc("dp2T1", 0, tc, debug);
		dp_test_fail_unless(j_obj != NULL,
				    "failed to find subport 0 tc %u\n", tc);
		json_object_put(j_obj);
	}

	/* Can we find the subport 0's default pipe - pipe 0? */
	j_obj = dp_test_qos_get_json_pipe("dp2T1", 0, 0, debug);
	dp_test_fail_unless(j_obj != NULL, "failed to find subport 0 pipe 0\n");
	json_object_put(j_obj);

	/* Can we find the subport 0's default pipe params? */
	j_obj = dp_test_qos_get_json_params("dp2T1", 0, 0, debug);
	dp_test_fail_unless(j_obj != NULL,
			    "failed to find subport 0 pipe 0 params\n");

	value = -1;
	if (!dp_test_json_int_field_from_obj(j_obj, "tb_rate", &value) ||
	    value != QOS_LIB_SELFTEST_PROFILE_RATE) {
		dp_test_fail("failed to get correct params tb_rate %d\n",
			     value);
	}

	value = -1;
	if (!dp_test_json_int_field_from_obj(j_obj, "tb_size", &value) ||
	    value != QOS_LIB_SELFTEST_PROFILE_SIZE) {
		dp_test_fail("failed to get correct params tb_size %d\n",
			     value);
	}

	value = -1;
	if (!dp_test_json_int_field_from_obj(j_obj, "tc_period", &value) ||
	    value != QOS_LIB_SELFTEST_PROFILE_PERIOD) {
		dp_test_fail("failed to get correct params tc_period %d\n",
			     value);
	}
	json_object_put(j_obj);

	/* Can we find the param's tc_rates? */
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		j_obj = dp_test_qos_get_json_tc_rate("dp2T1", 0, 0, tc, debug);
		dp_test_fail_unless(j_obj != NULL,
				    "failed to find subport 0 pipe 0 params "
				    "tc_rates for tc %u\n", tc);
		value = json_object_get_int(j_obj);
		json_object_put(j_obj);
		dp_test_fail_unless(value ==
				    QOS_LIB_SELFTEST_PROFILE_QUEUE_ACTUAL_RATE,
				    "failed to get correct tc_rate value for "
				    "tc %u - value %u\n", tc, value);
	}

	/* Can we find the params wrr_weights? */
	for (queue = 0; queue < RTE_SCHED_QUEUES_PER_PIPE; queue++) {
		j_obj = dp_test_qos_get_json_wrr_weight("dp2T1", 0, 0, queue,
							debug);
		dp_test_fail_unless(j_obj != NULL,
				    "failed to find subport 0 pipe 0 params "
				    "wrr_weight for queue %u\n", queue);
		value = json_object_get_int(j_obj);
		json_object_put(j_obj);
		/*
		 * The default WRR weight for each queue is one.
		 */
		dp_test_fail_unless(value == 1,
				    "failed to get correct wrr_weight value "
				    "for queue %u\n", queue);
	}

	/* Can we find the pipe's dscp map? */
	for (dscp = 0; dscp < MAX_DSCP; dscp++) {
		j_obj = dp_test_qos_get_json_dscp2q("dp2T1", 0, 0, dscp, debug);
		dp_test_fail_unless(j_obj != NULL,
				    "failed to find subport 0 pipe 0 dscp2q "
				    "%u map\n", dscp);

		value = json_object_get_int(j_obj);
		json_object_put(j_obj);
		/*
		 * Expect the default DSCP to queue mapping.
		 */
		if (dscp <= 15) {
			/*
			 * DSCPs less than 16 go to traffic-class 3
			 */
			dp_test_fail_unless(value == 3,
					    "wrong tc/queue %d value for dscp "
					    "%u\n", value, dscp);
		} else if (dscp > 15 && dscp <= 31) {
			/*
			 * DSCPs from 16 to 31 go to traffic-class 2
			 */
			dp_test_fail_unless(value == 2,
					    "wrong tc/queue %d value for dscp "
					    "%u\n", value, dscp);
		} else if (dscp > 31 && dscp <= 47) {
			/*
			 * DSCPs from 32 to 47 go to traffic-class 1
			 */
			dp_test_fail_unless(value == 1,
					    "wrong tc/queue %d value for dscp "
					    "%u\n", value, dscp);
		} else {
			/*
			 * DSCPs from 48 to 63 go to traffic-class 0
			 */
			dp_test_fail_unless(value == 0,
					    "wrong tc/queue %d value for dscp "
					    "%u\n", value, dscp);
		}
	}

	/* Can we find the pipe's pcp map? */
	for (pcp = 0; pcp < MAX_PCP; pcp++) {
		j_obj = dp_test_qos_get_json_pcp2q("dp2T1", 0, 0, pcp, debug);
		dp_test_fail_unless(j_obj != NULL,
				    "failed to find subport 0 pipe 0 pcp2q "
				    "%u map\n", dscp);

		value = json_object_get_int(j_obj);
		json_object_put(j_obj);
		/*
		 * Expect the default PCP to queue mapping.
		 */
		if (pcp == 0 || pcp == 1) {
			/*
			 * PCPs 0 and 1 go to traffic-class 3
			 */
			dp_test_fail_unless(value == 3,
					    "wrong tc/queue %d value for pcp "
					    "%u\n", value, pcp);
		} else if (pcp == 2 || pcp == 3) {
			/*
			 * PCPs 2 and 3 go to traffic-class 2
			 */
			dp_test_fail_unless(value == 2,
					    "wrong tc/queue %d value for pcp "
					    "%u\n", value, pcp);
		} else if (pcp == 4 || pcp == 5) {
			/*
			 * PCPs 4 and 5 go to traffic-class 1
			 */
			dp_test_fail_unless(value == 1,
					    "wrong tc/queue %d value for pcp "
					    "%u\n", value, pcp);
		} else {
			/*
			 * PCPs 6 and 7 go to traffic-class 0
			 */
			dp_test_fail_unless(value == 0,
					    "wrong tc/queue %d value for pcp "
					    "%u\n", value, pcp);
		}
	}

	/* Can we find the pipe's tcs? */
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		j_obj = dp_test_qos_get_json_pipe_tc("dp2T1", 0, 0, tc, debug);
		dp_test_fail_unless(j_obj != NULL,
				    "failed to find pipe 0 tc %u\n", tc);
		json_object_put(j_obj);

		for (queue = 0; queue < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
		     queue++) {
			/* Can we find the pipe's tcs queues? */
			j_obj = dp_test_qos_get_json_queue("dp2T1", 0, 0, tc,
							   queue, debug);
			dp_test_fail_unless(j_obj != NULL,
					    "failed to find the pipe's tc %u, "
					    "queue %u\n", tc, queue);
			json_object_put(j_obj);
		}
	}

	/*
	 * Can we find the subport's rules?
	 * We will just find an empty JSON object because no QoS class is
	 * configured.
	 */
	j_obj = dp_test_qos_get_json_rules("dp2T1", 0, debug);
	dp_test_fail_unless(j_obj != NULL, "failed to find rules\n");
	json_object_put(j_obj);

	/*
	 * Can we check for zero counters?
	 * All the counters will currently be zero as no packets have been
	 * sent.  This tests all the check_for_zero library functions.
	 */
	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * basic_pkt_fwd uses a minimal QoS configuration and sends a few packets with
 * different DSCP values and checks the QoS counters to verify that the
 * packets ended up being processed on the correct queue.  Since there
 * are no vlans and no classification in the QoS configuration, all the
 * packets end up being processed by subport 0 (the trunk), pipe 0 (the
 * default profile).
 *
 * basic_pkt_fwd_cmds generate from:
 *
 *  set interfaces dataplane dp0s5 policy qos 'trunk-egress'
 *  set policy qos name trunk-egress shaper default 'global-profile'
 *  set policy qos profile global-profile bandwidth '100Mbit'
 */

const char *basic_pkt_fwd_cmds[] = {
	"port subports 1 pipes 1 profiles 2 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"vlan 0 0",
	"profile 0 rate 12500000 size 50000 period 10",
	"profile 0 queue 0 rate 12500000 size 50000",
	"profile 0 queue 1 rate 12500000 size 50000",
	"profile 0 queue 2 rate 12500000 size 50000",
	"profile 0 queue 3 rate 12500000 size 50000",
	"pipe 0 0 0",
	"enable"
};

DP_START_TEST(qos_basic_ipv4, basic_pkt_fwd)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", basic_pkt_fwd_cmds, debug);

	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/*
	 * Send some packets out of the trunk interface that has QoS configured
	 * trunk interface = subport 0
	 * no QoS classification = pipe 0
	 *
	 * QoS's default DSCP to TC/queue mapping is:
	 * dscp 48-63 -> TC 0, queue 0
	 * dscp 32-47 -> TC 1, queue 0
	 * dscp 16-31 -> TC 2, queue 0
	 * dscp 0-15  -> TC 3, queue 0
	 */
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  48, 0, 0, 0, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  32, 0, 0, 1, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  16, 0, 0, 2, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  0, 0, 0, 3, 0, debug);

	dp_test_qos_clear_counters("dp2T1", debug);
	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * basic_pkt_classify extends basic_pkt_fwd by adding a simple QoS
 * classification.  Matching the source address of the packets against
 * 1.1.1.0/24.
 *
 * The first set of packets will be sent with a source address of 1.1.1.11
 * the packets will match class 1 and will therefore be processed by pipe 1
 * and not pipe 0.
 *
 * The second set of packets will be sent with a source address of 3.3.3.11,
 * won't match class 1 and will therefore be processed by pipe 0.
 *
 * basic_pkt_classify_cmds generate from:
 *
 *  set interfaces dataplane dp0s5 policy qos 'test'
 *  set policy qos name test shaper class 1 match m1 source address '1.1.1.0/24'
 *  set policy qos name test shaper class 1 profile 'bench'
 *  set policy qos name test shaper default 'bench'
 *  set policy qos name test shaper profile bench bandwidth '10mbit'
 */

const char *basic_pkt_classify_cmds[] = {
	"port subports 1 pipes 2 profiles 1 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"vlan 0 0",
	"profile 0 rate 1250000 size 5000 period 10",
	"profile 0 queue 0 rate 1250000 size 5000",
	"profile 0 queue 1 rate 1250000 size 5000",
	"profile 0 queue 2 rate 1250000 size 5000",
	"profile 0 queue 3 rate 1250000 size 5000",
	"pipe 0 0 0",
	"pipe 0 1 0",
	"match 0 1 action=accept src-addr=1.1.1.0/24 handle=tag(1)",
	"enable"
};

DP_START_TEST(qos_basic_ipv4, basic_pkt_classify)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", basic_pkt_classify_cmds,
					debug);

	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/*
	 * Send some packets out of the trunk interface that has QoS configured
	 * Trunk interface = subport 0
	 *
	 * Send the packets with a source address to match class 1.
	 * This means that the packets will be processed by pipe 1.
	 *
	 * QoS's default DSCP to TC/queue mapping is:
	 * dscp 48-63 -> TC 0, queue 0
	 * dscp 32-47 -> TC 1, queue 0
	 * dscp 16-31 -> TC 2, queue 0
	 * dscp 0-15  -> TC 3, queue 0
	 */
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  48, 0, 1, 0, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  32, 0, 1, 1, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  16, 0, 1, 2, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  0, 0, 1, 3, 0, debug);

	dp_test_qos_clear_counters("dp2T1", debug);
	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/*
	 * Send the packets with a source address that doesn't match class 1.
	 * This means that the packets will be processed by pipe 0.
	 */
	dp_test_qos_pkt_forw_test("dp2T1", 0, "3.3.3.11", "2.2.2.11",
				  48, 0, 0, 0, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "3.3.3.11", "2.2.2.11",
				  32, 0, 0, 1, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "3.3.3.11", "2.2.2.11",
				  16, 0, 0, 2, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "3.3.3.11", "2.2.2.11",
				  0, 0, 0, 3, 0, debug);

	dp_test_qos_clear_counters("dp2T1", debug);
	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * basic_dscp_map uses a non-default DSCP to TC/queue mapping so that all
 * 32 queues within the pipe get the opportunity to process packets.
 *
 * DSCPs 63-48 get spread evenly across the eight queues of TC 0
 * DSCPs 47-32 get spread evenly across the eight queues of TC 1
 * DSCPs 31-16 get spread evenly across the eight queues of TC 2
 * DSCPs 15-0 get spread evenly across the eight queues of TC 3
 *
 * DSCP->TC:WRR map for default: (dscp=d1d2)
 *
 *     d2 |    0    1    2    3    4    5    6    7    8    9
 *  d1    |
 *  ------+---------------------------------------------------
 *     0  |  3:7  3:7  3:6  3:6  3:5  3:5  3:4  3:4  3:3  3:3
 *     1  |  3:2  3:2  3:1  3:1  3:0  3:0  2:7  2:7  2:6  2:6
 *     2  |  2:5  2:5  2:4  2:4  2:3  2:3  2:2  2:2  2:1  2:1
 *     3  |  2:0  2:0  1:7  1:7  1:6  1:6  1:5  1:5  1:4  1:4
 *     4  |  1:3  1:3  1:2  1:2  1:1  1:1  1:0  1:0  0:7  0:7
 *     5  |  0:6  0:6  0:5  0:5  0:4  0:4  0:3  0:3  0:2  0:2
 *     6  |  0:1  0:1  0:0  0:0
 *
 * basic_dscp_map_cmds generate from:
 *
 *  set interfaces dataplane dp0s5 policy qos 'trunk-egress'
 *  set policy qos name trunk-egress shaper default 'global-profile-1'
 *  set policy qos profile global-profile-1 map dscp 0,1 to '31'
 *  set policy qos profile global-profile-1 map dscp 2,3 to '30'
 *  set policy qos profile global-profile-1 map dscp 4,5 to '29'
 *  set policy qos profile global-profile-1 map dscp 6,7 to '28'
 *  set policy qos profile global-profile-1 map dscp 8,9 to '27'
 *  set policy qos profile global-profile-1 map dscp 10,11 to '26'
 *  set policy qos profile global-profile-1 map dscp 12,13 to '25'
 *  set policy qos profile global-profile-1 map dscp 14,15 to '24'
 *  set policy qos profile global-profile-1 map dscp 16,17 to '23'
 *  set policy qos profile global-profile-1 map dscp 18,19 to '22'
 *  set policy qos profile global-profile-1 map dscp 20,21 to '21'
 *  set policy qos profile global-profile-1 map dscp 22,23 to '20'
 *  set policy qos profile global-profile-1 map dscp 24,25 to '19'
 *  set policy qos profile global-profile-1 map dscp 26,27 to '18'
 *  set policy qos profile global-profile-1 map dscp 28,29 to '17'
 *  set policy qos profile global-profile-1 map dscp 30,31 to '16'
 *  set policy qos profile global-profile-1 map dscp 32,33 to '15'
 *  set policy qos profile global-profile-1 map dscp 34,35 to '14'
 *  set policy qos profile global-profile-1 map dscp 36,37 to '13'
 *  set policy qos profile global-profile-1 map dscp 38,39 to '12'
 *  set policy qos profile global-profile-1 map dscp 40,41 to '11'
 *  set policy qos profile global-profile-1 map dscp 42,43 to '10'
 *  set policy qos profile global-profile-1 map dscp 44,45 to '9'
 *  set policy qos profile global-profile-1 map dscp 46,47 to '8'
 *  set policy qos profile global-profile-1 map dscp 48,49 to '7'
 *  set policy qos profile global-profile-1 map dscp 50,51 to '6'
 *  set policy qos profile global-profile-1 map dscp 52,53 to '5'
 *  set policy qos profile global-profile-1 map dscp 54,55 to '4'
 *  set policy qos profile global-profile-1 map dscp 56,57 to '3'
 *  set policy qos profile global-profile-1 map dscp 58,59 to '2'
 *  set policy qos profile global-profile-1 map dscp 60,61 to '1'
 *  set policy qos profile global-profile-1 map dscp 62,63 to '0'
 *  set policy qos profile global-profile-1 queue 0 traffic-class '0'
 *  set policy qos profile global-profile-1 queue 1 traffic-class '0'
 *  set policy qos profile global-profile-1 queue 2 traffic-class '0'
 *  set policy qos profile global-profile-1 queue 3 traffic-class '0'
 *  set policy qos profile global-profile-1 queue 4 traffic-class '0'
 *  set policy qos profile global-profile-1 queue 5 traffic-class '0'
 *  set policy qos profile global-profile-1 queue 6 traffic-class '0'
 *  set policy qos profile global-profile-1 queue 7 traffic-class '0'
 *  set policy qos profile global-profile-1 queue 8 traffic-class '1'
 *  set policy qos profile global-profile-1 queue 9 traffic-class '1'
 *  set policy qos profile global-profile-1 queue 10 traffic-class '1'
 *  set policy qos profile global-profile-1 queue 11 traffic-class '1'
 *  set policy qos profile global-profile-1 queue 12 traffic-class '1'
 *  set policy qos profile global-profile-1 queue 13 traffic-class '1'
 *  set policy qos profile global-profile-1 queue 14 traffic-class '1'
 *  set policy qos profile global-profile-1 queue 15 traffic-class '1'
 *  set policy qos profile global-profile-1 queue 16 traffic-class '2'
 *  set policy qos profile global-profile-1 queue 17 traffic-class '2'
 *  set policy qos profile global-profile-1 queue 18 traffic-class '2'
 *  set policy qos profile global-profile-1 queue 19 traffic-class '2'
 *  set policy qos profile global-profile-1 queue 20 traffic-class '2'
 *  set policy qos profile global-profile-1 queue 21 traffic-class '2'
 *  set policy qos profile global-profile-1 queue 22 traffic-class '2'
 *  set policy qos profile global-profile-1 queue 23 traffic-class '2'
 *  set policy qos profile global-profile-1 queue 24 traffic-class '3'
 *  set policy qos profile global-profile-1 queue 25 traffic-class '3'
 *  set policy qos profile global-profile-1 queue 26 traffic-class '3'
 *  set policy qos profile global-profile-1 queue 27 traffic-class '3'
 *  set policy qos profile global-profile-1 queue 28 traffic-class '3'
 *  set policy qos profile global-profile-1 queue 29 traffic-class '3'
 *  set policy qos profile global-profile-1 queue 30 traffic-class '3'
 *  set policy qos profile global-profile-1 queue 31 traffic-class '3'
 */

const char *basic_dscp_map_cmds[] = {
	"port subports 1 pipes 1 profiles 2 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"vlan 0 0",
	"profile 0 rate 1250000000 size 5000000 period 10",
	"profile 0 queue 0 rate 1250000000 size 5000000",
	"profile 0 queue 1 rate 1250000000 size 5000000",
	"profile 0 queue 2 rate 1250000000 size 5000000",
	"profile 0 queue 3 rate 1250000000 size 5000000",
	"profile 0 dscp 0 0x1f",
	"profile 0 dscp 1 0x1f",
	"profile 0 dscp 2 0x1b",
	"profile 0 dscp 3 0x1b",
	"profile 0 dscp 4 0x17",
	"profile 0 dscp 5 0x17",
	"profile 0 dscp 6 0x13",
	"profile 0 dscp 7 0x13",
	"profile 0 dscp 8 0xf",
	"profile 0 dscp 9 0xf",
	"profile 0 dscp 10 0xb",
	"profile 0 dscp 11 0xb",
	"profile 0 dscp 12 0x7",
	"profile 0 dscp 13 0x7",
	"profile 0 dscp 14 0x3",
	"profile 0 dscp 15 0x3",
	"profile 0 dscp 16 0x1e",
	"profile 0 dscp 17 0x1e",
	"profile 0 dscp 18 0x1a",
	"profile 0 dscp 19 0x1a",
	"profile 0 dscp 20 0x16",
	"profile 0 dscp 21 0x16",
	"profile 0 dscp 22 0x12",
	"profile 0 dscp 23 0x12",
	"profile 0 dscp 24 0xe",
	"profile 0 dscp 25 0xe",
	"profile 0 dscp 26 0xa",
	"profile 0 dscp 27 0xa",
	"profile 0 dscp 28 0x6",
	"profile 0 dscp 29 0x6",
	"profile 0 dscp 30 0x2",
	"profile 0 dscp 31 0x2",
	"profile 0 dscp 32 0x1d",
	"profile 0 dscp 33 0x1d",
	"profile 0 dscp 34 0x19",
	"profile 0 dscp 35 0x19",
	"profile 0 dscp 36 0x15",
	"profile 0 dscp 37 0x15",
	"profile 0 dscp 38 0x11",
	"profile 0 dscp 39 0x11",
	"profile 0 dscp 40 0xd",
	"profile 0 dscp 41 0xd",
	"profile 0 dscp 42 0x9",
	"profile 0 dscp 43 0x9",
	"profile 0 dscp 44 0x5",
	"profile 0 dscp 45 0x5",
	"profile 0 dscp 46 0x1",
	"profile 0 dscp 47 0x1",
	"profile 0 dscp 48 0x1c",
	"profile 0 dscp 49 0x1c",
	"profile 0 dscp 50 0x18",
	"profile 0 dscp 51 0x18",
	"profile 0 dscp 52 0x14",
	"profile 0 dscp 53 0x14",
	"profile 0 dscp 54 0x10",
	"profile 0 dscp 55 0x10",
	"profile 0 dscp 56 0xc",
	"profile 0 dscp 57 0xc",
	"profile 0 dscp 58 0x8",
	"profile 0 dscp 59 0x8",
	"profile 0 dscp 60 0x4",
	"profile 0 dscp 61 0x4",
	"profile 0 dscp 62 0x0",
	"profile 0 dscp 63 0x0",
	"profile 0 queue 0 wrr-weight 1 0",
	"profile 0 queue 0x4 wrr-weight 1 0",
	"profile 0 queue 0x8 wrr-weight 1 0",
	"profile 0 queue 0xc wrr-weight 1 0",
	"profile 0 queue 0x10 wrr-weight 1 0",
	"profile 0 queue 0x14 wrr-weight 1 0",
	"profile 0 queue 0x18 wrr-weight 1 0",
	"profile 0 queue 0x1c wrr-weight 1 0",
	"profile 0 queue 0x1 wrr-weight 1 0",
	"profile 0 queue 0x5 wrr-weight 1 0",
	"profile 0 queue 0x9 wrr-weight 1 0",
	"profile 0 queue 0xd wrr-weight 1 0",
	"profile 0 queue 0x11 wrr-weight 1 0",
	"profile 0 queue 0x15 wrr-weight 1 0",
	"profile 0 queue 0x19 wrr-weight 1 0",
	"profile 0 queue 0x1d wrr-weight 1 0",
	"profile 0 queue 0x2 wrr-weight 1 0",
	"profile 0 queue 0x6 wrr-weight 1 0",
	"profile 0 queue 0xa wrr-weight 1 0",
	"profile 0 queue 0xe wrr-weight 1 0",
	"profile 0 queue 0x12 wrr-weight 1 0",
	"profile 0 queue 0x16 wrr-weight 1 0",
	"profile 0 queue 0x1a wrr-weight 1 0",
	"profile 0 queue 0x1e wrr-weight 1 0",
	"profile 0 queue 0x3 wrr-weight 1 0",
	"profile 0 queue 0x7 wrr-weight 1 0",
	"profile 0 queue 0xb wrr-weight 1 0",
	"profile 0 queue 0xf wrr-weight 1 0",
	"profile 0 queue 0x13 wrr-weight 1 0",
	"profile 0 queue 0x17 wrr-weight 1 0",
	"profile 0 queue 0x1b wrr-weight 1 0",
	"profile 0 queue 0x1f wrr-weight 1 0",
	"pipe 0 0 0",
	"enable"
};

struct tc_queue_pair dscp_map[] = {
      /* tc  queue */
	{ 3, 7 },   /* DSCP = 0 */
	{ 3, 7 },
	{ 3, 6 },
	{ 3, 6 },
	{ 3, 5 },
	{ 3, 5 },
	{ 3, 4 },
	{ 3, 4 },
	{ 3, 3 },
	{ 3, 3 },
	{ 3, 2 },
	{ 3, 2 },
	{ 3, 1 },
	{ 3, 1 },
	{ 3, 0 },
	{ 3, 0 },   /* DSCP = 15 */
	{ 2, 7 },   /* DSCP = 16 */
	{ 2, 7 },
	{ 2, 6 },
	{ 2, 6 },
	{ 2, 5 },
	{ 2, 5 },
	{ 2, 4 },
	{ 2, 4 },
	{ 2, 3 },
	{ 2, 3 },
	{ 2, 2 },
	{ 2, 2 },
	{ 2, 1 },
	{ 2, 1 },
	{ 2, 0 },
	{ 2, 0 },   /* DSCP = 31 */
	{ 1, 7 },   /* DSCP = 32 */
	{ 1, 7 },
	{ 1, 6 },
	{ 1, 6 },
	{ 1, 5 },
	{ 1, 5 },
	{ 1, 4 },
	{ 1, 4 },
	{ 1, 3 },
	{ 1, 3 },
	{ 1, 2 },
	{ 1, 2 },
	{ 1, 1 },
	{ 1, 1 },
	{ 1, 0 },
	{ 1, 0 },   /* DSCP = 47 */
	{ 0, 7 },   /* DSCP = 48 */
	{ 0, 7 },
	{ 0, 6 },
	{ 0, 6 },
	{ 0, 5 },
	{ 0, 5 },
	{ 0, 4 },
	{ 0, 4 },
	{ 0, 3 },
	{ 0, 3 },
	{ 0, 2 },
	{ 0, 2 },
	{ 0, 1 },
	{ 0, 1 },
	{ 0, 0 },
	{ 0, 0 }    /* DSCP = 63 */
};

DP_START_TEST(qos_basic_ipv4, basic_dscp_map)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	uint dscp;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", basic_dscp_map_cmds, debug);

	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	for (dscp = 0; dscp < 64; dscp++) {
		/*
		 * Trunk interface = subport 0
		 * No QoS classification = pipe 0
		 * DSCP value determines TC and queue
		 */
		dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
					  dscp, 0, 0, dscp_map[dscp].tc,
					  dscp_map[dscp].queue, debug);

		/*
		 * dp_test_qos_pkt_forw_test expects to see only one
		 * packet processed by the expected subport/queue.
		 * Due to the DSCP mapping that we are using (two dscp values
		 * for each queue), we need to clear the counters after ever
		 * packet.
		 */
		dp_test_qos_clear_counters("dp2T1", debug);
		dp_test_qos_check_for_zero_counters("dp2T1", debug);
	}

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * basic_vlan_pkt_fwd is almost identical to basic_pkt_fwd, but this time we
 * also configure QoS on a vlan interface, and send packets over both the trunk
 * and vlan interfaces.  Packets over the trunk interface get processed by
 * subport 0, packets over the VLAN interface get processed by subport 1.
 *
 * basic_vlan_pkt_fwd_cmds generate from:
 *
 *  set interfaces dataplane dp0s5 policy qos 'trunk-policy'
 *  set interfaces dataplane dp0s5 vif 10 policy qos 'vlan-policy'
 *  set policy qos name trunk-policy shaper default 'global-profile-1'
 *  set policy qos name vlan-policy shaper default 'global-profile-1'
 *  set policy qos profile global-profile-1 bandwidth '100Mbit'
 */

const char *basic_vlan_pkt_fwd_cmds[] = {
	"port subports 2 pipes 1 profiles 3 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"vlan 0 0",
	"profile 0 rate 12500000 size 50000 period 10",
	"profile 0 queue 0 rate 12500000 size 50000",
	"profile 0 queue 1 rate 12500000 size 50000",
	"profile 0 queue 2 rate 12500000 size 50000",
	"profile 0 queue 3 rate 12500000 size 50000",
	"pipe 0 0 0",
	"subport 1 rate 1250000000 size 5000000 period 40",
	"subport 1 queue 0 rate 1250000000 size 5000000",
	"subport 1 queue 1 rate 1250000000 size 5000000",
	"subport 1 queue 2 rate 1250000000 size 5000000",
	"subport 1 queue 3 rate 1250000000 size 5000000",
	"vlan 10 1",
	"profile 0 rate 12500000 size 50000 period 10",
	"profile 0 queue 0 rate 12500000 size 50000",
	"profile 0 queue 1 rate 12500000 size 50000",
	"profile 0 queue 2 rate 12500000 size 50000",
	"profile 0 queue 3 rate 12500000 size 50000",
	"pipe 1 0 0",
	"enable"
};

DP_START_TEST(qos_basic_ipv4, basic_vlan_pkt_fwd)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up the VIF and its interface addresses */
	dp_test_intf_vif_create("dp2T1.10", "dp2T1", 10);
	dp_test_nl_add_ip_addr_and_connected("dp2T1.10", "3.3.3.3/24");
	dp_test_netlink_add_neigh("dp2T1.10", "3.3.3.11", "aa:bb:cc:dd:2:b1");

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", basic_vlan_pkt_fwd_cmds,
					debug);

	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/*
	 * Send some packets out of the trunk interface (subport 0)
	 * There is no QoS classification (pipe 0)
	 *
	 * QoS's default DSCP to TC/queue mapping is:
	 * dscp 48-63 -> TC 0, queue 0
	 * dscp 32-47 -> TC 1, queue 0
	 * dscp 16-31 -> TC 2, queue 0
	 * dscp 0-15  -> TC 3, queue 0
	 */
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  48, 0, 0, 0, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  32, 0, 0, 1, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  16, 0, 0, 2, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  0, 0, 0, 3, 0, debug);

	/* Zero the trunk interface counters */
	dp_test_qos_clear_counters("dp2T1", debug);
	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/*
	 * Send some packets out of the vlan interface (subport 1)
	 * There is no QoS classification (pipe 0)
	 *
	 * QoS's default DSCP to TC/queue mapping is:
	 * dscp 48-63 -> TC 0, queue 0
	 * dscp 32-47 -> TC 1, queue 0
	 * dscp 16-31 -> TC 2, queue 0
	 * dscp 0-15  -> TC 3, queue 0
	 */
	dp_test_qos_pkt_forw_test("dp2T1", 10, "1.1.1.11", "3.3.3.11",
				  48, 1, 0, 0, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 10, "1.1.1.11", "3.3.3.11",
				  32, 1, 0, 1, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 10, "1.1.1.11", "3.3.3.11",
				  16, 1, 0, 2, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 10, "1.1.1.11", "3.3.3.11",
				  0, 1, 0, 3, 0, debug);

	/* Zero the vlan interface counters */
	dp_test_qos_clear_counters("dp2T1.10", debug);
	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	/* Cleanup the VIF and its addresses */
	dp_test_nl_del_ip_addr_and_connected("dp2T1.10", "3.3.3.3/24");
	dp_test_netlink_del_neigh("dp2T1.10", "3.3.3.11", "aa:bb:cc:dd:2:b1");
	dp_test_intf_vif_del("dp2T1.10", 10);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * basic_pkt_remark uses classification to remark the DSCP value of some
 * packets so that they don't end up in the default queues.
 * Packets sent from 3.0.0.0/8 with a DSCP value of 63 get remarked as 31,
 * so rather than going through TC-0/WRR-queue-0 (default TC/Queue for DSCP 63)
 * they end up going through TC-2/WRR-queue-0.
 *
 * Packets sent from other source addresses with a DSCP value of 63 should
 * still go through TC-0/Queue-0
 *
 * basic_pkt_remark_cmds created from:
 *
 *   set interfaces dataplane dp0s5 policy qos 'trunk-egress'
 *   set policy qos name trunk shaper class 1 match 1 dscp '63'
 *   set policy qos name trunk shaper class 1 match 1 mark dscp '31'
 *   set policy qos name trunk shaper class 1 match 1 source address '3.0.0.0/8'
 *   set policy qos name trunk shaper class 1 profile 'profile-1'
 *   set policy qos name trunk shaper default 'profile-1'
 *   set policy qos name trunk shaper profile profile-1 bandwidth '100Mbit'
 */

const char *basic_pkt_remark_cmds[] = {
	"port subports 1 pipes 2 profiles 1 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"vlan 0 0",
	"profile 0 rate 12500000 size 50000 period 10",
	"profile 0 queue 0 rate 12500000 size 50000",
	"profile 0 queue 1 rate 12500000 size 50000",
	"profile 0 queue 2 rate 12500000 size 50000",
	"profile 0 queue 3 rate 12500000 size 50000",
	"pipe 0 0 0",
	"pipe 0 1 0",
	"match 0 1 action=accept src-addr=3.0.0.0/8 dscp=63 "
		"handle=tag(1) rproc=markdscp(31)",
	"enable"
};

DP_START_TEST(qos_basic_ipv4, basic_pkt_remark)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", basic_pkt_remark_cmds, debug);

	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/*
	 * Send some packets that should not get remarked
	 */
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  48, 0, 0, 0, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  32, 0, 0, 1, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  16, 0, 0, 2, 0, debug);
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  0, 0, 0, 3, 0, debug);

	dp_test_qos_clear_counters("dp2T1", debug);
	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/*
	 * Try a packet with a DSCP value of 63, but not from a 3.0.0.0/8
	 * address
	 */
	dp_test_qos_pkt_forw_test("dp2T1", 0, "1.1.1.11", "2.2.2.11",
				  63, 0, 0, 0, 0, debug);

	/*
	 * A packet from 3.0.0.0/8 with a DSCP of 63, this should be remarked
	 * as 31 and end up in pipe 1/TC-2/Queue-0
	 */
	dp_test_qos_pkt_remark_test("dp2T1", 0, "3.1.1.11", "2.2.2.11",
				    63, 31, 0, 1, 2, 0, debug);

	dp_test_qos_clear_counters("dp2T1", debug);
	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/*
	 * A packet from 3.0.0.0/8 with a DSCP of 62, this should not be
	 * remarked and should be processed by TC-0/Queue-0
	 */
	dp_test_qos_pkt_forw_test("dp2T1", 0, "3.1.1.11", "2.2.2.11",
				  62, 0, 0, 0, 0, debug);

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * basic_pkt_drop uses very small queue-limits in an attempt to get QoS to
 * tail-drop packets.  We queue enough packets on each queue to fill the queue
 * and then drop one packet.
 *
 * The UT libraries also have a limit of DP_TEST_MAX_EXPECTED_PAKS = 10
 *
 * basic_pkt_drop_cmds created from:
 *
 *   set interfaces dataplane dp0s5 policy qos 'trunk-policy'
 *   set policy qos name trunk-policy shaper default 'profile-1'
 *   set policy qos name trunk-policy shaper profile 'profile-1'
 *   set policy qos name trunk-policy shaper traffic-class 0 queue-limit '1'
 *   set policy qos name trunk-policy shaper traffic-class 1 queue-limit '2'
 *   set policy qos name trunk-policy shaper traffic-class 2 queue-limit '4'
 *   set policy qos name trunk-policy shaper traffic-class 3 queue-limit '8'
 */

const char *basic_pkt_drop_cmds[] = {
	"port subports 1 pipes 1 profiles 1 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"param 0 limit packets  1",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"param 1 limit packets 2",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"param 2 limit packets 4",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"param 3 limit packets 8",
	"vlan 0 0",
	"profile 0 rate 1250000000 size 5000000 period 10",
	"profile 0 queue 0 rate 1250000000 size 5000000",
	"profile 0 queue 1 rate 1250000000 size 5000000",
	"profile 0 queue 2 rate 1250000000 size 5000000",
	"profile 0 queue 3 rate 1250000000 size 5000000",
	"pipe 0 0 0",
	"enable"
};

DP_START_TEST(qos_basic_ipv4, basic_pkt_drop)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", basic_pkt_drop_cmds, debug);

	dp_test_qos_pkt_force_drop("dp2T1", 0, "1.1.1.11", "2.2.2.11", 63,
				   1, 0, 0, 0, 0, debug);

	dp_test_qos_pkt_force_drop("dp2T1", 0, "1.1.1.11", "2.2.2.11", 47,
				   2, 0, 0, 1, 0, debug);

	dp_test_qos_pkt_force_drop("dp2T1", 0, "1.1.1.11", "2.2.2.11", 31,
				   4, 0, 0, 2, 0, debug);

	dp_test_qos_pkt_force_drop("dp2T1", 0, "1.1.1.11", "2.2.2.11", 0,
				   8, 0, 0, 3, 0, debug);

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * vlan_subport_map checks that the vlan interfaces get associated with the
 * expected subport.
 *
 * vlan_subport_map_cmds created from:
 *
 *   set interfaces dataplane dp0s5 policy qos 'trunk-policy'
 *   set interfaces dataplane dp0s5 vif 10 policy qos 'vlan-policy-1'
 *   set interfaces dataplane dp0s5 vif 20 policy qos 'vlan-policy-2'
 *   set policy qos name trunk-policy shaper default 'profile-1'
 *   set policy qos name trunk-policy shaper profile 'profile-1'
 *   set policy qos name vlan-policy-1 shaper default 'profile-2'
 *   set policy qos name vlan-policy-1 shaper profile 'profile-2'
 *   set policy qos name vlan-policy-2 shaper default 'profile-3'
 *   set policy qos name vlan-policy-2 shaper profile 'profile-3'
 */

const char *vlan_subport_map_cmds[] = {
	"port subports 3 pipes 1 profiles 3 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"vlan 0 0",
	"profile 1 rate 1250000000 size 5000000 period 10",
	"profile 1 queue 0 rate 1250000000 size 5000000",
	"profile 1 queue 1 rate 1250000000 size 5000000",
	"profile 1 queue 2 rate 1250000000 size 5000000",
	"profile 1 queue 3 rate 1250000000 size 5000000",
	"pipe 0 0 1",
	"subport 1 rate 1250000000 size 5000000 period 40",
	"subport 1 queue 0 rate 1250000000 size 5000000",
	"subport 1 queue 1 rate 1250000000 size 5000000",
	"subport 1 queue 2 rate 1250000000 size 5000000",
	"subport 1 queue 3 rate 1250000000 size 5000000",
	"vlan 10 1",
	"profile 0 rate 1250000000 size 5000000 period 10",
	"profile 0 queue 0 rate 1250000000 size 5000000",
	"profile 0 queue 1 rate 1250000000 size 5000000",
	"profile 0 queue 2 rate 1250000000 size 5000000",
	"profile 0 queue 3 rate 1250000000 size 5000000",
	"pipe 1 0 0",
	"subport 2 rate 1250000000 size 5000000 period 40",
	"subport 2 queue 0 rate 1250000000 size 5000000",
	"subport 2 queue 1 rate 1250000000 size 5000000",
	"subport 2 queue 2 rate 1250000000 size 5000000",
	"subport 2 queue 3 rate 1250000000 size 5000000",
	"vlan 20 2",
	"profile 2 rate 1250000000 size 5000000 period 10",
	"profile 2 queue 0 rate 1250000000 size 5000000",
	"profile 2 queue 1 rate 1250000000 size 5000000",
	"profile 2 queue 2 rate 1250000000 size 5000000",
	"profile 2 queue 3 rate 1250000000 size 5000000",
	"pipe 2 0 2",
	"enable"
};

DP_START_TEST(qos_basic_ipv4, vlan_subport_map)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	bool rc;
	int subport_id;

	qos_lib_test_setup();

	/* Set up the VIFs and their interface addresses */
	dp_test_intf_vif_create("dp2T1.10", "dp2T1", 10);
	dp_test_nl_add_ip_addr_and_connected("dp2T1.10", "3.3.3.3/24");
	dp_test_netlink_add_neigh("dp2T1.10", "3.3.3.11", "aa:bb:cc:dd:2:b1");

	dp_test_intf_vif_create("dp2T1.20", "dp2T1", 20);
	dp_test_nl_add_ip_addr_and_connected("dp2T1.20", "4.4.4.4/24");
	dp_test_netlink_add_neigh("dp2T1.20", "4.4.4.11", "aa:bb:cc:dd:2:b1");

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", vlan_subport_map_cmds, debug);

	/* Check that the vlans get allocated to subport 1 and 2 */
	rc = dp_test_qos_get_json_vlan_subport("dp2T1", 10, &subport_id, debug);
	dp_test_fail_unless(rc && subport_id == 1,
			    "failed to get vlan subport for vlan-id 10\n");

	rc = dp_test_qos_get_json_vlan_subport("dp2T1", 20, &subport_id, debug);
	dp_test_fail_unless(rc && subport_id == 2,
			    "failed to get vlan subport for vlan-id 20\n");

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	/* Cleanup the VIF and its addresses */
	dp_test_nl_del_ip_addr_and_connected("dp2T1.10", "3.3.3.3/24");
	dp_test_netlink_del_neigh("dp2T1.10", "3.3.3.11", "aa:bb:cc:dd:2:b1");
	dp_test_intf_vif_del("dp2T1.10", 10);

	dp_test_nl_del_ip_addr_and_connected("dp2T1.20", "4.4.4.4/24");
	dp_test_netlink_del_neigh("dp2T1.20", "4.4.4.11", "aa:bb:cc:dd:2:b1");
	dp_test_intf_vif_del("dp2T1.20", 20);

	qos_lib_test_teardown();

} DP_END_TEST;

/*
 * npf_rules_checks sets up a couple of "match" rules and checks that op-mode
 * state returns the correct information for them.
 *
 * npf_rules_checks_cmds created from:
 *
 *   set interfaces dataplane dp0s5 policy qos 'trunk'
 *   set policy qos name trunk shaper class 1 match m1 source address
 *       '1.1.1.11/32'
 *   set policy qos name trunk shaper class 1 profile 'profile-1'
 *   set policy qos name trunk shaper class 2 match m2 destination address
 *       '2.2.2.11/32'
 *   set policy qos name trunk shaper class 2 match m2 destination port '999'
 *   set policy qos name trunk shaper class 2 match m2 protocol 'tcp'
 *   set policy qos name trunk shaper class 2 profile 'profile-2'
 *   set policy qos name trunk shaper default 'profile-0'
 *   set policy qos name trunk shaper profile profile-0 bandwidth '1Gbit'
 *   set policy qos name trunk shaper profile profile-1 bandwidth '500Mbit'
 *   set policy qos name trunk shaper profile profile-2 bandwidth '250Mbit'
 */

const char *npf_rules_check_cmds[] = {
	"port subports 1 pipes 3 profiles 3 overhead 24 ql_packets",
	"subport 0 rate 1250000000 size 5000000 period 40",
	"subport 0 queue 0 rate 1250000000 size 5000000",
	"subport 0 queue 1 rate 1250000000 size 5000000",
	"subport 0 queue 2 rate 1250000000 size 5000000",
	"subport 0 queue 3 rate 1250000000 size 5000000",
	"vlan 0 0",
	"profile 2 rate 31250000 size 125000 period 10",
	"profile 2 queue 0 rate 31250000 size 125000",
	"profile 2 queue 1 rate 31250000 size 125000",
	"profile 2 queue 2 rate 31250000 size 125000",
	"profile 2 queue 3 rate 31250000 size 125000",
	"profile 0 rate 125000000 size 500000 period 10",
	"profile 0 queue 0 rate 125000000 size 500000",
	"profile 0 queue 1 rate 125000000 size 500000",
	"profile 0 queue 2 rate 125000000 size 500000",
	"profile 0 queue 3 rate 125000000 size 500000",
	"profile 1 rate 62500000 size 250000 period 10",
	"profile 1 queue 0 rate 62500000 size 250000",
	"profile 1 queue 1 rate 62500000 size 250000",
	"profile 1 queue 2 rate 62500000 size 250000",
	"profile 1 queue 3 rate 62500000 size 250000",
	"pipe 0 0 0",
	"pipe 0 1 1",
	"match 0 1 action=accept src-addr=1.1.1.11/32 handle=tag(1)",
	"pipe 0 2 2",
	"match 0 2 action=accept proto=6 dst-addr=2.2.2.11/32 dst-port=999 "
		"handle=tag(2)",
	"enable"
};

DP_START_TEST(qos_basic_ipv4, npf_rules_check)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	json_object *j_obj;
	json_object *j_rule;
	bool rc;

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", npf_rules_check_cmds, debug);

	j_obj = dp_test_qos_get_json_groups_rules("dp2T1", 0, debug);
	rc = json_object_object_get_ex(j_obj, "1", &j_rule);
	dp_test_fail_unless(rc, "failed to get rule '1'\n");
	dp_test_qos_check_rule(j_rule, "pass",
			       "action=accept src-addr=1.1.1.11/32 "
			       "handle=tag(1)",
			       "from 1.1.1.11/32", "apply tag(1)",
			       0, 0, debug);

	rc = json_object_object_get_ex(j_obj, "2", &j_rule);
	dp_test_fail_unless(rc, "failed to get rule '2'\n");
	dp_test_qos_check_rule(j_rule, "pass",
			       "action=accept proto=6 dst-addr=2.2.2.11/32 "
			       "dst-port=999 handle=tag(2)",
			       "proto 6 to 2.2.2.11/32 port 999",
			       "apply tag(2)", 0, 0, debug);
	json_object_put(j_obj);

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;
