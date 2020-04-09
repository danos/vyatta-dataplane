/**
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
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

DP_DECL_TEST_SUITE(qos_burst);

DP_DECL_TEST_CASE(qos_burst, qos_burst1, NULL, NULL);

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
 * set policy qos name 50M shaper default NO_COS_PROFILE_50M
 * set policy qos name 50M shaper frame-overhead 28
 * set policy qos name 50M shaper profile NO_COS_PROFILE_50M bandwidth 50000kbit
 * set policy qos name 50M shaper profile NO_COS_PROFILE_50M burst 6250
 * set policy qos name 50M shaper profile NO_COS_PROFILE_50M map dscp 0-63 to 24
 * set policy qos name 50M shaper profile NO_COS_PROFILE_50M queue 24 traffic-class 3
 * set policy qos name 50M shaper traffic-class 3 queue-limit 1024
 *
 * The above cli config would be translated into the following set of
 * commands from vplaned.
 */
const char *burst_cmds[] = {
	"port subports 1 pipes 1 profiles 1 overhead 28 ql_packets",
	"subport 0 rate 1250000000 size 0 period 40",
	"subport 0 queue 0 percent 100 size 0",
	"param subport 0 0 limit packets 64",
	"subport 0 queue 1 percent 100 size 0",
	"param subport 0 1 limit packets 64",
	"subport 0 queue 2 percent 100 size 0",
	"param subport 0 2 limit packets 64",
	"subport 0 queue 3 percent 100 size 0",
	"param subport 0 3 limit packets 1024",
	"vlan 0 0",
	"profile 0 rate 6250000 size 6250 period 10",
	"profile 0 queue 0 percent 100 size 0",
	"profile 0 queue 1 percent 100 size 0",
	"profile 0 queue 2 percent 100 size 0",
	"profile 0 queue 3 percent 100 size 0",
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
	"profile 0 dscp 16 0x3",
	"profile 0 dscp 17 0x3",
	"profile 0 dscp 18 0x3",
	"profile 0 dscp 19 0x3",
	"profile 0 dscp 20 0x3",
	"profile 0 dscp 21 0x3",
	"profile 0 dscp 22 0x3",
	"profile 0 dscp 23 0x3",
	"profile 0 dscp 24 0x3",
	"profile 0 dscp 25 0x3",
	"profile 0 dscp 26 0x3",
	"profile 0 dscp 27 0x3",
	"profile 0 dscp 28 0x3",
	"profile 0 dscp 29 0x3",
	"profile 0 dscp 30 0x3",
	"profile 0 dscp 31 0x3",
	"profile 0 dscp 32 0x3",
	"profile 0 dscp 33 0x3",
	"profile 0 dscp 34 0x3",
	"profile 0 dscp 35 0x3",
	"profile 0 dscp 36 0x3",
	"profile 0 dscp 37 0x3",
	"profile 0 dscp 38 0x3",
	"profile 0 dscp 39 0x3",
	"profile 0 dscp 40 0x3",
	"profile 0 dscp 41 0x3",
	"profile 0 dscp 42 0x3",
	"profile 0 dscp 43 0x3",
	"profile 0 dscp 44 0x3",
	"profile 0 dscp 45 0x3",
	"profile 0 dscp 46 0x3",
	"profile 0 dscp 47 0x3",
	"profile 0 dscp 48 0x3",
	"profile 0 dscp 49 0x3",
	"profile 0 dscp 50 0x3",
	"profile 0 dscp 51 0x3",
	"profile 0 dscp 52 0x3",
	"profile 0 dscp 53 0x3",
	"profile 0 dscp 54 0x3",
	"profile 0 dscp 55 0x3",
	"profile 0 dscp 56 0x3",
	"profile 0 dscp 57 0x3",
	"profile 0 dscp 58 0x3",
	"profile 0 dscp 59 0x3",
	"profile 0 dscp 60 0x3",
	"profile 0 dscp 61 0x3",
	"profile 0 dscp 62 0x3",
	"profile 0 dscp 63 0x3",
	"profile 0 queue 0x3 wrr-weight 1 24",
	"pipe 0 0 0",
	"enable"
};

static void _dp_test_qos_burst_send(int count, bool wait,
				    const char *file,
				    const char *func, int line)
{
	struct rte_mbuf *test_pak;
	struct dp_test_pkt_desc_t v4_pkt_desc = {
		.text       = "TCP IPv4",
		.len        = 458, /* gives 512 byte packets */
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1000,
				.dport = 1001,
				.flags = 0
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	int i;

	for (i = 0; i < count; i++) {
		test_pak = dp_test_v4_pkt_from_desc(&v4_pkt_desc);
		dp_test_pak_add_to_ring("dp1T0", &test_pak, 1, false);
	}
}

#define dp_test_qos_burst_send(count, wait)	     \
	_dp_test_qos_burst_send(count, wait, \
				__FILE__, __func__, __LINE__)

/* Get packets from the receive ring and free them */
static int dp_test_qos_burst_receive(const char *if_name)
{
	struct rte_mbuf *bufs[64];
	int count;
	int i;

	count = dp_test_pak_get_from_ring("dp2T1",
					  &bufs[0],
					  64);
	for (i = 0; i < count; i++)
		rte_pktmbuf_free(bufs[i]);

	return count;
}

/*
 * We want to simulate the following setup:
 * A 50mbit shaper, with a 6520 byte burst per m/s burst
 * A queue of 1024 packets.
 *
 * This is what the burst_cmds above give us.
 *
 * Qos expects 24 bytes other than IP + payload
 *
 * 50000000 == circuit speed
 *
 * Sending packets at 99.5% of the circuit speed:
 * 49500000 == offered load (99.5%)
 * 49500000/8 = 6187500  bytes per sec
 * 6187500/512 + 24 = 11543 pps
 * 11543 pps = 86.6325 usec per packet.
 *
 * 11543 *15  = 173145 pkts in 15 secs.
 */
DP_START_TEST_DONT_RUN(qos_burst1, qos_burst1)
{
	bool debug = (dp_test_debug_get() == 2 ? true : false);
	int received = 0;
	int sent = 0;
	int sleep_count = 0;
	struct timeval start, now, diff;
	float time_diff_usec;
	float time_per_pak = 86.6325;
	int total_to_send = 173145;
	int should_have_sent;
	int to_send;
	int sent_burst_sizes[33] = { 0 };

	qos_lib_test_setup();

	dp_test_qos_debug(debug);

	/* Set up QoS config on dp2T1 */
	dp_test_qos_attach_config_to_if("dp2T1", burst_cmds, debug);

	dp_test_qos_check_for_zero_counters("dp2T1", debug);

	/* Send packets - but with no verify for speed */
	gettimeofday(&start, NULL);
	while (true) {
		/*
		 * Spin round sending packets, trying to make sure
		 * that we average them out at the required speed.
		 */
		gettimeofday(&now, NULL);
		timersub(&now, &start, &diff);
		time_diff_usec = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
		should_have_sent = (int)(time_diff_usec / time_per_pak);

		to_send = should_have_sent - sent;
		if (to_send) {
			if (to_send > 32) {
				dp_test_qos_burst_send(32, false);
				sent += 32;
				sent_burst_sizes[32]++;
			} else {
				dp_test_qos_burst_send(to_send, false);
				sent += to_send;
				sent_burst_sizes[to_send]++;
			}
		}
		received += dp_test_qos_burst_receive("dp2T1");

		if (sent >= total_to_send)
			break;
	}

	while (sent != received && sleep_count < 100000) {
		received += dp_test_qos_burst_receive("dp2T1");
		usleep(1);
		sleep_count++;
	}

	/* And fail if there are any drops */
	dp_test_fail_unless(received == sent,
			    "wrong counts:  sent %d rx %d  missing %d",
			    sent, received, sent - received);

	/* Cleanup */
	dp_test_qos_delete_config_from_if("dp2T1", debug);
	dp_test_qos_debug(false);

	qos_lib_test_teardown();

} DP_END_TEST;
