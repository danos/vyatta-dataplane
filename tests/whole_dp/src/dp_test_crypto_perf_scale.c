/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Measure performance of IPsec tunnel setup
 */
#include <stdbool.h>

#include <netinet/in.h>
#include <linux/xfrm.h>
#include <arpa/inet.h>

#include "ip_funcs.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test/dp_test_lib_intf.h"
#include "dp_test/dp_test_pktmbuf_lib.h"
#include "dp_test/dp_test_crypto_utils.h"
#include "dp_test/dp_test_netlink_state.h"
#include "dp_test_npf_lib.h"

#include "dp_test_console.h"

/*
 *                    +-----------+
 *                    |           |
 *             dp1T1  |           |  dp2T2
 *                    |           |
 *              +-----+    UUT    +-----+  2.2.2.2/24
 *                    |           |
 *        1.1.1.2/24  |           |
 *                    |           |
 *                    +-----------+
 */

#define TEST_VRF 42
#define SOURCE_IP_ADDR  "1.1.1.1"
#define SOURCE_MAC_ADDR "aa:bb:cc:dd:1:1"

/*
 * Tunnel 1 parameters
 */
#define TUN_1_LOCAL_IP_ADDR   "2.2.2.2"
#define TUN_1_REMOTE_IP_ADDR  "2.2.2.3"
#define TUN_1_REMOTE_MAC_ADDR "aa:bb:cc:dd:2:3"
#define TUN_1_LOCAL_PREFIX "1.%d.%d.0/24"
#define TUN_1_REMOTE_PREFIX "8.%d.%d.0/24"
#define TUN_1_SINK_IP_ADDR  "8.8.8.8"
#define TUN_1_IN_SA_SPI   0x22223333
#define TUN_1_OUT_SA_SPI  0x33332222
#define TUN_1_REQID_START 0x1111

#define TUN_1_EXTRA_OUT_SA_SPI 0x10002000

/*
 * Tunnel 1 IPsec policies and SAs
 *
 *   1.1.1.0/2 -[2.2.2.2]========[2.2.2.3] -- 8.8.8.0/24
 */
static struct dp_test_crypto_policy tun_1_in_policy = {
	.d_prefix = TUN_1_LOCAL_PREFIX,
	.s_prefix = TUN_1_REMOTE_PREFIX,
	.proto = 0,
	.dst = TUN_1_LOCAL_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUN_1_REQID_START,
	.priority = 1000,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy tun_1_out_policy = {
	.d_prefix = TUN_1_REMOTE_PREFIX,
	.s_prefix = TUN_1_LOCAL_PREFIX,
	.proto = 0,
	.dst = TUN_1_REMOTE_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUN_1_REQID_START,
	.priority = 1000,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

DP_DECL_TEST_SUITE(crypto_perf_scale_suite);

/*
 * setup()
 *
 * Setup the interfaces, address and ARP neighbours which are common
 * to all test cases in this module.
 */
static void setup(vrfid_t vrfid)
{
	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Set up local addresses and ARP cache entries for neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "1.1.1.0/24", vrfid);
	dp_test_netlink_add_neigh("dp1T1", SOURCE_IP_ADDR, SOURCE_MAC_ADDR);

	dp_test_nl_add_ip_addr_and_connected_vrf("dp2T2", "2.2.2.0/24", vrfid);
	dp_test_netlink_add_neigh("dp2T2", TUN_1_REMOTE_IP_ADDR,
				  TUN_1_REMOTE_MAC_ADDR);
}

static void setup_or_teardown_tunnels(uint32_t tunnel_cnt, bool setup)
{
#define PREFIX_SIZE 20
	char local_prefix[PREFIX_SIZE];
	char remote_prefix[PREFIX_SIZE];
	uint8_t i, j;
	uint32_t reqid = TUN_1_REQID_START;
	uint32_t rule_no = 0;
	struct timespec start, end;
	uint64_t ptime = 0;
	uint32_t outer = tunnel_cnt / 253;
	uint32_t inner = 253;
	uint64_t cur_cnt;

	if (tunnel_cnt < 253) {
		outer = 1;
		inner = tunnel_cnt;
	}

	clock_gettime(CLOCK_REALTIME, &start);

	cur_cnt = 0;
	for (i = 1; i <= outer; i++) {
		for (j = 1; j <= inner; j++) {
			snprintf(local_prefix, PREFIX_SIZE,
				 TUN_1_LOCAL_PREFIX, i, j);
			snprintf(remote_prefix, PREFIX_SIZE,
				 TUN_1_REMOTE_PREFIX, i, j);
			tun_1_in_policy.s_prefix = remote_prefix;
			tun_1_in_policy.d_prefix = local_prefix;
			tun_1_in_policy.reqid = reqid;
			tun_1_in_policy.rule_no = ++rule_no;

			tun_1_out_policy.s_prefix = local_prefix;
			tun_1_out_policy.d_prefix = remote_prefix;
			tun_1_out_policy.reqid = reqid++;
			tun_1_out_policy.rule_no = ++rule_no;

			if (setup) {
				dp_test_crypto_create_policy_verify(
					&tun_1_in_policy, false);
				dp_test_crypto_create_policy_verify(
					&tun_1_out_policy, false);
			} else {
				dp_test_crypto_delete_policy_verify(
					&tun_1_in_policy, false);
				dp_test_crypto_delete_policy_verify(
					&tun_1_out_policy, false);
			}
		}
		cur_cnt += inner * 2;
	}

	clock_gettime(CLOCK_REALTIME, &end);
	ptime = timespec_diff_us(&start, &end);
	printf("Time taken to request %s of %lu policies = %lu us\n",
	       setup ? "creation" : "deletion", cur_cnt, ptime);

	dp_test_crypto_check_policy_count(VRF_DEFAULT_ID,
					  setup ? cur_cnt : 0, AF_INET);

	if (setup)
		dp_test_npf_cleanup();

	clock_gettime(CLOCK_REALTIME, &end);
	ptime = timespec_diff_us(&start, &end);
	printf("Time taken to %s %lu policies = %lu us\n",
	       setup ? "install" : "delete", cur_cnt, ptime);
}

/*
 * teardown()
 *
 * Tear down the interfaces, address and ARP neighbours which are common
 * to all test cases in this module.
 */
static void teardown(vrfid_t vrfid)
{
	/* Remove local addresses and ARP cache entries for neighbours */
	dp_test_netlink_del_neigh("dp2T2", TUN_1_REMOTE_IP_ADDR,
				  TUN_1_REMOTE_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp2T2", "2.2.2.0/24", vrfid);
	dp_test_netlink_del_neigh("dp1T1", SOURCE_IP_ADDR, SOURCE_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "1.1.1.0/24", vrfid);

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);
}

DP_DECL_TEST_CASE(crypto_perf_scale_suite, crypto_policy_scale, NULL, NULL);

/*
 * TESTCASE: Policy scale
 *
 * This testcase tests the amount of time taken to build a set of policies
 * incrementally.
 */
DP_START_TEST_FULL_RUN(crypto_policy_scale, policy_update_scale)
{
	bool debug = false;

	if (debug)
		dp_test_console_request_reply("debug rldb-acl", true);

#define MAX_TUNNEL_CNT 64
	setup(VRF_DEFAULT_ID);

	setup_or_teardown_tunnels(MAX_TUNNEL_CNT, true);
	setup_or_teardown_tunnels(MAX_TUNNEL_CNT, false);

	teardown(VRF_DEFAULT_ID);

} DP_END_TEST;

