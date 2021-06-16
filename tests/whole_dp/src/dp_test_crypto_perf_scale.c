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

#define NETWORK_BASE_OUT_ADDR 0x14000000
#define NETWORK_BASE_IN_ADDR 0x15000000

/*
 * Tunnel 1 parameters
 */
#define TUN_1_LOCAL_IP_ADDR   "2.2.2.2"
#define TUN_1_REMOTE_IP_ADDR  "2.2.2.3"
#define TUN_1_REMOTE_MAC_ADDR "aa:bb:cc:dd:2:3"
#define TUN_1_REQID_START 0x1111

#define TUN_1_EXTRA_OUT_SA_SPI 0x10002000

/*
 * Tunnel 1 IPsec policies and SAs
 *
 *   1.1.1.0/2 -[2.2.2.2]========[2.2.2.3] -- 8.8.8.0/24
 */
static struct dp_test_crypto_policy tun_1_in_policy = {
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

static void setup_or_teardown_tunnels(uint32_t tunnel_cnt,
				      uint32_t policy_batch_size, bool setup)
{
#define PREFIX_SIZE 20
	char local_prefix[PREFIX_SIZE];
	char remote_prefix[PREFIX_SIZE];
	char ip_peer_addr_str[INET_ADDRSTRLEN];
	uint32_t i;
	uint32_t tmp_ip;
	uint32_t ip_peer_addr_out = NETWORK_BASE_OUT_ADDR;
	uint32_t ip_peer_addr_in = NETWORK_BASE_IN_ADDR;
	uint32_t reqid = TUN_1_REQID_START;
	uint32_t rule_no = 0;
	struct timespec total_start, start, end;
	uint64_t ptime = 0;
	uint64_t cur_cnt, batch_cnt = 0;
	bool do_commit = false;

	clock_gettime(CLOCK_REALTIME, &total_start);
	clock_gettime(CLOCK_REALTIME, &start);

	cur_cnt = 0;
	for (i = 0; i < tunnel_cnt; i++) {
		tmp_ip = htonl(ip_peer_addr_in++);
		if (!inet_ntop(AF_INET, &tmp_ip,
			       ip_peer_addr_str, INET_ADDRSTRLEN))
			assert(0);
		snprintf(local_prefix, sizeof(local_prefix), "%s/%u",
			 ip_peer_addr_str, 32);

		tmp_ip = htonl(ip_peer_addr_out++);
		if (!inet_ntop(AF_INET, &tmp_ip,
			       ip_peer_addr_str, INET_ADDRSTRLEN))
			assert(0);
		snprintf(remote_prefix, sizeof(remote_prefix), "%s/%u",
			 ip_peer_addr_str, 32);

		tun_1_in_policy.s_prefix = remote_prefix;
		tun_1_in_policy.d_prefix = local_prefix;
		tun_1_in_policy.reqid = reqid;
		tun_1_in_policy.rule_no = ++rule_no;

		tun_1_out_policy.s_prefix = local_prefix;
		tun_1_out_policy.d_prefix = remote_prefix;
		tun_1_out_policy.reqid = reqid++;
		tun_1_out_policy.rule_no = ++rule_no;

		cur_cnt += 2;

		if (i == tunnel_cnt-1 || cur_cnt % policy_batch_size == 0)
			do_commit = true;
		else
			do_commit = false;

		if (setup) {
			dp_test_crypto_create_policy_commit(
				&tun_1_in_policy, false);
			dp_test_crypto_create_policy_commit(
				&tun_1_out_policy, do_commit);
		} else {
			dp_test_crypto_delete_policy_commit(
				&tun_1_in_policy, false);
			dp_test_crypto_delete_policy_commit(
				&tun_1_out_policy, do_commit);
		}

		if (do_commit) {
			clock_gettime(CLOCK_REALTIME, &end);
			ptime = timespec_diff_us(&start, &end);
			printf("Time taken to %s %u/%lu policies (batch #%lu) = %lu us\n",
			       setup ? "create" : "delete",
			       policy_batch_size, cur_cnt,
			       ++batch_cnt, ptime);
			clock_gettime(CLOCK_REALTIME, &start);
		}
	}


	dp_test_crypto_check_policy_count(VRF_DEFAULT_ID,
					  setup ? cur_cnt : 0, AF_INET);

	if (setup)
		dp_test_npf_cleanup();

	clock_gettime(CLOCK_REALTIME, &end);
	ptime = timespec_diff_us(&total_start, &end);
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

#define POLICY_BATCH_SIZE 512
#define MAX_TUNNEL_CNT (1 << 13)
	setup(VRF_DEFAULT_ID);

	setup_or_teardown_tunnels(MAX_TUNNEL_CNT, POLICY_BATCH_SIZE, true);
	setup_or_teardown_tunnels(MAX_TUNNEL_CNT, POLICY_BATCH_SIZE, false);

	teardown(VRF_DEFAULT_ID);

} DP_END_TEST;

