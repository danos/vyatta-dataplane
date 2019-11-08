/*-
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <stdbool.h>

#include <netinet/in.h>
#include <linux/xfrm.h>
#include <arpa/inet.h>

#include "ip_funcs.h"

#include "dp_test.h"
#include "dp_test_lib.h"
#include "dp_test_macros.h"
#include "dp_test_lib_intf.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_crypto_utils.h"
#include "dp_test_netlink_state.h"

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
#define TUN_1_LOCAL_PREFIX "1.1.1.0/24"
#define TUN_1_REMOTE_PREFIX "8.8.8.0/24"
#define TUN_1_SINK_IP_ADDR  "8.8.8.8"
#define TUN_1_IN_SA_SPI   0x22223333
#define TUN_1_OUT_SA_SPI  0x33332222
#define TUN_1_REQID       0x1111

#define TUN_1_EXTRA_OUT_SA_SPI 0x10002000

/*
 * Tunnel 1 IPsec policies and SAs
 *
 *   1.1.1.0/2 -[2.2.2.2]========[2.2.2.3] -- 8.8.8.0/24
 */
static const struct dp_test_crypto_policy tun_1_in_policy = {
	.d_prefix = TUN_1_LOCAL_PREFIX,
	.s_prefix = TUN_1_REMOTE_PREFIX,
	.proto = 0,
	.dst = TUN_1_LOCAL_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUN_1_REQID,
	.priority = 1000,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_policy tun_1_out_policy = {
	.d_prefix = TUN_1_REMOTE_PREFIX,
	.s_prefix = TUN_1_LOCAL_PREFIX,
	.proto = 0,
	.dst = TUN_1_REMOTE_IP_ADDR,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUN_1_REQID,
	.priority = 1000,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_1_in_sa = {
	.spi = TUN_1_IN_SA_SPI,
	.d_addr = TUN_1_LOCAL_IP_ADDR,
	.s_addr = TUN_1_REMOTE_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_1_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_1_out_sa = {
	.spi = TUN_1_OUT_SA_SPI,
	.d_addr = TUN_1_REMOTE_IP_ADDR,
	.s_addr = TUN_1_LOCAL_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_1_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static const struct dp_test_crypto_sa tun_1_extra_out_sa = {
	.spi = TUN_1_EXTRA_OUT_SA_SPI,
	.d_addr = TUN_1_REMOTE_IP_ADDR,
	.s_addr = TUN_1_LOCAL_IP_ADDR,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUN_1_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

DP_DECL_TEST_SUITE(crypto_policy_suite);

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

DP_DECL_TEST_CASE(crypto_policy_suite, crypto_policy, NULL, NULL);

/*
 * TESTCASE: Simple policy update
 *
 * This test exercises the scenario when a policy is
 * updated and caused a list corruption leading to an infinite loop
 * when a new entry is subsequently created for the policy.
 */
DP_START_TEST(crypto_policy, simple_policy_update)
{
	setup(VRF_DEFAULT_ID);

	dp_test_crypto_create_policy(&tun_1_in_policy);
	dp_test_crypto_create_policy(&tun_1_out_policy);

	dp_test_crypto_create_sa(&tun_1_in_sa);
	dp_test_crypto_create_sa(&tun_1_out_sa);

	dp_test_crypto_update_policy(&tun_1_out_policy);

	dp_test_crypto_create_sa(&tun_1_extra_out_sa);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 3);

	dp_test_crypto_delete_sa(&tun_1_in_sa);
	dp_test_crypto_delete_sa(&tun_1_out_sa);
	dp_test_crypto_delete_sa(&tun_1_extra_out_sa);

	/* Tear down Tunnel 1 */
	dp_test_crypto_delete_policy(&tun_1_in_policy);
	dp_test_crypto_delete_policy(&tun_1_out_policy);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);

	teardown(VRF_DEFAULT_ID);
} DP_END_TEST;

/*
 * TESTCASE: Update policy action
 *
 * This tests that a policy can be created with an action
 * of block, updated to change the action to allow and then
 * back to block.
 */
DP_START_TEST(crypto_policy, update_policy_action)
{
	static struct dp_test_crypto_policy the_policy = {
		.d_prefix = "16.1.2.0/24",
		.s_prefix = "16.1.3.0/24",
		.proto = 0,
		.dst = "172.24.24.1",
		.dst_family = AF_INET,
		.dir = XFRM_POLICY_OUT,
		.action = XFRM_POLICY_BLOCK,
		.family = AF_INET,
		.reqid = 1234,
		.priority = 1000,
		.mark = 0,
		.vrfid = VRF_DEFAULT_ID
	};

	setup(VRF_DEFAULT_ID);
	dp_test_crypto_create_policy(&the_policy);

	/*
	 * Change the policy to ALLOW and check the
	 * update is reflected in the dataplane state.
	 */
	the_policy.action = XFRM_POLICY_ALLOW;
	the_policy.priority = 1400;
	dp_test_crypto_update_policy(&the_policy);

	/*
	 * Change the policy back to BLOCK and check
	 * the dataplane state again.
	 */
	the_policy.action = XFRM_POLICY_BLOCK;
	the_policy.priority = 1000;
	dp_test_crypto_update_policy(&the_policy);

	dp_test_crypto_delete_policy(&the_policy);
	teardown(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(crypto_policy, update_policy_action_vrf)
{
	static struct dp_test_crypto_policy the_policy = {
		.d_prefix = "16.1.2.0/24",
		.s_prefix = "16.1.3.0/24",
		.proto = 0,
		.dst = "172.24.24.1",
		.dst_family = AF_INET,
		.dir = XFRM_POLICY_OUT,
		.action = XFRM_POLICY_BLOCK,
		.family = AF_INET,
		.reqid = 1234,
		.priority = 1000,
		.mark = 0,
		.vrfid = TEST_VRF
	};

	setup(TEST_VRF);

	dp_test_crypto_create_policy(&the_policy);

	/*
	 * Change the policy to ALLOW and check the
	 * update is reflected in the dataplane state.
	 */
	the_policy.action = XFRM_POLICY_ALLOW;
	the_policy.priority = 1400;
	dp_test_crypto_update_policy(&the_policy);

	/*
	 * Change the policy back to BLOCK and check
	 * the dataplane state again.
	 */
	the_policy.action = XFRM_POLICY_BLOCK;
	the_policy.priority = 1000;
	dp_test_crypto_update_policy(&the_policy);

	dp_test_crypto_delete_policy(&the_policy);

	teardown(TEST_VRF);
} DP_END_TEST;
