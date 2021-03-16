/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Cross connect tests
 */
#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_controller.h"
#include "dp_test_json_utils.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"


#include "protobuf/XConnectConfig.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

DP_DECL_TEST_SUITE(xconnect);

DP_DECL_TEST_CASE(xconnect, xconnect_switching, NULL, NULL);

static void
_dp_test_wait_for_xconnect(const char *src_intf, const char *dst_intf,
			   bool gone, const char *file,
			   const char *func, int line)
{
	json_object *expected_json;
	char real_ifname_src[IFNAMSIZ];
	char real_ifname_dst[IFNAMSIZ];

	dp_test_intf_real(src_intf, real_ifname_src);
	dp_test_intf_real(dst_intf, real_ifname_dst);

	expected_json = dp_test_json_create(
		"{"
		"  \"xconn\":"
		"  ["
		"    { "
		"      \"local_ifname\": \"%s\", "
		"      \"peer_ifname\": \"%s\""
		"    }"
		"  ]"
		"}",
		real_ifname_src, real_ifname_dst);
	_dp_test_check_json_state("pipeline xconnect cmd -s", expected_json,
				  NULL, DP_TEST_JSON_CHECK_SUBSET,
				  gone, file, func, line);
	json_object_put(expected_json);
}

#define dp_test_wait_for_xconnect(src_intf, dst_intf)		\
	_dp_test_wait_for_xconnect(src_intf, dst_intf, false,	\
				  __FILE__, __func__, __LINE__)

#define dp_test_wait_for_xconnect_gone(src_intf, dst_intf)	\
	_dp_test_wait_for_xconnect(src_intf, dst_intf, true,	\
				  __FILE__, __func__, __LINE__)

static void
dp_test_create_and_send_xconnect_msg(const XConnectConfig__CommandType cmd,
				     const char *dp_ifname,
				     const char *new_ifname)
{
	int len;
	XConnectConfig xcon = XCONNECT_CONFIG__INIT;
	xcon.has_cmd = true;
	xcon.cmd = cmd;
	xcon.dp_ifname = (char *)dp_ifname;
	xcon.new_ifname = (char *)new_ifname;

	len = xconnect_config__get_packed_size(&xcon);
	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	xconnect_config__pack(&xcon, buf2);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:xconnect", buf2, len);
}

static void
dp_test_execute(const XConnectConfig__CommandType cmd,
		const char *intf1,
		const char *intf2)
{
	char real_ifname_src[IFNAMSIZ];
	char real_ifname_dst[IFNAMSIZ];

	dp_test_create_and_send_xconnect_msg(
		cmd,
		dp_test_intf_real(intf1, real_ifname_src),
		dp_test_intf_real(intf2, real_ifname_dst));
}

DP_START_TEST(xconnect_switching, xconnect_switching1)
{
	const char *mac_a = "00:00:a4:00:00:aa";
	const char *mac_b = "00:00:a4:00:00:bb";
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 64;

	dp_test_execute(XCONNECT_CONFIG__COMMAND_TYPE__ADD, "dp1T0", "dp2T0");
	dp_test_wait_for_xconnect("dp1T0", "dp2T0");

	/* Now send a packet */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
					 1, &len);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T0");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/*
	 * Send a packet in reverse direction, should be dropped since
	 * not for-us and xconnect config is undirectional.
	 */
	test_pak = dp_test_create_l2_pak(mac_b, mac_a, DP_TEST_ET_LLDP,
						1, &len);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_pak_receive(test_pak, "dp2T0", exp);

	/* Clean up */

	dp_test_execute(XCONNECT_CONFIG__COMMAND_TYPE__REMOVE,
			"dp1T0", "dp2T0");
	dp_test_wait_for_xconnect_gone("dp1T0", "dp2T0");

	/* Now the other way */

	dp_test_execute(XCONNECT_CONFIG__COMMAND_TYPE__ADD,
			"dp2T0", "dp1T0");
	dp_test_wait_for_xconnect("dp2T0", "dp1T0");

	/* Now send a packet */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
					 1, &len);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T0");
	dp_test_pak_receive(test_pak, "dp2T0", exp);

	/*
	 * Send a packet in reverse direction, should be dropped since
	 * not for-us and xconnect config is undirectional.
	 */
	test_pak = dp_test_create_l2_pak(mac_b, mac_a, DP_TEST_ET_LLDP,
					 1, &len);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_exp_set_oif_name(exp, "dp2T0");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean up */
	dp_test_execute(XCONNECT_CONFIG__COMMAND_TYPE__REMOVE,
			"dp2T0", "dp1T0");
	dp_test_wait_for_xconnect_gone("dp2T0", "dp1T0");

} DP_END_TEST;

DP_START_TEST(xconnect_switching, xconnect_switching_admin_down)
{
	const char *mac_a = "00:00:a4:00:00:aa";
	const char *mac_b = "00:00:a4:00:00:bb";
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 64;

	dp_test_execute(XCONNECT_CONFIG__COMMAND_TYPE__ADD, "dp1T0", "dp2T0");
	dp_test_wait_for_xconnect("dp1T0", "dp2T0");

	/* Now send a packet */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
					 1, &len);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T0");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Now admin down the output interface */
	dp_test_netlink_set_interface_admin_status("dp2T0", false);

	/* Now send another packet */
	test_pak = dp_test_create_l2_pak(mac_a, mac_b, DP_TEST_ET_LLDP,
					 1, &len);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_netlink_set_interface_admin_status("dp2T0", true);

	/* Clean up */
	dp_test_execute(XCONNECT_CONFIG__COMMAND_TYPE__REMOVE,
			"dp1T0", "dp2T0");
	dp_test_wait_for_xconnect_gone("dp1T0", "dp2T0");

} DP_END_TEST;

DP_START_TEST(xconnect_switching, xconnect_switching_out_of_order)
{
	dp_test_execute(XCONNECT_CONFIG__COMMAND_TYPE__ADD,
			"tun1", "tun2");
	dp_test_wait_for_xconnect("tun1", "tun2");

	/* Send src interface, dst doesn't exist */
	dp_test_intf_gre_create("tun1", "1.1.2.1", "1.1.2.2", 0,
				VRF_DEFAULT_ID);
	dp_test_intf_gre_delete("tun1", "1.1.2.1", "1.1.2.2", 0,
				VRF_DEFAULT_ID);

	/* Send dst interface, src doesn't exist */
	dp_test_intf_gre_create("tun2", "2.1.2.1", "2.1.2.2", 0,
				VRF_DEFAULT_ID);
	/* Send dst interface, src exists */
	dp_test_intf_gre_create("tun1", "1.1.2.1", "1.1.2.2", 0,
				VRF_DEFAULT_ID);

	/* Send src interface, dst exists */
	dp_test_intf_gre_delete("tun2", "2.1.2.1", "2.1.2.2", 0,
				VRF_DEFAULT_ID);
	dp_test_intf_gre_create("tun2", "2.1.2.1", "2.1.2.2", 0,
				VRF_DEFAULT_ID);

	/* Clean up */
	dp_test_intf_gre_delete("tun2", "2.1.2.1", "2.1.2.2", 0,
				VRF_DEFAULT_ID);
	dp_test_intf_gre_delete("tun1", "1.1.2.1", "1.1.2.2", 0,
				VRF_DEFAULT_ID);

	dp_test_execute(XCONNECT_CONFIG__COMMAND_TYPE__REMOVE,
			"tun1", "tun2");
	dp_test_wait_for_xconnect_gone("tun1", "tun2");
} DP_END_TEST;
