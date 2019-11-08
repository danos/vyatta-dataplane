/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test pipeline tests
 */
#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_controller.h"
#include "dp_test_json_utils.h"
#include "dp_test_netlink_state.h"
#include "dp_test_console.h"

#include "src/pipeline/nodes/sample/SampleFeatConfig.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

DP_DECL_TEST_SUITE(pipeline);

DP_DECL_TEST_CASE(pipeline, dyn_feat, NULL, NULL);

static void
dp_test_create_and_send_sample_feat_msg(bool enable,
					const char *ifname)
{
	int len;
	void *buf;

	SampleFeatConfig samplefeat = SAMPLE_FEAT_CONFIG__INIT;

	/* set values here */
	samplefeat.is_active = enable;
	samplefeat.has_is_active = true;
	/* strings don't have 'has_' */
	samplefeat.if_name = (char *)ifname;
	len = sample_feat_config__get_packed_size(&samplefeat);
	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	sample_feat_config__pack(&samplefeat, buf2);

	DataplaneEnvelope msg = DATAPLANE_ENVELOPE__INIT;
	msg.type = strdup("sample:sample-feat");
	msg.msg.data = buf2;
	msg.msg.len = len;

	len = dataplane_envelope__get_packed_size(&msg);

	buf = malloc(len);
	dp_test_assert_internal(buf);

	dataplane_envelope__pack(&msg, buf);

	dp_test_send_config_src_pb(dp_test_cont_src_get(), buf, len);

	free(buf2);
	free(msg.type);
	free(buf);
}


static void dp_test_pl_get_start_count(int *ipv4_val_cnt)
{
	json_object *jvalue;
	json_object *jresp;
	char *response;
	bool err;

	*ipv4_val_cnt = INT_MAX;

	response = dp_test_console_request_w_err(
		"pipeline sample-feat show", &err, false);
	if (!response || err)
		return;

	jresp = parse_json(response, NULL, 0);
	free(response);

	if (!jresp)
		return;

	if (!json_object_object_get_ex(jresp, "sample-feat", &jvalue))
		return;

	dp_test_json_int_field_from_obj(jvalue,
					"ipv4-validate-packet-count",
					ipv4_val_cnt);
	json_object_put(jresp);
}

DP_START_TEST(dyn_feat, dyn_feat_ipv4)
{
	const char *nh_mac_str = "aa:bb:cc:dd:2:b1";
	struct dp_test_expected *exp;
	json_object *expected_json;
	char real_ifname[IFNAMSIZ];
	struct rte_mbuf *test_pak;
	int init_pkt_cnt;
	int len = 22;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1",
				  nh_mac_str);

	dp_test_pl_get_start_count(&init_pkt_cnt);

	/* Enable the feature and check it's there */
	dp_test_create_and_send_sample_feat_msg(true,
				dp_test_intf_real("dp1T0", real_ifname));
	dp_test_wait_for_pl_feat("dp1T0", "sample:sample",
				 "ipv4-validate");

	/* Now send a packet that the feature should see */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str,
				 dp_test_intf_name2mac_str("dp2T1"),
				 ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Verify that the feature saw the packet */
	expected_json = dp_test_json_create(
		"{"
		"  \"sample-feat\":"
		"  { "
		"    \"ipv4-validate-packet-count\": %d,"
		"  }"
		"}",
		init_pkt_cnt + 1);
	dp_test_check_json_state("pipeline sample-feat show",
				 expected_json,
					 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected_json);

	/* Disable the feature and check it's gone */
	dp_test_create_and_send_sample_feat_msg(false,
				dp_test_intf_real("dp1T0", real_ifname));
	dp_test_wait_for_pl_feat_gone("dp1T0", "sample:sample",
				      "ipv4-validate");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

} DP_END_TEST;
