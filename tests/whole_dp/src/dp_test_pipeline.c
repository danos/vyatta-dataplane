/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test pipeline tests
 */

#include "dp_test_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test_macros.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"

#include <linux/if.h>

#include "SampleFeatConfig.pb-c.h"
#include "SampleFeatOp.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

DP_DECL_TEST_SUITE(pipeline);

DP_DECL_TEST_CASE(pipeline, dyn_feat, NULL, NULL);

static void
dp_test_create_and_send_sample_feat_msg(bool enable,
					const char *ifname)
{
	int len;
	SampleFeatConfig samplefeat = SAMPLE_FEAT_CONFIG__INIT;

	/* set values here */
	samplefeat.is_active = enable;
	samplefeat.has_is_active = true;
	/* strings don't have 'has_' */
	samplefeat.if_name = (char *)ifname;
	len = sample_feat_config__get_packed_size(&samplefeat);
	void *buf2 = malloc(len);
	assert(buf2);

	sample_feat_config__pack(&samplefeat, buf2);

	dp_test_lib_pb_wrap_and_send_pb("sample:sample-feat", buf2, len);
}


static bool validate_resp_callback(void *data, int len, void *arg)
{
	uint32_t expect_val = *(uint32_t *)arg; /* expected packet count */

	DataplaneEnvelope *dmsg_resp =
		dataplane_envelope__unpack(NULL, len, (unsigned char *)data);
	if (!dmsg_resp) {
		printf("Failed to read dataplane protobuf message\n");
		return false;
	}

	/* now decap pb */
	SampleFeatOpResp *smsg_resp =
		sample_feat_op_resp__unpack(NULL,
				       dmsg_resp->msg.len,
				       dmsg_resp->msg.data);
	if (!smsg_resp) {
		printf("unable to read protobuf message: %p, %d\n", data, len);
		dataplane_envelope__free_unpacked(dmsg_resp, NULL);
		return false;
	}

	uint32_t received_val = smsg_resp->count;

	sample_feat_op_resp__free_unpacked(smsg_resp, NULL);
	dataplane_envelope__free_unpacked(dmsg_resp, NULL);
	return (received_val == expect_val);
}

static void dp_test_pl_build_and_check_start_count(int init_pkt_cnt)
{
	SampleFeatOpReq sampleop = SAMPLE_FEAT_OP_REQ__INIT;

	int len = sample_feat_op_req__get_packed_size(&sampleop);
	void *buf2 = malloc(len);
	assert(buf2);

	sample_feat_op_req__pack(&sampleop, buf2);

	DataplaneEnvelope msg = DATAPLANE_ENVELOPE__INIT;
	msg.type = strdup("sample:sample-feat");
	msg.msg.data = buf2;
	msg.msg.len = len;

	len = dataplane_envelope__get_packed_size(&msg);

	unsigned char *buf = malloc(len);
	assert(buf);

	dataplane_envelope__pack(&msg, buf);

	uint32_t val = init_pkt_cnt + 1;
	void *arg = &val;

	dp_test_check_pb_state((char *)buf, len,
			       validate_resp_callback,
			       arg);
	free(buf2);
	free(msg.type);
	free(buf);
}

static bool get_start_count_callback(void *data, int len, void *arg)
{
	DataplaneEnvelope *dmsg_resp =
		dataplane_envelope__unpack(NULL, len, (unsigned char *)data);
	if (!dmsg_resp) {
		printf("Failed to read dataplane protobuf message\n");
		return false;
	}

	/* now decap pb */
	SampleFeatOpResp *smsg_resp =
		sample_feat_op_resp__unpack(NULL,
				       dmsg_resp->msg.len,
				       dmsg_resp->msg.data);
	if (!smsg_resp) {
		printf("unable to read protobuf message: %p, %d\n", data, len);
		dataplane_envelope__free_unpacked(dmsg_resp, NULL);
		return false;
	}
	uint32_t received_val = smsg_resp->count;

	*(uint32_t *)arg = received_val;

	sample_feat_op_resp__free_unpacked(smsg_resp, NULL);
	dataplane_envelope__free_unpacked(dmsg_resp, NULL);

	return true;
}

static void dp_test_pl_get_start_count(int *ipv4_val_cnt)
{
	*ipv4_val_cnt = INT_MAX;
	int len;
	void *buf;

	SampleFeatOpReq sampleop = SAMPLE_FEAT_OP_REQ__INIT;

	len = sample_feat_op_req__get_packed_size(&sampleop);
	void *buf2 = malloc(len);
	assert(buf2);

	sample_feat_op_req__pack(&sampleop, buf2);

	DataplaneEnvelope msg = DATAPLANE_ENVELOPE__INIT;
	msg.type = strdup("sample:sample-feat");
	msg.msg.data = buf2;
	msg.msg.len = len;

	len = dataplane_envelope__get_packed_size(&msg);

	buf = malloc(len);
	assert(buf);

	dataplane_envelope__pack(&msg, buf);

	dp_test_check_pb_state((char *)buf, len,
			       get_start_count_callback,
			       ipv4_val_cnt);

	free(buf2);
	free(msg.type);
	free(buf);

}


DP_START_TEST(dyn_feat, dyn_feat_ipv4)
{
	const char *nh_mac_str = "aa:bb:cc:dd:2:b1";
	struct dp_test_expected *exp;
	char real_ifname[IFNAMSIZ];
	struct rte_mbuf *test_pak;
	int init_pkt_cnt = 0;
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
				 RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str,
				 dp_test_intf_name2mac_str("dp2T1"),
				 RTE_ETHER_TYPE_IPV4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Verify that the feature saw the packet */
	dp_test_pl_build_and_check_start_count(init_pkt_cnt);

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
