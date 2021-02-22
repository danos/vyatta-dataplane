/*
 * Sample pipeline feature node
 *
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * To generate the protobuf message source:
 * "protoc-c -I=. --c_out=. ./SampleFeatConfig.proto"
 *
 * To compile sample as a standalone:
 * "gcc -shared -fPIC sample.c -I/usr/include/vyatta-dataplane
 *  $(pkg-config --cflags libdpdk) -o libsample.so"
 *
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/uatomic.h>

#include <compiler.h>
#include <feature_commands.h>
#include <feature_plugin.h>
#include <json_writer.h>
#include <pipeline.h>

#include <SampleFeatOp.pb-c.h>
#include <SampleFeatConfig.pb-c.h>

enum sample_dispositions {
	SAMPLE_ACCEPT,
	SAMPLE_NUM
};

static uint32_t sample_pkt_count;
static uint32_t sample_ctx = 0x12345678;
static uint32_t sample_cleanup_cb_count;

static void sample_cleanup_cb(const char *instance __unused,
			      void *context)
{
	sample_cleanup_cb_count++;

	assert(context == &sample_ctx);
}


static unsigned int
sample_process(struct pl_packet *pkt __unused,
	       void *context)
{
	uatomic_inc(&sample_pkt_count);
	assert(context == &sample_ctx);

	return SAMPLE_ACCEPT;
}


static int
sample_feat_cmd(struct pb_msg *msg)
{
	int ret = 0;

	SampleFeatConfig *sample_msg =
		sample_feat_config__unpack(NULL, msg->msg_len, msg->msg);
	if (!sample_msg) {
		dp_pb_cmd_err(msg, "failed to read sample protobuf command\n");
		return -1;
	}

	if (!sample_msg->has_is_active) {
		dp_pb_cmd_err(msg, "error in sample protobuf command\n");
		return -1;
	}

	if (sample_msg->is_active == false) {
		dp_pipeline_disable_feature_by_inst("sample:sample",
						    sample_msg->if_name);
		dp_pipeline_unregister_inst_storage("sample:sample",
						    sample_msg->if_name);
	} else {
		ret = dp_pipeline_register_inst_storage("sample:sample",
							sample_msg->if_name,
							&sample_ctx);
		if (ret)
			goto out;
		ret = dp_pipeline_enable_feature_by_inst("sample:sample",
							 sample_msg->if_name);

	}

out:
	sample_feat_config__free_unpacked(sample_msg, NULL);

	return ret;
}

static int
cmd_sample_feat_show(struct pb_msg *msg)
{
	/* request */
	SampleFeatOpReq *sample_op_req_msg =
		sample_feat_op_req__unpack(NULL, msg->msg_len, msg->msg);
	if (!sample_op_req_msg) {
		dp_pb_cmd_err(msg,
			      "failed to read sample protobuf op command\n");
		return -1;
	}
	sample_feat_op_req__free_unpacked(sample_op_req_msg, NULL);

	/* response */
	SampleFeatOpResp sample_op_resp_msg = SAMPLE_FEAT_OP_RESP__INIT;

	sample_op_resp_msg.count = uatomic_read(&sample_pkt_count);
	sample_op_resp_msg.has_count = true;

	/* now convert this to binary and add back */
	int len = sample_feat_op_resp__get_packed_size(&sample_op_resp_msg);
	void *buf2 = malloc(len);
	sample_feat_op_resp__pack(&sample_op_resp_msg, buf2);
	msg->ret_msg = buf2;
	msg->ret_msg_len = len;

	return 0;
}

const char *sampler_next_nodes[] = {
	"vyatta:term-noop",
};

static const char *plugin_name = "sample";

struct dp_pipeline_feat_registration sample_feat = {
	.plugin_name = "sample",
	.name = "sample:sample",
	.node_name = "sample:sample",
	.feature_point = "vyatta:ipv4-validate",
	.visit_before = NULL,
	.visit_after = "vyatta:ipv4-pbr",
	.cleanup_cb = sample_cleanup_cb,
};

int dp_feature_plugin_init(const char **name)
{
	int rv;

	rv = dp_pipeline_register_node("sample:sample",
				       1,
				       sampler_next_nodes,
				       PL_PROC,
				       sample_process);
	if (rv)
		goto error;


	rv = dp_pipeline_register_list_feature(&sample_feat);
	if (rv)
		goto error;

	rv = dp_feature_register_pb_cfg_handler("sample:sample-feat",
						sample_feat_cmd);
	if (rv)
		goto error;

	rv = dp_feature_register_pb_op_handler("sample:sample-feat",
					       cmd_sample_feat_show);
	if (rv)
		goto error;

	*name = plugin_name;
	return 0;
error:
	return rv;
}
