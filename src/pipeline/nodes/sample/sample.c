/*
 * Sample pipeline feature node
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
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
#include <urcu/uatomic.h>

#include <json_writer.h>
#include <pl_node.h>
#include <pl_common.h>

#include "protobuf.h"
#include <SampleFeatConfig.pb-c.h>

enum sample_dispositions {
	SAMPLE_ACCEPT,
	SAMPLE_NUM
};

static uint32_t sample_pkt_count;

static unsigned int
sample_process(struct pl_packet *pkt __attribute__((unused)))
{
	uatomic_inc(&sample_pkt_count);

	return SAMPLE_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(sample_node) = {
	.name = "sample:sample",
	.type = PL_PROC,
	.handler = sample_process,
	.num_next = SAMPLE_NUM,
	.next = {
		[SAMPLE_ACCEPT] = "vyatta:term-noop"
	}
};

PL_REGISTER_FEATURE(sample_feat) = {
	.name = "sample:sample",
	.node_name = "sample",
	.feature_point = "vyatta:ipv4-validate",
	.visit_after = "vyatta:ipv4-pbr",
};

static int
sample_feat_cmd(struct pb_msg *msg)
{
	int ret;

	SampleFeatConfig *sample_msg =
		sample_feat_config__unpack(NULL, msg->msg_len, msg->msg);
	if (!sample_msg) {
		pb_cmd_err(msg, "failed to read sample protobuf command\n");
		return -1;
	}

	if (!sample_msg->has_is_active) {
		pb_cmd_err(msg, "error in sample protobuf command\n");
		return -1;
	}

	if (sample_msg->is_active == false)
		ret = pl_node_remove_feature(&sample_feat,
					      sample_msg->if_name);
	else
		ret = pl_node_add_feature(&sample_feat, sample_msg->if_name);

	sample_feat_config__free_unpacked(sample_msg, NULL);

	return ret;
}

static int
cmd_sample_feat_show(struct pl_command *cmd)
{
	json_writer_t *json = jsonw_new(cmd->fp);

	if (!json)
		return 0;

	jsonw_name(json, "sample-feat");
	jsonw_start_object(json);

	jsonw_uint_field(json, "ipv4-validate-packet-count",
			 uatomic_read(&sample_pkt_count));

	jsonw_end_object(json);
	jsonw_destroy(&json);
	return 0;
}

PB_REGISTER_CMD(sample_cmd) = {
	.cmd = "sample:sample-feat",
	.handler = sample_feat_cmd,
};

PL_REGISTER_OPCMD(sample_show) = {
	.cmd = "sample-feat show",
	.handler = cmd_sample_feat_show,
};
