/*
 * IPv6 Commands
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "ip6_funcs.h"
#include "vplane_log.h"

#include "protobuf.h"
#include "protobuf/IP6RedirectsConfig.pb-c.h"

static int
ip6_cmd_handler(struct pb_msg *msg)
{
	void *payload = (void *)((char *)msg->msg);
	int len = msg->msg_len;

	IP6RedirectsConfig *smsg =
		ip6_redirects_config__unpack(NULL, len, payload);

	if (!smsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read IP6RedirectsConfig protobuf command\n");
		return -1;
	}

	ip6_redirects_set(smsg->enable_redirects);

	ip6_redirects_config__free_unpacked(smsg, NULL);

	return 0;
}

PB_REGISTER_CMD(ip6_cmd) = {
	.cmd = "vyatta:ip6",
	.handler = ip6_cmd_handler,
};
