/*-
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A test controller/console for the dataplane test harness.
 * This file provides a minimal implementation of a controlled
 * and the console so that the dataplane can be programmed and
 * queried.
 */

#ifndef _DP_TEST_CONTROLLER_H_
#define _DP_TEST_CONTROLLER_H_

#include <linux/netlink.h>
#include <czmq.h>

#include "control.h"

extern int dp_test_ifindex;

void dp_test_controller_debug_set(int debug_val);

int nl_generate_topic(const struct nlmsghdr *nlh, char *buf, size_t buflen);
void nl_propagate(const char *topic, const struct nlmsghdr *nlh);
void nl_propagate_broker(const char *topic, void *data, size_t size);
void nl_propagate_xfrm(zsock_t *sock, const struct nlmsghdr *nlh, size_t size,
		       const char *hdr);

void dp_test_controller_init(enum cont_src_en cont_src, char **req_ipc);
void dp_test_controller_close(enum cont_src_en cont_src);
void dp_test_cont_src_set(enum cont_src_en cont_src_new);
enum cont_src_en dp_test_cont_src_get(void);

__attribute__((format(printf, 2, 3)))
void dp_test_send_config_src(enum cont_src_en cont_src,
			     const char *cmd_fmt_str, ...);
void dp_test_send_config_src_pb(enum cont_src_en cont_src,
				void *cmd, size_t cmd_len);
void dp_test_set_config_err(int error);

#endif /* DP_TEST_CONTROLLER_H */
