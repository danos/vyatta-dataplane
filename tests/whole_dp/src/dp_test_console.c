/*-
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A test console for the dataplane test harness. This file
 * provides a minimal implementation of a console so that the
 * dataplane can be queried.
 */

#include <czmq.h>

#include "dp_test_controller.h"
#include "dp_test_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test.h"
#include "dp_test_console.h"

struct dp_test_cont_src_console_s {
	char console_ep[20];
};

static struct dp_test_cont_src_console_s cont_src_console[CONT_SRC_COUNT];

static const char *dp_test_console_names[CONT_SRC_COUNT] = {
	[CONT_SRC_MAIN] = "vplaned",
	[CONT_SRC_UPLINK] = "vplaned-uplink",
};

static const char *console_name(enum cont_src_en cont_src)
{
	return dp_test_console_names[cont_src];
}

static char *
dp_test_cmd_sock_recv1(enum cont_src_en cont_src, zsock_t *cmd_sock,
		       bool *return_err, bool print)
{
	zmsg_t *msg = zmsg_recv(cmd_sock);
	char *topic = zmsg_popstr(msg);

	if (!return_err)
		dp_test_assert_internal(strncmp("ERROR", topic, 5));
	else
		*return_err = !strncmp("ERROR", topic, 5);

	if (print)
		printf("console(%s) rep status: %s\n", console_name(cont_src),
		       topic);

	char *str = zmsg_popstr(msg);

	fflush(stdout);
	free(topic);
	zmsg_destroy(&msg);
	return str;
}

static void
dp_test_console_generate_endpoint(char *console_ep, size_t n)
{
	/* Get a unique filename. Dataplane has the REP end of it, so it needs
	 * to create it, can't use ipc:/  * from here.
	 */
	char buf[12] = "2134XXXXXX";
	int fd = mkstemp(buf);
	dp_test_assert_internal(fd != -1);
	close(fd);

	snprintf(console_ep, n, "ipc://%s", buf);
}

char *dp_test_console_set_endpoint(enum cont_src_en cont_src)
{
	dp_test_console_generate_endpoint(cont_src_console[cont_src].console_ep,
				sizeof(cont_src_console[cont_src].console_ep));
	return cont_src_console[cont_src].console_ep;
}

/*
 * Execute a console request and return either the response and/or
 * an error state flag (if one is provided).
 */
char *
dp_test_console_request_w_err_src(enum cont_src_en cont_src,
				  const char *request, bool *err_ret,
				  bool print)
{
	int ret;
	zsock_t *cmd_sock;

	/*
	 * Create ephemeral ZMQ channel to the console for sending
	 * show commands etc. to the dataplane.
	 */
	cmd_sock = zsock_new_req(cont_src_console[cont_src].console_ep);
	dp_test_assert_internal(cmd_sock);

	/*
	 * Create request message
	 */
	zmsg_t *msg = zmsg_new();
	zmsg_addstr(msg, request);
	if (print)
		printf("console(%s) req: %s\n", console_name(cont_src),
		       request);
	ret = zmsg_send(&msg, cmd_sock);
	if (ret == -1)
		dp_test_assert_internal(0);

	/*
	 * Send message and await reply
	 */
	char *reply = dp_test_cmd_sock_recv1(cont_src, cmd_sock, err_ret,
					     print);

	/*
	 * Kill ZMQ connection.
	 */
	zsock_destroy(&cmd_sock);

	return reply;
}

char *
dp_test_console_request_w_err(const char *request,
			      bool *err_ret, bool print)
{
	enum cont_src_en cont_src = dp_test_cont_src_get();

	return dp_test_console_request_w_err_src(cont_src, request,
						 err_ret, print);
}

char *
dp_test_console_request(const char *request, bool print)
{
	enum cont_src_en cont_src = dp_test_cont_src_get();

	return dp_test_console_request_w_err_src(cont_src, request, NULL,
						 print);
}

void
dp_test_console_request_reply(const char *cmd, bool print)
{
	char *reply;

	reply = dp_test_console_request(cmd, print);
	if (print)
		printf("console rep value: %s\n", reply ? reply : "<NULL>");
	free(reply);
}

char *
dp_test_console_request_src(enum cont_src_en cont_src, const char *request,
			    bool print)
{
	return dp_test_console_request_w_err_src(cont_src, request, NULL,
						 print);
}

void
dp_test_console_request_reply_src(enum cont_src_en cont_src, const char *cmd,
				  bool print)
{
	char *reply;

	reply = dp_test_console_request_src(cont_src, cmd, print);
	if (print)
		printf("console rep value: %s\n", reply ? reply : "<NULL>");
	free(reply);
}
