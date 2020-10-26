/*-
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * A test version of the xfrm broker process, running as its own thread.
 */
#include <pthread.h>

#include <czmq.h>
#include <zmq.h>
#include <libmnl/libmnl.h>

#include "dp_test_controller.h"
#include "dp_test_xfrm_server.h"
#include "util.h"
#include "zmq_dp.h"
#include "czmq.h"

static int process_xfrm_actor_message(zsock_t *sock)
{
	zmsg_t *msg;
	char *str;
	bool stop = false;

	msg = zmsg_recv(sock);
	if (!msg)
		return false;

	str = zmsg_popstr(msg);
	if (streq(str, "$TERM"))
		stop = true;

	free(str);
	zmsg_destroy(&msg);
	return stop;
}

uint32_t xfrm_seq_received;

static void process_xfrm_ack_message(zsock_t *sock)
{
	zframe_t *msg;

	struct nlmsghdr *nlh;
	struct nlmsgerr *err_msg;

	msg = zframe_recv(sock);
	assert(msg);
	nlh = (struct nlmsghdr *)zframe_data(msg);
	dp_test_assert_internal(nlh);
	/* Netlink ACK/OK are carried in Error messages*/
	dp_test_assert_internal(nlh->nlmsg_type == NLMSG_ERROR);
	err_msg = mnl_nlmsg_get_payload(nlh);
	/* An error code 0 indicates a ACK/OK */
	dp_test_assert_internal(err_msg->error == 0);

	xfrm_seq_received++;

	zframe_destroy(&msg);
}

zsock_t *xfrm_server_push_sock;
zsock_t *xfrm_server_pull_sock;

#define  XFRM_SERVER_POLL_TIMER 3000

void
dp_test_xfrm_server_thread_run(zsock_t *pipe, void *args)
{
	char socket_names[MAX_XFRM_SOCKET_NAME_SIZE * 2];
	char *ep_pull, *ep_push;

	pthread_setname_np(pthread_self(), "dp_test_xfrm_sv");

	xfrm_server_push_sock = zsock_new_push(NULL);
	assert(xfrm_server_push_sock);
	if (zsock_bind(xfrm_server_push_sock, "%s", "ipc://*") < 0)
		dp_test_assert_internal(0);
	ep_push = zsock_last_endpoint(xfrm_server_push_sock);

	xfrm_server_pull_sock = zsock_new_pull(NULL);
	assert(xfrm_server_pull_sock);
	if (zsock_bind(xfrm_server_pull_sock, "%s", "ipc://*") < 0)
		dp_test_assert_internal(0);
	ep_pull = zsock_last_endpoint(xfrm_server_pull_sock);

	snprintf(socket_names, sizeof(socket_names), "%s %s",
		 ep_push, ep_pull);

	zsock_signal(pipe, 0);
	zstr_send(pipe, socket_names);

	zmq_pollitem_t items[] = {
		{
			.socket = zsock_resolve(pipe),
			.events = ZMQ_POLLIN|ZMQ_POLLERR,
		},
	};
	int item_count = ARRAY_SIZE(items);

	while (!zsys_interrupted) {
		if (zmq_poll(items, item_count,
			     XFRM_SERVER_POLL_TIMER * ZMQ_POLL_MSEC) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (items[0].revents & ZMQ_POLLERR)
			break;

		if (items[0].revents & ZMQ_POLLIN)
			if (process_xfrm_actor_message(pipe))
				break;

	}
	zsock_destroy(&xfrm_server_pull_sock);
	zsock_destroy(&xfrm_server_push_sock);
}
