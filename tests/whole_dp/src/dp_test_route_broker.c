/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * A test version of the route broker process, running as its own thread.
 */
#include <pthread.h>

#include <czmq.h>
#include <zmq.h>

#include "dp_test_controller.h"
#include "dp_test_route_broker.h"
#include "util.h"
#include "zmq_dp.h"

zsock_t *broker_data_sock;

static int process_actor_message(zsock_t *sock)
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

static void process_ctrl_message(zsock_t *sock)
{
	char *uuid;
	zframe_t *envelope;
	zmsg_t *msg;
	char *msg_type;
	uint32_t proto_version;
	char *url;
	int rc;

	msg = zmsg_recv(sock);
	assert(msg);

	envelope = zmsg_unwrap(msg);
	assert(envelope);

	msg_type = zmsg_popstr(msg);
	if (!msg_type || strcmp(msg_type, "CONNECT")) {
		if (msg_type && !strcmp(msg_type, "KEEPALIVE")) {
			/* ignore keepalives */
			free(msg_type);
			zframe_destroy(&envelope);
			zmsg_destroy(&msg);
			return;
		}
		assert(0);
	}
	free(msg_type);

	if (zmsg_popu32(msg, &proto_version) < 0 || proto_version != 0)
		assert(0);

	uuid = zmsg_popstr(msg);
	assert(uuid);
	zmsg_destroy(&msg);

	/* Create data sock */
	if (broker_data_sock)
		/* This happens in the reset dataplane test */
		zsock_destroy(&broker_data_sock);
	broker_data_sock = zsock_new(ZMQ_PUSH);
	assert(broker_data_sock);

	zsock_set_sndhwm(broker_data_sock, 100);

	if (zsock_bind(broker_data_sock, "%s", "ipc://*") < 0)
		assert(0);
	url = zsock_last_endpoint(broker_data_sock);

	/* Now send a reply back with the data url */
	msg = zmsg_new();
	assert(msg);

	rc = zmsg_addstr(msg, "ACCEPT");
	assert(rc >= 0);

	rc = zmsg_addstr(msg, uuid);
	free(uuid);
	assert(rc >= 0);

	rc = zmsg_addstr(msg, url);
	free(url);
	assert(rc >= 0);

	rc = zmsg_prepend(msg, &envelope);
	assert(rc >= 0);

	zmsg_send(&msg, sock);
}

void
dp_test_broker_thread_run(zsock_t *pipe, void *args)
{
	char *broker_ctrl_ep;
	zsock_t *broker_ctrl_sock;

	pthread_setname_np(pthread_self(), "dp_test_broker");

	broker_ctrl_sock = zsock_new_router(NULL);
	assert(broker_ctrl_sock);

	if (zsock_bind(broker_ctrl_sock, "%s", "ipc://*") < 0)
		assert(0);

	broker_ctrl_ep = zsock_last_endpoint(broker_ctrl_sock);
	zsock_signal(pipe, 0);
	zstr_send(pipe, broker_ctrl_ep);
	free(broker_ctrl_ep);

	zmq_pollitem_t items[] = {
		{
			.socket = zsock_resolve(pipe),
			.events = ZMQ_POLLIN|ZMQ_POLLERR,
		},
		{
			.socket = zsock_resolve(broker_ctrl_sock),
			.events = ZMQ_POLLIN
		},
	};
	int item_count = ARRAY_SIZE(items);

	while (!zsys_interrupted) {
		if (zmq_poll(items, item_count, 3000 * ZMQ_POLL_MSEC) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (items[0].revents & ZMQ_POLLERR)
			break;

		if (items[0].revents & ZMQ_POLLIN)
			if (process_actor_message(pipe))
				break;

		if (items[1].revents & ZMQ_POLLIN)
			process_ctrl_message(broker_ctrl_sock);
	}

	zsock_destroy(&broker_data_sock);
	zsock_destroy(&broker_ctrl_sock);
}
