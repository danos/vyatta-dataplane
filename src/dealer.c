/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>
#include <errno.h>
#include <rte_log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zmq.h>

#include "config_internal.h"
#include "dealer.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "zmq_dp.h"

/* This is the total number of frames expected to be in an ACCEPT message */
#define NUM_FRAMES_ACCEPT_MSG	3
#define NUM_FRAMES_REJECT_MSG	2

#define CONNECT_TIMEOUT 5000

static int
process_dealer_reject(zmsg_t *reject, enum cont_src_en cont_src)
{
	int	 rc = 0;
	char	*uuid = NULL;

	/*
	 * Number of frames check - minus one because we alreay popped the
	 * "type" frame before the remainder was dispatched to us.
	 */
	if (zmsg_size(reject) != (NUM_FRAMES_REJECT_MSG - 1)) {
		RTE_LOG(ERR, DATAPLANE,
			"main(%s) Rx'd REJECT message with wrong number of frames\n",
			cont_src_name(cont_src));
		rc = -1;
		goto err;
	}

	uuid = zmsg_popstr(reject);
	if (strcmp(uuid, config.uuid)) {
		RTE_LOG(ERR, DATAPLANE,
			"main(%s) REJECT message mis-match on UUID\n",
			cont_src_name(cont_src));
		rc = -2;
		goto err;
	}
err:
	free(uuid);
	return rc;
}

static int
process_dealer_accept(zmsg_t *accept, enum cont_src_en cont_src)
{
	int			 rc;
	char			*uuid = NULL;
	uint16_t		 dp_idx;

	/*
	 * Number of frames check - minus one because we already popped the
	 * "type" frame before the remainder was dispatched to us.
	 */
	if (zmsg_size(accept) != (NUM_FRAMES_ACCEPT_MSG - 1)) {
		RTE_LOG(ERR, DATAPLANE,
			"main(%s) Rx'd ACCEPT msg with wrong number of frames\n",
			cont_src_name(cont_src));
		rc = -2;
		goto err;
	}

	/*
	* This is already configured, we just need it sanity checked.
	*/
	uuid = zmsg_popstr(accept);
	if (cont_src == CONT_SRC_MAIN) {
		if (strcmp(uuid, config.uuid)) {
			RTE_LOG(ERR, DATAPLANE,
				"main(%s) ACCEPT message mis-match on UUID\n",
				cont_src_name(cont_src));
			rc = -3;
			goto err;
		}
	}
	/* Once we've verified the UUID we don't need it any more */
	free(uuid);
	uuid = NULL;

	if (zmsg_popu16(accept, &dp_idx) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"main(%s) ACCEPT message fail on vPlane index\n",
			cont_src_name(cont_src));
		rc = -4;
		goto err;
	}

	if (config.dp_index != dp_idx)
		RTE_LOG(ERR, DATAPLANE,
			"main(%s) ACCEPT message dp id mismatch, local %u != rx %u\n",
			cont_src_name(cont_src), config.dp_index, dp_idx);

	return 0;

	/*
	 * In the error case, free eveything that ZMQ has malloc'd under the
	 * covers because we don't need it and won't have stored it anywhere
	 * now.
	 */
err:
	free(uuid);

	return rc;
}

static const struct dealer_msg_handler {
	const char *type;
	int (*handler)(zmsg_t *rep, enum cont_src_en cont_src);
} dealer_msg_handlers[] = {
	{"ACCEPT", process_dealer_accept},
	{"REJECT", process_dealer_reject},
	{NULL, NULL},
};

/*
 * Process the ZMQ from the DEALER socket
 */
static int process_dealer_msg(zmsg_t *rep, enum cont_src_en cont_src)
{
	char *type;
	const struct dealer_msg_handler *h;
	int rc;

	type = zmsg_popstr(rep);

	for (h = dealer_msg_handlers; h->type && type; ++h) {
		if (strcmp(h->type, type))
			continue;

		rc = (*h->handler)(rep, cont_src);

		free(type);
		return rc;
	}

	RTE_LOG(NOTICE, DATAPLANE,
		"main(%s) Couldn't process message with type '%s'\n",
		cont_src_name(cont_src), type);

	free(type);

	return -1;
}

/*
 * Fetch the ZMQ message off of the socket.
 */
static zmsg_t *dealer_msg_recv(zsock_t *socket)
{
	zmsg_t *zmsg = zmsg_recv(socket);

	if (!zmsg)
		return NULL;

	if (zmsg_size(zmsg) < 1) {
		RTE_LOG(ERR, DATAPLANE,
			"Received ZMQ message with size < 0. Ignoring\n");
		zmsg_destroy(&zmsg);
		return NULL;
	}

	return zmsg;
}

static int dealer_recv(zsock_t *socket, enum cont_src_en cont_src)
{
	int rc;
	zmsg_t *dealer_msg = dealer_msg_recv(socket);

	if (!dealer_msg) {
		RTE_LOG(ERR, DATAPLANE,
			"main(%s) Missing ZMQ message from DEALER socket\n",
			cont_src_name(cont_src));
		return -1;
	}

	rc = process_dealer_msg(dealer_msg, cont_src);
	if (rc < 0)
		RTE_LOG(ERR, DATAPLANE,
			"main(%s) Error processing ZMQ message from DEALER socket\n",
			cont_src_name(cont_src));

	zmsg_destroy(&dealer_msg);

	return rc;
}

int init_controller_connection(zsock_t *socket, enum cont_src_en cont_src)
{
	int rc;

	rc = send_controller_connect(socket, cont_src);
	if (rc < 0)
		RTE_LOG(ERR, DATAPLANE,
			"main(%s) ZMQ failed to connect to controller\n",
			cont_src_name(cont_src));
	return rc;
}

int try_controller_response(zsock_t *socket, enum cont_src_en cont_src)
{
	if (!(zsock_events(socket) & ZMQ_POLLIN))
		return -EAGAIN;

	/* We have a message waiting on the socket at this point */
	return dealer_recv(socket, cont_src);
}

/*
 * Request the publisher URL from the controller.
 */
void conf_query(enum cont_src_en cont_src)
{
	zsock_t *socket = cont_socket_get(cont_src);

	zstr_send(socket, "CONFQUERY");

	zsock_set_rcvtimeo(socket, CONNECT_TIMEOUT);

	zmsg_t *zmsg = zmsg_recv(socket);

	zsock_set_rcvtimeo(socket, -1);

	if (!zmsg)
		return;

	char *type = zmsg_popstr(zmsg);

	if (type && streq(type, "CONF")) {
		int x, count = zmsg_size(zmsg) >> 1;

		for (x = 0; x < count; x++) {
			char *param = zmsg_popstr(zmsg);

			if ((param != NULL) && streq(param, "PUBLISH")) {
				char *pub = zmsg_popstr(zmsg);

				if (pub != NULL) {
					switch (cont_src) {
					case CONT_SRC_MAIN:
						free(config.publish_url);
						config.publish_url = pub;
						break;
					case CONT_SRC_UPLINK:
						free(config.publish_url_uplink);
						config.publish_url_uplink = pub;
						break;
					}
					DP_DEBUG(DEALER, DEBUG, DATAPLANE,
						 "Received publisher(%s) URL %s\n",
						 cont_src_name(cont_src),
						 pub);
				}
			} else {
				zframe_t *frame = zmsg_pop(zmsg);

				zframe_destroy(&frame);
			}
			if (param)
				free(param);
		}
	}

	free(type);
	zmsg_destroy(&zmsg);
}

#ifdef DEALER_TEST
int __test_process_dealer_msg(zmsg_t *msg, enum cont_src_en cont_src)
{
	return process_dealer_msg(msg, cont_src);
}

int __test_process_dealer_reject(zmsg_t *reject, enum cont_src_en cont_src)
{
	return process_dealer_reject(reject, cont_src);
}

int __test_process_dealer_accept(zmsg_t *accept, enum cont_src_en cont_src)
{
	return process_dealer_accept(accept, cont_src);
}
#endif
