/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>
#include <rte_common.h>
#include <rte_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "vplane_log.h"
#include "zmq_dp.h"

/*
 * Create a frame around a uint16_t value for ZMQ and add it to the end of a
 * ZMQ message
 */
int
zmsg_addu16(zmsg_t *msg, uint16_t u)
{
	zframe_t *frame;

	if (!msg) {
		RTE_LOG(ERR, DATAPLANE,
			"Passed invalid pointer 'msg'\n");
		return -1;
	}

	frame = zframe_new(&u, sizeof(uint16_t));

	if (!frame) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to create ZMSG frame\n");
		return -1;
	}
	return zmsg_append(msg, &frame);
}

int
zmsg_popu16(zmsg_t *msg, uint16_t *p)
{
	zframe_t *frame = zmsg_pop(msg);

	if (!frame) {
		RTE_LOG(ERR, DATAPLANE,
			"missing uint16_t element\n");
		return -1;
	}

	if (zframe_size(frame) != sizeof(uint16_t)) {
		RTE_LOG(ERR, DATAPLANE,
			"expect uint16_t message got size %zd\n",
			zframe_size(frame));
		zframe_destroy(&frame);
		return -1;
	}

	memcpy(p, zframe_data(frame), sizeof(uint16_t));
	zframe_destroy(&frame);
	return 0;
}

/*
 * Create a frame around a uint32_t value for ZMQ and add it to the end of a
 * ZMQ message
 */
int
zmsg_addu32(zmsg_t *msg, uint32_t u)
{
	zframe_t *frame;

	if (!msg) {
		RTE_LOG(ERR, DATAPLANE,
			"Passed invalid pointer 'msg'\n");
		return -1;
	}

	frame = zframe_new(&u, sizeof(uint32_t));
	if (!frame) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to create ZMSG frame\n");
		return -1;
	}
	return zmsg_append(msg, &frame);
}

int
zmsg_popu32(zmsg_t *msg, uint32_t *p)
{
	zframe_t *frame = zmsg_pop(msg);

	if (frame == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"missing uint32_t element\n");
		return -1;
	}

	if (zframe_size(frame) != sizeof(uint32_t)) {
		RTE_LOG(ERR, DATAPLANE,
			"expect uint32_t message got size %zd\n",
			zframe_size(frame));
		zframe_destroy(&frame);
		return -1;
	}

	memcpy(p, zframe_data(frame), sizeof(uint32_t));
	zframe_destroy(&frame);
	return 0;
}

int
zmsg_addu64(zmsg_t *msg, uint64_t u)
{
	zframe_t *frame;

	if (!msg) {
		RTE_LOG(ERR, DATAPLANE,
			"Passed invalid pointer 'msg'\n");
		return -1;
	}

	frame = zframe_new(&u, sizeof(uint64_t));
	if (!frame) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to create ZMSG frame\n");
		return -1;
	}
	return zmsg_append(msg, &frame);
}

int
zmsg_popu64(zmsg_t *msg, uint64_t *p)
{
	zframe_t *frame = zmsg_pop(msg);

	if (frame == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"missing uint64_t element\n");
		return -1;
	}

	if (zframe_size(frame) != sizeof(uint64_t)) {
		RTE_LOG(ERR, DATAPLANE,
			"expect uint64_t message got size %zd\n",
			zframe_size(frame));
		zframe_destroy(&frame);
		return -1;
	}

	memcpy(p, zframe_data(frame), sizeof(uint64_t));
	zframe_destroy(&frame);
	return 0;
}

int zactor_terminated(zloop_t *loop __rte_unused, zsock_t *sock,
		      void *arg __rte_unused)
{
	int interrupted = 0;
	char *msg = zstr_recv(sock);

	if (zsys_interrupted || (msg && !strcmp(msg, "$TERM")))
		interrupted = -1;

	free(msg);
	return interrupted;
}

int zmsg_send_and_destroy(zmsg_t **msg, void *dest)
{
	int rv = zmsg_send(msg, dest);

	if (rv != 0)
		zmsg_destroy(msg);
	return rv;
}

/*
 * Build a properly formatted ZMQ message to CONNECT to send to the controller
 */
static int
build_connect_msg(zmsg_t *msg, enum cont_src_en cont_src)
{
	uint32_t version = CONTROL_PROTO_VER;
	const char *console_url = NULL;
	int rc = 0;

	if (!msg)
		return -1;

	rc = zmsg_addstr(msg, "CONNECT");
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Couldn't add message type to ZMQ control message\n",
			cont_src_name(cont_src));
		return -2;
	}

	rc = zmsg_addu32(msg, version);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Couldn't add message version to ZMQ control message\n",
			cont_src_name(cont_src));
		return -3;
	}

	if (cont_src == CONT_SRC_MAIN) {
		if (!config.uuid) {
			RTE_LOG(ERR, DATAPLANE,
				"(%s) Missing config UUID for ZMQ control message\n",
				cont_src_name(cont_src));
			return -4;
		}
		rc = zmsg_addstr(msg, config.uuid);
	} else {
		rc = zmsg_addstr(msg, DEFAULT_UUID);
	}
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Couldn't add UUID to ZMQ control message\n",
			cont_src_name(cont_src));
		return -5;
	}

	if (cont_src == CONT_SRC_MAIN)
		console_url = config.console_url_bound;
	else if (cont_src == CONT_SRC_UPLINK)
		console_url = config.console_url_bound_uplink;

	if (!console_url) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Missing config control IP for ZMQ control message\n",
			cont_src_name(cont_src));
		return -6;
	}
	rc = zmsg_addstr(msg, console_url);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Couldn't add control IP to ZMQ control message\n",
			cont_src_name(cont_src));
		return -7;
	}

	return 0;
}

int
send_controller_connect(zsock_t *csocket, enum cont_src_en cont_src)
{
	zmsg_t *connect_msg;
	int rc = 0;

	if (!csocket) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) csocket not set. Can't send CONNECT\n",
			cont_src_name(cont_src));
		rc = -1;
	}

	/* Init the ZMQ msg struct for the CONNECT mesage */
	if (rc == 0) {
		connect_msg = zmsg_new();
		if (!connect_msg) {
			RTE_LOG(ERR, DATAPLANE,
				"(%s) Could not initialse the CONNECT message.\n",
				cont_src_name(cont_src));
			rc = -2;
		}
	}

	/* Build the ZMQ CONNECT message */
	if (rc == 0) {
		rc = build_connect_msg(connect_msg, cont_src);
		if (rc < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"(%s) Could not build the CONNECT message\n",
				cont_src_name(cont_src));
			rc = -3;
		}
	}

	/* Send the CONNECT message */
	if (rc == 0) {
		rc = zmsg_send(&connect_msg, csocket);
		if (rc < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"(%s) Could not send the CONNECT message.\n",
				cont_src_name(cont_src));
			rc = -4;
		}
	}

	/*
	 * If rc != 0 the something went wrong (we don't know where but it's not
	 * important for this case). Destroy the connect_msg to make sure we're
	 * not leaking memory. In the case where the message was sent
	 * successfully, ZMQ will free the message for us.
	 */
	if (rc != 0)
		zmsg_destroy(&connect_msg);

	return rc;
}

/*
 * The following functions should be used exclusively to enable unit-tests.
 * They should **not** be used to implement real functionality.
 */
int __test_build_connect_msg(zmsg_t *msg, enum cont_src_en cont_src)
{
	return build_connect_msg(msg, cont_src);
}
