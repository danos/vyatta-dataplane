/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2018,2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>
#include <libmnl/libmnl.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_timer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_internal.h"
#include "control.h"
#include "event_internal.h"
#include "ip_rt_protobuf.h"
#include "master.h"
#include "netlink.h"
#include "route_broker.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "zmq_dp.h"

/* netlink format */
#define ROUTE_BROKER_FORMAT_NL 0x0
/* protobuf format */
#define ROUTE_BROKER_FORMAT_PB 0x1

#define BROKER_KEEPALIVE_TIMER_SEC 10
static struct rte_timer broker_keepalive_timer[CONT_SRC_COUNT];

/*
 * Receive netlink message from rib:
 *
 * dpmsg must be already allocated, and caller is responsible for destroying it.
 * Return 0 on success, -1 on error.
 */
static int dp_rt_msg_recv(zsock_t *sock, zmq_msg_t *route_msg)
{
	zmq_msg_init(route_msg);

	if (zmq_msg_recv(route_msg, zsock_resolve(sock), 0) <= 0)
		goto error;

	int more = zmq_msg_get(route_msg, ZMQ_MORE);
	while (more) {
		zmq_msg_t sink;
		zmq_msg_init(&sink);
		zmq_msg_recv(&sink, zsock_resolve(sock), 0);
		more = zmq_msg_get(&sink, ZMQ_MORE);
		zmq_msg_close(&sink);
	}

	return 0;
error:
	zmq_msg_close(route_msg);
	return -1;
}

static int route_netlink_recv(void *arg)
{
	zmq_msg_t route_msg;
	zsock_t *sock = arg;

	errno = 0;
	int rc = dp_rt_msg_recv(sock, &route_msg);
	if (rc != 0) {
		if (errno == 0)
			return 0;
		return -1;
	}

	rc = mnl_cb_run(zmq_msg_data(&route_msg),
			zmq_msg_size(&route_msg),
			0, 0, rtnl_process, (void *)CONT_SRC_MAIN);

	if (rc != MNL_CB_OK)
		DP_DEBUG(ROUTE, NOTICE, DATAPLANE,
			 "route message not handled\n");

	zmq_msg_close(&route_msg);

	return 0;
}

static int route_pb_recv(void *arg)
{
	zmq_msg_t route_msg;
	zsock_t *sock = arg;

	errno = 0;
	int rc = dp_rt_msg_recv(sock, &route_msg);
	if (rc != 0) {
		if (errno == 0)
			return 0;
		return -1;
	}

	rc = ip_route_pb_handler(zmq_msg_data(&route_msg),
				 zmq_msg_size(&route_msg),
				 CONT_SRC_MAIN);
	if (rc)
		DP_DEBUG(ROUTE, NOTICE, DATAPLANE,
			 "route message not handled\n");

	zmq_msg_close(&route_msg);

	return 0;
}

/*
 * Open a pull socket using the given url and register the event handler.
 */
static int
open_route_broker_data_sock(enum cont_src_en cont_src,
			    const char *data_url, bool protobuf_fmt)
{
	zsock_t *data_sock;

	data_sock = zsock_new(ZMQ_PULL);
	if (!data_sock)
		rte_panic("Could not open data socket to route broker");

	if (zsock_connect(data_sock, "%s", data_url) < 0)
		rte_panic("Could not connect data socket to route broker");

	cont_src_set_broker_data(cont_src, data_sock);

	dp_register_event_socket(
		zsock_resolve(data_sock),
		protobuf_fmt ? route_pb_recv : route_netlink_recv,
		data_sock);
	return 0;
}

/*
 * Send a request message to the broker ctrl socket.
 * Format is:
 * <request>
 * <proto version>
 * <uuid of this dataplane>
 */
static int
send_route_broker_ctrl_request(zsock_t *ctrl_socket, enum cont_src_en cont_src,
			       const char *req)
{
	zmsg_t *msg;
	int rc = 0;
	uint32_t version = CONTROL_PROTO_VER;

	msg = zmsg_new();
	if (!msg) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Couldn't create new broker message\n",
			cont_src_name(cont_src));
		return -1;
	}
	rc = zmsg_addstr(msg, req);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Couldn't add %s to ZMQ broker message\n",
			cont_src_name(cont_src), req);
		rc = -1;
		goto failure;
	}

	rc = zmsg_addu32(msg, version);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Couldn't add ver to ZMQ broker message\n",
			cont_src_name(cont_src));
		rc = -1;
		goto failure;
	}

	rc = zmsg_addstr(msg, config.uuid);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Couldn't add UUID to ZMQ broker message\n",
			cont_src_name(cont_src));
		rc = -1;
		goto failure;
	}

	rc = zmsg_send(&msg, ctrl_socket);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) Could not send the %s broker message.\n",
			cont_src_name(cont_src), req);
		rc = -1;
		goto failure;
	}
	return rc;

failure:
	zmsg_destroy(&msg);
	return rc;
}

/*
 * Send the CONNECT message to the broker ctrl socket.
 * Format is:
 * CONNECT
 * <proto version>
 * <uuid of this dataplane>
 */
static int
send_route_broker_ctrl_connect(zsock_t *ctrl_socket, enum cont_src_en cont_src)
{
	return send_route_broker_ctrl_request(ctrl_socket, cont_src, "CONNECT");
}

/*
 * Send a KEEPALIVE message to the broker ctrl socket.
 * Format is:
 * KEEPALIVE
 * <proto version>
 * <uuid of this dataplane>
 */
static int
send_route_broker_ctrl_keepalive(zsock_t *ctrl_socket,
				 enum cont_src_en cont_src)
{
	return send_route_broker_ctrl_request(ctrl_socket, cont_src,
					      "KEEPALIVE");
}

static void broker_keepalive_timer_event(struct rte_timer *tim __rte_unused,
					 void *arg)
{
	enum cont_src_en cont_src = (enum cont_src_en)arg;
	zsock_t *ctrl_socket = cont_src_get_broker_ctrl(cont_src);

	send_route_broker_ctrl_keepalive(ctrl_socket, cont_src);
}

/*
 * Start a keepalive timer to the route broker
 */
static int
start_route_broker_keepalives(enum cont_src_en cont_src)
{
	rte_timer_init(&broker_keepalive_timer[cont_src]);
	rte_timer_reset(&broker_keepalive_timer[cont_src],
			rte_get_timer_hz() * BROKER_KEEPALIVE_TIMER_SEC,
			PERIODICAL, rte_get_master_lcore(),
			broker_keepalive_timer_event, (void *)cont_src);
	return 0;
}

/*
 * Receive the ACCEPT from the broker ctrl socket.
 * The message contains the endpoint to use for the route broker data.
 * Format is:
 * ACCEPT
 * <UUID>
 * <data url>
 */
static int broker_ctrl_recv(void *src)
{
	enum cont_src_en cont_src = (enum cont_src_en)src;
	zsock_t *zsocket = cont_src_get_broker_ctrl(cont_src);
	uint32_t data_format = ROUTE_BROKER_FORMAT_NL;
	char *uuid = NULL;
	char *data_url = NULL;
	char *str = NULL;
	zmsg_t *msg = NULL;
	int rc = 0;

	msg = zmsg_recv(zsocket);
	if (!msg)
		return -1;

	str = zmsg_popstr(msg);
	if (!strcmp("RECONNECT", str)) {
		RTE_LOG(ERR, DATAPLANE,
			"route broker requesting reconnect\n");
		reset_dataplane(cont_src, false);
		goto out;
	}
	if (strcmp("ACCEPT", str)) {
		RTE_LOG(ERR, DATAPLANE,
			"unrecognized message from broker ctrl %s\n",
			str);
		rc = -1;
		goto out;
	}

	uuid = zmsg_popstr(msg);
	if (strcmp(uuid, config.uuid)) {
		RTE_LOG(ERR, DATAPLANE,
			"route broker(%s) ACCEPT message mis-match on UUID\n",
			cont_src_name(cont_src));
		rc = -1;
		goto out;
	}

	data_url = zmsg_popstr(msg);
	if (!data_url) {
		RTE_LOG(ERR, DATAPLANE,
			"route broker(%s) ACCEPT message with no url\n",
			cont_src_name(cont_src));
		rc = -1;
		goto out;
	}
	zmsg_popu32(msg, &data_format);

	open_route_broker_data_sock(cont_src, data_url,
				    data_format == ROUTE_BROKER_FORMAT_PB);
	start_route_broker_keepalives(cont_src);
out:
	free(str);
	free(uuid);
	free(data_url);
	zmsg_destroy(&msg);
	return rc;
}

void route_broker_init_event_handler(enum cont_src_en cont_src)
{
	zsock_t *broker = cont_src_get_broker_ctrl(cont_src);

	if (!broker)
		return;

	register_event_socket_src(zsock_resolve(broker), broker_ctrl_recv,
				  (void *)cont_src, cont_src);
}

int init_route_broker_ctrl_connection(zsock_t *socket,
				      enum cont_src_en cont_src)
{
	int rc;

	/* We only have a broker connection for the main src */
	if (cont_src != CONT_SRC_MAIN)
		return 0;

	rc = send_route_broker_ctrl_connect(socket, cont_src);
	if (rc < 0)
		RTE_LOG(ERR, DATAPLANE,
			"master(%s) ZMQ failed to connect to route broker\n",
			cont_src_name(cont_src));
	return rc;
}

/* Make the zmq request socket to route broker */
static zsock_t *open_route_broker_ctrl(enum cont_src_en cont_src)
{
	const char *rib_ctrl_url = NULL;
	zsock_t *zsock;

	switch (cont_src) {
	case CONT_SRC_MAIN:
		rib_ctrl_url = config.rib_ctrl_url;
		break;
	case CONT_SRC_UPLINK:
		return NULL;
	}
	if (rib_ctrl_url == NULL)
		rte_panic("Open route broker(%s) missing url\n",
			  cont_src_name(cont_src));

	zsock = zsock_new(ZMQ_DEALER);
	if (!zsock)
		rte_panic("Open route_broker(%s), cannot open ZMQ socket\n",
			  cont_src_name(cont_src));

	if (zsock_connect(zsock, "%s", rib_ctrl_url) < 0)
		rte_panic("Open route_broker (%s) connect to %s failed: %s\n",
			  cont_src_name(cont_src), rib_ctrl_url,
			  strerror(errno));
	RTE_LOG(DEBUG, DATAPLANE,
		"Connect to route broker(%s) at %s\n", cont_src_name(cont_src),
		rib_ctrl_url);
	return zsock;
}


zsock_t *route_broker_ctrl_socket_create(enum cont_src_en cont_src)
{
	zsock_t *sock = cont_src_get_broker_ctrl(cont_src);

	if (sock == NULL) {
		sock = open_route_broker_ctrl(cont_src);
		cont_src_set_broker_ctrl(cont_src, sock);
	}
	return sock;
}

void route_broker_unsubscribe(enum cont_src_en cont_src)
{
	zsock_t *broker_ctrl = cont_src_get_broker_ctrl(cont_src);
	zsock_t *broker_data = cont_src_get_broker_data(cont_src);

	if (broker_ctrl) {
		dp_unregister_event_socket(zsock_resolve(broker_ctrl));
		zsock_destroy(&broker_ctrl);
		cont_src_set_broker_ctrl(cont_src, NULL);
	}

	if (broker_data) {
		dp_unregister_event_socket(zsock_resolve(broker_data));
		zsock_destroy(&broker_data);
		cont_src_set_broker_data(cont_src, NULL);
		rte_timer_stop(&broker_keepalive_timer[cont_src]);
	}
}
