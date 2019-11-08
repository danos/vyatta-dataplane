/*
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef ROUTE_BROKER_H
#define ROUTE_BROKER_H

#include <czmq.h>

#include "control.h"

/*
 * Create the socket used for the control connection to the route
 * broker. This is only used for the CTRL_SRC_MAIN.
 */
zsock_t *route_broker_ctrl_socket_create(enum cont_src_en cont_src);

/*
 * Close all the broker sockets for this source.
 */
void route_broker_unsubscribe(enum cont_src_en cont_src);

/*
 * Start handling events received on the route broker control
 * connection.
 */
void route_broker_init_event_handler(enum cont_src_en cont_src);

/*
 * Send the CONNECT message to the route broker ctrl socket.
 * This is only done for the CONT_MAIN source.
 */
int init_route_broker_ctrl_connection(zsock_t *socket,
				      enum cont_src_en cont_src);


#endif /* ROUTE_BROKER_H */
