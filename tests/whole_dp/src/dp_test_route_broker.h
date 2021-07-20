/*-
 * Copyright (c) 2018-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DP_TEST_ROUTE_BROKER_H
#define DP_TEST_ROUTE_BROKER_H

/*
 * A test version of the route broker process, running as its own thread.
 */
#include <pthread.h>

#include <czmq.h>
#include <zmq.h>

extern zsock_t *broker_data_sock;
extern bool dp_test_route_broker_protobuf;

void dp_test_broker_thread_run(zsock_t *pipe, void *args);

#endif /* DP_TEST_ROUTE_BROKER_H */
