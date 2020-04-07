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

extern zsock_t *broker_data_sock;
void dp_test_broker_thread_run(zsock_t *pipe, void *args);
