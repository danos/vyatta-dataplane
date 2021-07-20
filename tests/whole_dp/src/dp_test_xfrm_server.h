/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DP_TEST_XFRM_SERVER_H
#define DP_TEST_XFRM_SERVER_H

/*
 * A test version of the route broker process, running as its own thread.
 */
#include <pthread.h>

#include <czmq.h>
#include <zmq.h>

#define MAX_XFRM_SOCKET_NAME_SIZE 48

extern zsock_t *xfrm_server_push_sock;
extern uint32_t xfrm_seq;
extern uint32_t xfrm_seq_received;
extern uint32_t xfrm_ack_err;

extern uint64_t xfrm_bytes;
extern uint64_t xfrm_packets;

void dp_test_xfrm_server_thread_run(zsock_t *pipe, void *args);

#endif /* DP_TEST_XFRM_SERVER_H */
