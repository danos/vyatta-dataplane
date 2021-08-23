/*-
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef ZMQ_DP_H
#define ZMQ_DP_H

#include <czmq.h>
#include <stdint.h>

#include "control.h"

/* Protocol version for Uplink control messages */
#define CONTROL_PROTO_VER 0

/*
 * Add and pop functions for uint16_t values
 *
 * These functions return 0 on success and -1 on failure.
 */
int zmsg_addu16(zmsg_t *msg, uint16_t u);
int zmsg_popu16(zmsg_t *msg, uint16_t *p);

/*
 * Add and pop functions for uint32_t values
 *
 * These functions return 0 on success and -1 on failure.
 */
int zmsg_addu32(zmsg_t *msg, uint32_t u);
int zmsg_popu32(zmsg_t *msg, uint32_t *p);

/*
 * Add and pop functions for uint64_t values
 *
 * These functions return 0 on success and -1 on failure.
 */
int zmsg_addu64(zmsg_t *msg, uint64_t u);
int zmsg_popu64(zmsg_t *msg, uint64_t *p);

/*
 * Send the Controller our CONNECT message.
 *
 * Send to the controller our, formatted CONNECT message via the ZMQ csocket.
 *
 * Returns -1 on failure.
 */
int send_controller_connect(zsock_t *csocket, enum cont_src_en cont_src);

/*
 * Do zmsg_send(), but also destroy message on failure
 */
int zmsg_send_and_destroy(zmsg_t **msg, void *dest);

/*
 * Handle end message from zactor
 */
int zactor_terminated(zloop_t *loop, zsock_t *sock, void *arg);

#endif /* ZMQ_DP_H */
