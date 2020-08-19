/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef XFRM_CLIENT_H
#define XFRM_CLIENT_H

#include <czmq.h>

#include "control.h"

extern bool xfrm_direct;
/*
 * Close all the client sockets for this source.
 */
void xfrm_client_unsubscribe(void);

int xfrm_client_init(void);

int xfrm_client_send_ack(uint32_t seq, int err);
#endif /* XFRM_CLIENT_H */
