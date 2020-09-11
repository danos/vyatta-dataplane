/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef DEALER_H
#define DEALER_H

#include <czmq.h>

#include "control.h"

/*
 * Send the CONNECT message
 */
int init_controller_connection(zsock_t *socket, enum cont_src_en cont_src);
/*
 *  Test for and process the controller's response.
 */
int try_controller_response(zsock_t *socket, enum cont_src_en cont_src);

/*
 * Query conf and wait for response.
 */
void conf_query(enum cont_src_en cont_src);

#endif /* DEALER_H */
