/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
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

#ifdef DEALER_TEST
/*
 * The following function are use for the purposes of unit-testing only.
 *
 * They should not be used in production code
 */
int __test_process_dealer_msg(zmsg_t *msg, enum cont_src_en cont_src);
int __test_process_dealer_reject(zmsg_t *reject, enum cont_src_en cont_src);
int __test_process_dealer_accept(zmsg_t *accept, enum cont_src_en cont_src);
#endif /* DEALER_TEST */

#endif /* DEALER_H */
