/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_LOG_PROTOBUF_ZMQ_H_
#define _CGN_LOG_PROTOBUF_ZMQ_H_

#include "npf/cgnat/cgn_log.h"

int cl_zmq_set_hwm(enum cgn_log_type ltype, int32_t hwm);
void cgn_show_zmq(FILE *f);

#endif /* _CGN_LOG_PROTOBUF_ZMQ_H_ */
