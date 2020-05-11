/*-
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef IP_RT_PROTOBUF_H
#define IP_RT_PROTOBUF_H

#include <stdint.h>

#include "control.h"

int ip_route_pb_handler(void *data, size_t len, enum cont_src_en cont_src);

#endif /* IP_RT_PROTOBUF_H */
