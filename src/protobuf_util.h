/*-
 * Copyright (c) 2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef PROTOBUF_UTIL_H
#define PROTOBUF_UTIL_H

#include "ip_addr.h"
#include "protobuf/IPAddress.pb-c.h"

int protobuf_get_ipaddr(IPAddress *addr_msg, struct ip_addr *addr);

#endif
