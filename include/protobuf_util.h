/*-
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VYATTA_DATAPLANE_PROTOBUF_UTIL_H
#define VYATTA_DATAPLANE_PROTOBUF_UTIL_H

#include <string.h>
#include "ip.h"
#include "protobuf/IPAddress.pb-c.h"

/*
 * Supports conversion of protobuf IPAddress msg to ip_addr struct
 * @param[in] addr_msg  IPAddress message struct
 * @param[in] ip_addr   converted to ip_addr struct
 *
 * @return  Error code or success
 */
int dp_protobuf_get_ipaddr(IPAddress *addr_msg, struct ip_addr *addr);

#endif
