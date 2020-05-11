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

/*
 * Supports initialization of protobuf IPAddress msg
 * @param[in] addr_msg  ptr to IPAddress message struct
 *
 * @return  Error code or success
 */
int dp_protobuf_create_ipaddr(IPAddress **addr_msg);

/*
 * Supports setting of protobuf IPAddress msg
 * @param[in] addr_msg  IPAddress pointer or destination
 * @param[in] val       value to set (struct ip_addr ptr)
 *
 * @return  Error code or success
 */
int dp_protobuf_set_ipaddr(IPAddress *to, struct ip_addr *from);

#endif
