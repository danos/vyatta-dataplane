/*-
 * Copyright (c) 2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "protobuf_util.h"
#include "stdio.h"

int protobuf_get_ipaddr(IPAddress *addr_msg, struct ip_addr *addr)
{
	if (!addr_msg)
		return -1;

	if (addr_msg->address_oneof_case ==
	    IPADDRESS__ADDRESS_ONEOF_IPV4_ADDR) {
		memcpy(&addr->address.ip_v4,
		       &addr_msg->ipv4_addr,
		       sizeof(addr->address.ip_v4));
		addr->type = AF_INET;
		return 0;
	} else if (addr_msg->address_oneof_case ==
		   IPADDRESS__ADDRESS_ONEOF_IPV6_ADDR &&
		   sizeof(addr->address.ip_v6) == addr_msg->ipv6_addr.len) {
		memcpy(&addr->address.ip_v6,
		       addr_msg->ipv6_addr.data,
		       addr_msg->ipv6_addr.len);
		addr->type = AF_INET6;
		return 0;
	}
	return -1;
}

