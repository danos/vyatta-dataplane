/*-
 * Copyright (c) 2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "vplane_log.h"
#include "protobuf_util.h"
#include "stdio.h"

int dp_protobuf_get_ipaddr(IPAddress *addr_msg, struct ip_addr *addr)
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
	}

	if (addr_msg->address_oneof_case ==
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

int dp_protobuf_create_ipaddr(IPAddress **addr_msg)
{
	if (!addr_msg) {
		RTE_LOG(ERR, DATAPLANE,
			"Error in addr value\n");
		return -1;
	}

	const IPAddress addr = IPADDRESS__INIT;
	*addr_msg = malloc(sizeof(addr));
	if (!*addr_msg) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to allocate protobuf ipaddr\n");
		return -1;
	}
	memcpy(*addr_msg, &addr, sizeof(addr));
	(*addr_msg)->ipv6_addr.data = malloc(sizeof(uint32_t) * 4);
	if (!(*addr_msg)->ipv6_addr.data) {
		free(*addr_msg);
		RTE_LOG(ERR, DATAPLANE,
			"Failed to allocate protobuf ipaddr\n");
		return -1;
	}
	return 0;
}

int dp_protobuf_set_ipaddr(IPAddress *to, struct ip_addr *from)
{
	if (from->type == AF_INET) {
		to->address_oneof_case = IPADDRESS__ADDRESS_ONEOF_IPV4_ADDR;
		to->ipv4_addr = from->address.ip_v4.s_addr;
	} else if (from->type == AF_INET6) {
		to->address_oneof_case = IPADDRESS__ADDRESS_ONEOF_IPV6_ADDR;
		memcpy(to->ipv6_addr.data, &from->address.ip_v6, 16);
		to->ipv6_addr.len = 16;
	} else
		return -1;
	return 0;
}
