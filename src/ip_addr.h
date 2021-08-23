/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef IP_ADDR_H
#define IP_ADDR_H

#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include "ip.h"
#define IP_ADDR_LEN sizeof(struct in_addr)

/*
 * Checks if address is set, true if set, false otherwise
 */
static inline bool is_addr_set(const struct ip_addr *addr)
{
	return (addr->type == AF_INET) || (addr->type == AF_INET6);
}

static inline bool addr_store(struct ip_addr *addr, uint32_t type,
			     const void *data)
{
	if (!addr)
		return false;

	if (!data || (type != AF_INET && type != AF_INET6)) {
		addr->type = AF_UNSPEC;
		return false;
	}

	addr->type = type;
	if (type == AF_INET) {
		addr->address.ip_v4.s_addr = *(in_addr_t *) data;
		return true;
	}
	if (type == AF_INET6) {
		addr->address.ip_v6 = *(struct in6_addr *) data;
		return true;
	}
	return false;
}

/*
 * Turn a prefix length into a network mask
 */
static inline uint32_t prefixlen_to_mask(uint8_t prefixlen)
{
	return htonl(prefixlen == 32 ? 0xffffffff : ~(0xffffffff >> prefixlen));
}

#endif /* IP_ADDR_H */
