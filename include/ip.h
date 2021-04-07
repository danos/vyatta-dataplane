/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VYATTA_DATAPLANE_IP_H
#define VYATTA_DATAPLANE_IP_H

#include <netinet/in.h>
#include <stdbool.h>

#include "compiler.h"

/*
 * IPv4 and IPv6 related defines and helpers.
 */

/*
 * The IPv6 version is the 4 most significant bits of the first byte in
 * the header.
 */
#define IPV6_VERSION      0x60
#define IPV6_VERSION_MASK 0xf0

/* The default hoplimit for locally generated IPv6 packets */
#define IPV6_DEFAULT_HOPLIMIT	64

/* Hoplimit for IPv6 packets that should remain on-link */
#define IPV6_ONLINK_HOPLIMIT	255

/*
 * Generate a random id to use in the Identification field of the IPv4 header.
 *
 * @param[in] salt Additional data to help randomise the returned value.
 *
 * @return A random id in the range of 0..65535
 */
uint16_t dp_ip_randomid(uint16_t salt);

union addr_u {
	struct in_addr ip_v4;
	struct in6_addr ip_v6;
};

/* structure to be used by functions that can take either IPv4 or IPv6 addr */
struct ip_addr {
	/*
	 * AF_INET or AF_INET6
	 */
	uint32_t type;
	union addr_u address;
};

static inline bool addr_u_eq_v4(const union addr_u *addr1,
				const union addr_u *addr2)
{
	return addr1->ip_v4.s_addr == addr2->ip_v4.s_addr;
}

static inline bool addr_u_eq_v6(const union addr_u *addr1,
				 const union addr_u *addr2)
{
	return IN6_ARE_ADDR_EQUAL(&addr1->ip_v6, &addr2->ip_v6);
}

/*
 * Check if 2 addresses are equal.
 *
 * @param[in] addr1 The first address.
 * @param[in] addr2 The second address.
 *
 * @return true if they are equal and the type is set to AF_INET or AF_INET6
 * @return false if not equal or type is not set to a valid value.
 *
 */
static inline bool dp_addr_eq(const struct ip_addr *addr1,
			      const struct ip_addr *addr2)
{
	if (addr1->type != addr2->type)
		return false;

	if (addr1->type == AF_INET)
		return addr_u_eq_v4(&addr1->address, &addr2->address);

	if (addr1->type == AF_INET6)
		return addr_u_eq_v6(&addr1->address, &addr2->address);

	return false;
}

/*
 * Check if 2 IPv6 prefixes are equal.
 *
 * @param[in] a1 The first prefix.
 * @param[in] a2 The second prefix.
 * @param[in] prefix_len The length prefix to compare.
 *
 * @return true if the prefixes are equal up to prefix_len.
 * @return false if prefixes are not equal up to prefix_len.
 */
static inline bool dp_in6_prefix_eq(const struct in6_addr *a1,
				    const struct in6_addr *a2,
				    unsigned int prefix_len)
{
	const uint32_t *p1 = a1->s6_addr32;
	const uint32_t *p2 = a2->s6_addr32;

	while (prefix_len >= 32) {
		if (*p1++ != *p2++)
			return false;
		prefix_len -= 32;
	}

	if (likely(prefix_len == 0))
		return true;

	uint32_t m = htonl(~0ul << (32 - prefix_len));

	/* find bits that differ, and mask in network byte order */
	return ((*p1 ^ *p2) & m) == 0;
}

#endif /* VYATTA_DATAPLANE_IP_H */
