/*-
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef IP_TTL_H
#define IP_TTL_H
#include "in_cksum.h"

#define IPTTLDEC 1
#define IPDEFTTL 64
static inline void decrement_ttl(struct iphdr *ip)
{
	uint16_t val;

	ip->ttl -= IPTTLDEC;
	val = (uint16_t) ~htons(IPTTLDEC << 8);
	if (ip->check >= val)
		ip->check -= val;
	else
		ip->check += ~val;
}

static inline void increment_ttl(struct iphdr *ip)
{
	uint16_t val;

	ip->ttl += IPTTLDEC;
	val = (uint16_t) htons(IPTTLDEC << 8);
	if (ip->check <= val)
		ip->check += ~val;
	else
		ip->check -= val;
}

static inline void ip_set_ttl(struct iphdr *ip, uint8_t ttl)
{
	/*
	 * Note that ip_partial_chksum_adjust() operates correctly
	 * irrespective of if its arguments are in native or byte
	 * swapped order, as long as they are all consistent.
	 *
	 * So on little endian, we'll be processing values which
	 * are in the wrong order,  i.e. TTL in low order bits.
	 * Whereas on big endian we'll have the values in the
	 * correct order, i.e. TTL in high order bits.
	 *
	 * We use the below construct to load the TTL bits in an order
	 * naive fashion such that we meet the above constraints.
	 *
	 * The alternative would be simply to generate the values as:
	 *
	 *    uint16_t old_val = ntohs(ip->ttl << 8);
	 *
	 * and work from there,  however this union construct
	 * generates better x86_64 code, with fewer data dependencies,
	 * and is also correct for big endian systems.
	 */
	union load {
		uint16_t w;
		uint8_t b[2];
	};

	union load old_val = { 0 };
	union load new_val = { 0 };
	old_val.b[0] = ip->ttl;
	new_val.b[0] = ttl;

	ip->ttl = ttl;
	ip->check = ~ip_partial_chksum_adjust(~ip->check, old_val.w, new_val.w);
}

#endif /* IP_TTL_H */
