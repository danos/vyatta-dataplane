/*
 * Copyright (c) 2019,2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _NPF_ADDR_H_
#define _NPF_ADDR_H_

#include <stdint.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Storage of address (both for IPv4 and IPv6) and netmask */
typedef struct in6_addr		npf_addr_t;
typedef uint8_t                 npf_netmask_t;

#define	NPF_MAX_NETMASK		128
#define	NPF_NO_NETMASK		((npf_netmask_t)~0)

/* Zero initializer for npf_addr_t */
#define NPF_ADDR_ZERO		{ { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }

/*
 * Convert a pointer to an npf_addr containing an IPv4 address to a uint32
 */
#define NPF_ADDR_TO_UINT32(_a)	(ntohl(*((uint32_t *)(_a))))

/*
 * Count Leading Zeros (clz) counts the number of zero bits preceding the most
 * significant one bit, e.g. 0x000000ff gives 24.
 */
static inline int npf_clz(uint32_t word)
{
	if (word == 0)
		return 32;
	return __builtin_clz(word);
}

/*
 * Get IPv4 network mask from a prefix length.  Mask is in host-byte
 * order. e.g.:
 *
 * prefix len	mask
 *      32	0xffffffff
 *      31	0xfffffffe
 *      30	0xfffffffc
 *      24	0xffffff00
 *      16	0xffff0000
 *       1	0x80000000
 *       0	0x00000000
 */
static inline uint32_t npf_prefix_to_net_mask4(npf_netmask_t plen)
{
	uint32_t mask = ((UINT64_C(0xffffffff) << (32 - MIN(plen, 32))));
	return mask;
}

/*
 * Get IPv4 host mask from a prefix length.  Mask is in host-byte order. e.g.:
 *
 * prefix len	host mask
 *      32	0x00000000
 *      31	0x00000001
 *      30	0x00000003
 *      24	0x000000ff
 *      16	0x0000ffff
 *       1	0x7fffffff
 *       0	0xffffffff
 */
static inline uint32_t npf_prefix_to_host_mask4(npf_netmask_t plen)
{
	uint32_t mask = ((UINT64_C(1) << (32 - MIN(plen, 32))) - 1);
	return mask;
}

/*
 * Get IPv4 prefix length from mask.  Mask is in host-byte order. e.g.:
 *
 * mask		prefix len
 * 0xffffffff	32
 * 0xfffffffe	31
 * 0xfffffffc	30
 */
static inline npf_netmask_t npf_mask_to_prefix4(uint32_t mask)
{
	return npf_clz(~mask);
}

/*
 * Get the number of IPv4 addresses for a given prefix length.
 *
 * Note that this *includes* the all-ones and all-zeros addresses.  If
 * required, the caller can subtract 2 if prefix length is 30 or less in order
 * to get the number of useable addresses.
 *
 * prefix len	naddrs
 *      32	1
 *      31	2
 *      30	4
 *      29	8
 *      28	16
 */
static inline uint32_t
npf_prefix_to_naddrs4(npf_netmask_t plen)
{
	return UINT64_C(1) << (32 - MIN(plen, 32));
}

/*
 * Get the number of useable IPv4 addresses for a given prefix length.
 *
 * prefix len	naddrs
 *      32	1
 *      31	2
 *      30	2
 *      29	6
 *      28	14
 */
static inline uint32_t
npf_prefix_to_useable_naddrs4(npf_netmask_t plen)
{
	if (plen <= 30)
		return npf_prefix_to_naddrs4(plen) - 2;
	if (plen == 31)
		return 2;
	return 1;
}

/*
 * Is the given IPv4 address range a full subnet per the given prefix length?
 * Start and stop addresses are in host-byte order.
 *
 * e.g.
 *
 * prefix len	start	stop	return
 *     32	0	0	true
 *     32	1	1	true
 *     31	0	1	true
 *     30	1	2	true
 *     29	1	6	true
 *     28	1	14	true
 *     27	1	29	false
 *     27	2	30	false
 *     27	1	30	true
 */
static inline bool
npf_is_range_subnet4(npf_netmask_t plen, uint32_t start, uint32_t stop)
{
	return (33 - ffs(~(start ^ stop))) == plen;
}

#endif /* NPF_ADDR_H */
