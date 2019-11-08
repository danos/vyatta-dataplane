/*-
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 *
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from tahoe:	in_cksum.c	1.2	86/01/05
 *	from:		@(#)in_cksum.c	1.3 (Berkeley) 1/19/91
 *	from: Id: in_cksum.c,v 1.8 1995/12/03 18:35:19 bde Exp
 * $FreeBSD$
 */

#ifndef IN_CKSUM_H
#define	IN_CKSUM_H	1

#include <endian.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <stdint.h>

struct ip6_hdr;
struct rte_mbuf;

/*
 * The IP one's complement checksum routine can be carried out without
 * byte swapping on both little and big endian machines,  as the carry
 * around works correctly for both.
 */
#if (__BYTE_ORDER == __LITTLE_ENDIAN) || (__BYTE_ORDER == __BIG_ENDIAN)
# define IPCHK_NTOHS(x) (x)
# define IPCHK_HTONS(x) (x)
#else
# include <arpa/inet.h>

# define IPCHK_NTOHS(x) ntohs(x)
# define IPCHK_HTONS(x) htons(x)
#endif

/*
 * This uses the algorithm given in RFC1624 for incremental checksum update
 *
 *     Given the following notation:
 *
 *           HC  - old checksum in header
 *           C   - one's complement sum of old header
 *           HC' - new checksum in header
 *           C'  - one's complement sum of new header
 *           m   - old value of a 16-bit field
 *           m'  - new value of a 16-bit field
 *
 *     Then:
 *           HC' = ~(C + (-m) + m')    --    [Eqn. 3]
 *               = ~(~HC + ~m + m')
 *
 */


/*
 * The 'core' part of the RFC 1624 algorithm,  assuming that we have not
 * negated the output value,  and hence do not need to negate the input
 * value.
 *    i.e. the RFC specifies:
 *	HC' = ~(~HC + ~m + m')
 *    whereas this implements:
 *	HC' = HC + ~m + m'
 */
static inline uint16_t
ip_partial_chksum_adjust(uint16_t cksum, uint16_t old_val, uint16_t new_val)
{
	uint16_t complement_m = ~IPCHK_NTOHS(old_val);
	uint16_t m_prime = IPCHK_NTOHS(new_val);

#ifdef __x86_64
	asm("addw %1, %0\n"
	    "adcw %2, %0\n"
	    "adcw $0, %0"
	    : "+r" (cksum)
	    : "g" (complement_m),
	      "g" (m_prime)
	    : "cc"
	    );
#else
	uint32_t sum = IPCHK_NTOHS(cksum);

	sum += complement_m + m_prime;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	cksum = sum;
#endif

	return IPCHK_HTONS(cksum);
}

#undef IPCHK_NTOHS
#undef IPCHK_HTONS

/*
 * ip_fixup{16,32}_cksum: update IP checksum.
 */
static inline uint16_t
ip_fixup16_cksum(uint16_t cksum, uint16_t odatum, uint16_t ndatum)
{
	cksum = ~ip_partial_chksum_adjust(~cksum, odatum, ndatum);

	return cksum;
}

static inline uint16_t
ip_fixup32_cksum(uint16_t cksum, uint32_t odatum, uint32_t ndatum)
{

	cksum = ip_fixup16_cksum(cksum, odatum & 0xffff, ndatum & 0xffff);
	cksum = ip_fixup16_cksum(cksum, odatum >> 16, ndatum >> 16);
	return cksum;
}

uint16_t in_cksum(const void *addr, int len);

uint16_t in6_cksum(const struct ip6_hdr *, uint8_t, uint32_t, uint32_t);

#if defined RTE_ARCH_I686 || defined RTE_ARCH_X86_64
/*
 * It it useful to have an Internet checksum routine which is inlineable
 * and optimized specifically for the task of computing IP header checksums
 * in the normal case (where there are no options and the header length is
 * therefore always exactly five 32-bit words.
 */
static inline uint32_t in_cksum_hdr(const struct iphdr *ip)
{
	/*
	 * Avoid violating type aliasing rules
	 */
	union ip32u {
		struct iphdr ip;
		uint32_t u32[5];
	} const *ipu = (const union ip32u *)ip;
	uint32_t sum = 0;

	asm("addl %1, %0\n"
	    "adcl %2, %0\n"
	    "adcl %3, %0\n"
	    "adcl %4, %0\n"
	    "adcl %5, %0\n"
	    "adcl $0, %0"
	    : "+r" (sum)
	    : "g" (ipu->u32[0]),
	      "g" (ipu->u32[1]),
	      "g" (ipu->u32[2]),
	      "g" (ipu->u32[3]),
	      "g" (ipu->u32[4])
	    : "cc"
	    );

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

#else

#include <rte_ip.h>

/* Portable version using DPDK checksum code. */
static inline uint16_t in_cksum_hdr(const struct iphdr *ip)
{
	uint16_t sum = rte_raw_cksum(ip, sizeof(*ip));

	return ~sum;
}
#endif

/**
 * Compute checksum of IP header.
 * Since IP options are rare, optimize for the case of no options
 */
static inline uint16_t ip_checksum(const struct iphdr *ip, uint16_t hlen)
{
	if (likely(hlen == sizeof(struct iphdr)))
		return in_cksum_hdr(ip);
	else
		return in_cksum(ip, hlen);
}

/**
 * Checksum a TCP, UDP or ICMP IPv4 packet.
 *
 * The IPv4 header should not contains options. The layer 4 checksum
 * must be set to 0 in the packet by the caller. The l4 header must be
 * in the first mbuf.
 *
 * @param pak [in] Pointer to mbuf chain
 * @param ip  [in] Pointer to the contiguous IP header.  Set to NULL for
 *                 ICMP (the pseudo hdr is not checksummed)
 * @param l4_hdr [in] Pointer to the beginning of the L4 header
 *
 * @return
 *   The complemented checksum to set in the IPv4 TCP, UDP or ICMP header
 */
uint16_t
in4_cksum_mbuf(const struct rte_mbuf *, const struct iphdr *,
	       const void *);

/**
 * Checksum a TCP, UDP or ICMP IPv6 packet.
 *
 * The layer 4 checksum must be set to 0 in the packet by the
 * caller. The l4 header must be in the first mbuf.
 *
 * @param pak [in] Pointer to mbuf chain
 * @param ip  [in] Pointer to the contiguous IPv6 header.
 * @param l4_hdr [in] Pointer to the beginning of the L4 header
 *
 * @return
 *   The complemented checksum to set in the IPv4 TCP, UDP or ICMPv6 header
 */
uint16_t
in6_cksum_mbuf(const struct rte_mbuf *, const struct ip6_hdr *,
	       const void *);

#endif /* IN_CKSUM_H */
