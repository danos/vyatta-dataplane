/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_ip.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "in_cksum.h"

uint16_t in_cksum(const void *addr, int len)
{
	uint16_t sum;

	sum = rte_raw_cksum(addr, len);

	sum = (~sum) & 0xffff;
	return sum;
}

/*
 * off is an offset where TCP/UDP/ICMP6 header starts.
 * len is a total length of a transport segment.
 * (e.g. TCP header + TCP payload)
 *
 * Build the pseudo header based on the given header and the next.
 * Checksum this pseudo header with the len bytes of data at off.
 *
 * Note: only supports non-chained mbuf
 */
static uint32_t __in6_cksum(const struct ip6_hdr *ip6, uint8_t next,
			    uint32_t off, uint32_t len)
{
	uint64_t sum = 0;
	struct ip6_pseudo_hdr {
		struct in6_addr src;
		struct in6_addr dst;
		uint32_t len;
		uint8_t zero[3];
		uint8_t next;
	} __attribute__((packed)) uph = {
		.src = ip6->ip6_src,
		.dst = ip6->ip6_dst,
		.len = ip6->ip6_plen,
		.next = next,
	};

	sum = rte_raw_cksum(&uph, sizeof(uph));
	sum += rte_raw_cksum((const char *)ip6 + off, len);

	return sum;
}

uint16_t in6_cksum(const struct ip6_hdr *ip6, uint8_t next,
		   uint32_t off, uint32_t len)
{
	uint64_t sum = 0;

	sum = __in6_cksum(ip6, next, off, len);
	sum = __rte_raw_cksum_reduce(sum);
	sum = (~sum) & 0xffff;

	return sum;
}

/*
 * Checksum a TCP, UDP or ICMP IPv4 packet in an mbuf chain.
 *
 * 'ip' should be set to NULL for ICMP.
 *
 * build the pseudo header based on the given header
 * checksum this pseudo header with all the bytes from l4_hdr onwards
 *
 * Assume l4 hdr is in first segment.
 */
uint16_t
dp_in4_cksum_mbuf(const struct rte_mbuf *m, const struct iphdr *ip,
		  const void *l4_hdr)
{
	uint32_t sum = 0;
	uint16_t hdr_sum = 0;
	uint32_t start_offset;
	uint32_t len;

	struct ip4_pseudo_hdr {
		uint32_t src;
		uint32_t dst;
		uint8_t zero;
		uint8_t proto;
		uint16_t len;
	} __attribute__((packed)) uph;

	/* Checksum pseudo header (not ICMP) */
	if (ip) {
		uph.src = ip->saddr;
		uph.dst = ip->daddr;
		uph.zero = 0;
		uph.proto = ip->protocol;
		uph.len = htons(ntohs(ip->tot_len) - sizeof(*ip));
		sum = __rte_raw_cksum(&uph, sizeof(uph), sum);
	}

	start_offset = (char *)l4_hdr - rte_pktmbuf_mtod(m, char *);
	len = m->pkt_len - start_offset;

	rte_raw_cksum_mbuf(m, start_offset, len, &hdr_sum);

	sum += hdr_sum;
	sum = __rte_raw_cksum_reduce(sum);

	return ~sum;
}

/*
 * Checksum a TCP, UDP or ICMP IPv6 packet in an mbuf chain.
 */
uint16_t
dp_in6_cksum_mbuf(const struct rte_mbuf *m, const struct ip6_hdr *ip6,
		  const void *l4_hdr)
{
	uint32_t sum = 0;
	uint16_t hdr_sum = 0;
	uint32_t start_offset;
	uint32_t len;

	if (ip6)
		sum = __in6_cksum(ip6, ip6->ip6_nxt, 0, 0);

	start_offset = (char *)l4_hdr - rte_pktmbuf_mtod(m, char *);
	len = m->pkt_len - start_offset;

	rte_raw_cksum_mbuf(m, start_offset, len, &hdr_sum);

	sum += hdr_sum;
	sum = __rte_raw_cksum_reduce(sum);

	return ~sum;

}


#if defined RTE_ARCH_I686 || defined RTE_ARCH_X86_64
/*
 * It it useful to have an Internet checksum routine which is inlineable
 * and optimized specifically for the task of computing IP header checksums
 * in the normal case (where there are no options and the header length is
 * therefore always exactly five 32-bit words.
 */
ALWAYS_INLINE uint32_t dp_in_cksum_hdr(const struct iphdr *ip)
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

/*
 * Aggressive optimization may result in elision of setting the IPv4 header
 * checksum to zero prior to calculating it, resulting in a faulty calculation.
 * Ensure this does not happen by setting the IPv4 header checksum without
 * relying on its previous value.
 */
ALWAYS_INLINE void dp_set_cksum_hdr(struct iphdr *ip)
{
	unsigned char const *u8 = (void const *)ip;
	uint32_t sum = 0;

	asm("movzwl %1, %0\n"
	    "adcl %2, %0\n"
	    "adcl %3, %0\n"
	    "adcl %4, %0\n"
	    "adcl %5, %0\n"
	    "adcl $0, %0"
	    : "=r" (sum)
	    : "o" (u8[8]),
	      "o" (u8[0]),
	      "o" (u8[4]),
	      "o" (u8[12]),
	      "o" (u8[16])
	    : "cc"
	    );

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	ip->check = ~sum;
}

#else

#include <rte_ip.h>

/* Portable version using DPDK checksum code. */
ALWAYS_INLINE uint16_t dp_in_cksum_hdr(const struct iphdr *ip)
{
	uint16_t sum = rte_raw_cksum(ip, sizeof(*ip));

	return ~sum;
}

ALWAYS_INLINE void dp_set_cksum_hdr(struct iphdr *ip)
{
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);
}

#endif


