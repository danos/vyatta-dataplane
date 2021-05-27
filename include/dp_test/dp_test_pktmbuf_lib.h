/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Library of functions for packet creation and handling
 */
#ifndef __DP_PKTMBUF_LIB_H__
#define __DP_PKTMBUF_LIB_H__

#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>

struct dp_test_addr {
	int family;
	union {
		in_addr_t ipv4;
		struct in6_addr ipv6;
		uint32_t mpls;
	} addr;
};
/**
 * Create and initialise a UDP IPv4 packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_ipv4_pak(const char *saddr, const char *daddr,
			int n, const int *len);

/**
 * Create and initialise a raw IPv4 packet with the given protocol.
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param protocol [in]	 Protocol, e.g. IPPROTO_UDP
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_raw_ipv4_pak(const char *saddr, const char *daddr,
			    uint8_t protocol, int n, const int *len);

/**
 * Create and initialise an IPv4 UDP packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param sport [in]  UDP source port
 * @param dport [in]  UDP dest port
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_udp_ipv4_pak(const char *saddr, const char *daddr,
			    uint16_t sport, uint16_t dport,
			    int n, const int *len);

/**
 * Create and initialise an IPv6 packet with no protocol.
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_ipv6_pak(const char *saddr, const char *daddr,
			int n, const int *len);

/**
 * Create and initialise a raw IPv6 packet with the given protocol.
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param protocol [in]	 Protocol, e.g. IPPROTO_UDP
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_raw_ipv6_pak(const char *saddr, const char *daddr,
			    uint8_t protocol, int n, const int *len);

/**
 * Create and initialise an IPv6 UDP packet
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param sport [in]  UDP source port (host order)
 * @param dport [in]  UDP dest port
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_udp_ipv6_pak(const char *saddr, const char *daddr,
			    uint16_t sport, uint16_t dport,
			    int n, const int *len);
/**
 * Create and initialise an IPv4 TCP packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param sport [in]  TCP source port
 * @param dport [in]  TCP dest port
 * @param flags [in]  TCP header flags
 * @param seq   [in]  TCP sequence number
 * @param ack   [in]  TCP acknowledgment number
 * @param win   [in]  TCP window value (host order)
 * @param opts  [in]  Byte array of TCP options.  See below.
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 *
 * TCP options - type (1 byte), length (1 byte), value (length-2 bytes), e.g.
 *
 * uint8_t opts[] = {
 *     2, 4, 0x18, 0x02,
 *     1,
 *     3, 3, 1,
 *     0
 * };
 *
 * The options list is terminated when 'type' is 0 (EOL).  Note that when
 * 'type' is 1 (NOP) then there is no length value.  This is commonly used to
 * separate options in a header.
 */
struct rte_mbuf *
dp_test_create_tcp_ipv4_pak(const char *saddr, const char *daddr,
			    uint16_t sport, uint16_t dport, uint8_t flags,
			    uint32_t seq, uint32_t ack, uint16_t win,
			    const uint8_t *opts, int n, const int *len);

/**
 * Create and initialise an IPv6 TCP packet
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param sport [in]  TCP source port (host order)
 * @param dport [in]  TCP dest port
 * @param flags [in]  TCP header flags
 * @param seq   [in]  TCP sequence number
 * @param ack   [in]  TCP acknowledgment number
 * @param win   [in]  TCP window value (host order)
 * @param opts  [in]  Byte array of TCP options. See above.
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_tcp_ipv6_pak(const char *saddr, const char *daddr,
			    uint16_t sport, uint16_t dport, uint8_t flags,
			    uint32_t seq, uint32_t ack, uint16_t win,
			    const uint8_t *opts, int n, const int *len);

/**
 * Calculate IPv4 UDP or TCP checksum.
 *
 * The IPv4 header should not contains options. The layer 4 checksum
 * must be set to 0 in the packet by the caller. The l4 header must be
 * in the first mbuf.
 *
 * @param m [in]      Pointer to the mbuf chain
 * @param ip [in]     Pointer to the contiguous IP header.
 * @param l4_hdr [in] Pointer to the beginning of the L4 header
 * @return
 *   The complemented checksum to set in the IPv4 UDP/TCP header
 */
uint16_t
dp_test_ipv4_udptcp_cksum(const struct rte_mbuf *m, const struct iphdr *ip,
			  void *l4_hdr);

/**
 * Calculate IPv6 UDP or TCP checksum.
 *
 * The layer 4 checksum must be set to 0 in the packet by the caller.
 *
 * @param ip6
 *   The pointer to the contiguous IPv6 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header (must be in first mbuf).
 * @return
 *   The complemented checksum to set in the IPv6 UDP/TCP header
 */
uint16_t
dp_test_ipv6_udptcp_cksum(const struct rte_mbuf *m,
			  const struct ip6_hdr *ip6,
			  const void *l4_hdr);


/*
 * API to allow us to set a given field within the ip header in a buffer.
 */
enum dp_test_pak_field_ {
	DP_TEST_SET_VERSION,
	DP_TEST_SET_SRC_ADDR_IPV4,
	DP_TEST_SET_DST_ADDR_IPV4,
	DP_TEST_SET_IP_ECN,
	DP_TEST_SET_DF,
	DP_TEST_SET_FRAG_MORE,
	DP_TEST_SET_FRAG_OFFSET,
	DP_TEST_SET_TOS,
	DP_TEST_SET_PROTOCOL,
	DP_TEST_SET_TTL,
	DP_TEST_SET_IP_ID,
};

/**
 * Initialize ethernet hdr.  If l2_len is 0, prepend 14 bytes and set
 * m->l2_len to 14.
 *
 * @param m	     [in] Pointer to packet mbuf
 * @param d_addr     [in] Dest mac string, e.g. "aa:bb:cc:dd:ee:ff"
 * @param s_addr     [in] Source mac string
 * @param ether_type [in] Ethernet type (host order), may be 0
 *
 * @return  Pointer to eth header if successful, else NULL
 *
 * To just check and set the mbuf l2_len:
 *   (void)dp_test_pktmbuf_eth_init(m, NULL, NULL, 0);
 *
 * To just check and set the mbuf l2_len and ether type:
 *   (void)dp_test_pktmbuf_eth_init(m, NULL, NULL, RTE_ETHER_TYPE_IPV4);
 */
struct rte_ether_hdr *
dp_test_pktmbuf_eth_init(struct rte_mbuf *m,
			 const char *d_addr,
			 const char *s_addr,
			 uint16_t ether_type);

void
dp_test_set_pak_ip_field(struct iphdr *ip,
			 enum dp_test_pak_field_ field,
			 uint32_t val);
void
dp_test_set_pak_ip6_field(struct ip6_hdr *ip,
			  enum dp_test_pak_field_ field,
			  uint32_t val);

void
dp_test_ipv4_decrement_ttl(struct rte_mbuf *m);

void
dp_test_ipv6_decrement_ttl(struct rte_mbuf *m);

/**
 * Initialize packet to emulate reception on vlan.
 *
 * @param m          [in] Pointer to packet mbuf
 * @param vlan       [in] vlan id
 *
 */
void
dp_test_pktmbuf_vlan_init(struct rte_mbuf *m,
			  uint16_t vlan);

void
dp_test_pktmbuf_vlan_clear(struct rte_mbuf *m);
#endif /* __DP_PKTMBUF_LIB_H__ */
