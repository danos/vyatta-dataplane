/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VYATTA_DATAPLANE_IP_CHECKSUM_H
#define VYATTA_DATAPLANE_IP_CHECKSUM_H

#include <netinet/in.h>
#include <rte_mbuf.h>

/*
 * Checksum an IPv4 header.
 *
 @return The complemented checksum to set in IP header

 */
uint32_t dp_in_cksum_hdr(const struct iphdr *ip);

/*
 * Set checksum for IPv4 header.
 */
void dp_set_cksum_hdr(struct iphdr *ip);

/*
 * Checksum a TCP, UDP or ICMP IPv4 packet.
 *
 * The IPv4 header should not contains options. The layer 4 checksum
 * must be set to 0 in the packet by the caller. The l4 header must be
 * in the first mbuf.
 *
 * @param m [in] Pointer to mbuf chain
 * @param ip  [in] Pointer to the contiguous IP header.  Set to NULL for
 *                 ICMP (the pseudo hdr is not checksummed)
 * @param l4_hdr [in] Pointer to the beginning of the L4 header
 *
 * @return The complemented checksum to set in the L4 header
 */
uint16_t
dp_in4_cksum_mbuf(const struct rte_mbuf *m, const struct iphdr *ip,
		  const void *l4_hdr);

/*
 * Checksum a TCP, UDP or ICMP IPv6 packet.
 *
 * The layer 4 checksum must be set to 0 in the packet by the
 * caller. The l4 header must be in the first mbuf.
 *
 * @param m [in] Pointer to mbuf chain
 * @param ip  [in] Pointer to the contiguous IPv6 header.
 * @param l4_hdr [in] Pointer to the beginning of the L4 header
 *
 * @return The complemented checksum to set in the L4 header
 */
uint16_t
dp_in6_cksum_mbuf(const struct rte_mbuf *m, const struct ip6_hdr *ip,
		  const void *l4_hdr);

#endif /* VYATTA_DATAPLANE_IP_CHECKSUM_H */
