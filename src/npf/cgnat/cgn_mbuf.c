/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_mbuf.c - CGNAT mbuf functions.
 */

#include <errno.h>

#include "in_cksum.h"
#include "pktmbuf_internal.h"
#include "if_var.h"

#include "npf/npf_mbuf.h"
#include "npf/nat/nat_proto.h"

#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_mbuf.h"

/*
 * Offset from start of layer 4 header to the furthest byte we will read/write
 * in the l4 header.
 */
static inline uint cgn_l4_max_rw_offset(uint8_t ipproto)
{
	switch (ipproto) {
	case IPPROTO_TCP:
		return offsetof(struct tcphdr, check) + 2;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		return offsetof(struct udphdr, check) + 2;
	case IPPROTO_DCCP:
		return offsetof(struct cgn_dccp, dc_res_type_x) + 1;
	case IPPROTO_ICMP:
		return offsetof(struct icmp, icmp_cksum) + 2;
	default:
		break;
	}
	return 0;
}

static int cgn_decode_icmp(struct cgn_packet *cpk, void *l4)
{
	struct icmp *ic = l4;

	cpk->cpk_l4ports = false;
	cpk->cpk_info |= CPK_ICMP;
	cpk->cpk_cksum = ic->icmp_cksum;
	cpk->cpk_hlen += sizeof(struct icmp);

	switch (ic->icmp_type) {
	case ICMP_ECHO:
		cpk->cpk_info |= (CPK_ICMP_ECHO_REQ | CPK_ICMP_ECHO);
		cpk->cpk_sid = ic->icmp_id;
		cpk->cpk_did = ic->icmp_id;
		break;
	case ICMP_ECHOREPLY:
		cpk->cpk_info |= CPK_ICMP_ECHO;
		cpk->cpk_sid = ic->icmp_id;
		cpk->cpk_did = ic->icmp_id;
		/* Echo replies do not keep sessions alive */
		cpk->cpk_keepalive = false;
		break;
	case ICMP_DEST_UNREACH:
	case ICMP_REDIRECT:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
		cpk->cpk_info |= CPK_ICMP_ERR;
		cpk->cpk_sid = 0;
		cpk->cpk_did = 0;
		/* Error msgs (embedded pkts) do not keep sessions alive */
		cpk->cpk_keepalive = false;
		break;
	default:
		return -CGN_BUF_ICMP;
	}
	return 0;
}

/*
 * Parse the L4 header for IDs and checksum.
 */
static int
cgn_parse_l4(struct rte_mbuf *m, uint l4_offset, uint8_t ipproto,
	     struct cgn_packet *cpk, bool icmp_err)
{
	unsigned char buf[20];
	size_t read_sz = cgn_l4_max_rw_offset(ipproto);
	void *l4;
	int rc;

	/*
	 * The ids (ports/etc)
	 *
	 * For all protocols we support that require an id, we can obtain the
	 * id from the first two (32bit) words of the protocol header.
	 *
	 * However, we can only count on the IP header in the first segment,
	 * so we may need to copy.
	 */

	l4 = (void *)rte_pktmbuf_read(m, l4_offset, read_sz, buf);
	if (unlikely(!l4)) {
		/*
		 * icmp_err indicates that the cache is being populated from
		 * an IP packet within an ICMP error packet, and so may be
		 * truncated.
		 */
		if (unlikely(icmp_err &&
			     (ipproto == IPPROTO_TCP ||
			      ipproto == IPPROTO_DCCP))) {
			read_sz = ICMP_ERROR_MIN_L4_SIZE;

			l4 = (void *)rte_pktmbuf_read(m, l4_offset, read_sz,
						      buf);
			if (!l4)
				return -CGN_BUF_ENOL4;

			cpk->cpk_info |= CPK_ICMP_EMBD_SHORT;
		} else
			return -CGN_BUF_ENOL4;
	}

	switch (ipproto) {
	case IPPROTO_TCP:
		{
			struct tcphdr *tcp = l4;

			/* src/dst ports */
			cpk->cpk_sid = tcp->th_sport;
			cpk->cpk_did = tcp->th_dport;
			cpk->cpk_l4ports = true;

			if (unlikely(cpk->cpk_info & CPK_ICMP_EMBD_SHORT)) {
				cpk->cpk_hlen += ICMP_ERROR_MIN_L4_SIZE;
				break;
			}

			cpk->cpk_tcp_flags = tcp->th_flags;

			/* TCP RSTs do not keep sessions alive */
			if (unlikely(cpk->cpk_tcp_flags & TH_RST))
				cpk->cpk_keepalive = false;

			cpk->cpk_cksum = tcp->check;
			cpk->cpk_hlen += sizeof(struct tcphdr);
			break;
		}
	case IPPROTO_DCCP:
		{
			struct cgn_dccp *dh = l4;

			/* src/dst ports */
			cpk->cpk_sid = dh->dc_src;
			cpk->cpk_did = dh->dc_dst;
			cpk->cpk_l4ports = true;
			cpk->cpk_cksum = dh->dc_checksum;

			if (unlikely(cpk->cpk_info & CPK_ICMP_EMBD_SHORT)) {
				cpk->cpk_hlen += ICMP_ERROR_MIN_L4_SIZE;
				break;
			}
			uint8_t type = (dh->dc_res_type_x >> 1) & 0x0f;

			if (type == DCCP_RESP || type == DCCP_RST)
				cpk->cpk_keepalive = false;

			cpk->cpk_hlen += sizeof(struct cgn_dccp);
			break;
		}
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		{
			struct udphdr *udp = l4;

			/* src/dst ports */
			cpk->cpk_sid = udp->source;
			cpk->cpk_did = udp->dest;
			cpk->cpk_l4ports = true;
			cpk->cpk_cksum = udp->check;
			cpk->cpk_hlen += sizeof(struct udphdr);
			break;
		}
	case IPPROTO_ICMP:
		rc = cgn_decode_icmp(cpk, l4);
		if (unlikely(rc < 0))
			return rc;
		break;
	default: /* All other IP protocols */
		return -CGN_BUF_PROTO;
	}

	return 0;
}

/*
 * Extract the fields we need from the mbuf
 */
int cgn_cache_all(struct rte_mbuf *m, uint l3_offset, struct ifnet *ifp,
		  int dir, struct cgn_packet *cpk, bool icmp_err)
{
	unsigned char buf[sizeof(struct iphdr)];
	struct iphdr *ip;
	int rc;

	/*
	 * Ensure IP header is available.  This *only* copies the header if it
	 * is *not* all in the first segment, else it returns a pointer into
	 * the mbuf.
	 */
	ip = (struct iphdr *)rte_pktmbuf_read(m, l3_offset,
					      sizeof(struct iphdr), buf);
	if (unlikely(!ip))
		return -CGN_BUF_ENOL3;

	cpk->cpk_info     = 0;
	cpk->cpk_ipproto  = ip->protocol;
	cpk->cpk_proto    = nat_proto_from_ipproto(ip->protocol);
	cpk->cpk_vrfid    = pktmbuf_get_vrf(m);
	cpk->cpk_len      = rte_pktmbuf_pkt_len(m) - dp_pktmbuf_l2_len(m);
	cpk->cpk_l3_len   = ip->ihl << 2;
	cpk->cpk_hlen     = cpk->cpk_l3_len;
	cpk->cpk_keepalive = true;
	cpk->cpk_pkt_instd = true;
	cpk->cpk_sid      = 0;
	cpk->cpk_did      = 0;
	cpk->cpk_l4ports  = false;
	cpk->cpk_cksum    = 0;
	cpk->cpk_ifindex = ifp->if_index;
	cpk->cpk_key.k_ifindex = cgn_if_key_index(ifp);
	cpk->cpk_key.k_expired = false;

	if (dir == CGN_DIR_IN || icmp_err)
		cpk->cpk_keepalive = false;

	rc = cgn_parse_l4(m, l3_offset + cpk->cpk_l3_len, ip->protocol, cpk,
			  icmp_err);
	if (unlikely(rc))
		return rc;

	cpk->cpk_saddr = ip->saddr;
	cpk->cpk_daddr = ip->daddr;

	/* Setup direction dependent part of hash key */
	cgn_pkt_key_init(cpk, dir);

	return 0;
}

/*
 * Rewrite IPv4 and/or transports checksums based upon provided checksum deltas,
 * also update the fields in the packet cache.
 *
 * n_ptr points to IP header.
 */
void cgn_rwrcksums(struct cgn_packet *cpk, void *n_ptr,
		   uint16_t l3_chk_delta, uint16_t l4_chk_delta)
{
	uint16_t cksum;
	uint16_t *cksum_ptr;
	struct ip *ip = n_ptr;

	/*
	 * Checksum update for IPv4 header
	 */
	ip->ip_sum = ip_fixup16_cksum(ip->ip_sum, 0xffff, l3_chk_delta);

	if (unlikely(cpk->cpk_ipproto == IPPROTO_UDP && cpk->cpk_cksum == 0))
		return;

	/* L3 pseudo header is not included in ICMP checksum */
	if (cpk->cpk_ipproto == IPPROTO_ICMP)
		l3_chk_delta = 0;

	/* Get ptr to l4 checksum */
	cksum_ptr = (uint16_t *)((char *)n_ptr + cpk->cpk_l3_len +
				 cgn_l4_cksum_offset(cpk->cpk_ipproto));

	cksum = ip_fixup16_cksum(cpk->cpk_cksum, ~l3_chk_delta, l4_chk_delta);

	if (unlikely(cksum == 0 && cpk->cpk_ipproto == IPPROTO_UDP))
		cksum = 0xffff;

	*cksum_ptr = cksum;
}
