/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*-
 * Copyright (c) 2009-2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Various procotol related helper routines.
 *
 * This layer manipulates npf_cache_t structure i.e. caches requested headers
 * and stores which information was cached in the information bit field.
 * It is also responsibility of this layer to update or invalidate the cache
 * on rewrites (e.g. by translation routines).
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_per_lcore.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "in_cksum.h"
#include "netinet6/in6.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_mbuf.h"
#include "npf/npf_nat.h"
#include "npf/npf_rc.h"

#define ICMP_ERROR_MIN_L4_SIZE	8

#define IPV6_HDR_FO_MASK 0xFFF8		/* fragment hdr mask - in host order */

static int npf_rw_proto_cksum(npf_cache_t *npc,
			      struct rte_mbuf *nbuf, uint16_t sum);
static int npf_set_ip_size(npf_cache_t *npc,
			   struct rte_mbuf *nbuf, uint16_t sz);
static int npf_rw_udp_len(npf_cache_t *npc,
			  struct rte_mbuf *nbuf, uint16_t len);

/*
 * Optimized version of npf_fetch_datum.
 * Assumes header in one mbuf.
 */
static inline void
__nbuf_fetch_datum(struct rte_mbuf *m __unused,
		   void *n_ptr, size_t len, void *buf)
{
	assert((char *)n_ptr + len
	       <= rte_pktmbuf_mtod(m, char *)  + rte_pktmbuf_data_len(m));
	memcpy(buf, n_ptr, len);
}

/* Optimized version to fetch header data. */

static inline int
__nbuf_advfetch(struct rte_mbuf **nbuf, void **n_ptr, u_int n,
		size_t len, void *buf)
{
	const struct rte_mbuf *m = *nbuf;
	char *nxt = *n_ptr;
	ptrdiff_t offs = nxt - rte_pktmbuf_mtod(m, char *);

	/* the fast way, data is in first segment */
	if (likely(offs + n + len <= m->data_len)) {
		nxt += n;
		memcpy(buf, nxt, len);
		*n_ptr = nxt;
		return 0;
	}

	/* "the cowboy way" */
	return nbuf_advfetch(nbuf, n_ptr, n, len, buf);
}

/*
 * npf_tcpsaw: helper to fetch SEQ, ACK, WIN and return TCP data length.
 *
 * => Returns all values in host byte-order.
 */
int
npf_tcpsaw(const npf_cache_t *npc, tcp_seq *seq, tcp_seq *ack, uint32_t *win)
{
	const struct tcphdr *th = &npc->npc_l4.tcp;
	u_int thlen;

	assert(npf_cache_ipproto(npc) == IPPROTO_TCP);

	*seq = ntohl(th->seq);
	*ack = ntohl(th->ack_seq);
	*win = (uint32_t)ntohs(th->window);
	thlen = th->doff << 2;

	if (npf_iscached(npc, NPC_IP4)) {
		const struct ip *ip = &npc->npc_ip.v4;
		return ntohs(ip->ip_len) - npf_cache_hlen(npc) - thlen;
	}
	if (npf_iscached(npc, NPC_IP6)) {
		const struct ip6_hdr *ip6 = &npc->npc_ip.v6;
		return ntohs(ip6->ip6_plen) - thlen;
	}
	return 0;
}

static inline void
npf_update_grouper(npf_cache_t *npc, void *from, uint offset, uint length)
{
	memcpy(npc->npc_grouper + offset, from, length);
}

/*
 * Parse TCP options.  Return window scale option value and, optionally, MSS
 * option value.
 */
bool
npf_fetch_tcpopts(const npf_cache_t *npc, struct rte_mbuf *nbuf,
		  uint16_t *mss, uint8_t *wscale)
{
	void *n_ptr = dp_pktmbuf_mtol4(nbuf, void *);
	const struct tcphdr *th = &npc->npc_l4.tcp;
	int topts_len, step;

	assert(npf_iscached(npc, NPC_IP46));
	assert(npf_cache_ipproto(npc) == IPPROTO_TCP);

	/* Determine if there are any TCP options, get their length. */
	topts_len = (th->doff << 2) - sizeof(struct tcphdr);
	if (topts_len <= 0) {
		/* No options. */
		return false;
	}

	/* First step: advance over TCP header up to options. */
	step = sizeof(struct tcphdr);

	while (topts_len > 0) {
		uint16_t val16;
		uint8_t val;

		/* Fetch the option type value */
		if (__nbuf_advfetch(&nbuf, &n_ptr, step, sizeof(val), &val))
			return false;

		switch (val) {
		case TCPOPT_EOL:
			/* Done. */
			return true;
		case TCPOPT_NOP:
			topts_len--;
			step = 1;
			break;
		case TCPOPT_MAXSEG:
			if (__nbuf_advfetch(&nbuf, &n_ptr, 2,
					    sizeof(val16), &val16))
				return false;
			if (mss)
				*mss = val16;
			topts_len -= TCPOLEN_MAXSEG;
			step = sizeof(val16);
			break;
		case TCPOPT_WINDOW:
			/* TCP Window Scaling (RFC 1323). */
			if (__nbuf_advfetch(&nbuf, &n_ptr, 2,
					    sizeof(val), &val))
				return false;
			*wscale = (val > TCP_MAX_WINSHIFT) ?
				TCP_MAX_WINSHIFT : val;
			topts_len -= TCPOLEN_WINDOW;
			step = sizeof(val);
			break;
		default:
			/* Fetch the option length value */
			if (__nbuf_advfetch(&nbuf, &n_ptr, 1,
					    sizeof(val), &val))
				return false;
			if (val < 2 || val > topts_len)
				return false;
			topts_len -= val;
			step = val - 1;
		}
	}

	return true;
}

/* get all tcp options */
void *npf_get_tcp_options(npf_cache_t *npc, struct rte_mbuf *nbuf, void *buf)
{
	struct tcphdr *th = &npc->npc_l4.tcp;
	void *ptr = npf_iphdr(nbuf);
	uint16_t offset = npf_cache_hlen(npc) + sizeof(struct tcphdr);
	uint16_t len = (th->doff << 2) - sizeof(struct tcphdr);

	if (__nbuf_advfetch(&nbuf, &ptr, offset, len, buf))
		return NULL;
	return buf;
}

/* store all tcp options */
void npf_store_tcp_options(npf_cache_t *npc, struct rte_mbuf *nbuf, void *buf)
{
	struct tcphdr *th = &npc->npc_l4.tcp;
	void *ptr = npf_iphdr(nbuf);
	uint16_t offset = npf_cache_hlen(npc) + sizeof(struct tcphdr);
	uint16_t len = (th->doff << 2) - sizeof(struct tcphdr);

	nbuf_advstore(&nbuf, &ptr, offset, len, buf);
}

/*
 * Cache IPv6 fragmentation header.
 *
 * n_ptr points to the fragmentation header within the mbuf chain that
 * start with 'm'.
 */
static void
npf_cache_ipv6_fh(npf_cache_t *npc, struct rte_mbuf *m,
		  void *n_ptr)
{
	struct ip6_frag fh;

	if (__nbuf_advfetch(&m, &n_ptr, 0, sizeof(struct ip6_frag), &fh) != 0)
		return;

	npc->fh_offset = ntohs(fh.ip6f_offlg) & IPV6_HDR_FO_MASK;
	/* IP6F_MORE_FRAG is in network byte order */
	npc->fh_more = (fh.ip6f_offlg & IP6F_MORE_FRAG) != 0;
	npc->fh_id = ntohl(fh.ip6f_ident);
}

static void
npf_cache_ipv6_routing_hdr(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr)
{
	struct ip6_rthdr rthdr;

	if (__nbuf_advfetch(&nbuf, &n_ptr, 0, sizeof(rthdr), &rthdr) != 0)
		return;

	npc->npc_info |= NPC_IPV6_ROUTING;
	npc->npc_ipv6_routing_type = rthdr.ip6r_type;
}

/*
 * Limited validation checks for IPv4 packet.
 * These are redundant when routing, but necessary for bridging.
 */
static int
npf_ipv4_valid(const struct rte_mbuf *m, const void *n_ptr)
{
	const struct ip *ip = n_ptr;
	const char *eod;
	uint16_t hlen;

	eod = rte_pktmbuf_mtod(m, char *) + rte_pktmbuf_data_len(m);

	if (unlikely((const char *) n_ptr + sizeof(struct ip) > eod))
		return -NPF_RC_L3_SHORT;

	if (unlikely(ip->ip_v != IPVERSION))
		return -NPF_RC_L3_HDR_VER;

	hlen = ip->ip_hl << 2;
	if (unlikely(hlen < sizeof(struct ip)))
		return -NPF_RC_L3_HDR_LEN;
	if (unlikely((const char *) n_ptr + hlen > eod))
		return -NPF_RC_L3_SHORT;

	return 0;
}

static int
npf_fetch_ipv4(npf_cache_t *npc, struct rte_mbuf *nbuf, const void *n_ptr)
{
	int rc = npf_ipv4_valid(nbuf, n_ptr);

	if (unlikely(rc < 0))
		return rc;

	struct ip *ip = &npc->npc_ip.v4;

	memcpy(ip, n_ptr, sizeof(struct ip));

	if (ip->ip_off & ~htons(IP_DF | IP_RF)) /*Note fragmentation.*/
		npc->npc_info |= NPC_IPFRAG;

	/* Cache: layer 3 - IPv4. */
	npc->npc_alen = sizeof(struct in_addr);
	npc->npc_srcdst = (npf_srcdst_t *)&ip->ip_src;
	npc->npc_info |= NPC_IP4;
	npc->npc_hlen = ip->ip_hl << 2;
	npc->npc_proto_final = npc->npc_ip.v4.ip_p;
	return 0;
}

/* Limited validation checks for IPv6 packet. */
static int
npf_ipv6_valid(const struct rte_mbuf *m, const void *n_ptr)
{
	const char *eod
		= rte_pktmbuf_mtod(m, char *) + rte_pktmbuf_data_len(m);

	if ((const char *) n_ptr + sizeof(struct ip6_hdr) > eod)
		return -NPF_RC_L3_SHORT;

	const struct ip6_hdr *ip6 = n_ptr;

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return -NPF_RC_L3_HDR_VER;

	return 0;
}

static int
npf_fetch_ipv6(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr)
{
	int rc = npf_ipv6_valid(nbuf, n_ptr);

	if (unlikely(rc < 0))
		return rc;

	struct ip6_hdr *ip6 = &npc->npc_ip.v6;

	uint32_t hlen = sizeof(struct ip6_hdr), next_hlen;
	uint16_t last_unfrg_hlen;
	uint16_t last_unfrg_hofs;

	/* Fetch IPv6 header and set initial next-protocol value. */
	memcpy(ip6, n_ptr, sizeof(struct ip6_hdr));
	npc->npc_proto_final = ip6->ip6_nxt;
	npc->npc_hlen = hlen;

	/*
	 * Scan an IPv6 packet and cache the following:
	 *
	 *   1. offset of last unfragmentable extension header
	 *   2. size of last unfragmentable extension header
	 *   3. offset of fragmentation header (0 if no frag hdr)
	 *   4. Protocol type of first fragmentable header
	 *
	 * The Unfragmentable Part consists of the IPv6 header
	 * plus any extension headers that must be processed
	 * by nodes en route to* the destination, that is, all
	 * headers up to and including the Routing header if
	 * present, else the Hop-by-Hop Options header if
	 * present, else no extension headers.
	 */

	/*
	 * Offset of last unfragmentable header, *not*
	 * including the fragmentation header, from the start
	 * of the layer 3 header.  (0 means that the IPv6
	 * header itself is the last/only header before the
	 * fragmentation header)
	 */
	last_unfrg_hofs = 0;

	/*
	 * Length of the last unfragmentable header, *not* including
	 * the fragmentation header.
	 */
	last_unfrg_hlen = hlen;

	/*
	 * Advance by the length of the current header and
	 * prefetch the extension header.
	 */
	while (npc->npc_proto_final != IPPROTO_NONE) {
		struct ip6_ext ip6e;

		if (unlikely(__nbuf_advfetch(&nbuf, &n_ptr, hlen,
				     sizeof(struct ip6_ext), &ip6e) != 0)) {
			/* Failed to fetch header */
			npc->npc_proto_final = IPPROTO_NONE;
			break;
		}

		/*
		 * Determine whether we are going to continue.
		 */
		switch (npc->npc_proto_final) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
			/*
			 * Header length is the length of the
			 * header, in units of 8 octets, *not*
			 * including the first 8 octets (hence
			 * the '+ 1').
			 *
			 * Will be in *every* fragment, if
			 * present
			 */
			next_hlen = (ip6e.ip6e_len + 1) << 3;
			break;

		case IPPROTO_ROUTING:
			npf_cache_ipv6_routing_hdr(npc, nbuf, n_ptr);
			next_hlen = (ip6e.ip6e_len + 1) << 3;
			break;

		case IPPROTO_FRAGMENT:
			/*
			 * Fetch the remaining 6 bytes of the
			 * fragmentation hdr
			 */
			npf_cache_ipv6_fh(npc, nbuf, n_ptr);
			npc->npc_info |= NPC_IPFRAG;
			next_hlen = sizeof(struct ip6_frag);
			break;
		case IPPROTO_AH:
			/*
			 * The authentication header will
			 * appear in the fragmentable part,
			 * i.e. only once, and *after* any
			 * hop-by-hop, dest opts, routing, or
			 * frag headers.
			 */
			next_hlen = (ip6e.ip6e_len + 2) << 2;
			break;
		default:
			/*
			 * We have reached the first
			 * fragmentable ext. header, so stop
			 * here
			 */
			next_hlen = 0;
			break;
		}

		if (next_hlen == 0)
			break;

		if (npc->npc_proto_final != IPPROTO_FRAGMENT) {
			last_unfrg_hlen = next_hlen;
			last_unfrg_hofs += hlen;
		}
		npc->npc_proto_final = ip6e.ip6e_nxt;
		npc->npc_hlen += next_hlen;
		hlen = next_hlen;
	}

	/* Store the l3_len, if not calculated earlier. */
	if (dp_pktmbuf_l3_len(nbuf) == 0)
		dp_pktmbuf_l3_len(nbuf) = npc->npc_hlen;

	npc->last_unfrg_hlen = last_unfrg_hlen;
	npc->last_unfrg_hofs = last_unfrg_hofs;

	/* Cache: layer 3 - IPv6. */
	npc->npc_alen = sizeof(struct in6_addr);
	npc->npc_srcdst = (npf_srcdst_t *)&ip6->ip6_src;
	npc->npc_info |= NPC_IP6;

	return 0;
}


/*
 * npf_fetch_ip: fetch, check and cache IP header.
 */
static int npf_fetch_ip(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
			 uint16_t eth_proto)
{
	switch (ntohs(eth_proto)) {
	case RTE_ETHER_TYPE_IPV4:
		return npf_fetch_ipv4(npc, nbuf, n_ptr);

	case RTE_ETHER_TYPE_IPV6:
		return npf_fetch_ipv6(npc, nbuf, n_ptr);

	default:
		return -NPF_RC_NON_IP;
	}
}

/* In output path post TTL decrement recache the TTL and checksum */
void npf_recache_ip_ttl(npf_cache_t *npc, struct rte_mbuf *nbuf)
{
	if (!npf_iscached(npc, NPC_IP46))
		return;
	char *n_ptr = dp_pktmbuf_mtol3(nbuf, char *);

	/* This reads TTL/PROTO/CHECKSUM */
	if (npf_iscached(npc, NPC_IP4)) {
		struct ip *ip = &npc->npc_ip.v4;
		n_ptr += offsetof(struct ip, ip_ttl);
		__nbuf_fetch_datum(nbuf, n_ptr, 4, &ip->ip_ttl);
	}

	/* This reads the HLIM alone */
	if (npf_iscached(npc, NPC_IP6)) {
		struct ip6_hdr *ip6 = &npc->npc_ip.v6;
		n_ptr += offsetof(struct ip6_hdr, ip6_hlim);
		__nbuf_fetch_datum(nbuf, n_ptr, 1, &ip6->ip6_hlim);
	}
}

/*
 * npf_fetch_tcp: fetch, check and cache TCP header.
 *
 * "icmp_err" indicates that the cache is being populated from an IP
 * packet within an ICMP error packet, and so may be truncated.
 */
static inline int npf_fetch_tcp(npf_cache_t *npc, struct rte_mbuf *nbuf,
				void *n_ptr, u_int hlen, bool icmp_err)
{
	struct tcphdr *th = &npc->npc_l4.tcp;

	/* Fetch TCP header. */
	if (__nbuf_advfetch(&nbuf, &n_ptr, hlen, sizeof(struct tcphdr), th)) {
		if (icmp_err) {
			if (__nbuf_advfetch(&nbuf, &n_ptr, hlen,
					    ICMP_ERROR_MIN_L4_SIZE, th))
				return -NPF_RC_L4_SHORT;
			npc->npc_info |= NPC_SHORT_ICMP_ERR;
		} else
			return -NPF_RC_L4_SHORT;
	}

	npc->npc_info |= NPC_L4PORTS;

	return 0;
}

/*
 * npf_fetch_udp: fetch, check and cache UDP/UDP-Lite header.
 */
static inline int npf_fetch_udp(npf_cache_t *npc, struct rte_mbuf *nbuf,
				void *n_ptr, u_int hlen)
{
	struct udphdr *uh = &npc->npc_l4.udp;

	/* Fetch UDP/UDP-Lite header. */
	if (__nbuf_advfetch(&nbuf, &n_ptr, hlen, sizeof(struct udphdr), uh))
		return -NPF_RC_L4_SHORT;

	npc->npc_info |= NPC_L4PORTS;

	return 0;
}

/*
 * npf_fetch_sctp: fetch, check and cache common STCP header.
 *
 * This only fetches the basic 'common header',  it does not fetch any
 * of the various chunks.
 */
static inline int npf_fetch_sctp(npf_cache_t *npc, struct rte_mbuf *nbuf,
				 void *n_ptr, u_int hlen)
{
	struct npf_sctp *sh = &npc->npc_l4.sctp;

	/* Ensure it is small enough in case it is within an ICMP error */
	static_assert(sizeof(struct npf_sctp) <= ICMP_ERROR_MIN_L4_SIZE,
		      "npf sctp structure is too big");

	/* Fetch SCTP common header. */
	if (__nbuf_advfetch(&nbuf, &n_ptr, hlen, sizeof(*sh), sh))
		return -NPF_RC_L4_SHORT;

	npc->npc_info |= NPC_L4PORTS;

	return 0;
}

/*
 * npf_fetch_dccp: fetch, check and cache DCCP short header.
 *
 * If we ever wish to look at DCCP data or options this would need to
 * be more complex to cope with the possibility of short vs long header.
 * A Data packet with 0 data can be 12 bytes long,  whereas all other
 * packets are at least 16 bytes long,  and most use the long header.
 *
 * "icmp_err" indicates that the cache is being populated from an IP
 * packet within an ICMP error packet, and so may be truncated.
 */
static inline int npf_fetch_dccp(npf_cache_t *npc, struct rte_mbuf *nbuf,
				 void *n_ptr, u_int hlen, bool icmp_err)
{
	struct npf_dccp *dh = &npc->npc_l4.dccp;

	/* Fetch DCCP short header. */
	if (__nbuf_advfetch(&nbuf, &n_ptr, hlen, sizeof(*dh), dh)) {
		if (icmp_err) {
			if (__nbuf_advfetch(&nbuf, &n_ptr, hlen,
					    ICMP_ERROR_MIN_L4_SIZE, dh))
				return -NPF_RC_L4_SHORT;
			npc->npc_info |= NPC_SHORT_ICMP_ERR;
		} else
			return -NPF_RC_L4_SHORT;
	}

	npc->npc_info |= NPC_L4PORTS;

	return 0;
}

/*
 * npf_decode_icmp4: decode IPv4 ICMP type
 */
static void npf_decode_icmp4(npf_cache_t *npc)
{
	struct icmp *ic = &npc->npc_l4.icmp;
	switch (ic->icmp_type) {
	/*
	 * Some Values are deprecated - see RFC 6918
	 *   Information request/reply
	 *   Address Mask request/reply
	 *   Source Quench (see RFC 6633)
	 * We ignore Timestamp request/reply to save query IDs
	 */
	case ICMP_ECHO:
		npc->npc_info |= NPC_ICMP_ECHO_REQ;
		/* fall through */
	case ICMP_ECHOREPLY:
		npc->npc_info |= NPC_ICMP_ECHO;
		break;
	case ICMP_DEST_UNREACH:
	case ICMP_REDIRECT:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
		npc->npc_info |= NPC_ICMP_ERR;
		break;
	}
}

/*
 * npf_decode_icmp6: decode IPv6 ICMP type
 */
static void npf_decode_icmp6(npf_cache_t *npc)
{
	struct icmp6_hdr *ic6 = &npc->npc_l4.icmp6;

	if (!(ic6->icmp6_type & ICMP6_INFOMSG_MASK)) {
		npc->npc_info |= NPC_ICMP_ERR;
		return;
	}

	switch (ic6->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
		npc->npc_info |= NPC_ICMP_ECHO_REQ;
		/* fall through */
	case ICMP6_ECHO_REPLY:
		npc->npc_info |= NPC_ICMP_ECHO;
		break;
	case ND_ROUTER_SOLICIT:
	case ND_ROUTER_ADVERT:
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
	case ND_REDIRECT:
		if (npc->npc_ip.v6.ip6_hlim == 255)
			npc->npc_info |= NPC_NDP;
		break;
	}

}

/*
 * npf_fetch_icmp: fetch ICMP code, type and possible query ID.
 */
static inline int npf_fetch_icmp(npf_cache_t *npc, struct rte_mbuf *nbuf,
				 void *n_ptr, u_int hlen)
{
	/* Ensure the ICMP protocol and IP protocol are compatible */
	if (npf_iscached(npc, NPC_IP4) ^
			 (npf_cache_ipproto(npc) == IPPROTO_ICMP))
		return -NPF_RC_L3_PROTO;

	/* Fetch basic ICMP header and possibly id/seq */
	if (__nbuf_advfetch(&nbuf, &n_ptr, hlen, ICMP_MINLEN, &npc->npc_l4))
		return -NPF_RC_L4_SHORT;

	if (npf_cache_ipproto(npc) == IPPROTO_ICMP)
		npf_decode_icmp4(npc);
	else
		npf_decode_icmp6(npc);

	/* Cache: layer 4 - ICMP. */
	npc->npc_info |= NPC_ICMP;
	return 0;
}

static int _npf_cache_all_at(npf_cache_t *npc, struct rte_mbuf *nbuf,
			     void *n_ptr, uint16_t eth_proto, bool icmp_err,
			     bool update_grouper)
{
	int rc = npf_fetch_ip(npc, nbuf, n_ptr, eth_proto);

	if (unlikely(rc < 0))
		return rc;

	u_int hlen = npf_cache_hlen(npc);

	if (unlikely(npf_iscached(npc, NPC_IPFRAG)))
		return 0;

	switch (npf_cache_ipproto(npc)) {
	case IPPROTO_TCP:
		rc = npf_fetch_tcp(npc, nbuf, n_ptr, hlen, icmp_err);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		rc = npf_fetch_udp(npc, nbuf, n_ptr, hlen);
		break;
	case IPPROTO_SCTP:
		rc = npf_fetch_sctp(npc, nbuf, n_ptr, hlen);
		break;
	case IPPROTO_DCCP:
		rc = npf_fetch_dccp(npc, nbuf, n_ptr, hlen, icmp_err);
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		rc = npf_fetch_icmp(npc, nbuf, n_ptr, hlen);
		break;
	default:
		break;
	}
	if (unlikely(rc < 0))
		return rc;

	/*
	 * If we have an IPv6 routing header then we only want to match in the
	 * bytecode since we may need to match on route type.
	 */
	if (unlikely(npf_iscached(npc, NPC_IPV6_ROUTING)))
		return 0;

	if (unlikely(!update_grouper)) {
		npc->npc_info &= ~NPC_GROUPER;
		return 0;
	}

	/*
	 * Update grouper protocol, source address, and destination address
	 */
	if (likely(npc->npc_info & NPC_IP4)) {
		npf_update_grouper(npc, &npc->npc_proto_final,
				   NPC_GPR_PROTO_OFF_v4,
				   NPC_GPR_PROTO_LEN_v4);

		npf_update_grouper(npc, npf_cache_v4src(npc),
				   NPC_GPR_SADDR_OFF_v4,
				   NPC_GPR_SADDR_LEN_v4);

		npf_update_grouper(npc, npf_cache_v4dst(npc),
				   NPC_GPR_DADDR_OFF_v4,
				   NPC_GPR_DADDR_LEN_v4);
	} else {
		/*
		 * Must be IPv6 else call to npf_fetch_ip would have failed
		 */
		npf_update_grouper(npc, &npc->npc_proto_final,
				   NPC_GPR_PROTO_OFF_v6,
				   NPC_GPR_PROTO_LEN_v6);

		npf_update_grouper(npc, npf_cache_v6src(npc),
				   NPC_GPR_SADDR_OFF_v6,
				   NPC_GPR_SADDR_LEN_v6);

		npf_update_grouper(npc, npf_cache_v6dst(npc),
				   NPC_GPR_DADDR_OFF_v6,
				   NPC_GPR_DADDR_LEN_v6);
	}

	/*
	 * Update grouper L4 ports
	 */
	if (npf_iscached(npc, NPC_L4PORTS)) {
		struct npf_ports *ports = &npc->npc_l4.ports;
		if (npc->npc_info & NPC_IP4) {

			npf_update_grouper(npc, &ports->s_port,
					   NPC_GPR_SPORT_OFF_v4,
					   NPC_GPR_SPORT_LEN_v4);
			npf_update_grouper(npc, &ports->d_port,
					   NPC_GPR_DPORT_OFF_v4,
					   NPC_GPR_DPORT_LEN_v4);

		} else {

			npf_update_grouper(npc, &ports->s_port,
					   NPC_GPR_SPORT_OFF_v6,
					   NPC_GPR_SPORT_LEN_v6);
			npf_update_grouper(npc, &ports->d_port,
					   NPC_GPR_DPORT_OFF_v6,
					   NPC_GPR_DPORT_LEN_v6);
		}
	}

	/*
	 * Update grouper ICMP type and code
	 */
	if (unlikely(npf_iscached(npc, NPC_ICMP))) {
		if (npf_cache_ipproto(npc) == IPPROTO_ICMP) {
			struct icmp *ic = &npc->npc_l4.icmp;

			npf_update_grouper(npc, &ic->icmp_type,
					   NPC_GPR_ICMPTYPE_OFF_v4,
					   NPC_GPR_ICMPTYPE_LEN_v4);
			npf_update_grouper(npc, &ic->icmp_code,
					   NPC_GPR_ICMPCODE_OFF_v4,
					   NPC_GPR_ICMPCODE_LEN_v4);
		} else {
			struct icmp6_hdr *ic6 = &npc->npc_l4.icmp6;

			npf_update_grouper(npc, &ic6->icmp6_type,
					   NPC_GPR_ICMPTYPE_OFF_v6,
					   NPC_GPR_ICMPTYPE_LEN_v6);
			npf_update_grouper(npc, &ic6->icmp6_code,
					   NPC_GPR_ICMPCODE_OFF_v6,
					   NPC_GPR_ICMPCODE_LEN_v6);
		}
	}

	/* Mark the cache grouper as populated */
	npc->npc_info |= NPC_GROUPER;

	return 0;
}

/*
 * npf_cache_all: general routine to cache all relevant IP (v4 or v6)
 * and TCP, UDP or ICMP headers. Only called once at top level
 * of NPF processing.
 *
 * returns 0 if packet is OK.
 */
int npf_cache_all(npf_cache_t *npc, struct rte_mbuf *nbuf, uint16_t eth_proto)
{
	return _npf_cache_all_at(npc, nbuf, npf_iphdr(nbuf), eth_proto,
				 false, true);
}

bool npf_cache_all_at(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		      uint16_t eth_proto)
{
	return _npf_cache_all_at(npc, nbuf, n_ptr, eth_proto, true, true) == 0;
}

/* Cache packet without updating the cache grouper */
bool npf_cache_all_nogpr(npf_cache_t *npc, struct rte_mbuf *nbuf,
			 uint16_t eth_proto)
{
	return _npf_cache_all_at(npc, nbuf, npf_iphdr(nbuf), eth_proto,
				 false, false) == 0;
}

/*
 * npf_hdrlen() - Length of headers in packet.
 */
uint16_t npf_hdrlen(npf_cache_t *npc)
{
	uint16_t len;

	assert(npf_iscached(npc, NPC_IP46));

	/* Add ipv4/6 header len */
	len = npf_cache_hlen(npc);

	/* Add protocol header */
	uint8_t proto = npf_cache_ipproto(npc);
	switch (proto) {
	case IPPROTO_TCP:
		len += (npc->npc_l4.tcp.doff << 2);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		len += sizeof(struct udphdr);
		break;
	default:
		if (npf_iscached(npc, NPC_ICMP))
			len += sizeof(struct icmp);
		break;
	}

	return len;
}

/*
 * Return the size of the l4 payload, i.e. does not include the TCP,
 * UDP or ICMP header size (or any other protocol supported by the npf
 * cache).
 */
uint16_t npf_payload_len(npf_cache_t *npc)
{
	uint16_t  total = 0;

	if (npf_iscached(npc, NPC_IP6)) {
		total = ntohs(npc->npc_ip.v6.ip6_plen);
		/*
		 * Note: we do not support ipv6 Jumbograms, since our
		 * L4 parsing does not either.
		 */
		if (!total)
			return 0;
		total += sizeof(struct ip6_hdr);
	} else if (npf_iscached(npc, NPC_IP4))
		total = ntohs(npc->npc_ip.v4.ip_len);

	return (total - npf_hdrlen(npc));
}


/* npf_payload_fetch() - Fetch payload data */
uint16_t npf_payload_fetch(npf_cache_t *npc, struct rte_mbuf *nbuf, void *buf,
		uint16_t min, uint16_t max)
{
	uint16_t len = npf_payload_len(npc);

	/* Enforce a min packet size */
	if (!len || len < min)
		return 0;

	void *n_ptr = npf_iphdr(nbuf);
	uint16_t offset = npf_hdrlen(npc);

	/* Enforce a max data return */
	len = max >= len ? len : max;

	if (__nbuf_advfetch(&nbuf, &n_ptr, offset, len, buf))
		return 0;

	return len;
}

/* npf_payload_store() - Rewrite payload */
static uint16_t npf_payload_store(npf_cache_t *npc, struct rte_mbuf *nbuf,
			void *buf, uint16_t  new)
{
	uint16_t offset = npf_hdrlen(npc);
	uint16_t orig = npf_payload_len(npc);
	void *n_ptr = npf_iphdr(nbuf);

	/* Fix up packet size */
	if (orig > new) {
		if (rte_pktmbuf_trim(nbuf, (orig - new)))
			return 0;
	} else if (orig < new) {
		if (!rte_pktmbuf_append(nbuf, (new - orig)))
			return 0;
	}

	if (nbuf_advstore(&nbuf, &n_ptr, offset, new, buf))
		return 0;

	return new;
}

/*
 * Update payload and IP/proto headers.
 *
 * NB: As this stands it is not currently appropriate to use
 *     for UDP-Lite, DCCP, or SCTP.
 *     The first two because they include partial checksum
 *     coverage,  the latter because it used a form of CRC32.
 */
int npf_payload_update(npf_session_t *se, npf_cache_t *npc,
			struct rte_mbuf *nbuf, void *pl,
			const int di, uint16_t nlen)
{
	uint16_t olen = npf_payload_len(npc);
	int16_t diff;
	uint16_t old;
	uint16_t new;

	if (unlikely(npf_payload_store(npc, nbuf, pl, nlen) != nlen))
		return -ENOSPC;

	diff = nlen - olen;
	old = npf_get_ip_size(npc);
	new = old + diff;

	/* Reset IP header if needed */
	if (diff)
		npf_set_ip_size(npc, nbuf, new);

	/*
	 * Update UDP/TCP accordingly
	 */
	switch (npf_cache_ipproto(npc)) {
	case IPPROTO_UDP:
		nlen += sizeof(struct udphdr);
		npf_rw_udp_len(npc, nbuf, nlen);
		npf_udp_cksum(npc, nbuf);
		break;
	case IPPROTO_TCP:
		if (diff)
			npf_nat_set_seq_ack(se, npc, diff, di);
		npf_tcp_cksum(npc, nbuf);
		break;
	}

	return 0;
}

/*
 * Get the size of an IP or IPv6 packet from the cached layer 3
 * header.  IPv6 jumbogram are not supported by ip6_input or the npf
 * parsing, so this function assumes the cached pkt is not jumbogram.
 */
uint16_t npf_get_ip_size(npf_cache_t *npc)
{
	uint16_t total = 0;

	if (npf_iscached(npc, NPC_IP4))
		total = ntohs(npc->npc_ip.v4.ip_len);
	else if (npf_iscached(npc, NPC_IP6)) {
		total = ntohs(npc->npc_ip.v6.ip6_plen) +
			sizeof(struct ip6_hdr);
	}
	return total;
}

/* npf_set_ip_size() - Set size of IP packet */
static int npf_set_ip_size(npf_cache_t *npc, struct rte_mbuf *nbuf, uint16_t sz)
{
	void *p = npf_iphdr(nbuf);

	/*
	 * First the copy in the npc decomposition, then
	 * the actual packet;
	 */

	if (npf_iscached(npc, NPC_IP4)) {
		struct ip *ip = &npc->npc_ip.v4;
		uint16_t old_ip_len = ip->ip_len;
		u_int offby;

		ip->ip_len = htons(sz);

		/* Advance to the IP len and rewrite it. */
		offby = offsetof(struct ip, ip_len);
		if (nbuf_advstore(&nbuf, &p, offby, sizeof(ip->ip_len),
				  &ip->ip_len))
			return -1;

		if (npf_update_v4_cksum(npc, nbuf, old_ip_len, ip->ip_len))
			return -1;

	} else if (npf_iscached(npc, NPC_IP6)) {
		uint16_t offby = offsetof(struct ip6_hdr, ip6_plen);
		struct ip6_hdr *ip6 = &npc->npc_ip.v6;

		ip6->ip6_plen = htons(sz);
		if (nbuf_advstore(&nbuf, &p, offby, sizeof(uint16_t),
							&ip6->ip6_plen))
			return -1;
	}

	return 0;
}

/*
 * Re-write the UDP len in the cache and packet.
 *
 * NB: Do not use this on UDP-Lite,  at it uses the IP payload length to
 *     indicate its size.  What would otherwise be the UDP header payload
 *     length field is used to specify the checksum coverage length.
 */
static int npf_rw_udp_len(npf_cache_t *npc, struct rte_mbuf *nbuf, uint16_t len)
{
	void *ptr = npf_iphdr(nbuf);
	struct udphdr *uh = &npc->npc_l4.udp;

	uint16_t offby  = offsetof(struct udphdr, len) + npf_cache_hlen(npc);

	uh->len = htons(len);
	len = htons(len);
	if (nbuf_advstore(&nbuf, &ptr, offby, sizeof(uint16_t), &len))
		return -1;
	return 0;
}

/*
 * Calculate a UDP cksum and update the UDP header and cache
 */
void npf_udp_cksum(npf_cache_t *npc, struct rte_mbuf *nbuf)
{
	struct udphdr *udp;
	uint16_t cksum;
	void *l3hdr;

	l3hdr = dp_pktmbuf_mtol3(nbuf, void *);
	udp = (struct udphdr *)(rte_pktmbuf_mtod(nbuf, char *) +
				nbuf->l2_len + npf_cache_hlen(npc));
	udp->check = 0;

	if (npf_iscached(npc, NPC_IP4))
		cksum = dp_in4_cksum_mbuf(nbuf, l3hdr, udp);
	else if (npf_iscached(npc, NPC_IP6))
		cksum = dp_in6_cksum_mbuf(nbuf, l3hdr, udp);
	else
		return;

	/* Do not encode the 'no checksum' value */
	cksum = (cksum == 0) ? 0xffff : cksum;

	/* Write checksum to packet and cache */
	npf_rw_proto_cksum(npc, nbuf, cksum);
}

/*
 * Calculate a TCP cksum and update the TCP header and cache
 */
void npf_tcp_cksum(npf_cache_t *npc, struct rte_mbuf *nbuf)
{
	struct tcphdr *tcp;
	uint16_t cksum;
	void *l3hdr;

	l3hdr = dp_pktmbuf_mtol3(nbuf, void *);
	tcp = (struct tcphdr *)(rte_pktmbuf_mtod(nbuf, char *) +
				nbuf->l2_len + npf_cache_hlen(npc));
	tcp->check = 0;

	if (npf_iscached(npc, NPC_IP4))
		cksum = dp_in4_cksum_mbuf(nbuf, l3hdr, tcp);
	else if (npf_iscached(npc, NPC_IP6))
		cksum = dp_in6_cksum_mbuf(nbuf, l3hdr, tcp);
	else
		return;

	/* Write checksum to packet and cache */
	npf_rw_proto_cksum(npc, nbuf, cksum);
}

/*
 * Calculate a TCP, UDP, ICMP v4 cksum.
 *
 * Used by NAT64,  and can not currently cope with UDP-Lite nor DCCP.
 * Happily we do not need to recalculate the SCTP CRC32, as it does
 * not include a pseudo-header.
 */
void
npf_ipv4_cksum(struct rte_mbuf *nbuf, int proto, char *l4hdr)
{
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmp *icmp;
	struct iphdr *l3hdr;

	l3hdr = dp_pktmbuf_mtol3(nbuf, struct iphdr *);

	switch (proto) {
	case IPPROTO_TCP:
		tcp = (struct tcphdr *)l4hdr;
		tcp->check = 0;
		tcp->check = dp_in4_cksum_mbuf(nbuf, l3hdr, tcp);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr *)l4hdr;
		udp->check = 0;
		udp->check = dp_in4_cksum_mbuf(nbuf, l3hdr, udp);
		/* Do not encode the 'no checksum' value */
		udp->check = (udp->check == 0) ? 0xffff : udp->check;
		break;
	case IPPROTO_ICMP:
		icmp = (struct icmp *)l4hdr;
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = dp_in4_cksum_mbuf(nbuf, NULL, icmp);
		break;
	case IPPROTO_SCTP: /* CRC without pseudo-header */
	default:
		break;
	}
}

/*
 * Calculate a TCP, UDP, ICMP v6 cksum.
 *
 * Used by NAT64,  and can not currently cope with UDP-Lite nor DCCP.
 * Happily we do not need to recalculate the SCTP CRC32, as it does
 * not include a pseudo-header.
 */
void npf_ipv6_cksum(struct rte_mbuf *nbuf, int proto, char *l4hdr)
{
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *l3hdr;

	l3hdr = dp_pktmbuf_mtol3(nbuf, struct ip6_hdr *);

	switch (proto) {
	case IPPROTO_TCP:
		tcp = (struct tcphdr *)l4hdr;
		tcp->check = 0;
		tcp->check = dp_in6_cksum_mbuf(nbuf, l3hdr, tcp);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr *)l4hdr;
		udp->check = 0;
		udp->check = dp_in6_cksum_mbuf(nbuf, l3hdr, udp);
		/* Do not encode the 'no checksum' value */
		udp->check = (udp->check == 0) ? 0xffff : udp->check;
		break;
	case IPPROTO_ICMPV6:
		icmp6 = (struct icmp6_hdr *)l4hdr;
		icmp6->icmp6_cksum = 0;
		icmp6->icmp6_cksum = dp_in6_cksum_mbuf(nbuf, l3hdr, icmp6);
		break;
	case IPPROTO_SCTP: /* CRC without pseudo-header */
	default:
		break;
	}
}

/* Re-write the TCP/UDP cksum in the cache and packet */
static int npf_rw_proto_cksum(npf_cache_t *npc,
			      struct rte_mbuf *nbuf, uint16_t sum)
{
	void *ptr = npf_iphdr(nbuf);
	int16_t offby = 0;

	if (npf_cache_ipproto(npc) == IPPROTO_TCP) {
		npc->npc_l4.tcp.check = sum;
		offby = offsetof(struct tcphdr, check);
	} else {
		npc->npc_l4.udp.check = sum;
		offby = offsetof(struct udphdr, check);
	}

	offby += npf_cache_hlen(npc);

	if (nbuf_advstore(&nbuf, &ptr, offby, sizeof(uint16_t), &sum))
		return -1;
	return 0;
}

/* Update the TCP cksum based on a new 32bit datum. */
int npf_update_tcp_cksum(npf_cache_t *npc, struct rte_mbuf *nbuf,
			 uint32_t old_val, uint32_t new_val)
{
	struct tcphdr *th = &npc->npc_l4.tcp;
	uint16_t sum = th->check;

	sum = ip_fixup32_cksum(sum, htonl(old_val), htonl(new_val));

	return npf_rw_proto_cksum(npc, nbuf, sum);
}

/*
 * npf_rwrip: rewrite required IP address, update the cache.
 */
int npf_rwrip(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
	      const int di, const npf_addr_t *addr)
{
	npf_addr_t *oaddr;
	u_int offby;

	if (di == PFIL_OUT) {
		/* Rewrite source address, if outgoing. */
		offby = offsetof(struct ip, ip_src);
		oaddr = npf_cache_v4src(npc);
	} else {
		/* Rewrite destination, if incoming. */
		offby = offsetof(struct ip, ip_dst);
		oaddr = npf_cache_v4dst(npc);
	}

	/* Advance to the address and rewrite it. */
	if (nbuf_advstore(&nbuf, &n_ptr, offby, npc->npc_alen, addr))
		return -NPF_RC_L3_SHORT;

	/* Cache: IP address. */
	memcpy(oaddr, addr, npc->npc_alen);

	/* Update grouper, N.B: we only translate IPv4 */
	if (di == PFIL_OUT)
		npf_update_grouper(npc, npf_cache_v4src(npc),
				   NPC_GPR_SADDR_OFF_v4, NPC_GPR_SADDR_LEN_v4);
	else
		npf_update_grouper(npc, npf_cache_v4dst(npc),
				   NPC_GPR_DADDR_OFF_v4, NPC_GPR_DADDR_LEN_v4);

	return 0;
}

/*
 * npf_rwrip6: rewrite required IP address, update the cache.
 */
bool npf_rwrip6(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		const int di, const npf_addr_t *addr)
{
	npf_addr_t *oaddr;
	u_int offby;

	if (di == PFIL_OUT) {
		/* Rewrite source address, if outgoing. */
		offby = offsetof(struct ip6_hdr, ip6_src);
		oaddr = npf_cache_v6src(npc);
	} else {
		/* Rewrite destination, if incoming. */
		offby = offsetof(struct ip6_hdr, ip6_dst);
		oaddr = npf_cache_v6dst(npc);
	}

	/* Advance to the address and rewrite it. */
	if (nbuf_advstore(&nbuf, &n_ptr, offby, npc->npc_alen, addr))
		return false;

	/* Cache: IPv6 address. */
	memcpy(oaddr, addr, npc->npc_alen);

	/* Update grouper */
	if (di == PFIL_OUT)
		npf_update_grouper(npc, npf_cache_v6src(npc),
				   NPC_GPR_SADDR_OFF_v6, NPC_GPR_SADDR_LEN_v6);
	else
		npf_update_grouper(npc, npf_cache_v6dst(npc),
				   NPC_GPR_DADDR_OFF_v6, NPC_GPR_DADDR_LEN_v6);

	return true;
}

/*
 * npf_rwrport: rewrite required TCP/UDP port, update the cache.
 */
int npf_rwrport(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		const int di, in_port_t port)
{
	u_int offby = npf_cache_hlen(npc);
	in_port_t *oport = NULL;

	/* Offset to the port and pointer in the cache. */
	if (npf_iscached(npc, NPC_L4PORTS)) {
		struct npf_ports *ports = &npc->npc_l4.ports;

		if (di == PFIL_OUT) {
			oport = &ports->s_port;
		} else {
			offby += offsetof(struct npf_ports, d_port);
			oport = &ports->d_port;
		}
	}

	/* Advance and rewrite the port. */
	if (nbuf_advstore(&nbuf, &n_ptr, offby, sizeof(in_port_t), &port))
		return -NPF_RC_L4_SHORT;

	/* Cache: TCP/UDP port. */
	if (oport)
		*oport = port;

	/* Update grouper port */
	if (di == PFIL_OUT)
		npf_update_grouper(npc, &port,
				   NPC_GPR_SPORT_OFF_v4, NPC_GPR_SPORT_LEN_v4);
	else
		npf_update_grouper(npc, &port,
				   NPC_GPR_DPORT_OFF_v4, NPC_GPR_DPORT_LEN_v4);

	return 0;
}

/*
 * Rewrite required ICMP query ID, update the cache.
 */
int npf_rwricmpid(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		  uint16_t new_id)
{
	struct icmp *ic = &npc->npc_l4.icmp;
	uint16_t *old_id = &ic->icmp_id;

	u_int offby = npf_cache_hlen(npc)
		    + offsetof(struct icmp, icmp_id);

	/* Advance and rewrite the ICMP id. */
	if (nbuf_advstore(&nbuf, &n_ptr, offby, sizeof(new_id), &new_id))
		return -NPF_RC_L4_SHORT;

	/* Cache: ICMP id */
	*old_id = new_id;

	return 0;
}

/*
 * Rewrite IPv4 and/or transports checksums based upon provided checksum deltas,
 * also update the fields in the packet cache.
 */
int
npf_v4_rwrcksums(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		 uint16_t l3_chk_delta, uint16_t l4_chk_delta)
{
	uint16_t *cksum;
	u_int offby;

	/*
	 * Checksum update for IPv4 header
	 */
	struct ip *ip = &npc->npc_ip.v4;
	uint16_t ipsum;

	ipsum = ip_fixup16_cksum(ip->ip_sum, 0xffff, l3_chk_delta);

	/* Advance to the IPv4 checksum and rewrite it. */
	offby = offsetof(struct ip, ip_sum);
	if (nbuf_advstore(&nbuf, &n_ptr, offby, sizeof(ipsum), &ipsum))
		return -NPF_RC_L3_SHORT;

	ip->ip_sum = ipsum;
	offby = npf_cache_hlen(npc) - offby;

	/* What, if any transport checksum update is needed */
	switch (npf_cache_ipproto(npc)) {
	case IPPROTO_TCP: {
		struct tcphdr *th = &npc->npc_l4.tcp;

		cksum = &th->check;
		offby += offsetof(struct tcphdr, check);
		break;
	}
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE: {
		struct udphdr *uh = &npc->npc_l4.udp;

		cksum = &uh->check;
		if (*cksum == 0) {
			/* No need to update. */
			return 0;
		}
		offby += offsetof(struct udphdr, check);
		break;
	}
	case IPPROTO_DCCP: {
		struct npf_dccp *dh = &npc->npc_l4.dccp;

		cksum = &dh->dc_checksum;
		offby += offsetof(struct npf_dccp, dc_checksum);
		break;
	}
	case IPPROTO_SCTP: {
		return 0;
	}
	case IPPROTO_ICMP: {
		/* This should never occur (due to having no session) */
		if (unlikely(!npf_iscached(npc, NPC_ICMP_ECHO)))
			return 0;
		struct icmp *ic = &npc->npc_l4.icmp;
		cksum = &ic->icmp_cksum;
		offby += offsetof(struct icmp, icmp_cksum);
		/* L3 pseudo header is not included in ICMP checksum */
		l3_chk_delta = 0;
		break;
	}
	default:
		/* In case we ever add another L4 port based protocol */
		if (npf_iscached(npc, NPC_L4PORTS))
			return -NPF_RC_INTL;
		return 0;
	}

	/* Update the checksum in the cache */
	*cksum = ip_fixup16_cksum(*cksum, ~l3_chk_delta, l4_chk_delta);

	/* Update the checksum in the mbuf */
	if (nbuf_advstore(&nbuf, &n_ptr, offby, sizeof(uint16_t), cksum))
		return -NPF_RC_L4_SHORT;
	return 0;
}

/* Convert a string port to a port */
in_port_t npf_port_from_str(const char *p)
{
	char *tmp;
	unsigned long n = 0;

	if (p) {
		n = strtoul(p, &tmp, 10);
		if (*tmp != '\0' || n > USHRT_MAX)
			return 0;
	}
	return (in_port_t) n;
}

RTE_DEFINE_PER_LCORE(npf_cache_t, npf_cache);

npf_cache_t *npf_cache(void)
{
	return &RTE_PER_LCORE(npf_cache);
}

/*
 * The gleaned mtu is set if we have a reassembled packet that might
 * need re-fragmenting
 */
uint16_t npf_cache_mtu(void)
{
	npf_cache_t *npc = &RTE_PER_LCORE(npf_cache);

	return npc->gleaned_mtu;
}

/* Cached IPv6 fragmentation header ID */
uint32_t npf_cache_frag_ident(void)
{
	npf_cache_t *npc = &RTE_PER_LCORE(npf_cache);

	return npc->fh_id;
}

/*
 * Is the packet an IPv6 fragment that is eligible for reassembly?
 */
bool
npf_ipv6_is_fragment(struct rte_mbuf *m, uint16_t *npf_flag)
{
	/*
	 * We need to scan the IPv6 headers to get the info we need to
	 * reassemble the pkt. The scan will stop if it hits a
	 * fragmentation header. If there is no frag hdr then the
	 * packet will be fully cached, and the packet will not be
	 * cached again.
	 */
	int rc;
	npf_cache_t *n = npf_get_cache(npf_flag, m,
				       htons(RTE_ETHER_TYPE_IPV6), &rc);

	if (n && npf_iscached(n, NPC_IPFRAG) &&
	    !npf_ip6_has_non_frag_ext_hdrs(n))
		return true;

	return false;
}

/*
 * Protocol index to name
 */
static const char *npf_protocol_name[NPF_PROTO_IDX_COUNT + 1] = {
	[NPF_PROTO_IDX_TCP] = "tcp",
	[NPF_PROTO_IDX_UDP] = "udp",
	[NPF_PROTO_IDX_ICMP] = "icmp",
	[NPF_PROTO_IDX_OTHER] = "other",
	[NPF_PROTO_IDX_NONE] = "none",
};

const char *
npf_get_protocol_name_from_idx(enum npf_proto_idx proto_idx)
{
	if (proto_idx <= NPF_PROTO_IDX_COUNT)
		return npf_protocol_name[proto_idx];

	return "none";
}

enum npf_proto_idx npf_proto_idx_from_str(const char *proto)
{
	uint8_t idx;

	for (idx = NPF_PROTO_IDX_FIRST; idx <= NPF_PROTO_IDX_LAST; idx++) {
		if (strcmp(proto, npf_get_protocol_name_from_idx(idx)) == 0)
			return idx;
	}
	return NPF_PROTO_IDX_NONE;
}

int npf_prepare_for_l4_header_change(struct rte_mbuf **m, npf_cache_t *npc)
{
	uint header_len = dp_pktmbuf_l2_len(*m) + npf_cache_hlen(npc);

	/* Include minimum L4 header for handled L4 protocols. */
	switch (npf_cache_ipproto(npc)) {
	case IPPROTO_TCP:
		header_len += sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		header_len += sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
		header_len += sizeof(struct icmp);
		break;
	case IPPROTO_ICMPV6:
		header_len += sizeof(struct icmp6_hdr);
		break;
	case IPPROTO_SCTP:
		header_len += sizeof(struct npf_sctp);
		break;
	case IPPROTO_DCCP:
		header_len += sizeof(struct npf_dccp);
		break;
	default:
		break;
	}

	return pktmbuf_prepare_for_header_change(m, header_len);
}

#ifdef _NPF_TESTING
void
npf_addr_dump(const npf_addr_t *addr)
{
	printf("IP[%x:%x:%x:%x]\n",
	    addr->s6_addr32[0], addr->s6_addr32[1],
	    addr->s6_addr32[2], addr->s6_addr32[3]);
}
#endif
