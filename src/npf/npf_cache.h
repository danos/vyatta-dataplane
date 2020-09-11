/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*
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

#ifndef NPF_CACHE_H
#define NPF_CACHE_H

/*
 * This contains structures relating to the NPF cache, and
 * functions to access it and process protocol headers.
 */

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <rte_branch_prediction.h>
#include <rte_per_lcore.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "compiler.h"
#include "in_cksum.h"
#include "npf/npf.h"
#include "npf/npf_mbuf.h"
#include "pktmbuf_internal.h"

typedef uint32_t tcp_seq;

struct rte_mbuf;

#define npf_iphdr(m) (dp_pktmbuf_mtol3(m, struct iphdr *))

enum npf_proto_idx {
	NPF_PROTO_IDX_TCP,
	NPF_PROTO_IDX_UDP,
	NPF_PROTO_IDX_ICMP,
	NPF_PROTO_IDX_OTHER,
};

#define NPF_PROTO_IDX_FIRST	NPF_PROTO_IDX_TCP
#define NPF_PROTO_IDX_LAST	NPF_PROTO_IDX_OTHER
#define NPF_PROTO_IDX_COUNT	(NPF_PROTO_IDX_LAST + 1)
#define NPF_PROTO_IDX_NONE	NPF_PROTO_IDX_COUNT

/* Get the npf_proto_idx enum from the protocol number */
static inline uint8_t npf_proto_idx_from_proto(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return NPF_PROTO_IDX_TCP;
	case IPPROTO_UDP:
		return NPF_PROTO_IDX_UDP;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return NPF_PROTO_IDX_ICMP;
	}
	return NPF_PROTO_IDX_OTHER;
}

const char *npf_get_protocol_name_from_idx(uint8_t proto_idx);
uint8_t npf_proto_idx_from_str(const char *proto);

/* The SCTP common header - which is all we read */
struct npf_sctp {
	uint16_t sc_src;	/* source port */
	uint16_t sc_dst;	/* destination port */
	uint32_t sc_verif_tag;	/* verification tag */
};

/* The DCCP short header - as we never look beyond the type */
struct npf_dccp {
	uint16_t dc_src;	/* source port */
	uint16_t dc_dst;	/* destination port */
	uint8_t  dc_doff;	/* data offset */
	uint8_t  dc_cc_cov;	/* CCVal and checksum coverage */
	uint16_t dc_checksum;
	uint8_t  dc_res_type_x;	/* Reserved, Type, X-bit */
	uint8_t  dc_seqs_hi;	/* High order 8 bits */
	uint16_t dc_seqs_lo;	/* Low order 16 bits */
};

/*
 * All of the transports (TCP/UDP/UDP-Lite/DCCP/SCTP) share the same
 * offsets for their ports.
 */
struct npf_ports {
	uint16_t s_port;	/* source port */
	uint16_t d_port;	/* destination port */
};

/*
 * IPv4 cache offsets and lengths
 *
 * The L4 area is either: Source and dest ports, ICMP type and code, or is
 * unused, in which case we set it to "match all" (Note, since this at the end
 * of the grouper array, an optimization might be to reduce the grouper length
 * instead).
 */
#define NPC_GPR_PROTO_OFF_v4	0
#define NPC_GPR_PROTO_LEN_v4	1

#define NPC_GPR_SADDR_OFF_v4	1
#define NPC_GPR_SADDR_LEN_v4	4

#define NPC_GPR_DADDR_OFF_v4	5
#define NPC_GPR_DADDR_LEN_v4	4

#define NPC_GPR_SPORT_OFF_v4	9	/* L4 option #1 */
#define NPC_GPR_SPORT_LEN_v4	2

#define NPC_GPR_DPORT_OFF_v4	11
#define NPC_GPR_DPORT_LEN_v4	2

#define NPC_GPR_ICMPTYPE_OFF_v4	9	/* L4 option #2 */
#define NPC_GPR_ICMPTYPE_LEN_v4	1

#define NPC_GPR_ICMPCODE_OFF_v4	10
#define NPC_GPR_ICMPCODE_LEN_v4	1

#define NPC_GPR_ICMP_UNUSED_OFF_v4	11
#define NPC_GPR_ICMP_UNUSED_LEN_v4	2

#define NPC_GPR_SIZE_v4		13

/*
 * IPv6 cache offsets and lengths
 */
#define NPC_GPR_PROTO_OFF_v6	0
#define NPC_GPR_PROTO_LEN_v6	1

#define NPC_GPR_SADDR_OFF_v6	1
#define NPC_GPR_SADDR_LEN_v6	16

#define NPC_GPR_DADDR_OFF_v6	17
#define NPC_GPR_DADDR_LEN_v6	16

#define NPC_GPR_SPORT_OFF_v6	33	/* L4 option #1 */
#define NPC_GPR_SPORT_LEN_v6	2

#define NPC_GPR_DPORT_OFF_v6	35
#define NPC_GPR_DPORT_LEN_v6	2

#define NPC_GPR_ICMPTYPE_OFF_v6	33	/* L4 option #2 */
#define NPC_GPR_ICMPTYPE_LEN_v6	1

#define NPC_GPR_ICMPCODE_OFF_v6	34
#define NPC_GPR_ICMPCODE_LEN_v6	1

#define NPC_GPR_ICMP_UNUSED_OFF_v6	35
#define NPC_GPR_ICMP_UNUSED_LEN_v6	2

#define NPC_GPR_SIZE_v6		37

/* This struct remains incomplete */
typedef struct npf_srcdst npf_srcdst_t;

/*
 * The 'npc'.
 *
 * This is a decomposition of a packet
 */
typedef struct npf_cache {
	void		*npc_tuple;	/* Pointer to alg */
	npf_srcdst_t	*npc_srcdst;	/* Pointer to addresses */

	uint32_t	npc_info;	/* Information flags */
	uint16_t	npc_hlen;
	uint8_t		npc_alen;	/* Size (v4/6) of addrs */
	uint8_t		npc_next_proto;
	uint8_t		npc_proto_idx;
	uint8_t		npc_ipv6_routing_type;
	uint8_t		npc_alg_flags;	/* Per-packet alg flags */

	/* IPv4, IPv6. */
	union {
		struct ip	v4;
		struct ip6_hdr	v6;
	} npc_ip;

	/* TCP, UDP, ICMP. */
	union {
		struct tcphdr		tcp;
		struct udphdr		udp;
		struct icmp		icmp;
		struct icmp6_hdr	icmp6;
		struct npf_sctp		sctp;
		struct npf_dccp		dccp;
		struct npf_ports	ports;
	} npc_l4;

	char	npc_grouper[NPC_GPR_SIZE_v6];

	/*
	 * Fragment reassembly and re-fragmentation
	 *
	 * Offset (from start of l3 hdr) and length of last
	 * unfragmentable ext header before the fragmentation header.
	 * For the usual case of no non-frag hdrs, last_unfrg_hlen
	 * will be 40, last_unfrg_hofs 0, and frag_hofs 40.
	 *
	 * gleaned_mtu is the senders MTU gleaned from the largest
	 * fragment. It is used during re-fragmentation.  It is only
	 * valid if PKT_MDATA_DEFRAG bit is set in the metadata.
	 */
	uint16_t  last_unfrg_hlen;
	uint16_t  last_unfrg_hofs;
	uint16_t  gleaned_mtu;

	/* Fragmentation header values (in host order) */
	uint16_t  fh_offset;
	bool      fh_more;
	uint32_t  fh_id;
} npf_cache_t;

/*
 * npf_cache_t information (npc_info) flags
 */
#define	NPC_IP4			0x00001 /* Indicates fetched IPv4 header. */
#define	NPC_IP6			0x00002 /* Indicates IPv6 header. */
#define	NPC_IPFRAG		0x00004 /* IPv4/IPv6 fragment. */
#define	NPC_L4PORTS		0x00008 /* Layer 4 has standard ports */

#define	NPC_NDP			0x00010 /* IPv6 NDP packet */
#define	NPC_ICMP		0x00020 /* ICMP header. */
#define	NPC_ICMP_ECHO		0x00040 /* ICMP echo req/reply with query ID. */
#define	NPC_ICMP_ECHO_REQ	0x00080 /* ICMP echo req. */
#define	NPC_ICMP_ERR		0x00100 /* ICMP error with embedded packet */
#define NPC_SHORT_ICMP_ERR      0x00200 /* embedded packet with short L4 hdr */
#define	NPC_ICMP_ERR_NAT	0x00400 /* ICMP error w' embedded NAT pkt */
#define NPC_IPV6_ROUTING	0x00800 /* has IPv6 Routing Header */

#define NPC_GROUPER             0x01000 /* grouper optimization */
#define NPC_NATTED              0x02000 /* Packet natted? */
#define NPC_ALG_TLUP            0x04000 /* Set if we did a tuple lookup */
#define NPC_DROP                0x08000 /* Packet has to be dropped */

#define	NPC_IP46	(NPC_IP4|NPC_IP6)

#include "npf/npf_session.h"

int npf_tcpsaw(const npf_cache_t *npc, tcp_seq *seq, tcp_seq *ack,
	       uint32_t *win);
bool npf_fetch_tcpopts(const npf_cache_t *npc, struct rte_mbuf *nbuf,
		       uint16_t *mss, uint8_t *wscale);
void *npf_get_tcp_options(npf_cache_t *npc, struct rte_mbuf *nbuf, void *buf);
void npf_store_tcp_options(npf_cache_t *npc, struct rte_mbuf *nbuf, void *buf);
void npf_recache_ip_ttl(npf_cache_t *npc, struct rte_mbuf *nbuf);


/**
 * General routine to cache all relevant IP (v4 or v6) and TCP, UDP or ICMP
 * headers. Only called once at top level of NPF processing.
 *
 * @param npc
 * The npf packet cache.
 *
 * @param nbuf
 * The packet.
 *
 * @param eth_proto
 * The ethernet header type field in network byte order.
 */
int npf_cache_all(npf_cache_t *npc, struct rte_mbuf *nbuf, uint16_t eth_proto);

/**
 * Cache all relevant IP (v4 or v6) and TCP, UDP or ICMP headers from a given
 * point in a packet.  Used to cache packets embedded within ICMP error
 * messages, in which case the l4 header may be truncated.
 *
 * @param npc
 * The npf packet cache.
 *
 * @param n_ptr
 * Pointer to the l3 header in the packet.
 *
 * @param nbuf
 * The packet.
 *
 * @param eth_proto
 * The ethernet header type field in network byte order.
 */
bool npf_cache_all_at(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		      uint16_t eth_proto);

/**
 * Cache all relevant IP (v4 or v6) and TCP, UDP or ICMP headers in a packet
 * without updating the cashe grouper data.  Not to be used for packets
 * embedded within ICMP error messages.
 *
 * @param npc
 * The npf packet cache.
 *
 * @param nbuf
 * The packet.
 *
 * @param eth_proto
 * The ethernet header type field in network byte order.
 */
bool npf_cache_all_nogpr(npf_cache_t *npc, struct rte_mbuf *nbuf,
			   uint16_t eth_proto);

uint16_t npf_hdrlen(npf_cache_t *npc);
uint16_t npf_payload_len(npf_cache_t *npc);
uint16_t npf_payload_fetch(npf_cache_t *npc, struct rte_mbuf *nbuf,
			   void *buf, uint16_t min, uint16_t max);
int npf_payload_update(npf_session_t *se, npf_cache_t *npc,
		       struct rte_mbuf *nbuf, void *pl,
		       const int di, uint16_t nlen);
uint16_t npf_get_ip_size(npf_cache_t *npc);
void npf_udp_cksum(npf_cache_t *npc, struct rte_mbuf *nbuf);
void npf_tcp_cksum(npf_cache_t *npc, struct rte_mbuf *nbuf);
void npf_ipv4_cksum(struct rte_mbuf *nbuf, int proto, char *l4hdr);
void npf_ipv6_cksum(struct rte_mbuf *nbuf, int proto, char *l4hdr);
int npf_update_tcp_cksum(npf_cache_t *npc, struct rte_mbuf *nbuf,
			 uint32_t old_val, uint32_t new_val);
int npf_rwrip(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
	      const int di, const npf_addr_t *addr);
bool npf_rwrip6(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		const int di, const npf_addr_t *addr);
int npf_rwrport(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		const int di, in_port_t port);
int npf_rwricmpid(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		  uint16_t new_id);
int npf_v4_rwrcksums(npf_cache_t *npc, struct rte_mbuf *nbuf, void *n_ptr,
		     uint16_t l3_chk_delta, uint16_t l4_chk_delta);
in_port_t npf_port_from_str(const char *p);
npf_cache_t *npf_cache(void);
uint16_t npf_cache_mtu(void);
uint32_t npf_cache_frag_ident(void);
bool npf_ipv6_is_fragment(struct rte_mbuf *m, uint16_t *npf_flag);
int npf_prepare_for_l4_header_change(struct rte_mbuf **m, npf_cache_t *npc);

#ifdef _NPF_TESTING
void npf_addr_dump(const npf_addr_t *addr);
#endif

/* Init a npf_cache_t */
static inline void npf_cache_init(npf_cache_t *npc)
{
	npc->npc_info = 0;
	npc->npc_tuple = NULL;
}

/* Reset a npf_cache_t */
static inline void npf_cache_reset(npf_cache_t *npc)
{
	npc->npc_info &= ~(NPC_NATTED | NPC_ALG_TLUP);
	npc->npc_tuple = NULL;
}

RTE_DECLARE_PER_LCORE(npf_cache_t, npf_cache);

static inline npf_cache_t *
npf_get_cache(uint16_t *npf_flag, struct rte_mbuf *m, uint16_t eth_type,
	      int *error)
{
	npf_cache_t *n = &RTE_PER_LCORE(npf_cache);

	/* Cache cheater, only compute once when processing mbuf */
	if (*npf_flag & NPF_FLAG_CACHE_EMPTY) {
		/* reset npf cache for this rx thread */
		npf_cache_init(n);

		/* Cache everything. Drop if junk. */
		int rc = npf_cache_all(n, m, eth_type);
		if (unlikely(rc < 0)) {
			*error = rc;
			return NULL;
		}

		*npf_flag ^= NPF_FLAG_CACHE_EMPTY;
	} else {
		npf_cache_reset(n);
		npf_recache_ip_ttl(n, m);
	}

	return n;
}

static inline bool
npf_ip6_has_non_frag_ext_hdrs(npf_cache_t *npc)
{
	/*
	 * If there are no non-fragmentable extension headers then the
	 * last_unfrg_hofs will refer to the IPv6 header, and will be
	 * 0.
	 */
	return npc->last_unfrg_hofs > 0;
}

static inline bool
npf_iscached(const npf_cache_t *npc, const int inf)
{
	return ((npc->npc_info & inf) != 0);
}

static inline uint8_t
npf_cache_ipproto(const npf_cache_t *npc)
{
	return npc->npc_next_proto;
}

static inline uint8_t
npf_cache_proto_idx(const npf_cache_t *npc)
{
	return npc->npc_proto_idx;
}

static inline u_int
npf_cache_hlen(const npf_cache_t *npc)
{
	return npc->npc_hlen;
}

/* Set npc alg */
static inline void npf_cache_set_tuple(npf_cache_t *npc, void *tuple)
{
	npc->npc_tuple = tuple;
}

/* Get npc alg */
static inline void *npf_cache_get_tuple(npf_cache_t *npc)
{
	return npc->npc_tuple;
}

/*
 * The npc_srcdst pointer points to the two addresses in the packet.
 * For IPv4 and IPv6 are adjacenct, with the dst following the src,
 * so we point at the src, and adjust for the dst based upon AF.
 */

/* Generic accessors for when we do not have the AF context */
static ALWAYS_INLINE
npf_addr_t *npf_cache_srcip(const npf_cache_t *npc)
{
	return (npf_addr_t *)npc->npc_srcdst;
}

static ALWAYS_INLINE
npf_addr_t *npf_cache_dstip(const npf_cache_t *npc)
{
	uint8_t *raw = (uint8_t *)npc->npc_srcdst;

	return (npf_addr_t *)(raw + npc->npc_alen);
}

/* IPv4 accessors */
static ALWAYS_INLINE
npf_addr_t *npf_cache_v4src(const npf_cache_t *npc)
{
	return (npf_addr_t *)npc->npc_srcdst;
}

static ALWAYS_INLINE
npf_addr_t *npf_cache_v4dst(const npf_cache_t *npc)
{
	uint8_t *raw = (uint8_t *)npc->npc_srcdst;

	return (npf_addr_t *)(raw + sizeof(struct in_addr));
}

/* IPv4 accessors */
static ALWAYS_INLINE
npf_addr_t *npf_cache_v6src(const npf_cache_t *npc)
{
	return (npf_addr_t *)npc->npc_srcdst;
}

static ALWAYS_INLINE
npf_addr_t *npf_cache_v6dst(const npf_cache_t *npc)
{
	uint8_t *raw = (uint8_t *)npc->npc_srcdst;

	return (npf_addr_t *)(raw + sizeof(struct in6_addr));
}

/* Return inet family from alen. */
static inline int npf_alen_inet_family(uint8_t alen)
{
	switch (alen) {
	case 4:
		return AF_INET;
	case 16:
		return AF_INET6;
	}
	return 0;
}

/* Extract ids from a NPF cache */
static ALWAYS_INLINE void
npf_cache_extract_ids(npf_cache_t *npc, uint16_t *src_id, uint16_t *dst_id)
{
	if (likely(npf_iscached(npc, NPC_L4PORTS))) {
		struct npf_ports *ports = &npc->npc_l4.ports;
		*src_id = ports->s_port;
		*dst_id = ports->d_port;
	} else if (npf_iscached(npc, NPC_ICMP_ECHO)) {
		const struct icmp *ic = &npc->npc_l4.icmp;
		*src_id = *dst_id = ic->icmp_id;
	} else
		*src_id = *dst_id = 0;
}


/* Differential rewrite of the IP checksum in the NPF cache and packet */
static ALWAYS_INLINE
int npf_update_v4_cksum(npf_cache_t *npc, struct rte_mbuf *nbuf,
			uint16_t old_val, uint16_t new_val)
{
	void *n_ptr = npf_iphdr(nbuf);
	struct ip *ip = &npc->npc_ip.v4;
	u_int offby = offsetof(struct ip, ip_sum);

	ip->ip_sum = ip_fixup16_cksum(ip->ip_sum, old_val, new_val);

	/* Advance to the IPv4 checksum and rewrite it. */
	return nbuf_advstore(&nbuf, &n_ptr, offby, sizeof(ip->ip_sum),
			     &ip->ip_sum);
}
#endif /* NPF_CACHE_H */
