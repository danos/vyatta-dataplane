/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_MBUF_H_
#define _CGN_MBUF_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "pktmbuf_internal.h"
#include "npf/cgnat/cgn_dir.h"
#include "npf/cgnat/cgn_hash_key.h"
#include "npf/nat/nat_proto.h"

/*
 * cgn_packet - decomposition of a packet
 *
 * cpk_keepalive is used to denote if a packet is eligible for clearing the
 * session idle flag for existing sessions, or creating new nested sessions.
 *
 * Initially it is set true for all internal to external traffic.
 * Subsequently it may be set false if a packet is deemed unsuitable for
 * keeping a session alive, e.g. TCP resets.
 *
 * Any new fields added to this scructure MUST be explicitly set or
 * initialised by cgn_cache_all.
 */
struct cgn_packet {
	struct cgn_3tuple_key	cpk_key; /* hash lookup key */

	uint32_t	cpk_ifindex;
	uint32_t	cpk_info;

	vrfid_t		cpk_vrfid;	/* VRF id */
	uint8_t		cpk_keepalive:1; /* Can we clear idle flag? */
	uint8_t		cpk_pkt_instd:1;
	uint8_t		cpk_pkt_cgnat:1; /* CGNAT pkt? */
	uint8_t		cpk_pkt_hpinned:1; /* Hairpinned pkt? */
	uint8_t		cpk_tcp_flags;
	enum nat_proto	cpk_proto;	/* tcp, udp, other enum */
	uint8_t		cpk_l4ports;	/* true if there are l4ports*/

	uint16_t	cpk_cksum;	/* l4 checksum */
	uint16_t	cpk_sid;	/* source port or id */
	uint16_t	cpk_did;	/* dest port or id */
	uint8_t		cpk_pad1[2];

	uint32_t	cpk_saddr;	/* source address */
	uint32_t	cpk_daddr;	/* destination address */

	uint16_t	cpk_l3_len;	/* IP header length */
	uint16_t	cpk_l4_len;	/* L4 header length */
	uint32_t	cpk_len;	/* l3 + l4 + data */
};

#define cpk_ipproto	cpk_key.k_ipproto

/*
 * Init the direction dependent part of the hash key in the packet cache
 * structure.
 */
static inline void cgn_pkt_key_init(struct cgn_packet *cpk, enum cgn_dir dir)
{
	if (dir == CGN_DIR_OUT) {
		/* Hash key is source address and port */
		cpk->cpk_key.k_addr = cpk->cpk_saddr;
		cpk->cpk_key.k_port = cpk->cpk_sid;
	} else {
		/* Hash key is destination address and port */
		cpk->cpk_key.k_addr = cpk->cpk_daddr;
		cpk->cpk_key.k_port = cpk->cpk_did;
	}
	assert(cpk->cpk_key.k_addr != 0);
}

#define ICMP_ERROR_MIN_L4_SIZE	8

#define CPK_ICMP		0x0001
#define CPK_ICMP_ECHO		0x0002	/* REQ or REPLY */
#define CPK_ICMP_ECHO_REQ	0x0004	/* REQ */
#define CPK_ICMP_ERR		0x0008
#define CPK_ICMP_EMBD_SHORT	0x0010	/* Embedded packet with short L4 hdr */


/*
 * For all supported protocols, we only need and reference the first two 32bit
 * words of the L4 header to obtain the sentry ids for matching and the
 * checksum.
 *
 * DCCP gets overlayed onto UDP for translation since the fields of interest
 * (ports and checksum) are the same.
 */

/*
 * All of the transports (TCP/UDP/UDP-Lite) share the same offsets for
 * their ports.
 */
struct cgn_ports {
	uint16_t	p_sport;
	uint16_t	p_dport;
};

/* The DCCP short header - as we never look beyond the type */
struct cgn_dccp {
	uint16_t dc_src;        /* source port */
	uint16_t dc_dst;        /* destination port */
	uint8_t  dc_doff;       /* data offset */
	uint8_t  dc_cc_cov;     /* CCVal and checksum coverage */
	uint16_t dc_checksum;
	uint8_t  dc_res_type_x; /* Reserved, Type, X-bit */
	uint8_t  dc_seqs_hi;    /* High order 8 bits */
	uint16_t dc_seqs_lo;    /* Low order 16 bits */
};

/* DCCP Type field */
#define DCCP_REQ	0
#define DCCP_RESP	1
#define DCCP_RST	7

/*
 * Layer 4 checksum offset from start of layer 4 header.
 */
static inline uint cgn_l4_cksum_offset(uint8_t ipproto)
{
	switch (ipproto) {
	case IPPROTO_TCP:
		return offsetof(struct tcphdr, check);
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_DCCP:
		return offsetof(struct udphdr, check);
	case IPPROTO_ICMP:
		return offsetof(struct icmp, icmp_cksum);
	default:
		break;
	}
	return 0;
}

/*
 * cgn_rwrip: rewrite required IP address
 */
static inline void cgn_rwrip(void *n_ptr, bool write_src, const uint32_t addr)
{
	struct ip *ip = n_ptr;

	if (write_src)
		ip->ip_src.s_addr = addr;
	else
		ip->ip_dst.s_addr = addr;
}

/*
 * cgn_rwrport: rewrite required TCP/UDP port
 */
static inline void cgn_rwrport(char *l4_ptr, bool write_src, in_port_t port)
{
	if (!write_src)
		l4_ptr += offsetof(struct cgn_ports, p_dport);
	*(in_port_t *)l4_ptr = port;
}

/*
 * cgn_rwricmpid: rewrite ICMP ECHO REQ/REPLY id
 */
static inline void cgn_rwricmpid(char *l4_ptr, uint16_t new_id)
{
	l4_ptr += offsetof(struct icmp, icmp_id);
	*(uint16_t *)l4_ptr = new_id;
}

int cgn_cache_all(struct rte_mbuf *m, uint l3_offset, struct ifnet *ifp,
		  enum cgn_dir dir, struct cgn_packet *cpk, bool icmp_err);

void cgn_rwrcksums(struct cgn_packet *cpk, void *n_ptr,
		   uint16_t l3_chk_delta, uint16_t l4_chk_delta);

#endif /* _CGN_MBUF_H_ */
