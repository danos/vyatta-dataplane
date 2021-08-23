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
#include "vrf.h"

#include "npf/nat/nat_proto.h"
#include "npf/cgnat/alg/alg_defs.h"
#include "npf/cgnat/cgn_hash_key.h"
#include "npf/cgnat/cgn.h"

struct cgn_sess2;
struct cgn_source;
struct cgn_policy;
struct alg_pinhole;

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
 * oaddr and oid are the original subscriber address and port/id.
 *
 * taddr and tid are the translation address and port/id.  These may be set
 * from an ALG pinhole.
 *
 * cpk_pkt_cgnat is set true if either: 1. Matched session, 2. Matched CGNAT
 * policy.
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

	uint32_t	cpk_saddr;	/* source address */
	uint32_t	cpk_daddr;	/* destination address */

	uint16_t	cpk_l3_len;	/* IP header length */
	uint16_t	cpk_l4_len;	/* L4 header length */
	uint32_t	cpk_len;	/* l3 + l4 + data */

	uint16_t	cpk_cksum;	/* l4 checksum */
	uint16_t	cpk_sid;	/* source port or id */
	uint16_t	cpk_did;	/* dest port or id */
	uint8_t		cpk_pad1[1];

	/*
	 * cpk_alg_id is *only* set for new ALG flows.
	 *
	 * For new parent flows, cpk_alg_id is set from cgn_session_establish
	 * based on the return value of cgn_alg_dest_port_lookup.
	 *
	 * For new child/data flows, cpk_alg_id is set in
	 * cgn_alg_pinhole_lookup.
	 */
	enum cgn_alg_id		cpk_alg_id;

	/* Set for first pkt of a child/data flow */
	struct alg_pinhole	*cpk_alg_pinhole;
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

/* cpk_info */
#define CPK_ICMP		0x0001
#define CPK_ICMP_ECHO		0x0002	/* REQ or REPLY */
#define CPK_ICMP_ECHO_REQ	0x0004	/* REQ */
#define CPK_ICMP_ERR		0x0008
#define CPK_ICMP_EMBD_SHORT	0x0010	/* Embedded packet with short L4 hdr */
#define CPK_GRE			0x0020	/* Enhanced GRE (for PPTP) */


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
 * GRE (for PPTP)
 */
#define GRE_VERSION_ENHANCED	1

/*
 * Enhanced GRE header (rfc2637).  This directly follows the IP header.
 *
 * The important parameter is the Call ID (egre_call_id).  This identifies the
 * session (analogous to TCP/UDP source port)
 */
struct egre {
	union {
		struct {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint16_t egre_A_flag:1;  /* ack number present */
			uint16_t egre_flgs:4;    /* Must be set to zero */
			uint16_t egre_ver:3;     /* Must be 1. Enhanced GRE */

			uint16_t egre_C_flag:1;  /* checksum present */
			uint16_t egre_R_flag:1;  /* routing present */
			uint16_t egre_K_flag:1;  /* key present */
			uint16_t egre_S_flag:1;  /* seq number present */

			uint16_t egre_s_flag:1;  /* strict src route present */
			uint16_t egre_recur:3;   /* recursion ctrl */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t egre_recur:3;   /* recursion ctrl */
			uint16_t egre_s_flag:1;  /* strict src route present */

			uint16_t egre_S_flag:1;  /* seq number present */
			uint16_t egre_K_flag:1;  /* key present */
			uint16_t egre_R_flag:1;  /* routing present */
			uint16_t egre_C_flag:1;  /* checksum present */

			uint16_t egre_ver:3;     /* Must be 1. Enhanced GRE */
			uint16_t egre_flgs:4;    /* Must be set to zero */
			uint16_t egre_A_flag:1;  /* ack number present */
#else
#error "Please include <bits/endian.h>"
#endif
		};
		uint16_t egre_flags;	/* Flags and version */
	};
	uint16_t	egre_protocol;  /* protocol type */
	uint16_t	egre_pload_len; /* key payload length */
	uint16_t	egre_call_id;   /* key Call ID */

	/*
	 * Optional:
	 * uint32_t seq_number
	 * uint32_t ack_number
	 */
	uint8_t		egre_opt[0];
};

/*
 * Masks for flags/version word.
 *
 * Note that the #defines below will work with the egre_flags word (network
 * byte order) in 'struct egre'
 *
 * The bit-map in the comment below is what you might expect to see in
 * Wireshark as it will show the egre_flags word in host byte order.
 *
 * X... .... .... .... = Checksum bit
 * .X.. .... .... .... = Routing bit
 * ..X. .... .... .... = Key bit
 * ...X .... .... .... = Seq number bit
 * .... X... .... .... = Strict Source Route bit
 * .... .XXX .... .... = Recursion control
 * .... .... X... .... = Ack
 * .... .... .XXX X... = Flags (Reserved)
 * .... .... .... .XXX = Version
 */
#define EGRE_MASK_CKSUM	0x0080
#define EGRE_MASK_RT	0x0040
#define EGRE_MASK_KEY	0x0020
#define EGRE_MASK_SEQ	0x0010
#define EGRE_MASK_SSRT	0x0008
#define EGRE_MASK_RCSN	0x0007
#define EGRE_MASK_ACK	0x8000
#define EGRE_MASK_FLAGS	0x7800
#define EGRE_MASK_VERS	0x0700

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

/*
 * Extended GRE Call ID
 */
static inline void cgn_write_pptp_call_id(char *l4_ptr, uint16_t new_id)
{
	l4_ptr += offsetof(struct egre, egre_call_id);
	*(uint16_t *)l4_ptr = new_id;
}

int cgn_cache_all(struct rte_mbuf *m, uint l3_offset, struct ifnet *ifp,
		  enum cgn_dir dir, struct cgn_packet *cpk, bool icmp_err);

void cgn_rwrcksums(struct cgn_packet *cpk, void *n_ptr,
		   uint16_t l3_chk_delta, uint16_t l4_chk_delta);

/* Payload len *after* the L4 header */
static inline uint cgn_payload_len(struct cgn_packet *cpk)
{
	return cpk->cpk_len - (cpk->cpk_l3_len + cpk->cpk_l4_len);
}

/* Pointer to CGNAT packet payload *after* the L4 header */
static inline char *cgn_payload(struct cgn_packet *cpk, struct rte_mbuf *mbuf)
{
	return dp_pktmbuf_mtol3(mbuf, char *) + cpk->cpk_l3_len +
		cpk->cpk_l4_len;
}

#endif /* CGN_MBUF_H */
