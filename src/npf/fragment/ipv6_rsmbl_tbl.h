/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef IPV6_FRAG_TBL_H
#define IPV6_FRAG_TBL_H

#include <rte_spinlock.h>
#include <stdint.h>

#include "npf/fragment/ipv6_rsmbl.h"
#include "urcu.h"
#include "vrf_internal.h"

struct cds_lfht;
struct vrf;

/*
 * Default IPv6 RCU hash table values.
 *
 * IPV6_FRAG_HT_INIT - Number of hash buckets to alloc initially. Must be
 *                     a power or two.
 * IPV6_FRAG_HT_MIN  - Min number of hash buckets.  Must be a power of two.
 * IPV6_FRAG_HT_MAX  - Max number of hash buckets.  Must be a power of two.
 */
#define IPV6_FRAG_HT_INIT	32
#define IPV6_FRAG_HT_MIN	64
#define IPV6_FRAG_HT_MAX	512

/* Max number of fragment sets we support */
#define IPV6_MAX_FRAG_SETS	1024

/* GC periodic hash table cleanup interval (seconds) */
#define IPV6_FRAG_INTERVAL	10

/* Timeout period for incomplete fragment sets */
#define IPV6_FRAG_SET_TTL       15

/*
 * IPv6 reassembly fragment
 */
struct ipv6_frag {
	/* Frag hdr offset value */
	uint16_t   ofs;
	/*
	 * Number of bytes in this fragment that we want to include in
	 * the reassembled packet. For the first fragment this is the
	 * IPv6 payload length less the fragmentation header.  For
	 * subsequent fragments this is the IPv6 payload length less
	 * the fragmentation header and less any non-fragmentable
	 * extension headers.
	 *
	 * This value relates to the frag hdr offset in that the sum
	 * of the previous fragment 'len' values will equal the
	 * current fragment header 'offset' value.
	 */
	uint16_t   len;
	struct rte_mbuf *mb;
};

/*
 * Use <src addr, dst_addr, id> to uniquely identify fragmented datagram.
 */
#define IPV6_FRAG_KEY_WORDS 8

struct ipv6_frag_key {
	uint32_t  src_dst[IPV6_FRAG_KEY_WORDS];
	uint32_t  id;
};

/*
 * IPv6 fragmented packet to reassemble.  First two entries in the
 * frags[] array are for the last and first fragments.
 */
struct ipv6_frag_pkt {
	struct rcu_head		pkt_rcu_head;	/* for call_rcu */
	struct cds_lfht_node	pkt_node;	/* For hash table */
	rte_spinlock_t		pkt_lock;	/* lock for this pkt */
	struct ipv6_frag_key	pkt_key;	/* src_dst/id key */
	uint64_t		pkt_expire;	/* expiration timestamp */
	uint32_t		total_size;	/* expected reassd size */
	uint32_t		frag_size;	/* size of fragments rcvd */
	uint32_t		last_idx;	/* next entry to fill */
	/*
	 * Offset  (from  start   of  l3  hdr)  and   length  of  last
	 * unfragmentable  extension header  before the  fragmentation
	 * header.  Taken from the first  fragment (since we know this
	 * is the same for all fragments)
	 */
	uint16_t                last_unfrg_hlen;
	uint16_t                last_unfrg_hofs;
	/* Protocol type of first fragmentable hdr after the frag hdr */
	uint8_t                 first_frg_proto;
	/* Senders MTU gleaned from the largest fragment */
	uint16_t                mtu;
	struct ipv6_frag	frags[IPV6_MAX_FRAGS_PER_SET];
};

struct ipv6_frag_pkt *
ipv6_frag_find_or_create(struct vrf *vrf, const struct ipv6_frag_key *);
void ipv6_frag_free(struct cds_lfht *frag_table, struct ipv6_frag_pkt *);
void ipv6_frag_clear(struct ipv6_frag_pkt *);

#endif /* IPV6_RSMBL_TBL_H */
