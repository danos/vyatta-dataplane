/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef IPV4_FRAG_TBL_H
#define IPV4_FRAG_TBL_H

#include <rte_memory.h>
#include <rte_spinlock.h>
#include <stdint.h>
#include <urcu.h>

#include "urcu.h"
#include "vrf.h"

struct cds_lfht;
struct vrf;

/*
 * Default IPv4 RCU hash table values.
 *
 * IPV4_FRAG_HT_INIT - Number of hash buckets to alloc initially. Must be
 *                     a power or two.
 * IPV4_FRAG_HT_MIN  - Min number of hash buckets.  Must be a power of two.
 * IPV4_FRAG_HT_MAX  - Max number of hash buckets.  Must be a power of two.
 */
#define IPV4_FRAG_HT_INIT	32
#define IPV4_FRAG_HT_MIN	64
#define IPV4_FRAG_HT_MAX	512

/* Max number of fragment sets we support */
#define IPV4_MAX_FRAG_SETS	1024

/* Max number of fragments per fragment set */
#define IPV4_MAX_FRAGS_PER_SET	44

/* GC periodic hash table cleanup interval (seconds) */
#define IPV4_FRAG_INTERVAL	10

/* Timeout period for incomplete fragment sets */
#define IPV4_FRAG_SET_TTL       15

struct ipv4_frag {
	uint16_t ofs;
	uint16_t len;
	struct rte_mbuf *mb;
};

/*
 * Use <src addr, dst_addr, id> to uniquely identify fragmented datagram.
 */
struct ipv4_frag_key {
	uint64_t  src_dst;
	uint32_t  id;
};

/*
 * Fragmented packet to reassemble.
 * First two entries in the frags[] array are for the last and first fragments.
 */
struct ipv4_frag_pkt {
	struct rcu_head		pkt_rcu_head;	/* for call_rcu */
	struct cds_lfht_node	pkt_node;	/* For hash table */
	rte_spinlock_t		pkt_lock;	/* lock for this pkt */
	struct ipv4_frag_key	pkt_key;	/* src_dst/id key */
	uint64_t		pkt_expire;	/* expiration timestamp */
	uint32_t		total_size;	/* expected reassembled size */
	uint32_t		frag_size;	/* size of fragments received */
	uint32_t		last_idx;	/* next entry to fill */
	struct ipv4_frag	frags[IPV4_MAX_FRAGS_PER_SET];
} __rte_cache_aligned;


void ipv4_frag_tbl_create(void);
void ipv4_frag_free(struct cds_lfht *frag_table, struct ipv4_frag_pkt *);
void ipv4_frag_clear(struct ipv4_frag_pkt *);
struct ipv4_frag_pkt *ipv4_frag_find(struct vrf *vrf,
				     const struct ipv4_frag_key *);

#endif /* IPV4_FRAG_TBL_H */
