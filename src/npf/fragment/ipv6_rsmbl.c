/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "npf/fragment/ipv4_rsmbl.h"
#include "ip6_funcs.h"
#include "npf/npf.h"
#include "npf/fragment/ipv6_rsmbl.h"
#include "npf/fragment/ipv6_rsmbl_tbl.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "pktmbuf_internal.h"
#include "snmp_mib.h" /* IPv6 stats */
#include "util.h"
#include "vrf_internal.h"

struct cds_lfht;

/*
 * Helper function.  Takes 2 mbufs that represents two fragments of
 * the same packet and chains them into one mbuf.
 *
 * non_frag_hdr_len is the IPv6 hdr plus any non fragmentable
 * extension hdrs.
 */
static void
ipv6_frag_chain(struct rte_mbuf *mn __unused, struct rte_mbuf *mp,
		int non_frag_hdr_len)
{
	struct rte_mbuf *ms;

	/*
	 * adjust start of the last fragment data.  This aims to set
	 * m->data_off such that it bypasses the eth hdr, IPv6 hdr,
	 * fragmentation hdr, and any repeated extension hdrs (which
	 * would come before the frag hdr).
	 */
	rte_pktmbuf_adj(mp, (uint16_t)(mp->l2_len +
				       non_frag_hdr_len +
				       sizeof(struct ip6_frag)));

	/* chain two fragments. */
	ms = rte_pktmbuf_lastseg(mn);
	ms->next = mp;

	/* accumulate number of segments and total length. */
	mn->nb_segs = (uint8_t)(mn->nb_segs + mp->nb_segs);
	mn->pkt_len += mp->pkt_len;

	/* reset pkt_len and nb_segs for chained fragment. */
	mp->pkt_len = mp->data_len;
	mp->nb_segs = 1;
}

/*
 * Reassemble fragments into one packet.
 *
 * Return Values :
 *    If an error occurred, then return NULL
 *    If the fragments have been reassembled, then return head of the
 *    mbuf chain
 */
static struct rte_mbuf *
ipv6_frag_reassemble(struct ipv6_frag_pkt *fp)
{
	unsigned int non_frag_hdr_len;
	uint32_t i, n, ofs, first_len;
	struct rte_mbuf *m, *prev;
	struct ip6_hdr	*ip6;
	uint32_t m_idx;

	if (!fp->frags[FIRST_FRAG_IDX].mb)
		return NULL;

	first_len = fp->frags[FIRST_FRAG_IDX].len;
	n = fp->last_idx - 1;

	/* start from the last fragment. */
	m = fp->frags[LAST_FRAG_IDX].mb;
	m_idx = LAST_FRAG_IDX;
	ofs = fp->frags[LAST_FRAG_IDX].ofs;

	/* IPv6 hdr plus non fragmentable ext hdrs */
	non_frag_hdr_len = fp->last_unfrg_hofs + fp->last_unfrg_hlen;

	while (ofs != first_len) {
		prev = m;

		for (i = n; i != FIRST_FRAG_IDX && ofs != first_len; i--) {
			if (fp->frags[i].mb == NULL)
				/* Already merged */
				continue;

			/* previous fragment found. */
			if (fp->frags[i].ofs + fp->frags[i].len == ofs) {

				ipv6_frag_chain(fp->frags[i].mb, m,
						non_frag_hdr_len);
				/*
				 * We have chained them, so now clear the ptr
				 * to the chained mbuf so that we do not double
				 * free it later if there is an error.
				 */
				fp->frags[m_idx].mb = NULL;

				/* update our last fragment and offset. */
				m = fp->frags[i].mb;
				m_idx = i;
				ofs = fp->frags[i].ofs;
			}
		}

		/* error - hole in the packet. */
		if (m == prev)
			return NULL;
	}

	/* chain with the first fragment. */
	ipv6_frag_chain(fp->frags[FIRST_FRAG_IDX].mb, m, non_frag_hdr_len);

	/* At this point we have a single chain of mbufs. */
	m = fp->frags[FIRST_FRAG_IDX].mb;
	ip6 = ip6hdr(m);
	ip6->ip6_plen = htons(fp->total_size);

	/*
	 * The m->data_off of all mbuf's except the first will point
	 * to the data.
	 *
	 * The first mbuf still points to (in order) the original
	 * fragments IPv6 header, non-fragmentable ext. headers,
	 * fragment header, fragmentable ext. headers, and the data.
	 *
	 * Remove fragmentation header by moving all headers before
	 * the frag header up 8 bytes. note that per RFC2460, we need
	 * to update the last non-fragmentable header with the "next
	 * header" field to contain type of the first fragmentable
	 * header.  Go backwards to make sure we don't overwrite
	 * anything important
	 *
	 * Adjust down: data_len and pkt_len in first mbuf
	 * Adjust up:	data_off ... ?
	 *
	 * We want to go from:
	 *
	 * |--- IPv6 hdr ---|-- unfrg ext --|-- frag hdr --|-- payload --|
	 * |	   40	    |	extra_hlen  |	   8	   |		 |
	 *
	 * to:
	 *		  |--- IPv6 hdr ---|-- unfrg ext --|-- payload --|
	 *
	 * Data in buffer starts at: (char *)((m)->buf_addr) + (m)->data_off
	 *
	 * rte_pktmbuf_adj increments data_off, and decrements data_len
	 * and pkt_len.
	 */
	char *src, *dst;
	int j;
	int len;

	/* Copy the ethernet header as well */
	len = non_frag_hdr_len + m->l2_len;
	src = (char *)(m->buf_addr) + m->data_off;

	/* Move data_off up by 8 bytes etc. */
	rte_pktmbuf_adj(m, sizeof(struct ip6_frag));
	dst = (char *)(m->buf_addr) + m->data_off;

	/* Copy from high to low */
	for (j = len - 1; j >= 0; j--)
		dst[j] = src[j];

	/*
	 * Update the proto field in the last unfragmentable hdr
	 */
	ip6 = ip6hdr(m);

	if (fp->last_unfrg_hofs == 0) {
		/*
		 * There are no unfrg ext hdrs, so update the IPv6
		 * hdr
		 */
		ip6->ip6_nxt = fp->first_frg_proto;
	} else {
		/*
		 * There is at least one non-fragmentable extension
		 * hdr.	 We need to update the 'next proto' field of
		 * the last non-frag. etc hdr.
		 */
		struct ip6_ext *ip6e;

		ip6e = (struct ip6_ext *)((char *)ip6 + fp->last_unfrg_hofs);
		if (ip6e)
			ip6e->ip6e_nxt = fp->first_frg_proto;
	}

	return m;
}

/*
 * Return Values:
 *    If fragment reassembled returns the new mbuf
 *    Otherwise NULL
 *	 - no room for the fragment
 *	 - bad fragment
 *	 - mbuf was added to the table, and held for later
 */
static struct rte_mbuf *
ipv6_frag_process(struct cds_lfht *frag_table, struct ipv6_frag_pkt *fp,
		  struct rte_mbuf *m, npf_cache_t *npc, uint16_t *gleaned_mtu)
{
	struct ip6_hdr	*ip6;
	uint32_t idx = 0;
	vrfid_t vrf_id = pktmbuf_get_vrf(m);
	struct pl_packet pkt = {
		.mbuf = m,
		.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
	};
	unsigned int i;

	/*
	 * Payload length (everything after the initial IPv6 hdr)
	 */
	uint16_t plen;
	/*
	 * Sum of the unfragmentable extension hdr lengths to be
	 * subtracted from the payload length to get the size of the
	 * reassembled pkt.  (For the first fragment this is just the
	 * fragmentation header length).
	 */
	uint16_t extra_hlen;

	if (!npc)
		return m;

	ip6 = ip6hdr(m);
	plen = ntohs(ip6->ip6_plen);

	/*
	 * Size of non fragmentable hdrs between IPv6 hdr and fragment
	 * data.  For the simple case of no non-frg hdrs this will be
	 * 0 + 40 + 8 - 40 == 8.
	 *
	 * If there was a 16 byte hdr, for example, this would be:
	 * 40 + 16 + 8 - 40 == 24
	 */
	extra_hlen = npc->last_unfrg_hofs + npc->last_unfrg_hlen +
		sizeof(struct ip6_frag) - sizeof(struct ip6_hdr);

	/* Lock the frag pkt */
	rte_spinlock_lock(&fp->pkt_lock);

	if (npc->fh_offset == 0) {
		/*
		 * First fragment
		 */
		if (fp->frags[FIRST_FRAG_IDX].mb == NULL) {
			idx = FIRST_FRAG_IDX;
		} else {
			rte_pktmbuf_free(m);
			m = NULL;
			goto done;
		}
		/*
		 * 'fp->frag_size' is the accumulated number of bytes
		 * that will comprise the reassembled packet.
		 *
		 * Unlike the intermediate and last fragments, all ext
		 * hdrs in the first fragment except for the frag hdr,
		 * will be in the reassembled pkt, so we only subtract
		 * the frag hdr length from plen.
		 */
		fp->frag_size += (plen - sizeof(struct ip6_frag));

		fp->last_unfrg_hlen = npc->last_unfrg_hlen;
		fp->last_unfrg_hofs = npc->last_unfrg_hofs;
		fp->first_frg_proto = npf_cache_ipproto(npc);
	} else if (!npc->fh_more) {
		/*
		 * Last fragment
		 */
		idx = (fp->frags[LAST_FRAG_IDX].mb == NULL) ?
			LAST_FRAG_IDX : UINT32_MAX;

		fp->frag_size += (plen - extra_hlen);

		/*
		 * Total pkt size is the offset value in the last frag
		 * hdr offset plus the payload length of the last
		 * fragment less fragmentation header.
		 */
		fp->total_size = npc->fh_offset + plen - sizeof(struct ip6_frag);
	} else {
		/*
		 * Intermediate fragment
		 */
		idx = fp->last_idx;
		/*
		 * Check if its a duplicate intermediate fragment
		 * by checking the offset of all previous fragments
		 */
		for (i = 0; i < fp->last_idx; i++) {
			if (fp->frags[i].ofs == npc->fh_offset) {
				rte_pktmbuf_free(m);
				m = NULL;
				goto done;
			}

			if (fp->frags[i].ofs < npc->fh_offset &&
			    (fp->frags[i].ofs + fp->frags[i].len) >
			    npc->fh_offset) {
				/*
				 * We already have a fragment that includes
				 * the start byte of this one.
				 */
				rte_pktmbuf_free(m);
				m = NULL;
				goto done;
			}

			if (fp->frags[i].ofs <
			    (npc->fh_offset + (plen - extra_hlen)) &&
			    (fp->frags[i].ofs + fp->frags[i].len) >
			    (npc->fh_offset + (plen - extra_hlen))) {
				/*
				 * We already have a fragment that includes
				 * the end byte of this one.
				 */
				rte_pktmbuf_free(m);
				m = NULL;
				goto done;
			}

		}
		if (idx < IPV6_MAX_FRAGS_PER_SET)
			fp->last_idx++;

		fp->frag_size += (plen - extra_hlen);
	}

	/*
	 * Glean the senders MTU from the payload length of the
	 * largest fragment.
	 */
	if (plen + sizeof(struct ip6_hdr) > fp->mtu)
		fp->mtu = plen + sizeof(struct ip6_hdr);

	/*
	 * errorneous packet: exceeded max allowed number of
	 * fragments.
	 */
	if (idx >= ARRAY_SIZE(fp->frags) ||
		fp->frags[idx].mb != NULL) {
		ipv6_frag_free(frag_table, fp);
		IP6STAT_INC(vrf_id, IPSTATS_MIB_REASMFAILS);
		rte_pktmbuf_free(m);	/* drop bad packet as well */
		m = NULL;
		goto done;
	}

	if (unlikely(!pipeline_fused_l2_consume(&pkt))) {
		m = NULL;
		goto done;
	}

	fp->frags[idx].ofs = npc->fh_offset;
	/* Payload bytes in this fragment */
	fp->frags[idx].len = plen - extra_hlen;
	fp->frags[idx].mb = m;

	pktmbuf_mdata_clear(m, PKT_MDATA_SESSION_SENTRY);

	m = NULL;

	if (likely(fp->frag_size < fp->total_size)) {
		/* Not all fragments are collected yet */
		goto done;
	}

	/*
	 * If we have collected all fragments then try to reassemble
	 * them
	 */
	if (fp->frag_size == fp->total_size &&
	    fp->frags[FIRST_FRAG_IDX].mb != NULL) {
		m = ipv6_frag_reassemble(fp);
		if (!m) {
			IP6STAT_INC(vrf_id, IPSTATS_MIB_REASMFAILS);
			ipv6_frag_free(frag_table, fp);
		} else {
			/*
			 * Pass the values we cached from the first
			 * fragment back to the calling function so
			 * they can be used for re-fragmentation if
			 * necessary.
			 */
			npc->last_unfrg_hlen = fp->last_unfrg_hlen;
			npc->last_unfrg_hofs = fp->last_unfrg_hofs;

			/*
			 * Update the caches final proto field, since
			 * the final proto is no longer a fragmentation
			 * header.
			 */
			npc->npc_proto_final = fp->first_frg_proto;

			/*
			 * Retrieve the senders mtu value that we
			 * gleaned from the first fragment
			 */
			*gleaned_mtu = fp->mtu;

			/*
			 * On successful reassembly, NULL out the
			 * mb's so that the frag_free doesn't free them
			 */
			ipv6_frag_clear(fp);

			/* Delete this pkt from the table */
			ipv6_frag_free(frag_table, fp);
			IP6STAT_INC(vrf_id, IPSTATS_MIB_REASMOKS);
		}
	}

done:
	rte_spinlock_unlock(&fp->pkt_lock);
	return m;
}

/*
 * Process new mbuf with fragment of IPv6 packet.
 */
static struct rte_mbuf *
ipv6_frag_mbuf(struct rte_mbuf *m, npf_cache_t *npc,
	       uint16_t *gleaned_mtu)
{
	struct ipv6_frag_pkt *fp;
	struct ipv6_frag_key key;
	struct ip6_hdr	*ip6;
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	struct vrf *vrf = vrf_get_rcu(vrfid);

	if (!vrf)
		return NULL;

	ip6 = ip6hdr(m);

	/*
	 * Key is 9 words - src, dst and fragmentation identifier
	 */
	assert(sizeof(key.src_dst) == sizeof(ip6->ip6_src) +
	       sizeof(ip6->ip6_dst));
	memcpy(key.src_dst, &ip6->ip6_src, sizeof(ip6->ip6_src));
	memcpy(&key.src_dst[IPV6_FRAG_KEY_WORDS/2],
	       &ip6->ip6_dst, sizeof(ip6->ip6_dst));
	key.id = npc->fh_id;

	/*
	 * try to find an entry in the fragment's table.  If one
	 * doesn't exist then create one.  This will fail if we have
	 * reached the max fragment sets.
	 */
	fp = ipv6_frag_find_or_create(vrf, &key);
	if (fp == NULL) {
		IP6STAT_INC_VRF(vrf, IPSTATS_MIB_REASMFAILS);
		rte_pktmbuf_free(m);
		return NULL;
	}

	/* process the fragmented packet. */
	m = ipv6_frag_process(vrf->v_ipv6_frag_table, fp, m, npc, gleaned_mtu);

	return m;
}

/**
 * IPv6 reassembly handling
 *
 * Takes packet fragments as they are received and stores them until
 * the last fragment is received.  Returns a mbuf containing the chain
 * of fragments if all fragments are found.  Returns NULL if there was
 * an error
 *
 * @param[in] m
 *   The input packet fragment.
 * @param[in] npf_flag
 *   Pointer to npf flags
 * @ret
 *   NULL if fragment is retained; non-NULL if packet not retained, or
 *   for a reassembled packet
 */
struct rte_mbuf *
ipv6_handle_fragment(struct rte_mbuf *m, uint16_t *npf_flag)
{
	npf_cache_t *npc;
	uint16_t gleaned_mtu = RTE_ETHER_MTU;

	if (!m || (*npf_flag & NPF_FLAG_CACHE_EMPTY) != 0)
		return m;

	npc = npf_cache();

	/*
	 * ipv6_frag_mbuf will return NULL if it holds onto a
	 * fragment, or on error
	 */
	m = ipv6_frag_mbuf(m, npc, &gleaned_mtu);
	if (m) {
		npc->gleaned_mtu = gleaned_mtu;

		/*
		 * Set the empty flag so that the reassembled packet
		 * is cached on return of this function.  The previous
		 * cache will have stopped at the fragmentation
		 * header, and not have cached any layer 4 info.
		 *
		 * Mark the packet as being a reassembled packet so
		 * that we can re-fragment it on output using the
		 * gleaned mtu.
		 */
		uint32_t from_us = *npf_flag & NPF_FLAG_FROM_US;
		*npf_flag = NPF_FLAG_CACHE_EMPTY | from_us;
		pktmbuf_mdata_set(m, PKT_MDATA_DEFRAG);
	}
	return m;
}
