/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
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

#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <stddef.h>
#include <stdint.h>

#include "in_cksum.h"
#include "ip_funcs.h"
#include "ipv4_frag_tbl.h"
#include "ipv4_rsmbl.h"
#include "pipeline.h"
#include "pl_fused_gen.h"
#include "pktmbuf_internal.h"
#include "snmp_mib.h"
#include "util.h"
#include "vrf_internal.h"

struct cds_lfht;

/*
 * Helper function.
 * Takes 2 mbufs that represents two fragments of the same packet and
 * chains them into one mbuf.
 */
static void ipv4_frag_chain(struct rte_mbuf *mn, struct rte_mbuf *mp)
{
	struct rte_mbuf *ms;

	/* adjust start of the last fragment data. */
	rte_pktmbuf_adj(mp, (uint16_t)(mp->l2_len +
			mp->l3_len));

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
 *    If the fragments have been reassembled, then return head of the mbuf chain
 */
static struct rte_mbuf *ipv4_frag_reassemble(struct ipv4_frag_pkt *fp)
{
	struct iphdr *ip_hdr;
	struct rte_mbuf *m, *prev;
	uint32_t i, n, ofs, first_len;
	uint16_t hlen;
	uint32_t m_idx;

	first_len = fp->frags[FIRST_FRAG_IDX].len;
	n = fp->last_idx - 1;

	/*start from the last fragment. */
	m = fp->frags[LAST_FRAG_IDX].mb;
	m_idx = LAST_FRAG_IDX;
	ofs = fp->frags[LAST_FRAG_IDX].ofs;

	while (ofs != first_len) {

		prev = m;

		for (i = n; i != FIRST_FRAG_IDX && ofs != first_len; i--) {
			if (fp->frags[i].mb == NULL)
				/* Already merged */
				continue;

			/* previous fragment found. */
			if (fp->frags[i].ofs + fp->frags[i].len == ofs) {

				ipv4_frag_chain(fp->frags[i].mb, m);
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
	ipv4_frag_chain(fp->frags[FIRST_FRAG_IDX].mb, m);

	m = fp->frags[FIRST_FRAG_IDX].mb;

	/* update ipv4 header for the reassembled packet */
	ip_hdr = iphdr(m);

	ip_hdr->tot_len = htons(fp->total_size +
				m->l3_len);
	ip_hdr->frag_off = (ip_hdr->frag_off & htons(IP_DF));
	hlen = ip_hdr->ihl << 2;
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum(ip_hdr, hlen);

	return m;
}

/*
 * Return Values:
 *    If fragment reassembled returns the new mbuf
 *    Otherwise NULL
 *       - no room for the fragment
 *	 - bad fragment
 *	 - mbuf was added to the table, and held for later
 */
static struct rte_mbuf *
ipv4_frag_process(struct cds_lfht *frag_tables, struct ipv4_frag_pkt *fp,
		  struct rte_mbuf *mb, uint16_t ofs, uint16_t len,
		  uint16_t more_frags)
{
	uint32_t idx = 0;
	vrfid_t vrf_id = pktmbuf_get_vrf(mb);
	struct pl_packet pkt = {
		.mbuf = mb,
		.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(mb),
	};
	unsigned int i;

	/* Lock the frag pkt */
	rte_spinlock_lock(&fp->pkt_lock);

	if (ofs == 0) {
		/* is this a repeat of the first fragment? */
		if (fp->frags[FIRST_FRAG_IDX].mb == NULL) {
			idx = FIRST_FRAG_IDX;
		} else {
			rte_pktmbuf_free(mb);
			mb = NULL;
			goto done;
		}
	} else if (more_frags == 0) {
		/* this is the last fragment. */
		fp->total_size = ofs + len;
		idx = (fp->frags[LAST_FRAG_IDX].mb == NULL) ?
			LAST_FRAG_IDX : UINT32_MAX;
	} else {
		/* this is an intermediate fragment. */
		idx = fp->last_idx;
		/*
		 * Check if its a duplicate intermediate fragment
		 * by checking the offset of all previous fragments
		 */
		for (i = 0; i < fp->last_idx; i++) {
			if (fp->frags[i].ofs == ofs) {
				rte_pktmbuf_free(mb);
				mb = NULL;
				goto done;
			}
		}

		if (idx < ARRAY_SIZE(fp->frags))
			fp->last_idx++;
	}

	/* errorneous packet: exceeded max allowed number of fragments */
	if (idx >= ARRAY_SIZE(fp->frags)) {
		ipv4_frag_free(frag_tables, fp);
		IPSTAT_INC(vrf_id, IPSTATS_MIB_REASMFAILS);
		rte_pktmbuf_free(mb);	/* drop bad packet as well */
		mb = NULL;
		goto done;
	}

	if (unlikely(!pipeline_fused_l2_consume(&pkt))) {
		mb = NULL;
		goto done;
	}

	IPSTAT_INC(vrf_id, IPSTATS_MIB_REASMREQDS);

	/* Remove session if we enqueue or reassemble */
	pktmbuf_mdata_clear(mb, PKT_MDATA_SESSION_SENTRY);

	fp->frag_size += len;
	fp->frags[idx].ofs = ofs;
	fp->frags[idx].len = len;
	fp->frags[idx].mb = mb;


	mb = NULL;

	/* not all fragments are collected yet. */
	if (likely(fp->frag_size < fp->total_size)) {
		mb = NULL;
		goto done;
	}

	/* if we collected all fragments, then try to reassemble. */
	if (fp->frag_size == fp->total_size &&
					fp->frags[FIRST_FRAG_IDX].mb != NULL) {
		mb = ipv4_frag_reassemble(fp);
		if (!mb) {
			IPSTAT_INC(vrf_id, IPSTATS_MIB_REASMFAILS);
			ipv4_frag_free(frag_tables, fp);
		} else {
			/*
			 * On successful reassembly, NULL out the
			 * mb's so that the frag_free doesn't free them
			 */
			ipv4_frag_clear(fp);

			/* Delete this pkt from the table */
			ipv4_frag_free(frag_tables, fp);
			IPSTAT_INC(vrf_id, IPSTATS_MIB_REASMOKS);
		}
	}

done:
	rte_spinlock_unlock(&fp->pkt_lock);
	return mb;
}

/*
 * Process new mbuf with fragment of IPV4 packet.
 */
static struct rte_mbuf *ipv4_frag_mbuf(struct rte_mbuf *mb)
{
	struct ipv4_frag_pkt *fp;
	struct ipv4_frag_key key;
	const uint64_t *psd;
	uint16_t ip_len;
	uint16_t flag_offset, ip_flag, ip_ofs;
	struct iphdr  *ipv4_hdr;
	vrfid_t vrfid = pktmbuf_get_vrf(mb);
	struct vrf *vrf = vrf_get_rcu(vrfid);

	if (!vrf)
		return NULL;

	ipv4_hdr = iphdr(mb);

	flag_offset = ntohs(ipv4_hdr->frag_off);
	ip_ofs = (flag_offset & IP_OFFMASK);
	ip_ofs <<= 3;
	ip_flag = flag_offset & IP_MF;

	/*
	 * Build the 4-tuple (src-ip, dst-ip, ID, proto) fragment key.
	 */
	psd = (uint64_t *)&ipv4_hdr->saddr;
	key.src_dst = psd[0];
	key.id = ipv4_hdr->id | (ipv4_hdr->protocol << 16);

	ip_len = (uint16_t)(ntohs(ipv4_hdr->tot_len) -
	mb->l3_len);

	/* try to find/add entry into the fragment's table. */
	fp = ipv4_frag_find(vrf, &key);
	if (fp == NULL) {
		IPSTAT_INC(pktmbuf_get_vrf(mb), IPSTATS_MIB_REASMFAILS);
		rte_pktmbuf_free(mb);
		return NULL;
	}

	/* process the fragmented packet. */
	mb = ipv4_frag_process(vrf->v_ipv4_frag_table,
			       fp, mb, ip_ofs, ip_len, ip_flag);

	return mb;
}

/*
 * Returns a mbuf containing the chain of fragments if all fragments are found
 * Returns NULL if mbuf containing fragment held or there was an error
 */
struct rte_mbuf *ipv4_handle_fragment(struct rte_mbuf *m)
{
	struct rte_mbuf *mo;
	struct iphdr *ip;
	uint16_t hlen;

	/* prepare mbuf: setup l2_len/l3_len. */
	ip = iphdr(m);
	hlen = ip->ihl << 2;
	m->l2_len = ETHER_HDR_LEN;
	m->l3_len = hlen;

	mo = ipv4_frag_mbuf(m);
	if (mo)
		pktmbuf_mdata_set(mo, PKT_MDATA_DEFRAG);

	return mo;
}
