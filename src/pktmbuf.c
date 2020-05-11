/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Mbuf handling extensions
 */

#include <errno.h>
#include <netinet/udp.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <string.h>

#include "debug.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "netinet6/ip6_funcs.h"
#include "pktmbuf_internal.h"

struct rte_mempool;

void pktmbuf_free_bulk(struct rte_mbuf *pkts[], unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		rte_pktmbuf_free(pkts[i]);
}

struct rte_mbuf *pktmbuf_allocseg(struct rte_mempool *mpool, vrfid_t vrf_id,
				  int space)
{
	struct rte_mbuf *m0 = NULL, *m, **mp, *last = NULL;

	for (mp = &m0; space > 0; mp = &m->next) {
		m = pktmbuf_alloc(mpool, vrf_id);

		if (unlikely(m == NULL)) {
			rte_pktmbuf_free(m0);
			return NULL;
		}

		if (last)
			last->next = m;
		last = m;
		space -= rte_pktmbuf_tailroom(m);
		*mp = m;
		if (m != m0)
			++m0->nb_segs;
	}
	return m0;
}

/*
 * Append len bytes of data to the chain segment. If the last segment
 * does not have enough tailroom allocate and link a new segment.
 */
char *pktmbuf_append_alloc(struct rte_mbuf *m, uint16_t len)
{
	char *tail;
	struct rte_mbuf *m_new, *m_last;

	__rte_mbuf_sanity_check(m, 1);

	tail = rte_pktmbuf_append(m, len);
	if (tail)
		return tail;
	m_last = rte_pktmbuf_lastseg(m);

	m_new =  pktmbuf_allocseg(m->pool, pktmbuf_get_vrf(m), len);
	if (unlikely(!m_new))
		return NULL;

	m_last->next = m_new;
	m->nb_segs += m_new->nb_segs;
	m_new->nb_segs = 1;

	return rte_pktmbuf_append(m, len);
}

ALWAYS_INLINE void
dp_pktmbuf_mdata_invar_ptr_set(struct rte_mbuf *m,
			       uint32_t feature_id,
			       void *ptr)
{
	struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);

	/* userdata repurposed as flags + vrf field */
	mdata->md_feature_ptrs[feature_id] = ptr;
	m->udata64 |=
		((PKT_MDATA_INVAR_FEATURE_PTRS << feature_id) & UINT16_MAX)
		<< 16;
}

ALWAYS_INLINE bool
dp_pktmbuf_mdata_invar_ptr_get(const struct rte_mbuf *m,
			       uint32_t feature_id,
			       void **ptr)
{
	assert(feature_id < DP_PKTMBUF_MAX_INVAR_FEATURE_PTRS);

	if (m->udata64 &
	    (((PKT_MDATA_INVAR_FEATURE_PTRS << feature_id) & UINT16_MAX)
	     << 16)) {
		struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);

		*ptr = mdata->md_feature_ptrs[feature_id];
		return true;
	}
	return false;
}

ALWAYS_INLINE void
dp_pktmbuf_mdata_invar_ptr_clear(struct rte_mbuf *m,
				 uint32_t feature_id)
{
	m->udata64 &= ~((uint64_t)
			(((PKT_MDATA_INVAR_FEATURE_PTRS << feature_id) &
			  UINT16_MAX) << 16));
}

void pktmbuf_move_mdata(struct rte_mbuf *md, struct rte_mbuf *ms)
{
	int i;
	int found = 0;
	void *ptr;

	if (pktmbuf_mdata_invar_exists(ms, PKT_MDATA_INVAR_SPATH |
				       PKT_MDATA_INVAR_NAT64) ||
	    pktmbuf_mdata_exists(ms, PKT_MDATA_SESSION |
				  PKT_MDATA_CGNAT_SESSION |
				  PKT_MDATA_DPI_SEEN |
				  PKT_MDATA_SESSION_SENTRY))
		found = true;

	for (i = 0; i < DP_PKTMBUF_MAX_INVAR_FEATURE_PTRS; i++)
		found |= dp_pktmbuf_mdata_invar_ptr_get(ms, i, &ptr);

	if (!found)
		return;

	struct pktmbuf_mdata *mdatad = pktmbuf_mdata(md);
	struct pktmbuf_mdata *mdatas = pktmbuf_mdata(ms);

	for (i = 0; i < DP_PKTMBUF_MAX_INVAR_FEATURE_PTRS; i++) {
		if (dp_pktmbuf_mdata_invar_ptr_get(ms, i, &ptr)) {
			dp_pktmbuf_mdata_invar_ptr_set(md, i, ptr);
			dp_pktmbuf_mdata_invar_ptr_clear(ms, i);
		}
	}

	if (pktmbuf_mdata_exists(ms, PKT_MDATA_SESSION)) {
		pktmbuf_mdata_set(md, PKT_MDATA_SESSION);
		mdatad->md_session = mdatas->md_session;
		pktmbuf_mdata_clear(ms, PKT_MDATA_SESSION);
	}

	if (pktmbuf_mdata_exists(ms, PKT_MDATA_SESSION_SENTRY)) {
		pktmbuf_mdata_set(md, PKT_MDATA_SESSION_SENTRY);
		mdatad->md_sentry = mdatas->md_sentry;
		pktmbuf_mdata_clear(ms, PKT_MDATA_SESSION_SENTRY);
	}

	if (pktmbuf_mdata_exists(ms, PKT_MDATA_CGNAT_SESSION)) {
		pktmbuf_mdata_set(md, PKT_MDATA_CGNAT_SESSION);
		mdatad->md_cgn_session = mdatas->md_cgn_session;
		pktmbuf_mdata_clear(ms, PKT_MDATA_CGNAT_SESSION);
	}

	if (pktmbuf_mdata_invar_exists(ms, PKT_MDATA_INVAR_NAT64)) {
		pktmbuf_mdata_invar_set(md, PKT_MDATA_INVAR_NAT64);
		mdatad->md_nat64 = mdatas->md_nat64;
		pktmbuf_mdata_invar_clear(ms, PKT_MDATA_INVAR_NAT64);
	}

	if (pktmbuf_mdata_invar_exists(ms, PKT_MDATA_INVAR_SPATH)) {
		pktmbuf_mdata_invar_set(md, PKT_MDATA_INVAR_SPATH);
		mdatad->md_spath = mdatas->md_spath;
		pktmbuf_mdata_invar_clear(ms, PKT_MDATA_INVAR_SPATH);
	}

	if (pktmbuf_mdata_exists(ms, PKT_MDATA_DPI_SEEN)) {
		pktmbuf_mdata_set(md, PKT_MDATA_DPI_SEEN);
		pktmbuf_mdata_clear(ms, PKT_MDATA_DPI_SEEN);
	}
}

void pktmbuf_copy_meta(struct rte_mbuf *md, const struct rte_mbuf *ms)
{
	md->port = ms->port;
	md->ol_flags = ms->ol_flags & ~IND_ATTACHED_MBUF;
	md->packet_type = ms->packet_type;
	md->vlan_tci = ms->vlan_tci;
	md->vlan_tci_outer = ms->vlan_tci_outer;
	md->hash = ms->hash;
	md->tx_offload = ms->tx_offload;
	if (pktmbuf_mdata_exists(ms, PKT_MDATA_FROM_US))
		pktmbuf_mdata_set(md, PKT_MDATA_FROM_US);
}

struct rte_mbuf *pktmbuf_copy(const struct rte_mbuf *ms, struct rte_mempool *mp)
{
	struct rte_mbuf *md, *md_next, **prev;
	const char *src_p = rte_pktmbuf_mtod(ms, const char *);
	uint16_t src_bytes = ms->data_len;

	md = md_next = pktmbuf_alloc(mp, pktmbuf_get_vrf(ms));
	if (unlikely(!md))
		return NULL;

	/* Clone meta data from first mbuf */
	pktmbuf_copy_meta(md, ms);
	md->pkt_len = ms->pkt_len;
	prev = &md->next;

	for (;;) {
		/*
		 * Copy as many bytes as are available in the source mbuf, or
		 * as will fit in the destination mbuf, whichever is less.
		 */
		uint16_t dst_bytes = rte_pktmbuf_tailroom(md_next);
		size_t bytes_copied = RTE_MIN(dst_bytes, src_bytes);
		char *dst_p = rte_pktmbuf_mtod_offset(md_next, char *,
						      md_next->data_len);

		rte_memcpy(dst_p, src_p, bytes_copied);
		md_next->data_len += bytes_copied;
		src_p += bytes_copied;

		src_bytes -= bytes_copied;
		if (src_bytes == 0) {
			/*
			 * We copied all that was left in the ms buffer.
			 * Advance to the next source buffer if there is one.
			 */
			ms = ms->next;
			if (!ms) {
				__rte_mbuf_sanity_check(md, 1);
				return md;
			}

			src_p = rte_pktmbuf_mtod(ms, const char *);
			src_bytes = ms->data_len;
		}

		dst_bytes -= bytes_copied;
		if (dst_bytes == 0) {
			/*
			 * Exhausted current mbuf space
			 * Allocate a new one.
			 */
			md_next = pktmbuf_alloc(mp, pktmbuf_get_vrf(ms));
			if (unlikely(!md_next)) {
				rte_pktmbuf_free(md);
				return NULL;
			}

			md->nb_segs++;

			/* Make the previous segment point at this one. */
			*prev = md_next;
			prev = &md_next->next;
		}

	}
}


int pktmbuf_prepare_for_header_change(struct rte_mbuf **m, uint16_t header_len)
{
	struct rte_mbuf *mdir;
	uint16_t refcnt;

	/*
	 * Get the direct mbuf since an indirect mbuf can refer to an
	 * mbuf that is shared
	 */
	if (RTE_MBUF_DIRECT(*m))
		mdir = *m;
	else
		mdir = rte_mbuf_from_indirect(*m);

	refcnt = rte_mbuf_refcnt_read(mdir);

	if (unlikely(header_len > (*m)->data_len ||
		     (header_len == 0 && refcnt > 1))) {
		/*
		 * If the first segment is not big enough, then we will
		 * just copy the message, as there could be complications
		 * of different segments having different refcnts, etc.
		 *
		 * Also copy if header_len is 0, which means that changes
		 * could be anywhere in the packet.
		 */
		struct rte_mbuf *mc = pktmbuf_copy(*m, mdir->pool);

		if (unlikely(mc == NULL))
			return -ENOMEM;

		pktmbuf_move_mdata(mc, *m);
		rte_pktmbuf_free(*m);
		*m = mc;
		return 0;
	}

	if (unlikely(refcnt > 1)) {
		struct rte_mbuf *m_new;
		char *new_hdr;

		/*
		 * If the mbuf is being shared then we can't modify
		 * it, so we need to allocate a new mbuf for any
		 * modifications into and adjust the head of the
		 * original mbuf.
		 */
		m_new = pktmbuf_alloc(mdir->pool, pktmbuf_get_vrf(*m));
		if (unlikely(m_new == NULL))
			return -ENOMEM;

		new_hdr = rte_pktmbuf_append(m_new, header_len);
		if (unlikely(new_hdr == NULL))
			return -ENOMEM;
		memcpy(new_hdr, rte_pktmbuf_mtod(*m, char *), header_len);

		rte_pktmbuf_adj(*m, header_len);
		pktmbuf_copy_meta(m_new, *m);
		pktmbuf_move_mdata(m_new, *m);
		rte_pktmbuf_chain(m_new, *m);
		*m = m_new;
	}

	return 0;
}


/*
 * This function must get called on the head mbuf and never on a segment mbuf.
 */
void *memcpy_to_mbuf(struct rte_mbuf *m, const void *src, unsigned int offset,
		     unsigned int length)
{
	const char *tail = (const char *)src;

	if (offset + length > rte_pktmbuf_pkt_len(m))
		return NULL;

	while (length) {
		unsigned int count = length;

		if (offset >= m->data_len) {
			offset -= m->data_len;
			m = m->next;
			if (!m)
				return NULL;
			continue;
		}

		if (offset + length > m->data_len)
			count = m->data_len - offset;

		memcpy(rte_pktmbuf_mtod(m, char *) + offset, tail, count);
		length -= count;
		offset += count;
		tail += count;
	}

	return rte_pktmbuf_mtod(m, char *) + offset;
}

/*
 * This function must get called on the head mbuf and never on a segment mbuf.
 */
void *memcpy_from_mbuf(void *dest, struct rte_mbuf *m, unsigned int offset,
		       unsigned int length)
{
	char *tail = (char *)dest;

	if (offset + length > rte_pktmbuf_pkt_len(m))
		return NULL;

	while (length) {
		unsigned int count = length;

		if (offset >= m->data_len) {
			offset -= m->data_len;
			m = m->next;
			if (!m)
				return NULL;
			continue;
		}

		if (offset + length > m->data_len)
			count = m->data_len - offset;

		memcpy(tail, rte_pktmbuf_mtod(m, char *) + offset, count);
		length -= count;
		offset += count;
		tail += count;
	}

	return dest;
}

void pktmbuf_ecn_set_ce(struct rte_mbuf *m)
{
	const struct rte_ether_hdr *eh
		= rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);

	if (eh->ether_type == htons(RTE_ETHER_TYPE_IPV4))
		ip_tos_set_ecn_ce(iphdr(m));
	else if (eh->ether_type == htons(RTE_ETHER_TYPE_IPV6))
		ip6_tos_set_ecn_ce(ip6hdr(m));
}

void pktmbuf_save_ifp(struct rte_mbuf *m, struct ifnet *ifp)
{
	if (ifp->if_type == IFT_ETHER && ifp->if_local_port) {
		m->port = ifp->if_port;
		assert(m->port < DATAPLANE_MAX_PORTS);
	} else {
		pktmbuf_mdata(m)->md_ifindex.ifindex = ifp->if_index;
		pktmbuf_mdata_set(m, PKT_MDATA_IFINDEX);
	}
}

struct ifnet *pktmbuf_restore_ifp(struct rte_mbuf *m)
{
	struct ifnet *ifp;

	if (pktmbuf_mdata_exists(m, PKT_MDATA_IFINDEX)) {
		ifp = dp_ifnet_byifindex(pktmbuf_mdata(m)->md_ifindex.ifindex);
		pktmbuf_mdata_clear(m, PKT_MDATA_IFINDEX);
	} else {
		assert(m->port < DATAPLANE_MAX_PORTS);
		ifp = ifnet_byport(m->port);
	}

	return ifp;
}

int pktmbuf_tcp_header_is_usable(struct rte_mbuf *m)
{
	unsigned int l2l3hlen;
	unsigned int tcphlen;
	struct tcphdr *tcp;

	l2l3hlen = dp_pktmbuf_l2_len(m) + dp_pktmbuf_l3_len(m);
	tcphlen = l2l3hlen + sizeof(struct tcphdr);
	if (rte_pktmbuf_data_len(m) <= tcphlen)
		return 0;	/* can not overlay header */

	tcp = dp_pktmbuf_mtol4(m, struct tcphdr *);
	if (rte_pktmbuf_pkt_len(m) - l2l3hlen < ntohs(tcp->th_off)*4)
		return 0;	/* truncated */

	return 1;

}

int pktmbuf_udp_header_is_usable(struct rte_mbuf *m)
{
	unsigned int l2l3hlen;
	unsigned int udphlen;
	struct udphdr *udp;

	l2l3hlen = dp_pktmbuf_l2_len(m) + dp_pktmbuf_l3_len(m);
	udphlen = l2l3hlen + sizeof(struct udphdr);
	if (rte_pktmbuf_data_len(m) <= udphlen)
		return 0;	/* can not overlay header */

	udp = dp_pktmbuf_mtol4(m, struct udphdr *);
	if (rte_pktmbuf_pkt_len(m) - l2l3hlen < ntohs(udp->len))
		return 0;	/* truncated */

	return 1;

}

struct rte_mbuf *dp_pktmbuf_alloc_from_default(vrfid_t vrf_id)
{
	return pktmbuf_alloc(mbuf_pool(0), vrf_id);
}

vrfid_t
dp_pktmbuf_get_vrf(const struct rte_mbuf *m)
{
	return pktmbuf_get_vrf(m);
}

void dp_pktmbuf_mark_locally_generated(struct rte_mbuf *m)
{
	pktmbuf_mdata_set(m, PKT_MDATA_FROM_US);
}

static char *pktmbuf_mdata_feat_regs[DP_PKTMBUF_MAX_INVAR_FEATURE_PTRS];

int dp_pktmbuf_mdata_invar_feature_register(const char *name)
{
	int i;

	ASSERT_MASTER();

	if (!name)
		return -EINVAL;

	for (i = 0; i < DP_PKTMBUF_MAX_INVAR_FEATURE_PTRS; i++) {
		if (!pktmbuf_mdata_feat_regs[i]) {
			pktmbuf_mdata_feat_regs[i] =
				strdup(name);
			if (!pktmbuf_mdata_feat_regs[i]) {
				RTE_LOG(ERR, DATAPLANE,
					"Feature %s registration for meta data failed\n",
					name);
				return -ENOMEM;
			}
			RTE_LOG(INFO, DATAPLANE,
				"Feature %s registered for meta data ptr %d\n",
				name, i);
			return i;
		}
	}

	return -ENOSPC;
}

int dp_pktmbuf_mdata_invar_feature_unregister(const char *name, int slot)
{
	ASSERT_MASTER();

	if (!name)
		return -EINVAL;

	if (!pktmbuf_mdata_feat_regs[slot])
		return -EINVAL;

	if (strcmp(pktmbuf_mdata_feat_regs[slot], name))
		return -EINVAL;

	free(pktmbuf_mdata_feat_regs[slot]);
	pktmbuf_mdata_feat_regs[slot] = NULL;

	RTE_LOG(INFO, DATAPLANE,
		"Feature %s unregistered for meta data ptr %d\n",
		name, slot);

	return 0;
}
