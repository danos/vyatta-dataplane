/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <rte_ether.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "in_cksum.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_icmp.h"
#include "npf/npf_mbuf.h"
#include "npf/npf_nat.h"
#include "pktmbuf_internal.h"

struct ifnet;
struct npf_instance;
struct rte_mbuf;

npf_session_t __noinline *
npf_icmp_err_session_find(int di, struct rte_mbuf *nbuf, npf_cache_t *npc,
		const struct ifnet *ifp)
{
	uint16_t ether_proto;

	/* Sanity checks - these should never occur */
	if (!(npc->npc_info & NPC_ICMP_ERR))
		return NULL;

	/* Only valid for IPv4/IPv6 */
	if (npf_iscached(npc, NPC_IP4))
		ether_proto = htons(ETHER_TYPE_IPv4);
	else if (npf_iscached(npc, NPC_IP6))
		ether_proto = htons(ETHER_TYPE_IPv6);
	else
		return NULL;

	void *n_ptr = dp_pktmbuf_mtol3(nbuf, char *) + npf_cache_hlen(npc);

	/* Find the start of the packet embedded in the ICMP error. */
	n_ptr = nbuf_advance(&nbuf, n_ptr, ICMP_MINLEN);
	if (!n_ptr)
		return NULL;

	/* Init the embedded npc. */
	npf_cache_t enpc;
	npf_cache_init(&enpc);

	/* Inspect the embedded packet. */
	if (!npf_cache_all_at(&enpc, nbuf, n_ptr, ether_proto, true))
		return NULL;

	/*
	 * Sanity checks - these should never occur.
	 *
	 * We should not receive an ICMP error for an ICMP error trigger
	 * packet, and the trigger packet IP protocol version must be the
	 * same as the error packet IP protocol version.
	 */
	if ((npc->npc_info ^ enpc.npc_info) & NPC_IP46)
		return NULL;
	if (enpc.npc_info & NPC_ICMP_ERR)
		return NULL;

	return npf_session_find_by_npc(&enpc, di, ifp, true);
}

/*
 * Note that the logic below for translating ICMP error packets intentionally
 * does not verify the ICMP checksum, as doing to would kill performance.
 *
 * So a damaged ICMP error will be forwarded to the end host, and it will
 * have to discard the packet.
 *
 * In theory if the NIC supports h/w checksum validation for ICMP errors,
 * we could take advantage of it to avoid processing such a damaged packet.
 */
static int
npf_icmpv4_err_nat(npf_cache_t *npc,
		   struct rte_mbuf **mbuf, const struct ifnet *ifp,
		   const int di)
{
	if (!npc || !di || !ifp || !(*mbuf))
		return 1;

	if (pktmbuf_prepare_for_header_change(mbuf, 0) != 0)
		return 1;

	struct rte_mbuf *m0 = *mbuf;
	struct rte_mbuf *m = m0;
	void *n_ptr = dp_pktmbuf_mtol3(m, char *) + npf_cache_hlen(npc);

	/* Find the start of the packet embedded in the ICMP error. */
	n_ptr = nbuf_advance(&m, n_ptr, ICMP_MINLEN);
	if (!n_ptr)
		return 1;

	/* Init the embedded npc. */
	npf_cache_t enpc;
	npf_cache_init(&enpc);

	/* Inspect the embedded packet. */
	if (!npf_cache_all_at(&enpc, m, n_ptr, htons(ETHER_TYPE_IPv4), true))
		return 1;

	/* Sanity checks - these should never occur */
	if (!npf_iscached(&enpc, NPC_IP4))
		return 1;
	if (enpc.npc_info & NPC_ICMP_ERR)
		return 1;

	/* Find the session for the embedded packet */
	npf_session_t *se = npf_session_find_by_npc(&enpc, di, ifp, true);
	if (!se)
		return 1;

	/*
	 * For payloads which use a pseudo header,  the final ICMP header
	 * checksum will be incorrect in that the the pseudo header has not
	 * been taken in to account as it is not present in the packet.
	 *
	 * So calculate the first half of its checksum delta - the inverse of
	 * the pre-translated source and destination address.
	 *
	 * Note that if the payload is UDP with checksum disabled, we have to
	 * use port deltas, not address deltas.
	 */
	const uint32_t embed_pre_s_a = enpc.npc_ip.v4.ip_src.s_addr;
	const uint32_t embed_pre_d_a = enpc.npc_ip.v4.ip_dst.s_addr;
	const uint16_t embed_pre_s_p = enpc.npc_l4.ports.s_port;
	const uint16_t embed_pre_d_p = enpc.npc_l4.ports.d_port;
	uint16_t icmp_cksum_delta = 0;
	bool fix_icmp_chksum32 = true;
	bool fix_icmp_chksum16 = false;

	switch (npf_cache_ipproto(&enpc)) {
	default:
		fix_icmp_chksum32 = false;
		break;
	case IPPROTO_UDP:
		if (!enpc.npc_l4.udp.check) {
			fix_icmp_chksum32 = false;
			fix_icmp_chksum16 = true;
			icmp_cksum_delta =
				ip_partial_chksum_adjust(0,
					embed_pre_s_p, ~embed_pre_d_p);
			break;
		}
		/* FALLTHRU */
	case IPPROTO_TCP:
		/* FALLTHRU */
	case IPPROTO_UDPLITE:
		/* FALLTHRU */
	case IPPROTO_DCCP:
		icmp_cksum_delta =
			ip_fixup32_cksum(0, embed_pre_s_a, ~embed_pre_d_a);
		break;
	}

	/* Is the error travelling in the session forward direction */
	bool forw = false;
	bool dnat = (di == PFIL_IN);
	npf_nat_t *nt = npf_session_retnat(se, di, &forw);

	/* Translate the embedded packet */
	int error = npf_nat_untranslate_at(&enpc, m, nt, !forw, di ^ PFIL_ALL,
					   n_ptr);
	if (error)
		return 1;

	/*
	 * With the embedded packet having now been translated,  we adjust the
	 * outer packet accordingly.
	 */
	const uint32_t *embed_src = &enpc.npc_ip.v4.ip_src.s_addr;
	const uint32_t *embed_dst = &enpc.npc_ip.v4.ip_dst.s_addr;

	npf_addr_t outer_addr;
	memcpy(&outer_addr, dnat ? embed_src : embed_dst, sizeof(uint32_t));

	n_ptr = dp_pktmbuf_mtol3(m0, void *);
	if (!npf_nat_translate_l3_at(npc, m0, n_ptr, dnat, &outer_addr))
		return 1;

	/*
	 * Cannot use deltas for the ICMP checksum for truncated
	 * ICMP error packets, so calculate it over all the data.
	 */
	if (enpc.npc_info & NPC_SHORT_ICMP_ERR) {
		char *start_icmp = dp_pktmbuf_mtol4(m, char *);

		npf_ipv4_cksum(m, IPPROTO_ICMP, start_icmp);

		npc->npc_info &= ~NPC_ICMP_ERR_NAT;

		return 0;
	}

	/*
	 * If needed, finish the calculation of the ICMP checksum delta,  then
	 * update the cache and the packet.
	 */
	if (fix_icmp_chksum32 || fix_icmp_chksum16) {
		if (fix_icmp_chksum16)
			icmp_cksum_delta =
				ip_partial_chksum_adjust(icmp_cksum_delta,
						 ~enpc.npc_l4.ports.s_port,
						  enpc.npc_l4.ports.d_port);
		else
			icmp_cksum_delta =
				ip_fixup32_cksum(icmp_cksum_delta,
						 ~*embed_src, *embed_dst);

		struct icmp *ic = &npc->npc_l4.icmp;
		uint16_t *cksum = &ic->icmp_cksum;

		*cksum = ip_fixup16_cksum(*cksum, 0, icmp_cksum_delta);

		unsigned int offby = npf_cache_hlen(npc);
		offby += offsetof(struct icmp, icmp_cksum);
		if (nbuf_advstore(&m0, &n_ptr, offby, sizeof(*cksum), cksum))
			return 1;
	}

	/*
	 * Now that this packet has been altered,  while it is still an ICMP
	 * error, it no longer matches a NAT'ed session for an ICMP error.
	 */
	npc->npc_info &= ~NPC_ICMP_ERR_NAT;

	return 0;
}

int __noinline
npf_icmp_err_nat(npf_cache_t *npc, struct rte_mbuf **nbuf,
		const struct ifnet *ifp, const int di)
{
	return npf_icmpv4_err_nat(npc, nbuf, ifp, di);
}
