/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_instr.c,v 1.14 2012/07/19 21:52:29 spz Exp $	*/

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

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#include "ether.h"
#include "npf/npf.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_cache.h"
#include "npf/npf_instr.h"
#include "npf/npf_ncode.h"
#include "npf/npf_ruleset.h"

#define NPF_PORTRANGE_MATCH(r, p) (p >= (r >> 16) && p <= (r & 0xffff))


/*
 * npf_match_mac: match mac address length and/or layer 4 protocol.
 */
int
npf_match_mac(const struct rte_mbuf *nbuf, uint32_t opts, const char *filt)
{
	const struct rte_ether_hdr *eh =
				rte_pktmbuf_mtod(nbuf, struct rte_ether_hdr *);
	const struct rte_ether_addr *addr;

	addr = (opts & NC_MATCH_SRC) ? &eh->s_addr : &eh->d_addr;

	return rte_ether_addr_equal(addr,
				    (struct rte_ether_addr *)filt) ? 0 : -1;
}

/*
 * npf_match_proto: match layer 4 protocol.
 */
int
npf_match_proto(const npf_cache_t *npc, uint32_t ap)
{
	const int proto = ap & 0xff;

	if (!npf_iscached(npc, NPC_IP46))
		return -1;

	return (npf_cache_ipproto(npc) != proto) ? -1 : 0;
}

/*
 * npf_match_pcp: match class of service in 802.1q frame
 */
int
npf_match_pcp(const struct rte_mbuf *nbuf, uint32_t pcp)
{
	return pcp == pktmbuf_get_vlan_pcp(nbuf) ? 0 : -1;
}

/*
 * npf_match_table: match IP address against NPF table.  Returns 0 for match.
 */
int
npf_match_table(const npf_cache_t *npc,	uint32_t opts, const u_int tid)
{
	npf_addr_t *addr;

	if (opts & NC_MATCH_SRC)
		addr = npf_cache_srcip(npc);
	else
		addr = npf_cache_dstip(npc);

	if (npf_iscached(npc, NPC_IP4))
		return npf_addrgrp_lookup(AG_IPv4, tid, addr);
	else if (npf_iscached(npc, NPC_IP6))
		return npf_addrgrp_lookup(AG_IPv6, tid, addr);

	return -1;
}

int
npf_match_ip_fam(const npf_cache_t *npc, uint32_t fam)
{
	if (fam == AF_INET && npf_iscached(npc, NPC_IP4))
		return 0;
	else if (fam == AF_INET6 && npf_iscached(npc, NPC_IP6))
		return 0;
	return -1;
}

int
npf_match_ip_frag(const npf_cache_t *npc)
{
	if (npf_iscached(npc, NPC_IPFRAG))
		return 0;
	return -1;
}

/*
 * npf_match_ip4mask: match an IPv4 address against netaddr/mask.
 */
int
npf_match_ip4mask(const npf_cache_t *npc, uint32_t opts,
		  uint32_t maddr, npf_netmask_t mask_len)
{
	/* already attempted at beginning of hook */
	if (unlikely(!npf_iscached(npc, NPC_IP4)))
		return -1;

	uint32_t addr, mask;
	bool match;

	if (opts & NC_MATCH_SRC)
		addr = *(uint32_t *)npf_cache_v4src(npc);
	else
		addr = *(uint32_t *)npf_cache_v4dst(npc);

	mask = htonl(npf_prefix_to_net_mask4(mask_len));
	match = (addr & mask) == (maddr & mask);

	return (match ^ NCODE_IS_INVERTED(opts)) ? 0 : -1;
}

/*
 * npf_match_ip6mask: match an IPv6 address against netaddr/mask.
 */
int
npf_match_ip6mask(const npf_cache_t *npc, uint32_t opts,
		  const npf_addr_t *maddr, npf_netmask_t mask_len)
{
	/* already attempted at beginning of hook */
	if (unlikely(!npf_iscached(npc, NPC_IP6)))
		return -1;

	uint64_t word1, word2, mask;
	npf_addr_t *addr;
	uint hpfx, lpfx;
	bool match;

	if (opts & NC_MATCH_SRC)
		addr = npf_cache_v6src(npc);
	else
		addr = npf_cache_v6dst(npc);

	/* Determine high-order prefix and low-order prefix lengths */
	if (mask_len >= 64) {
		if (mask_len > 128)
			mask_len = 128;
		hpfx = 64;
		lpfx = mask_len - 64;
	} else {
		hpfx = mask_len; /* never zero */
		lpfx = 0;
	}

	/* first 64-bit word */
	mask = htobe64((0xfffffffffffffffful << (64 - hpfx)));
	word1 = ((uint64_t *)addr)[0];
	word2 = ((uint64_t *)maddr)[0];

	match = (word1 & mask) == (word2 & mask);

	/* second 64-bit word */
	if (match && lpfx > 0) {
		mask = htobe64((0xfffffffffffffffful << (64 - lpfx)));
		word1 = ((uint64_t *)addr)[1];
		word2 = ((uint64_t *)maddr)[1];

		match = (word1 & mask) == (word2 & mask);
	}

	return (match ^ NCODE_IS_INVERTED(opts)) ? 0 : -1;
}

/*
 * Match TCP/UDP/UDP-Lite/DCCP/SCTP port in header against the range.
 */
int
npf_match_ports(const npf_cache_t *npc, uint32_t opts, uint32_t prange)
{
	const struct npf_ports *l4 = &npc->npc_l4.ports;
	in_port_t p;
	bool match;

	if (unlikely(!npf_iscached(npc, NPC_L4PORTS)))
		return -1;

	p = (opts & NC_MATCH_SRC) ? l4->s_port : l4->d_port;

	/* Match against the port range. */
	match = NPF_PORTRANGE_MATCH(prange, ntohs(p));

	return (match ^ NCODE_IS_INVERTED(opts)) ? 0 : -1;
}

int
npf_match_ttl(const npf_cache_t *npc, uint32_t value)
{
	uint8_t ttl = 0;

	if (likely(npf_iscached(npc, NPC_IP4))) {
		const struct ip *ip = &npc->npc_ip.v4;
		ttl = ip->ip_ttl;
	} else if (npf_iscached(npc, NPC_IP6)) {
		const struct ip6_hdr *ip6 = &npc->npc_ip.v6;
		ttl = ip6->ip6_hlim;
	} else
		return -1;

	if (ttl == value)
		return 0;
	return -1;
}

/*
 * npf_match_icmp4: match ICMPv4 packet.
 */
int
npf_match_icmp4(const npf_cache_t *npc, uint32_t tc)
{
	const struct icmp *ic = &npc->npc_l4.icmp;

	/* We'll only cache ICMPv4 within an IPv4 packet */
	if (unlikely(npf_cache_ipproto(npc) != IPPROTO_ICMP))
		return -1;

	/* Match type class, if required. */
	if (tc & NC_ICMP_HAS_CLASS) {
		const bool error = NC_ICMP_GET_TYPE_FROM_OP(tc);
		if (npf_iscached(npc, NPC_ICMP_ERR) != error)
			return -1;
		return 0;
	}

	/* Match code/type, if required. */
	if (tc & NC_ICMP_HAS_TYPE) {
		const uint8_t type = NC_ICMP_GET_TYPE_FROM_OP(tc);
		if (type != ic->icmp_type)
			return -1;
	}
	if (tc & NC_ICMP_HAS_CODE) {
		const uint8_t code = NC_ICMP_GET_CODE_FROM_OP(tc);
		if (code != ic->icmp_code)
			return -1;
	}
	return 0;
}

/*
 * npf_match_icmp6: match ICMPv6 routing packet.
 */
int
npf_match_ip6_rt(const npf_cache_t *npc, uint32_t type)
{
	if (!npf_iscached(npc, NPC_IPV6_ROUTING))
		return -1;

	return type == npc->npc_ipv6_routing_type ? 0 : -1;
}

/*
 * npf_match_icmp6: match ICMPv6 packet.
 */
int
npf_match_icmp6(const npf_cache_t *npc, uint32_t tc)
{
	const struct icmp6_hdr *ic6 = &npc->npc_l4.icmp6;

	/* We'll only cache ICMPv6 within an IPv6 packet */
	if (unlikely(npf_cache_ipproto(npc) != IPPROTO_ICMPV6))
		return -1;

	/* Match type class, if required. */
	if (tc & NC_ICMP_HAS_CLASS) {
		const bool error = NC_ICMP_GET_TYPE_FROM_OP(tc);
		if (npf_iscached(npc, NPC_ICMP_ERR) != error)
			return -1;
		return 0;
	}

	/* Match code/type, if required. */
	if (tc & NC_ICMP_HAS_TYPE) {
		const uint8_t type = NC_ICMP_GET_TYPE_FROM_OP(tc);
		if (type != ic6->icmp6_type)
			return -1;
	}
	if (tc & NC_ICMP_HAS_CODE) {
		const uint8_t code = NC_ICMP_GET_CODE_FROM_OP(tc);
		if (code != ic6->icmp6_code)
			return -1;
	}
	return 0;
}

/*
 * npf_match_tcpfl: match TCP flags.
 */
int
npf_match_tcpfl(const npf_cache_t *npc, uint32_t fl)
{
	const uint8_t tcpfl = (fl >> 8) & 0xff, mask = fl & 0xff;
	const struct tcphdr *th = &npc->npc_l4.tcp;

	if (unlikely(!npf_iscached(npc, NPC_IP46)))
		return -1;

	/* already attempted at beginning of hook */
	if (unlikely(npf_cache_ipproto(npc) != IPPROTO_TCP))
		return -1;

	return ((th->th_flags & mask) == tcpfl) ? 0 : -1;
}

int
npf_match_dscp(const npf_cache_t *npc, const uint64_t set)
{
	uint8_t dscp = 0;
	uint32_t flow;

	if (likely(npf_iscached(npc, NPC_IP4))) {
		const struct ip *ip = &npc->npc_ip.v4;
		dscp = ip->ip_tos >> 2;
	} else if (npf_iscached(npc, NPC_IP6)) {
		const struct ip6_hdr *ip6 = &npc->npc_ip.v6;
		flow = ntohl(ip6->ip6_flow);
		dscp = (flow & 0x0FC00000) >> 22;
	}
	if (dscp <= DSCP_MAX && ((1ul << dscp) & set))
		return 0;
	return -1;
}

/*
 *  npf_match_etype: match ethertype
 */
int
npf_match_etype(const struct rte_mbuf *nbuf, uint32_t etype)
{
	uint16_t ether_type = ethtype(nbuf, RTE_ETHER_TYPE_VLAN);

	if (ether_type != etype)
		return -1;
	return 0;
}

/*
 *  npf_match_rproc: match rproc
 */
int
npf_match_rproc(npf_cache_t *npc, struct rte_mbuf *nbuf, const npf_rule_t *rl,
		const struct ifnet *ifp, int dir, npf_session_t *se)
{
	/*
	 * Dispatch to all match functions in the rprocs for this
	 * rule. If not match return -1, or match return 0
	 */
	if (!npf_rproc_match(npc, nbuf, rl, ifp, dir, se))
		return -1;

	return 0;
}
