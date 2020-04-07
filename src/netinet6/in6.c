/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */
/*	$NetBSD: in6.c,v 1.141 2008/07/31 18:24:07 matt Exp $	*/
/*	$KAME: in6.c,v 1.198 2001/07/18 09:12:38 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_timer.h>
#include <stdbool.h>
/*
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in.c	8.2 (Berkeley) 11/15/93
 */
#include <stdio.h>
#include <sys/socket.h>
#include <urcu/list.h>

#include "if_ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "in6.h"
#include "in6_var.h"
#include "ip6_funcs.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pktmbuf_internal.h"
#include "pl_node.h"
#include "urcu.h"

/*
 * Definitions of some constant IP6 addresses.
 */
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;

/*
 * find the internet address corresponding to a given interface and address.
 */
struct if_addr *
in6ifa_ifpwithaddr(const struct ifnet *ifp, const struct in6_addr *addr)
{
	struct if_addr *ifa;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;

		if (sa->sa_family != AF_INET6)
			continue;
		if (IN6_ARE_ADDR_EQUAL(addr, IFA_IN6(ifa)))
			return ifa;
	}

	return NULL;
}

/* Prefix length to mask */
void
in6_prefixlen2mask(struct in6_addr *maskp, uint len)
{
	static const u_char maskarray[8] = {0x80, 0xc0, 0xe0, 0xf0,
					    0xf8, 0xfc, 0xfe, 0xff};
	uint bytelen, bitlen, i;

	/* sanity check */
	if (len > 128)
		return;

	memset(maskp, 0, sizeof(*maskp));
	bytelen = len >> 3;
	bitlen = len & 0x7;
	for (i = 0; i < bytelen; i++)
		maskp->s6_addr[i] = 0xff;
	if (bitlen)
		maskp->s6_addr[bytelen] = maskarray[bitlen - 1];
}

/*
 * find the internet address on a given interface corresponding to a neighbor's
 * address.
 */
struct if_addr *
in6ifa_ifplocaladdr(const struct ifnet *ifp, const struct in6_addr *addr)
{
	struct if_addr *ifa;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;

		if (sa->sa_family != AF_INET6)
			continue;

		struct sockaddr_in6 *sin6 = satosin6(sa);
		if (dp_in6_prefix_eq(addr, &sin6->sin6_addr,
				     ifa->ifa_prefixlen))
			return ifa;
	}

	return NULL;
}

/*
 * Find an IPv6 interface link-local address specific to an interface.
 * ifaddr is returned referenced.
 */
struct if_addr *
in6ifa_ifpforlinklocal(const struct ifnet *ifp)
{
	struct if_addr *ifa;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;

		if (sa->sa_family != AF_INET6)
			continue;

		if (IN6_IS_ADDR_LINKLOCAL(IFA_IN6(ifa)))
			return ifa;

	}

	return NULL;
}


/*
 * Convert IP6 address to printable (loggable) representation.
 */
const char *
ip6_sprintf(const struct in6_addr *addr)
{
	static char buf[INET6_ADDRSTRLEN];

	return inet_ntop(AF_INET6, addr, buf, sizeof(buf));
}

struct lltable *
in6_domifattach(struct ifnet *ifp)
{
	struct lltable *llt;

	llt = lltable_new(ifp);

	llt->lle_refresh_expire = rte_get_timer_cycles() + rte_get_timer_hz();
	rte_timer_reset(&llt->lle_timer, rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(),
			in6_lladdr_timer, llt);
	pl_node_add_feature_by_inst(
		&ipv6_in_no_address_feat, ifp);

	return llt;
}

/* Version of murmur hash optimized for IPv6 addresses */
uint32_t in6_addr_hash(const void *key, uint32_t key_len __rte_unused,
		       uint32_t seed)
{
	const uint64_t *data = (const uint64_t *)key;
	const uint64_t m = 0xc6a4a7935bd1e995ull;
	const int r = 47;
	uint64_t h = seed ^ (16 * m);
	uint64_t k;

	k = data[0];
	k *= m;
	k ^= k >> r;
	k *= m;
	h ^= k;
	h *= m;

	k = data[1];
	k *= m;
	k ^= k >> r;
	k *= m;
	h ^= k;
	h *= m;

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}
/*
 * Find the offset (relative to start of ipv6 header)
 * of the "next_proto" field prior to the payload
 */
uint16_t ip6_findprevoff(struct rte_mbuf *m)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct ip6_ext *ip6e;
	struct ip6_frag *fh;
	uint16_t off = sizeof(*ip6);
	uint16_t prev_off = offsetof(struct ip6_hdr, ip6_nxt);
	uint16_t proto = ip6->ip6_nxt;

	for (;;) {
		switch (proto) {
		case IPPROTO_IPV6:
			prev_off = off + offsetof(struct ip6_hdr, ip6_nxt);
			ip6 = ip6_exthdr(m, off, sizeof(*ip6));
			if (!ip6)
				goto bad;
			off += sizeof(*ip6);
			proto = ip6->ip6_nxt;
			break;
		case IPPROTO_AH:
			prev_off = off;
			ip6e = ip6_exthdr(m, off, sizeof(*ip6e));
			if (!ip6e)
				goto bad;
			off += (ip6e->ip6e_len + 2) << 2;
			proto = ip6e->ip6e_nxt;
			break;
		case IPPROTO_FRAGMENT:
			prev_off = off;
			fh = ip6_exthdr(m, off, sizeof(*fh));
			if (!fh)
				goto bad;

			/* if looking at the 2nd or more fragment, stop */
			if (fh->ip6f_offlg & IP6F_OFF_MASK)
				return prev_off;

			off += sizeof(*fh);
			proto = fh->ip6f_nxt;
			break;
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			prev_off = off;
			ip6e = ip6_exthdr(m, off, sizeof(*ip6e));
			if (!ip6e)
				goto bad;
			off += (ip6e->ip6e_len + 1) << 3;
			proto = ip6e->ip6e_nxt;
			break;
		default:
			return prev_off;
		}
	}
bad:
	return 0;
}

/* Chase through the headers, jumping over extension headers */
uint16_t ip6_findpayload(struct rte_mbuf *m, uint16_t *offset)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct ip6_ext *ip6e;
	struct ip6_frag *fh;

	uint16_t off = dp_pktmbuf_l2_len(m) + sizeof(*ip6);
	uint16_t proto = ip6->ip6_nxt;

	for (;;) {
		switch (proto) {
		case IPPROTO_IPV6:
			ip6 = ip6_exthdr(m, off, sizeof(*ip6));
			if (!ip6)
				goto bad;
			off += sizeof(*ip6);
			proto = ip6->ip6_nxt;
			break;
		case IPPROTO_AH:
			ip6e = ip6_exthdr(m, off, sizeof(*ip6e));
			if (!ip6e)
				goto bad;
			off += (ip6e->ip6e_len + 2) << 2;
			proto = ip6e->ip6e_nxt;
			break;
		case IPPROTO_FRAGMENT:
			fh = ip6_exthdr(m, off, sizeof(*fh));
			if (!fh)
				goto bad;

			/* if looking at the 2nd or more fragment, stop */
			if (fh->ip6f_offlg & IP6F_OFF_MASK) {
				if (offset)
					*offset = off;
				return proto;
			}
			off += sizeof(*fh);
			proto = fh->ip6f_nxt;
			break;
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			ip6e = ip6_exthdr(m, off, sizeof(*ip6e));
			if (!ip6e)
				goto bad;
			off += (ip6e->ip6e_len + 1) << 3;
			proto = ip6e->ip6e_nxt;
			break;
		default:
			if (offset)
				*offset = off;
			return proto;
		}
	}

bad:
	return IPPROTO_MAX;
}
