/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
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

/*
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	@(#)in.h	8.3 (Berkeley) 1/3/94
 */
#ifndef IN6_H
#define IN6_H

#include <endian.h>
#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
/*
 * Taken needed pieces from the Netbsd code.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ip.h"

struct ifnet;

#if __BYTE_ORDER == __BIG_ENDIAN
#define IPV6_FLOWINFO_MASK	0x0fffffff	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0x000fffff	/* flow label (20 bits) */
#define IPV6_TCLASS_MASK	0x0ff00000	/* traffic class (8 bits) */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define IPV6_FLOWINFO_MASK	0xffffff0f	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0xffff0f00	/* flow label (20 bits) */
#define IPV6_TCLASS_MASK	0x0000f00f	/* traffic class (8 bits) */
#else
# error	"Please include <bits/endian.h>"
#endif

/*
 * Local definition for masks
 */
#if BYTE_ORDER == BIG_ENDIAN
#define IPV6_ADDR_INT32_ONE     1
#define IPV6_ADDR_INT32_TWO     2
#define IPV6_ADDR_INT32_MNL     0xff010000
#define IPV6_ADDR_INT32_MLL     0xff020000
#define IPV6_ADDR_INT32_SMP     0x0000ffff
#define IPV6_ADDR_INT16_ULL     0xfe80
#define IPV6_ADDR_INT16_USL     0xfec0
#define IPV6_ADDR_INT16_MLL     0xff02
#elif BYTE_ORDER == LITTLE_ENDIAN
#define IPV6_ADDR_INT32_ONE     0x01000000
#define IPV6_ADDR_INT32_TWO     0x02000000
#define IPV6_ADDR_INT32_MNL     0x000001ff
#define IPV6_ADDR_INT32_MLL     0x000002ff
#define IPV6_ADDR_INT32_SMP     0xffff0000
#define IPV6_ADDR_INT16_ULL     0x80fe
#define IPV6_ADDR_INT16_USL     0xc0fe
#define IPV6_ADDR_INT16_MLL     0x02ff
#endif


/*
 * Definition of some useful macros to handle IP6 addresses
 */
#define IN6ADDR_NODELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}}

/* Scope Vlaues */
#define IPV6_ADDR_SCOPE_NODELOCAL       0x01
#define IPV6_ADDR_SCOPE_INTFACELOCAL    0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL       0x02
#define IPV6_ADDR_SCOPE_SITELOCAL       0x05
#define IPV6_ADDR_SCOPE_ORGLOCAL        0x08    /* just used in this file */
#define IPV6_ADDR_SCOPE_GLOBAL          0x0e

/*
 * Multicast
 */
#define IPV6_ADDR_MC_SCOPE(a)           ((a)->s6_addr[1] & 0x0f)

#define IN6_IS_ADDR_MC_INTFACELOCAL(a)  \
	(IN6_IS_ADDR_MULTICAST(a) &&    \
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_INTFACELOCAL))

#define IN6_IS_SCOPE_LINKLOCAL(a)       \
	((IN6_IS_ADDR_LINKLOCAL(a)) ||  \
	 (IN6_IS_ADDR_MC_LINKLOCAL(a)))

#define IN6_IS_SCOPE_EMBEDDABLE(__a)    \
    (IN6_IS_SCOPE_LINKLOCAL(__a) || IN6_IS_ADDR_MC_INTFACELOCAL(__a))

#define IFA6_IS_DEPRECATED(a) \
	((a)->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_second - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_pltime)
#define IFA6_IS_INVALID(a) \
	((a)->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_second - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_vltime)

/* Missing from glibc's netinet/icmp6.h */
#ifndef MLDV2_LISTENER_REPORT
#define MLDV2_LISTENER_REPORT 143
#endif

/*
 * Check if the 64-bit interface identifier of an address is zero. Used as a
 * partial check for a subnet-router anycast address: RFC4291 2.6.1 does not
 * specify the length of the subnet prefix (followed by an interface id set to
 * zero), but industry convention is that the length is 64 bits. If only anycast
 * address is needed, caller must check for other cases e.g. unspecified address
 */
static inline bool in6_is_addr_id_zero(const struct in6_addr *addr)
{
	return ((const uint64_t *)(addr))[1] == 0;
}

static inline void *ip6_exthdr(struct rte_mbuf *m, uint16_t offs, size_t len)
{
	if (offs + len > rte_pktmbuf_data_len(m))
		return NULL; /* outside received buffer */

	return rte_pktmbuf_mtod(m, char *) + offs;
}

struct if_addr *in6ifa_ifplocaladdr(const struct ifnet *ifp, const struct in6_addr *addr);
struct if_addr *in6_ifawithifp(struct ifnet *ifp, struct in6_addr *dst);
struct lltable *in6_domifattach(struct ifnet *ifp);
uint32_t in6_addr_hash(const void *key, uint32_t key_len, uint32_t init_val);
uint16_t ip6_findprevoff(struct rte_mbuf *m);
uint16_t ip6_findpayload(struct rte_mbuf *m, uint16_t *offset);

#endif /* IN6_H */
