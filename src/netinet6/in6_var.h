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

/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 1985, 1986, 1993
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
 *	@(#)in_var.h	8.1 (Berkeley) 6/10/93
 */

#ifndef IN6_VAR_H
#define IN6_VAR_H
#include <netinet/ip6.h>

/*
 * Given a pointer to an in6_ifaddr (ifaddr),
 * return a pointer to the addr as a sockaddr_in6
 */
//#define IA6_IN6(ia)     (&((ia)->ifa_addr.sin6_addr))
//#define IA6_DSTIN6(ia)  (&((ia)->ia_dstaddr.sin6_addr))
//#define IA6_MASKIN6(ia) (&((ia)->ia_prefixmask.sin6_addr))
//#define IA6_SIN6(ia)    (&((ia)->ia_addr))
//#define IA6_DSTSIN6(ia) (&((ia)->ia_dstaddr))
#define IFA_ADDR6(x)      (&((struct sockaddr_in6 *)(&(x)->ifa_addr))->sin6_addr)
#define IFA_IN6(x)      (&((struct sockaddr_in6 *)(&(x)->ifa_addr))->sin6_addr)
#define IFA_DSTIN6(x)   (&((struct sockaddr_in6 *)((x)->ifa_dstaddr))->sin6_addr)


#define IN6_IFF_ANYCAST         0x01    /* anycast address */
#define IN6_IFF_TENTATIVE       0x02    /* tentative address */
#define IN6_IFF_DUPLICATED      0x04    /* DAD detected duplicate */
#define IN6_IFF_DETACHED        0x08    /* may be detached from the link */
#define IN6_IFF_DEPRECATED      0x10    /* deprecated address */
#define IN6_IFF_NODAD           0x20    /* don't perform DAD on this address
					 * (used only at first SIOC* call)
					 */
#define IN6_IFF_AUTOCONF        0x40    /* autoconfigurable address. */
#define IN6_IFF_TEMPORARY       0x80    /* temporary (anonymous) address. */

/* fast IPv6 prefix copy */
static inline void in6_prefix_cpy(struct in6_addr *dest,
				  const struct in6_addr *src,
				  uint prefix_len)
{
	const uint32_t *s = src->s6_addr32;
	uint32_t *d = dest->s6_addr32;

	while (prefix_len >= 32) {
		*d++ = *s++;
		prefix_len -= 32;
	}

	if (likely(prefix_len == 0))
		return;

	uint32_t m = htonl(~0ul << (32 - prefix_len));

	*d = (*s & m) | (*d & ~m);
}


int in6_setscope(struct in6_addr *in6,
			const struct ifnet *ifp, uint32_t *ret_id);
int in6_addrscope(const struct in6_addr *addr);
const char *ip6_sprintf(const struct in6_addr *addr);
struct if_addr *in6ifa_ifpwithaddr(const struct ifnet *ifp,
					  const struct in6_addr *addr);
struct if_addr *in6ifa_ifpforlinklocal(const struct ifnet *ifp);
void in6_prefixlen2mask(struct in6_addr *maskp, uint len);
int ip6_forwarding_enabled(const struct ifnet *ifp);

#endif /* IN6_VAR_H */
