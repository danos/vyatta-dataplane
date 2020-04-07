/*
 * Copyright (c) 1980, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)route.h	8.5 (Berkeley) 2/8/95
 */

/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 */
#ifndef ROUTE_FLAGS_H
#define ROUTE_FLAGS_H

#define	RTF_GATEWAY	0x1	/* destination is a gateway */
#define	RTF_REJECT	0x2	/* host or net unreachable */

#define RTF_DEAD	0x4	/* nexthop is down */
#define RTF_MAPPED_IPV6	0x8	/* nexthop is ipv4 mapped ipv6 */

#define RTF_SLOWPATH	0x10	/* route target is off dataplane */

#define RTF_BLACKHOLE	0x20	/* just discard pkts (during updates) */
#define RTF_LOCAL	0x40  /* local route */
#define	RTF_BROADCAST	0x80	/* route represents a bcast address */
#define	RTF_MULTICAST	0x100	/* route represents a mcast address */
#define	RTF_OUTLABEL	0x200	/* output label rather than local label */
#define	RTF_NOROUTE	0x400	/* trigger no-route behaviour */

#define RTF_NEIGH_CREATED  0x10000 /* Nexthop was created to store neigh info */
#define RTF_NEIGH_PRESENT  0x20000 /* Nexthop contains neigh info */

/*
 * When comparing NHs for equality, mask the flags as the NEIGH_ ones are
 * local optimisations.
 */
#define NH_FLAGS_CMP_MASK ~(RTF_NEIGH_CREATED | RTF_NEIGH_PRESENT)

enum rt_print_nexthop_verbosity {
	RT_PRINT_NH_BRIEF,
	RT_PRINT_NH_DETAIL,
};

#endif /* ROUTE_FLAGS_H */
