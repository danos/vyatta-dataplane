/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 * Copyright (c) 2017, AT&T Intellectual Property.  All rights reserved.
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
 * Copyright (c) 1982, 1986, 1988, 1993
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
 */

#include <linux/snmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <rte_mbuf.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "if_var.h"
#include "ip6_funcs.h"
#include "pktmbuf.h"
#include "snmp_mib.h"

/*
 * Unknown option processing.
 * The third argument `off' is the offset from the IPv6 header to the option,
 * which is necessary if the IPv6 header the and option header and IPv6 header
 * is not continuous in order to return an ICMPv6 error.
 */
static int __attribute__((cold))
ip6_unknown_opt(uint8_t *optp, struct rte_mbuf *m, struct ifnet *iif, int off)
{
	struct ip6_hdr *ip6;

	switch (IP6OPT_TYPE(*optp)) {
	case IP6OPT_TYPE_SKIP: /* ignore the option */
		return *(optp + 1);
	case IP6OPT_TYPE_DISCARD:	/* silently discard */
		break;
	case IP6OPT_TYPE_FORCEICMP: /* send ICMP even if multicasted */
		IP6STAT_INC(if_vrfid(iif), IPSTATS_MIB_INHDRERRORS);
		icmp6_error(iif, m, ICMP6_PARAM_PROB,
			    ICMP6_PARAMPROB_OPTION, htonl(off));
		return -1;
	case IP6OPT_TYPE_ICMP: /* send ICMP if not multicasted */
		IP6STAT_INC(if_vrfid(iif), IPSTATS_MIB_INHDRERRORS);
		ip6 = ip6hdr(m);
		if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
			rte_pktmbuf_free(m);
		else
			icmp6_error(iif, m, ICMP6_PARAM_PROB,
				    ICMP6_PARAMPROB_OPTION, htonl(off));
		return -1;
	}

	rte_pktmbuf_free(m);
	return -1;
}

/*
 * Search header for all Hop-by-hop options and process each option.
 * This function is separate from ip6_hopopts_input() in order to
 * handle a case where the sending node itself process its hop-by-hop
 * options header. In such a case, the function is called from ip6_output().
 *
 * The function assumes that hbh header is located right after the IPv6 header
 * (RFC2460 p7), opthead is pointer into data content in m, and opthead to
 * opthead + hbhlen is located in continuous memory region.
 */
static int
ip6_process_hopopts(struct rte_mbuf *m, struct ifnet *iif,
		    uint8_t *opthead, int hbhlen, uint32_t *rtalertp)
{
	int optlen = 0;
	u_int8_t *opt = opthead;
	uint16_t rtalert_val;
	const int erroff = sizeof(struct ip6_hdr) + sizeof(struct ip6_hbh);

	for (; hbhlen > 0; hbhlen -= optlen, opt += optlen) {
		switch (*opt) {
		case IP6OPT_PAD1:
			optlen = 1;
			break;
		case IP6OPT_PADN:
			if (hbhlen < (int)sizeof(struct ip6_opt)) {
				IP6STAT_INC(if_vrfid(iif),
					    IPSTATS_MIB_INHDRERRORS);
				goto bad;
			}
			optlen = *(opt + 1) + sizeof(struct ip6_opt);
			if (hbhlen < optlen) {
				IP6STAT_INC(if_vrfid(iif),
					    IPSTATS_MIB_INHDRERRORS);
				goto bad;
			}
			break;
		case IP6OPT_ROUTER_ALERT:
			if (hbhlen < (int)sizeof(struct ip6_opt_router)) {
				IP6STAT_INC(if_vrfid(iif),
					    IPSTATS_MIB_INHDRERRORS);
				goto bad;
			}
			if (*(opt + 1) != sizeof(struct ip6_opt_router) - 2) {
				IP6STAT_INC(if_vrfid(iif),
					    IPSTATS_MIB_INHDRERRORS);
				icmp6_error(iif, m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    htonl(erroff + opt + 1 - opthead));
				return -1;
			}
			optlen = sizeof(struct ip6_opt_router);
			memcpy(&rtalert_val, opt + 2, 2);
			*rtalertp = ntohs(rtalert_val);
			break;
		default:		/* unknown option */
			if (hbhlen < (int)sizeof(struct ip6_opt)) {
				IP6STAT_INC(if_vrfid(iif),
					    IPSTATS_MIB_INHDRERRORS);
				goto bad;
			}
			optlen = ip6_unknown_opt(opt, m, iif,
			    erroff + opt - opthead);
			if (optlen == -1)
				return -1;
			optlen += 2;
			break;
		}
	}

	return 0;

bad:
	rte_pktmbuf_free(m);
	return -1;
}

/*
 * Hop-by-Hop options header processing
 * Return zero on success, non-zero on failure in which case packet was consumed
 */
int
ip6_hopopts_input(struct rte_mbuf *m, struct ifnet *iif, uint32_t *rtalertp)
{
	unsigned int l3_data_len, hbhlen;
	struct ip6_hbh *hbh;

	/* validation of the length of the header */
	l3_data_len = rte_pktmbuf_data_len(m) - pktmbuf_l2_len(m);
	if (l3_data_len - sizeof(struct ip6_hdr) < sizeof(*hbh)) {
		IP6STAT_INC(if_vrfid(iif), IPSTATS_MIB_INHDRERRORS);
		rte_pktmbuf_free(m);
		return -1;
	}
	hbh = (struct ip6_hbh *)(ip6hdr(m) + 1);
	hbhlen = (hbh->ip6h_len + 1) * 8;
	if (l3_data_len - sizeof(struct ip6_hdr) < hbhlen) {
		IP6STAT_INC(if_vrfid(iif), IPSTATS_MIB_INHDRERRORS);
		rte_pktmbuf_free(m);
		return -1;
	}
	hbhlen -= sizeof(struct ip6_hbh);

	if (ip6_process_hopopts(m, iif,
				(uint8_t *)hbh + sizeof(struct ip6_hbh),
				hbhlen, rtalertp) < 0)
		return -1;

	return 0;
}
