/*
 * Copyright (c) 2017,2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.
 * Copyright (c) 2005 Andre Oppermann, Internet Business Solutions AG.
 * All rights reserved.
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
 * 4. Neither the name of the University nor the names of its contributors
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

#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>

#include "ip_funcs.h"
#include "ip_options.h"

struct rte_mbuf;

/*
 * Do option validation on a datagram
 *
 * Returns 1 if packet should be freed, 0 if the packet should be
 * processed further.
 *
 * Vyatta changes:
 *  - never send icmp for bad options
 *  - drop packets with some options per Draft RFC
 *     "IP Options Filtering Recommendtions"
 *  - handle router alert
 */
int ip_dooptions(struct rte_mbuf *m, bool *ra_present)
{
	const struct iphdr *ip = iphdr(m);
	const uint8_t *cp = (const uint8_t *)(ip + 1);
	unsigned int optlen, cnt;

	cnt = (ip->ihl << 2) - sizeof(struct ip);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		uint8_t opt = cp[IPOPT_OPTVAL];

		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < IPOPT_OLEN + sizeof(*cp))
				goto bad;

			optlen = cp[IPOPT_OLEN];
			if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt)
				goto bad;
		}

		switch (opt) {
		case IPOPT_LSRR:
		case IPOPT_SSRR:
		case IPOPT_RR:
			/* per RFC 7126 "Recommendations on Filtering
			 * of IPv4 Packets Containing IPv4 Options"
			 * advice:
			 * All systems should by defalut drop IP packets
			 * containing these options.
			 */
			goto drop;

		case IPOPT_RA:
			/*
			 * RFC 2113: Routers that recognize this
			 * option shall examine packets carrying it
			 * more closely.
			 *
			 */
			if (optlen != 4)
				goto bad;

			*ra_present = true;
			break;
		}
	}

	return 0;
 bad:
	/* Don't send icmp because of potential denial-of-service */
 drop:
	return 1;
}
