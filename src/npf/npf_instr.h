/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*
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

#ifndef NPF_INSTR_H
#define NPF_INSTR_H

#include <stdint.h>
#include <sys/types.h>

#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "pktmbuf.h"

struct rte_mbuf;

/* Forward Declarations */
typedef struct npf_session npf_session_t;
typedef struct npf_cache npf_cache_t;
typedef struct npf_rule npf_rule_t;

int npf_match_mac(const struct rte_mbuf *nbuf, uint32_t opts, const char *filt);
int npf_match_proto(const npf_cache_t *npc, uint32_t ap);
int npf_match_pcp(const struct rte_mbuf *nbuf, uint32_t pcp);
int npf_match_table(const npf_cache_t *npc, uint32_t opts, const u_int tid);
int npf_match_ip_fam(const npf_cache_t *npc, uint32_t fam);
int npf_match_ip_frag(const npf_cache_t *npc);
int npf_match_ip4mask(const npf_cache_t *npc, uint32_t opts,
		      uint32_t maddr, npf_netmask_t mask_len);
int npf_match_ip6mask(const npf_cache_t *npc, uint32_t opts,
		      const npf_addr_t *maddr, npf_netmask_t mask_len);
int npf_match_ports(const npf_cache_t *npc, uint32_t opts, uint32_t prange);
int npf_match_ttl(const npf_cache_t *npc, uint32_t value);
int npf_match_icmp4(const npf_cache_t *npc, uint32_t tc);
int npf_match_ip6_rt(const npf_cache_t *npc, uint32_t type);
int npf_match_icmp6(const npf_cache_t *npc, uint32_t tc);
int npf_match_tcpfl(const npf_cache_t *npc, uint32_t fl);
int npf_match_dscp(const npf_cache_t *npc, const uint64_t n);
int npf_match_etype(const struct rte_mbuf *nbuf, uint32_t etype);
struct ifnet;

int npf_match_rproc(npf_cache_t *npc, struct rte_mbuf *nbuf,
		    const npf_rule_t *rl, const struct ifnet *ifp,
		    int dir, npf_session_t *se);

#endif /* NPF_INSTR_H */
