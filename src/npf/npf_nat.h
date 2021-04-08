/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
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

#ifndef NPF_NAT_H
#define NPF_NAT_H

typedef struct npf_nat npf_nat_t;
typedef struct npf_natpolicy npf_natpolicy_t;

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "alg/alg_npf.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "npf/npf_apm.h"
#include "pktmbuf_internal.h"
#include "util.h"

/* Forward Declarations */
struct ifnet;
struct npf_config;
struct npf_session;
struct rte_mbuf;
struct npf_pack_nat;

typedef struct npf_cache npf_cache_t;
typedef struct npf_session npf_session_t;
typedef struct npf_rule npf_rule_t;

/* Address translation types and flags. */
#define NPF_NATIN                       1
#define NPF_NATOUT                      2

/* NAT Policy Flags */
enum {
	NPF_NAT_MASQ		= (1u <<  0),
	NPF_NAT_REVERSE		= (1u <<  1),
	NPF_NAT_CLONE_APM	= (1u <<  2),
	NPF_NAT_TABLE		= (1u <<  3),
	NPF_NAT_MAP_PORT	= (1u <<  4),
	NPF_NAT_MAP_EVEN_PORT	= (1u <<  5),
	NPF_NAT_PINHOLE		= (1u <<  6),
	NPF_NAT_OBEY_DF		= (1u <<  7),	/* npf_nat_t only */
	NPF_NAT_PA_SEQ		= (1u <<  8),	/* alloc ports sequentially */
};

/* Take reference on a NAT policy */
npf_natpolicy_t *npf_nat_policy_get(npf_natpolicy_t *np);

/* Release reference on a NAT policy */
void npf_nat_policy_put(npf_natpolicy_t *np);

uint32_t npf_nat_get_map_flags(npf_nat_t *nt);
void npf_nat_set_seq_ack(npf_session_t *se, npf_cache_t *npc,
			 int16_t diff, int di);
void npf_nat_get_original_tuple(npf_nat_t *nt, npf_cache_t *npc,
		const void **saddr, uint16_t *sid,
		const void **daddr, uint16_t *did);
int npf_create_natpolicy(npf_rule_t *rl, uint8_t type, uint32_t flags,
			 uint32_t table_id, uint8_t addr_sz, npf_addr_t *taddr,
			 npf_addr_t *taddr_stop, uint32_t match_mask,
			 in_port_t tport, in_port_t tport_stop);
uint64_t npf_natpolicy_get_map_range(const npf_natpolicy_t *np);
void npf_natpolicy_update_masq(npf_rule_t *rl, const npf_addr_t *addr);
npf_nat_t *npf_nat_custom_nat(npf_nat_t *pnat, uint32_t flags);
void npf_nat_finalise(npf_cache_t *npc, npf_session_t *se, int di,
		      npf_nat_t *nt);
int npf_nat_untranslate_at(npf_cache_t *npc, struct rte_mbuf *nbuf,
			   npf_nat_t *nt, const bool forw,
			   const int di, void *n_ptr);
int npf_local_undnat(struct rte_mbuf **m, npf_cache_t *npc, npf_session_t *se);
bool npf_nat_translate_l3_at(npf_cache_t *npc, struct rte_mbuf *mbuf,
			     void *n_ptr, bool dnat, const npf_addr_t *addr);
int nat_do_subsequent(npf_cache_t *npc, struct rte_mbuf **nbuf,
			npf_session_t *se, npf_nat_t *nt,
			const int di);
int nat_do_icmp_err(npf_cache_t *npc, struct rte_mbuf **nbuf,
		const struct ifnet *ifp, const int di);
int nat_try_initial(const struct npf_config *npf_config, npf_cache_t *npc,
		npf_session_t **se_ptr, struct rte_mbuf **nbuf,
		const struct ifnet *ifp, const int di);
void npf_nat_get_trans(const npf_nat_t *nt, npf_addr_t *addr, in_port_t *tport);
void npf_nat_get_orig(const npf_nat_t *nt, npf_addr_t *addr, in_port_t *oport);
void npf_nat_set_trans(npf_nat_t *nt, const npf_addr_t *addr, in_port_t tport);
void npf_nat_set_orig(npf_nat_t *nt, const npf_addr_t *addr, in_port_t oport);
void npf_nat_setalg(npf_nat_t *nt, struct npf_alg *alg);
const struct npf_alg *npf_nat_getalg(npf_nat_t *nt);

/* Get the NAT policy from a NAT struct.  Does *not* take a reference. */
npf_natpolicy_t *npf_nat_get_policy(const npf_nat_t *nt);

npf_rule_t *npf_nat_get_rule(const npf_nat_t *nt);
uint8_t npf_nat_type(npf_nat_t *nt);
void npf_nat_destroy(npf_nat_t *nt);
void npf_nat_expire(npf_nat_t *nt, vrfid_t vrfid);
int npf_nat_alloc_map(npf_natpolicy_t *np, npf_rule_t *rl, uint32_t map_flags,
		uint8_t ip_prot, vrfid_t vrfid, npf_addr_t *addr,
		in_port_t *port, int num);
int npf_nat_free_map(npf_natpolicy_t *np, npf_rule_t *rl, uint32_t map_flags,
		uint8_t ip_prot, vrfid_t vrfid, const npf_addr_t addr,
		in_port_t port);
bool npf_nat_info(npf_nat_t *nat, int *type, npf_addr_t *addr,
		  in_port_t *port, u_int *masq);
struct rte_mbuf *
npf_nat_clone_and_undo(struct rte_mbuf *m, const struct ifnet *in_ifp,
		       const struct ifnet *out_ifp);
struct rte_mbuf *
npf_nat_copy_and_undo(struct rte_mbuf *m, const struct ifnet *in_ifp,
		      const struct ifnet *out_ifp);
int npf_nat_npf_pack_pack(npf_nat_t *nt, struct npf_pack_nat *pnt,
			  struct sentry_packet *sp_back);
int npf_nat_npf_pack_restore(struct npf_session *se, struct npf_pack_nat *pnt,
			     struct ifnet *ifp);
#endif /* NPF_NAT_H */
