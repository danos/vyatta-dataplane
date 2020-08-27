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

#ifndef NPF_SESSION_H
#define NPF_SESSION_H

typedef struct npf_session	npf_session_t;

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "util.h"
#include "session/session.h"
#include "session/session_feature.h"

#include "npf/npf.h"

struct npf_alg;
struct npf_session;
struct rte_mbuf;
struct npf_pack_npf_session;
struct npf_pack_session_state;

/* Forward Declarations */
typedef struct npf_rule npf_rule_t;
typedef struct npf_nat npf_nat_t;
typedef struct npf_natpolicy npf_natpolicy_t;
typedef struct npf_cache npf_cache_t;
struct ifnet;
struct npf_if;
struct npf_nat64;

typedef bool session_pkt_hook(npf_session_t *se, npf_cache_t *npc,
			      struct rte_mbuf *mbuf, int di);

/*
 * Get the dataplane session ID given an npf session.  If se or se->s_session
 * are NULL then 0 is returned.
 */
uint64_t npf_session_get_id(struct npf_session *se);

void npf_session_add_fw_rule(npf_session_t *s, npf_rule_t *r);
bool npf_session_is_fw(npf_session_t *s);

/* Appfw */
void npf_session_set_appfw_decision(npf_session_t *, npf_decision_t);
npf_decision_t npf_session_get_appfw_decision(npf_session_t *);

/* ALG-related */
struct npf_session_alg *npf_session_get_alg_ptr(const npf_session_t *se);
void npf_session_set_alg_ptr(npf_session_t *se, struct npf_session_alg *sa);
bool npf_session_uses_alg(npf_session_t *se);

uint32_t npf_session_get_if_index(npf_session_t *se);
void npf_session_link_child(struct npf_session *parent, struct npf_session *c);
struct npf_session *npf_session_get_parent(const struct npf_session *se);
const struct npf_session *npf_session_get_base_parent(
		const struct npf_session *se);
npf_session_t *npf_session_find_cached(struct rte_mbuf *mbuf);
npf_session_t *npf_session_inspect(npf_cache_t *npc, struct rte_mbuf *nbuf,
		const struct ifnet *ifp, const int di, int *error,
		bool *internal_hairpin);
npf_session_t *npf_session_inspect_or_create(npf_cache_t *npc,
		struct rte_mbuf *nbuf, const struct ifnet *ifp,
		const int di, uint16_t *npf_flag, int *error,
		bool *internal_hairpin);
npf_session_t *npf_session_find(struct rte_mbuf *m, int di,
		const struct ifnet *ifp, bool *sforw, bool *internal_hairpin);
npf_session_t *npf_session_find_or_create(npf_cache_t *npc,
		struct rte_mbuf *mbuf, const struct ifnet *ifp, int dir,
		int *error);
npf_session_t *npf_session_find_by_npc(npf_cache_t *npc, const int di,
		const struct ifnet *ifp, bool embedded);
npf_session_t *npf_session_establish(npf_cache_t *npc,
		struct rte_mbuf *nbuf, const struct ifnet *ifp,
		const int di, int *error);
void npf_session_update_state(npf_session_t *se);
uint8_t npf_session_get_proto(npf_session_t *se);
bool npf_session_is_active(const npf_session_t *se);
bool npf_session_is_child(const npf_session_t *se);
int npf_session_activate(npf_session_t *se, const struct ifnet *ifp,
		npf_cache_t *npc, struct rte_mbuf *nbuf);
vrfid_t npf_session_get_vrfid(npf_session_t *se);
npf_nat_t *npf_session_get_nat(const npf_session_t *se);
void npf_session_setnat(npf_session_t *se, npf_nat_t *nt, bool pinhole);

void npf_session_set_dp_session(npf_session_t *se, struct session *s);
struct session *npf_session_get_dp_session(npf_session_t *se);
int npf_session_sentry_extract(npf_session_t *se, uint32_t *if_index, int *af,
			       npf_addr_t **src, uint16_t *sid,
			       npf_addr_t **dst, uint16_t *did);

void npf_session_expire(npf_session_t *se);
void npf_session_destroy(npf_session_t *se);
bool npf_session_is_pass(const npf_session_t *se, npf_rule_t **rl);
bool npf_session_is_nat_pinhole(const npf_session_t *se, int dir);
bool npf_session_forward_dir(npf_session_t *se, int di);
npf_nat_t *npf_session_retnat(npf_session_t *se, const int di, bool *forw);

void npf_session_feature_json(json_writer_t *json, npf_session_t *se);
void npf_session_feature_log(enum session_log_event event, struct session *s,
			    struct session_feature *sf);
int npf_session_feature_nat_info(npf_session_t *se, uint32_t *taddr,
				 uint16_t *tport);

void npf_session_set_nat64(npf_session_t *se, struct npf_nat64 *nat64);
struct npf_nat64 *npf_session_get_nat64(npf_session_t *se);
bool npf_session_is_nat64(npf_session_t *se);
void npf_session_nat64_log(npf_session_t *se, bool created);

int npf_enable_session_log(const char *proto, const char *state);
int npf_disable_session_log(const char *proto, const char *state);
void npf_reset_session_log(void);

bool npf_session_set_dpi(npf_session_t *se, void *data);
void *npf_session_get_dpi(npf_session_t *se);

void npf_session_set_pkt_hook(npf_session_t *se, session_pkt_hook *fn);

void npf_session_set_local_zone_nat(npf_session_t *se);
bool npf_session_is_local_zone_nat(npf_session_t *se);

void npf_session_disassoc_nif(unsigned int if_index);

void npf_save_stats(npf_session_t *se, int dir, uint64_t bytes);

int npf_session_npf_pack_state_pack(struct npf_session *se,
				    struct npf_pack_session_state *pst);
int npf_session_pack_state_update_gen(struct npf_session *se,
				      struct npf_pack_session_state *pst);
int npf_session_pack_state_update_tcp(struct npf_session *se,
				      struct npf_pack_session_state *pst);
int npf_session_npf_pack_pack(npf_session_t *se,
			      struct npf_pack_npf_session *pns,
			      struct npf_pack_session_state *pst);
struct npf_session *
npf_session_npf_pack_restore(struct npf_pack_npf_session *pns,
			     struct npf_pack_session_state *pst,
			     vrfid_t vrfid, uint8_t protocol,
			     uint32_t ifindex);
int npf_session_npf_pack_activate(struct npf_session *se, struct ifnet *ifp);

#endif /* NPF_SESSION_H */
