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

#ifndef NPF_RPROC_H
#define NPF_RPROC_H

#include <stdbool.h>
#include <stdint.h>

#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_ruleset.h"

struct ifnet;
struct rte_mbuf;

/*
 * rproc types.  Each rproc type uses a different command string.
 */
enum npf_rproc_type {
	NPF_RPROC_TYPE_MATCH,  /* match=(...) */
	NPF_RPROC_TYPE_ACTION, /* rproc=(...) */
	NPF_RPROC_TYPE_HANDLE, /* handle=(...) */
};
#define NPF_RPROC_TYPE_FIRST NPF_RPROC_TYPE_MATCH
#define NPF_RPROC_TYPE_LAST  NPF_RPROC_TYPE_HANDLE
#define NPF_RPROC_TYPE_COUNT (NPF_RPROC_TYPE_LAST + 1)

/*
 * Enum to uniquely identify each npf_rproc_ops_t structure.  We don't care
 * whether the ops structure is match, action, neither or both.
 */
enum npf_rproc_id {
	NPF_RPROC_ID_APPFW,
	NPF_RPROC_ID_POLICER,
	NPF_RPROC_ID_MARKDSCP,
	NPF_RPROC_ID_MARKPCP,
	NPF_RPROC_ID_LOG,
	NPF_RPROC_ID_APP,
	NPF_RPROC_ID_DPI,
	NPF_RPROC_ID_PATHMON,
	NPF_RPROC_ID_SLIMIT,
	NPF_RPROC_ID_SETVRF,
	NPF_RPROC_ID_ACTIONGRP,
	NPF_RPROC_ID_TAG,
	NPF_RPROC_ID_NPTV6,
	NPF_RPROC_ID_NAT64,
	NPF_RPROC_ID_NAT46,
	NPF_RPROC_ID_CTR_DEF,
	NPF_RPROC_ID_CTR_REF,
	NPF_RPROC_ID_COUNTER,
	NPF_RPROC_ID_APP_GRP,
	/* Insert new ID above this comment */
	NPF_RPROC_ID_LAST,
};

typedef struct {
	const char         *ro_name;
	enum npf_rproc_type ro_type;
	enum npf_rproc_id   ro_id;
	int	(*ro_ctor)(npf_rule_t *rl,
			   const char *args,
			   void **handle);
	void	(*ro_dtor)(void *handle);
	bool	ro_bidir;
	bool	ro_logger;
	bool	(*ro_action)(npf_cache_t *npc,
			     struct rte_mbuf **nbuf,
			     void *handle,
			     npf_session_t *se,
			     npf_rproc_result_t *result);
	bool	(*ro_match)(npf_cache_t *npc,
			    struct rte_mbuf *nbuf,
			    const struct ifnet *ifp,
			    int dir,
			    npf_session_t *se,
			    void *handle);
	void    (*ro_json)(json_writer_t *json,
			   npf_rule_t *rl,
			   const char *args,
			   void *handle);
	void    (*ro_clear_stats)(void *handle);
} npf_rproc_ops_t;


const char *npf_rproc_type2string(enum npf_rproc_type ro_type);
void *npf_rule_rproc_handle_from_id(npf_rule_t *rl, enum npf_rproc_id id);
uint32_t npf_rule_rproc_tag(npf_rule_t *rl, bool *tag_set);
unsigned int npf_rproc_max_rprocs(void);
int npf_create_rproc(const npf_rproc_ops_t *ops, npf_rule_t *rl,
		     const char *args, void **handle);

void npf_destroy_rproc(const npf_rproc_ops_t *ops, void *arg);

/* Find an rproc handler by name and type */
const npf_rproc_ops_t *npf_find_rproc(char *name, enum npf_rproc_type ro_type);

/* Find an rproc handler by id */
const npf_rproc_ops_t *npf_find_rproc_by_id(enum npf_rproc_id ro_id);

/* Query the ID for an rproc */
enum npf_rproc_id npf_rproc_get_id(const npf_rproc_ops_t *ops);

/* npf_ext_policer.c */
void police_enable_inner_marking(void *arg);

void police_disable_inner_marking(void *arg);

void
npf_policer_json(json_writer_t *json, npf_rule_t *rl,
		 const char *params, void *handle);

/* npf_ext_mark.c */
void npf_remark_dscp(npf_cache_t *npc, struct rte_mbuf **m, uint8_t n,
		     npf_rproc_result_t *result);

void mark_enable_inner_marking(void **markpcp_handle);

void mark_disable_inner_marking(void **markpcp_handle);

bool mark_inner(uintptr_t mark);

bool mark_inner_state(uintptr_t mark);

void markpcp_inner(struct rte_mbuf *m, uint16_t val);

void
npf_markpcp_json(json_writer_t *json, npf_rule_t *rl,
		 const char *params, void *handle);

void policer_show(json_writer_t *wr, void *arg);

#endif /* NPF_RPROC_H */
