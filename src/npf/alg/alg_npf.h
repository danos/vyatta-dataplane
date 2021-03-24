/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_NPF_H_
#define _ALG_NPF_H_

#include <stdio.h>
#include "json_writer.h"
#include "util.h"

struct npf_alg;
struct npf_alg_instance;
struct npf_session_alg;
struct npf_session;
struct npf_cache;
struct rte_mbuf;
struct npf_nat;
struct ifnet;


void npf_alg_init(void);
void npf_alg_uninit(void);

struct npf_alg_instance *npf_alg_create_instance(uint32_t ext_vrfid);
void npf_alg_destroy_instance(struct npf_alg_instance *ai);

struct npf_alg *npf_alg_get(struct npf_alg *alg);
void npf_alg_put(struct npf_alg *alg);

void npf_alg_inspect(struct npf_session *se, struct npf_cache *npc,
		     struct rte_mbuf *nbuf, struct ifnet *ifp,
		     int di) __cold_func;
void npf_alg_nat_inspect(struct npf_session *se, struct npf_cache *npc,
			 struct npf_nat *nat, int di);
int npf_alg_nat(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *nbuf, struct npf_nat *nat,
		const int di) __cold_func;

bool npf_alg_bypass_cgnat(const struct ifnet *ifp, struct rte_mbuf *m);

/**
 * ALG session init.  Called when a session has just been created, and has
 * been identified as an ALG session.  If a data/child session has been
 * identified then the tuple (pinhole) is attached to the packet cache.
 *
 * @param se Pointer to the session
 * @param npc Pointer to the npf packet cache
 * @param di Direction of packet relative to interface (in or out)
 * @return 0 if successful else -errno
 */
int npf_alg_session_init(struct npf_session *se, struct npf_cache *npc, int di);

struct npf_session *npf_alg_session(struct npf_cache *npc,
				    struct rte_mbuf *nbuf,
				    const struct ifnet *ifp, const int di,
				    int *error);
void npf_alg_session_expire(struct npf_session *se, struct npf_session_alg *sa);
void npf_alg_session_destroy(struct npf_session *se,
			     struct npf_session_alg *sa);
int npf_alg_session_json(json_writer_t *json, struct npf_session *se,
			 struct npf_session_alg *sa);

void npf_alg_reset(bool hard);
int npf_alg_cfg(FILE *f, int argc, char **argv);
void npf_alg_dump(FILE *fp, vrfid_t vrfid);
const char *npf_alg_name(struct npf_session *se);

#endif /* End of _ALG_NPF_H_ */
