/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
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


#ifndef NALG

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

int npf_alg_session_init(struct npf_session *se, struct npf_cache *npc,
			 const int di);
struct npf_session *npf_alg_session(struct npf_cache *npc, struct rte_mbuf *m,
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

#else /* ~NALG */

static inline void npf_alg_init(void)
{
}

static inline void npf_alg_uninit(void)
{
}

static inline struct npf_alg_instance *
npf_alg_create_instance(uint32_t ext_vrfid __unused)
{
	return NULL;
}

static inline void
npf_alg_destroy_instance(struct npf_alg_instance *ai __unused)
{
}

struct npf_alg *npf_alg_get(struct npf_alg *alg __unused)
{
	return NULL;
}

void npf_alg_put(struct npf_alg *alg __unused)
{
}

static inline void
npf_alg_inspect(struct npf_session *se __unused,
		struct npf_cache *npc __unused,
		struct rte_mbuf *nbuf __unused,
		struct ifnet *ifp __unused, int di __unused)
{
}

static inline void
npf_alg_nat_inspect(struct npf_session *se __unused,
		    struct npf_cache *npc __unused,
		    struct npf_nat *nt __unused, int di __unused)
{
}

static inline int
npf_alg_nat(struct npf_session *se __unused, struct npf_cache *npc __unused,
	    struct rte_mbuf *nbuf __unused, struct npf_nat *nt __unused,
	    const int di __unused)
{
	return 0;
}

static inline int
npf_alg_session_init(struct npf_session *se __unused,
		     struct npf_cache *npc __unused,
		     const int di __unused)
{
	return 0;
}

static inline struct npf_session *
npf_alg_session(struct npf_cache *npc __unused, struct rte_mbuf *nbuf __unused,
		const struct ifnet *ifp __unused, const int di __unused,
		int *error __unused)
{
	return NULL;
}

static inline void
npf_alg_session_expire(struct npf_session *se __unused,
		       struct npf_session_alg *sa __unused)
{
}

static inline void
npf_alg_session_destroy(struct npf_session *se __unused,
			struct npf_session_alg *sa __unused)
{
}

static inline bool
npf_alg_session_trackable_p(vrfid_t vrfid __unused,
			    struct npf_cache *npc __unused)
{
	return true;
}

static inline void npf_alg_reset(bool hard __unused)
{
}

static inline int
npf_alg_cfg(FILE *f __unused, int argc __unused, char **argv __unused)
{
	return 0;
}

static inline void npf_alg_dump(FILE *fp, vrfid_t vrfid __unused)
{
	json_writer_t *json;

	json = jsonw_new(fp);
	jsonw_name(json, "alg");
	jsonw_start_object(json);

	jsonw_end_object(json);
	jsonw_destroy(&json);
}

static const char *npf_alg_name(struct npf_session *se)
{
	return NULL;
}

#endif /* NALG */

#endif /* End of _ALG_NPF_H_ */
