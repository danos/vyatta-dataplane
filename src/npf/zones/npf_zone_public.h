/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_ZONE_PUBLIC_H
#define NPF_ZONE_PUBLIC_H

#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"

struct ifnet;
struct npf_if;
struct npf_cache;
struct npf_session;
struct npf_zone_intf;

#ifndef NZONEFW

bool npf_zone_local_is_set(void);

bool npf_zone_hook(struct ifnet *in_ifp, struct npf_if *nif,
		   uint16_t npf_flags, struct npf_config **fw_config,
		   npf_decision_t *decision, enum npf_ruleset_type *rlset_type,
		   bool *reverse_stateful);

bool npf_local_zone_hook(struct ifnet *ifp, struct rte_mbuf **m,
			 struct npf_cache *npc, struct npf_session *se,
			 struct npf_if *nif);

int npf_zone_show(FILE *fp, int argc, char **argv);

int npf_zone_cfg_add(FILE *f, int argc, char **argv);
int npf_zone_cfg_remove(FILE *f, int argc, char **argv);
int npf_zone_cfg_local(FILE *f, int argc, char **argv);
int npf_zone_cfg_policy_add(FILE *f, int argc, char **argv);
int npf_zone_cfg_policy_remove(FILE *f, int argc, char **argv);
int npf_zone_cfg_intf_add(FILE *f, int argc, char **argv);
int npf_zone_cfg_intf_remove(FILE *f, int argc, char **argv);

void npf_zone_inst_destroy(void);
struct npf_zone *npf_zone_zif2zone(const struct npf_zone_intf *zif);
int npf_zone_if_index_set(struct ifnet *ifp);
int npf_zone_if_index_unset(struct ifnet *ifp);

#else  /* ~NZONEFW */

static inline bool npf_zone_local_is_set(void)
{
	return false;
}

static inline bool
npf_zone_hook(struct ifnet *in_ifp __unused,
	      struct npf_if *nif __unused,
	      uint16_t npf_flags __unused,
	      struct npf_config **fw_config __unused,
	      npf_decision_t *decision __unused,
	      enum npf_ruleset_type *rlset_type __unused,
	      bool *reverse_stateful __unused)
{
	return false;
}

static inline bool
npf_local_zone_hook(struct ifnet *ifp __unused,
		    struct rte_mbuf **m __unused,
		    struct npf_cache *npc __unused,
		    struct npf_session *se __unused,
		    struct npf_if *nif __unused)
{
	return false;
}

static inline int
npf_zone_show(FILE *fp __unused, int argc __unused, char **argv __unused)
{
	return 0;
}

static inline int
npf_zone_cfg_add(FILE *f __unused, int argc __unused, char **argv __unused)
{
	return 0;
}

static inline int
npf_zone_cfg_remove(FILE *f __unused, int argc __unused, char **argv __unused)
{
	return 0;
}

static inline int
npf_zone_cfg_local(FILE *f __unused, int argc __unused, char **argv __unused)
{
	return 0;
}

static inline int
npf_zone_cfg_policy_add(FILE *f __unused, int argc __unused,
			char **argv __unused)
{
	return 0;
}

static inline int
npf_zone_cfg_policy_remove(FILE *f __unused, int argc __unused,
			   char **argv __unused)
{
	return 0;
}

static inline int
npf_zone_cfg_intf_add(FILE *f __unused, int argc __unused,
		      char **argv __unused)
{
	return 0;
}

static inline int
npf_zone_cfg_intf_remove(FILE *f __unused, int argc __unused,
			 char **argv __unused)
{
	return 0;
}

static inline void
npf_zone_inst_destroy(void)
{
}

static inline struct
npf_zone *npf_zone_zif2zone(const struct npf_zone_intf *zif __unused)
{
	return NULL;
}

static inline int npf_zone_if_index_set(struct ifnet *ifp __unused)
{
	return 0;
}

static inline int npf_zone_if_index_unset(struct ifnet *ifp __unused);
{
	return 0;
}

#endif /* ~NZONEFW */

#endif /* NPF_ZONE_PUBLIC_H */
