/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GPC_DB_QUERY_H
#define GPC_DB_QUERY_H

#include <stdint.h>
#include <stdbool.h>

struct gpc_rlset;
struct gpc_group;
struct gpc_cntg;
struct gpc_rule;
struct gpc_cntr;

struct pmf_rule;

/*
 * When adding new features, check existing static arrays of
 * GPC_FEAT__MAX elements, initialised based on the feature
 * index. Also update the GPC_FEAT__LAST definition.
 */
#define GPC_FEAT__FIRST 1
enum gpc_feature {
	GPC_FEAT_ACL = GPC_FEAT__FIRST,
	GPC_FEAT_QOS,
};
#define GPC_FEAT__LAST (GPC_FEAT_QOS)
#define GPC_FEAT__MAX (GPC_FEAT__LAST + 1)

static inline bool gpc_feature_is_valid(enum gpc_feature feat)
{
	return (feat >= GPC_FEAT__FIRST && feat <= GPC_FEAT__LAST);
}

char const *gpc_feature_get_name(enum gpc_feature feat);

/* -- ruleset accessors -- */

char const *gpc_rlset_get_ifname(struct gpc_rlset const *gprs);
struct ifnet *gpc_rlset_get_ifp(struct gpc_rlset const *gprs);
void *gpc_rlset_get_owner(struct gpc_rlset const *gprs);
bool gpc_rlset_is_ingress(struct gpc_rlset const *gprs);
bool gpc_rlset_is_if_created(struct gpc_rlset const *gprs);
struct gpc_rlset *gpc_rlset_first(void);
struct gpc_rlset *gpc_rlset_next(struct gpc_rlset const *cursor);

#define GPC_RLSET_FOREACH(var) \
	for ((var) = gpc_rlset_first(); \
	    (var); \
	    (var) = gpc_rlset_next((var)))

/* -- group accessors -- */

char const *gpc_group_get_name(struct gpc_group const *gprg);
struct gpc_rlset *gpc_group_get_rlset(struct gpc_group const *gprg);
void *gpc_group_get_owner(struct gpc_group const *gprg);
enum gpc_feature gpc_group_get_feature(struct gpc_group const *gprg);
uint32_t gpc_group_get_summary(struct gpc_group const *gprg);
bool gpc_group_has_family(struct gpc_group const *gprg);
bool gpc_group_is_v6(struct gpc_group const *gprg);
bool gpc_group_is_ingress(struct gpc_group const *gprg);
bool gpc_group_is_published(struct gpc_group const *gprg);
bool gpc_group_is_ll_created(struct gpc_group const *gprg);
bool gpc_group_is_attached(struct gpc_group const *gprg);
bool gpc_group_is_ll_attached(struct gpc_group const *gprg);
bool gpc_group_is_deferred(struct gpc_group const *gprg);
struct gpc_cntg *gpc_group_get_cntg(struct gpc_group const *gprg);
uintptr_t gpc_group_get_objid(struct gpc_group const *gprg);

void gpc_group_set_objid(struct gpc_group *gprg, uintptr_t objid);
uint32_t gpc_group_recalc_summary(struct gpc_group *gprg,
				  struct pmf_rule *rule);

struct gpc_group *gpc_group_first(struct gpc_rlset const *gprs);
struct gpc_group *gpc_group_next(struct gpc_group const *cursor);

#define GPC_GROUP_FOREACH(var, head) \
	for ((var) = gpc_group_first((head)); \
	    (var); \
	    (var) = gpc_group_next((var)))

/* -- rule accessors -- */

uint16_t gpc_rule_get_index(struct gpc_rule const *gprl);
struct pmf_rule *gpc_rule_get_rule(struct gpc_rule const *gprl);
struct gpc_group *gpc_rule_get_group(struct gpc_rule const *gprl);
void *gpc_rule_get_owner(struct gpc_rule const *gprl);
struct gpc_cntr *gpc_rule_get_cntr(struct gpc_rule const *gprl);
uintptr_t gpc_rule_get_objid(struct gpc_rule const *gprl);
void gpc_rule_set_objid(struct gpc_rule *gprl, uintptr_t objid);
bool gpc_rule_is_published(struct gpc_rule const *gprl);
bool gpc_rule_is_ll_created(struct gpc_rule const *gprl);

struct gpc_rule *gpc_rule_find(struct gpc_group *gprg, uint32_t index);

struct gpc_rule *gpc_rule_first(struct gpc_group const *gprg);
struct gpc_rule *gpc_rule_last(struct gpc_group const *gprg);
struct gpc_rule *gpc_rule_next(struct gpc_rule const *cursor);

#define GPC_RULE_FOREACH(var, head) \
	for ((var) = gpc_rule_first((head)); \
	    (var); \
	    (var) = gpc_rule_next((var)))

#endif /* GPC_DB_QUERY_H */
