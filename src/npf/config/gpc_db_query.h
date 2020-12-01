/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GPC_DB_QUERY_H
#define GPC_DB_QUERY_H

#include <stdint.h>
#include <stdbool.h>

struct gpc_rlset;
struct gpc_group;
struct gpc_cntr;
struct gpc_rule;

struct pmf_rule;

enum gpc_feature {
	GPC_FEAT_ACL = 1,
	GPC_FEAT_QOS,
};

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

/* -- counter accessors -- */

struct gpc_group *gpc_cntr_get_group(struct gpc_cntr const *ark);
uintptr_t gpc_cntr_get_objid(struct gpc_cntr const *ark);
void gpc_cntr_set_objid(struct gpc_cntr *ark, uintptr_t objid);
char const *gpc_cntr_get_name(struct gpc_cntr const *ark);
bool gpc_cntr_pkt_enabled(struct gpc_cntr const *ark);
bool gpc_cntr_byt_enabled(struct gpc_cntr const *ark);

/* -- rule accessors -- */

uint16_t gpc_rule_get_index(struct gpc_rule const *gprl);
struct pmf_rule *gpc_rule_get_rule(struct gpc_rule const *gprl);
struct gpc_group *gpc_rule_get_group(struct gpc_rule const *gprl);
void *gpc_rule_get_owner(struct gpc_rule const *gprl);
struct gpc_cntr *gpc_rule_get_cntr(struct gpc_rule *gprl);
uintptr_t gpc_rule_get_objid(struct gpc_rule const *gprl);
void gpc_rule_set_objid(struct gpc_rule *gprl, uintptr_t objid);
bool gpc_rule_is_published(struct gpc_rule const *gprl);
bool gpc_rule_is_ll_created(struct gpc_rule const *gprl);

struct gpc_rule *gpc_rule_find(struct gpc_group *gprg, uint32_t idx);

struct gpc_rule *gpc_rule_first(struct gpc_group const *gprg);
struct gpc_rule *gpc_rule_last(struct gpc_group const *gprg);
struct gpc_rule *gpc_rule_next(struct gpc_rule const *cursor);

#define GPC_RULE_FOREACH(var, head) \
	for ((var) = gpc_rule_first((head)); \
	    (var); \
	    (var) = gpc_rule_next((var)))

#endif /* GPC_DB_QUERY_H */
