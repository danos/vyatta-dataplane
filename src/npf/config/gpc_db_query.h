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

/* -- ruleset accessors -- */

char const *gpc_rlset_get_ifname(struct gpc_rlset const *gprs);

/* -- group accessors -- */

char const *gpc_group_get_name(struct gpc_group const *arg);
struct gpc_rlset *gpc_group_get_rlset(struct gpc_group const *arg);
uint32_t gpc_group_get_summary(struct gpc_group const *arg);
bool gpc_group_is_v6(struct gpc_group const *arg);
bool gpc_group_is_ingress(struct gpc_group const *arg);
bool gpc_group_is_ll_attached(struct gpc_group const *arg);
uintptr_t gpc_group_get_objid(struct gpc_group const *arg);
void gpc_group_set_objid(struct gpc_group *arg, uintptr_t objid);

/* -- counter accessors -- */

struct gpc_group *gpc_cntr_get_group(struct gpc_cntr const *ark);
uintptr_t gpc_cntr_get_objid(struct gpc_cntr const *ark);
void gpc_cntr_set_objid(struct gpc_cntr *ark, uintptr_t objid);
char const *gpc_cntr_get_name(struct gpc_cntr const *ark);
bool gpc_cntr_pkt_enabled(struct gpc_cntr const *ark);
bool gpc_cntr_byt_enabled(struct gpc_cntr const *ark);

/* -- rule accessors -- */

uint16_t gpc_rule_get_index(struct gpc_rule const *arl);
struct gpc_group *gpc_rule_get_group(struct gpc_rule const *arl);
struct gpc_cntr *gpc_rule_get_cntr(struct gpc_rule *arl);
uintptr_t gpc_rule_get_objid(struct gpc_rule const *arl);
void gpc_rule_set_objid(struct gpc_rule *arl, uintptr_t objid);

#endif /* GPC_DB_QUERY_H */
