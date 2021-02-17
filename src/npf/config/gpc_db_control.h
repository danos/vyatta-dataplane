/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GPC_DB_CONTROL_H
#define GPC_DB_CONTROL_H

#include <stdint.h>
#include <stdbool.h>

enum gpc_feature;

struct gpc_rlset;
struct gpc_group;
struct gpc_cntg;
struct gpc_rule;
struct gpc_cntr;

struct pmf_rule;

/* -- ruleset -- */

void gpc_rlset_set_if_created(struct gpc_rlset *gprs);
bool gpc_rlset_set_ifp(struct gpc_rlset *gprs);
void gpc_rlset_clear_ifp(struct gpc_rlset *gprs);

struct gpc_rlset *gpc_rlset_create(bool ingress, char const *if_name,
				   void *owner);
void gpc_rlset_delete(struct gpc_rlset *gprs);

/* -- group -- */

void gpc_group_clear_family(struct gpc_group *gprg);
void gpc_group_set_v4(struct gpc_group *gprg);
void gpc_group_set_v6(struct gpc_group *gprg);
void gpc_group_set_deferred(struct gpc_group *gprg);
void gpc_group_clear_deferred(struct gpc_group *gprg);

void gpc_group_set_cntg(struct gpc_group *gprg, struct gpc_cntg *cntg);

struct gpc_group *gpc_group_create(struct gpc_rlset *gprs,
				   enum gpc_feature feat,
				   char const *rg_name, void *owner);
void gpc_group_delete(struct gpc_group *gprg);

void gpc_group_hw_ntfy_create(struct gpc_group *gprg, struct pmf_rule *rule);
void gpc_group_hw_ntfy_delete(struct gpc_group *gprg);
void gpc_group_hw_ntfy_modify(struct gpc_group *gprg, uint32_t new);
void gpc_group_hw_ntfy_attach(struct gpc_group *gprg);
void gpc_group_hw_ntfy_detach(struct gpc_group *gprg);

void gpc_group_hw_ntfy_rules_create(struct gpc_group *gprg);
void gpc_group_hw_ntfy_rules_delete(struct gpc_group *gprg);

/* -- rule -- */

struct gpc_rule *gpc_rule_create(struct gpc_group *gprg, uint32_t rl_idx,
				 void *owner);
void gpc_rule_delete(struct gpc_rule *gprl);
void gpc_rule_change_rule(struct gpc_rule *gprl, struct pmf_rule *new_rule);

void gpc_rule_set_cntr(struct gpc_rule *gprl, struct gpc_cntr *cntr);

void gpc_rule_hw_ntfy_create(struct gpc_group *gprg, struct gpc_rule *gprl);
void gpc_rule_hw_ntfy_modify(struct gpc_group *gprg, struct gpc_rule *gprl,
				struct pmf_rule *old_rule);
void gpc_rule_hw_ntfy_delete(struct gpc_group *gprg, struct gpc_rule *gprl);

#endif /* GPC_DB_CONTROL_H */
