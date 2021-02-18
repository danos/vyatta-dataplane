/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GPC_HW_H
#define GPC_HW_H

#include <stdbool.h>
#include <stdint.h>

struct gpc_group;
struct gpc_rule;
struct gpc_cntr;
struct pmf_rule;
struct ifnet;

bool gpc_hw_rule_add(struct gpc_rule *gprl);
void gpc_hw_rule_mod(struct gpc_rule *gprl, struct pmf_rule *old_rule);
void gpc_hw_rule_del(struct gpc_rule *gprl);

bool gpc_hw_group_attach(struct gpc_group *gprg, struct ifnet *ifp);
void gpc_hw_group_detach(struct gpc_group *gprg, struct ifnet *ifp);
bool gpc_hw_group_create(struct gpc_group *gprg);
void gpc_hw_group_mod(struct gpc_group *gprg, uint32_t new);
void gpc_hw_group_delete(struct gpc_group *gprg);

bool gpc_hw_counter_create(struct gpc_cntr *gprk);
void gpc_hw_counter_delete(struct gpc_cntr *gprk);
bool gpc_hw_counter_clear(struct gpc_cntr const *gprk);
bool gpc_hw_counter_read(struct gpc_cntr const *gprk,
			 uint64_t *pkts, uint64_t *bytes);
void gpc_hw_commit(void);

#endif /* GPC_HW_H */
