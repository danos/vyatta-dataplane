/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <stdint.h>

struct gpc_group;
struct pmf_cntr;
struct pmf_attrl;
struct pmf_rule;
struct ifnet;

bool pmf_hw_rule_add(struct pmf_attrl *earl, struct pmf_rule *rule);
void pmf_hw_rule_mod(struct pmf_attrl *earl, struct pmf_rule *rule);
void pmf_hw_rule_del(struct pmf_attrl *earl);

bool pmf_hw_group_attach(struct gpc_group *gprg, struct ifnet *ifp);
void pmf_hw_group_detach(struct gpc_group *gprg, struct ifnet *ifp);
bool pmf_hw_group_create(struct gpc_group *gprg);
void pmf_hw_group_mod(struct gpc_group *gprg, uint32_t new);
void pmf_hw_group_delete(struct gpc_group *gprg);

bool pmf_hw_counter_create(struct pmf_cntr *eark);
void pmf_hw_counter_delete(struct pmf_cntr *eark);
bool pmf_hw_counter_clear(struct pmf_cntr const *eark);
bool pmf_hw_counter_read(struct pmf_cntr const *eark,
			 uint64_t *pkts, uint64_t *bytes);
void pmf_hw_commit(void);
