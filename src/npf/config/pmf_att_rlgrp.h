/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef PMF_ATT_RLGRP_H
#define PMF_ATT_RLGRP_H

#include <stdio.h>
#include <stdint.h>

struct pmf_rlset_ext;
struct pmf_group_ext;
struct pmf_cntr;
struct pmf_attrl;
struct pmf_rule;

struct gpc_group;

void pmf_arlg_init(void);
void pmf_arlg_commit(void);
void pmf_arlg_dump(FILE *fp);
int pmf_arlg_cmd_show_counters(FILE *fp, char const *ifname, int dir,
				char const *rgname);
int pmf_arlg_cmd_clear_counters(char const *ifname, int dir,
				char const *rgname);

uint16_t pmf_arlg_attrl_get_index(struct pmf_attrl const *earl);
struct gpc_group *pmf_arlg_attrl_get_grp(struct pmf_attrl const *earl);
struct pmf_cntr *pmf_arlg_attrl_get_cntr(struct pmf_attrl *earl);
uintptr_t pmf_arlg_attrl_get_objid(struct pmf_attrl const *earl);
void pmf_arlg_attrl_set_objid(struct pmf_attrl *earl, uintptr_t objid);

struct gpc_group *pmf_arlg_cntr_get_grp(struct pmf_cntr const *eark);
uintptr_t pmf_arlg_cntr_get_objid(struct pmf_cntr const *eark);
void pmf_arlg_cntr_set_objid(struct pmf_cntr *eark, uintptr_t objid);
char const *pmf_arlg_cntr_get_name(struct pmf_cntr const *eark);
bool pmf_arlg_cntr_pkt_enabled(struct pmf_cntr const *eark);
bool pmf_arlg_cntr_byt_enabled(struct pmf_cntr const *eark);

uint32_t pmf_arlg_recalc_summary(struct pmf_group_ext *earg,
				 struct pmf_rule *rule);

#endif /* PMF_ATT_RLGRP_H */
