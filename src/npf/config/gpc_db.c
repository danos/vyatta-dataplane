/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "compiler.h"

#include "npf/config/gpc_db_query.h"
#include "npf/config/pmf_att_rlgrp.h"

/* ---- */

/* -- ruleset accessors -- */

char const *
gpc_rlset_get_ifname(struct gpc_rlset const *ars)
{
	return pmf_arlg_rls_get_ifname((struct pmf_rlset_ext const *)ars);
}

/* -- group accessors -- */

char const *
gpc_group_get_name(struct gpc_group const *arg)
{
	return pmf_arlg_grp_get_name((struct pmf_group_ext const *)arg);
}

struct gpc_rlset *
gpc_group_get_rlset(struct gpc_group const *arg)
{
	struct pmf_rlset_ext *ears
		= pmf_arlg_grp_get_rls((struct pmf_group_ext const *)arg);
	return (struct gpc_rlset *)ears;
}

uint32_t
gpc_group_get_summary(struct gpc_group const *arg)
{
	return pmf_arlg_grp_get_summary((struct pmf_group_ext const *)arg);
}

bool
gpc_group_is_v6(struct gpc_group const *arg)
{
	return pmf_arlg_grp_is_v6((struct pmf_group_ext const *)arg);
}

bool
gpc_group_is_ingress(struct gpc_group const *arg)
{
	return pmf_arlg_grp_is_ingress((struct pmf_group_ext const *)arg);
}

bool
gpc_group_is_ll_attached(struct gpc_group const *arg)
{
	return pmf_arlg_grp_is_ll_attached((struct pmf_group_ext const *)arg);
}

uintptr_t
gpc_group_get_objid(struct gpc_group const *arg)
{
	return pmf_arlg_grp_get_objid((struct pmf_group_ext const *)arg);
}

void
gpc_group_set_objid(struct gpc_group *arg, uintptr_t objid)
{
	pmf_arlg_grp_set_objid((struct pmf_group_ext *)arg, objid);
}

/* -- counter accessors -- */

struct gpc_group *
gpc_cntr_get_group(struct gpc_cntr const *ark)
{
	struct pmf_group_ext *earg
		= pmf_arlg_cntr_get_grp((struct pmf_cntr const *)ark);
	return (struct gpc_group *)earg;
}

uintptr_t
gpc_cntr_get_objid(struct gpc_cntr const *ark)
{
	return pmf_arlg_cntr_get_objid((struct pmf_cntr const *)ark);
}

void
gpc_cntr_set_objid(struct gpc_cntr *ark, uintptr_t objid)
{
	pmf_arlg_cntr_set_objid((struct pmf_cntr *)ark, objid);
}

char const *
gpc_cntr_get_name(struct gpc_cntr const *ark)
{
	return pmf_arlg_cntr_get_name((struct pmf_cntr const *)ark);
}

bool
gpc_cntr_pkt_enabled(struct gpc_cntr const *ark)
{
	return pmf_arlg_cntr_pkt_enabled((struct pmf_cntr const *)ark);
}

bool
gpc_cntr_byt_enabled(struct gpc_cntr const *ark)
{
	return pmf_arlg_cntr_byt_enabled((struct pmf_cntr const *)ark);
}

/* -- rule accessors -- */

uint16_t
gpc_rule_get_index(struct gpc_rule const *arl)
{
	return pmf_arlg_attrl_get_index((struct pmf_attrl const *)arl);
}

struct gpc_group *
gpc_rule_get_group(struct gpc_rule const *arl)
{
	struct pmf_group_ext *earg
		= pmf_arlg_attrl_get_grp((struct pmf_attrl const *)arl);
	return (struct gpc_group *)earg;
}

struct gpc_cntr *
gpc_rule_get_cntr(struct gpc_rule *arl)
{
	struct pmf_cntr *eark
		= pmf_arlg_attrl_get_cntr((struct pmf_attrl *)arl);
	return (struct gpc_cntr *)eark;
}

uintptr_t
gpc_rule_get_objid(struct gpc_rule const *arl)
{
	return pmf_arlg_attrl_get_objid((struct pmf_attrl const *)arl);
}

void
gpc_rule_set_objid(struct gpc_rule *arl, uintptr_t objid)
{
	pmf_arlg_attrl_set_objid((struct pmf_attrl *)arl, objid);
}

