/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <sys/queue.h>		/* TAILQ macros */

#include "compiler.h"
#include "if_var.h"

#include "npf/config/gpc_db_control.h"
#include "npf/config/gpc_db_query.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/config/pmf_hw.h"

/* -- ruleset -- */

enum gpc_rs_flags {
	GPC_RSF_IN		= (1 << 0),
	GPC_RSF_IF_CREATED	= (1 << 1),
};

struct gpc_rlset {
	TAILQ_ENTRY(gpc_rlset) gprs_list;
	TAILQ_HEAD(, gpc_group) gprs_groups;
	void			*gprs_owner;	/* weak */
	char const		*gprs_ifname;	/* weak */
	struct ifnet		*gprs_ifp;	/* weak */
	uint32_t		gprs_flags;
};


/* -- group -- */

enum gpc_rg_flags {
	GPC_RGF_PUBLISHED	= (1 << 0),
	GPC_RGF_LL_CREATED	= (1 << 1),
	GPC_RGF_ATTACHED	= (1 << 2),
	GPC_RGF_LL_ATTACHED	= (1 << 3),
	GPC_RGF_FAMILY		= (1 << 4),
	GPC_RGF_V6		= (1 << 5),
	GPC_RGF_DEFERRED	= (1 << 6),

};

struct gpc_group {
	TAILQ_ENTRY(gpc_group)	gprg_list;
	void			*gprg_owner;	/* weak */
	struct gpc_rlset	*gprg_rlset;
	char const		*gprg_rgname;	/* weak */
	uintptr_t		gprg_objid;	/* FAL object */
	uint32_t		gprg_summary;
	uint32_t		gprg_flags;
};


/* -- locals -- */

static TAILQ_HEAD(, gpc_rlset) att_rlsets
	= TAILQ_HEAD_INITIALIZER(att_rlsets);

/* -- ruleset accessors -- */

char const *
gpc_rlset_get_ifname(struct gpc_rlset const *gprs)
{
	return gprs->gprs_ifname;
}

struct ifnet *
gpc_rlset_get_ifp(struct gpc_rlset const *gprs)
{
	return gprs->gprs_ifp;
}

void *
gpc_rlset_get_owner(struct gpc_rlset const *gprs)
{
	return gprs->gprs_owner;
}

bool
gpc_rlset_is_ingress(struct gpc_rlset const *gprs)
{
	return gprs->gprs_flags & GPC_RSF_IN;
}

bool
gpc_rlset_is_if_created(struct gpc_rlset const *gprs)
{
	return gprs->gprs_flags & GPC_RSF_IF_CREATED;
}

/* -- ruleset manipulators -- */

void
gpc_rlset_set_if_created(struct gpc_rlset *gprs)
{
	gprs->gprs_flags |= GPC_RSF_IF_CREATED;
}

static void
gpc_rlset_clear_if_created(struct gpc_rlset *gprs)
{
	gprs->gprs_flags &= ~GPC_RSF_IF_CREATED;
}

bool
gpc_rlset_set_ifp(struct gpc_rlset *gprs)
{
	struct ifnet *iface = dp_ifnet_byifname(gprs->gprs_ifname);
	if (!iface)
		return false;

	gprs->gprs_ifp = iface;
	if (iface->if_created)
		gpc_rlset_set_if_created(gprs);

	return true;
}

void
gpc_rlset_clear_ifp(struct gpc_rlset *gprs)
{
	gprs->gprs_ifp = NULL;
	gpc_rlset_clear_if_created(gprs);
}

/* -- ruleset DB walk -- */

struct gpc_rlset *
gpc_rlset_first(void)
{
	return TAILQ_FIRST(&att_rlsets);
}

struct gpc_rlset *
gpc_rlset_next(struct gpc_rlset const *cursor)
{
	return TAILQ_NEXT(cursor, gprs_list);
}

/* -- ruleset DB manipulation -- */

void
gpc_rlset_delete(struct gpc_rlset *gprs)
{
	TAILQ_REMOVE(&att_rlsets, gprs, gprs_list);
	gprs->gprs_owner = NULL;
	free(gprs);
}

struct gpc_rlset *
gpc_rlset_create(bool ingress, char const *if_name, void *owner)
{
	struct gpc_rlset *gprs = calloc(1, sizeof(*gprs));
	if (!gprs)
		return NULL;

	gprs->gprs_flags = ingress ? GPC_RSF_IN : 0;
	gprs->gprs_ifname = if_name;
	gprs->gprs_ifp = NULL;
	gprs->gprs_owner = owner;
	TAILQ_INIT(&gprs->gprs_groups);

	gpc_rlset_set_ifp(gprs);

	TAILQ_INSERT_TAIL(&att_rlsets, gprs, gprs_list);

	return gprs;
}

/* -- group accessors -- */

char const *
gpc_group_get_name(struct gpc_group const *gprg)
{
	return gprg->gprg_rgname;
}

struct gpc_rlset *
gpc_group_get_rlset(struct gpc_group const *gprg)
{
	return gprg->gprg_rlset;
}

void *
gpc_group_get_owner(struct gpc_group const *gprg)
{
	return gprg->gprg_owner;
}

uint32_t
gpc_group_get_summary(struct gpc_group const *gprg)
{
	return gprg->gprg_summary;
}

bool
gpc_group_has_family(struct gpc_group const *gprg)
{
	return gprg->gprg_flags & GPC_RGF_FAMILY;
}

bool
gpc_group_is_v6(struct gpc_group const *gprg)
{
	return gprg->gprg_flags & GPC_RGF_V6;
}

bool
gpc_group_is_ingress(struct gpc_group const *gprg)
{
	return gpc_rlset_is_ingress(gprg->gprg_rlset);
}

bool
gpc_group_is_published(struct gpc_group const *gprg)
{
	return gprg->gprg_flags & GPC_RGF_PUBLISHED;
}

bool
gpc_group_is_ll_created(struct gpc_group const *gprg)
{
	return gprg->gprg_flags & GPC_RGF_LL_CREATED;
}

bool
gpc_group_is_attached(struct gpc_group const *gprg)
{
	return gprg->gprg_flags & GPC_RGF_ATTACHED;
}

bool
gpc_group_is_ll_attached(struct gpc_group const *gprg)
{
	return gprg->gprg_flags & GPC_RGF_LL_ATTACHED;
}

bool
gpc_group_is_deferred(struct gpc_group const *gprg)
{
	return gprg->gprg_flags & GPC_RGF_DEFERRED;
}

uintptr_t
gpc_group_get_objid(struct gpc_group const *gprg)
{
	return gprg->gprg_objid;
}

/* -- group manipulators -- */

void
gpc_group_clear_family(struct gpc_group *gprg)
{
	gprg->gprg_flags &= ~(GPC_RGF_FAMILY|GPC_RGF_V6);
}

void
gpc_group_set_v4(struct gpc_group *gprg)
{
	gprg->gprg_flags |= GPC_RGF_FAMILY;
	gprg->gprg_flags &= ~GPC_RGF_V6;
}

void
gpc_group_set_v6(struct gpc_group *gprg)
{
	gprg->gprg_flags |= (GPC_RGF_FAMILY|GPC_RGF_V6);
}

static void
gpc_group_set_published(struct gpc_group *gprg)
{
	gprg->gprg_flags |= GPC_RGF_PUBLISHED;
}

static void
gpc_group_clear_published(struct gpc_group *gprg)
{
	gprg->gprg_flags &= ~GPC_RGF_PUBLISHED;
}

static void
gpc_group_set_ll_created(struct gpc_group *gprg)
{
	gprg->gprg_flags |= GPC_RGF_LL_CREATED;
}

static void
gpc_group_clear_ll_created(struct gpc_group *gprg)
{
	gprg->gprg_flags &= ~GPC_RGF_LL_CREATED;
}

static void
gpc_group_set_attached(struct gpc_group *gprg)
{
	gprg->gprg_flags |= GPC_RGF_ATTACHED;
}

static void
gpc_group_clear_attached(struct gpc_group *gprg)
{
	gprg->gprg_flags &= ~GPC_RGF_ATTACHED;
}

static void
gpc_group_set_ll_attached(struct gpc_group *gprg)
{
	gprg->gprg_flags |= GPC_RGF_LL_ATTACHED;
}

static void
gpc_group_clear_ll_attached(struct gpc_group *gprg)
{
	gprg->gprg_flags &= ~GPC_RGF_LL_ATTACHED;
}

void
gpc_group_set_deferred(struct gpc_group *gprg)
{
	gprg->gprg_flags |= GPC_RGF_DEFERRED;
}

void
gpc_group_clear_deferred(struct gpc_group *gprg)
{
	gprg->gprg_flags &= ~GPC_RGF_DEFERRED;
}

void
gpc_group_set_objid(struct gpc_group *gprg, uintptr_t objid)
{
	gprg->gprg_objid = objid;
}

/* -- group DB walk -- */

struct gpc_group *
gpc_group_first(struct gpc_rlset const *gprs)
{
	return TAILQ_FIRST(&gprs->gprs_groups);
}

struct gpc_group *
gpc_group_next(struct gpc_group const *cursor)
{
	return TAILQ_NEXT(cursor, gprg_list);
}

/* -- group DB manipulation -- */

void
gpc_group_delete(struct gpc_group *gprg)
{
	struct gpc_rlset *gprs = gprg->gprg_rlset;

	TAILQ_REMOVE(&gprs->gprs_groups, gprg, gprg_list);
	gprg->gprg_owner = NULL;
	free(gprg);
}

struct gpc_group *
gpc_group_create(struct gpc_rlset *gprs, char const *rg_name, void *owner)
{
	struct gpc_group *gprg = calloc(1, sizeof(*gprg));
	if (!gprg)
		return NULL;

	gprg->gprg_owner = owner;
	gprg->gprg_rlset = gprs;
	gprg->gprg_rgname = rg_name;
	gprg->gprg_summary = 0;
	gprg->gprg_flags = 0;

	TAILQ_INSERT_TAIL(&gprs->gprs_groups, gprg, gprg_list);

	return gprg;
}

/* -- group hardware notify -- */

void
gpc_group_hw_ntfy_create(struct gpc_group *gprg, struct pmf_rule *rule)
{
	if (gpc_group_is_published(gprg))
		return;
	if (!gpc_group_has_family(gprg))
		return;
	if (gpc_group_is_deferred(gprg))
		return;

	/* Recalculate summary before publish */
	uint32_t summary = pmf_arlg_recalc_summary(gprg->gprg_owner, rule);
	gprg->gprg_summary = summary;

	if (pmf_hw_group_create(gprg))
		gpc_group_set_ll_created(gprg);

	gpc_group_set_published(gprg);
}

void
gpc_group_hw_ntfy_delete(struct gpc_group *gprg)
{
	if (!gpc_group_is_published(gprg))
		return;

	pmf_hw_group_delete(gprg);

	/* Rules summary cleared to optimise rule delete */
	gprg->gprg_summary = 0;

	gpc_group_clear_ll_created(gprg);
	gpc_group_clear_published(gprg);
}

void
gpc_group_hw_ntfy_modify(struct gpc_group *gprg, uint32_t new)
{
	if (!gpc_group_is_published(gprg))
		return;

	if (new == gprg->gprg_summary)
		return;

	pmf_hw_group_mod(gprg, new);

	gprg->gprg_summary = new;
}

void
gpc_group_hw_ntfy_attach(struct gpc_group *gprg)
{
	if (!gpc_group_is_published(gprg))
		return;
	if (gpc_group_is_deferred(gprg))
		return;
	if (gpc_group_is_attached(gprg))
		return;

	struct gpc_rlset *gprs = gprg->gprg_rlset;

	struct ifnet *att_ifp = gpc_rlset_get_ifp(gprs);
	if (!att_ifp || !gpc_rlset_is_if_created(gprs))
		return;

	if (pmf_hw_group_attach(gprg, att_ifp))
		gpc_group_set_ll_attached(gprg);

	gpc_group_set_attached(gprg);
}

void
gpc_group_hw_ntfy_detach(struct gpc_group *gprg)
{
	if (!gpc_group_is_published(gprg))
		return;
	if (!gpc_group_is_attached(gprg))
		return;

	struct gpc_rlset *gprs = gprg->gprg_rlset;
	struct ifnet *att_ifp = gpc_rlset_get_ifp(gprs);

	pmf_hw_group_detach(gprg, att_ifp);

	gpc_group_clear_ll_attached(gprg);
	gpc_group_clear_attached(gprg);
}


/* -- counter accessors -- */

struct gpc_group *
gpc_cntr_get_group(struct gpc_cntr const *ark)
{
	return pmf_arlg_cntr_get_grp((struct pmf_cntr const *)ark);
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
	return pmf_arlg_attrl_get_grp((struct pmf_attrl const *)arl);
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

