/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <sys/queue.h>		/* TAILQ macros */
#include <rte_debug.h>

#include "compiler.h"
#include "vplane_log.h"
#include "if_var.h"

#include "npf/config/gpc_cntr_query.h"
#include "npf/config/gpc_db_control.h"
#include "npf/config/gpc_db_query.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/config/pmf_rule.h"
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
	TAILQ_HEAD(gpc_rlqh, gpc_rule) gprg_rules;
	void			*gprg_owner;	/* weak */
	struct gpc_rlset	*gprg_rlset;
	enum gpc_feature	gprg_feature;
	char const		*gprg_rgname;	/* weak */
	uintptr_t		gprg_objid;	/* FAL object */
	uint32_t		gprg_summary;
	uint32_t		gprg_flags;
};


/* -- rule -- */

enum gpc_rl_flags {
	GPC_RLF_PUBLISHED	= (1 << 0),
	GPC_RLF_LL_CREATED	= (1 << 1),
};

struct gpc_rule {
	TAILQ_ENTRY(gpc_rule)	gprl_list;
	void			*gprl_owner;	/* weak */
	struct gpc_group	*gprl_group;
	struct pmf_rule		*gprl_rule;
	uintptr_t		gprl_objid;	/* FAL object */
	uint16_t		gprl_index;
	uint16_t		gprl_flags;
};

/* -- locals -- */

static TAILQ_HEAD(, gpc_rlset) att_rlsets
	= TAILQ_HEAD_INITIALIZER(att_rlsets);

/* -- feature utility -- */

char const *
gpc_feature_get_name(enum gpc_feature feat)
{
	switch (feat) {
	case GPC_FEAT_ACL:
		return "ACL";
	case GPC_FEAT_QOS:
		return "QOS";
	default:
		return "Error";
	}
}

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

enum gpc_feature
gpc_group_get_feature(struct gpc_group const *gprg)
{
	return gprg->gprg_feature;
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

/* -- group DB misc -- */

/*
 * Recalculate this after a difficult change, generally
 * a rule deletion, or rule change.
 */
uint32_t
gpc_group_recalc_summary(struct gpc_group *gprg, struct pmf_rule *rule)
{
	uint32_t group_summary = 0;

#define RLATTR_SUMMARY_MASK (PMF_RMS_IP_FAMILY|PMF_RAS_COUNT_DEF| \
	PMF_SUMMARY_COUNT_DEF_NAMED_FLAGS)
	if (rule)
		group_summary |= rule->pp_summary & RLATTR_SUMMARY_MASK;

	struct gpc_rule *gprl;
	TAILQ_FOREACH(gprl, &gprg->gprg_rules, gprl_list)
		group_summary |= gprl->gprl_rule->pp_summary;

	return group_summary;
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
gpc_group_create(struct gpc_rlset *gprs, enum gpc_feature feat,
		 char const *rg_name, void *owner)
{
	struct gpc_group *gprg = calloc(1, sizeof(*gprg));
	if (!gprg)
		return NULL;

	gprg->gprg_owner = owner;
	gprg->gprg_rlset = gprs;
	gprg->gprg_feature = feat;
	gprg->gprg_rgname = rg_name;
	TAILQ_INIT(&gprg->gprg_rules);
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
	uint32_t summary = gpc_group_recalc_summary(gprg, rule);
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

/* -- group hardware notify of multiple rules -- */

/*
 * For a group, notify creation or deletion of all rules.
 *
 * These are used for deferred notifications based upon the
 * change in the group status.
 */
void
gpc_group_hw_ntfy_rules_create(struct gpc_group *gprg)
{
	if (!gpc_group_is_published(gprg))
		return;

	struct gpc_rule *gprl;
	TAILQ_FOREACH(gprl, &gprg->gprg_rules, gprl_list)
		gpc_rule_hw_ntfy_create(gprg, gprl);
}

void
gpc_group_hw_ntfy_rules_delete(struct gpc_group *gprg)
{
	if (!gpc_group_is_published(gprg))
		return;

	struct gpc_rule *gprl;
	TAILQ_FOREACH(gprl, &gprg->gprg_rules, gprl_list)
		gpc_rule_hw_ntfy_delete(gprg, gprl);
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
gpc_rule_get_index(struct gpc_rule const *gprl)
{
	return gprl->gprl_index;
}

struct pmf_rule *
gpc_rule_get_rule(struct gpc_rule const *gprl)
{
	return gprl->gprl_rule;
}

struct gpc_group *
gpc_rule_get_group(struct gpc_rule const *gprl)
{
	return gprl->gprl_group;
}

void *
gpc_rule_get_owner(struct gpc_rule const *gprl)
{
	return gprl->gprl_owner;
}

struct gpc_cntr *
gpc_rule_get_cntr(struct gpc_rule *gprl)
{
	struct pmf_cntr *eark
		= pmf_arlg_attrl_get_cntr(gprl->gprl_owner);
	return (struct gpc_cntr *)eark;
}

uintptr_t
gpc_rule_get_objid(struct gpc_rule const *gprl)
{
	return gprl->gprl_objid;
}

bool
gpc_rule_is_published(struct gpc_rule const *gprl)
{
	return gprl->gprl_flags & GPC_RLF_PUBLISHED;
}

bool
gpc_rule_is_ll_created(struct gpc_rule const *gprl)
{
	return gprl->gprl_flags & GPC_RLF_LL_CREATED;
}

/* -- rule manipulators -- */

static void
gpc_rule_set_published(struct gpc_rule *gprl)
{
	gprl->gprl_flags |= GPC_RLF_PUBLISHED;
}

static void
gpc_rule_clear_published(struct gpc_rule *gprl)
{
	gprl->gprl_flags &= ~GPC_RLF_PUBLISHED;
}

static void
gpc_rule_set_ll_created(struct gpc_rule *gprl)
{
	gprl->gprl_flags |= GPC_RLF_LL_CREATED;
}

static void
gpc_rule_clear_ll_created(struct gpc_rule *gprl)
{
	gprl->gprl_flags &= ~GPC_RLF_LL_CREATED;
}

void
gpc_rule_set_objid(struct gpc_rule *gprl, uintptr_t objid)
{
	gprl->gprl_objid = objid;
}

/* -- rule DB walk -- */

struct gpc_rule *
gpc_rule_first(struct gpc_group const *gprg)
{
	return TAILQ_FIRST(&gprg->gprg_rules);
}

struct gpc_rule *
gpc_rule_last(struct gpc_group const *gprg)
{
	return TAILQ_LAST(&gprg->gprg_rules, gpc_rlqh);
}

struct gpc_rule *
gpc_rule_next(struct gpc_rule const *cursor)
{
	return TAILQ_NEXT(cursor, gprl_list);
}

/* -- rule DB lookup -- */

static struct gpc_rule *
gpc_rule_find_core(struct gpc_group *gprg, uint32_t rl_idx, bool insert)
{
	struct gpc_rule *cursor;

	TAILQ_FOREACH(cursor, &gprg->gprg_rules, gprl_list)
		if (rl_idx <= cursor->gprl_index)
			break;

	if (!cursor)
		return NULL;

	if (rl_idx == cursor->gprl_index || insert)
		return cursor;

	return NULL;
}

static struct gpc_rule *
gpc_rule_find_insertion(struct gpc_group *gprg, uint32_t index)
{
	return gpc_rule_find_core(gprg, index, true);
}

struct gpc_rule *
gpc_rule_find(struct gpc_group *gprg, uint32_t index)
{
	return gpc_rule_find_core(gprg, index, false);
}

/* -- rule DB manipulation -- */

void
gpc_rule_change_rule(struct gpc_rule *gprl, struct pmf_rule *new_rule)
{
	if (!gprl)
		return;

	struct gpc_group *gprg = gprl->gprl_group;

	/* If any were published, update and notify */
	uint32_t old_summary = gpc_group_get_summary(gprg);
	uint32_t new_summary = old_summary | new_rule->pp_summary;
	gpc_group_hw_ntfy_modify(gprg, new_summary);

	/* Update the rule criteria now */

	struct pmf_rule *old_rule = gprl->gprl_rule;

	gprl->gprl_rule = pmf_rule_copy(new_rule);

	gpc_rule_hw_ntfy_modify(gprg, gprl, old_rule);

	pmf_rule_free(old_rule);
}

void
gpc_rule_delete(struct gpc_rule *gprl)
{
	struct gpc_group *gprg = gprl->gprl_group;

	TAILQ_REMOVE(&gprg->gprg_rules, gprl, gprl_list);
	gprl->gprl_owner = NULL;

	pmf_rule_free(gprl->gprl_rule);
	free(gprl);
}

struct gpc_rule *
gpc_rule_create(struct gpc_group *gprg, uint32_t rl_idx, void *owner)
{
	struct gpc_rule *gprl = calloc(1, sizeof(*gprl));
	if (!gprl)
		return NULL;

	gprl->gprl_owner = owner;
	gprl->gprl_group = gprg;
	gprl->gprl_rule = NULL;
	gprl->gprl_index = rl_idx;
	gprl->gprl_flags = 0;

	struct gpc_rule *cursor = TAILQ_LAST(&gprg->gprg_rules, gpc_rlqh);
	if (!cursor || cursor->gprl_index < rl_idx) {
		TAILQ_INSERT_TAIL(&gprg->gprg_rules, gprl, gprl_list);
	} else {
		cursor = gpc_rule_find_insertion(gprg, rl_idx);

		/* Never NULL, do not allow duplicates */
		if (!cursor || rl_idx == cursor->gprl_index) {
			struct gpc_rlset *gprs = gprg->gprg_rlset;
			bool dir_in = gpc_rlset_is_ingress(gprs);
			RTE_LOG(ERR, FIREWALL,
				"Error: No insertion point for GPC rule"
				" %s/%s|%s:%u\n",
				(dir_in) ? " In" : "Out",
				gpc_rlset_get_ifname(gprs),
				gpc_group_get_name(gprg), rl_idx);
			free(gprl);
			return NULL;
		}

		TAILQ_INSERT_BEFORE(cursor, gprl, gprl_list);
	}

	return gprl;
}
/* -- rule hardware notify -- */

void
gpc_rule_hw_ntfy_create(struct gpc_group *gprg, struct gpc_rule *gprl)
{
	if (!gpc_group_is_published(gprg))
		return;
	if (gpc_rule_is_published(gprl))
		return;

	/* These counter related lines need to move */
	struct pmf_group_ext *earg = gpc_group_get_owner(gprg);

	pmf_arlg_hw_ntfy_cntr_add(earg, gpc_rule_get_owner(gprl));

	if (pmf_hw_rule_add(gprl))
		gpc_rule_set_ll_created(gprl);

	gpc_rule_set_published(gprl);
}

void
gpc_rule_hw_ntfy_modify(struct gpc_group *gprg, struct gpc_rule *gprl,
			struct pmf_rule *old_rule)
{
	if (!gpc_group_is_published(gprg))
		return;
	if (!gpc_rule_is_published(gprl)) {
		gpc_rule_hw_ntfy_create(gprg, gprl);
		return;
	}

	pmf_hw_rule_mod(gprl, old_rule);
}

void
gpc_rule_hw_ntfy_delete(struct gpc_group *gprg, struct gpc_rule *gprl)
{
	if (!gpc_group_is_published(gprg))
		return;
	if (!gpc_rule_is_published(gprl))
		return;

	pmf_hw_rule_del(gprl);

	gpc_rule_clear_ll_created(gprl);
	gpc_rule_clear_published(gprl);

	/* These counter related lines need to move */
	struct pmf_group_ext *earg = gpc_group_get_owner(gprg);

	pmf_arlg_hw_ntfy_cntr_del(earg, gpc_rule_get_owner(gprl));
}

