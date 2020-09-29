/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/queue.h>		/* TAILQ macros */
#include <rte_debug.h>

#include "compiler.h"
#include "vplane_log.h"
#include "if_var.h"

#include "npf/config/pmf_rule.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/pmf_hw.h"
#include "dp_event.h"

#define CNTR_NAME_LEN	8

enum pmf_eark_flags {
	PMF_EARKF_PUBLISHED	= (1 << 0),
	PMF_EARKF_LL_CREATED	= (1 << 1),
	PMF_EARKF_CNT_PACKET	= (1 << 2),
	PMF_EARKF_CNT_BYTE	= (1 << 3),
	PMF_EARKF_TYPE_NAMED	= (1 << 4),
};

struct pmf_cntr {
	TAILQ_ENTRY(pmf_cntr)	eark_list;
	struct pmf_group_ext	*eark_group;
	char			eark_name[CNTR_NAME_LEN];
	uintptr_t		eark_objid;	/* FAL object */
	uint16_t		eark_flags;
	uint16_t		eark_refcount;
};

enum pmf_earl_flags {
	PMF_EARLF_PUBLISHED	= (1 << 0),
	PMF_EARLF_LL_CREATED	= (1 << 1),
};

struct pmf_attrl {
	TAILQ_ENTRY(pmf_attrl)	earl_list;
	struct pmf_group_ext	*earl_group;
	struct pmf_rule		*earl_rule;
	struct pmf_cntr		*earl_cntr;
	uintptr_t		earl_objid;	/* FAL object */
	uint16_t		earl_index;
	uint16_t		earl_flags;
};

enum pmf_earg_flags {
	PMF_EARGF_PUBLISHED	= (1 << 0),
	PMF_EARGF_ATTACHED	= (1 << 1),
	PMF_EARGF_DEFERRED	= (1 << 3),
	PMF_EARGF_RULE_ATTR	= (1 << 4),
	PMF_EARGF_FAMILY	= (1 << 5),
	PMF_EARGF_V6		= (1 << 6),
	PMF_EARGF_LL_CREATED	= (1 << 7),
	PMF_EARGF_LL_ATTACHED	= (1 << 8),
};

struct pmf_group_ext {
	TAILQ_ENTRY(pmf_group_ext) earg_list;
	TAILQ_HEAD(pmf_rlqh, pmf_attrl) earg_rules;
	TAILQ_HEAD(pmf_cnqh, pmf_cntr) earg_cntrs;
	struct npf_attpt_group	*earg_base;
	struct pmf_rlset_ext	*earg_rlset;
	struct pmf_attrl	*earg_rlattr;
	char const		*earg_rgname;	/* weak */
	uintptr_t		earg_objid;	/* FAL object */
	uint32_t		earg_summary;
	uint32_t		earg_num_rules;
	uint32_t		earg_flags;
};

enum pmf_ears_flags {
	PMF_EARSF_IN		= (1 << 0),
	PMF_EARSF_IFP		= (1 << 1),
	PMF_EARSF_IF_CREATED	= (1 << 2),
};

struct pmf_rlset_ext {
	TAILQ_ENTRY(pmf_rlset_ext) ears_list;
	TAILQ_HEAD(, pmf_group_ext) ears_groups;
	struct npf_attpt_rlset	*ears_base;
	char const		*ears_ifname;	/* weak */
	struct ifnet		*ears_ifp;
	uint32_t		ears_flags;
};

/* ---- */

static TAILQ_HEAD(, pmf_rlset_ext) att_rlsets
	= TAILQ_HEAD_INITIALIZER(att_rlsets);

static bool deferrals;

static bool commit_pending;

/* ---- */

uint16_t
pmf_arlg_attrl_get_index(struct pmf_attrl const *earl)
{
	return earl->earl_index;
}

struct pmf_group_ext *
pmf_arlg_attrl_get_grp(struct pmf_attrl const *earl)
{
	return earl->earl_group;
}

struct pmf_cntr *
pmf_arlg_attrl_get_cntr(struct pmf_attrl *earl)
{
	struct pmf_cntr *eark = earl->earl_cntr;
	if (!eark)
		return NULL;

	if (!(eark->eark_flags & PMF_EARKF_PUBLISHED))
		return NULL;

	return eark;
}

uintptr_t
pmf_arlg_attrl_get_objid(struct pmf_attrl const *earl)
{
	return earl->earl_objid;
}

void
pmf_arlg_attrl_set_objid(struct pmf_attrl *earl, uintptr_t objid)
{
	earl->earl_objid = objid;
}

struct pmf_group_ext *
pmf_arlg_cntr_get_grp(struct pmf_cntr const *eark)
{
	return eark->eark_group;
}

uintptr_t
pmf_arlg_cntr_get_objid(struct pmf_cntr const *eark)
{
	if (!eark)
		return 0;

	return eark->eark_objid;
}

void
pmf_arlg_cntr_set_objid(struct pmf_cntr *eark, uintptr_t objid)
{
	eark->eark_objid = objid;
}

char const *
pmf_arlg_cntr_get_name(struct pmf_cntr const *eark)
{
	return eark->eark_name;
}

bool
pmf_arlg_cntr_pkt_enabled(struct pmf_cntr const *eark)
{
	return (eark->eark_flags & PMF_EARKF_CNT_PACKET);
}

bool
pmf_arlg_cntr_byt_enabled(struct pmf_cntr const *eark)
{
	return (eark->eark_flags & PMF_EARKF_CNT_BYTE);
}

/*
 * Returns true if the group has named counters (e.g. auto-per-action).
 */
static bool
pmf_arlg_cntr_type_named(struct pmf_group_ext const *earg)
{
	if (earg->earg_summary & PMF_RAS_COUNT_DEF)
		return (earg->earg_summary & PMF_SUMMARY_COUNT_DEF_NAMED_FLAGS);
	return false;
}

/*
 * Returns true if the group has numbered counters (auto-per-rule).
 */
static bool
pmf_arlg_cntr_type_numbered(struct pmf_group_ext const *earg)
{
	if (earg->earg_summary & PMF_RAS_COUNT_DEF)
		return !pmf_arlg_cntr_type_named(earg);
	return false;
}

/*
 * Returns true if the auto-per-action group has action "accept" counters.
 */
static bool
pmf_arlg_cntr_type_named_accept(struct pmf_group_ext const *earg)
{
	if (earg->earg_summary & PMF_RAS_COUNT_DEF)
		return (earg->earg_summary & PMF_RAS_COUNT_DEF_PASS);
	return false;
}

/*
 * Returns true if the auto-per-action group has action "drop" counters.
 */
static bool
pmf_arlg_cntr_type_named_drop(struct pmf_group_ext const *earg)
{
	if (earg->earg_summary & PMF_RAS_COUNT_DEF)
		return (earg->earg_summary & PMF_RAS_COUNT_DEF_DROP);
	return false;
}

static struct pmf_cntr *
pmf_arlg_find_cntr(struct pmf_group_ext *earg, const char *name)
{
	struct pmf_cntr *eark;

	TAILQ_FOREACH(eark, &earg->earg_cntrs, eark_list)
		if (strcmp(name, eark->eark_name) == 0)
			return eark;

	return NULL;
}

static void
pmf_arlg_cntr_refcount_inc(struct pmf_cntr *eark)
{
	eark->eark_refcount++;
}

/*
 * Decrements the number of users of the counter.
 * Returns true if the counter still has users left.
 */
static bool
pmf_arlg_cntr_refcount_dec(struct pmf_cntr *eark)
{
	if (--eark->eark_refcount > 0)
		return true;

	return false;
}

static struct pmf_cntr *
pmf_arlg_alloc_cntr(struct pmf_group_ext *earg, const char *name)
{
	struct pmf_cntr *eark;

	eark = calloc(1, sizeof(*eark));
	if (!eark) {
		RTE_LOG(ERR, FIREWALL,
			"Error: OOM for counter %s\n", name);
		return NULL;
	}
	snprintf(eark->eark_name, sizeof(eark->eark_name), "%s", name);
	TAILQ_INSERT_HEAD(&earg->earg_cntrs, eark, eark_list);

	return eark;
}

static void
pmf_arlg_free_cntr(struct pmf_group_ext *earg, struct pmf_cntr *eark)
{
	if (!earg || !eark)
		return;

	TAILQ_REMOVE(&earg->earg_cntrs, eark, eark_list);
	free(eark);
}

static struct pmf_cntr *
pmf_arlg_get_or_alloc_cntr(struct pmf_group_ext *earg, const char *name)
{
	struct pmf_cntr *eark;

	if (!earg || !name)
		return NULL;

	eark = pmf_arlg_find_cntr(earg, name);

	if (!eark) {
		eark = pmf_arlg_alloc_cntr(earg, name);
		if (!eark)
			return NULL;
	}

	pmf_arlg_cntr_refcount_inc(eark);

	return eark;
}

static struct pmf_cntr *
pmf_arlg_alloc_numbered_cntr(struct pmf_group_ext *earg, struct pmf_attrl *earl)
{
	char eark_name[CNTR_NAME_LEN];
	struct pmf_cntr *eark;

	if (!earg || !earl)
		return NULL;

	snprintf(eark_name, sizeof(eark_name), "%u", earl->earl_index);
	if (pmf_arlg_find_cntr(earg, eark_name)) {
		RTE_LOG(ERR, FIREWALL,
			"Error: Attempt to alloc numbered counter that already exists (%d)\n",
			earl->earl_index);
		return NULL;
	}

	eark = pmf_arlg_alloc_cntr(earg, eark_name);
	if (!eark)
		return NULL;

	pmf_arlg_cntr_refcount_inc(eark);

	return eark;
}

static struct pmf_cntr *
pmf_arlg_get_or_alloc_named_cntr(struct pmf_group_ext *earg, const char *name)
{
	struct pmf_cntr *eark;

	eark = pmf_arlg_get_or_alloc_cntr(earg, name);
	if (!eark)
		return NULL;

	/* Is it a new counter? */
	if (!(eark->eark_flags & PMF_EARKF_PUBLISHED))
		eark->eark_flags |= PMF_EARKF_TYPE_NAMED;

	return eark;
}

static struct pmf_cntr *
pmf_arlg_get_or_alloc_action_cntr_accept(struct pmf_group_ext *earg)
{
	return pmf_arlg_get_or_alloc_named_cntr(earg, "accept");
}

static struct pmf_cntr *
pmf_arlg_get_or_alloc_action_cntr_drop(struct pmf_group_ext *earg)
{
	return pmf_arlg_get_or_alloc_named_cntr(earg, "drop");
}

char const *
pmf_arlg_grp_get_name(struct pmf_group_ext const *earg)
{
	return earg->earg_rgname;
}

struct pmf_rlset_ext *
pmf_arlg_grp_get_rls(struct pmf_group_ext const *earg)
{
	return earg->earg_rlset;
}

uint32_t
pmf_arlg_grp_get_summary(struct pmf_group_ext const *earg)
{
	return earg->earg_summary;
}

bool
pmf_arlg_grp_is_v6(struct pmf_group_ext const *earg)
{
	bool is_v6 = (earg->earg_flags & PMF_EARGF_V6);

	return is_v6;
}

bool
pmf_arlg_grp_is_ingress(struct pmf_group_ext const *earg)
{
	struct pmf_rlset_ext *ears = earg->earg_rlset;

	bool is_ingress = (ears->ears_flags & PMF_EARSF_IN);

	return is_ingress;
}

bool
pmf_arlg_grp_is_ll_attached(struct pmf_group_ext const *earg)
{
	bool ll_attached = (earg->earg_flags & PMF_EARGF_LL_ATTACHED);

	return ll_attached;
}

uintptr_t
pmf_arlg_grp_get_objid(struct pmf_group_ext const *earg)
{
	return earg->earg_objid;
}

void
pmf_arlg_grp_set_objid(struct pmf_group_ext *earg, uintptr_t objid)
{
	earg->earg_objid = objid;
}

char const *
pmf_arlg_rls_get_ifname(struct pmf_rlset_ext const *ears)
{
	return ears->ears_ifname;
}

/* ---- */

/*
 * Recalculate this after a difficult change, generally
 * a rule deletion, or rule change.
 */
static uint32_t
pmf_arlg_recalc_summary(struct pmf_group_ext *earg, struct pmf_rule *rule)
{
	uint32_t group_summary = 0;

#define RLATTR_SUMMARY_MASK (PMF_RMS_IP_FAMILY|PMF_RAS_COUNT_DEF| \
	PMF_SUMMARY_COUNT_DEF_NAMED_FLAGS)
	if (rule)
		group_summary |= rule->pp_summary & RLATTR_SUMMARY_MASK;

	struct pmf_attrl *earl;
	TAILQ_FOREACH(earl, &earg->earg_rules, earl_list)
		group_summary |= earl->earl_rule->pp_summary;

	return group_summary;
}

/* ---- */

static void
pmf_alrg_hw_ntfy_grp_create(struct pmf_group_ext *earg, struct pmf_rule *rule)
{
	if (earg->earg_flags & PMF_EARGF_PUBLISHED)
		return;
	if (!(earg->earg_flags & PMF_EARGF_FAMILY))
		return;
	if (earg->earg_flags & PMF_EARGF_DEFERRED)
		return;

	/* Recalculate summary before publish */
	uint32_t summary = pmf_arlg_recalc_summary(earg, rule);
	earg->earg_summary = summary;

	if (pmf_hw_group_create(earg))
		earg->earg_flags |= PMF_EARGF_LL_CREATED;

	earg->earg_flags |= PMF_EARGF_PUBLISHED;
}

static void
pmf_alrg_hw_ntfy_grp_delete(struct pmf_group_ext *earg)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;

	pmf_hw_group_delete(earg);

	/* Rules summary cleared to optimise rule delete */
	earg->earg_summary = 0;

	earg->earg_flags &= ~(PMF_EARGF_PUBLISHED|PMF_EARGF_LL_CREATED);
}

static void
pmf_alrg_hw_ntfy_grp_summary_mod(struct pmf_group_ext *earg, uint32_t new)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;

	if (new == earg->earg_summary)
		return;

	pmf_hw_group_mod(earg, new);

	earg->earg_summary = new;
}

static void
pmf_alrg_hw_ntfy_grp_attach(struct pmf_group_ext *earg)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;
	if (earg->earg_flags & PMF_EARGF_DEFERRED)
		return;
	if (earg->earg_flags & PMF_EARGF_ATTACHED)
		return;

	struct pmf_rlset_ext *ears = earg->earg_rlset;
	if (!(ears->ears_flags & PMF_EARSF_IFP))
		return;
	if (!(ears->ears_flags & PMF_EARSF_IF_CREATED))
		return;

	if (pmf_hw_group_attach(earg, ears->ears_ifp))
		earg->earg_flags |= PMF_EARGF_LL_ATTACHED;

	earg->earg_flags |= PMF_EARGF_ATTACHED;
}

static void
pmf_alrg_hw_ntfy_grp_detach(struct pmf_group_ext *earg)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;
	if (!(earg->earg_flags & PMF_EARGF_ATTACHED))
		return;

	struct pmf_rlset_ext *ears = earg->earg_rlset;

	pmf_hw_group_detach(earg, ears->ears_ifp);

	earg->earg_flags &= ~(PMF_EARGF_ATTACHED|PMF_EARGF_LL_ATTACHED);
}

static void
pmf_arlg_hw_ntfy_cntr_add(struct pmf_group_ext *earg, struct pmf_attrl *earl)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;

	if (!(earl->earl_rule->pp_summary & PMF_RAS_COUNT_REF))
		return;

	struct pmf_cntr *eark = NULL;

	if (pmf_arlg_cntr_type_numbered(earg)) {
		/* Counter type: auto-per-rule: */
		eark = pmf_arlg_alloc_numbered_cntr(earg, earl);
		if (!eark)
			return;
		earl->earl_cntr = eark;
	} else if (pmf_arlg_cntr_type_named(earg)) {
		/* Counter type: auto-per-action: */

		/* Rule's action should have a counter? */
		if (pmf_arlg_cntr_type_named_accept(earg) &&
		    (earl->earl_rule->pp_summary & PMF_RAS_PASS))
			eark = pmf_arlg_get_or_alloc_action_cntr_accept(earg);

		if (pmf_arlg_cntr_type_named_drop(earg) &&
		    (earl->earl_rule->pp_summary & PMF_RAS_DROP))
			eark = pmf_arlg_get_or_alloc_action_cntr_drop(earg);

		if (!eark)
			return;

		earl->earl_cntr = eark;
	} else
		return;

	if (!(eark->eark_flags & PMF_EARKF_PUBLISHED)) {
		eark->eark_group = earg;
		eark->eark_objid = 0;
		eark->eark_flags |= PMF_EARKF_CNT_PACKET;
		eark->eark_flags |= PMF_EARKF_PUBLISHED;
	}

	if (!(eark->eark_flags & PMF_EARKF_LL_CREATED))
		if (pmf_hw_counter_create(eark))
			eark->eark_flags |= PMF_EARKF_LL_CREATED;
}

static void
pmf_arlg_hw_ntfy_cntr_del(struct pmf_group_ext *earg, struct pmf_attrl *earl)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;

	struct pmf_cntr *eark = earl->earl_cntr;
	if (!eark)
		return;

	earl->earl_cntr = NULL;

	if (pmf_arlg_cntr_refcount_dec(eark))
		return;

	if (eark->eark_flags & PMF_EARKF_LL_CREATED)
		pmf_hw_counter_delete(eark);

	pmf_arlg_free_cntr(earg, eark);
}

static void
pmf_alrg_hw_ntfy_rule_add(struct pmf_group_ext *earg, struct pmf_attrl *earl)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;
	if (earl->earl_flags & PMF_EARLF_PUBLISHED)
		return;

	pmf_arlg_hw_ntfy_cntr_add(earg, earl);

	if (pmf_hw_rule_add(earl, earl->earl_rule))
		earl->earl_flags |= PMF_EARLF_LL_CREATED;

	earl->earl_flags |= PMF_EARLF_PUBLISHED;
}

static void
pmf_alrg_hw_ntfy_rule_chg(struct pmf_group_ext *earg, struct pmf_attrl *earl,
			  struct pmf_rule *new_rule)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;
	if (!(earl->earl_flags & PMF_EARLF_PUBLISHED)) {
		pmf_alrg_hw_ntfy_rule_add(earg, earl);
		return;
	}

	pmf_hw_rule_mod(earl, new_rule);
}

static void
pmf_alrg_hw_ntfy_rule_del(struct pmf_group_ext *earg, struct pmf_attrl *earl)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;
	if (!(earl->earl_flags & PMF_EARLF_PUBLISHED))
		return;

	pmf_hw_rule_del(earl);

	earl->earl_flags &= ~(PMF_EARLF_PUBLISHED|PMF_EARLF_LL_CREATED);

	pmf_arlg_hw_ntfy_cntr_del(earg, earl);
}

/* ---- */

/*
 * For a group, notify creation or deletion of all rules.
 *
 * These are used for deferred notifications based upon the
 * change in the group status.
 */
static void
pmf_alrg_hw_ntfy_rules_add(struct pmf_group_ext *earg)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;

	struct pmf_attrl *earl;

	TAILQ_FOREACH(earl, &earg->earg_rules, earl_list)
		pmf_alrg_hw_ntfy_rule_add(earg, earl);
}

static void
pmf_alrg_hw_ntfy_rules_del(struct pmf_group_ext *earg)
{
	if (!(earg->earg_flags & PMF_EARGF_PUBLISHED))
		return;

	struct pmf_attrl *earl;

	TAILQ_FOREACH(earl, &earg->earg_rules, earl_list)
		pmf_alrg_hw_ntfy_rule_del(earg, earl);
}


/* ---- */

static void
pmf_arlg_rl_free(struct pmf_attrl *earl)
{
	if (!earl)
		return;

	pmf_rule_free(earl->earl_rule);
	free(earl);
}

static void
pmf_arlg_rl_change(struct pmf_attrl *earl, struct pmf_rule *new_rule)
{
	if (!earl)
		return;

	struct pmf_rule *old_rule = earl->earl_rule;

	earl->earl_rule = pmf_rule_copy(new_rule);
	pmf_rule_free(old_rule);
}

static struct pmf_attrl *
pmf_arlg_rl_alloc(struct pmf_rule *rule, uint32_t idx)
{
	struct pmf_attrl *earl = calloc(1, sizeof(*earl));

	if (earl) {
		earl->earl_index = idx;
		earl->earl_rule = pmf_rule_copy(rule);
	}

	return earl;
}

static struct pmf_attrl *
pmf_arlg_rl_find(struct pmf_group_ext *earg, uint32_t idx, bool insert)
{
	if (idx == UINT32_MAX)
		return earg->earg_rlattr;

	struct pmf_attrl *cursor;

	TAILQ_FOREACH(cursor, &earg->earg_rules, earl_list)
		if (idx <= cursor->earl_index)
			break;

	if (!cursor)
		return NULL;

	if (idx == cursor->earl_index || insert)
		return cursor;

	return NULL;
}

/* ---- */

/*
 * Check for a change in publication status due to the group attribute rule.
 */
static void
pmf_arlg_rl_attr_check(struct pmf_group_ext *earg, struct pmf_rule *rule)
{
	struct pmf_attr_ip_family *ipfam = NULL;

	/* The group attribute rule has been removed */
	if (!rule) {
		if (!(earg->earg_flags & PMF_EARGF_RULE_ATTR))
			return;
unpublish_group:
		/* A group is only visible if it has attr rule, and a family */
		if (earg->earg_flags & PMF_EARGF_PUBLISHED) {
			pmf_alrg_hw_ntfy_grp_detach(earg);
			pmf_alrg_hw_ntfy_rules_del(earg);
			/* eventually delete counters */
			pmf_alrg_hw_ntfy_grp_delete(earg);
			/* Enable deferred republish */
			earg->earg_flags |= PMF_EARGF_DEFERRED;
			deferrals = true;
		}
		earg->earg_flags &=
			~(PMF_EARGF_RULE_ATTR|PMF_EARGF_FAMILY|PMF_EARGF_V6);
		return;
	}

	/* Have just acquired group attribute rule */
	if (!(earg->earg_flags & PMF_EARGF_RULE_ATTR)) {
		earg->earg_flags |= PMF_EARGF_RULE_ATTR;

		ipfam = (rule) ?
			rule->pp_match.l2[PMF_L2F_IP_FAMILY].pm_ipfam : NULL;
		if (!ipfam)
			return;

publish_group:
		/* semi-colon for goto target */;
		bool is_v6 = ipfam->pm_v6;
		earg->earg_flags |= PMF_EARGF_FAMILY;
		earg->earg_flags |= (is_v6) ? PMF_EARGF_V6 : 0;

		/* Now publish everything referencing the group */
		pmf_alrg_hw_ntfy_grp_create(earg, rule);
		/* eventually create counters */
		pmf_alrg_hw_ntfy_rules_add(earg);
		pmf_alrg_hw_ntfy_grp_attach(earg);

		return;
	}

	/* The group attribute rule has changed */

	/* Eventually check for counters change here */

	/* Deleting the family acts like a group removal */
	ipfam = (rule) ?
		rule->pp_match.l2[PMF_L2F_IP_FAMILY].pm_ipfam : NULL;
	if (!ipfam) {
		if (earg->earg_flags & PMF_EARGF_FAMILY)
			goto unpublish_group;
		return;
	}

	/* Just acquired a family, so acts like group creation, publish all */
	if (!(earg->earg_flags & PMF_EARGF_FAMILY))
		goto publish_group;

	/* Ensure the address family is the same */
	bool is_v6 = ipfam->pm_v6;
	if (!(earg->earg_flags & PMF_EARGF_V6) == !is_v6)
		return;

	/* The AF is different, so delete and re-add everything */

	if (earg->earg_flags & PMF_EARGF_PUBLISHED) {
		pmf_alrg_hw_ntfy_grp_detach(earg);
		pmf_alrg_hw_ntfy_rules_del(earg);
		/* eventually delete counters */
		pmf_alrg_hw_ntfy_grp_delete(earg);
	}
	earg->earg_flags &=
		~(PMF_EARGF_RULE_ATTR|PMF_EARGF_FAMILY|PMF_EARGF_V6);

	/* Now add it all back again, with new AF */
	goto publish_group;
}

/* ---- */

static bool
pmf_arlg_rl_del(struct pmf_group_ext *earg, uint32_t rl_idx)
{
	struct pmf_rlset_ext *ears = earg->earg_rlset;
	bool dir_in = (ears->ears_flags & PMF_EARSF_IN);

	struct pmf_attrl *earl = pmf_arlg_rl_find(earg, rl_idx, false);
	if (!earl) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No rule to delete for ACL attached group"
			" %s/%s|%s:%u\n",
			(dir_in) ? " In" : "Out", ears->ears_ifname,
			earg->earg_rgname, rl_idx);
		return false;
	}

	/* This rule is for group attributes */
	if (rl_idx == UINT32_MAX) {
		pmf_arlg_rl_attr_check(earg, NULL);
		earg->earg_rlattr = NULL;
		pmf_arlg_rl_free(earl);
		return true;
	}

	--earg->earg_num_rules;

	pmf_alrg_hw_ntfy_rule_del(earg, earl);

	TAILQ_REMOVE(&earg->earg_rules, earl, earl_list);
	pmf_arlg_rl_free(earl);

	/* If any were published, recalculate and notify */
	if (earg->earg_summary) {
		struct pmf_rule *attr_rule
			= (earg->earg_rlattr)
			? earg->earg_rlattr->earl_rule
			: NULL;
		uint32_t new_summary = pmf_arlg_recalc_summary(earg, attr_rule);
		pmf_alrg_hw_ntfy_grp_summary_mod(earg, new_summary);
	}

	return true;
}

static bool
pmf_arlg_rl_chg(struct pmf_group_ext *earg,
		struct pmf_rule *new_rule, uint32_t rl_idx)
{
	struct pmf_rlset_ext *ears = earg->earg_rlset;
	bool dir_in = (ears->ears_flags & PMF_EARSF_IN);

	struct pmf_attrl *earl = pmf_arlg_rl_find(earg, rl_idx, false);
	if (!earl) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No rule to change for ACL attached group"
			" %s/%s|%s:%u\n",
			(dir_in) ? " In" : "Out", ears->ears_ifname,
			earg->earg_rgname, rl_idx);
		return false;
	}

	if (rl_idx == UINT32_MAX) {
		pmf_arlg_rl_attr_check(earg, new_rule);
		pmf_arlg_rl_change(earl, new_rule);
		return true;
	}

	/* If any were published, update and notify */
	uint32_t old_summary = earg->earg_summary;
	uint32_t new_summary = old_summary | new_rule->pp_summary;
	pmf_alrg_hw_ntfy_grp_summary_mod(earg, new_summary);

	pmf_alrg_hw_ntfy_rule_chg(earg, earl, new_rule);
	pmf_arlg_rl_change(earl, new_rule);

	/* We turned on new stuff above, turn off old stuff now */
	if (old_summary) {
		struct pmf_rule *attr_rule
			= (earg->earg_rlattr)
			? earg->earg_rlattr->earl_rule
			: NULL;
		new_summary = pmf_arlg_recalc_summary(earg, attr_rule);
		pmf_alrg_hw_ntfy_grp_summary_mod(earg, new_summary);
	}

	return true;
}

static bool
pmf_arlg_rl_add(struct pmf_group_ext *earg,
		struct pmf_rule *rule, uint32_t rl_idx)
{
	struct pmf_rlset_ext *ears = earg->earg_rlset;
	bool dir_in = (ears->ears_flags & PMF_EARSF_IN);

	struct pmf_attrl *earl = pmf_arlg_rl_alloc(rule, rl_idx);
	if (!earl) {
		RTE_LOG(ERR, FIREWALL,
			"Error: OOM for ACL attached group rule"
			" %s/%s|%s:%u\n",
			(dir_in) ? " In" : "Out", ears->ears_ifname,
			earg->earg_rgname, rl_idx);
		return false;
	}

	earl->earl_group = earg;

	/* This rule is for group attributes */
	if (rl_idx == UINT32_MAX) {
		if (earg->earg_rlattr) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Dup rule 0 for ACL attached group rule"
				" %s/%s|%s\n",
				(dir_in) ? " In" : "Out", ears->ears_ifname,
				earg->earg_rgname);
			pmf_arlg_rl_free(earl);
			return false;
		}

		earg->earg_rlattr = earl;
		pmf_arlg_rl_attr_check(earg, rule);

		return true;
	}

	++earg->earg_num_rules;

	/* If any were published, update and notify */
	uint32_t new_summary = earg->earg_summary | rule->pp_summary;
	pmf_alrg_hw_ntfy_grp_summary_mod(earg, new_summary);

	pmf_alrg_hw_ntfy_rule_add(earg, earl);

	struct pmf_attrl *cursor = TAILQ_LAST(&earg->earg_rules, pmf_rlqh);
	if (!cursor || cursor->earl_index < rl_idx) {
		TAILQ_INSERT_TAIL(&earg->earg_rules, earl, earl_list);
		return true;
	}

	/* Find the element to insert in front of */
	cursor = pmf_arlg_rl_find(earg, rl_idx, true);
	if (!cursor) {
		RTE_LOG(ERR, FIREWALL,
			"Error: No insertion point for ACL attached group"
			" %s/%s|%s:%u\n",
			(dir_in) ? " In" : "Out", ears->ears_ifname,
			earg->earg_rgname, rl_idx);
		pmf_arlg_rl_free(earl);
		return false;
	}

	TAILQ_INSERT_BEFORE(cursor, earl, earl_list);

	return true;
}

/* ---- */

/*
 * The initial build of the rules in the attached rule group,
 * driven by a walk over the group definition.
 */
static bool
pmf_arlg_group_build(void *vctx, struct npf_cfg_rule_walk_state *grp)
{
	struct pmf_group_ext *earg = vctx;

	bool ok = pmf_arlg_rl_add(earg, grp->parsed, grp->index);

	return ok;
}

/*
 * Modify the attached rule group based upon changes to the group
 * definition, notified via group events.
 */
static void
pmf_arlg_group_modify(void *vctx, struct npf_cfg_rule_group_event *ev)
{
	if (ev->group_class != NPF_RULE_CLASS_ACL)
		return;

	enum npf_cfg_rule_group_event_type const evt = ev->event_type;
	struct pmf_group_ext *earg = vctx;

	switch (evt) {
	case NPF_EVENT_GROUP_RULE_ADD:
		(void)pmf_arlg_rl_add(earg, ev->parsed, ev->index);
		break;
	case NPF_EVENT_GROUP_RULE_CHANGE:
		(void)pmf_arlg_rl_chg(earg, ev->parsed, ev->index);
		break;
	case NPF_EVENT_GROUP_RULE_DELETE:
		(void)pmf_arlg_rl_del(earg, ev->index);
		break;
	default:
		return;
	}

	/* This came from config, expect a commit */
	commit_pending = true;
}

/*
 * Listen to attach point events to learn of ACL group use on
 * interfaces.
 *
 * Note that these may arrive before the interface exists, so
 * we will have to listen for interface creation events in order
 * to eventually notify to the platform.
 *
 * Also that the group will already exist when we first learn of
 * its use, so we will have to walk the group in order to learn
 * of its contents, as well as registering for subsequent group
 * change events.
 */
static npf_attpt_ev_cb pmf_arlg_attpt_grp_ev_handler;
static void
pmf_arlg_attpt_grp_ev_handler(enum npf_attpt_ev_type event,
			      struct npf_attpt_item *ap, void *data)
{
	bool const enabled = (event == NPF_ATTPT_EV_GRP_ADD);
	struct npf_attpt_group *agr = data;
	struct npf_attpt_key const *ap_key = npf_attpt_item_key(ap);

	if (ap_key->apk_type != NPF_ATTACH_TYPE_INTERFACE)
		return;

	char const *if_name = ap_key->apk_point;

	struct npf_rlgrp_key const *rg_key = npf_attpt_group_key(agr);
	if (rg_key->rgk_class != NPF_RULE_CLASS_ACL)
		return;

	char const *rg_name = rg_key->rgk_name;

	struct npf_attpt_rlset const *ars = npf_attpt_group_rlset(agr);

	enum npf_ruleset_type const rls_type = npf_attpt_rlset_type(ars);
	if (rls_type != NPF_RS_ACL_IN && rls_type != NPF_RS_ACL_OUT)
		return;

	bool const dir_in = (rls_type == NPF_RS_ACL_IN);

	struct pmf_group_ext *earg;
	struct pmf_rlset_ext *ears;
	int ev_rc = -1;

	if (!enabled)
		earg = npf_attpt_group_get_extend(agr);

	/* Attached a group to an interface, so built it, maybe publish */
	if (enabled) {
		earg = calloc(1, sizeof(*earg));
		if (!earg) {
			RTE_LOG(ERR, FIREWALL,
				"Error: OOM for attached group extension"
				" (%s/%s/%s/%s)\n",
				"ACL", (dir_in) ? " In" : "Out",
				if_name, rg_name);

			return;
		}
		ears = npf_attpt_rlset_get_extend(ars);
		earg->earg_base = agr;
		earg->earg_rlset = ears;
		earg->earg_rgname = rg_name;
		earg->earg_flags |= PMF_EARGF_DEFERRED;
		TAILQ_INIT(&earg->earg_rules);
		TAILQ_INIT(&earg->earg_cntrs);
		bool ok = npf_attpt_group_set_extend(agr, earg);
		if (!ok) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Failed to attach group extension"
				" (%s/%s/%s/%s)\n",
				"ACL", (dir_in) ? " In" : "Out",
				if_name, rg_name);

			free(earg);
			return;
		}

		ev_rc = npf_cfg_rule_group_reg_user(NPF_RULE_CLASS_ACL,
						    rg_name, earg,
						    pmf_arlg_group_modify);
		if (ev_rc) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Failed to register group listener"
				" (%s/%s/%s/%s) => %d\n",
				"ACL", (dir_in) ? " In" : "Out",
				if_name, rg_name, ev_rc);

			npf_attpt_group_set_extend(agr, NULL);
			free(earg);
			return;
		}

		/* Append it to the list */
		TAILQ_INSERT_TAIL(&ears->ears_groups, earg, earg_list);
	}

	if (enabled) {
		/* Build rules, look for the group attribute rule */
		npf_cfg_rule_group_walk(NPF_RULE_CLASS_ACL, rg_name,
					earg, pmf_arlg_group_build);

		deferrals = true;
	}


	/* Detached a group from an interface, so maybe unpublish, destroy */
	if (!enabled && earg) {
		/* Notify clients */
		pmf_alrg_hw_ntfy_grp_detach(earg);

		ev_rc = npf_cfg_rule_group_dereg_user(NPF_RULE_CLASS_ACL,
						      rg_name, earg);
		if (ev_rc) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Failed to deregister group listener"
				" (%s/%s/%s/%s) => %d\n",
				"ACL", (dir_in) ? " In" : "Out",
				if_name, rg_name, ev_rc);
		}

		/* Notify clients */
		pmf_alrg_hw_ntfy_rules_del(earg);

		/* Deallocate all of the rules */
		struct pmf_attrl *cursor;
		while (!!(cursor = TAILQ_LAST(&earg->earg_rules, pmf_rlqh))) {
			--earg->earg_num_rules;

			TAILQ_REMOVE(&earg->earg_rules, cursor, earl_list);
			pmf_arlg_rl_free(cursor);
		}

		/* Sanity before freeing */
		earg->earg_num_rules = 0;

		if (earg->earg_rlattr) {
			pmf_arlg_rl_free(earg->earg_rlattr);
			earg->earg_rlattr = NULL;
		}

		/* Notify clients */
		pmf_alrg_hw_ntfy_grp_delete(earg);

		npf_attpt_group_set_extend(agr, NULL);
		ears = earg->earg_rlset;
		TAILQ_REMOVE(&ears->ears_groups, earg, earg_list);
		free(earg);
	}

	/* This came from config, expect a commit */
	commit_pending = true;
}

/*
 * Handle notifications about an attached group going up/down.
 * i.e the interface to which it is attached was created or deleted.
 */
static npf_attpt_walk_groups_cb pmf_arlg_attpt_grp_updn_handler;
static bool
pmf_arlg_attpt_grp_updn_handler(const struct npf_attpt_group *rsg, void *ctx)
{
	bool is_up = *(bool *)ctx;

	struct pmf_group_ext *earg = npf_attpt_group_get_extend(rsg);
	if (!earg)
		return true;

	if (is_up)
		pmf_alrg_hw_ntfy_grp_attach(earg);
	else
		pmf_alrg_hw_ntfy_grp_detach(earg);

	return true;
}

/*
 * The ruleset went up or down, so update the if index in the correct
 * order relative to updating any attach/detach events for the groups
 * on the ruleset.
 *   On up:   Set index, then notify
 *   On down: Nottify, then clear index
 * This allows us to usefully propagate the attach/detach events.
 */
static void
pmf_arlg_attpt_rls_updn(struct npf_attpt_rlset *ars, bool is_up)
{
	struct pmf_rlset_ext *ears = npf_attpt_rlset_get_extend(ars);
	if (!ears)
		return;

	struct ifnet *iface = dp_ifnet_byifname(ears->ears_ifname);
	if (is_up) {
		if (!iface)
			return;
		/* Fill in the index */
		ears->ears_ifp = iface;
		ears->ears_flags |= PMF_EARSF_IFP;
		if (iface->if_created)
			ears->ears_flags |= PMF_EARSF_IF_CREATED;
	}

	npf_attpt_walk_rlset_grps(ars, pmf_arlg_attpt_grp_updn_handler, &is_up);

	if (!is_up) {
		/* Clear the index */
		ears->ears_ifp = NULL;
		ears->ears_flags &= ~PMF_EARSF_IFP;
	}
}

static void
pmf_arlg_attpt_rls_if_created(struct npf_attpt_rlset *ars)
{
	struct pmf_rlset_ext *ears = npf_attpt_rlset_get_extend(ars);
	if (!ears)
		return;

	if (ears->ears_flags & PMF_EARSF_IF_CREATED)
		return;

	/* Mark as created */
	ears->ears_flags |= PMF_EARSF_IF_CREATED;

	if (!(ears->ears_flags & PMF_EARSF_IFP))
		return;

	/* Claim it came up */
	bool is_up = true;
	npf_attpt_walk_rlset_grps(ars, pmf_arlg_attpt_grp_updn_handler, &is_up);
}

static npf_attpt_ev_cb pmf_arlg_attpt_rls_ev_handler;
static void
pmf_arlg_attpt_rls_ev_handler(enum npf_attpt_ev_type event,
			      struct npf_attpt_item *ap, void *data)
{
	bool const enabled = (event == NPF_ATTPT_EV_RLSET_ADD);
	struct npf_attpt_rlset *ars = data;
	struct npf_attpt_key const *ap_key = npf_attpt_item_key(ap);

	if (ap_key->apk_type != NPF_ATTACH_TYPE_INTERFACE)
		return;

	char const *if_name = ap_key->apk_point;

	enum npf_ruleset_type const rls_type = npf_attpt_rlset_type(ars);
	if (rls_type != NPF_RS_ACL_IN && rls_type != NPF_RS_ACL_OUT)
		return;

	bool const dir_in = (rls_type == NPF_RS_ACL_IN);

	uint32_t ears_flags
			= 0
			| (dir_in) ? PMF_EARSF_IN : 0;
	struct pmf_rlset_ext *ears;

	if (!enabled) {
		ears = npf_attpt_rlset_get_extend(ars);
		npf_attpt_rlset_set_extend(ars, NULL);
		TAILQ_REMOVE(&att_rlsets, ears, ears_list);
		free(ears);
	} else {
		ears = calloc(1, sizeof(*ears));
		if (!ears) {
			RTE_LOG(ERR, FIREWALL,
				"Error: OOM for attached ruleset extension"
				" (%s/%s/%s)\n",
				"ACL", (dir_in) ? " In" : "Out", if_name);

			return;
		}
		ears->ears_base = ars;
		ears->ears_flags = ears_flags;
		ears->ears_ifname = if_name;
		TAILQ_INIT(&ears->ears_groups);
		bool ok = npf_attpt_rlset_set_extend(ars, ears);
		if (!ok) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Failed to attach ruleset extension"
				" (%s/%s/%s)\n",
				"ACL", (dir_in) ? " In" : "Out", if_name);

			free(ears);
			return;
		}

		/* Fill in the index */
		struct ifnet *iface = dp_ifnet_byifname(if_name);
		if (iface) {
			ears->ears_ifp = iface;
			ears->ears_flags |= PMF_EARSF_IFP;
			if (iface->if_created)
				ears->ears_flags |= PMF_EARSF_IF_CREATED;
		}

		/* Append it to the list */
		TAILQ_INSERT_TAIL(&att_rlsets, ears, ears_list);
	}
}

static npf_attpt_ev_cb pmf_arlg_attpt_ap_ev_handler;
static void
pmf_arlg_attpt_ap_ev_handler(enum npf_attpt_ev_type event,
			     struct npf_attpt_item *ap, void *data __unused)
{
	struct npf_attpt_rlset *ars;
	bool is_up = (event == NPF_ATTPT_EV_UP);

	bool any_sets = false;
	if (npf_attpt_rlset_find(ap, NPF_RS_ACL_IN, &ars) == 0) {
		pmf_arlg_attpt_rls_updn(ars, is_up);
		any_sets = true;
	}
	if (npf_attpt_rlset_find(ap, NPF_RS_ACL_OUT, &ars) == 0) {
		pmf_arlg_attpt_rls_updn(ars, is_up);
		any_sets = true;
	}

	/* If this occurs outside of config, force a commit */
	if (any_sets && !commit_pending)
		pmf_hw_commit();
}

static void
pmf_arlg_if_feat_mode_change(struct ifnet *ifp,
			     enum if_feat_mode_event event)
{
	struct npf_attpt_item *ap;

	if (event != IF_FEAT_MODE_EVENT_L3_FAL_ENABLED)
		return;

	if (npf_attpt_item_find_any(NPF_ATTACH_TYPE_INTERFACE,
				    ifp->if_name, &ap) != 0)
		return;

	struct npf_attpt_rlset *ars;

	bool any_sets = false;
	if (npf_attpt_rlset_find(ap, NPF_RS_ACL_IN, &ars) == 0) {
		pmf_arlg_attpt_rls_if_created(ars);
		any_sets = true;
	}
	if (npf_attpt_rlset_find(ap, NPF_RS_ACL_OUT, &ars) == 0) {
		pmf_arlg_attpt_rls_if_created(ars);
		any_sets = true;
	}

	/* If this occurs outside of config, force a commit */
	if (any_sets && !commit_pending)
		pmf_hw_commit();
}

static const struct dp_event_ops pmf_arlg_events = {
	.if_feat_mode_change = pmf_arlg_if_feat_mode_change,
};

static void
pmf_arlg_commit_deferrals(void)
{
	struct pmf_rlset_ext *ears;
	TAILQ_FOREACH(ears, &att_rlsets, ears_list) {
		struct pmf_group_ext *earg;
		TAILQ_FOREACH(earg, &ears->ears_groups, earg_list) {
			uint32_t rg_flags = earg->earg_flags;
			bool rg_deferred = (rg_flags & PMF_EARGF_DEFERRED);
			if (!rg_deferred)
				continue;

			/* Process a deferred group notification */

			earg->earg_flags &= ~PMF_EARGF_DEFERRED;

			/* Could be blocked by lack of address family */
			struct pmf_rule *attr_rule
				= (earg->earg_rlattr)
				? earg->earg_rlattr->earl_rule
				: NULL;
			pmf_alrg_hw_ntfy_grp_create(earg, attr_rule);

			/* Notify about all rules */
			pmf_alrg_hw_ntfy_rules_add(earg);

			/* If the interface exists, we will attach */
			pmf_alrg_hw_ntfy_grp_attach(earg);
		}
	}
}

void
pmf_arlg_commit(void)
{
	if (deferrals)
		pmf_arlg_commit_deferrals();

	pmf_hw_commit();
	deferrals = false;
	commit_pending = false;
}

void pmf_arlg_init(void)
{
	const uint32_t ap_events
		= (1 << NPF_ATTPT_EV_UP)
		| (1 << NPF_ATTPT_EV_DOWN);
	const uint32_t rls_events
		= (1 << NPF_ATTPT_EV_RLSET_ADD)
		| (1 << NPF_ATTPT_EV_RLSET_DEL);
	const uint32_t grp_events
		= (1 << NPF_ATTPT_EV_GRP_ADD)
		| (1 << NPF_ATTPT_EV_GRP_DEL);

	dp_event_register(&pmf_arlg_events);

	if (npf_attpt_ev_listen(NPF_ATTACH_TYPE_INTERFACE, ap_events,
				pmf_arlg_attpt_ap_ev_handler) < 0)
		rte_panic("PMF FAL top cannot listen to attpt events\n");
	if (npf_attpt_ev_listen(NPF_ATTACH_TYPE_INTERFACE, rls_events,
				pmf_arlg_attpt_rls_ev_handler) < 0)
		rte_panic("PMF FAL top cannot listen to attpt rls events\n");
	if (npf_attpt_ev_listen(NPF_ATTACH_TYPE_INTERFACE, grp_events,
				pmf_arlg_attpt_grp_ev_handler) < 0)
		rte_panic("PMF FAL top cannot listen to attpt grp events\n");
}

/* Op-mode commands : dump internals */

void
pmf_arlg_dump(FILE *fp)
{
	struct pmf_rlset_ext *ears;

	/* Rulesets */
	TAILQ_FOREACH(ears, &att_rlsets, ears_list) {
		uint32_t rs_flags = ears->ears_flags;
		bool rs_in = (rs_flags & PMF_EARSF_IN);
		bool rs_ifp = (rs_flags & PMF_EARSF_IFP);
		bool rs_if_created = (rs_flags & PMF_EARSF_IF_CREATED);
		uint32_t if_index = rs_ifp ? ears->ears_ifp->if_index : 0;
		fprintf(fp, " RLS:%p: %s(%u)/%s%s%s\n",
			ears, ears->ears_ifname, if_index,
			rs_in ? "In " : "Out",
			rs_ifp ? " IFP" : "",
			rs_if_created ? " IfCrt" : ""
			);
		/* Groups - i.e. TABLES */
		struct pmf_group_ext *earg;
		TAILQ_FOREACH(earg, &ears->ears_groups, earg_list) {
			uint32_t rg_flags = earg->earg_flags;
			bool rg_published = (rg_flags & PMF_EARGF_PUBLISHED);
			bool rg_attached = (rg_flags & PMF_EARGF_ATTACHED);
			bool rg_deferred = (rg_flags & PMF_EARGF_DEFERRED);
			bool rg_attr_rl = (rg_flags & PMF_EARGF_RULE_ATTR);
			bool rg_family = (rg_flags & PMF_EARGF_FAMILY);
			bool rg_v6 = (rg_flags & PMF_EARGF_V6);
			bool rg_ll_create = (rg_flags & PMF_EARGF_LL_CREATED);
			bool rg_ll_attach = (rg_flags & PMF_EARGF_LL_ATTACHED);
			fprintf(fp,
				"  GRP:%p(%lx): %s(%u/%x)%s%s%s%s%s%s%s\n",
				earg, earg->earg_objid,
				earg->earg_rgname, earg->earg_num_rules,
				earg->earg_summary,
				rg_published ? " Pub" : "",
				rg_ll_create ? " LLcrt" : "",
				rg_attached ? " Att" : "",
				rg_ll_attach ? " LLatt" : "",
				rg_deferred ? " Defr" : "",
				rg_attr_rl ? " GAttr" : "",
				rg_family ? rg_v6 ? " v6" : " v4" : ""
				);
			struct pmf_cntr *eark;
			TAILQ_FOREACH(eark, &earg->earg_cntrs, eark_list) {
				uint32_t ct_flags = eark->eark_flags;
				bool ct_published
					= (ct_flags & PMF_EARKF_PUBLISHED);
				if (!ct_published)
					continue;
				bool ct_ll_create
					= (ct_flags & PMF_EARKF_LL_CREATED);
				bool ct_cnt_packet
					= (ct_flags & PMF_EARKF_CNT_PACKET);
				bool ct_cnt_byte
					= (ct_flags & PMF_EARKF_CNT_BYTE);
				fprintf(fp, "   CT:%p(%lx): %s%s%s%s%s\n",
					eark, eark->eark_objid,
					eark->eark_name,
					ct_published ? " Pub" : "",
					ct_ll_create ? " LLcrt" : "",
					ct_cnt_packet ? " Pkt" : "",
					ct_cnt_byte ? " Byte" : ""
					);
				uint64_t val_pkt = -1;
				uint64_t val_byt = -1;
				pmf_hw_counter_read(eark, &val_pkt, &val_byt);
				fprintf(fp, "      %s(%lu/%lx)) %s(%lu/%lx)\n",
					ct_cnt_packet ? "Pkt" : "-",
					(unsigned long)val_pkt,
					(unsigned long)val_pkt,
					ct_cnt_byte ? "Byte" : "-",
					(unsigned long)val_byt,
					(unsigned long)val_byt
					);
			}
			/* Rules - i.e. ENTRIES */
			struct pmf_attrl *earl;
			TAILQ_FOREACH(earl, &earg->earg_rules, earl_list) {
				uint32_t rl_flags = earl->earl_flags;
				bool rl_published
					= (rl_flags & PMF_EARLF_PUBLISHED);
				bool rl_ll_create
					= (rl_flags & PMF_EARLF_LL_CREATED);
				fprintf(fp, "   RL:%p(%lx): %u(%x)%s%s\n",
					earl, earl->earl_objid,
					earl->earl_index,
					earl->earl_rule->pp_summary,
					rl_published ? " Pub" : "",
					rl_ll_create ? " LLcrt" : ""
					);
			}
		}
	}
}

/* Op-mode commands : show counters */

static void
pmf_arlg_show_cntr_ruleset(json_writer_t *json, struct pmf_rlset_ext *ears)
{
	uint32_t rs_flags = ears->ears_flags;
	bool rs_in = (rs_flags & PMF_EARSF_IN);

	jsonw_string_field(json, "interface", ears->ears_ifname);
	jsonw_string_field(json, "direction", rs_in ? "in" : "out");
}

static void
pmf_arlg_show_hw_cntr(json_writer_t *json, struct pmf_cntr *eark)
{
	uint32_t ct_flags = eark->eark_flags;

	bool ct_ll_create = (ct_flags & PMF_EARKF_LL_CREATED);
	if (!ct_ll_create)
		return;

	bool ct_cnt_packet = (ct_flags & PMF_EARKF_CNT_PACKET);
	bool ct_cnt_byte = (ct_flags & PMF_EARKF_CNT_BYTE);

	uint64_t val_pkt = -1;
	uint64_t val_byt = -1;
	bool ok = pmf_hw_counter_read(eark, &val_pkt, &val_byt);
	if (!ok)
		return;

	jsonw_name(json, "hw");
	jsonw_start_object(json);

	if (ct_cnt_packet)
		jsonw_uint_field(json, "pkts", val_pkt);
	if (ct_cnt_byte)
		jsonw_uint_field(json, "bytes", val_byt);

	jsonw_end_object(json);
}

static void
pmf_arlg_show_cntr(json_writer_t *json, struct pmf_cntr *eark)
{
	uint32_t ct_flags = eark->eark_flags;

	bool ct_published = (ct_flags & PMF_EARKF_PUBLISHED);
	if (!ct_published)
		return;

	bool ct_cnt_packet = (ct_flags & PMF_EARKF_CNT_PACKET);
	bool ct_cnt_byte = (ct_flags & PMF_EARKF_CNT_BYTE);

	jsonw_start_object(json);

	jsonw_string_field(json, "name", eark->eark_name);
	jsonw_bool_field(json, "cnt-pkts", ct_cnt_packet);
	jsonw_bool_field(json, "cnt-bytes", ct_cnt_byte);

	pmf_arlg_show_hw_cntr(json, eark);

	jsonw_end_object(json);
}

int
pmf_arlg_cmd_show_counters(FILE *fp, char const *ifname, int dir,
			   char const *rgname)
{
	json_writer_t *json = jsonw_new(fp);
	if (!json) {
		RTE_LOG(ERR, DATAPLANE, "failed to create json stream\n");
		return -ENOMEM;
	}

	/* Enforce filter heirarchy */
	if (!ifname)
		dir = 0;
	if (!dir)
		rgname = NULL;

	jsonw_pretty(json, true);

	/* Rulesets */
	struct pmf_rlset_ext *ears;
	jsonw_name(json, "rulesets");
	jsonw_start_array(json);
	TAILQ_FOREACH(ears, &att_rlsets, ears_list) {
		uint32_t rs_flags = ears->ears_flags;
		/* Skip rulesets w/o an interface */
		if (!(ears->ears_flags & PMF_EARSF_IFP))
			continue;
		/* Filter on interface & direction */
		if (ifname && strcmp(ifname, ears->ears_ifname) != 0)
			continue;
		if (dir < 0 && !(rs_flags & PMF_EARSF_IN))
			continue;
		if (dir > 0 && (rs_flags & PMF_EARSF_IN))
			continue;

		jsonw_start_object(json);
		pmf_arlg_show_cntr_ruleset(json, ears);

		/* Groups - i.e. TABLES */
		struct pmf_group_ext *earg;
		jsonw_name(json, "groups");
		jsonw_start_array(json);
		TAILQ_FOREACH(earg, &ears->ears_groups, earg_list) {
			/* Filter on group name */
			if (rgname && strcmp(rgname, earg->earg_rgname) != 0)
				continue;

			jsonw_start_object(json);

			jsonw_string_field(json, "name", earg->earg_rgname);

			struct pmf_cntr *eark;
			jsonw_name(json, "counters");
			jsonw_start_array(json);
			TAILQ_FOREACH(eark, &earg->earg_cntrs, eark_list)
				pmf_arlg_show_cntr(json, eark);
			jsonw_end_array(json);

			jsonw_end_object(json);
		}
		jsonw_end_array(json);

		jsonw_end_object(json);
	}
	jsonw_end_array(json);

	jsonw_destroy(&json);

	return 0;
}

/* Op-mode commands : clear counters */

int
pmf_arlg_cmd_clear_counters(char const *ifname, int dir, char const *rgname)
{
	int rc = 0; /* Success */

	/* Enforce filter heirarchy */
	if (!ifname)
		dir = 0;
	if (!dir)
		rgname = NULL;

	/* Rulesets */
	struct pmf_rlset_ext *ears;
	TAILQ_FOREACH(ears, &att_rlsets, ears_list) {
		uint32_t rs_flags = ears->ears_flags;
		/* Skip rulesets w/o an interface */
		if (!(ears->ears_flags & PMF_EARSF_IFP))
			continue;
		/* Filter on interface & direction */
		if (ifname && strcmp(ifname, ears->ears_ifname) != 0)
			continue;
		if (dir < 0 && !(rs_flags & PMF_EARSF_IN))
			continue;
		if (dir > 0 && (rs_flags & PMF_EARSF_IN))
			continue;

		/* Groups - i.e. TABLES */
		struct pmf_group_ext *earg;
		TAILQ_FOREACH(earg, &ears->ears_groups, earg_list) {
			/* Filter on group name */
			if (rgname && strcmp(rgname, earg->earg_rgname) != 0)
				continue;

			struct pmf_cntr *eark;
			TAILQ_FOREACH(eark, &earg->earg_cntrs, eark_list) {
				uint32_t ct_flags = eark->eark_flags;
				if (!(ct_flags & PMF_EARKF_PUBLISHED))
					continue;
				if (!pmf_hw_counter_clear(eark))
					rc = -EIO;
			}
		}
	}

	return rc;
}
