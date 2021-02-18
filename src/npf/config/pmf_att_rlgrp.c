/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
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

#include "npf/config/gpc_db_control.h"
#include "npf/config/gpc_db_query.h"
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

struct pmf_attrl {
	struct gpc_rule		*earl_gprl;	/* strong */
	struct pmf_cntr		*earl_cntr;
};

enum pmf_earg_flags {
	PMF_EARGF_RULE_ATTR	= (1 << 0),
};

struct pmf_group_ext {
	struct gpc_group	*earg_gprg;	/* strong */
	TAILQ_HEAD(pmf_cnqh, pmf_cntr) earg_cntrs;
	struct npf_attpt_group	*earg_base;
	struct pmf_rule		*earg_attr_rule;
	uint32_t		earg_num_rules;
	uint32_t		earg_flags;
};

/* ---- */

static bool deferrals;

static bool commit_pending;

/* ---- */

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

struct gpc_group *
pmf_arlg_cntr_get_grp(struct pmf_cntr const *eark)
{
	return eark->eark_group->earg_gprg;
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
	uint32_t summary = gpc_group_get_summary(earg->earg_gprg);

	if (summary & PMF_RAS_COUNT_DEF)
		return (summary & PMF_SUMMARY_COUNT_DEF_NAMED_FLAGS);
	return false;
}

/*
 * Returns true if the group has numbered counters (auto-per-rule).
 */
static bool
pmf_arlg_cntr_type_numbered(struct pmf_group_ext const *earg)
{
	uint32_t summary = gpc_group_get_summary(earg->earg_gprg);

	if (summary & PMF_RAS_COUNT_DEF)
		return !pmf_arlg_cntr_type_named(earg);
	return false;
}

/*
 * Returns true if the auto-per-action group has action "accept" counters.
 */
static bool
pmf_arlg_cntr_type_named_accept(struct pmf_group_ext const *earg)
{
	uint32_t summary = gpc_group_get_summary(earg->earg_gprg);

	if (summary & PMF_RAS_COUNT_DEF)
		return (summary & PMF_RAS_COUNT_DEF_PASS);
	return false;
}

/*
 * Returns true if the auto-per-action group has action "drop" counters.
 */
static bool
pmf_arlg_cntr_type_named_drop(struct pmf_group_ext const *earg)
{
	uint32_t summary = gpc_group_get_summary(earg->earg_gprg);

	if (summary & PMF_RAS_COUNT_DEF)
		return (summary & PMF_RAS_COUNT_DEF_DROP);
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

	uint32_t rule_index = gpc_rule_get_index(earl->earl_gprl);
	snprintf(eark_name, sizeof(eark_name), "%u", rule_index);
	if (pmf_arlg_find_cntr(earg, eark_name)) {
		RTE_LOG(ERR, FIREWALL,
			"Error: Attempt to alloc numbered counter that already exists (%d)\n",
			rule_index);
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

/* ---- */

/* ---- */

void
pmf_arlg_hw_ntfy_cntr_add(struct pmf_group_ext *earg, struct pmf_attrl *earl)
{
	if (!gpc_group_is_published(earg->earg_gprg))
		return;

	struct pmf_rule *rule = gpc_rule_get_rule(earl->earl_gprl);

	if (!(rule->pp_summary & PMF_RAS_COUNT_REF))
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
		    (rule->pp_summary & PMF_RAS_PASS))
			eark = pmf_arlg_get_or_alloc_action_cntr_accept(earg);

		if (pmf_arlg_cntr_type_named_drop(earg) &&
		    (rule->pp_summary & PMF_RAS_DROP))
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

void
pmf_arlg_hw_ntfy_cntr_del(struct pmf_group_ext *earg, struct pmf_attrl *earl)
{
	if (!gpc_group_is_published(earg->earg_gprg))
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

/* ---- */


/* ---- */

/* ---- */

/*
 * Check for a change in publication status due to the group attribute rule.
 */
static void
pmf_arlg_rl_attr_check(struct pmf_group_ext *earg, struct pmf_rule *attr_rule)
{
	struct gpc_group *gprg = earg->earg_gprg;
	struct pmf_attr_ip_family *ipfam = NULL;

	/* The group attribute rule has been removed */
	if (!attr_rule) {
		if (!(earg->earg_flags & PMF_EARGF_RULE_ATTR))
			return;
unpublish_group:
		/* A group is only visible if it has attr rule, and a family */
		if (gpc_group_is_published(gprg)) {
			gpc_group_hw_ntfy_detach(gprg);
			gpc_group_hw_ntfy_rules_delete(gprg);
			/* eventually delete counters */
			gpc_group_hw_ntfy_delete(gprg);
			/* Enable deferred republish */
			gpc_group_set_deferred(gprg);
			deferrals = true;
		}
		earg->earg_flags &= ~PMF_EARGF_RULE_ATTR;
		gpc_group_clear_family(gprg);
		return;
	}

	/* Have just acquired group attribute rule */
	if (!(earg->earg_flags & PMF_EARGF_RULE_ATTR)) {
		earg->earg_flags |= PMF_EARGF_RULE_ATTR;

		ipfam = (attr_rule)
		      ? attr_rule->pp_match.l2[PMF_L2F_IP_FAMILY].pm_ipfam
		      : NULL;
		if (!ipfam)
			return;

publish_group:
		/* semi-colon for goto target */;
		bool is_v6 = ipfam->pm_v6;
		if (is_v6)
			gpc_group_set_v6(gprg);
		else
			gpc_group_set_v4(gprg);

		/* Now publish everything referencing the group */
		gpc_group_hw_ntfy_create(gprg, attr_rule);
		/* eventually create counters */
		gpc_group_hw_ntfy_rules_create(gprg);
		gpc_group_hw_ntfy_attach(gprg);

		return;
	}

	/* The group attribute rule has changed */

	/* Eventually check for counters change here */

	/* Deleting the family acts like a group removal */
	ipfam = (attr_rule) ?
		attr_rule->pp_match.l2[PMF_L2F_IP_FAMILY].pm_ipfam : NULL;
	if (!ipfam) {
		if (gpc_group_has_family(gprg))
			goto unpublish_group;
		return;
	}

	/* Just acquired a family, so acts like group creation, publish all */
	if (!gpc_group_has_family(gprg))
		goto publish_group;

	/* Ensure the address family is the same */
	bool is_v6 = ipfam->pm_v6;
	if (gpc_group_is_v6(gprg) == is_v6)
		return;

	/* The AF is different, so delete and re-add everything */

	if (gpc_group_is_published(gprg)) {
		gpc_group_hw_ntfy_detach(gprg);
		gpc_group_hw_ntfy_rules_delete(gprg);
		/* eventually delete counters */
		gpc_group_hw_ntfy_delete(gprg);
	}
	earg->earg_flags &= ~PMF_EARGF_RULE_ATTR;
	gpc_group_clear_family(gprg);

	/* Now add it all back again, with new AF */
	goto publish_group;
}

/* ---- */

static bool
pmf_arlg_rl_del(struct pmf_group_ext *earg, uint32_t rl_idx)
{
	struct gpc_group *gprg = earg->earg_gprg;
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	bool dir_in = gpc_rlset_is_ingress(gprs);

	/* This rule is for group attributes */
	if (rl_idx == UINT32_MAX) {
		struct pmf_rule *attr_rule = earg->earg_attr_rule;
		if (!attr_rule)
			goto rule_del_error;
		pmf_arlg_rl_attr_check(earg, NULL);
		earg->earg_attr_rule = NULL;
		pmf_rule_free(attr_rule);
		return true;
	}

	struct gpc_rule *gprl = gpc_rule_find(gprg, rl_idx);
	if (!gprl) {
rule_del_error:
		RTE_LOG(ERR, FIREWALL,
			"Error: No rule to delete for ACL attached group"
			" %s/%s|%s:%u\n",
			(dir_in) ? " In" : "Out", gpc_rlset_get_ifname(gprs),
			gpc_group_get_name(gprg), rl_idx);
		return false;
	}

	uint32_t old_summary = gpc_group_get_summary(gprg);
	struct pmf_attrl *earl = gpc_rule_get_owner(gprl);

	--earg->earg_num_rules;

	gpc_rule_hw_ntfy_delete(gprg, gprl);
	gpc_rule_delete(gprl);

	free(earl);

	/* If any were published, recalculate and notify */
	if (old_summary) {
		struct pmf_rule *attr_rule = earg->earg_attr_rule;
		uint32_t summary = gpc_group_recalc_summary(gprg, attr_rule);
		gpc_group_hw_ntfy_modify(gprg, summary);
	}

	return true;
}

static bool
pmf_arlg_rl_chg(struct pmf_group_ext *earg,
		struct pmf_rule *new_rule, uint32_t rl_idx)
{
	struct gpc_group *gprg = earg->earg_gprg;
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	bool dir_in = gpc_rlset_is_ingress(gprs);

	if (rl_idx == UINT32_MAX) {
		struct pmf_rule *old_attr_rule = earg->earg_attr_rule;
		if (!old_attr_rule)
			goto rule_chg_error;
		pmf_arlg_rl_attr_check(earg, new_rule);
		earg->earg_attr_rule = pmf_rule_copy(new_rule);
		pmf_rule_free(old_attr_rule);
		return true;
	}

	struct gpc_rule *gprl = gpc_rule_find(gprg, rl_idx);
	if (!gprl) {
rule_chg_error:
		RTE_LOG(ERR, FIREWALL,
			"Error: No rule to change for ACL attached group"
			" %s/%s|%s:%u\n",
			(dir_in) ? " In" : "Out", gpc_rlset_get_ifname(gprs),
			gpc_group_get_name(gprg), rl_idx);
		return false;
	}

	/* If any were published, update and notify */
	uint32_t old_summary = gpc_group_get_summary(gprg);

	gpc_rule_change_rule(gprl, new_rule);

	/* We turned on new stuff above, turn off old stuff now */
	if (old_summary) {
		struct pmf_rule *attr_rule = earg->earg_attr_rule;
		uint32_t summary = gpc_group_recalc_summary(gprg, attr_rule);
		gpc_group_hw_ntfy_modify(gprg, summary);
	}

	return true;
}

static bool
pmf_arlg_rl_add(struct pmf_group_ext *earg,
		struct pmf_rule *rule, uint32_t rl_idx)
{
	struct gpc_group *gprg = earg->earg_gprg;
	struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
	bool dir_in = gpc_rlset_is_ingress(gprs);

	/* This rule is for group attributes */
	if (rl_idx == UINT32_MAX) {
		if (earg->earg_attr_rule) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Dup rule 0 for ACL attached group rule"
				" %s/%s|%s\n",
				(dir_in) ? " In" : "Out",
				gpc_rlset_get_ifname(gprs),
				gpc_group_get_name(gprg));
			return false;
		}

		earg->earg_attr_rule = pmf_rule_copy(rule);
		pmf_arlg_rl_attr_check(earg, rule);

		return true;
	}

	struct pmf_attrl *earl = calloc(1, sizeof(*earl));
	if (!earl) {
rule_add_error:
		RTE_LOG(ERR, FIREWALL,
			"Error: OOM for ACL attached group rule"
			" %s/%s|%s:%u\n",
			(dir_in) ? " In" : "Out", gpc_rlset_get_ifname(gprs),
			gpc_group_get_name(gprg), rl_idx);
		return false;
	}

	++earg->earg_num_rules;

	struct gpc_rule *gprl = gpc_rule_create(gprg, rl_idx, earl);
	if (!gprl) {
		free(earl);
		goto rule_add_error;
	}

	earl->earl_gprl = gprl;

	gpc_rule_change_rule(gprl, rule);

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
		earg->earg_base = agr;
		TAILQ_INIT(&earg->earg_cntrs);

		struct gpc_rlset *gprs = npf_attpt_rlset_get_extend(ars);
		struct gpc_group *gprg
			= gpc_group_create(gprs, GPC_FEAT_ACL, rg_name, earg);
		if (!gprg) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Failed to create GPC group"
				" (%s/%s/%s/%s)\n",
				"ACL", (dir_in) ? " In" : "Out",
				if_name, rg_name);

			free(earg);
			return;
		}
		gpc_group_set_deferred(gprg);
		earg->earg_gprg = gprg;

		bool ok = npf_attpt_group_set_extend(agr, earg);
		if (!ok) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Failed to attach group extension"
				" (%s/%s/%s/%s)\n",
				"ACL", (dir_in) ? " In" : "Out",
				if_name, rg_name);

			earg->earg_gprg = NULL;
			gpc_group_delete(gprg);
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
			earg->earg_gprg = NULL;
			gpc_group_delete(gprg);
			free(earg);
			return;
		}
	}

	if (enabled) {
		/* Build rules, look for the group attribute rule */
		npf_cfg_rule_group_walk(NPF_RULE_CLASS_ACL, rg_name,
					earg, pmf_arlg_group_build);

		deferrals = true;
	}


	/* Detached a group from an interface, so maybe unpublish, destroy */
	if (!enabled && earg) {
		struct gpc_group *gprg = earg->earg_gprg;

		/* Notify clients */
		gpc_group_hw_ntfy_detach(gprg);

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
		gpc_group_hw_ntfy_rules_delete(gprg);

		/* Deallocate all of the rules */
		struct gpc_rule *cursor;
		while (!!(cursor = gpc_rule_last(gprg))) {
			--earg->earg_num_rules;

			struct pmf_attrl *earl = gpc_rule_get_owner(cursor);

			/* gpc_rule_hw_ntfy_delete(gprg, cursor); is a NO-OP */
			gpc_rule_delete(cursor);

			free(earl);
		}

		/* Sanity before freeing */
		earg->earg_num_rules = 0;

		if (earg->earg_attr_rule) {
			pmf_rule_free(earg->earg_attr_rule);
			earg->earg_attr_rule = NULL;
		}

		/* Notify clients */
		gpc_group_hw_ntfy_delete(gprg);

		npf_attpt_group_set_extend(agr, NULL);
		earg->earg_gprg = NULL;
		gpc_group_delete(gprg);
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
		gpc_group_hw_ntfy_attach(earg->earg_gprg);
	else
		gpc_group_hw_ntfy_detach(earg->earg_gprg);

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
	struct gpc_rlset *gprs = npf_attpt_rlset_get_extend(ars);
	if (!gprs)
		return;

	if (is_up && !gpc_rlset_set_ifp(gprs))
		return;

	npf_attpt_walk_rlset_grps(ars, pmf_arlg_attpt_grp_updn_handler, &is_up);

	if (!is_up)
		gpc_rlset_clear_ifp(gprs);
}

static void
pmf_arlg_attpt_rls_if_created(struct npf_attpt_rlset *ars)
{
	struct gpc_rlset *gprs = npf_attpt_rlset_get_extend(ars);
	if (!gprs)
		return;

	if (gpc_rlset_is_if_created(gprs))
		return;

	/* Mark as created */
	gpc_rlset_set_if_created(gprs);

	if (!gpc_rlset_get_ifp(gprs))
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

	struct gpc_rlset *gprs;

	if (!enabled) {
		gprs = npf_attpt_rlset_get_extend(ars);
		npf_attpt_rlset_set_extend(ars, NULL);
		gpc_rlset_delete(gprs);
	} else {
		gprs = gpc_rlset_create(dir_in, if_name, ars);
		if (!gprs) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Failed to create GPC ruleset"
				" (%s/%s/%s)\n",
				"ACL", (dir_in) ? " In" : "Out", if_name);

			return;
		}

		bool ok = npf_attpt_rlset_set_extend(ars, gprs);
		if (!ok) {
			RTE_LOG(ERR, FIREWALL,
				"Error: Failed to attach ruleset extension"
				" (%s/%s/%s)\n",
				"ACL", (dir_in) ? " In" : "Out", if_name);

			gpc_rlset_delete(gprs);
			return;
		}
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
	struct gpc_rlset *gprs;
	GPC_RLSET_FOREACH(gprs) {
		struct gpc_group *gprg;
		GPC_GROUP_FOREACH(gprg, gprs) {
			if (gpc_group_get_feature(gprg) != GPC_FEAT_ACL)
				continue;

			struct pmf_group_ext *earg
				= gpc_group_get_owner(gprg);

			if (!gpc_group_is_deferred(gprg))
				continue;

			/* Process a deferred group notification */

			gpc_group_clear_deferred(gprg);

			/* Could be blocked by lack of address family */
			struct pmf_rule *attr_rule = earg->earg_attr_rule;
			gpc_group_hw_ntfy_create(gprg, attr_rule);

			/* Notify about all rules */
			gpc_group_hw_ntfy_rules_create(gprg);

			/* If the interface exists, we will attach */
			gpc_group_hw_ntfy_attach(gprg);
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
	struct gpc_rlset *gprs;

	/* Rulesets */
	GPC_RLSET_FOREACH(gprs) {
		bool rs_in = gpc_rlset_is_ingress(gprs);
		struct ifnet *rs_ifp = gpc_rlset_get_ifp(gprs);
		bool rs_if_created = gpc_rlset_is_if_created(gprs);
		char const *ifname = gpc_rlset_get_ifname(gprs);
		uint32_t if_index = rs_ifp ? rs_ifp->if_index : 0;
		fprintf(fp, " RLS:%p: %s(%u)/%s%s%s\n",
			gprs, ifname, if_index,
			rs_in ? "In " : "Out",
			rs_ifp ? " IFP" : "",
			rs_if_created ? " IfCrt" : ""
			);
		/* Groups - i.e. TABLES */
		struct gpc_group *gprg;
		GPC_GROUP_FOREACH(gprg, gprs) {
			if (gpc_group_get_feature(gprg) != GPC_FEAT_ACL)
				continue;

			struct pmf_group_ext *earg = gpc_group_get_owner(gprg);
			uint32_t rg_flags = earg->earg_flags;
			bool rg_published = gpc_group_is_published(gprg);
			bool rg_attached = gpc_group_is_attached(gprg);
			bool rg_deferred = gpc_group_is_deferred(gprg);
			bool rg_attr_rl = (rg_flags & PMF_EARGF_RULE_ATTR);
			bool rg_family = gpc_group_has_family(gprg);
			bool rg_v6 = gpc_group_is_v6(gprg);
			bool rg_ll_create = gpc_group_is_ll_created(gprg);
			bool rg_ll_attach = gpc_group_is_ll_attached(gprg);
			fprintf(fp,
				"  GRP:%p(%lx): %s(%u/%x)%s%s%s%s%s%s%s\n",
				gprg, gpc_group_get_objid(gprg),
				gpc_group_get_name(gprg),
				earg->earg_num_rules,
				gpc_group_get_summary(gprg),
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
			struct gpc_rule *gprl;
			GPC_RULE_FOREACH(gprl, gprg) {
				bool rl_published = gpc_rule_is_published(gprl);
				bool rl_ll_create
					= gpc_rule_is_ll_created(gprl);
				fprintf(fp, "   RL:%p(%lx): %u(%x)%s%s\n",
					gprl, gpc_rule_get_objid(gprl),
					gpc_rule_get_index(gprl),
					gpc_rule_get_rule(gprl)->pp_summary,
					rl_published ? " Pub" : "",
					rl_ll_create ? " LLcrt" : ""
					);
			}
		}
	}
}

/* Op-mode commands : show counters */

static void
pmf_arlg_show_cntr_ruleset(json_writer_t *json, struct gpc_rlset *gprs)
{
	bool rs_in = gpc_rlset_is_ingress(gprs);

	jsonw_string_field(json, "interface", gpc_rlset_get_ifname(gprs));
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
	struct gpc_rlset *gprs;
	jsonw_name(json, "rulesets");
	jsonw_start_array(json);
	GPC_RLSET_FOREACH(gprs) {
		/* Skip rulesets w/o an interface */
		if (!gpc_rlset_get_ifp(gprs))
			continue;
		/* Filter on interface & direction */
		if (ifname && strcmp(ifname, gpc_rlset_get_ifname(gprs)) != 0)
			continue;
		if (dir < 0 && !gpc_rlset_is_ingress(gprs))
			continue;
		if (dir > 0 && gpc_rlset_is_ingress(gprs))
			continue;

		jsonw_start_object(json);
		pmf_arlg_show_cntr_ruleset(json, gprs);

		/* Groups - i.e. TABLES */
		struct gpc_group *gprg;
		jsonw_name(json, "groups");
		jsonw_start_array(json);
		GPC_GROUP_FOREACH(gprg, gprs) {
			if (gpc_group_get_feature(gprg) != GPC_FEAT_ACL)
				continue;

			/* Filter on group name */
			if (rgname &&
			    strcmp(rgname, gpc_group_get_name(gprg)) != 0)
				continue;

			jsonw_start_object(json);

			jsonw_string_field(json, "name",
					   gpc_group_get_name(gprg));

			struct pmf_group_ext *earg = gpc_group_get_owner(gprg);

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
	struct gpc_rlset *gprs;
	GPC_RLSET_FOREACH(gprs) {
		/* Skip rulesets w/o an interface */
		if (!gpc_rlset_get_ifp(gprs))
			continue;
		/* Filter on interface & direction */
		if (ifname && strcmp(ifname, gpc_rlset_get_ifname(gprs)) != 0)
			continue;
		if (dir < 0 && !gpc_rlset_is_ingress(gprs))
			continue;
		if (dir > 0 && gpc_rlset_is_ingress(gprs))
			continue;

		/* Groups - i.e. TABLES */
		struct gpc_group *gprg;
		GPC_GROUP_FOREACH(gprg, gprs) {
			if (gpc_group_get_feature(gprg) != GPC_FEAT_ACL)
				continue;

			/* Filter on group name */
			if (rgname &&
			    strcmp(rgname, gpc_group_get_name(gprg)) != 0)
				continue;

			struct pmf_group_ext *earg = gpc_group_get_owner(gprg);

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
