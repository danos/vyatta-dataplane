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

#include "npf/config/gpc_cntr_query.h"
#include "npf/config/gpc_cntr_control.h"
#include "npf/config/gpc_db_control.h"
#include "npf/config/gpc_db_query.h"
#include "npf/config/pmf_rule.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/pmf_hw.h"
#include "dp_event.h"

#define CNTR_NAME_LEN	8

enum pmf_earg_flags {
	PMF_EARGF_RULE_ATTR	= (1 << 0),
};

struct pmf_group_ext {
	struct gpc_group	*earg_gprg;	/* strong */
	struct npf_attpt_group	*earg_base;
	struct pmf_rule		*earg_attr_rule;
	uint32_t		earg_num_rules;
	uint32_t		earg_flags;
};

/* ---- */

static bool deferrals;

static bool commit_pending;

/* ---- */

void *
pmf_arlg_earg_get_attr_rule(void *earg_ptr)
{
	struct pmf_group_ext *earg = earg_ptr;
	if (!earg)
		return NULL;

	uint32_t rg_flags = earg->earg_flags;
	if (!(rg_flags & PMF_EARGF_RULE_ATTR))
		return NULL;

	return earg->earg_attr_rule;
}

uint32_t
pmf_arlg_earg_get_rule_count(void *earg_ptr)
{
	struct pmf_group_ext *earg = earg_ptr;
	if (!earg)
		return 0;

	return earg->earg_num_rules;
}

static bool
pmf_arlg_rule_needs_cntr(struct gpc_cntg const *cntg,
			 struct pmf_rule const *rule)
{
	enum gpc_cntr_type type = gpc_cntg_type(cntg);

	switch (type) {
	case GPC_CNTT_NUMBERED:
		return true;
	case GPC_CNTT_NAMED:
		break;
	default:
		return false;
	}

	if (!(rule->pp_summary & PMF_RAS_COUNT_REF))
		return false;

	return true;
}

static struct gpc_cntr *
pmf_arlg_rule_get_cntr(struct gpc_cntg *cntg,
		       struct pmf_rule const *rule,
		       uint32_t rl_number)
{
	enum gpc_cntr_type type = gpc_cntg_type(cntg);
	struct gpc_cntr *cntr = NULL;

	if (type == GPC_CNTT_NUMBERED)
		cntr = gpc_cntr_create_numbered(cntg, rl_number);
	else if (type == GPC_CNTT_NAMED) {
		/* This needs to be done better */
		if (rule->pp_summary & PMF_RAS_PASS)
			cntr = gpc_cntr_find_and_retain(cntg, "accept");
		else if (rule->pp_summary & PMF_RAS_DROP)
			cntr = gpc_cntr_find_and_retain(cntg, "drop");
	}

	return cntr;
}

/*
 * The logic in here should really be based upon the names extracted
 * as part of the rproc.
 */
static void
pmf_arlg_rule_create_cntg_rules(struct gpc_group *gprg,
				struct gpc_cntg *cntg,
				struct pmf_rule const *attr_rule)
{
	struct gpc_cntr *cntr = NULL;
	char const *cntr_name;

	/* What do we need? */
	bool const need_accept = attr_rule->pp_summary & PMF_RAS_COUNT_DEF_PASS;
	bool const need_drop = attr_rule->pp_summary & PMF_RAS_COUNT_DEF_DROP;

	/* Have we got "accept"? */
	bool got_accept = false;
	cntr = gpc_cntr_find_and_retain(cntg, "accept");
	got_accept = !!cntr;
	if (cntr)
		gpc_cntr_release(cntr);

	/* Have we got "drop"? */
	bool got_drop = false;
	cntr = gpc_cntr_find_and_retain(cntg, "drop");
	got_drop = !!cntr;
	if (cntr)
		gpc_cntr_release(cntr);

	/* Make "accept" if needed and not present */
	if (need_accept && !got_accept) {
		cntr_name = "accept";
		cntr = gpc_cntr_create_named(cntg, cntr_name);
		if (!cntr) {
cntr_error:
			;/* semi-colon for goto target */
			struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
			bool dir_in = gpc_rlset_is_ingress(gprs);
			RTE_LOG(ERR, FIREWALL,
				"Error: OOM for ACL attached group cntr=%s"
				" %s/%s|%s\n",
				cntr_name,
				(dir_in) ? " In" : "Out",
				gpc_rlset_get_ifname(gprs),
				gpc_group_get_name(gprg));
			return;
		}
		gpc_cntr_hw_ntfy_create(cntg, cntr);
	}

	/* Make "drop" if needed and not present */
	if (need_drop && !got_drop) {
		cntr_name = "drop";
		cntr = gpc_cntr_create_named(cntg, cntr_name);
		if (!cntr)
			goto cntr_error;
		gpc_cntr_hw_ntfy_create(cntg, cntr);
	}
}

static void
pmf_arlg_rule_create_cntg(struct gpc_group *gprg,
			  struct pmf_rule const *attr_rule)
{
	struct gpc_cntg *cntg;

	if (!(attr_rule->pp_summary & PMF_RAS_COUNT_DEF))
		return;

	/*
	 * This should be changed to depend upon information extracted
	 * from the rproc, specifically the 'type=' key/value pair.
	 */
	enum gpc_cntr_type type = GPC_CNTT_NUMBERED;
	if (attr_rule->pp_summary & PMF_SUMMARY_COUNT_DEF_NAMED_FLAGS)
		type = GPC_CNTT_NAMED;

	cntg = gpc_cntg_create(gprg, type,
			       GPC_CNTW_PACKET, GPC_CNTS_INTERFACE);
	if (!cntg) {
		struct gpc_rlset *gprs = gpc_group_get_rlset(gprg);
		bool dir_in = gpc_rlset_is_ingress(gprs);
		RTE_LOG(ERR, FIREWALL,
			"Error: OOM for ACL attached group cntg"
			" %s/%s|%s\n",
			(dir_in) ? " In" : "Out", gpc_rlset_get_ifname(gprs),
			gpc_group_get_name(gprg));
		return;
	}

	gpc_group_set_cntg(gprg, cntg);

	if (type != GPC_CNTT_NAMED)
		return;

	pmf_arlg_rule_create_cntg_rules(gprg, cntg, attr_rule);
}

static void
pmf_arlg_rule_delete_cntg(struct gpc_cntg *cntg)
{
	if (gpc_cntg_type(cntg) == GPC_CNTT_NAMED) {
		struct gpc_cntr *cntr;
		GPC_CNTR_FOREACH(cntr, cntg) {
			gpc_cntr_release(cntr);
		}
	}

	gpc_cntg_release(cntg);
}

static void
pmf_arlg_rl_attr_check(struct pmf_group_ext *earg, struct pmf_rule *attr_rule);

static void
pmf_arlg_rule_change_cntg(struct pmf_group_ext *earg,
			  struct gpc_group *gprg,
			  struct pmf_rule *attr_rule)
{
	struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);
	if (!cntg) {
		pmf_arlg_rule_create_cntg(gprg, attr_rule);
		pmf_arlg_rl_attr_check(earg, attr_rule);
		return;
	}

	if (!(attr_rule->pp_summary & PMF_RAS_COUNT_DEF)) {
		pmf_arlg_rule_delete_cntg(cntg);
		gpc_group_set_cntg(gprg, NULL);
		return;
	}

	/* Check if the counter type has changed */
	enum gpc_cntr_type type = GPC_CNTT_NUMBERED;
	if (attr_rule->pp_summary & PMF_SUMMARY_COUNT_DEF_NAMED_FLAGS)
		type = GPC_CNTT_NAMED;

	if (type != gpc_cntg_type(cntg)) {
		pmf_arlg_rl_attr_check(earg, NULL);

		pmf_arlg_rule_delete_cntg(cntg);
		gpc_group_set_cntg(gprg, NULL);
		pmf_arlg_rule_create_cntg(gprg, attr_rule);

		pmf_arlg_rl_attr_check(earg, attr_rule);
		return;
	}

	/* Same type of counters, nothing to do for numbered */
	if (type == GPC_CNTT_NUMBERED)
		return;

	/* We could have changed the specific named counters */
	bool const need_accept = attr_rule->pp_summary & PMF_RAS_COUNT_DEF_PASS;
	bool const need_drop = attr_rule->pp_summary & PMF_RAS_COUNT_DEF_DROP;

	bool got_accept = false;
	struct gpc_cntr *cntr_accept
		= gpc_cntr_find_and_retain(cntg, "accept");
	got_accept = !!cntr_accept;

	bool got_drop = false;
	struct gpc_cntr *cntr_drop = gpc_cntr_find_and_retain(cntg, "drop");
	got_drop = !!cntr_drop;

	/* If we have what we need, nothing to do */
	if ((got_accept == need_accept) && (got_drop == need_drop)) {
		if (cntr_accept)
			gpc_cntr_release(cntr_accept);
		if (cntr_drop)
			gpc_cntr_release(cntr_drop);
		return;
	}

	/* Force all rules to be unpublished (inefficient, but simple) */
	pmf_arlg_rl_attr_check(earg, NULL);

	/* Create any missing counters */
	if ((need_accept && !got_accept) || (need_drop && !got_drop))
		pmf_arlg_rule_create_cntg_rules(gprg, cntg, attr_rule);

	/* Release unneeded counters */

	if (got_accept && !need_accept)
		gpc_cntr_release(cntr_accept);

	if (got_drop && !need_drop)
		gpc_cntr_release(cntr_drop);

	/* Force all to be republished */
	pmf_arlg_rl_attr_check(earg, attr_rule);

	/* Release references from lookup */
	if (cntr_accept)
		gpc_cntr_release(cntr_accept);
	if (cntr_drop)
		gpc_cntr_release(cntr_drop);
}


/* ---- */

/*
 * Check for a change in publication status due to the group attribute rule.
 */
static void
pmf_arlg_rl_attr_check(struct pmf_group_ext *earg, struct pmf_rule *attr_rule)
{
	struct gpc_group *gprg = earg->earg_gprg;
	struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);
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
			if (cntg)
				gpc_cntg_hw_ntfy_cntrs_delete(cntg);
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
		if (cntg)
			gpc_cntg_hw_ntfy_cntrs_create(cntg);
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
		if (cntg)
			gpc_cntg_hw_ntfy_cntrs_delete(cntg);
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

		struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);
		if (cntg) {
			pmf_arlg_rule_delete_cntg(cntg);
			gpc_group_set_cntg(gprg, NULL);
		}
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

	--earg->earg_num_rules;

	gpc_rule_hw_ntfy_delete(gprg, gprl);

	struct gpc_cntr *cntr = gpc_rule_get_cntr(gprl);

	gpc_rule_delete(gprl);

	if (cntr)
		gpc_cntr_release(cntr);

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
		pmf_arlg_rule_change_cntg(earg, gprg, new_rule);

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

	/* Adjust a counter if necessary */
	struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);
	struct gpc_cntr *rel_cntr = NULL;

	/* If the group has counters configured */
	if (cntg) {
		struct gpc_cntr *cntr = gpc_rule_get_cntr(gprl);
		bool need_counter = pmf_arlg_rule_needs_cntr(cntg, new_rule);
		if (!need_counter) {
			/* This rule should release its counter (if any) */
			rel_cntr = cntr;
		} else if (!cntr) {
			/* Need a counter, but don't have one - acquire one */
			cntr = pmf_arlg_rule_get_cntr(cntg, new_rule, rl_idx);
			gpc_rule_set_cntr(gprl, cntr);
			gpc_cntr_hw_ntfy_create(cntg, cntr);
		} else {
			/* Counter needed, and/or rule match have changed */
			if (gpc_cntg_type(cntg) == GPC_CNTT_NAMED) {
				struct gpc_cntr *new_cntr
					= pmf_arlg_rule_get_cntr(cntg,
								 new_rule, 0);
				if (new_cntr == cntr) {
					gpc_cntr_release(new_cntr);
					/* Do we need to clear the counter? */
				} else {
					gpc_rule_set_cntr(gprl, new_cntr);
					gpc_cntr_hw_ntfy_create(cntg, new_cntr);
					rel_cntr = cntr;
				}
			}
			/*
			 * The below call to gpc_rule_change_rule() will
			 * eventually publish the rule if unpublished,
			 * or delete it and add a new one (which we desire
			 * here) if already published.
			 *
			 * This is necessary as at the FAL layer, a rule
			 * references a counter, so changing the counter
			 * requires changing the rule; and we don't have
			 * support for in-place modify.
			 */
		}
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

	/* Release a counter, possibly freeing it */
	if (rel_cntr)
		gpc_cntr_release(rel_cntr);

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

		rule = pmf_rule_copy(rule);
		pmf_arlg_rule_create_cntg(gprg, rule);
		pmf_arlg_rl_attr_check(earg, rule);
		earg->earg_attr_rule = rule;

		return true;
	}

	++earg->earg_num_rules;

	/* Find a counter if necessary */
	struct gpc_cntr *cntr = NULL;
	struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);
	if (cntg && pmf_arlg_rule_needs_cntr(cntg, rule))
		cntr = pmf_arlg_rule_get_cntr(cntg, rule, rl_idx);

	/* Create the GPC rule, or fail and clean up */
	struct gpc_rule *gprl = gpc_rule_create(gprg, rl_idx, NULL);
	if (!gprl) {
		RTE_LOG(ERR, FIREWALL,
			"Error: OOM for ACL attached group rule"
			" %s/%s|%s:%u\n",
			(dir_in) ? " In" : "Out", gpc_rlset_get_ifname(gprs),
			gpc_group_get_name(gprg), rl_idx);
		if (cntr)
			gpc_cntr_release(cntr);
		return false;
	}

	gpc_rule_set_cntr(gprl, cntr);

	if (cntr)
		gpc_cntr_hw_ntfy_create(cntg, cntr);

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

		struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);
		if (cntg)
			gpc_cntg_hw_ntfy_cntrs_delete(cntg);

		/* Deallocate all of the rules */
		struct gpc_rule *cursor;
		while (!!(cursor = gpc_rule_last(gprg))) {
			--earg->earg_num_rules;

			struct gpc_cntr *cntr = gpc_rule_get_cntr(cursor);
			/* gpc_rule_hw_ntfy_delete(gprg, cursor); is a NO-OP */
			gpc_rule_delete(cursor);
			if (cntr)
				gpc_cntr_release(cntr);
		}

		/* Deallocate remaining counters */
		if (cntg) {
			if (gpc_cntg_type(cntg) == GPC_CNTT_NAMED) {
				struct gpc_cntr *cntr;
				while (!!(cntr = gpc_cntr_last(cntg)))
					gpc_cntr_release(cntr);
			}
			gpc_cntg_release(cntg);
			gpc_group_set_cntg(gprg, NULL);
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
		gpc_hw_commit();
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
		gpc_hw_commit();
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

			/* Notify about all counters */
			struct gpc_cntg *cntg = gpc_group_get_cntg(gprg);
			if (cntg)
				gpc_cntg_hw_ntfy_cntrs_create(cntg);

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

	gpc_hw_commit();
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
