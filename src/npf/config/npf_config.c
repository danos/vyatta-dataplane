/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "json_writer.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_gen_ruleset.h"
#include "npf/config/npf_rule_group.h"
#include "npf/npf_ruleset.h"
#include "vplane_log.h"

struct npf_attpt_group;
struct npf_attpt_item;

enum npf_commit_type {
	NPF_COMMIT_UPDATE,
	NPF_COMMIT_DELETE
};

static void npf_config_free_rcu(struct rcu_head *head)
{
	struct npf_config *npf_conf =
		caa_container_of(head, struct npf_config, nc_rcu);

	free(npf_conf);
}

static int npf_config_default_alloc_free(struct npf_config **npf_confp,
					 bool alloc)
{
	struct npf_config *npf_conf;

	if (alloc) {
		npf_conf = calloc(sizeof(*npf_conf), 1);

		if (npf_conf == NULL)
			return -ENOMEM;

		rcu_assign_pointer(*npf_confp, npf_conf);
	} else {
		npf_conf = *npf_confp;

		rcu_assign_pointer(*npf_confp, NULL);
		call_rcu(&npf_conf->nc_rcu, npf_config_free_rcu);
	}

	return 0;
}

static int npf_config_alloc(struct npf_config **npf_confp,
			    struct npf_attpt_item *ap)
{
	const struct npf_attpt_key *apk = npf_attpt_item_key(ap);
	char *attach_point;
	int rc;

	if (*npf_confp != NULL && (*npf_confp)->nc_attach_point != NULL)
		return 0;	/* already allocated and associated */

	attach_point = strdup(apk->apk_point);
	if (attach_point == NULL)
		return -ENOMEM;

	npf_attpt_item_fn_ctx *npf_attpt_item_fn =
		npf_attpt_item_up_fn_context(ap);

	if (npf_attpt_item_fn)
		rc = npf_attpt_item_fn(npf_confp, true);
	else
		rc = npf_config_default_alloc_free(npf_confp, true);

	if (rc) {
		free(attach_point);
		return rc;
	}

	(*npf_confp)->nc_attach_type = apk->apk_type;
	(*npf_confp)->nc_attach_point = attach_point;

	return 0;
}

static void
npf_update_active_flags(struct npf_config *npf_conf,
		enum npf_ruleset_type ruleset_type, npf_ruleset_t *ruleset)
{
	unsigned long active_flags = npf_conf->nc_active_flags;
	unsigned long stateful_flags = npf_conf->nc_stateful;
	bool rs_is_stateful;

	if (ruleset) {
		active_flags |= BIT(ruleset_type);
		rs_is_stateful = npf_ruleset_is_stateful(ruleset);
	} else {
		active_flags &= ~BIT(ruleset_type);
		rs_is_stateful = false;
	}

	if (rs_is_stateful)
		stateful_flags |= BIT(ruleset_type);
	else
		stateful_flags &= ~BIT(ruleset_type);

	npf_conf->nc_stateful = stateful_flags;

	/*
	 * Calculate stateful firewall summary.
	 *
	 * This makes the stateful firewall default reverse block work.
	 * It ensures that we will enter npf_hook_track() in the reverse
	 * direction when there are no existing firewall rules,  and that
	 * we can test that rule summary value.
	 */
	active_flags &= ~(NPF_FW_STATE_IN|NPF_FW_STATE_OUT);
	if (stateful_flags & NPF_FW_IN)
		active_flags |= NPF_FW_STATE_IN;
	if (stateful_flags & NPF_FW_OUT)
		active_flags |= NPF_FW_STATE_OUT;

	uatomic_xchg(&npf_conf->nc_active_flags, active_flags);
}


static void npf_cfg_commit(struct npf_attpt_item *ap, enum npf_commit_type type)
{
	enum npf_ruleset_type ruleset_type;
	npf_ruleset_t **nc_rulesets;
	bool *nc_dirty_rulesets;
	enum npf_attach_type nc_attach_type;
	const char *nc_attach_point;
	unsigned long prev_active_flags;

	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	if (!npf_conf_p)
		return;

	struct npf_config *npf_conf = *npf_conf_p;
	if (!npf_conf)
		return;

	nc_rulesets = npf_conf->nc_rulesets;
	nc_dirty_rulesets = npf_conf->nc_dirty_rulesets;
	nc_attach_type = npf_conf->nc_attach_type;
	nc_attach_point = npf_conf->nc_attach_point;
	prev_active_flags = npf_conf->nc_active_flags;

	for (ruleset_type = 0; ruleset_type < NPF_RS_TYPE_COUNT;
	     ruleset_type++, nc_rulesets++, nc_dirty_rulesets++) {
		if (!*nc_dirty_rulesets)
			continue;

		npf_ruleset_t *new_ruleset = NULL;

		if (type == NPF_COMMIT_UPDATE) {
			int ret = npf_cfg_build_ruleset(&new_ruleset,
							nc_attach_type,
							nc_attach_point,
							ruleset_type);

			if (ret != 0) {
				RTE_LOG(ERR, DATAPLANE,
					"failed to update dataplane ruleset\n");
				continue;
			}
		}

		/* Following is also for type NPF_COMMIT_DELETE */

		npf_update_active_flags(npf_conf, ruleset_type, new_ruleset);

		/* Notify if ruleset type was removed or added. */
		if (prev_active_flags & BIT(ruleset_type)) {
			if (!(npf_conf->nc_active_flags & BIT(ruleset_type)))
				npf_attpt_ev_notify(
					NPF_ATTPT_EV_RLSET_DEL_COMMIT, ap,
					&ruleset_type);

		} else {
			if (npf_conf->nc_active_flags & BIT(ruleset_type))
				npf_attpt_ev_notify(
					NPF_ATTPT_EV_RLSET_ADD_COMMIT, ap,
					&ruleset_type);
		}

		npf_replace_ruleset(nc_rulesets, new_ruleset);
	}

	/* Mark all the rulesets as clean. */
	memset(npf_conf->nc_dirty_rulesets, 0, NPF_RS_TYPE_COUNT);

	if (npf_conf->nc_active_flags == 0 && npf_conf->nc_attach_point) {

		free((void *)npf_conf->nc_attach_point);
		npf_conf->nc_attach_point = NULL;

		npf_attpt_item_fn_ctx *npf_attpt_item_fn =
			npf_attpt_item_up_fn_context(ap);

		if (npf_attpt_item_fn)
			npf_attpt_item_fn(npf_conf_p, false);
		else
			npf_config_default_alloc_free(npf_conf_p, false);
	}
}

static npf_attpt_walk_items_cb npf_cfg_commit_cb;
static bool
npf_cfg_commit_cb(struct npf_attpt_item *ap, void *ctx __unused)
{
	npf_cfg_commit(ap, NPF_COMMIT_UPDATE);

	return true;
}

void npf_cfg_commit_all(void)
{
	npf_attpt_item_walk_up(npf_cfg_commit_cb, NULL);
}

/*
 * This function is called for notification of a change to a group of rules
 * and is registered for each time a group is attached to a ruleset.
 */
static void npf_rule_group_event_handler(void *param,
					 struct npf_cfg_rule_group_event *event
					 __unused)
{
	/* Just mark the ruleset as dirty for any change to the group. */
	*((bool *)param) = true;
}

static void
npf_cfg_handle_group_add(struct npf_attpt_item *ap,
			 const struct npf_attpt_group *agr)
{
	const struct npf_rlgrp_key *rgk = npf_attpt_group_key(agr);
	struct npf_attpt_rlset *ars = npf_attpt_group_rlset(agr);
	enum npf_ruleset_type rls_type = npf_attpt_rlset_type(ars);
	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	struct npf_config *npf_conf;
	int ret;

	ret = npf_config_alloc(npf_conf_p, ap);
	npf_conf = *npf_conf_p;
	if (ret) {
		RTE_LOG(ERR, DATAPLANE, "failed to allocate npf_config\n");
		return;
	}

	/* Notify to dirty the ruleset on any change to the group. */
	bool *dirty_flag = &npf_conf->nc_dirty_rulesets[rls_type];
	ret = npf_cfg_rule_group_reg_user(rgk->rgk_class, rgk->rgk_name,
					  dirty_flag,
					  npf_rule_group_event_handler);
	if (ret)
		RTE_LOG(ERR, DATAPLANE,
			"failed to register for changes to a rule group\n");

	*dirty_flag = true;
}

static void
npf_cfg_handle_group_del(struct npf_attpt_item *ap,
			 const struct npf_attpt_group *agr)
{
	const struct npf_rlgrp_key *rgk = npf_attpt_group_key(agr);
	struct npf_attpt_rlset *ars = npf_attpt_group_rlset(agr);
	enum npf_ruleset_type rls_type = npf_attpt_rlset_type(ars);
	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	struct npf_config *npf_conf;
	int ret;

	ret = npf_config_alloc(npf_conf_p, ap);
	npf_conf = *npf_conf_p;
	if (ret) {
		RTE_LOG(ERR, DATAPLANE, "failed to allocate npf_config\n");
		return;
	}

	/* No longer want notified of group changes. */
	bool *dirty_flag = &npf_conf->nc_dirty_rulesets[rls_type];
	ret = npf_cfg_rule_group_dereg_user(rgk->rgk_class, rgk->rgk_name,
					    dirty_flag);
	if (ret)
		RTE_LOG(ERR, DATAPLANE,
			"failed to deregister from changes to a rule group\n");

	*dirty_flag = true;
}

struct update_event_info {
	struct npf_attpt_item *ap;
	bool up;
};

static npf_attpt_walk_groups_cb update_gr_event_handlers;
static bool
update_gr_event_handlers(const struct npf_attpt_group *rsg, void *ctx)
{
	struct update_event_info *info = ctx;

	if (info->up)
		npf_cfg_handle_group_add(info->ap, rsg);
	else
		npf_cfg_handle_group_del(info->ap, rsg);

	return true;
}

/*
 * Simulate a group add or remove for each attached group on the
 * attach point which has changed state.
 */
static void update_event_handlers(struct npf_attpt_item *ap, bool up)
{
	struct update_event_info info = {
		.ap = ap,
		.up = up,
	};

	npf_attpt_walk_all_grps(ap, update_gr_event_handlers, &info);
}

static void
npf_cfg_handle_attpt_up(struct npf_attpt_item *ap)
{
	update_event_handlers(ap, true);
	npf_cfg_commit(ap, NPF_COMMIT_UPDATE);
}

static void
npf_cfg_handle_attpt_down(struct npf_attpt_item *ap)
{
	update_event_handlers(ap, false);
	npf_cfg_commit(ap, NPF_COMMIT_DELETE);
}

static npf_attpt_ev_cb npf_cfg_attpt_ev_handler;
static void
npf_cfg_attpt_ev_handler(enum npf_attpt_ev_type event,
			 struct npf_attpt_item *ap, void *data)
{
	switch (event) {
	case NPF_ATTPT_EV_UP:
		npf_cfg_handle_attpt_up(ap);
		break;
	case NPF_ATTPT_EV_DOWN:
		npf_cfg_handle_attpt_down(ap);
		break;
	case NPF_ATTPT_EV_GRP_ADD:
		if (npf_attpt_item_is_up(ap))
			npf_cfg_handle_group_add(ap, data);
		break;
	case NPF_ATTPT_EV_GRP_DEL:
		if (npf_attpt_item_is_up(ap))
			npf_cfg_handle_group_del(ap, data);
		break;
	default:
		break;
	}
}

void npf_config_init(void)
{
	enum npf_attach_type ap_type;

	for (ap_type = 0; ap_type < NPF_ATTACH_TYPE_COUNT; ++ap_type) {
		if (npf_attpt_ev_listen(ap_type, -1,
					npf_cfg_attpt_ev_handler) < 0)
			rte_panic("NPF config cannot listen to attpt events\n");
	}
}

static void npf_dirty_attach_point_rulesets(struct npf_attpt_item *ap,
					    unsigned long rulesets)
{
	enum npf_ruleset_type ruleset_type;
	unsigned long ruleset_type_bit;

	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	if (!npf_conf_p)
		return;

	struct npf_config *npf_conf = *npf_conf_p;
	if (!npf_conf)
		return;

	for (ruleset_type = 0; ruleset_type < NPF_RS_TYPE_COUNT;
	     ruleset_type++) {
		ruleset_type_bit = BIT(ruleset_type);

		if (((rulesets & ruleset_type_bit) != 0) &&
		    npf_active(npf_conf, ruleset_type_bit)) {

			npf_conf->nc_dirty_rulesets[ruleset_type] = true;
		}
	}
}

static npf_attpt_walk_items_cb npf_dirty_cb;
static bool
npf_dirty_cb(struct npf_attpt_item *ap, void *ctx)
{
	struct ruleset_select *sel = ctx;

	npf_dirty_attach_point_rulesets(ap, sel->rulesets);

	return true;
}

int
npf_dirty_selected_rulesets(struct ruleset_select *sel)
{
	if (sel->attach_type == NPF_ATTACH_TYPE_ALL) {
		npf_attpt_item_walk_up(npf_dirty_cb, sel);
		return 0;
	}

	struct npf_attpt_item *ap;
	if (npf_attpt_item_find_up(sel->attach_type,
				   sel->attach_point, &ap) < 0)
		return 0;

	npf_dirty_attach_point_rulesets(ap, sel->rulesets);

	return 0;
}

void npf_show_attach_point_rulesets(json_writer_t *json,
				    struct npf_attpt_item *ap,
				    unsigned long rulesets)
{
	enum npf_ruleset_type ruleset_type;
	unsigned long ruleset_type_bit;
	bool attach_point_json_printed = 0;

	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	if (!npf_conf_p)
		return;

	struct npf_config *npf_conf = *npf_conf_p;
	if (!npf_conf)
		return;

	for (ruleset_type = 0; ruleset_type < NPF_RS_TYPE_COUNT;
	     ruleset_type++) {
		ruleset_type_bit = BIT(ruleset_type);

		if (((rulesets & ruleset_type_bit) != 0) &&
		    npf_active(npf_conf, ruleset_type_bit)) {

			if (!attach_point_json_printed) {
				jsonw_start_object(json);
				jsonw_string_field(json, "attach_type",
					npf_get_attach_type_name(
					npf_conf->nc_attach_type));
				jsonw_string_field(json, "attach_point",
						   npf_conf->nc_attach_point);
				jsonw_name(json, "rulesets");
				jsonw_start_array(json);

				attach_point_json_printed = 1;
			}
			jsonw_start_object(json);
			jsonw_string_field(json, "ruleset_type",
					   npf_get_ruleset_type_name(
						   ruleset_type));

			npf_json_ruleset(npf_get_ruleset(npf_conf,
					 ruleset_type), json);

			jsonw_end_object(json);
		}
	}

	if (attach_point_json_printed) {
		jsonw_end_array(json);
		jsonw_end_object(json);
	}
}

struct npf_show_select_info {
	json_writer_t *json;
	struct ruleset_select *sel;
};

static npf_attpt_walk_items_cb npf_show_cb;
static bool
npf_show_cb(struct npf_attpt_item *ap, void *ctx)
{
	struct npf_show_select_info *info = ctx;

	npf_show_attach_point_rulesets(info->json, ap, info->sel->rulesets);

	return true;
}

int
npf_show_selected_rulesets(FILE *fp, struct ruleset_select *sel)
{
	json_writer_t *json = jsonw_new(fp);

	if (json == NULL) {
		RTE_LOG(ERR, DATAPLANE, "failed to create json stream\n");
		return -ENOMEM;
	}

	jsonw_pretty(json, true);
	jsonw_name(json, "config");
	jsonw_start_array(json);

	if (sel->attach_type == NPF_ATTACH_TYPE_ALL) {
		struct npf_show_select_info info = {
			.json = json,
			.sel = sel
		};

		npf_attpt_item_walk_up(npf_show_cb, &info);
	} else {
		struct npf_attpt_item *ap;
		if (npf_attpt_item_find_up(sel->attach_type,
					   sel->attach_point, &ap) >= 0) {
			npf_show_attach_point_rulesets(json, ap, sel->rulesets);
		}
	}

	jsonw_end_array(json);
	jsonw_destroy(&json);
	return 0;
}

static void npf_clear_attach_point_rulesets(struct npf_attpt_item *ap,
					    struct ruleset_select *sel)
{
	enum npf_ruleset_type ruleset_type;
	unsigned long ruleset_type_bit;

	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	if (!npf_conf_p)
		return;

	struct npf_config *npf_conf = *npf_conf_p;
	if (!npf_conf)
		return;

	for (ruleset_type = 0; ruleset_type < NPF_RS_TYPE_COUNT;
	     ruleset_type++) {
		ruleset_type_bit = BIT(ruleset_type);

		if (((sel->rulesets & ruleset_type_bit) != 0) &&
		    npf_active(npf_conf, ruleset_type_bit)) {

			npf_clear_stats(
				npf_get_ruleset(npf_conf, ruleset_type),
				sel->group_class, sel->group_name,
				sel->rule_no);
		}
	}
}

static npf_attpt_walk_items_cb npf_clear_cb;
static bool
npf_clear_cb(struct npf_attpt_item *ap, void *ctx)
{
	struct ruleset_select *sel = ctx;

	npf_clear_attach_point_rulesets(ap, sel);

	return true;
}

int
npf_clear_selected_rulesets(struct ruleset_select *sel)
{
	if (sel->attach_type == NPF_ATTACH_TYPE_ALL) {
		npf_attpt_item_walk_up(npf_clear_cb, sel);
		return 0;
	}

	struct npf_attpt_item *ap;
	if (npf_attpt_item_find_up(sel->attach_type,
				   sel->attach_point, &ap) >= 0) {
		npf_clear_attach_point_rulesets(ap, sel);
	}

	return 0;
}
