/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_log.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "json_writer.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_dump.h"
#include "npf/config/pmf_dump.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"
#include "vplane_log.h"
#include "vplane_debug.h"

struct npf_attpt_group;
struct npf_attpt_item;
struct npf_attpt_rlset;

struct rule_group_dump_info {
	json_writer_t *json;
	enum npf_rule_class last_group_class;
	const char *last_group;
};

static bool print_rule_cb(void *param, struct npf_cfg_rule_walk_state *state)
{
	struct rule_group_dump_info *info = param;
	json_writer_t *json = info->json;

	/* see if the group has changed */
	if (state->group_class != info->last_group_class ||
	    (strcmp(state->group, info->last_group) != 0)) {

		if (info->last_group_class != NPF_RULE_CLASS_COUNT) {
			jsonw_end_array(json);
			jsonw_end_object(json);
		}

		jsonw_start_object(json);
		jsonw_string_field(json, "group_class",
				npf_get_rule_class_name(state->group_class));
		jsonw_string_field(json, "group", state->group);
		jsonw_name(json, "rules");
		jsonw_start_array(json);

		info->last_group_class = state->group_class;
		info->last_group = state->group;
	}

	jsonw_start_object(json);
	jsonw_uint_field(json, "index", state->index);
	jsonw_string_field(json, "rule", state->rule);
	if (state->parsed && DP_DEBUG_ENABLED(NPF)) {
		jsonw_name(json, "parsed");
		pmf_dump_rule_json(state->parsed, json);
	}
	jsonw_end_object(json);

	return true;
}

void npf_dump_rule_groups(FILE *fp)
{
	json_writer_t *json = jsonw_new(fp);
	struct rule_group_dump_info info = {
		.json = json,
		.last_group_class = NPF_RULE_CLASS_COUNT,
	};

	if (json == NULL) {
		RTE_LOG(ERR, DATAPLANE, "failed to create json stream\n");
		return;
	}

	jsonw_pretty(json, true);
	jsonw_name(json, "rule_groups");
	jsonw_start_array(json);

	npf_cfg_rule_group_walk_all(&info, print_rule_cb);

	if (info.last_group_class != NPF_RULE_CLASS_COUNT) {
		jsonw_end_array(json);
		jsonw_end_object(json);
	}

	jsonw_end_array(json);
	jsonw_destroy(&json);
}

static npf_attpt_walk_groups_cb dump_group_cb;
static bool
dump_group_cb(const struct npf_attpt_group *rsg, void *ctx)
{
	const struct npf_rlgrp_key *rgk = npf_attpt_group_key(rsg);
	json_writer_t *json = ctx;

	jsonw_start_object(json);
	jsonw_string_field(json, "group_class",
			   npf_get_rule_class_name(rgk->rgk_class));
	jsonw_string_field(json, "group", rgk->rgk_name);
	jsonw_end_object(json);

	return true;
}

struct dump_attach_point_info {
	json_writer_t *json;
	const struct npf_attpt_key *apk;
	bool attach_point_printed;
};

static npf_attpt_walk_rlsets_cb dump_ruleset_cb;
static bool
dump_ruleset_cb(struct npf_attpt_rlset *ars, void *ctx)
{
	struct dump_attach_point_info *info = ctx;

	if (!info->attach_point_printed) {
		const struct npf_attpt_key *apk = info->apk;
		jsonw_start_object(info->json);
		jsonw_string_field(info->json, "attach_type",
				   npf_get_attach_type_name(apk->apk_type));
		jsonw_string_field(info->json, "attach_point", apk->apk_point);
		jsonw_name(info->json, "rulesets");
		jsonw_start_array(info->json);

		info->attach_point_printed = true;
	}

	enum npf_ruleset_type ruleset_type = npf_attpt_rlset_type(ars);
	jsonw_start_object(info->json);
	jsonw_string_field(info->json, "ruleset_type",
			   npf_get_ruleset_type_name(ruleset_type));
	jsonw_name(info->json, "groups");
	jsonw_start_array(info->json);

	npf_attpt_walk_rlset_grps(ars, dump_group_cb, info->json);

	jsonw_end_array(info->json);
	jsonw_end_object(info->json);

	return true;
}

static npf_attpt_walk_items_cb dump_attach_point_cb;
static bool
dump_attach_point_cb(struct npf_attpt_item *ap, void *ctx)
{
	struct dump_attach_point_info *info = ctx;

	info->apk = npf_attpt_item_key(ap);
	info->attach_point_printed = false;

	npf_attpt_walk_rlsets(ap, dump_ruleset_cb, info);

	if (info->attach_point_printed) {
		jsonw_end_array(info->json);
		jsonw_end_object(info->json);
	}

	return true;
}

void npf_dump_attach_points(FILE *fp)
{
	struct dump_attach_point_info info;

	info.json = jsonw_new(fp);

	if (info.json == NULL) {
		RTE_LOG(ERR, DATAPLANE, "failed to create json stream\n");
		return;
	}

	jsonw_pretty(info.json, true);
	jsonw_name(info.json, "attach_points");
	jsonw_start_array(info.json);

	npf_attpt_item_walk_all(dump_attach_point_cb, &info);

	jsonw_end_array(info.json);
	jsonw_destroy(&(info.json));
}
