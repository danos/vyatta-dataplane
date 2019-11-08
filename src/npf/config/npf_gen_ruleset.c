/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <urcu/uatomic.h>

#include "if_var.h"
#include "npf/npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_gen_ruleset.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_ruleset.h"
#include "urcu.h"
#include "vplane_log.h"

struct npf_attpt_group;
struct npf_attpt_rlset;

void
npf_replace_ruleset(npf_ruleset_t **dp_ruleset, npf_ruleset_t *new_dp_ruleset)
{
	npf_ruleset_t *old_dp_ruleset;

	old_dp_ruleset = rcu_xchg_pointer(dp_ruleset, new_dp_ruleset);

	/* Perform cleanup on the old ruleset */
	if (old_dp_ruleset) {
		if (new_dp_ruleset)
			npf_copy_stats(old_dp_ruleset, new_dp_ruleset);
		npf_ruleset_free(old_dp_ruleset);
	}
}

struct create_ruleset_info {
	int error;
	npf_ruleset_t **new_dp_ruleset;
	npf_rule_group_t *dp_rule_group;
	const struct npf_rlgrp_key *rgk;
	uint num_rules_in_group;
	unsigned int ruleset_type_flags;
};

static bool
npf_cfg_create_ruleset_group_rule_cb(void *param,
				    struct npf_cfg_rule_walk_state *state)
{
	struct create_ruleset_info *info = param;
	int ret;

	/* ACLs use this rule for group attributes */
	if (state->index == UINT32_MAX &&
	    info->rgk->rgk_class == NPF_RULE_CLASS_ACL)
		return true;

	ret = npf_make_rule(info->dp_rule_group, state->index, state->rule);
	if (ret) {
		info->error = ret;
		return false;
	}
	info->num_rules_in_group++;

	return true;
}

static npf_attpt_walk_groups_cb npf_cfg_create_ruleset_group_cb;
static bool
npf_cfg_create_ruleset_group_cb(const struct npf_attpt_group *rsg, void *ctx)
{
	const struct npf_rlgrp_key *rgk = npf_attpt_group_key(rsg);
	struct create_ruleset_info *info = ctx;
	npf_rule_group_t *rg;

	/* Determine the match direction for this group */
	uint8_t dir = 0;
	uint32_t dir_mask = npf_attpt_group_dir_mask(rsg);
	uint32_t ruleset_dir_flags = info->ruleset_type_flags & ~dir_mask;

	if (ruleset_dir_flags & NPF_RS_FLAG_DIR_IN)
		dir |= PFIL_IN;
	if (ruleset_dir_flags & NPF_RS_FLAG_DIR_OUT)
		dir |= PFIL_OUT;

	rg = npf_rule_group_create(*info->new_dp_ruleset, rgk->rgk_class,
				   rgk->rgk_name, dir);
	if (rg == NULL) {
		info->error = -ENOMEM;
		return false;
	}

	npf_grouper_init(rg);

	info->dp_rule_group = rg;
	info->rgk = rgk;

	npf_cfg_rule_group_walk(rgk->rgk_class, rgk->rgk_name, info,
				npf_cfg_create_ruleset_group_rule_cb);
	if (info->error)
		return false;

	if (info->num_rules_in_group == 0)
		/* no rules in the group or does no exist, so discard it */
		npf_free_group(rg);
	else
		npf_grouper_optimize(rg);

	info->num_rules_in_group = 0;
	info->dp_rule_group = NULL;

	return true;
}

static int
npf_cfg_create_ruleset(npf_ruleset_t **new_dp_ruleset,
		       enum npf_attach_type attach_type,
		       const char *attach_point,
		       enum npf_ruleset_type ruleset_type,
		       unsigned int ruleset_type_flags,
		       struct npf_attpt_rlset *ars)
{
	struct create_ruleset_info info = {
		.error = 0,
		.dp_rule_group = NULL,
		.num_rules_in_group = 0,
		.new_dp_ruleset = new_dp_ruleset,
		.ruleset_type_flags = ruleset_type_flags
	};

	if (attach_type >= NPF_ATTACH_TYPE_COUNT ||
	    ruleset_type >= NPF_RS_TYPE_COUNT)
		return -EINVAL;

	*new_dp_ruleset = npf_ruleset_create(ruleset_type, attach_type,
					     attach_point);
	if (*new_dp_ruleset == NULL) {
		RTE_LOG(ERR, DATAPLANE, "failed to create new ruleset\n");
		info.error = -ENOMEM;
	} else {
		npf_attpt_walk_rlset_grps(ars, npf_cfg_create_ruleset_group_cb,
					  &info);
	}
	if (info.error) {
		npf_ruleset_free(*new_dp_ruleset);
		*new_dp_ruleset = NULL;
	}
	return info.error;
}

int npf_cfg_build_ruleset(npf_ruleset_t **dp_ruleset,
			  enum npf_attach_type attach_type,
			  const char *attach_point,
			  enum npf_ruleset_type ruleset_type)
{
	int ret = 0;
	struct npf_attpt_item *ap = NULL;
	struct npf_attpt_rlset *ars = NULL;
	unsigned int ruleset_type_flags =
		npf_get_ruleset_type_flags(ruleset_type);

	ret = npf_attpt_item_find_any(attach_type, attach_point, &ap);
	if (ret) {
		if (ret != -ENOENT)
			return ret;
		*dp_ruleset = NULL;
		return 0;
	}

	ret = npf_attpt_rlset_find(ap, ruleset_type, &ars);
	if (ret) {
		if (ret != -ENOENT)
			return ret;
		*dp_ruleset = NULL;
		return 0;
	}

	ret = npf_cfg_create_ruleset(dp_ruleset, attach_type,
				     attach_point, ruleset_type,
				     ruleset_type_flags,
				     ars);
	if (ret)
		RTE_LOG(ERR, DATAPLANE, "failed to create ruleset\n");

	return ret;
}
