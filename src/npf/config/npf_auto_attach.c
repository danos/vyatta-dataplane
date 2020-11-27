/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <stdint.h>

#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_auto_attach.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"

struct npf_cfg_attach_info {
	enum npf_attach_type attach_type;
	const char *attach_point;
	enum npf_ruleset_type ruleset_type;
	enum npf_rule_class group_class;
	const char *group;
};

typedef int (*npf_auto_attach_fn)(enum npf_rule_class group_class,
				  const char *group,
				  struct npf_cfg_attach_info *attach_info);


static int get_attach_point_nat(enum npf_rule_class group_class,
				const char *group,
				struct npf_cfg_attach_info *attach_info)
{
	attach_info->attach_type = NPF_ATTACH_TYPE_INTERFACE;
	attach_info->attach_point = group;
	if (group_class == NPF_RULE_CLASS_DNAT)
		attach_info->ruleset_type = NPF_RS_DNAT;
	else
		attach_info->ruleset_type = NPF_RS_SNAT;
	attach_info->group_class = group_class;
	attach_info->group = group;

	return 0;
}

static int get_attach_point_qos(enum npf_rule_class group_class,
				const char *group,
				struct npf_cfg_attach_info *attach_info)
{
	attach_info->attach_type = NPF_ATTACH_TYPE_QOS;
	attach_info->attach_point = group;
	attach_info->ruleset_type = NPF_RS_QOS;
	attach_info->group_class = group_class;
	attach_info->group = group;

	return 0;
}

static int get_attach_point_custom_timeout(enum npf_rule_class group_class,
					   const char *group,
					   struct npf_cfg_attach_info
					   *attach_info)
{
	attach_info->attach_type = NPF_ATTACH_TYPE_VRF;
	attach_info->attach_point = group;
	attach_info->ruleset_type = NPF_RS_CUSTOM_TIMEOUT;
	attach_info->group_class = group_class;
	attach_info->group = group;

	return 0;
}

static int get_attach_point_application(enum npf_rule_class group_class,
					const char *group,
					struct npf_cfg_attach_info *attach_info)
{
	attach_info->attach_type = NPF_ATTACH_TYPE_GLOBAL;
	attach_info->attach_point = "";
	attach_info->ruleset_type = NPF_RS_APPLICATION;
	attach_info->group_class = group_class;
	attach_info->group = group;

	return 0;
}

static npf_auto_attach_fn npf_auto_attach_fns[NPF_RULE_CLASS_COUNT] =  {
	[NPF_RULE_CLASS_DNAT] = get_attach_point_nat,
	[NPF_RULE_CLASS_SNAT] = get_attach_point_nat,
	[NPF_RULE_CLASS_QOS] = get_attach_point_qos,
	[NPF_RULE_CLASS_CUSTOM_TIMEOUT] = get_attach_point_custom_timeout,
	[NPF_RULE_CLASS_APPLICATION] = get_attach_point_application,
};

static int get_auto_attach_point(enum npf_rule_class group_class,
				 const char *group,
				 struct npf_cfg_attach_info *attach_info)
{
	static npf_auto_attach_fn fn;

	if (group_class >= NPF_RULE_CLASS_COUNT)
		return -EINVAL;

	fn = npf_auto_attach_fns[group_class];
	if (fn)
		return fn(group_class, group, attach_info);

	return -ENOENT;
}

int npf_cfg_auto_attach_rule_add(enum npf_rule_class group_class,
				 const char *group,
				 uint32_t index, const char *rule)
{
	int attach_ret = -EINVAL;
	struct npf_cfg_attach_info info;
	int rule_ret;

	if (npf_cfg_rule_count(group_class, group) == 0) {
		if (get_auto_attach_point(group_class, group, &info) == 0) {
			attach_ret = npf_cfg_attach_group(info.attach_type,
				info.attach_point, info.ruleset_type,
				info.group_class, info.group);
			if (attach_ret != 0)
				return attach_ret;
		}
	}

	rule_ret = npf_cfg_rule_add(group_class, group, index, rule);
	if (rule_ret != 0) {
		if (attach_ret == 0) {
			npf_cfg_detach_group(info.attach_type,
				info.attach_point, info.ruleset_type,
				info.group_class, info.group);
		}
		return rule_ret;
	}
	return 0;
}

int npf_cfg_auto_attach_rule_delete(enum npf_rule_class group_class,
				    const char *group, uint32_t index,
				    const char *rule)
{
	int rule_ret = npf_cfg_rule_delete(group_class, group, index, rule);

	if (rule_ret != 0)
		return rule_ret;

	if (npf_cfg_rule_count(group_class, group) == 0) {
		struct npf_cfg_attach_info info;

		if (get_auto_attach_point(group_class, group, &info) == 0) {
			npf_cfg_detach_group(info.attach_type,
				info.attach_point, info.ruleset_type,
				info.group_class, info.group);
		}
	}

	return 0;
}
