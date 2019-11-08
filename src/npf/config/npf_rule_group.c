/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>
#include <errno.h>
#include <rte_debug.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "vplane_log.h"
#include "vplane_debug.h"

#include "npf/config/npf_rule_group.h"
#include "npf/config/pmf_rule.h"
#include "npf/config/pmf_parse.h"

enum class_flags {
	CF_HAS_RULE		= 0x0001,
	CF_RPROC_ONLY		= 0x0002,
	CF_RETAIN_PARSED	= 0x0004,
};

static bool npf_group_class_has_rules(enum npf_rule_class group_class);
static bool npf_group_class_rproc_only(enum npf_rule_class group_class);
static bool npf_group_class_retain_parsed(enum npf_rule_class group_class);

/* Rule definition */
struct cfg_rule {
	uint32_t	index;
	const char	*rule;
	struct pmf_rule *parsed;
};

struct cfg_group_user {
	npf_cfg_rule_group_event_cb fn;
	void *param;
};

struct cfg_group_item {
	zlistx_t		*rules;
	zlistx_t		*users;
};

static zhashx_t	*group_hash;	/* hash of all rule groups */

/*
 * Destructor, duplicator, and compare for rules on groups
 */

static void rule_destroy(void **object)
{
	struct cfg_rule *cr = *object;

	free((void *)cr->rule);
	pmf_rule_free(cr->parsed);
	cr->parsed = NULL;
	free(cr);
	*object = NULL;
}

static void *rule_dup(const void *object)
{
	const struct cfg_rule *cr = object;
	struct cfg_rule *new = malloc(sizeof(*new));

	if (new) {
		new->index = cr->index;
		new->rule = strdup(cr->rule);
		if (new->rule == NULL) {
			free(new);
			return NULL;
		}
		new->parsed = pmf_rule_copy(cr->parsed);
		if (!new->parsed && cr->parsed) {
			free((void *)new->rule);
			free(new);
			return NULL;
		}
	}
	return new;
}

static int rule_compare(const void *object1, const void *object2)
{
	const struct cfg_rule *cr1 = object1;
	const struct cfg_rule *cr2 = object2;

	/*
	 * handles both 'ordered' and 'unordered' rules.
	 * 'unordered' rules have an index of 0 (zero).
	 *
	 * A group should only contain one or the other.
	 */
	if (cr1->index || cr2->index)
		return cr1->index - cr2->index;
	return strcmp(cr1->rule, cr2->rule);
}

/*
 * Destructor, duplicator, and compare for users of groups
 */

static void users_destroy(void **object)
{
	struct cfg_group_user *cu = *object;

	free(cu);
	*object = NULL;
}

static void *users_dup(const void *object)
{
	const struct cfg_group_user *cu = object;
	struct cfg_group_user *new = malloc(sizeof(*new));

	if (new) {
		new->fn = cu->fn;
		new->param = cu->param;
	}
	return new;
}

static int users_compare(const void *object1, const void *object2)
{
	const struct cfg_group_user *cu1 = object1;
	const struct cfg_group_user *cu2 = object2;

	if (cu1->param < cu2->param)
		return -1;
	if (cu1->param > cu2->param)
		return 1;
	return 0;
}

static size_t group_hasher(const void *key)
{
	const struct npf_rlgrp_key *rgk = key;
	size_t key_hash = rgk->rgk_class;
	const char *pointer = rgk->rgk_name;

	while (*pointer)
		key_hash = 33 * key_hash ^ *pointer++;
	return key_hash;
}

/*
 * Destructor, duplicator, and compare for group keys and items
 */

static void group_key_destroy(void **object)
{
	struct npf_rlgrp_key *rgk = *object;

	free((void *)rgk->rgk_name);
	free(rgk);
	*object = NULL;
}

static void *group_key_dup(const void *object)
{
	const struct npf_rlgrp_key *rgk = object;
	struct npf_rlgrp_key *new  = malloc(sizeof(*new));

	if (new) {
		new->rgk_class = rgk->rgk_class;
		new->rgk_name = strdup(rgk->rgk_name);
		if (new->rgk_name == NULL) {
			free(new);
			return NULL;
		}
	}
	return new;
}

static int group_key_compare(const void *object1, const void *object2)
{
	const struct npf_rlgrp_key *rgk1 = object1;
	const struct npf_rlgrp_key *rgk2 = object2;
	int class_diff = rgk1->rgk_class - rgk2->rgk_class;

	return class_diff ? class_diff : strcmp(rgk1->rgk_name, rgk2->rgk_name);
}

static void group_item_destroy(void **object)
{
	struct cfg_group_item *cg = *object;

	zlistx_destroy(&cg->rules);
	zlistx_destroy(&cg->users);
	free(cg);
	*object = NULL;
}

static void *group_item_dup(const void *object)
{
	const struct cfg_group_item *cg = object;
	struct cfg_group_item *new = malloc(sizeof(*new));

	if (new) {
		if (cg) {
			new->rules = zlistx_dup(cg->rules);
			new->users = zlistx_dup(cg->users);
		} else {
			new->rules = zlistx_new();
			if (new->rules) {
				zlistx_set_destructor(new->rules, rule_destroy);
				zlistx_set_duplicator(new->rules, rule_dup);
				zlistx_set_comparator(new->rules, rule_compare);
			}

			new->users = zlistx_new();
			if (new->users) {
				zlistx_set_destructor(new->users,
						      users_destroy);
				zlistx_set_duplicator(new->users, users_dup);
				zlistx_set_comparator(new->users,
						      users_compare);
			}
		}
		if (new->users == NULL || new->rules == NULL) {
			group_item_destroy((void **) &new);
			return NULL;
		}
	}

	return new;
}

void npf_rule_group_init(void)
{
	/* Create list */
	group_hash = zhashx_new();

	if (group_hash == NULL)
		rte_panic("NPF cannot init group hash\n");

	zhashx_set_key_hasher(group_hash, group_hasher);
	zhashx_set_key_destructor(group_hash, group_key_destroy);
	zhashx_set_key_duplicator(group_hash, group_key_dup);
	zhashx_set_key_comparator(group_hash, group_key_compare);
	zhashx_set_destructor(group_hash, group_item_destroy);
	zhashx_set_duplicator(group_hash, group_item_dup);
}

static void npf_cfg_rule_event(enum npf_cfg_rule_group_event_type event_type,
			       enum npf_rule_class group_class,
			       const char *group, uint32_t index,
			       struct pmf_rule *parsed,
			       const char *old_rule, const char *new_rule)
{
	struct npf_cfg_rule_group_event event = {.event_type = event_type,
						 .group_class = group_class,
						 .group = group,
						 .index = index,
						 .parsed = parsed,
						 .old_rule = old_rule,
						 .new_rule = new_rule};
	struct npf_rlgrp_key rg_match = {.rgk_class = group_class,
					 .rgk_name = group};
	struct cfg_group_item *cg = zhashx_lookup(group_hash, &rg_match);
	struct cfg_group_user *cu;

	if (cg == NULL)
		return;

	/* Call the event function for each user in the list */
	cu = zlistx_first(cg->users);
	while (cu) {
		if (cu->fn)
			cu->fn(cu->param, &event);
		cu = zlistx_next(cg->users);
	}
}

int npf_cfg_rule_add(enum npf_rule_class group_class, const char *group,
		     uint32_t index, const char *rule)
{
	struct npf_rlgrp_key rg_match = {.rgk_class = group_class,
					 .rgk_name = group};
	struct cfg_group_item *cg = zhashx_lookup(group_hash, &rg_match);
	struct cfg_group_item *new_cg = NULL;
	struct cfg_rule cr_match = {.index = index, .rule = rule};
	struct cfg_rule *cr;
	struct pmf_rule *parsed_rule = NULL;
	int ret;

	if (group_class >= NPF_RULE_CLASS_COUNT)
		return -EINVAL;

	if (cg == NULL) {
		ret = zhashx_insert(group_hash, &rg_match, NULL);
		if (ret == -1)
			goto fail;
		new_cg = zhashx_lookup(group_hash, &rg_match);
		cg = new_cg;
	}
	if (cg == NULL)
		goto fail;

	/* Parse the rule to binary if allowed for this group */
	struct pkp_unused *tail = NULL;
	if (npf_group_class_has_rules(group_class)) {
		int err = pkp_parse_rule_line(rule, &parsed_rule, &tail);
		if (err || !tail)
			goto fail;
	} else if (npf_group_class_rproc_only(group_class)) {
		int err = pkp_parse_rproc_line(rule, &parsed_rule, &tail);
		if (err || !tail)
			goto fail;
	}
	if (tail) {
		if (tail->num_unused) {
			const char *gcn = npf_get_rule_class_name(group_class);
			RTE_LOG(ERR, FIREWALL,
				"NPF: %u ignored pairs in %s:%s rule %u: %s\n",
				tail->num_unused,
				gcn ? gcn : "", group,
				index, rule);

			for (uint32_t idx = 0; idx < tail->num_pairs; ++idx) {
				if (!tail->pairs[idx].key)
					continue;
				RTE_LOG(ERR, FIREWALL,
					"NPF: ignored %s=%s\n",
					tail->pairs[idx].key,
					tail->pairs[idx].value);
			}
			/* Some UTs have garbage, so nothing gets recognised */
			if (tail->num_unused == tail->num_pairs) {
				pmf_rule_free(parsed_rule);
				parsed_rule = NULL;
			}
		}
		free(tail);

		/*
		 * If we do not need to use this yet, throw away the results
		 * unless we have debug enabled.
		 * That way we can enforce correct rule form until we actually
		 * make use of the rules.
		 */
		if (!DP_DEBUG_ENABLED(NPF) &&
		    !npf_group_class_retain_parsed(group_class)) {
			pmf_rule_free(parsed_rule);
			parsed_rule = NULL;
		}
	}

	/* add/replace the rule */
	cr = zlistx_handle_item(zlistx_find(cg->rules, &cr_match));
	if (cr) {
		const char *r = strdup(rule);
		if (r == NULL)
			goto fail;

		struct pmf_rule *old_parsed = cr->parsed;
		cr->parsed = parsed_rule;
		npf_cfg_rule_event(NPF_EVENT_GROUP_RULE_CHANGE, group_class,
				   group, index, parsed_rule, cr->rule, rule);

		free((void *)cr->rule);
		pmf_rule_free(old_parsed);
		cr->rule = r;
	} else {
		cr_match.parsed = parsed_rule;
		/* Insert sorted */
		void *h = zlistx_insert(cg->rules, &cr_match, true);
		if (h == NULL)
			goto fail;

		pmf_rule_free(parsed_rule);

		if (zlistx_size(cg->rules) == 1) { /* was empty */
			npf_cfg_rule_event(NPF_EVENT_GROUP_CREATE, group_class,
					   group, 0, NULL, NULL, NULL);
		}

		npf_cfg_rule_event(NPF_EVENT_GROUP_RULE_ADD, group_class, group,
				   index, parsed_rule, NULL, rule);
	}

	return 0;

fail:
	pmf_rule_free(parsed_rule);
	if (new_cg)
		zhashx_delete(group_hash, &rg_match);

	return -ENOMEM;
}

int npf_cfg_rule_delete(enum npf_rule_class group_class, const char *group,
			uint32_t index, const char *rule)
{
	struct npf_rlgrp_key rg_match = {.rgk_class = group_class,
					 .rgk_name = group};
	struct cfg_group_item *cg = zhashx_lookup(group_hash, &rg_match);
	struct cfg_rule cr_match = {.index = index, .rule = rule};
	struct cfg_rule *cr;
	void *crh;

	if (group_class >= NPF_RULE_CLASS_COUNT)
		return -EINVAL;

	if (cg == NULL)
		return -ENOENT;

	crh = zlistx_find(cg->rules, &cr_match);
	if (crh == NULL)
		return -ENOENT;

	cr = zlistx_handle_item(crh);
	npf_cfg_rule_event(NPF_EVENT_GROUP_RULE_DELETE, group_class, group,
			   index, cr->parsed, cr->rule, NULL);

	if (zlistx_delete(cg->rules, crh)) {
		npf_cfg_rule_event(NPF_EVENT_GROUP_RULE_ADD, group_class, group,
				   index, cr->parsed, NULL, cr->rule);
		return -EINVAL;
	}

	/* If no rules or users delete the group */
	if (zlistx_size(cg->rules) == 0) {
		npf_cfg_rule_event(NPF_EVENT_GROUP_DELETE, group_class, group,
				   0, NULL, NULL, NULL);
		if (zlistx_size(cg->users) == 0)
			zhashx_delete(group_hash, &rg_match);
	}

	return 0;
}

int npf_cfg_group_delete(enum npf_rule_class group_class, const char *group)
{
	struct npf_rlgrp_key rg_match = {.rgk_class = group_class,
					 .rgk_name = group};
	struct cfg_group_item *cg = zhashx_lookup(group_hash, &rg_match);
	struct cfg_rule *cr, *cr_next;
	void *crh;

	if (group_class >= NPF_RULE_CLASS_COUNT)
		return -EINVAL;

	if (cg == NULL)
		return -ENOENT;

	cr = zlistx_first(cg->rules);
	while (cr) {
		npf_cfg_rule_event(NPF_EVENT_GROUP_RULE_DELETE, group_class,
				   group, cr->index,
				   cr->parsed, cr->rule, NULL);
		crh = zlistx_cursor(cg->rules);
		cr_next = zlistx_next(cg->rules);
		if (zlistx_delete(cg->rules, crh)) {
			npf_cfg_rule_event(NPF_EVENT_GROUP_RULE_ADD,
					   group_class, group, cr->index,
					   cr->parsed, NULL, cr->rule);
			return -EINVAL;
		}
		cr = cr_next;
	}

	npf_cfg_rule_event(NPF_EVENT_GROUP_DELETE, group_class, group,
			   0, NULL, NULL, NULL);
	/* If no users delete the group */
	if (zlistx_size(cg->users) == 0)
		zhashx_delete(group_hash, &rg_match);

	return 0;
}

int npf_cfg_all_group_delete(void)
{
	/*
	 * Note that it is not possible to delete while iterating over the
	 * list using zhashx_first()/zhashz_next(), so we look up the keys
	 * first, and then iterate over them to delete entries.
	 */
	zlistx_t *keys = zhashx_keys(group_hash);
	const struct npf_rlgrp_key *rgk;

	if (keys == NULL)
		return -ENOMEM;

	rgk = zlistx_first(keys);
	while (rgk) {
		npf_cfg_group_delete(rgk->rgk_class, rgk->rgk_name);
		rgk = zlistx_next(keys);
	}
	zlistx_destroy(&keys);
	return 0;
}

size_t npf_cfg_rule_count(enum npf_rule_class group_class, const char *group)
{
	struct npf_rlgrp_key rg_match = {.rgk_class = group_class,
					 .rgk_name = group};
	struct cfg_group_item *cg = zhashx_lookup(group_hash, &rg_match);

	if (cg == NULL)
		return 0;

	return zlistx_size(cg->rules);
}

int npf_cfg_rule_group_reg_user(enum npf_rule_class group_class,
				const char *group, void *param,
				npf_cfg_rule_group_event_cb event_cb)
{
	struct npf_rlgrp_key rg_match = {.rgk_class = group_class,
					 .rgk_name = group};
	struct cfg_group_item *cg = zhashx_lookup(group_hash, &rg_match);
	struct cfg_group_item *new_cg = NULL;
	struct cfg_group_user new_cu = {.fn = event_cb, .param = param};
	struct cfg_group_user *cu;
	int ret;
	int err = -ENOMEM;

	if (group_class >= NPF_RULE_CLASS_COUNT)
		return -EINVAL;

	if (cg == NULL) {
		ret = zhashx_insert(group_hash, &rg_match, NULL);
		if (ret == -1)
			goto fail;
		new_cg = zhashx_lookup(group_hash, &rg_match);
		cg = new_cg;
	}
	if (cg == NULL)
		goto fail;

	cu = zlistx_handle_item(zlistx_add_end(cg->users, &new_cu));
	if (cu == NULL)
		goto fail;

	return 0;

fail:
	if (new_cg)
		zhashx_delete(group_hash, &rg_match);

	return err;
}

int npf_cfg_rule_group_dereg_user(enum npf_rule_class group_class,
				  const char *group, void *param)
{
	struct npf_rlgrp_key rg_match = {.rgk_class = group_class,
					 .rgk_name = group};
	struct cfg_group_item *cg = zhashx_lookup(group_hash, &rg_match);
	struct cfg_group_user cu_match = {.param = param};
	void *cuh;

	if (group_class >= NPF_RULE_CLASS_COUNT)
		return -EINVAL;

	if (cg == NULL)
		return -ENOENT;

	cuh = zlistx_find(cg->users, &cu_match);
	if (cuh == NULL)
		return -ENOENT;

	if (zlistx_delete(cg->users, cuh))
		return -EINVAL;

	/* If no rules or users delete the group */
	if (zlistx_size(cg->rules) == 0 && zlistx_size(cg->users) == 0)
		zhashx_delete(group_hash, &rg_match);

	return 0;
}

void npf_cfg_rule_group_walk(enum npf_rule_class group_class, const char *group,
			     void *param,
			     npf_cfg_rule_group_walker_cb walker_cb)
{
	struct npf_rlgrp_key rg_match = {.rgk_class = group_class,
					 .rgk_name = group};
	struct cfg_group_item *cg = zhashx_lookup(group_hash, &rg_match);
	struct cfg_rule *cr;
	struct npf_cfg_rule_walk_state state = { .group_class = group_class,
						 .group = group};

	if (group_class >= NPF_RULE_CLASS_COUNT)
		return;

	if (cg == NULL)
		return;

	/* Call walker_cb for each rule in the group */
	cr = zlistx_first(cg->rules);
	while (cr) {
		state.index = cr->index;
		state.rule = cr->rule;
		state.parsed = cr->parsed;
		if (!walker_cb(param, &state))
			return;
		cr = zlistx_next(cg->rules);
	}
}

void npf_cfg_rule_group_walk_all(void *param,
				 npf_cfg_rule_group_walker_cb walker_cb)
{
	const struct npf_rlgrp_key *rgk;
	struct cfg_group_item *cg;
	struct cfg_rule *cr;
	struct npf_cfg_rule_walk_state state;

	cg = zhashx_first(group_hash);
	while (cg) {
		rgk = zhashx_cursor(group_hash);
		state.group_class = rgk->rgk_class;
		state.group = rgk->rgk_name;

		/* Call walker_cb for each rule in the group */
		cr = zlistx_first(cg->rules);
		while (cr) {
			state.index = cr->index;
			state.rule = cr->rule;
			state.parsed = cr->parsed;
			if (!walker_cb(param, &state))
				return;
			cr = zlistx_next(cg->rules);
		}
		cg = zhashx_next(group_hash);
	}
}

struct rule_class_attrs {
	char const *cl_name;
	uint16_t cl_flags;
};

static struct rule_class_attrs npf_rule_class_attrs[NPF_RULE_CLASS_COUNT] =  {
	[NPF_RULE_CLASS_PORT_GROUP] = {
		.cl_name = "port-group",
	},
	[NPF_RULE_CLASS_ICMP_GROUP] = {
		.cl_name = "icmp-group",
	},
	[NPF_RULE_CLASS_ICMPV6_GROUP] = {
		.cl_name = "icmpv6-group",
	},
	[NPF_RULE_CLASS_ACL] = {
		.cl_name = "acl",
		.cl_flags = CF_HAS_RULE | CF_RETAIN_PARSED,
	},
	[NPF_RULE_CLASS_FW] = {
		.cl_name = "fw",
		.cl_flags = CF_HAS_RULE,
	},
	[NPF_RULE_CLASS_PBR] = {
		.cl_name = "pbr",
		.cl_flags = CF_HAS_RULE,
	},
	[NPF_RULE_CLASS_DNAT] = {
		.cl_name = "dnat",
		.cl_flags = CF_HAS_RULE,
	},
	[NPF_RULE_CLASS_SNAT] = {
		.cl_name = "snat",
		.cl_flags = CF_HAS_RULE,
	},
	[NPF_RULE_CLASS_NAT64] = {
		.cl_name = "nat64",
		.cl_flags = CF_HAS_RULE,
	},
	[NPF_RULE_CLASS_NAT46] = {
		.cl_name = "nat46",
	},
	[NPF_RULE_CLASS_QOS] = {
		.cl_name = "qos",
		.cl_flags = CF_HAS_RULE,
	},
	[NPF_RULE_CLASS_IPSEC] = {
		.cl_name = "ipsec",
		.cl_flags = CF_HAS_RULE,
	},
	[NPF_RULE_CLASS_CUSTOM_TIMEOUT] = {
		.cl_name = "custom-timeout",
	},
	[NPF_RULE_CLASS_SESSION_LIMITER] = {
		.cl_name = "session-limiter",
	},
	[NPF_RULE_CLASS_APP_FW] = {
		.cl_name = "app-firewall",
	},
	[NPF_RULE_CLASS_DSCP_GROUP] = {
		.cl_name = "dscp-group",
	},
	[NPF_RULE_CLASS_PROTOCOL_GROUP] = {
		.cl_name = "protocol-group",
	},
	[NPF_RULE_CLASS_ACTION_GROUP] = {
		.cl_name = "action-group",
		.cl_flags = CF_RPROC_ONLY,
	},
	[NPF_RULE_CLASS_APPLICATION] = {
		.cl_name = "app",
	},
	[NPF_RULE_CLASS_NPTV6_IN] = {
		.cl_name = "nptv6-in",
		.cl_flags = CF_HAS_RULE,
	},
	[NPF_RULE_CLASS_NPTV6_OUT] = {
		.cl_name = "nptv6-out",
		.cl_flags = CF_HAS_RULE,
	},
};

const char *npf_get_rule_class_name(enum npf_rule_class group_class)
{
	if (group_class >= NPF_RULE_CLASS_COUNT)
		return NULL;
	return npf_rule_class_attrs[group_class].cl_name;
}

int npf_get_rule_class(const char *name, enum npf_rule_class *group_class)
{
	enum npf_rule_class c;

	for (c = 0; c < NPF_RULE_CLASS_COUNT; c++) {
		if (strcmp(name, npf_rule_class_attrs[c].cl_name) == 0) {
			*group_class = c;
			return 0;
		}
	}

	return -ENOENT;
}

static bool npf_group_class_has_rules(enum npf_rule_class group_class)
{
	if (group_class >= NPF_RULE_CLASS_COUNT)
		return false;

	uint16_t class_flags = npf_rule_class_attrs[group_class].cl_flags;

	return (class_flags & CF_HAS_RULE);
}

static bool npf_group_class_rproc_only(enum npf_rule_class group_class)
{
	if (group_class >= NPF_RULE_CLASS_COUNT)
		return false;

	uint16_t class_flags = npf_rule_class_attrs[group_class].cl_flags;

	return (class_flags & CF_RPROC_ONLY);
}

static bool npf_group_class_retain_parsed(enum npf_rule_class group_class)
{
	if (group_class >= NPF_RULE_CLASS_COUNT)
		return false;

	uint16_t class_flags = npf_rule_class_attrs[group_class].cl_flags;

	return (class_flags & CF_RETAIN_PARSED);
}
