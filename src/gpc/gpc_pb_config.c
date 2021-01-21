/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Generalised Packet Classification (GPF) configuration handling
 */

#include <assert.h>
#include <errno.h>
#include <vplane_log.h>
#include <vplane_debug.h>
#include <urcu/list.h>
#include "gpc_pb.h"
#include "gpc_util.h"
#include "ip.h"
#include "protobuf.h"
#include "protobuf/GPCConfig.pb-c.h"
#include "urcu.h"
#include "util.h"

/*
 * Local storage
 */
static struct cds_list_head *gpc_feature_list;

/*
 * Protobuf parsing functions
 */

static int
gpc_pb_policer_parse(struct _PolicerParams *msg __unused,
		     struct gpc_pb_action *action __unused)
{
	return 0;
}

/*
 * GPC match functions
 */
static void
gpc_pb_match_delete(struct gpc_pb_match *match)
{
	assert(match);

	cds_list_del(&match->match_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC match %p\n", match);
	free(match);
}

static int
gpc_pb_match_parse(struct gpc_pb_rule *rule, RuleMatch *msg)
{
	struct gpc_pb_match *match;
	int rv = 0;

	match = calloc(1, sizeof(*match));
	if (!match) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate GPC match\n");
		return -ENOMEM;
	}

	switch (msg->match_value_case) {
	case RULE_MATCH__MATCH_VALUE__NOT_SET:
		rv = -EINVAL;
		break;
	case RULE_MATCH__MATCH_VALUE_SRC_IP:
		match->match_type = GPC_RULE_MATCH_VALUE_SRC_IP;
		break;
	case RULE_MATCH__MATCH_VALUE_DEST_IP:
		match->match_type = GPC_RULE_MATCH_VALUE_DEST_IP;
		break;
	case RULE_MATCH__MATCH_VALUE_SRC_PORT:
		match->match_type = GPC_RULE_MATCH_VALUE_SRC_PORT;
		match->match_value.src_port = msg->src_port;
		break;
	case RULE_MATCH__MATCH_VALUE_DEST_PORT:
		match->match_type = GPC_RULE_MATCH_VALUE_DEST_PORT;
		match->match_value.dest_port = msg->dest_port;
		break;
	case RULE_MATCH__MATCH_VALUE_FRAGMENT:
		match->match_type = GPC_RULE_MATCH_VALUE_FRAGMENT;
		match->match_value.fragment = msg->fragment;
		break;
	case RULE_MATCH__MATCH_VALUE_DSCP:
		match->match_type = GPC_RULE_MATCH_VALUE_DSCP;
		match->match_value.dscp = msg->dscp;
		break;
	case RULE_MATCH__MATCH_VALUE_TTL:
		match->match_type = GPC_RULE_MATCH_VALUE_TTL;
		match->match_value.ttl = msg->ttl;
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV4:
		match->match_type = GPC_RULE_MATCH_VALUE_ICMPV4;
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV6:
		match->match_type = GPC_RULE_MATCH_VALUE_ICMPV6;
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV6_CLASS:
		match->match_type = GPC_RULE_MATCH_VALUE_ICMPV6_CLASS;
		match->match_value.icmpv6_class = msg->icmpv6_class;
		break;
	case RULE_MATCH__MATCH_VALUE_PROTO_BASE:
		match->match_type = GPC_RULE_MATCH_VALUE_PROTO_BASE;
		match->match_value.proto_base = msg->proto_base;
		break;
	case RULE_MATCH__MATCH_VALUE_PROTO_FINAL:
		match->match_type = GPC_RULE_MATCH_VALUE_PROTO_FINAL;
		match->match_value.proto_final = msg->proto_final;
		break;
	default:
		rv = -EINVAL;
		break;
	}
	if (rv) {
		free(match);
	} else {
		cds_list_add_tail(&match->match_list, &rule->match_list);
		DP_DEBUG(GPC, DEBUG, GPC,
			 "Added GPC match %p to GPC rule %p\n",
			 match, rule);
	}
	return rv;
}

/*
 * GPC action functions
 */
static void
gpc_pb_action_delete(struct gpc_pb_action *action)
{
	assert(action);

	cds_list_del(&action->action_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC action %p\n", action);
	free(action);

}

static int
gpc_pb_action_parse(struct gpc_pb_rule *rule, RuleAction *msg)
{
	struct gpc_pb_action *action;
	int rv = 0;

	action = calloc(1, sizeof(*action));
	if (!action) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate GPC action\n");
		return -ENOMEM;
	}

	switch (msg->action_value_case) {
	case RULE_ACTION__ACTION_VALUE__NOT_SET:
		rv = -EINVAL;
		break;
	case RULE_ACTION__ACTION_VALUE_DECISION:
		action->action_type = GPC_RULE_ACTION_VALUE_DECISION;
		action->action_value.decision = msg->decision;
		break;
	case RULE_ACTION__ACTION_VALUE_DESIGNATION:
		action->action_type = GPC_RULE_ACTION_VALUE_DESIGNATION;
		action->action_value.designation = msg->designation;
		break;
	case RULE_ACTION__ACTION_VALUE_COLOUR:
		action->action_type = GPC_RULE_ACTION_VALUE_COLOUR;
		action->action_value.colour = msg->colour;
		break;
	case RULE_ACTION__ACTION_VALUE_POLICER:
		action->action_type = GPC_RULE_ACTION_VALUE_POLICER;
		rv = gpc_pb_policer_parse(msg->policer, action);
		break;
	default:
		rv = -EINVAL;
		break;
	}
	if (rv) {
		free(action);
	} else {
		cds_list_add_tail(&action->action_list, &rule->action_list);
		DP_DEBUG(GPC, DEBUG, GPC,
			 "Added GPC action %p to GPC rule %p\n",
			 action, rule);
	}
	return rv;
}

/*
 * GPC counter functions
 */
static void
gpc_pb_counter_free(struct rcu_head *head)
{
	struct gpc_pb_counter *counter;

	counter = caa_container_of(head, struct gpc_pb_counter, counter_rcu);
	free(counter->name);
	free(counter);
}

static void
gpc_pb_counter_delete(struct gpc_pb_counter *counter)
{
	assert(counter);

	cds_list_del(&counter->counter_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC counter %p\n", counter);

	call_rcu(&counter->counter_rcu, gpc_pb_counter_free);
}

static int
gpc_pb_counter_parse(struct gpc_pb_feature *feature, GPCCounter *msg)
{
	struct gpc_pb_counter *counter;

	/*
	 * Mandatory field checking.
	 */
	if (!msg->has_format) {
		RTE_LOG(ERR, GPC,
			"GPCCounter protobuf missing mandatory field\n");
		return -EPERM;
	}

	counter = calloc(1, sizeof(*counter));
	if (!counter) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate GPC counter\n");
		return -ENOMEM;
	}

	counter->format = msg->format;
	if (msg->name) {
		counter->name = strdup(msg->name);
		if (!counter->name) {
			RTE_LOG(ERR, GPC,
				"Failed to allocate name for counter\n");
			goto error_path;
		}
	}

	cds_list_add_tail(&counter->counter_list, &feature->counter_list);
	DP_DEBUG(GPC, DEBUG, GPC,
		 "Added GPC counter %p to GPC feature %p\n",
		 counter, feature);

	return 0;

 error_path:
	free(counter);
	return -ENOMEM;
}

static int
gpc_pb_rule_counter_parse(struct gpc_pb_rule *rule, RuleCounter *msg)
{
	struct gpc_pb_rule_counter *counter = &rule->counter;
	int rv = 0;

	/*
	 * Mandatory field checking.
	 */
	if (!msg->has_counter_type) {
		RTE_LOG(ERR, GPC,
			"RuleCounter protobuf missing mandatory field\n");
		return -EPERM;
	}

	switch (msg->counter_type) {
	case RULE_COUNTER__COUNTER_TYPE__COUNTER_UNKNOWN:
		counter->counter_type = GPC_COUNTER_TYPE_UNKNOWN;
		break;
	case RULE_COUNTER__COUNTER_TYPE__DISABLED:
		counter->counter_type = GPC_COUNTER_TYPE_DISABLED;
		break;
	case RULE_COUNTER__COUNTER_TYPE__AUTO:
		counter->counter_type = GPC_COUNTER_TYPE_AUTO;
		break;
	case RULE_COUNTER__COUNTER_TYPE__NAMED:
		counter->counter_type = GPC_COUNTER_TYPE_NAMED;
		if (msg->name) {
			counter->name = strdup(msg->name);
			if (!counter->name) {
				RTE_LOG(ERR, GPC,
					"Failed to allocate counter name\n");
				return -ENOMEM;
			}
		}
		break;
	default:
		RTE_LOG(ERR, GPC, "Unknown rule counter type %u\n",
			msg->counter_type);
		rv = -EINVAL;
		break;
	}

	return rv;
}

/*
 * GPC rule functions
 */

static void
gpc_pb_rule_delete(struct gpc_pb_rule *rule)
{
	struct gpc_pb_match *match, *tmp_match;
	struct gpc_pb_action *action, *tmp_action;

	assert(rule);

	if (rule->number == 0)
		return;

	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC rule: %u at %p\n",
		 rule->number, rule);

	/*
	 * Mark the rule as unused.
	 */
	rule->number = 0;

	/*
	 * Delete any matches and actions attached to this rule
	 */
	cds_list_for_each_entry_safe(match, tmp_match, &rule->match_list,
				     match_list)
		gpc_pb_match_delete(match);

	cds_list_for_each_entry_safe(action, tmp_action, &rule->action_list,
				     action_list)
		gpc_pb_action_delete(action);

}

static int
gpc_pb_rule_parse(struct gpc_pb_table *table, Rule *msg)
{
	struct gpc_pb_rule *rule;
	uint32_t i;
	int rv = 0;

	if (!msg) {
		RTE_LOG(ERR, GPC,
			"Failed to read Rule protobuf\n");
		return -EPERM;
	}
	/*
	 * Mandatory field checking.
	 */
	if (!msg->has_number) {
		RTE_LOG(ERR, GPC,
			"Rule protobuf missing mandatory field\n");
		return -EPERM;
	}

	/*
	 * We never have a rule 0, we always start with rule 1, hence the -1
	 */
	rule = &table->rules_table[msg->number - 1];

	/*
	 * Initialise the rule's list heads before we mark it as used
	 */
	CDS_INIT_LIST_HEAD(&rule->match_list);
	CDS_INIT_LIST_HEAD(&rule->action_list);

	/*
	 * Mark the rule as used, that is non-zero
	 */
	rule->number = msg->number;

	for (i = 0; i < msg->n_matches; i++) {
		rv = gpc_pb_match_parse(rule, msg->matches[i]);
		if (rv)
			goto error_path;
	}

	for (i = 0; i < msg->n_actions; i++)  {
		rv = gpc_pb_action_parse(rule, msg->actions[i]);
		if (rv)
			goto error_path;
	}

	if (msg->counter) {
		rv = gpc_pb_rule_counter_parse(rule, msg->counter);
		if (rv)
			goto error_path;
	}

	if (msg->has_table_index)
		rule->table_index = msg->table_index;

	if (msg->has_orig_number)
		rule->orig_number = msg->orig_number;

	if (msg->result) {
		rule->result = strdup(msg->result);
		if (!rule->result) {
			RTE_LOG(ERR, GPC, "Failed to allocate result name\n");
			rv = -ENOMEM;
			goto error_path;
		}
	}
	return rv;

 error_path:
	RTE_LOG(ERR, GPC, "Problems parsing Rule protobuf, %d\n", rv);
	gpc_pb_rule_delete(rule);
	return rv;
}

/*
 * GPC rules functions
 */
static int
gpc_pb_rules_parse(struct gpc_pb_table *table, Rules *msg)
{
	uint32_t i;
	int rv;

	if (!msg) {
		RTE_LOG(ERR, GPC,
			"Failed to read Rules protobuf\n");
		return -EPERM;
	}
	/*
	 * Mandatory field checking.
	 */
	if (!msg->traffic_type) {
		RTE_LOG(ERR, GPC,
			"Rules protobuf missing mandatory field\n");
		return -EPERM;
	}

	table->traffic_type = msg->traffic_type;

	table->rules_table = calloc(msg->n_rules, sizeof(struct gpc_pb_rule));
	if (!table->rules_table) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate rules-table for %lu rules\n",
			msg->n_rules);
		rv = -ENOMEM;
		goto error_path;
	}

	table->n_rules = msg->n_rules;
	for (i = 0; i < table->n_rules; i++) {
		rv = gpc_pb_rule_parse(table, msg->rules[i]);
		if (rv)
			goto error_path;
	}
	return rv;

 error_path:
	RTE_LOG(ERR, GPC, "Problems parsing Rules protobuf: %d\n", rv);
	if (table->rules_table) {
		for (i = 0; i < table->n_rules; i++)
			gpc_pb_rule_delete(&table->rules_table[i]);
	}
	free(table->rules_table);
	table->rules_table = NULL;
	return rv;
}

/*
 * GPC table functions
 */
static void
gpc_pb_table_free(struct rcu_head *head)
{
	struct gpc_pb_table *table;
	uint32_t i;

	table = caa_container_of(head, struct gpc_pb_table, table_rcu);

	for (i = 0; i < table->n_table_names; i++)
		free(table->table_names[i]);

	free(table->rules_table);
	free(table->ifname);
	free(table);
}

static void
gpc_pb_table_delete(struct gpc_pb_table *table)
{
	uint32_t i;

	assert(table);

	cds_list_del(&table->table_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC table %p\n", table);

	for (i = 0; i < table->n_rules; i++)
		gpc_pb_rule_delete(&table->rules_table[i]);

	call_rcu(&table->table_rcu, gpc_pb_table_free);
}

static struct gpc_pb_table *
gpc_pb_table_find(struct gpc_pb_feature *feature, const char *ifname,
		  uint32_t location, uint32_t traffic_type)
{
	struct gpc_pb_table *table;

	cds_list_for_each_entry(table, &feature->table_list, table_list) {
		if (!strcmp(table->ifname, ifname) &&
		    table->location == location &&
		    table->traffic_type == traffic_type)
			return table;
	}
	return NULL;
}

static int
gpc_pb_table_add(struct gpc_pb_feature *feature, GPCTable *msg)
{
	struct gpc_pb_table *table;
	uint32_t i;
	int rv = 0;

	table = calloc(1, sizeof(*table) +
		       (sizeof(char *) * msg->n_table_names));
	if (!table) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate GPC table");
		return -ENOMEM;
	}

	table->ifname = strdup(msg->ifname);
	if (!table->ifname) {
		rv = -ENOMEM;
		goto error_path;
	}
	table->location = msg->location;

	cds_list_add_tail(&table->table_list, &feature->table_list);
	DP_DEBUG(GPC, DEBUG, GPC,
		 "Allocated GPC table %p for %s/%s\n",
		 table, table->ifname,
		 gpc_get_table_location_str(table->location));

	for (i = 0; i < msg->n_table_names; i++) {
		table->table_names[i] = strdup(msg->table_names[i]);
		if (!table->table_names[i]) {
			rv = -ENOMEM;
			goto error_path;
		}
		table->n_table_names = i;
	}

	/* Parse the rest of config message */
	rv = gpc_pb_rules_parse(table, msg->rules);
	if (rv)
		goto error_path;

	return rv;

 error_path:
	RTE_LOG(ERR, GPC, "Failed to allocate memory for table\n");
	gpc_pb_table_delete(table);

	return rv;

}

static int
gpc_pb_table_parse(struct gpc_pb_feature *feature, GPCTable *msg)
{
	struct gpc_pb_table *table;
	enum gpc_config_action action;
	int rv;

	if (!msg) {
		RTE_LOG(ERR, GPC,
			"Failed to read GPCTable protobuf\n");
		return -EPERM;
	}
	/*
	 * Mandatory field checking.
	 */
	if (!msg->ifname || !msg->has_location || !msg->has_traffic_type) {
		RTE_LOG(ERR, GPC,
			"GPCTable protobuf missing mandatory field\n");
		return -EPERM;
	}

	action = CREATE;
	table = gpc_pb_table_find(feature, msg->ifname, msg->location,
				  msg->traffic_type);
	if (table) {
		/*
		 * If the table already exists, we delete it if the new
		 * msg has no rules.  This is because if a GPC feature, e.g.
		 * ACL has more than one table of the same type (IPv4/IPv6),
		 * at the same location (ingress/egress/punt-path) and on the
		 * same interface, the VCI code will have collapsed them into
		 * a single table.  The multiple tables allow different ACL
		 * use-cases to have separate tables in the CLI.
		 */
		DP_DEBUG(GPC, DEBUG, GPC,
			 "Found existing table %s/%s, msg->rules: %p\n",
			 msg->ifname,
			 gpc_get_table_location_str(msg->location),
			 msg->rules);
		if (!msg->rules)
			action = DELETE;
		else
			action = MODIFY;
	}

	switch (action) {
	case CREATE:
		rv = gpc_pb_table_add(feature, msg);
		break;

	case MODIFY:
		/*
		 * Modifies are "nuke-and-rebuild" to start with.
		 * We will do in-place modifications at a later date.
		 */
		gpc_pb_table_delete(table);
		rv  = gpc_pb_table_add(feature, msg);
		break;

	case DELETE:
		gpc_pb_table_delete(table);
		rv = 0;
		break;

	default:
		break;
	}
	return rv;
}

/*
 * GPC feature functions
 */
static void
gpc_pb_feature_free(struct rcu_head *head)
{
	struct gpc_pb_feature *feature;

	feature = caa_container_of(head, struct gpc_pb_feature, feature_rcu);
	free(feature);
}

static void
gpc_pb_feature_delete(struct gpc_pb_feature *feature)
{
	struct gpc_pb_table *table, *tmp_table;
	struct gpc_pb_counter *counter, *tmp_counter;

	assert(feature);

	cds_list_del(&feature->feature_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC feature %p\n", feature);

	cds_list_for_each_entry_safe(table, tmp_table, &feature->table_list,
				     table_list)
		gpc_pb_table_delete(table);

	cds_list_for_each_entry_safe(counter, tmp_counter,
				     &feature->counter_list,
				     counter_list)
		gpc_pb_counter_delete(counter);

	call_rcu(&feature->feature_rcu, gpc_pb_feature_free);
}

static struct gpc_pb_feature *
gpc_pb_feature_find(uint32_t type)
{
	struct gpc_pb_feature *feature;

	if (!gpc_feature_list)
		return NULL;

	cds_list_for_each_entry(feature, gpc_feature_list, feature_list) {
		if (feature->type == type)
			return feature;
	}
	return NULL;
}

static int
gpc_pb_feature_add(GPCConfig *msg)
{
	struct gpc_pb_feature *feature;
	uint32_t i;
	int32_t rv;

	feature = calloc(1, sizeof(*feature));
	if (!feature) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate GPC feature");
		return -ENOMEM;
	}

	feature->type = msg->feature_type;

	DP_DEBUG(GPC, DEBUG, GPC,
		 "Allocated GPC feature %p for %s\n", feature,
		 gpc_get_feature_type_str(feature->type));

	CDS_INIT_LIST_HEAD(&feature->table_list);
	CDS_INIT_LIST_HEAD(&feature->counter_list);
	cds_list_add_tail(&feature->feature_list, gpc_feature_list);

	/* Parse the rest of config message */
	for (i = 0; i < msg->n_tables; i++) {
		rv = gpc_pb_table_parse(feature, msg->tables[i]);
		if (rv)
			goto error_path;
	}

	for (i = 0; i < msg->n_counters; i++) {
		rv = gpc_pb_counter_parse(feature, msg->counters[i]);
		if (rv)
			goto error_path;
	}
	return 0;

 error_path:
	RTE_LOG(ERR, GPC, "Failed to add GPC feature, type: %s: %d\n",
		gpc_get_feature_type_str(feature->type), rv);
	gpc_pb_feature_delete(feature);
	return rv;
}

static int
gpc_pb_feature_parse(GPCConfig *msg)
{
	struct gpc_pb_feature *feature;
	enum gpc_config_action action;
	int rv;

	if (!msg) {
		RTE_LOG(ERR, GPC,
			"Failed to read GPCConfig protobuf\n");
		return -EPERM;
	}

	if (!msg->has_feature_type) {
		RTE_LOG(ERR, GPC,
			"GPCConfig protobuf missing mandatory field\n");
		return -EPERM;
	}

	action = CREATE;
	feature = gpc_pb_feature_find(msg->feature_type);
	if (feature) {
		/*
		 * If the feature already exists we delete it if the new
		 * config-msg has no tables.
		 */
		if (!msg->n_tables)
			action = DELETE;
		else
			action = MODIFY;
	}

	switch (action) {
	case CREATE:
		rv = gpc_pb_feature_add(msg);
		break;

	case MODIFY:
		/*
		 * Modifies are "nuke-and-rebuild" to start with.
		 * We will do in-place modifications at a later date.
		 */
		gpc_pb_feature_delete(feature);
		rv = gpc_pb_feature_add(msg);
		break;

	case DELETE:
		gpc_pb_feature_delete(feature);
		rv = 0;
		break;

	default:
		rv = -EINVAL;
		break;
	}
	return rv;
}

static int
gpc_config(struct pb_msg *msg)
{
	GPCConfig *config_msg = gpcconfig__unpack(NULL, msg->msg_len,
						  msg->msg);
	int rv;

	/*
	 * Carry out any one-time initialisation
	 */
	if (!gpc_feature_list) {
		gpc_feature_list = calloc(1, sizeof(*gpc_feature_list));
		if (!gpc_feature_list) {
			RTE_LOG(ERR, GPC, "Failed to initialise GPC\n");
			return -ENOMEM;
		}

		CDS_INIT_LIST_HEAD(gpc_feature_list);
	}

	rv = gpc_pb_feature_parse(config_msg);

	gpcconfig__free_unpacked(config_msg, NULL);
	return rv;
}

PB_REGISTER_CMD(gpc_config_cmd) = {
	.cmd = "vyatta:gpc-config",
	.handler = gpc_config,
};
