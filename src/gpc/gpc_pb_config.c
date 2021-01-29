/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Generalised Packet Classification (GPF) configuration handling
 */

#include <errno.h>
#include <netinet/icmp6.h>
#include <urcu/list.h>
#include <vplane_log.h>
#include <vplane_debug.h>
#include <urcu/list.h>
#include "gpc_pb.h"
#include "gpc_util.h"
#include "ip.h"
#include "npf/config/pmf_rule.h"
#include "protobuf.h"
#include "protobuf/GPCConfig.pb-c.h"
#include "protobuf/IPAddress.pb-c.h"
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
gpc_pb_policer_parse(struct _PolicerParams *msg,
		     struct gpc_pb_action *action)
{
	/*
	 * Mandatory field checking.
	 */
	if (!msg->has_bw) {
		RTE_LOG(ERR, GPC,
			"PolicerParams protobuf missing mandatory field\n");
		return -EPERM;
	}

	action->action_value.policer.bw = msg->bw;
	if (msg->has_burst)
		action->action_value.policer.burst = msg->burst;
	if (msg->has_excess_bw)
		action->action_value.policer.excess_bw = msg->excess_bw;
	if (msg->has_excess_burst)
		action->action_value.policer.excess_burst = msg->excess_burst;
	if (msg->has_awareness)
		action->action_value.policer.awareness = msg->awareness;
	return 0;
}

/*
 * GPC match functions
 */
static void
gpc_pb_match_free(struct rcu_head *head)
{
	struct gpc_pb_match *match;

	match = caa_container_of(head, struct gpc_pb_match, match_rcu);
	free(match);
}

static void
gpc_pb_match_delete(struct gpc_pb_match *match)
{
	if (!match)
		return;

	cds_list_del(&match->match_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC match %p\n", match);
	call_rcu(&match->match_rcu, gpc_pb_match_free);
}

static int
gpc_match_ip(uint32_t pt_field __unused, struct pmf_rule *pmf_rule __unused,
	     IPPrefix * proto_pfx __unused,
	     struct ip_prefix *cfg_pfx __unused)
{
	return 0;
}

static int
gpc_match_port(uint32_t pt_field __unused, struct pmf_rule *pmf_rule __unused,
	       uint32_t proto_port __unused, uint32_t *cfg_port __unused)
{
	return 0;
}

static int
gpc_match_fragment(struct pmf_rule *pmf_rule __unused,
		   RuleMatch__FragValue proto_fragment __unused,
		   uint8_t *cfg_fragment __unused)
{
	return 0;
}

static int
gpc_match_dscp(struct pmf_rule *pmf_rule __unused, uint32_t proto_dscp __unused,
	       uint32_t *cfg_dscp __unused)
{
	return 0;
}

static int
gpc_match_ttl(struct pmf_rule *pmf_rule __unused, uint32_t proto_ttl __unused,
	      uint32_t *cfg_ttl __unused)
{
	return 0;
}

static int
gpc_match_icmp(struct pmf_rule *pmf_rule __unused,
	       RuleMatch__ICMPTypeAndCode * proto_icmp __unused,
	       struct icmp_type_code *cfg_icmp __unused, bool is_v4 __unused)
{
	return 0;
}

static int
gpc_match_icmpv6_class(struct pmf_rule *pmf_rule __unused,
		       RuleMatch__ICMPV6Class proto_v6class __unused,
		       uint8_t *cfg_v6class __unused)
{
	return 0;
}

static int
gpc_match_proto(uint32_t pt_field __unused, struct pmf_rule *pmf_rule __unused,
		uint32_t proto_proto __unused, uint32_t *cfg_proto __unused)
{
	return 0;
}

static int
gpc_pb_match_parse(struct gpc_pb_rule *rule, RuleMatch *msg)
{
	struct gpc_pb_match *match;
	struct pmf_rule *pmf_rule = rule->pmf_rule;
	int rv = 0;

	match = calloc(1, sizeof(*match));
	if (!match) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate GPC match\n");
		return -ENOMEM;
	}

	switch (msg->match_value_case) {
	case RULE_MATCH__MATCH_VALUE__NOT_SET:
		match->match_type = GPC_RULE_MATCH_VALUE_NOT_SET;
		rv = -EINVAL;
		break;
	case RULE_MATCH__MATCH_VALUE_SRC_IP:
		match->match_type = GPC_RULE_MATCH_VALUE_SRC_IP;
		rv = gpc_match_ip(PMF_L3F_SRC, pmf_rule, msg->src_ip,
				  &match->match_value.src_ip);
		break;
	case RULE_MATCH__MATCH_VALUE_DEST_IP:
		match->match_type = GPC_RULE_MATCH_VALUE_DEST_IP;
		rv = gpc_match_ip(PMF_L3F_DST, pmf_rule, msg->dest_ip,
				  &match->match_value.dest_ip);
		break;
	case RULE_MATCH__MATCH_VALUE_SRC_PORT:
		match->match_type = GPC_RULE_MATCH_VALUE_SRC_PORT;
		rv = gpc_match_port(PMF_L4F_SRC, pmf_rule, msg->src_port,
				    &match->match_value.src_port);
		break;
	case RULE_MATCH__MATCH_VALUE_DEST_PORT:
		match->match_type = GPC_RULE_MATCH_VALUE_DEST_PORT;
		rv = gpc_match_port(PMF_L4F_DST, pmf_rule, msg->dest_port,
				    &match->match_value.dest_port);
		break;
	case RULE_MATCH__MATCH_VALUE_FRAGMENT:
		match->match_type = GPC_RULE_MATCH_VALUE_FRAGMENT;
		rv = gpc_match_fragment(pmf_rule, msg->fragment,
					&match->match_value.fragment);
		break;
	case RULE_MATCH__MATCH_VALUE_DSCP:
		match->match_type = GPC_RULE_MATCH_VALUE_DSCP;
		rv = gpc_match_dscp(pmf_rule, msg->dscp,
				    &match->match_value.dscp);
		break;
	case RULE_MATCH__MATCH_VALUE_TTL:
		match->match_type = GPC_RULE_MATCH_VALUE_TTL;
		rv = gpc_match_ttl(pmf_rule, msg->ttl, &match->match_value.ttl);
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV4:
		match->match_type = GPC_RULE_MATCH_VALUE_ICMPV4;
		rv = gpc_match_icmp(pmf_rule, msg->icmpv4,
				    &match->match_value.icmpv4, true);
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV6:
		match->match_type = GPC_RULE_MATCH_VALUE_ICMPV6;
		rv = gpc_match_icmp(pmf_rule, msg->icmpv6,
				    &match->match_value.icmpv6, false);
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV6_CLASS:
		match->match_type = GPC_RULE_MATCH_VALUE_ICMPV6_CLASS;
		rv = gpc_match_icmpv6_class(pmf_rule, msg->icmpv6_class,
					    &match->match_value.icmpv6_class);
		break;
	case RULE_MATCH__MATCH_VALUE_PROTO_BASE:
		match->match_type = GPC_RULE_MATCH_VALUE_PROTO_BASE;
		rv = gpc_match_proto(PMF_L3F_PROTOB, pmf_rule, msg->proto_base,
				     &match->match_value.proto_base);
		break;
	case RULE_MATCH__MATCH_VALUE_PROTO_FINAL:
		match->match_type = GPC_RULE_MATCH_VALUE_PROTO_FINAL;
		rv = gpc_match_proto(PMF_L3F_PROTOF, pmf_rule, msg->proto_final,
				     &match->match_value.proto_final);
		break;
	default:
		RTE_LOG(ERR, GPC, "Unknown RuleMatch value case value %u\n",
			msg->match_value_case);
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
gpc_pb_action_free(struct rcu_head *head)
{
	struct gpc_pb_action *action;

	action = caa_container_of(head, struct gpc_pb_action, action_rcu);
	free(action);
}

static void
gpc_pb_action_delete(struct gpc_pb_action *action)
{
	if (!action)
		return;

	cds_list_del(&action->action_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC action %p\n", action);
	call_rcu(&action->action_rcu, gpc_pb_action_free);
}

static int
gpc_pb_action_parse(struct gpc_pb_rule *rule, RuleAction *msg)
{
	struct gpc_pb_action *action;
	struct pmf_rule *pmf_rule = rule->pmf_rule;
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
		switch (action->action_value.decision) {
		case RULE_ACTION__PACKET_DECISION__PASS:
			pmf_rule->pp_action.fate = PMV_TRUE;
			pmf_rule->pp_summary |= PMF_RAS_PASS;
			break;
		case RULE_ACTION__PACKET_DECISION__DROP:
			pmf_rule->pp_action.fate = PMV_FALSE;
			pmf_rule->pp_summary |= PMF_RAS_DROP;
			break;
		default:
			RTE_LOG(ERR, GPC,
				"Unexpected value in rule: decision=%u\n",
				action->action_value.decision);
			rv = -EINVAL;
			break;
		}
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
		RTE_LOG(ERR, GPC, "Unknown RuleAction value case value %u\n",
			msg->action_value_case);
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
	if (!counter)
		return;

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
gpc_pb_rule_free(struct rcu_head *head)
{
	struct gpc_pb_rule *rule;

	rule = caa_container_of(head, struct gpc_pb_rule, rule_rcu);
	free(rule->result);
	free(rule);
}

static void
gpc_pb_rule_delete(struct gpc_pb_rule *rule)
{
	struct gpc_pb_match *match, *tmp_match;
	struct gpc_pb_action *action, *tmp_action;

	if (!rule)
		return;

	cds_list_del(&rule->rule_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC rule %p\n", rule);

	/*
	 * Delete the pmf_rule if we have one attached
	 */
	pmf_rule_free(rule->pmf_rule);
	rule->pmf_rule = NULL;

	/*
	 * Delete any matches and actions attached to this rule
	 */
	cds_list_for_each_entry_safe(match, tmp_match, &rule->match_list,
				     match_list)
		gpc_pb_match_delete(match);

	cds_list_for_each_entry_safe(action, tmp_action, &rule->action_list,
				     action_list)
		gpc_pb_action_delete(action);

	call_rcu(&rule->rule_rcu, gpc_pb_rule_free);
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

	rule = calloc(1, sizeof(*rule));
	if (!rule) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate GPC rule\n");
		return -ENOMEM;
	}

	rule->number = msg->number;
	CDS_INIT_LIST_HEAD(&rule->match_list);
	CDS_INIT_LIST_HEAD(&rule->action_list);

	cds_list_add_tail(&rule->rule_list, &table->rule_list);

	rule->pmf_rule = pmf_rule_alloc();
	if (!rule->pmf_rule) {
		RTE_LOG(ERR, GPC,
			"Failed to allocate PMF rule\n");
		goto error_path;
	}
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

	cds_list_add_tail(&rule->rule_list, &table->rule_list);
	return rv;

 error_path:
	RTE_LOG(ERR, GPC, "Problems parsing Rule protobuf, %d\n", rv);
	gpc_pb_rule_delete(rule);
	return rv;
}

void
gpc_pb_rule_match_walk(struct gpc_pb_rule *rule,
		       gpc_pb_rule_match_walker_cb walker_cb,
		       struct gpc_walk_context *context)
{
	struct gpc_pb_match *match;

	cds_list_for_each_entry(match, &rule->match_list, match_list)
		if (!walker_cb(match, context))
			return;
}

void
gpc_pb_rule_action_walk(struct gpc_pb_rule *rule,
			gpc_pb_rule_action_walker_cb walker_cb,
			struct gpc_walk_context *context)
{
	struct gpc_pb_action *action;

	cds_list_for_each_entry(action, &rule->action_list, action_list)
		if (!walker_cb(action, context))
			return;
}

/*
 * GPC rules functions
 */
static int
gpc_pb_rules_parse(struct gpc_pb_table *table, Rules *msg)
{
	struct gpc_pb_rule *rule, *tmp_rule;
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

	for (i = 0; i < msg->n_rules; i++) {
		rv = gpc_pb_rule_parse(table, msg->rules[i]);
		if (rv)
			goto error_path;
	}
	return rv;

 error_path:
	RTE_LOG(ERR, GPC, "Problems parsing Rules protobuf: %d\n", rv);
	cds_list_for_each_entry_safe(rule, tmp_rule, &table->rule_list,
				     rule_list)
		gpc_pb_rule_delete(rule);

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

	free(table->ifname);
	free(table);
}

static void
gpc_pb_table_delete(struct gpc_pb_table *table)
{
	struct gpc_pb_rule *rule, *tmp_rule;

	if (!table)
		return;

	cds_list_del(&table->table_list);
	DP_DEBUG(GPC, DEBUG, GPC, "Freeing GPC table %p\n", table);

	cds_list_for_each_entry_safe(rule, tmp_rule, &table->rule_list,
				     rule_list)
		gpc_pb_rule_delete(rule);

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
		table->n_table_names = i + 1;
	}

	CDS_INIT_LIST_HEAD(&table->rule_list);

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

void
gpc_pb_table_rule_walk(struct gpc_pb_table *table,
		       gpc_pb_table_rule_walker_cb walker_cb,
		       struct gpc_walk_context *context)
{
	struct gpc_pb_rule *rule;

	cds_list_for_each_entry(rule, &table->rule_list, rule_list)
		if (!walker_cb(rule, context))
			return;
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

	if (!feature)
		return;

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

void
gpc_pb_feature_table_walk(struct gpc_pb_feature *feature,
			  gpc_pb_feature_table_walker_cb walker_cb,
			  struct gpc_walk_context *context)
{
	struct gpc_pb_table *table;

	cds_list_for_each_entry(table, &feature->table_list, table_list) {
		if ((!context->ifname ||
		     !strcmp(table->ifname, context->ifname)) &&
		    (!context->location ||
		     table->location == context->location) &&
		    (!context->traffic_type ||
		     table->traffic_type == context->traffic_type))
			if (!walker_cb(table, context))
				return;
	}
}

void
gpc_pb_feature_counter_walk(struct gpc_pb_feature *feature,
			    gpc_pb_feature_counter_walker_cb walker_cb,
			    struct gpc_walk_context *context)
{
	struct gpc_pb_counter *counter;

	cds_list_for_each_entry(counter, &feature->counter_list, counter_list)
		if (!walker_cb(counter, context))
			return;
}

void
gpc_pb_feature_walk(gpc_pb_feature_walker_cb walker_cb,
		    struct gpc_walk_context *context)
{
	struct gpc_pb_feature *feature;

	if (gpc_feature_list)
		cds_list_for_each_entry(feature, gpc_feature_list, feature_list)
			if (!context->feature_type ||
			    feature->type == context->feature_type)
				if (!walker_cb(feature, context))
					return;
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
