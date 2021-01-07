/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Generalised Packet Classification (GPF) configuration handling
 */

#ifndef GPC_PB_H
#define GPC_PB_H

#include <urcu/list.h>
#include "fal_plugin.h"
#include "ip.h"
#include "npf/config/pmf_rule.h"
#include "urcu.h"
#include "util.h"

/*
 * Enum definitions
 */
enum policer_flags_type {
	POLICER_HAS_BW           = (1 << 0),
	POLICER_HAS_BURST        = (1 << 1),
	POLICER_HAS_EXCESS_BW    = (1 << 2),
	POLICER_HAS_EXCESS_BURST = (1 << 3),
	POLICER_HAS_AWARENESS    = (1 << 4),
};

enum gpc_rule_match_value_type {
	GPC_RULE_MATCH_VALUE_NOT_SET,
	GPC_RULE_MATCH_VALUE_SRC_IP,
	GPC_RULE_MATCH_VALUE_DEST_IP,
	GPC_RULE_MATCH_VALUE_SRC_PORT,
	GPC_RULE_MATCH_VALUE_DEST_PORT,
	GPC_RULE_MATCH_VALUE_FRAGMENT,
	GPC_RULE_MATCH_VALUE_DSCP,
	GPC_RULE_MATCH_VALUE_TTL,
	GPC_RULE_MATCH_VALUE_ICMPV4,
	GPC_RULE_MATCH_VALUE_ICMPV6,
	GPC_RULE_MATCH_VALUE_ICMPV6_CLASS,
	GPC_RULE_MATCH_VALUE_PROTO_BASE,
	GPC_RULE_MATCH_VALUE_PROTO_FINAL,
};

enum gpc_rule_action_value_type {
	GPC_RULE_ACTION_VALUE_NOT_SET,
	GPC_RULE_ACTION_VALUE_DECISION,
	GPC_RULE_ACTION_VALUE_DESIGNATION,
	GPC_RULE_ACTION_VALUE_COLOUR,
	GPC_RULE_ACTION_VALUE_POLICER,
};

enum gpc_counter_type {
	GPC_COUNTER_TYPE_UNKNOWN,
	GPC_COUNTER_TYPE_DISABLED,
	GPC_COUNTER_TYPE_AUTO,
	GPC_COUNTER_TYPE_NAMED,
};

enum gpc_config_action {
	CREATE,
	MODIFY,
	DELETE
};

/*
 * Constants
 */
#define GPC_MAX_DESIGNATION 7

/*
 * Structure definitions
 */
struct ip_prefix {
	uint32_t prefix_length;
	struct ip_addr addr;
};

struct gpc_pb_policer {
	uint64_t        bw;
	uint64_t        burst;
	uint64_t        excess_bw;
	uint64_t        excess_burst;
	uint32_t        flags;
	uint8_t         awareness;
	fal_object_t    objid;
};

/*
 * Each rule can have a single action.
 */
struct gpc_pb_action {
	struct cds_list_head		action_list;
	struct rcu_head			action_rcu;
	enum gpc_rule_action_value_type action_type;
	union gpc_pb_action_value_t {
		uint8_t			decision;
		uint8_t			designation;
		uint8_t			colour;
		struct gpc_pb_policer	policer;
	} action_value;
};

struct icmp_type_code {
	uint32_t        typenum;
	uint32_t        code;
	bool            has_typenum;
	bool            has_code;
};

/*
 * Each rule can have multiple matches, but only one of each type, so a
 * maximum of 12.
 */
struct gpc_pb_match {
	struct cds_list_head		match_list;
	struct rcu_head			match_rcu;
	enum gpc_rule_match_value_type	match_type;
	union gpc_pb_match_value_t {
		struct ip_prefix	src_ip;
		struct ip_prefix	dest_ip;
		uint32_t		src_port;
		uint32_t		dest_port;
		uint8_t			fragment;
		uint32_t		dscp;
		uint32_t		ttl;
		struct icmp_type_code	icmpv4;
		struct icmp_type_code	icmpv6;
		uint8_t			icmpv6_class;
		uint32_t		proto_base;
		uint32_t		proto_final;
	} match_value;
};

struct gpc_pb_counter {
	struct cds_list_head	counter_list;
	struct rcu_head		counter_rcu;
	/* format - packet-only/packets-and-bytes */
	uint32_t		format;
	char			*name;
};

struct gpc_pb_rule_counter {
	uint32_t		counter_type;
	char			*name;
};

/*
 * Each user-visible table can have up to 9999 rules.  However the VCI code can
 * collapse multiple tables from the same feature togther, renumbering the rules
 * so that they are guaranteed to arrive in numercial order.
 */
struct gpc_pb_rule {
	/* The following field uniquely identifies the rule */
	uint32_t			number;
	/* Other operational fields */
	struct cds_list_head		match_list;
	struct cds_list_head		action_list;
	struct gpc_pb_rule_counter	counter;
	struct pmf_rule			*pmf_rule;
	/*
	 * The VCI code can collapse multiple tables into a single table.
	 * The following fields tell us what table this rule originally
	 * came from, what its original rule-number was, and the name of the
	 * result associated with it.
	 */
	/* Debug fields */
	uint32_t			table_index;
	uint32_t			orig_number;
	char				*result;
};

/*
 * Each feature can have up to three tables per interface.
 * An ingress table, an egress table and a punt-path table.
 * Some features, e.g. QoS, will only have a single table per interface.
 */
struct gpc_pb_table {
	struct cds_list_head		table_list;
	struct rcu_head			table_rcu;
	/* The following two fields uniquely identify this table */
	char				*ifname;
	/* location - ingress/egress/punt-path */
	uint32_t			location;
	/* Other operational fields */
	uint32_t			n_rules;
	/*
	 * The protobuf tells us how many rules are in the rules_table so
	 * we can allocate memory for all the rules in a single chunk.
	 */
	struct gpc_pb_rule		*rules_table;
	/* traffic-type - ipv4/ipv6 */
	uint32_t			traffic_type;
	/*
	 * The VCI code can collapse multiple tables into a single table.
	 * The following fields allows us to identify the user-visible table's
	 * name using the table_index field from the gpc_pb_rule struct.
	 */
	uint32_t			n_table_names;
	/* The following array is variable length */
	char				*table_names[0];
};

/*
 * Currently only two features are supported, QoS and ACL.  In the future
 * CPP may also be added.
 */
struct gpc_pb_feature {
	struct cds_list_head	feature_list;
	struct rcu_head		feature_rcu;
	/* Feature type uniquely identifies each feature */
	uint32_t		type;
	/* Other operational fields */
	struct cds_list_head	table_list;
	struct cds_list_head	counter_list;
};

struct gpc_walk_context {
	uint32_t	feature_type;
	char		*ifname;
	uint32_t	location;
	uint32_t	traffic_type;
	void		*data;
};

/**
 * Type for function passed in as a parameter in calls to
 * gpc_pb_rule_match_walk()
 */
typedef bool (gpc_pb_rule_match_walker_cb)(struct gpc_pb_match *match,
					   struct gpc_walk_context *context);

/**
 * Walk over the matches of a GPC rule, calling a function for each match.
 *
 * @param rule A pointer to the GPC protobuf rule to walk.
 * @param walker_cb This function is called back.
 *	The function should return "true" to continue to the next entry,
 *	or "false" to end the walk of entries.
 * @param context This is passed into the walker_cb() function.
 */
void
gpc_pb_rule_match_walk(struct gpc_pb_rule *rule,
		       gpc_pb_rule_match_walker_cb walker_cb,
		       struct gpc_walk_context *context);

/**
 * Type for function passed in as a parameter in calls to
 * gpc_pb_rule_action_walk()
 */
typedef bool (gpc_pb_rule_action_walker_cb)(struct gpc_pb_action *action,
					    struct gpc_walk_context *context);

/**
 * Walk over the actions of a GPC rule, calling a function for each action.
 *
 * @param rule A pointer to the GPC protobuf rule to walk.
 * @param walker_cb This function is called back.
 *	The function should return "true" to continue to the next entry,
 *	or "false" to end the walk of entries.
 * @param context This is passed into the walker_cb() function.
 */
void
gpc_pb_rule_action_walk(struct gpc_pb_rule *rule,
			gpc_pb_rule_action_walker_cb walker_cb,
			struct gpc_walk_context *context);

/**
 * Type for function passed in as a parameter in calls to
 * gpc_pb_table_rule_walk()
 */
typedef bool (gpc_pb_table_rule_walker_cb)(struct gpc_pb_rule *rule,
					   struct gpc_walk_context *context);

/**
 * Walk over the rules of a GPC table, calling a function for each rule.
 *
 * @param table A pointer to the GPC table to walk.
 * @param walker_cb This function is called back.
 *	The function should return "true" to continue to the next entry,
 *	or "false" to end the walk of entries.
 * @param context This is passed into the walker_cb() function.
 */
void
gpc_pb_table_rule_walk(struct gpc_pb_table *table,
		       gpc_pb_table_rule_walker_cb walker_cb,
		       struct gpc_walk_context *context);

/**
 * Type for function passed in as a parameter in calls to
 * gpc_pb_feature_table_walk()
 */
typedef bool (gpc_pb_feature_table_walker_cb)(struct gpc_pb_table *table,
					      struct gpc_walk_context *context);

/**
 * Walk over the tables of a GPC feature, calling a function for each table.
 *
 * @param feature A pointer to the GPC feature to walk.
 * @param walker_cb This function is called back.
 *	The function should return "true" to continue to the next entry,
 *	or "false" to end the walk of entries.
 * @param context This is passed into the walker_cb() function.
 */
void gpc_pb_feature_table_walk(struct gpc_pb_feature *feature,
			       gpc_pb_feature_table_walker_cb walker_cb,
			       struct gpc_walk_context *context);

/**
 * Type for function passed in as a parameter in calls to
 * gpc_pb_feature_counter_walk()
 */
typedef bool (gpc_pb_feature_counter_walker_cb)(struct gpc_pb_counter *counter,
					      struct gpc_walk_context *context);

/**
 * Walk over the counters of a GPC feature, calling a function for each table.
 *
 * @param feature A pointer to the GPC feature to walk.
 * @param walker_cb This function is called back.
 *	The function should return "true" to continue to the next entry,
 *	or "false" to end the walk of entries.
 * @param context This is passed into the walker_cb() function.
 */
void gpc_pb_feature_counter_walk(struct gpc_pb_feature *feature,
				 gpc_pb_feature_counter_walker_cb walker_cb,
				 struct gpc_walk_context *context);


/**
 * Type for function passed in as a parameter in calls to
 * gpc_pb_feature_walk()
 */
typedef bool (gpc_pb_feature_walker_cb)(struct gpc_pb_feature *feature,
					struct gpc_walk_context *context);

/**
 * Walk over the features of the GPC config, calling a function for each
 * feature.
 *
 * @param walker_cb This function is called back.
 *	The function should return "true" to continue to the next entry,
 *	or "false" to end the walk of entries.
 * @param context This is passed into the walker_cb() function.
 */
void gpc_pb_feature_walk(gpc_pb_feature_walker_cb walker_cb,
			 struct gpc_walk_context *context);

#endif /* GPC_PB_H */
