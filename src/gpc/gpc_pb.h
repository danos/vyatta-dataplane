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
#include "ip.h"
#include "urcu.h"
#include "util.h"

/*
 * Enum definitions
 */
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
	uint8_t         awareness;
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
	struct cds_list_head		rule_list;
	struct rcu_head			rule_rcu;
	/* The following field uniquely identifies the rule */
	uint32_t			number;
	/* Other operational fields */
	struct cds_list_head		match_list;
	struct cds_list_head		action_list;
	struct gpc_pb_rule_counter	counter;
	/*
	 * The VCI code can collapse multiple tables into a single table.
	 * The following fields tell us what table this rule originally
	 * came from, what its original rule-number was, and the name of the
	 * result associated with it.
	 */
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
	struct cds_list_head	table_list;
	struct rcu_head		table_rcu;
	/* The following two fields uniquely identify this table */
	char			*ifname;
	/* location - ingress/egress/punt-path */
	uint32_t		location;
	/* Other operational fields */
	struct cds_list_head	rule_list;
	/* traffic-type - ipv4/ipv6 */
	uint32_t		traffic_type;
	/*
	 * The VCI code can collapse multiple tables into a single table.
	 * The following fields allows us to identify the user-visible table's
	 * name using the table_index field from the gpc_pb_rule struct.
	 */
	uint32_t		n_table_names;
	/* The following array is variable length */
	char			*table_names[0];
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

enum gpc_config_action {
	CREATE,
	MODIFY,
	DELETE
};

#endif /* GPC_PB_H */
