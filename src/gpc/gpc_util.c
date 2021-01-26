/*-
 * Copyright (c) 2020-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Generalised Packet Classification (GPF) configuration handling
 */

#include <stdint.h>
#include "gpc_util.h"
#include "protobuf/GPCConfig.pb-c.h"
#include "util.h"
#include "vplane_log.h"

/*
 * GPC enum to string mapping definitions and functions
 */

const char *gpc_action_type_str[] = {
	[RULE_ACTION__ACTION_VALUE__NOT_SET] = "not-set",
	[RULE_ACTION__ACTION_VALUE_DECISION] = "decision",
	[RULE_ACTION__ACTION_VALUE_DESIGNATION] = "set-designation",
	[RULE_ACTION__ACTION_VALUE_COLOUR] = "set-colour",
	[RULE_ACTION__ACTION_VALUE_POLICER] = "policer",
};

const char *gpc_policer_awareness_str[] = {
	[POLICER_AWARENESS__AWARENESS_UNKNOWN] = "unknown",
	[POLICER_AWARENESS__COLOUR_AWARE] = "aware",
	[POLICER_AWARENESS__COLOUR_UNAWARE] = "unaware",
};

const char *gpc_cntr_format_str[] = {
	[GPCCOUNTER__COUNTER_FORMAT__FORMAT_UNKNOWN] = "format-unknown",
	[GPCCOUNTER__COUNTER_FORMAT__PACKETS_ONLY] = "packets",
	[GPCCOUNTER__COUNTER_FORMAT__PACKETS_AND_L2_L3_BYTES] =
		"packets-and-l2-and-l3-bytes",
};

const char *gpc_feature_type_str[] = {
	[GPCCONFIG__FEATURE_TYPE__FEATURE_UNKNOWN] = "unknown",
	[GPCCONFIG__FEATURE_TYPE__QOS] = "qos",
	[GPCCONFIG__FEATURE_TYPE__ACL] = "acl",
};

const char *gpc_match_type_str[] = {
	[RULE_MATCH__MATCH_VALUE__NOT_SET] = "not-set",
	[RULE_MATCH__MATCH_VALUE_SRC_IP] = "src-ip",
	[RULE_MATCH__MATCH_VALUE_DEST_IP] = "dst-ip",
	[RULE_MATCH__MATCH_VALUE_SRC_PORT] = "src-port",
	[RULE_MATCH__MATCH_VALUE_DEST_PORT] = "dst-port",
	[RULE_MATCH__MATCH_VALUE_FRAGMENT] = "fragment",
	[RULE_MATCH__MATCH_VALUE_DSCP] = "dscp",
	[RULE_MATCH__MATCH_VALUE_TTL] = "ttl",
	[RULE_MATCH__MATCH_VALUE_ICMPV4] = "icmpv4",
	[RULE_MATCH__MATCH_VALUE_ICMPV6] = "icmpv6",
	[RULE_MATCH__MATCH_VALUE_ICMPV6_CLASS] = "icmpv6-class",
	[RULE_MATCH__MATCH_VALUE_PROTO_BASE] = "proto-base",
	[RULE_MATCH__MATCH_VALUE_PROTO_FINAL] = "proto-final",
};

const char *gpc_pkt_colour_str[] = {
	[RULE_ACTION__COLOUR_VALUE__GREEN] = "green",
	[RULE_ACTION__COLOUR_VALUE__YELLOW] = "yellow",
	[RULE_ACTION__COLOUR_VALUE__RED] = "red",
};

const char *gpc_pkt_decision_str[] = {
	[RULE_ACTION__PACKET_DECISION__DECISION_UNKNOWN] = "unknown",
	[RULE_ACTION__PACKET_DECISION__PASS] = "pass",
	[RULE_ACTION__PACKET_DECISION__DROP] = "drop",
};

const char *gpc_table_location_str[] = {
	[GPCTABLE__FEATURE_LOCATION__LOCATION_UNKNOWN] = "unknown",
	[GPCTABLE__FEATURE_LOCATION__INGRESS] = "ingress",
	[GPCTABLE__FEATURE_LOCATION__EGRESS] = "egress",
	[GPCTABLE__FEATURE_LOCATION__PUNT_PATH] = "punt-path",
};

const char *gpc_traffic_type_str[] = {
	[TRAFFIC_TYPE__TRAFFIC_UNKNOWN] = "unknown",
	[TRAFFIC_TYPE__IPV4] = "ipv4",
	[TRAFFIC_TYPE__IPV6] = "ipv6",
};


static const char *
gpc_get_str(uint32_t index, uint32_t size, const char *str_array[])
{
	if (index >= size) {
		RTE_LOG(WARNING, GPC,
			"Unexpected string index %u for str-array %p\n",
			index, str_array);
		index = 0;
	}

	return str_array[index];
}

const char *
gpc_get_action_type_str(uint32_t action)
{
	return gpc_get_str(action, ARRAY_SIZE(gpc_action_type_str),
			   gpc_action_type_str);
}

const char *
gpc_get_cntr_format_str(uint32_t format)
{
	return gpc_get_str(format, ARRAY_SIZE(gpc_cntr_format_str),
			   gpc_cntr_format_str);
}

const char *
gpc_get_feature_type_str(uint32_t type)
{
	return gpc_get_str(type, ARRAY_SIZE(gpc_feature_type_str),
			   gpc_feature_type_str);
}

const char *
gpc_get_match_type_str(uint32_t match)
{
	return gpc_get_str(match, ARRAY_SIZE(gpc_match_type_str),
			   gpc_match_type_str);
}

const char *
gpc_get_pkt_colour_str(uint32_t colour)
{
	return gpc_get_str(colour, ARRAY_SIZE(gpc_pkt_colour_str),
			   gpc_pkt_colour_str);
}

const char *
gpc_get_pkt_decision_str(uint32_t decision)
{
	return gpc_get_str(decision, ARRAY_SIZE(gpc_pkt_decision_str),
			   gpc_pkt_decision_str);
}

const char *
gpc_get_policer_awareness_str(uint32_t awareness)
{
	return gpc_get_str(awareness, ARRAY_SIZE(gpc_policer_awareness_str),
			   gpc_policer_awareness_str);
}

const char *
gpc_get_table_location_str(uint32_t location)
{
	return gpc_get_str(location, ARRAY_SIZE(gpc_table_location_str),
			   gpc_table_location_str);
}

const char *
gpc_get_traffic_type_str(uint32_t traffic_type)
{
	return gpc_get_str(traffic_type, ARRAY_SIZE(gpc_traffic_type_str),
			   gpc_traffic_type_str);
}

static uint32_t
gpc_get_value(const char *str, uint32_t size, const char *str_array[])
{
	uint32_t i;

	for (i = 0; i < size; i++) {
		if (!strcmp(str_array[i], str))
			return i;
	}
	return 0;
}

uint32_t
gpc_feature_str_to_type(const char *str)
{
	return gpc_get_value(str, ARRAY_SIZE(gpc_feature_type_str),
			     gpc_feature_type_str);
}

uint32_t
gpc_table_location_str_to_value(const char *str)
{
	return gpc_get_value(str, ARRAY_SIZE(gpc_table_location_str),
			     gpc_table_location_str);
}

uint32_t
gpc_traffic_type_str_to_value(const char *str)
{
	return gpc_get_value(str, ARRAY_SIZE(gpc_traffic_type_str),
			     gpc_traffic_type_str);
}
