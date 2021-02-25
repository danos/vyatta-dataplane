/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * GPC protobuf parsing test cases
 */

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_lib_internal.h"

#include "protobuf/GPCConfig.pb-c.h"
#include "protobuf/IPAddress.pb-c.h"

static bool dp_test_gpc_debug_state;

static void
dp_test_gpc_debug(bool enable)
{
	char cmd[TEST_MAX_CMD_LEN];

	if (enable != dp_test_gpc_debug_state) {
		snprintf(cmd, TEST_MAX_CMD_LEN, "debug %sgpc", enable ? "":"-");
		dp_test_console_request_reply(cmd, false);

		rte_log_set_level(RTE_LOGTYPE_SCHED,
				  enable ? RTE_LOG_DEBUG : RTE_LOG_INFO);

		dp_test_gpc_debug_state = enable;
	}
}

#ifdef NOT_YET
static void
dp_test_gpc_json_dump(json_object *j_obj)
{
	const char *str;

	str = json_object_to_json_string_ext(j_obj,
					     JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
}
#endif

static void
dp_test_gpc_setup_action(RuleAction *action, PolicerParams *policer,
			 RuleAction__ActionValueCase action_type,
			 uint32_t value)
{
	action->action_value_case = action_type;
	switch (action_type) {
	case RULE_ACTION__ACTION_VALUE__NOT_SET:
		dp_test_fail("invalid action type - not-set\n");
		break;
	case RULE_ACTION__ACTION_VALUE_DECISION:
		action->decision = value;
		break;
	case RULE_ACTION__ACTION_VALUE_DESIGNATION:
		action->designation = value;
		break;
	case RULE_ACTION__ACTION_VALUE_COLOUR:
		action->colour = value;
		break;
	case RULE_ACTION__ACTION_VALUE_POLICER:
		/* limited policer testing */
		policer->has_bw = true;
		policer->bw = value;
		action->policer = policer;
		break;
	default:
		dp_test_fail("invalid rule action value case: %u\n",
			     action_type);
		break;
	}
}

static void
dp_test_lib_pb_set_ip_prefix(IPPrefix *prefix, const char *addr_str,
			     uint32_t prefix_length, void *data)
{
	IPAddress *ip_address = prefix->address;

	dp_test_lib_pb_set_ip_addr(ip_address, addr_str, data);
	prefix->has_length = true;
	prefix->length = prefix_length;
}

static void
dp_test_gpc_setup_match(RuleMatch *match,
			RuleMatch__MatchValueCase match_type,
			char *addr_str, uint32_t value, IPPrefix *ip_prefix,
			void *v6_addr,
			RuleMatch__ICMPTypeAndCode *icmp_type_code)
{
	match->match_value_case = match_type;
	switch (match_type) {
	case RULE_MATCH__MATCH_VALUE__NOT_SET:
		dp_test_fail("invalid match type - not-set\n");
		break;
	case RULE_MATCH__MATCH_VALUE_SRC_IP:
		if (!addr_str || !ip_prefix)
			dp_test_fail("required argument is NULL\n");

		dp_test_lib_pb_set_ip_prefix(ip_prefix, addr_str, value,
					     v6_addr);
		match->src_ip = ip_prefix;
		break;
	case RULE_MATCH__MATCH_VALUE_DEST_IP:
		if (!addr_str || !ip_prefix)
			dp_test_fail("required argument is NULL\n");

		dp_test_lib_pb_set_ip_prefix(ip_prefix, addr_str, value,
					     v6_addr);

		match->dest_ip = ip_prefix;
		break;
	case RULE_MATCH__MATCH_VALUE_SRC_PORT:
		match->src_port = value;
		break;
	case RULE_MATCH__MATCH_VALUE_DEST_PORT:
		match->dest_port = value;
		break;
	case RULE_MATCH__MATCH_VALUE_FRAGMENT:
		match->fragment = value;
		break;
	case RULE_MATCH__MATCH_VALUE_DSCP:
		match->dscp = value;
		break;
	case RULE_MATCH__MATCH_VALUE_TTL:
		match->ttl = value;
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV4:
		if (!icmp_type_code)
			dp_test_fail("required argument is NULL\n");

		/* code and type packed into lower 16-bits of value */
		icmp_type_code->has_code = true;
		icmp_type_code->code = value >> 8;
		icmp_type_code->has_typenum = true;
		icmp_type_code->typenum = value & 0xFF;
		match->icmpv4 = icmp_type_code;
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV6:
		if (!icmp_type_code)
			dp_test_fail("required argument is NULL\n");

		/* code and type packed into lower 16-bits of value */
		icmp_type_code->has_code = true;
		icmp_type_code->code = value >> 8;
		icmp_type_code->has_typenum = true;
		icmp_type_code->typenum = value & 0xFF;
		match->icmpv6 = icmp_type_code;
		break;
	case RULE_MATCH__MATCH_VALUE_ICMPV6_CLASS:
		match->icmpv6_class = value;
		break;
	case RULE_MATCH__MATCH_VALUE_PROTO_BASE:
		match->proto_base = value;
		break;
	case RULE_MATCH__MATCH_VALUE_PROTO_FINAL:
		match->proto_final = value;
		break;
	default:
		dp_test_fail("invalid rule match type: %u\n",
			     match_type);
		break;
	}
}

static void
dp_test_gpc_setup_match_src_ip(RuleMatch *match, char *addr_str,
			       uint32_t prefix_length, IPPrefix *ip_prefix,
			       void *v6_addr)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_SRC_IP, addr_str,
				prefix_length, ip_prefix, v6_addr, NULL);
}

static void
dp_test_gpc_setup_match_dest_ip(RuleMatch *match, char *addr_str,
				uint32_t prefix_length, IPPrefix *ip_prefix,
				void *v6_addr)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_DEST_IP,
				addr_str, prefix_length, ip_prefix, v6_addr,
				NULL);
}

static void
dp_test_gpc_setup_match_src_port(RuleMatch *match, uint32_t port)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_SRC_PORT,
				NULL, port, NULL, NULL, NULL);
}

static void
dp_test_gpc_setup_match_dest_port(RuleMatch *match, uint32_t port)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_DEST_PORT,
				NULL, port, NULL, NULL, NULL);

}

static void
dp_test_gpc_setup_match_fragment(RuleMatch *match, uint32_t fragment)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_FRAGMENT,
				NULL, fragment, NULL, NULL, NULL);
}

static void
dp_test_gpc_setup_match_dscp(RuleMatch *match, uint32_t dscp)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_DSCP,
				NULL, dscp, NULL, NULL, NULL);
}

static void
dp_test_gpc_setup_match_ttl(RuleMatch *match, uint32_t ttl)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_TTL,
				NULL, ttl, NULL, NULL, NULL);
}

static void
dp_test_gpc_setup_match_icmpv4(RuleMatch *match,
				 RuleMatch__ICMPTypeAndCode *icmp_type_code,
				 uint32_t type, uint32_t code)
{
	uint32_t value;

	dp_test_fail_unless(type < 256, "icmp type value too large: %u\n",
			    type);
	dp_test_fail_unless(code < 256, "icmp code value too large: %u\n",
			    code);

	/* pack code and type into lower 16-bit of value */
	value = (code << 8) | type;
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_ICMPV4,
				NULL, value, NULL, NULL, icmp_type_code);
}

static void
dp_test_gpc_setup_match_icmpv6(RuleMatch *match,
				 RuleMatch__ICMPTypeAndCode *icmp_type_code,
				 uint32_t type, uint32_t code)
{
	uint32_t value;

	dp_test_fail_unless(type < 256, "icmp type value too large: %u\n",
			    type);
	dp_test_fail_unless(code < 256, "icmp code value too large: %u\n",
			    code);

	/* pack code and type into lower 16-bit of value */
	value = (code << 8) | type;
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_ICMPV6,
				NULL, value, NULL, NULL, icmp_type_code);
}

static void
dp_test_gpc_setup_match_proto_base(RuleMatch *match, uint32_t proto)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_PROTO_BASE,
				NULL, proto, NULL, NULL, NULL);
}

static void
dp_test_gpc_setup_match_proto_final(RuleMatch *match, uint32_t proto)
{
	dp_test_gpc_setup_match(match, RULE_MATCH__MATCH_VALUE_PROTO_FINAL,
				NULL, proto, NULL, NULL, NULL);
}

static void
dp_test_gpc_setup_rule(Rule *gpc_rule, uint32_t rule_number,
		       size_t n_matches, RuleMatch **matches,
		       size_t n_actions, RuleAction **actions,
		       RuleCounter *counter)
{
	gpc_rule->has_number = true;
	gpc_rule->number = rule_number;

	gpc_rule->n_matches = n_matches;
	gpc_rule->matches = matches;

	gpc_rule->n_actions = n_actions;
	gpc_rule->actions = actions;

	gpc_rule->counter = counter;

	gpc_rule->has_table_index = true;
	gpc_rule->table_index = 1;

	gpc_rule->has_orig_number = true;
	gpc_rule->orig_number = rule_number;
}


static void
dp_test_gpc_setup_rules(Rules *gpc_rules, TrafficType traffic_type,
			size_t n_rules, Rule **rules)
{
	gpc_rules->has_traffic_type = true;
	gpc_rules->traffic_type = traffic_type;
	gpc_rules->n_rules = n_rules;
	gpc_rules->rules = rules;
}

static void
dp_test_gpc_setup_table(GPCTable *table, const char *ifname,
			GPCTable__FeatureLocation location,
			TrafficType traffic_type, Rules *rules,
			uint32_t n_table_names, char **table_names)
{
	table->ifname = "dp1T0";
	table->has_location = true;
	table->location = location;
	table->has_traffic_type = true;
	table->traffic_type = traffic_type;
	table->rules = rules;
	table->n_table_names = n_table_names;
	table->table_names = table_names;
}

static void
dp_test_create_and_send_gpc_config_msg()
{
	TrafficType traffic_type = TRAFFIC_TYPE__IPV4;

	/* set match values here */
	RuleMatch match_1_1 = RULE_MATCH__INIT;
	RuleMatch match_1_2 = RULE_MATCH__INIT;
	RuleMatch match_1_3 = RULE_MATCH__INIT;
	RuleMatch match_1_4 = RULE_MATCH__INIT;
	RuleMatch match_1_5 = RULE_MATCH__INIT;
	RuleMatch match_2_1 = RULE_MATCH__INIT;
	RuleMatch match_2_2 = RULE_MATCH__INIT;
	RuleMatch match_2_3 = RULE_MATCH__INIT;
	RuleMatch match_2_4 = RULE_MATCH__INIT;
	RuleMatch match_2_5 = RULE_MATCH__INIT;
	RuleMatch match_2_6 = RULE_MATCH__INIT;

	IPPrefix ip_prefix_1 = IPPREFIX__INIT;
	IPAddress ip_address_1 = IPADDRESS__INIT;
	uint32_t v6_addr[4];

	ip_prefix_1.address = &ip_address_1;
	dp_test_gpc_setup_match_src_ip(&match_1_1, "10.10.10.0", 24,
				       &ip_prefix_1, &v6_addr);

	IPPrefix ip_prefix_2 = IPPREFIX__INIT;
	IPAddress ip_address_2 = IPADDRESS__INIT;

	ip_prefix_2.address = &ip_address_2;
	dp_test_gpc_setup_match_dest_ip(&match_1_2, "20.0.0.0", 8,
					&ip_prefix_2, &v6_addr);

	dp_test_gpc_setup_match_src_port(&match_1_3, 1234);

	dp_test_gpc_setup_match_dest_port(&match_1_4, 4321);

	dp_test_gpc_setup_match_ttl(&match_1_5, 64);

	RuleMatch__ICMPTypeAndCode icmp_type_code_1 =
		RULE_MATCH__ICMPTYPE_AND_CODE__INIT;

	dp_test_gpc_setup_match_icmpv4(&match_2_1, &icmp_type_code_1, 3, 9);

	RuleMatch__ICMPTypeAndCode icmp_type_code_2 =
		RULE_MATCH__ICMPTYPE_AND_CODE__INIT;

	dp_test_gpc_setup_match_icmpv6(&match_2_2, &icmp_type_code_2, 1, 3);

	dp_test_gpc_setup_match_fragment(&match_2_3, 1);

	dp_test_gpc_setup_match_dscp(&match_2_4, 63);

	dp_test_gpc_setup_match_proto_base(&match_2_5, 19);

	dp_test_gpc_setup_match_proto_final(&match_2_6, 100);

	/* set action values here */
	RuleAction action_1_1 = RULE_ACTION__INIT;
	RuleAction action_1_2 = RULE_ACTION__INIT;
	RuleAction action_2_1 = RULE_ACTION__INIT;
	RuleAction action_2_2 = RULE_ACTION__INIT;
	PolicerParams policer = POLICER_PARAMS__INIT;

	dp_test_gpc_setup_action(&action_1_1, NULL,
				 RULE_ACTION__ACTION_VALUE_DECISION,
				 RULE_ACTION__PACKET_DECISION__PASS);

	dp_test_gpc_setup_action(&action_1_2, &policer,
				 RULE_ACTION__ACTION_VALUE_POLICER,
				 12345678);

	dp_test_gpc_setup_action(&action_2_1, NULL,
				 RULE_ACTION__ACTION_VALUE_DESIGNATION,
				 6);

	dp_test_gpc_setup_action(&action_2_2, NULL,
				 RULE_ACTION__ACTION_VALUE_COLOUR,
				 RULE_ACTION__COLOUR_VALUE__YELLOW);

	/* set rule values here */
	Rule rule_1 = RULE__INIT;
	Rule rule_2 = RULE__INIT;
	RuleMatch *match_array_1[] = { &match_1_1, &match_1_2, &match_1_3,
				       &match_1_4, &match_1_5 };
	RuleMatch *match_array_2[] = { &match_2_1, &match_2_2, &match_2_3,
				       &match_2_4, &match_2_5, &match_2_6 };
	RuleAction *action_array_1[] = { &action_1_1, &action_1_2 };
	RuleAction *action_array_2[] = { &action_2_1, &action_2_2 };

	dp_test_gpc_setup_rule(&rule_1, 1, ARRAY_SIZE(match_array_1),
			       match_array_1, ARRAY_SIZE(action_array_1),
			       action_array_1, NULL);

	dp_test_gpc_setup_rule(&rule_2, 2, ARRAY_SIZE(match_array_2),
			       match_array_2, ARRAY_SIZE(action_array_2),
			       action_array_2, NULL);

	/* set rules values here */
	Rules rules = RULES__INIT;
	Rule *rules_array[] = { &rule_1, &rule_2 };

	dp_test_gpc_setup_rules(&rules, traffic_type, ARRAY_SIZE(rules_array),
				rules_array);

	/* set table values here */
	GPCTable table = GPCTABLE__INIT;
	char *table_name = "gpc-table-name-1";
	char *table_names[1];

	table_names[0] = table_name;
	dp_test_gpc_setup_table(&table, "dp1T0",
				GPCTABLE__FEATURE_LOCATION__INGRESS,
				traffic_type, &rules,
				ARRAY_SIZE(table_names), table_names);

	/* set config values here */
	GPCConfig config = GPCCONFIG__INIT;
	GPCTable * table_array[] = { &table };

	config.has_feature_type = true;
	config.feature_type = GPCCONFIG__FEATURE_TYPE__QOS;
	config.n_counters = 0;
	config.n_tables = 1;
	config.tables = table_array;

	size_t len = gpcconfig__get_packed_size(&config);
	void *buf = malloc(len);
	dp_test_assert_internal(buf);

	gpcconfig__pack(&config, buf);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:gpc-config", buf, len);
}

const char *expected_reply_1 =
	"{"
	"  \"gpc\":{"
	"    \"features\":["
	"      {"
	"        \"type\":\"qos\","
	"        \"tables\":["
	"          {"
	"            \"table-id\":\"dp1T0/ingress/ipv4\","
	"            \"rules\":["
	"              {"
	"                \"rule-number\":1,"
	"                \"matches\":["
	"                  {"
	"                    \"match\":\"src-ip\","
	"                    \"value\":\"0.10.10.10/24\""
	"                  },{"
	"                    \"match\":\"dest-ip\","
	"                    \"value\": \"0.0.0.20/8\""
	"                  },{"
	"                    \"match\":\"src-port\","
	"                    \"value\":1234"
	"                  },{"
	"                    \"match\":\"dest-port\","
	"                    \"value\":4321"
	"                  },{"
	"                    \"match\":\"ttl\","
	"                    \"value\":64"
	"                  }"
	"                ],"
	"                \"decision\":\"pass\","
	"                \"police\":{"
	"                    \"bandwidth\": 12345678,"
	"                    \"packets\":0,"
	"                    \"drops\":0"
	"                  },"
	"                \"table-index\":1,"
	"                \"orig-number\":1"
	"              },{"
	"                \"rule-number\":2,"
	"                \"matches\":["
	"                  {"
	"                    \"match\":\"icmpv4\","
	/* type 3, code 9 -> (3 << 8) | 9 = 777 */
	"                    \"value\":777"
	"                  },{"
	"                    \"match\":\"icmpv6\","
	/* type 1, code 3 -> (1 << 8) | 3 = 259 */
	"                    \"value\":259"
	"                  },{"
	"                    \"match\":\"fragment\","
	"                    \"value\":1"
	"                  },{"
	"                    \"match\":\"dscp\","
	"                    \"value\":63"
	"                  },{"
	"                    \"match\":\"base-protocol\","
	"                    \"value\":19"
	"                  },{"
	"                    \"match\":\"final-protocol\","
	"                    \"value\":100"
	"                  }"
	"                ],"
	"                \"designation\":6,"
	"                \"colour\":\"yellow\","
	"                \"table-index\":1,"
	"                \"orig-number\":2"
	"              }"
	"            ],"
	"            \"table-names\":["
	"              {"
	"                \"table-index\": 1,"
	"                \"name\": \"gpc-table-name-1\""
	"              }"
	"            ]"
	"          }"
	"        ],"
	"        \"counters\":["
	"        ]"
	"      }"
	"    ]"
	"  }"
	"}";

static void
dp_test_gpc_check_state(const char *expected_reply)
{
	json_object *jexp;

	jexp = dp_test_json_create("%s", expected_reply);
	dp_test_check_json_poll_state("gpc show", jexp,
				      DP_TEST_JSON_CHECK_SUBSET, false,
				      DP_TEST_POLL_COUNT);
	json_object_put(jexp);
}

static void
dp_test_create_and_send_gpc_delete_msg()
{
	/* set config values here */
	GPCConfig config = GPCCONFIG__INIT;

	config.has_feature_type = true;
	config.feature_type = GPCCONFIG__FEATURE_TYPE__QOS;

	/* A gpc config message with zero tables deletes the feature */
	config.n_tables = 0;

	size_t len = gpcconfig__get_packed_size(&config);
	void *buf = malloc(len);
	dp_test_assert_internal(buf);

	gpcconfig__pack(&config, buf);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:gpc-config", buf, len);
}

const char *expected_reply_2 =
	"{"
	"  \"gpc\":{\"features\":[]}"
	"}";

DP_DECL_TEST_SUITE(gpc_pb_suite);

DP_DECL_TEST_CASE(gpc_pb_suite, gpc_pb_parsing, NULL, NULL);

DP_START_TEST(gpc_pb_parsing, test1)
{

	dp_test_gpc_debug(true);

	dp_test_create_and_send_gpc_config_msg();
	dp_test_gpc_check_state(expected_reply_1);

	dp_test_create_and_send_gpc_delete_msg();
	dp_test_gpc_check_state(expected_reply_2);

} DP_END_TEST;
