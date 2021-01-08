/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf ruleset state checks
 */

#include <libmnl/libmnl.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/config/npf_config.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_sess_lib.h"

DP_DECL_TEST_SUITE(npf_ruleset_state);

/*
 * dpt_fw
 */
static void
dpt_fw(const char *if_name, bool in, const char *fw_name, bool add)
{
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
			.npf      = "proto-final=17 dst-port=48879"
		},
		{
			.rule     = "20",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=17 dst-port=48878"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = in ? "fw-in" : "fw-out",
		.name   = fw_name,
		.enable = 1,
		.attach_point   = if_name,
		.fwd    = FWD,
		.dir    = in ? "in" : "out",
		.rules  = rset
	};

	if (add)
		dp_test_npf_fw_add(&fw, false);
	else
		dp_test_npf_fw_del(&fw, false);
}

static void
dpt_dnat(const char *if_name, const char *rule, bool add)
{
	/*
	 * Add DNAT rule. Change dest addr from 2.2.2.12 to 2.2.2.11
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= rule,
		.ifname		= if_name,
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.12",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	if (add)
		dp_test_npf_dnat_add(&dnat, true);
	else
		dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);
}

static void
dpt_snat(const char *if_name, const char *rule, bool add)
{
	/*
	 * Add SNAT rule. Change dest addr from 2.2.2.12 to 2.2.2.11
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= rule,
		.ifname		= if_name,
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.from_addr	= "1.1.1.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "1.1.1.12",
		.trans_port	= NULL
	};

	if (add)
		dp_test_npf_snat_add(&snat, true);
	else
		dp_test_npf_snat_del(snat.ifname, snat.rule, true);
}

static void
dpt_pbr(const char *if_name, bool add)
{
	char real_if[IFNAMSIZ];
	dp_test_intf_real(if_name, real_if);

	if (add) {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add pbr:pbr4 10 action=accept "
			"family=inet dst-addr=10.73.2.1/32 handle=tag(4)");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut attach interface:%s pbr pbr:pbr4", real_if);
		dp_test_npf_cmd_fmt(false, "npf-ut commit");
	} else {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut detach interface:%s pbr pbr:pbr4", real_if);
		dp_test_npf_cmd_fmt(
			false, "npf-ut delete pbr:pbr4");
		dp_test_npf_cmd_fmt(false, "npf-ut commit");
	}
}

static void
dpt_nat64(const char *if_name, bool add)
{
	const struct dp_test_npf_nat64_rule_t rule48 = {
		.rule		= "1",
		.ifname		= if_name,
		.from_addr	= "2001:101:1::/48",
		.to_addr	= "2001:101:2::/48",
		.spl		= 48,
		.dpl		= 48
	};

	if (add)
		dp_test_npf_nat64_add(&rule48, true);
	else
		dp_test_npf_nat64_del(&rule48, true);

	dp_test_npf_cmd_fmt(false, "npf-ut commit");
}

static void
dpt_zone(bool add)
{
	if (add) {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone add ZONE1");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone intf add ZONE1 dpT10");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone intf add ZONE1 dpT11");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone add ZONE2");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone intf add ZONE2 dpT12");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone add ZONE3");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone intf add ZONE3 dpT13");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone policy add ZONE1 ZONE2");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:ZFW1 1 action=accept");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut attach zone:ZONE1>ZONE2 zone fw:ZFW1");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone policy add ZONE1 ZONE3");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:ZFW3 1 action=accept");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut attach zone:ZONE1>ZONE3 zone fw:ZFW3");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone policy add ZONE2 ZONE1");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:ZFW2 10 action=accept");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut attach zone:ZONE2>ZONE1 zone fw:ZFW2");

		dp_test_npf_cmd_fmt(false, "npf-ut commit");
	} else {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut detach zone:ZONE1>ZONE2 zone fw:ZFW1");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut delete fw:ZFW1");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone policy remove ZONE1 ZONE2");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut detach zone:ZONE1>ZONE3 zone fw:ZFW3");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut delete fw:ZFW3");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone policy remove ZONE1 ZONE3");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut detach zone:ZONE2>ZONE1 zone fw:ZFW2");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut delete fw:ZFW2");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone policy remove ZONE2 ZONE1");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone intf remove ZONE1 dpT10");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone intf remove ZONE1 dpT11");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone remove ZONE1");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone intf remove ZONE2 dpT12");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone remove ZONE2");

		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone intf remove ZONE3 dpT13");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut zone remove ZONE3");

		dp_test_npf_cmd_fmt(false, "npf-ut commit");
	}
}

static void
dpt_show_rulesets(const char *rs_name, const char *if_name)
{
	json_object *jresp;
	char cmd[TEST_MAX_CMD_LEN];
	char intf_str[50];
	char *response;
	bool err;

	if (if_name) {
		char real_if[IFNAMSIZ];
		dp_test_intf_real(if_name, real_if);
		snprintf(intf_str, sizeof(intf_str), "interface:%s", real_if);
	} else
		snprintf(intf_str, sizeof(intf_str), "all:");

	snprintf(cmd, sizeof(cmd), "npf-op show %s %s",
		 intf_str, rs_name);

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err) {
		dp_test_fail("no response from dataplane");
		return;
	}

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp) {
		dp_test_fail("failed to parse response");
		return;
	}

	/* Optional debug */
	const char *str = json_object_to_json_string_ext(
		jresp, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);

	json_object_put(jresp);
}

static void
dpt_show_ruleset_state(const char *rs_name, const char *if_name)
{
	json_object *jresp;
	char cmd[TEST_MAX_CMD_LEN];
	char intf_str[50];
	char *response;
	bool err;
	int l = 0;

	if (if_name) {
		char real_if[IFNAMSIZ];
		dp_test_intf_real(if_name, real_if);
		snprintf(intf_str, sizeof(intf_str), "interface:%s", real_if);
	} else
		snprintf(intf_str, sizeof(intf_str), "all:");

	l += snprintf(cmd+l, sizeof(cmd)-l, "npf-op state %s %s",
		      intf_str, rs_name);

	(void) l;

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err) {
		dp_test_fail("no response from dataplane");
		return;
	}

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp) {
		dp_test_fail("failed to parse response");
		return;
	}

	/* Optional debug */
	const char *str = json_object_to_json_string_ext(
		jresp, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);

	json_object_put(jresp);
}

/*
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_get_state1
 */
static void dpt_get_state1_verify_fw_out(void)
{
	json_object *jexp;
	char cmd_str[30];

	snprintf(cmd_str, sizeof(cmd_str),
		 "npf-op state interface:dpT10 fw-out");

	jexp = dp_test_json_create(
		"{ "
		"  \"dataplane\": ["
		"    { "
		"        \"tagnode\": \"dpT10\", "
		"        \"firewall\":{"
		"          \"state\":{"
		"            \"out\":{"
		"              \"name\": ["
		"                { "
		"                  \"group-name\": \"FW_OUT1\", "
		"                  \"rule\": [ "
		"                    { "
		"	               \"rule-number\": 10, "
		"	              \"bytes\": 0, "
		"	              \"packets\": 0, "
		"                   },"
		"                    { "
		"	               \"rule-number\": 20, "
		"	              \"bytes\": 0, "
		"	              \"packets\": 0, "
		"                   },"
		"                    { "
		"	               \"rule-number\": 10000, "
		"	              \"bytes\": 0, "
		"	              \"packets\": 0, "
		"                   }"
		"                  ] "
		"                } "
		"              ]"
		"          } "
		"        } "
		"      } "
		"    } "
		"  ]"
		"} ");

	dp_test_check_json_poll_state(cmd_str, jexp,
				      DP_TEST_JSON_CHECK_SUBSET,
				      false, 0);
	json_object_put(jexp);
}

DP_DECL_TEST_CASE(npf_ruleset_state, npf_get_state1, NULL, NULL);
DP_START_TEST(npf_get_state1, test1)
{

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	dpt_fw("dpT10", true,  "FW_IN1", true);
	dpt_fw("dpT10", true,  "FW_IN2", true);
	dpt_fw("dpT10", false, "FW_OUT1", true);
	dpt_fw("dpT11", true,  "FW_IN2", true);

	if (0)
		dpt_show_ruleset_state("fw-in fw-out local bridge", NULL);

	/* verify dpT10 fw-out */
	dpt_get_state1_verify_fw_out();

	dpt_fw("dpT10", true,  "FW_IN1", false);
	dpt_fw("dpT10", true,  "FW_IN2", false);
	dpt_fw("dpT10", false, "FW_OUT1", false);
	dpt_fw("dpT11", true,  "FW_IN2", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

} DP_END_TEST;


/*
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_get_state2
 */
static void dpt_get_state2_verify_snat(void)
{
	json_object *jexp;
	char cmd_str[30];

	snprintf(cmd_str, sizeof(cmd_str), "npf-op state all: snat");

	jexp = dp_test_json_create(
		"{ "
		"  \"source\":{"
		"    \"rule\":"
		"      [ "
		"        { "
		"	   \"rule-number\": 30, "
		"	   \"bytes\": 0, "
		"	   \"packets\": 0, "
		"        }"
		"      ] "
		"  } "
		"} ");

	dp_test_check_json_poll_state(cmd_str, jexp,
				      DP_TEST_JSON_CHECK_SUBSET,
				      false, 0);
	json_object_put(jexp);
}

static void dpt_get_state2_verify_dnat(void)
{
	json_object *jexp;
	char cmd_str[30];

	snprintf(cmd_str, sizeof(cmd_str), "npf-op state all: dnat");

	jexp = dp_test_json_create(
		"{ "
		"  \"destination\":{"
		"    \"rule\":"
		"      [ "
		"        { "
		"	   \"rule-number\": 10, "
		"	   \"bytes\": 0, "
		"	   \"packets\": 0, "
		"        },"
		"        { "
		"	   \"rule-number\": 20, "
		"	   \"bytes\": 0, "
		"	   \"packets\": 0, "
		"        }"
		"      ] "
		"  } "
		"} ");

	dp_test_check_json_poll_state(cmd_str, jexp,
				      DP_TEST_JSON_CHECK_SUBSET,
				      false, 0);
	json_object_put(jexp);
}

static void dpt_get_state2_verify_nat64(void)
{
	json_object *jexp;
	char cmd_str[30];

	snprintf(cmd_str, sizeof(cmd_str), "npf-op state all: nat64");

	jexp = dp_test_json_create(
		"{ "
		"  \"ipv6-to-ipv4\":{"
		"    \"rule\":"
		"      [ "
		"        { "
		"	   \"rule-number\": 1, "
		"	   \"bytes\": 0, "
		"	   \"packets\": 0, "
		"        }"
		"      ] "
		"  } "
		"} ");

	dp_test_check_json_poll_state(cmd_str, jexp,
				      DP_TEST_JSON_CHECK_SUBSET,
				      false, 0);
	json_object_put(jexp);
}

DP_DECL_TEST_CASE(npf_ruleset_state, npf_get_state2, NULL, NULL);
DP_START_TEST(npf_get_state2, test1)
{

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	dpt_dnat("dp1T0", "10", true);
	dpt_dnat("dp1T1", "20", true);
	dpt_snat("dp1T2", "30", true);
	dpt_nat64("dp1T3", true);

	if (0)
		dpt_show_rulesets("snat dnat nat64", NULL);

	if (0)
		dpt_show_ruleset_state("snat dnat nat64", NULL);

	dpt_get_state2_verify_snat();
	dpt_get_state2_verify_dnat();
	dpt_get_state2_verify_nat64();

	dpt_dnat("dp1T0", "10", false);
	dpt_dnat("dp1T1", "20", false);
	dpt_snat("dp1T2", "30", false);
	dpt_nat64("dp1T3", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

} DP_END_TEST;


/*
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_get_state3
 */
static void dpt_get_state3_verify_pbr(void)
{
	json_object *jexp;
	char cmd_str[30];

	snprintf(cmd_str, sizeof(cmd_str),
		 "npf-op state all: pbr");

	jexp = dp_test_json_create(
		"{ "
		"  \"dataplane\": ["
		"    { "
		"        \"tagnode\": \"dpT10\", "
		"        \"policy\":{"
		"          \"route\":{"
		"            \"pbr-state\":{"
		"              \"name\": ["
		"                { "
		"                  \"group-name\": \"pbr4\", "
		"                  \"rule\": [ "
		"                    { "
		"	               \"rule-number\": 10, "
		"	              \"bytes\": 0, "
		"	              \"packets\": 0, "
		"                   }"
		"                  ] "
		"                } "
		"              ]"
		"          } "
		"        } "
		"      } "
		"    } "
		"  ]"
		"} ");

	dp_test_check_json_poll_state(cmd_str, jexp,
				      DP_TEST_JSON_CHECK_SUBSET,
				      false, 0);
	json_object_put(jexp);
}

DP_DECL_TEST_CASE(npf_ruleset_state, npf_get_state3, NULL, NULL);
DP_START_TEST(npf_get_state3, test1)
{

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	dpt_pbr("dp1T0", true);

	if (0)
		dpt_show_rulesets("pbr", NULL);

	if (0)
		dpt_show_ruleset_state("pbr", NULL);

	dpt_get_state3_verify_pbr();

	dpt_pbr("dp1T0", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

} DP_END_TEST;

/*
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_get_state4
 */
static void dpt_get_state4_verify_zone(void)
{
	json_object *jexp;
	char cmd_str[30];

	snprintf(cmd_str, sizeof(cmd_str),
		 "npf-op state all: zone");

	jexp = dp_test_json_create(
		"{"
		"  \"zone\":["
		"    {"
		"      \"input-zone-name\":\"ZONE2\","
		"      \"to\":["
		"        {"
		"          \"output-zone-name\":\"ZONE1\","
		"          \"name\":["
		"            {"
		"              \"group-name\":\"ZFW2\","
		"              \"rule\":["
		"                {"
		"                  \"rule-number\":10,"
		"                  \"bytes\":0,"
		"                  \"packets\":0"
		"                }"
		"              ]"
		"            }"
		"          ]"
		"        }"
		"      ]"
		"    },"
		"    {"
		"      \"input-zone-name\":\"ZONE1\","
		"      \"to\":["
		"        {"
		"          \"output-zone-name\":\"ZONE2\","
		"          \"name\":["
		"            {"
		"              \"group-name\":\"ZFW1\","
		"              \"rule\":["
		"                {"
		"                  \"rule-number\":1,"
		"                  \"bytes\":0,"
		"                  \"packets\":0"
		"                }"
		"              ]"
		"            }"
		"          ]"
		"        },"
		"        {"
		"          \"output-zone-name\":\"ZONE3\","
		"          \"name\":["
		"            {"
		"              \"group-name\":\"ZFW3\","
		"              \"rule\":["
		"                {"
		"                  \"rule-number\":1,"
		"                  \"bytes\":0,"
		"                  \"packets\":0"
		"                }"
		"              ]"
		"            }"
		"          ]"
		"        }"
		"      ]"
		"    }"
		"  ]"
		"}"
		);

	dp_test_check_json_poll_state(cmd_str, jexp,
				      DP_TEST_JSON_CHECK_SUBSET,
				      false, 0);
	json_object_put(jexp);
}

DP_DECL_TEST_CASE(npf_ruleset_state, npf_get_state4, NULL, NULL);
DP_START_TEST(npf_get_state4, test1)
{

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	dpt_zone(true);

	if (0)
		dpt_show_rulesets("zone", NULL);

	if (0)
		dpt_show_ruleset_state("zone", NULL);

	dpt_get_state4_verify_zone();

	dpt_zone(false);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

} DP_END_TEST;
