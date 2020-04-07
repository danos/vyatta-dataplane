/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane portmonitor command tests
 */

#include <libmnl/libmnl.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_portmonitor.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"

#define POLL_CNT	1

struct dp_test_command_t {
	const char *cmd;
	const char *exp_reply; /* expected reply */
	bool        exp_ok;    /* expected cmd success or fail */
	bool        exp_json;  /* true if json response expected */
};

static const struct dp_test_command_t portmonitor_cmd[] = {
	 /*
	 * portmonitor set session
	 */
	{
		"portmonitor set session",
		"Unknown portmonitor command: set\n",
		false,
		false,
	},
	{
		"portmonitor set session ZZZ type 1 0 0",
		"Invalid portmonitor session id ZZZ\n",
		false,
		false,
	},
	/* Create a valid session for other set negative tests */
	{
		"portmonitor set session 1 type 1 0 0",
		"",
		true,
		false,
	},
	{
		"portmonitor set session 1 srcif dp1T1 ZZZ 0",
		"Invalid vid ZZZ\n",
		false,
		false,
	},
	{
		"portmonitor set session 1 srcif dp1T1 0 ZZZ",
		"Invalid direction ZZZ\n",
		false,
		false,
	},
	 /* portmonitor del session negative tests */
	{
		"portmonitor del session 2 type 1 0 0",
		"Invalid portmonitor session id 2\n",
		false,
		false,
	},
	{
		"portmonitor del session 1 srcif dp1T1 0 0",
		"Cannot delete source interface dp1T1\n",
		false,
		false,
	},
	{
		"portmonitor del session 1 dstif dp1T2 0 0",
		"Cannot delete destination interface dp1T2\n",
		false,
		false,
	},
	{
		"portmonitor del session 1 filter-in ZZZ 0 0",
		"Cannot delete \"in\" filter ZZZ\n",
		false,
		false,
	},
	{
		"portmonitor del session 1 filter-out ZZZ 0 0",
		"Cannot delete \"out\" filter ZZZ\n",
		false,
		false,
	},
	/* Delete the valid session that was created for negative tests */
	{
		"portmonitor del session 1 type 1 0 0",
		"",
		true,
		false,
	},
};


DP_DECL_TEST_SUITE(portmonitor_cmds);

DP_DECL_TEST_CASE(portmonitor_cmds, pmcmds, NULL, NULL);

/*
 * Loop through portmonitor command array, and verrify both pass/fail of command
 * and the response string.  Asserts pass/fail at the end of the loop.
 */
DP_START_TEST(pmcmds, neg_test)
{
	unsigned int i;
	json_object *jexp;

	for (i = 0; i < ARRAY_SIZE(portmonitor_cmd); i++) {
		/* Do we expect a json reply or a string reply? */
		if (portmonitor_cmd[i].exp_json) {
			jexp = dp_test_json_create("%s",
					portmonitor_cmd[i].exp_reply);
			dp_test_check_json_poll_state(
					portmonitor_cmd[i].cmd, jexp,
					DP_TEST_JSON_CHECK_SUBSET,
					false, POLL_CNT);
			json_object_put(jexp);
		} else
			dp_test_check_state_poll_show(
					portmonitor_cmd[i].cmd,
					portmonitor_cmd[i].exp_reply,
					portmonitor_cmd[i].exp_ok,
					false, POLL_CNT);
	}
} DP_END_TEST;

DP_START_TEST(pmcmds, span)
{
	char src_ifname[IFNAMSIZ];
	char dst_ifname[IFNAMSIZ];
	json_object *expected;

	dp_test_intf_real("dp1T1", src_ifname);
	dp_test_intf_real("dp1T2", dst_ifname);
	dp_test_portmonitor_create_span(1, src_ifname, dst_ifname,
						"PMFIN", "PMFOUT");
	expected = dp_test_json_create(
	  "{ \"portmonitor_information\": "
	  "  [ {   \"session\":1,"
	  "        \"type\": \"span\","
	  "        \"state\": \"enabled\","
	  "        \"source_interfaces\":["
	  "        {"
	  "	       \"name\":\"%s\","
	  "	       \"direction\":\"both\""
	  "	   }"
	  "        ],"
	  "        \"destination_interface\":\"%s\","
	  "        \"filters\":["
	  "        {"
	  "	       \"name\":\"PMFIN\","
	  "	       \"type\":\"in\""
	  "	   },"
	  "        {"
	  "	       \"name\":\"PMFOUT\","
	  "	       \"type\":\"out\""
	  "	   }"
	  "        ]"
	  "    }"
	  "    ]"
	  "}", src_ifname, dst_ifname);

	dp_test_check_json_state("portmonitor show session", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	/* Delete SPAN session */
	dp_test_portmonitor_delete_session(1);
} DP_END_TEST;

DP_START_TEST(pmcmds, rspan_source)
{
	char src_ifname[IFNAMSIZ];
	char dst_ifname[IFNAMSIZ];
	char ifname[IFNAMSIZ];
	json_object *expected;

	/* Set up vif interface */
	dp_test_intf_vif_create("dp1T3.10", "dp1T3", 10);
	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T3.10");

	dp_test_intf_real("dp1T1", src_ifname);
	dp_test_intf_real("dp1T3", dst_ifname);
	dp_test_portmonitor_create_rspansrc(1, src_ifname, dst_ifname, 10,
						"PMFIN", "PMFOUT");

	sprintf(ifname, "%s.10", dst_ifname);
	expected = dp_test_json_create(
	  "{ \"portmonitor_information\": "
	  "  [ {   \"session\":1,"
	  "        \"type\": \"rspan-source\","
	  "        \"state\": \"enabled\","
	  "        \"source_interfaces\":["
	  "        {"
	  "	       \"name\":\"%s\","
	  "	       \"direction\":\"both\""
	  "	   }"
	  "        ],"
	  "        \"destination_interface\":\"%s\","
	  "        \"filters\":["
	  "        {"
	  "	       \"name\":\"PMFIN\","
	  "	       \"type\":\"in\""
	  "	   },"
	  "        {"
	  "	       \"name\":\"PMFOUT\","
	  "	       \"type\":\"out\""
	  "	   }"
	  "        ]"
	  "    }"
	  "    ]"
	  "}", src_ifname, ifname);
	dp_test_check_json_state("portmonitor show session", expected,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected);

	/* Delete RSPAN-source session */
	dp_test_portmonitor_delete_session(1);

	/* Clean up vif interface */
	dp_test_intf_bridge_remove_port("br1", "dp1T3.10");
	dp_test_intf_vif_del("dp1T3.10", 10);
	dp_test_intf_bridge_del("br1");
} DP_END_TEST;

DP_START_TEST(pmcmds, rspan_destination)
{
	char src_ifname[IFNAMSIZ];
	char dst_ifname[IFNAMSIZ];
	char ifname[IFNAMSIZ];
	json_object *expected;

	/* Create vif interface */
	dp_test_intf_vif_create("dp1T3.10", "dp1T3", 10);
	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T3.10");

	dp_test_intf_real("dp1T3", src_ifname);
	dp_test_intf_real("dp1T2", dst_ifname);
	dp_test_portmonitor_create_rspandst(1, src_ifname, 10, dst_ifname);

	sprintf(ifname, "%s.10", src_ifname);
	expected = dp_test_json_create(
	  "{ \"portmonitor_information\": "
	  "  [ {   \"session\":1,"
	  "        \"type\": \"rspan-destination\","
	  "        \"state\": \"enabled\","
	  "        \"source_interfaces\":["
	  "        {"
	  "	       \"name\":\"%s\","
	  "	   }"
	  "        ],"
	  "        \"destination_interface\":\"%s\","
	  "    }"
	  "    ]"
	  "}", ifname, dst_ifname);
	dp_test_check_json_state("portmonitor show session", expected,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected);

	/* Delete RSPAN-destination session */
	dp_test_portmonitor_delete_session(1);

	/* Delete vif interface */
	dp_test_intf_bridge_remove_port("br1", "dp1T3.10");
	dp_test_intf_vif_del("dp1T3.10", 10);
	dp_test_intf_bridge_del("br1");
} DP_END_TEST;

DP_START_TEST(pmcmds, erspan_source)
{
	json_object *expected;
	char src_ifname[IFNAMSIZ];

	/* Create erspan tunnel */
	dp_test_intf_erspan_create("erspan1",
				   "1.1.2.1", "1.1.2.2",
				   0, 1, VRF_DEFAULT_ID);

	dp_test_intf_real("dp1T1", src_ifname);
	dp_test_portmonitor_create_erspansrc(1, src_ifname, "erspan1", 20, 1,
						"PMFIN", "PMFOUT");

	expected = dp_test_json_create(
	  "{ \"portmonitor_information\": "
	  "  [ {  \"session\":1,"
	  "        \"type\": \"erspan-source\","
	  "        \"state\": \"enabled\","
	  "        \"erspanid\":20,"
	  "        \"erspanhdr\":1,"
	  "        \"source_interfaces\":["
	  "        {"
	  "	       \"name\":\"%s\","
	  "	       \"direction\":\"both\""
	  "	   }"
	  "        ],"
	  "        \"destination_interface\":\"erspan1\","
	  "        \"filters\":["
	  "        {"
	  "	       \"name\":\"PMFIN\","
	  "	       \"type\":\"in\""
	  "	   },"
	  "        {"
	  "	       \"name\":\"PMFOUT\","
	  "	       \"type\":\"out\""
	  "	   }"
	  "        ]"
	  "    }"
	  "    ]"
	  "}", src_ifname);

	dp_test_check_json_state("portmonitor show session", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	/* Delete ERSPAN-source session */
	dp_test_portmonitor_delete_session(1);

	/* Delete erpsan tunnel */
	dp_test_intf_erspan_delete("erspan1", "1.1.2.1",
					"1.1.2.2", 0, 1, VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(pmcmds, erspan_destination)
{
	char dst_ifname[IFNAMSIZ];
	json_object *expected;

	/* Create erspan tunnel */
	dp_test_intf_erspan_create("erspan1", "1.1.2.1", "1.1.2.2",
					0, 1, VRF_DEFAULT_ID);

	dp_test_intf_real("dp1T2", dst_ifname);
	dp_test_portmonitor_create_erspandst(1, "erspan1", dst_ifname, 20, 1);

	expected = dp_test_json_create(
	  "{ \"portmonitor_information\": "
	  "  [ {  \"session\":1,"
	  "        \"type\": \"erspan-destination\","
	  "        \"state\": \"enabled\","
	  "        \"erspanid\":20,"
	  "        \"erspanhdr\":1,"
	  "        \"source_interfaces\":["
	  "        {"
	  "	       \"name\":\"erspan1\","
	  "	   }"
	  "        ],"
	  "        \"destination_interface\":\"%s\","
	  "    }"
	  "    ]"
	  "}", dst_ifname);

	dp_test_check_json_state("portmonitor show session", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	/* Delete ERSPAN-destination session */
	dp_test_portmonitor_delete_session(1);

	/* Delete erpsan tunnel */
	dp_test_intf_erspan_delete("erspan1", "1.1.2.1", "1.1.2.2",
					0, 1, VRF_DEFAULT_ID);
} DP_END_TEST;

