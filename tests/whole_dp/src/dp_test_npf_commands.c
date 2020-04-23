/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf command tests
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
#include "dp_test_npf_sess_lib.h"


#define POLL_CNT	1

/*
 * Empty string is returned when command is accepted ok
 */
#define EXP_EMPTY_STRING ""
#define EXP_MISSING_CMD "missing command"
#define EXP_MISSING_ARG "missing argument"

#ifndef NALG
#define EXP_ALG_DUMP							\
	"{ \"alg\":"							\
	"  { \"instances\": [ {"					\
	"    \"vrfid\":1,"						\
	"    \"tuples\": ["						\
	"    { \"alg\": \"sip\","					\
	"        \"protocol\":6,"					\
	"        \"alg_flags\":1,"					\
	"        \"flags\":5,"						\
	"        \"dport\":5060"					\
	"    },"							\
	"    { \"alg\": \"tftp\","					\
	"        \"protocol\":17,"					\
	"        \"flags\":5,"						\
	"        \"dport\":69"						\
	"    },"							\
	"    { \"alg\": \"sip\","					\
	"        \"protocol\":17,"					\
	"        \"alg_flags\":1,"					\
	"        \"flags\":5,"						\
	"        \"dport\":5060"					\
	"    },"							\
	"    { \"alg\": \"rpc\","					\
	"        \"protocol\":6,"					\
	"        \"flags\":5,"						\
	"        \"dport\":111"						\
	"    },"							\
	"    { \"alg\": \"rpc\","					\
	"        \"protocol\":17,"					\
	"        \"flags\":5,"						\
	"        \"dport\":111"						\
	"    },"							\
	"    { \"alg\": \"ftp\","					\
	"        \"protocol\":6,"					\
	"        \"flags\":5,"						\
	"        \"dport\":21"						\
	"    }"								\
	"    ]}"							\
	"  ]}"								\
	"}"
#else
#define EXP_ALG_DUMP							\
	"{ \"alg\":"							\
	"   {"								\
	"   }"								\
	"}"
#endif

/*
 * Command to dataplane
 */
struct dp_test_command_t {
	const char *cmd;
	const char *exp_reply; /* expected reply */
	bool        exp_ok;    /* expected cmd success or fail */
	bool        exp_json;  /* true if json response expected */
};

/*
 * This test array loosely follows the command array in npf_cmd_op.c / npf_cmd_cfg.c
 */
static const struct dp_test_command_t npf_cmd[] = {
	/* cmd_dump_alg */
	{
		"npf-op fw dump-alg",
		EXP_ALG_DUMP,
		true,
		true,
	},
#ifndef NALG
	/*
	 * cmd_npf_fw_alg
	 *
	 * "set system alg ftp port x" -> "npf-ut fw alg set ftp port x"
	 * "del system alg ftp port x" -> "npf-ut fw alg delete ftp port x"
	 * "set system alg ftp disable" -> "npf-ut fw alg disable ftp"
	 * "del system alg ftp disable" -> "npf-ut fw alg enable ftp"
	 */
	{
		"npf-ut fw alg 1",
		EXP_MISSING_CMD,
		false,
		false,
	},
	{
		"npf-ut fw alg 1 enable",
		EXP_MISSING_CMD,
		false,
		false,
	},
	{
		"npf-ut fw alg 1 set ftp",
		"missing command",
		false,
		false,
	},
	{
		"npf-ut fw alg 1 set ftp port",
		"missing command",
		false,
		false,
	},
	{
		"npf-ut fw alg 1 set ftp port 1021",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw alg 1 delete ftp port 1021",
		"failed to delete alg ftp config",
		false,
		false,
	},
	{
		"npf-ut fw alg 1 disable ftp",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw alg 1 enable ftp",
		EXP_EMPTY_STRING,
		true,
		false,
	},
#endif

	/*
	 * cmd_npf_fw_table
	 *
	 * npf-ut fw table {create | delete} <table-id>
	 * npf-ut fw table {add | remove} <table-id> <address>
	 */
	{
		/* incomplete command */
		"npf-ut fw table",
		"unknown command: fw",
		false,
		false,
	},
	{
		/* incomplete command */
		"npf-ut fw table create",
		EXP_MISSING_CMD,
		false,
		false,
	},
	{
		"npf-ut fw table create ADDR_GRP1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		/* invalid address */
		"npf-ut fw table add ADDR_GRP1 12.0.0.",
		"failed to add table item (errno 22)",
		false,
		false,
	},
	{
		/* table doesn't exist */
		"npf-ut fw table add ADDR_GRP2 12.0.0.1",
		EXP_EMPTY_STRING,
		false,
		false,
	},
	{
		"npf-ut fw table add ADDR_GRP1 12.0.0.1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw table add ADDR_GRP1 13.0.0.1/24",
		"failed to add table item (errno 22)",
		false,
		false,
	},
	{
		"npf-ut fw table remove ADDR_GRP1 12.0.0.1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		/* deleting a non-existent table is a noop */
		"npf-ut fw table delete ADDR_GRP3",
		"npf address-group ADDR_GRP3 not found",
		false,
		false,
	},
	{
		"npf-ut fw table delete ADDR_GRP1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw table delete ADDR_GRP2",
		"npf address-group ADDR_GRP2 not found",
		false,
		false,
	},
	/* cmd_npf_fw_session_log_add */
	{
		/* incomplete command */
		"npf-ut fw session-log add tcp",
		"missing command",
		false,
		false,
	},
	{
		/* 'syn' is not a valid value */
		"npf-ut fw session-log add tcp syn",
		"failed to enable session log",
		false,
		false,
	},
	{
		"npf-ut fw session-log add tcp syn-sent",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw session-log add tcp closed",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw session-log add udp new",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw session-log add icmp closed",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* cmd_npf_fw_session_log_remove */
	{
		"npf-ut fw session-log remove tcp syn-sent",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw session-log remove tcp closed",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw session-log remove udp new",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut fw session-log remove icmp closed",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* cmd_npf_global_tcp_strict_enable */
	{
		"npf-ut fw global tcp-strict enable",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* cmd_ npf_global_tcp_strict_disable*/
	{
		"npf-ut fw global tcp-strict disable",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* cmd_npf_global_sessions_max */
	{
		"session-ut sessions-max",
		"missing max_session count",
		false,
		false,
	},
	{
		"session-ut sessions-max ten",
		"invalid max session count: ten",
		false,
		false,
	},
	{
		/* UINT32_MAX + 1 */
		"session-ut sessions-max 4294967296",
		"invalid max session count: 4294967296",
		false,
		false,
	},
	{
		/* UINT32_MAX */
		"session-ut sessions-max 4294967295",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		/* set back to default value */
		"session-ut sessions-max 0",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/*
	 * cmd_npf_global_timeout
	 *
	 * Valid protocols: tcp, udp, icmp, other
	 */
	{
		"npf-ut fw global timeout",
		EXP_MISSING_ARG,
		false,
		false,
	},
	{
		"npf-ut fw global timeout tcp",
		EXP_MISSING_ARG,
		false,
		false,
	},
	{
		"npf-ut fw global timeout closed",
		EXP_MISSING_ARG,
		false,
		false,
	},
	{
		"npf-ut fw global timeout 1 update tcp closed 10",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* Only check section_size/mapping_count */
	{
		"npf-op fw dump-portmap",
		"{"
		"  \"apm\":"
		"  { \"section_size\": 512,"
		"    \"protocols\":"
		"    [ "
		"      { "
		"        \"protocol\": \"tcp\", "
		"        \"mapping_count\": 0"
		"      }, "
		"      { "
		"        \"protocol\": \"udp\", "
		"        \"mapping_count\": 0"
		"      }, "
		"      { "
		"        \"protocol\": \"other\", "
		"        \"mapping_count\": 0"
		"      } "
		"    ] "
		"  } "
		"}",
		true,
		true,
	},

	/* npf-ut add <class>:<group> <index> <rule> */
	{ /* no colon in group */
		"npf-ut add GROUP 10 rule=1",
		"invalid group name: GROUP (-22)",
		false,
		false,
	},
	{ /* invalid group class */
		"npf-ut add XXX:GROUP 10 rule=1",
		"invalid group name: XXX:GROUP (-2)",
		false,
		false,
	},
	{ /* too short */
		"npf-ut add fw:GROUP",
		"missing command",
		false,
		false,
	},
	{ /* bad index */
		"npf-ut add fw:GROUP hello rule=1",
		"invalid index: hello",
		false,
		false,
	},
	{ /* valid entry with index */
		"npf-ut add fw:GROUP 10 rule=1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* valid unnumbered entry */
		"npf-ut add fw:UNNUMBERED 0 rule=1",
		EXP_EMPTY_STRING,
		true,
		false,
	},

	/* npf-ut delete <class>:<group> [<index> [<rule>]] */
	{ /* no colon in group */
		"npf-ut delete GROUP 10 rule=1",
		"invalid group name: GROUP (-22)",
		false,
		false,
	},
	{ /* invalid group class */
		"npf-ut delete XXX:GROUP 10 rule=1",
		"invalid group name: XXX:GROUP (-2)",
		false,
		false,
	},
	{ /* too short */
		"npf-ut delete",
		"missing command",
		false,
		false,
	},
	{ /* bad index */
		"npf-ut delete fw:GROUP hello rule=1",
		"invalid index: hello",
		false,
		false,
	},
	{ /* delete unnumbered without rule */
		"npf-ut delete fw:GROUP 0",
		"need rule when index is 0",
		false,
		false,
	},
	{ /* delete existing entry with index (add done above) */
		"npf-ut delete fw:GROUP 10 rule=1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* delete non-existing entry with index */
		"npf-ut delete fw:GROUP 99 rule=1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* delete non-existing entry with index, but no rule */
		"npf-ut delete fw:GROUP 99",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* delete existing unnumbered entry (add done above) */
		"npf-ut delete fw:UNNUMBERED 0 rule=1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* delete non-existing unnumbered entry */
		"npf-ut delete fw:YYYYYY 0 rule=1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* delete whole group */
		"npf-ut delete fw:GROUP",
		EXP_EMPTY_STRING,
		true,
		false,
	},

	/*
	 * npf-ut attach <attach-type>:<attach-point> <ruleset-type>
	 *            <class>:<group>
	 */
	{ /* too short */
		"npf-ut attach dp0s10 fw-in",
		"missing command",
		false,
		false,
	},
	{ /* no colon in attach type */
		"npf-ut attach dp0s10 fw-in fw:GROUP",
		"invalid attach point: dp0s10 (-22)",
		false,
		false,
	},
	{ /* invalid attach type */
		"npf-ut attach XXX:dp0s10 fw-in fw:GROUP",
		"invalid attach point: XXX:dp0s10 (-2)",
		false,
		false,
	},
	{ /* invalid ruleset type */
		"npf-ut attach interface:dp0s10 BAD fw:GROUP",
		"invalid ruleset type: BAD (-2)",
		false,
		false,
	},
	{ /* no colon in group */
		"npf-ut attach interface:dp0s10 fw-in GROUP",
		"invalid group name: GROUP (-22)",
		false,
		false,
	},
	{ /* invalid group class */
		"npf-ut attach interface:dp0s10 fw-in XXX:GROUP",
		"invalid group name: XXX:GROUP (-2)",
		false,
		false,
	},
	{ /* attach */
		"npf-ut attach interface:dp0s10 fw-in fw:GROUP",
		EXP_EMPTY_STRING,
		true,
		false,
	},

	/*
	 * npf-ut detach <attach-type>:<attach-point> <ruleset-type>
	 *            <class>:<group>
	 */
	{ /* too short */
		"npf-ut detach dp0s10 fw-in",
		"missing command",
		false,
		false,
	},
	{ /* no colon in attach type */
		"npf-ut detach dp0s10 fw-in fw:GROUP",
		"invalid attach point: dp0s10 (-22)",
		false,
		false,
	},
	{ /* invalid attach type */
		"npf-ut detach XXX:dp0s10 fw-in fw:GROUP",
		"invalid attach point: XXX:dp0s10 (-2)",
		false,
		false,
	},
	{ /* invalid ruleset type */
		"npf-ut detach interface:dp0s10 BAD fw:GROUP",
		"invalid ruleset type: BAD (-2)",
		false,
		false,
	},
	{ /* no colon in group */
		"npf-ut detach interface:dp0s10 fw-in GROUP",
		"invalid group name: GROUP (-22)",
		false,
		false,
	},
	{ /* invalid group class */
		"npf-ut detach interface:dp0s10 fw-in XXX:GROUP",
		"invalid group name: XXX:GROUP (-2)",
		false,
		false,
	},
	{ /* detach (was created above)*/
		"npf-ut detach interface:dp0s10 fw-in fw:GROUP",
		EXP_EMPTY_STRING,
		true,
		false,
	},

	 /* npf-op dump groups */
	{ /* empty database */
		"npf-op dump groups",
		"{"
		"    \"rule_groups\": []"
		"}",
		true,
		true,
	},
	/* add 3 enties and then dump */
	{
		"npf-ut add fw:GROUP1 10 rule=1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut add pbr:GROUP2 0 rule=PBR",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut add fw:GROUP1 200 rule=200",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-op dump groups",
		"{"
		"  \"rule_groups\":["
		"    {"
		"      \"group_class\":\"pbr\","
		"      \"group\":\"GROUP2\","
		"      \"rules\":["
		"	{"
		"	  \"index\":0,"
		"	  \"rule\":\"rule=PBR\""
		"	}"
		"      ]"
		"    },"
		"    {"
		"      \"group_class\":\"fw\","
		"      \"group\":\"GROUP1\","
		"      \"rules\":["
		"	{"
		"	  \"index\":10,"
		"	  \"rule\":\"rule=1\""
		"	},"
		"	{"
		"	  \"index\":200,"
		"	  \"rule\":\"rule=200\""
		"	}"
		"      ]"
		"    }"
		"  ]"
		"}",
		true,
		true,
	},
	/* remove entries added to keep config clean */
	{
		"npf-ut delete fw:GROUP1 10 rule=1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut delete pbr:GROUP2 0 rule=PBR",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut delete fw:GROUP1 200 rule=200",
		EXP_EMPTY_STRING,
		true,
		false,
	},

	 /* npf-op dump attach-points */
	{ /* empty database */
		"npf-op dump attach-points",
		"{"
		"    \"attach_points\": []"
		"}",
		true,
		true,
	},
	/* add 2 enties and then dump */
	{
		"npf-ut attach interface:dp0s10 fw-in fw:GROUP1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut attach interface:dp0s10 fw-in fw:GROUP2",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-op dump attach-points",
		  "{"
		  "    \"attach_points\":["
		  "    {"
		  "        \"attach_type\":\"interface\","
		  "        \"attach_point\":\"dp0s10\","
		  "        \"rulesets\":["
		  "	   {"
		  "	       \"ruleset_type\":\"fw-in\","
		  "	       \"groups\":["
		  "	       {"
		  "	           \"group_class\":\"fw\","
		  "	           \"group\":\"GROUP1\","
		  "	       },"
		  "	       {"
		  "	           \"group_class\":\"fw\","
		  "	           \"group\":\"GROUP2\","
		  "	       }"
		  "	       ]"
		  "	   }"
		  "       ]"
		  "    }"
		  "    ]"
		  "}",
		true,
		true,
	},
	/* remove entries added to keep config clean */
	{
		"npf-ut detach interface:dp0s10 fw-in fw:GROUP1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut detach interface:dp0s10 fw-in fw:GROUP2",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		/* attempt to commit with too many parameters */
		"npf-ut commit today",
		"too many arguments",
		false,
		false,
	},
	{
		/* attempt to commit with nothing configured */
		"npf-ut commit",
		EXP_EMPTY_STRING,
		true,
		false,
	},

	/*
	 * npf-op show  [<attach-type>:[<attach-point>] [<ruleset-type> ...]]
	 */
	/* show all when none are configured */
	{
		"npf-op show",
		"{"
		"	\"config\": []"
		"}",
		true,
		true,
	},
	/* show attach point when none are configured */
	{
		"npf-op show interface:dp0s10",
		"{"
		"	\"config\": []"
		"}",
		true,
		true,
	},
	/* show attach point and some rulesets when not configured */
	{
		"npf-op show interface:dp0s10 fw-in pbr",
		"{"
		"	\"config\": []"
		"}",
		true,
		true,
	},
	/* bad attach-type */
	{
		"npf-op show BAD:22",
		"invalid selected attach point: BAD:22 (-2)",
		false,
		false,
	},
	/* bad ruleset-type */
	{
		"npf-op show interface:dp0s10 BAD",
		"invalid selected ruleset type: BAD (-2)",
		false,
		false,
	},
	/* bad 2nd ruleset-type */
	{
		"npf-op show interface:dp0s10 fw-in VBAD",
		"invalid selected ruleset type: VBAD (-2)",
		false,
		false,
	},

	/*
	 * npf-op clear  [<attach-type>:[<attach-point>] [<ruleset-type> ...]]
	 */
	/* clear all when none are configured */
	{
		"npf-op clear",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* clear attach point when none are configured */
	{
		"npf-op clear interface:dp0s10",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* clear attach point and some rulesets when not configured */
	{
		"npf-op clear interface:dp0s10 fw-in pbr",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* bad attach-type */
	{
		"npf-op clear BAD:22",
		"invalid selected attach point: BAD:22 (-2)",
		false,
		false,
	},
	/* bad ruleset-type */
	{
		"npf-op clear interface:dp0s10 BAD",
		"invalid selected ruleset type: BAD (-2)",
		false,
		false,
	},
	/* bad 2nd ruleset-type */
	{
		"npf-op clear interface:dp0s10 fw-in VBAD",
		"invalid selected ruleset type: VBAD (-2)",
		false,
		false,
	},
	/*
	 * create a rule group on interface and display rulesets,
	 * clear the statistics, and dump the generated file
	 */
	{ /* add rule to a rule group */
		"npf-ut add fw:FW1 10 action=accept proto=6 src-port=80",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* attach group to an interface */
		"npf-ut attach interface:dpFWTEST fw-in fw:FW1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* commit the changes */
		"npf-ut commit",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* show all and check we see ruleset configured above */
	{
		"npf-op show",
		"{"
		"  \"config\":["
		"    {"
		"      \"attach_type\":\"interface\","
		"      \"attach_point\":\"dpFWTEST\","
		"      \"rulesets\":["
		"	{"
		"	  \"ruleset_type\":\"fw-in\","
		"	  \"groups\":["
		"	    {"
		"	      \"class\":\"fw\","
		"	      \"name\":\"FW1\","
		"	      \"direction\":\"in\","
		"	      \"rules\":{"
		"		\"10\":{"
		"		  \"bytes\":0,"
		"		  \"packets\":0,"
		"		  \"action\":\"pass \","
		"		  \"match\":\"proto 6 from any port 80 \""
		"		}"
		"	      }"
		"	    }"
		"	  ]"
		"	}"
		"      ]"
		"    }"
		"  ]"
		"}",
		true,
		true,
	},
	{ /* clear all statistics */
		"npf-op clear",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* undo the changes above */
	{ /* detach group from an interface */
		"npf-ut detach interface:dpFWTEST fw-in fw:FW1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* remove rule from a rule group */
		"npf-ut delete fw:FW1 10",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{ /* commit the changes */
		"npf-ut commit",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	/* show all - should now be none */
	{
		"npf-op show",
		"{"
		"	\"config\": []"
		"}",
		true,
		true,
	},
	/* ruleset type portmonitor-in: attach to group */
	{
		"npf-ut add fw:GROUP1 200 rule=200",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-ut attach interface:dp0s10 portmonitor-in fw:GROUP1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-op dump attach-points",
		  "{"
		  "    \"attach_points\":["
		  "    {"
		  "        \"attach_type\":\"interface\","
		  "        \"attach_point\":\"dp0s10\","
		  "        \"rulesets\":["
		  "	   {"
		  "	       \"ruleset_type\":\"portmonitor-in\","
		  "	       \"groups\":["
		  "	       {"
		  "	           \"group_class\":\"fw\","
		  "	           \"group\":\"GROUP1\","
		  "	       },"
		  "	       ]"
		  "	   }"
		  "       ]"
		  "    }"
		  "    ]"
		  "}",
		true,
		true,
	},
	{
		"npf-ut detach interface:dp0s10 portmonitor-in fw:GROUP1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	 /* npf dump attach-points */
	{ /* empty database */
		"npf-op dump attach-points",
		"{"
		"    \"attach_points\": []"
		"}",
		true,
		true,
	},
	/* ruleset type portmonitor-out: attach to group */
	{
		"npf-ut attach interface:dp0s10 portmonitor-out fw:GROUP1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"npf-op dump attach-points",
		  "{"
		  "    \"attach_points\":["
		  "    {"
		  "        \"attach_type\":\"interface\","
		  "        \"attach_point\":\"dp0s10\","
		  "        \"rulesets\":["
		  "	   {"
		  "	       \"ruleset_type\":\"portmonitor-out\","
		  "	       \"groups\":["
		  "	       {"
		  "	           \"group_class\":\"fw\","
		  "	           \"group\":\"GROUP1\","
		  "	       },"
		  "	       ]"
		  "	   }"
		  "       ]"
		  "    }"
		  "    ]"
		  "}",
		true,
		true,
	},
	{
		"npf-ut detach interface:dp0s10 portmonitor-out fw:GROUP1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	 /* npf dump attach-points */
	{ /* empty database */
		"npf-op dump attach-points",
		"{"
		"    \"attach_points\": []"
		"}",
		true,
		true,
	},
	{
		"npf-ut delete fw:GROUP1 200 rule=200",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	 /* npf dump attach-points */
	{ /* empty database */
		"npf-op dump attach-points",
		"{"
		"    \"attach_points\": []"
		"}",
		true,
		true,
	},
};

DP_DECL_TEST_SUITE(npf_cmds);

DP_DECL_TEST_CASE(npf_cmds, case1, NULL, NULL);

/*
 * Loop through npf command array, and verrify both pass/fail of command
 * and the response string.  Asserts pass/fail at the end of the loop.
 */
DP_START_TEST(case1, test1)
{
	unsigned int i;
	int rc;
	struct npf_config *npf_conf = NULL;
	json_object *jexp;

	/* use own attach point */
	rc = npf_attpt_item_set_up(NPF_ATTACH_TYPE_INTERFACE, "dpFWTEST",
				   &npf_conf, NULL);

	dp_test_fail_unless(rc == 0, "failed bringing attach point up");

	for (i = 0; i < ARRAY_SIZE(npf_cmd); i++) {
		/* Do we expect a json reply or a string reply? */
		if (npf_cmd[i].exp_json) {
			jexp = dp_test_json_create("%s", npf_cmd[i].exp_reply);
			dp_test_check_json_poll_state(npf_cmd[i].cmd, jexp,
						      DP_TEST_JSON_CHECK_SUBSET,
						      false,
						      POLL_CNT);
			json_object_put(jexp);
		} else
			dp_test_check_state_poll_show(npf_cmd[i].cmd,
					npf_cmd[i].exp_reply,
					npf_cmd[i].exp_ok, false, POLL_CNT);

		dp_test_npf_cleanup();
	}

	rc = npf_attpt_item_set_down(NPF_ATTACH_TYPE_INTERFACE, "dpFWTEST");

	dp_test_fail_unless(rc == 0, "failed bringing attach point down");
} DP_END_TEST;
