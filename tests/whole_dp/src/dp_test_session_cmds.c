/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
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
#include "dp_test_lib.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_netlink_state.h"
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

#define EXP_SESSION_SUMMARY						\
	"{ \"config\":"							\
	"  { \"sessions\":"						\
	"    { \"statistics\":"						\
	"      { \"used\":0,"						\
	"        \"max\":1048576,"					\
	"        \"nat\":0,"						\
	"        \"udp\":"						\
	"        { \"new\":0,"						\
	"          \"established\":0,"					\
	"          \"closed\":0"					\
	"        },"							\
	"        \"other\":"						\
	"        { \"new\":0,"						\
	"          \"established\":0,"					\
	"          \"closed\":0"					\
	"        },"							\
	"        \"tcp\":"						\
	"        { \"closed\":0,"					\
	"          \"syn_sent\":0,"					\
	"          \"simsyn_sent\":0,"					\
	"          \"syn_received\":0,"					\
	"          \"established\":0,"					\
	"          \"fin_sent\":0,"					\
	"          \"fin_received\":0,"					\
	"          \"close_wait\":0,"					\
	"          \"fin_wait\":0,"					\
	"          \"closing\":0,"					\
	"          \"last_ack\":0,"					\
	"          \"time_wait\":0"					\
	"        }"							\
	"      }"							\
	"    }"								\
	"  }"								\
	"}"

#define EXP_SESSIONS					\
	"{ \"config\":"					\
	"  {"						\
	"    \"sessions\": {}"				\
	"  }"						\
	"}"

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
 * This test array tests ./session/session_cmds.c
 */
static const struct dp_test_command_t session_cmd[] = {
	/*
	 * cmd_npf_walk_sessions_nat
	 *
	 * session-op show sessions nat [<start> [<count>]]
	 */
	{
		"session-op show sessions full",
		EXP_SESSIONS,
		true,
		true,
	},
	{
		"session-op show sessions full foo",
		"invalid start limit: foo",
		false,
		false,
	},
	{
		/* strtoul will find the '1' ok */
		"session-op show sessions full 1foo",
		EXP_SESSIONS,
		true,
		true,
	},
	{
		"session-op show sessions full 1",
		EXP_SESSIONS,
		true,
		true,
	},
	{
		"session-op show sessions full 1 2",
		EXP_SESSIONS,
		true,
		true,
	},
	/* cmd_npf_walk_sessions_summary */
	{
		"session-op show sessions summary",
		EXP_SESSION_SUMMARY,
		true,
		true,
	},
	/*
	 * cmd_npf_walk_sessions
	 *
	 * session-op show sessions [<start> [<count>]]
	 */
	{
		"session-op show sessions",
		EXP_SESSIONS,
		true,
		true,
	},
	{
		"session-op show sessions 1 2",
		EXP_SESSIONS,
		true,
		true,
	},
	/*
	 * cmd_npf_clear
	 *
	 * "delete session-table"
	 *  -> "session-op clear session all"
	 *
	 * "delete session-table conn-id 1"
	 *  -> "session-op clear session id 1"
	 *
	 * "delete session-table source 10.0.0.1 destination 11.0.0.1"
	 *  -> "session-op clear session filter saddr 10.0.0.1 sport any"
	 *     " daddr 11.0.0.1 dport any"
	 */
	{
		"session-op clear",
		"unknown command: clear",
		false,
		false,
	},
	{
		"session-op clear session all",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"session-op clear session foo",
		"unknown command: foo",
		false,
		false,
	},
	{
		"session-op clear session id 1",
		EXP_EMPTY_STRING,
		true,
		false,
	},
	{
		"session-op clear session filter saddr 10.0.0.1 sport any "
		"daddr 11.0.0.1 dport any",
		EXP_EMPTY_STRING,
		true,
		false,
	},
};

DP_DECL_TEST_SUITE(session_cmds);

DP_DECL_TEST_CASE(session_cmds, sess, NULL, NULL);

/*
 * Loop through npf command array, and verrify both pass/fail of command
 * and the response string.  Asserts pass/fail at the end of the loop.
 */
DP_START_TEST(sess, test1)
{
	unsigned int i;
	int rc;
	struct npf_config *npf_conf = NULL;
	json_object *jexp;

	rc = npf_attpt_item_set_up(NPF_ATTACH_TYPE_INTERFACE, "dpFWTEST",
				   &npf_conf, NULL);

	dp_test_fail_unless(rc == 0, "failed bringing attach point up");

	for (i = 0; i < ARRAY_SIZE(session_cmd); i++) {
		/* Do we expect a json reply or a string reply? */
		if (session_cmd[i].exp_json) {
			jexp = dp_test_json_create("%s",
					session_cmd[i].exp_reply);
			dp_test_check_json_poll_state(session_cmd[i].cmd, jexp,
						      DP_TEST_JSON_CHECK_SUBSET,
						      false,
						      POLL_CNT);
			json_object_put(jexp);
		} else
			dp_test_check_state_poll_show(session_cmd[i].cmd,
					session_cmd[i].exp_reply,
					session_cmd[i].exp_ok, false, POLL_CNT);

		dp_test_npf_cleanup();
	}

	rc = npf_attpt_item_set_down(NPF_ATTACH_TYPE_INTERFACE, "dpFWTEST");

	dp_test_fail_unless(rc == 0, "failed bringing attach point down");
} DP_END_TEST;
