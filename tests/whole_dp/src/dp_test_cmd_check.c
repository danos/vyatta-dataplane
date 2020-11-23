/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Check dataplane internal state using operational commands
 */
#include "dp_test/dp_test_cmd_check.h"

#include <czmq.h>

#include "if_var.h"
#include "mpls/mpls.h"
#include "npf/npf_if.h"

#include "dp_test_lib_internal.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test.h"
#include "dp_test_npf_lib.h"
#include "vrf_internal.h"

#define STRINGIFZ(x) #x
#define STRINGIFY(x) STRINGIFZ(x)

/*
 * We want to be able to verify that state we send to the dataplane via
 * netlink or via a console command, has been processed properly.
 */
static char expected_ifconfig_str[28000];
static char expected_route_str[DP_TEST_TMP_BUF] =
"{ \"route_show\": "
"  [ "
"  ] "
"}";
char expected_npf_fw_portmap_str[DP_TEST_TMP_BUF];

#define DP_TEST_EXP_NPF_FW_PORTMAP_VR_STR \
"{" \
"  \"apm\":" \
"  { \"section_size\": 512," \
"    \"protocols\":" \
"    [ " \
"      { " \
"        \"protocol\": \"tcp\", " \
"        \"mapping_count\": 0" \
"      }, " \
"      { " \
"        \"protocol\": \"udp\", " \
"        \"mapping_count\": 0" \
"      }, " \
"      { " \
"        \"protocol\": \"other\", " \
"        \"mapping_count\": 0" \
"      } " \
"    ] " \
"  } " \
"}"

char expected_vrf_str[DP_TEST_TMP_BUF];

/* VR vrf clean refcounts vrf 0 (invalid) = 1 for invalid vrf table
 * vrf 1 (default) = 20 dpdk ports +1 loopback +1 for
 * default vrf table = 22
 */
#define DP_TEST_EXP_VRF_VR_STR \
"{ \"vrf_table\":" \
"  [ " \
"    { " \
"      \"vrf_id\": 0," \
"      \"internal_vrf_id\": 0," \
"      \"ref_count\": 1" \
"    },{" \
"      \"vrf_id\": 1," \
"      \"internal_vrf_id\": 1," \
"      \"ref_count\": 22" \
"    } " \
"  ] " \
"}"

char expected_route_stats_str[DP_TEST_TMP_BUF];

#define DP_TEST_EXP_ROUTE_STATS_VR_STR \
	"{ \"route_stats\": " \
	"   {  " \
	"     \"prefix\":" \
	"       { " \
	"       }, " \
	"     \"total\": 0," \
	"     \"used\": 1," \
	"     \"free\": 255," \
	"     \"nexthop\": "  \
	"       { " \
	"         \"neigh_present\": 0," \
	"         \"neigh_created\": 0," \
	"       }, "			 \
	"   }"				 \
	"}"

char parse_err_str[10000];
static char mismatch_str[10000];

uint32_t dp_test_wait_sec = DP_TEST_WAIT_SEC_DEFAULT;

void dp_test_wait_set(uint8_t wait_sec)
{
	dp_test_wait_sec = wait_sec;
}

/*
 * Callback function for the state checker, that is called until either
 * we have been round the loop too many times, or we find what we are
 * looking for.
 */
static int
dp_test_check_state(zloop_t *loop, int poller, void *arg)
{
	struct dp_test_cmd_check *state = arg;
	char buf[DP_TEST_TMP_BUF];
	char *reply;
	bool match;
	bool err;
	int i;

	state->poll_cnt--;
	snprintf(buf, DP_TEST_TMP_BUF, "%s", state->cmd);
	if (state->print) {
		for (i = 0; i < state->exp_count; i++) {
			printf("console req: looking for %s'%s'\n",
			       state->negate_match ? "absence of " : "",
			       state->expected[i]);
		}
	}
	reply = dp_test_console_request_w_err(buf, &err, state->print);
	if  (state->print)
		printf("console rep content: '%s'", reply ? reply : "<NULL>");

	if (err != state->exp_err || !reply)
		match = false;
	else {
		match = false;
		for (i = 0; i < state->exp_count; i++) {
			switch (state->type) {
			case DP_TEST_CHECK_STR_SUBSET:
				match = strstr(reply,
					       state->expected[i]) != NULL;
				break;
			case DP_TEST_CHECK_STR_EXACT:
				match = !strcmp(reply, state->expected[i]);
				break;
			}
			if (match)
				/* Can't negate if multiple matches */
				break;
		}
	}
	free(state->actual);
	state->actual = reply;

	if (state->negate_match)
		state->result = !match;
	else
		state->result = match;

	/* return -1 to stop if we got what we want or run out of retries */
	return (state->result || state->poll_cnt == 0) ? -1 : 0;
}

static void
dp_test_check_state_with_show(const char *file, int line, const char *cmd,
			      int expected_count,
			      const char **expected, bool exp_err,
			      bool negate_match, bool print,
			      dp_test_check_str_type type, int poll_cnt)
{
	if (!poll_cnt)
		poll_cnt = DP_TEST_POLL_COUNT;
	struct dp_test_cmd_check state = {
		.cmd = cmd,
		.exp_count = expected_count,
		.expected = expected,
		.actual = NULL,
		.print = print,
		.exp_err = exp_err,
		.negate_match = negate_match,
		.type = type,
		.poll_cnt = poll_cnt,
		.result = false,
	};
	int timer;
	zloop_t *loop = zloop_new();
	int i;

	dp_test_assert_internal(loop);

	/*
	 * loop every millisec, forever. dp_test_check_state returning < 0 will
	 * break loop.
	 */
	timer = zloop_timer(loop, DP_TEST_POLL_INTERVAL, 0, dp_test_check_state,
			    &state);
	dp_test_assert_internal(timer >= 0);

	zloop_start(loop);
	zloop_destroy(&loop);

	if (dp_test_debug_get() > 1 || !state.result)
		printf("%s: Cmd \"%s\" returned %s after %d ms (%d/%d)\n",
		       dp_test_pname, cmd,
		       state.result ? "found" : "not found",
		       (poll_cnt - state.poll_cnt) * DP_TEST_POLL_INTERVAL,
		       poll_cnt - state.poll_cnt, poll_cnt);

	if (!state.result && expected_count > 1) {
		/* We have failed */
		printf("Expected one of %d:\n", expected_count);
		for (i = 0; i < expected_count; i++)
			printf("%s\n", expected[i]);

		_dp_test_fail_unless(state.result,
				     file, line,
				     "\nstate not present in show %s:\n%s",
				     state.cmd, state.actual);
	}
	_dp_test_fail_unless(
		state.result, file, line,
		"\nUnexpected show state: '%s' %spresent in show %s:\n%s",
		state.expected[0], state.negate_match ? "" : "not ",
		state.cmd, state.actual);
	free(state.actual);
	/* TODO: Remove me when ck_assert_msg is reliable. */
	dp_test_assert_internal(state.result);
}

void
_dp_test_check_state_poll_show(const char *file, int line,
			       const char *cmd,
			       const char *expected,
			       bool exp_ok, bool print, int poll_cnt,
			       dp_test_check_str_type type)
{
	dp_test_check_state_with_show(file, line, cmd, 1,
				      &expected, !exp_ok,
				      false, print, type, poll_cnt);
}

void
_dp_test_check_state_show(const char *file, int line, const char *cmd,
			  const char *expected, bool print,
			  dp_test_check_str_type type)
{
	dp_test_check_state_with_show(file, line, cmd, 1,
				      &expected, false, false,
				      print, type, 0);
}

void
_dp_test_check_state_show_one_of(const char *file, int line, const char *cmd,
				 int exp_count, const char **expected,
				 bool print, dp_test_check_str_type type)
{
	dp_test_check_state_with_show(file, line, cmd, exp_count,
				      expected, false, false,
				      print, type, 0);
}

void
_dp_test_check_state_gone_show(const char *file, int line, const char *cmd,
			       const char *expected, bool print,
			       dp_test_check_str_type type)
{
	dp_test_check_state_with_show(file, line, cmd, 1,
				      &expected, false, true,
				      print, type, 0);
}

struct cmd_expect {
	const char *cmd;
	dp_test_check_str_type mode;
	const char *expected;
};

struct cmd_expect_json {
	const char *cmd;
	enum dp_test_check_json_mode mode;
	const char *expected;
	const char *filter;
};

static struct cmd_expect cmd_expect_clean[] = {
	{
		"local", DP_TEST_CHECK_STR_EXACT, "\n"
	},
};

static struct cmd_expect_json cmd_expect_clean_json[] = {
	{
		"route", DP_TEST_JSON_CHECK_EXACT,
		"{ \"route_show\": "
			"  [ "
			"  ] "
		"}",
		"",
	},
	{
		"route summary", DP_TEST_JSON_CHECK_SUBSET,
		expected_route_stats_str,
		""
	},
	{
		"route6", DP_TEST_JSON_CHECK_EXACT,
		"{ \"route6_show\": "
		"  [ "
		"  ] "
		"}", ""
	},
	{
		"route6 summary", DP_TEST_JSON_CHECK_SUBSET,
		"{ \"route6_stats\":"
		"  {  "
		"     \"tbl8s\":"
		"       {"
		"         \"used\":"
		"           14," /* for reserved routes */
		"         \"free\":"
		"           242"
		"       },"
		"     \"nexthop\": "		\
		"       { "			\
		"         \"neigh_present\": 0,"	\
		"         \"neigh_created\": 0,"	\
		"       }, "				\
		"  }"
		"}", ""
	},
	{
		"arp", DP_TEST_JSON_CHECK_EXACT,
		"{ \"arp\": "
		"  [ "
		"  ] "
		"}", ""
	},
	{
		"nd6", DP_TEST_JSON_CHECK_EXACT,
		"{ \"nd6\": "
		"  [ "
		"  ] "
		"}", ""
	},
	{
		"ifconfig", DP_TEST_JSON_CHECK_EXACT,
		expected_ifconfig_str,
		/*
		 * filter out fields that are read-only and stats that
		 * we don't expect to stay clean.
		 */
		"{ \"interfaces\": "
		"  [ "
		"    { "
		"      \"biosname\": \"\","
		"      \"dev\": "
		"      { "
		"      }, "
		"      \"xstatistics\": "
		"      { "
		"      }, "
		"      \"statistics\": "
		"      { "
		"      }, "
		"      \"l2_mcast_filters\": "
		"      { "
		"      }, "
		"      \"eth-info\": "
		"      { "
		"      } "
		"    } "
		"  ] "
		"}",
	},
	{
		"ipsec spd", DP_TEST_JSON_CHECK_EXACT,
		"{ \"ipsec_policies\": "
		"  { \"vrf\": 1,"
		"    \"policy_statistics\": "
		"    {"
		"        \"rekey_requests\": 0"
		"    },"
		"    \"total_policy_count\": "
		"    { "
		"        \"ipv4\": 0,"
		"        \"ipv6\": 0"
		"    }, "
		"    \"live_policy_count\": "
		"    { "
		"        \"ipv4\": 0,"
		"        \"ipv6\": 0"
		"    }, "
		"    \"policies\":"
		"    ["
		"    ]"
		"  }"
		"}", ""
	},
	{
		"ipsec sad", DP_TEST_JSON_CHECK_EXACT,
		"{ \"ipsec-sas\": "
		"  { "
		"    \"vrf\": 1, "
		"    \"total-sas\": 0 "
		"  }, "
		"  \"sas\": "
		"  [ "
		"  ] "
		"}", ""
	},
	{
		"npf-op show",
		DP_TEST_JSON_CHECK_EXACT,
		"{\n    \"config\": []\n    }\n", ""
	},
	{
		"npf-op dump groups",
		DP_TEST_JSON_CHECK_EXACT,
		"{\n    \"rule_groups\": []\n    }\n", ""
	},
	{
		"npf-op dump attach-points",
		DP_TEST_JSON_CHECK_EXACT,
		"{\n    \"attach_points\": []\n    }\n", ""
	},
	{
		"session-op show sessions summary",
		DP_TEST_JSON_CHECK_SUBSET,
		"{ \"config\":"
		"  { \"sessions\":"
		"    { \"statistics\":"
		"      {"
		"        \"used\":0, "
		"        \"nat\":0 "
		"      }"
		"    }"
		"  }"
		"}", ""
	},
	{
		"npf-op fw dump-portmap",
		DP_TEST_JSON_CHECK_SUBSET,
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
		"}", ""
	},
	{
		"mpls show config", DP_TEST_JSON_CHECK_SUBSET,
		"{ "
		"  \"config\":"
		"  {"
		"    \"ipttlpropagate\":1,"
		"    \"defaultttl\":-1"
		"  }"
		"}", ""
	},
	{
		"mpls show tables", DP_TEST_JSON_CHECK_EXACT,
		"{ "
		"  \"mpls_tables\":"
		"  ["
		"  ]"
		"}", ""
	},
	{
		"incomplete", DP_TEST_JSON_CHECK_SUBSET,
		"{ \"incomplete\":"
		"  {  "
		"    \"incomplete\": 0,"
		"    \"ignored\": 0 "
		"  }"
		"}", ""
	},
	{
		"vrf", DP_TEST_JSON_CHECK_EXACT,
		expected_vrf_str,
		""
	},
	{
		"pipeline xconnect cmd -s", DP_TEST_JSON_CHECK_EXACT,
		"{"
		"  \"xconn\":"
		"  ["
		"  ]"
		"}",
		""
	},
};

/* Return the expected refcount on the default VRF */
unsigned int
dp_test_default_vrf_clean_count(void)
{
	return dp_test_intf_clean_count() + 1; /* vrf table */
}

void
_dp_test_check_state_clean(const char *file, int line, bool print)
{
	const char *cmd, *expected;
	unsigned int in_use_mbufs;
	uint8_t i;

	/* Regenerate the expected ifconfig json */
	dp_test_reset_expected_ifconfig();

	for (i = 0; i < ARRAY_SIZE(cmd_expect_clean); i++) {
		cmd = cmd_expect_clean[i].cmd;
		expected = cmd_expect_clean[i].expected;
		/* checking for a subset implies the check is inverted */
		if (cmd_expect_clean[i].mode == DP_TEST_CHECK_STR_SUBSET)
			_dp_test_check_state_gone_show(
				file, line, cmd, expected, print,
				cmd_expect_clean[i].mode);
		else
			_dp_test_check_state_show(
				file, line, cmd, expected, print,
				cmd_expect_clean[i].mode);
	}

	for (i = 0; i < ARRAY_SIZE(cmd_expect_clean_json); i++) {
		json_object *filter_json = NULL;
		json_object *expected_json;

		expected = cmd_expect_clean_json[i].expected;
		expected_json = parse_json(expected, parse_err_str,
					   sizeof(parse_err_str));
		if (!expected_json) {
			printf("%s:%d %s - %s", __FILE__, __LINE__, __func__,
			       parse_err_str);
			dp_test_assert_internal(!"dp_test_json_create failed");
		}

		if (cmd_expect_clean_json[i].filter[0])
			filter_json = dp_test_json_create(
				"%s", cmd_expect_clean_json[i].filter);

		_dp_test_check_json_state(cmd_expect_clean_json[i].cmd,
					  expected_json,
					  filter_json,
					  cmd_expect_clean_json[i].mode,
					  false, file, "", line);
		json_object_put(expected_json);
		if (filter_json)
			json_object_put(filter_json);
	}

	in_use_mbufs = rte_mempool_in_use_count(mbuf_pool(0));
	_dp_test_fail_unless(in_use_mbufs == 0, file, line,
			     "%u mbufs leaked", in_use_mbufs);
}

/*
 * Create a json object from printf format string and argument list.
 */
json_object *
dp_test_json_create(const char *fmt_str, ...)
{
	char json_str[DP_TEST_TMP_BUF];
	json_object *jobj;
	va_list ap;
	int len;

	va_start(ap, fmt_str);
	len = vsnprintf(json_str, sizeof(json_str), fmt_str, ap);
	va_end(ap);
	dp_test_assert_internal(len < DP_TEST_TMP_BUF);

	jobj = parse_json(json_str, parse_err_str, sizeof(parse_err_str));
	if (!jobj) {
		printf("%s:%d %s - %s", __FILE__, __LINE__, __func__,
		       parse_err_str);
		dp_test_assert_internal(!"dp_test_json_create failed");
	}
	return jobj;
};

struct dp_test_show_cmd_poll_state {
	char request_str[DP_TEST_TMP_BUF]; /* poll req */
	void *pb_req;
	int pb_req_len;
	void *pb_resp;
	int pb_resp_len;
	dp_test_state_pb_cb pb_func;
	void *pb_arg;
	json_object *json_resp; /* latest reply */
	int poll_cnt;

	/* matches for each reply */
	json_object *required_superset;
	json_object *required_subset;
	json_object *required_exact;

	/* filter out the leaves of this json object */
	json_object *filter;

	/* mismatches of above */
	struct dp_test_json_mismatches *mismatches;

	/* negate the result - i.e. we want a mismatch */
	bool negate_match;

	bool print; /* dbg print each req/resp */
	bool result; /* (!mismatches && !negate) ||
			(mismatches && negate)    */
};

static int
poll_for_matching_state(zloop_t *loop, int poller, void *arg)
{
	struct dp_test_json_mismatches *mismatches = NULL;
	struct dp_test_show_cmd_poll_state *cmd = arg;
	json_object *json_resp;

	--(cmd->poll_cnt);
	json_resp = dp_test_json_do_show_cmd(cmd->request_str,
					     &mismatches, cmd->print);
	if (!json_resp) {
		dp_test_json_mismatch_record(
			&mismatches,
			"Json tokener error:",
			NULL,
			"quoted object property name expected.");
	} else {
		if (cmd->filter)
			dp_test_json_filter(json_resp, cmd->filter);

		if (cmd->required_exact)
			(void)dp_test_json_match(cmd->required_exact, json_resp,
						 &mismatches);
		if (cmd->required_subset)
			(void)dp_test_json_subset(cmd->required_subset,
						  json_resp, &mismatches);
		if (cmd->required_superset)
			(void)dp_test_json_superset(cmd->required_superset,
						    json_resp, &mismatches);
	}
	/*
	 * if there's a previous result then free that and take this
	 * latest one.
	 */
	if (cmd->mismatches)
		dp_test_json_mismatch_free(cmd->mismatches);
	cmd->mismatches = mismatches;
	if (cmd->json_resp)
		json_object_put(cmd->json_resp);
	cmd->json_resp = json_resp;

	/*
	 * if we don't have a mismatch or we do have a mismatch
	 * but we are negating the result then result is good.
	 */
	if (cmd->negate_match)
		cmd->result = mismatches;
	else
		cmd->result = !mismatches;

	/* return -1 to stop if we got what we want or run out of retries */
	return (cmd->result ||
		(cmd->poll_cnt == 0)) ? -1 : 0;
}

static int
poll_for_matching_state_pb(zloop_t *loop, int poller, void *arg)
{
	struct dp_test_show_cmd_poll_state *cmd = arg;

	--(cmd->poll_cnt);

	zmsg_t *resp_msg;
	dp_test_console_request_pb(cmd->pb_req, cmd->pb_req_len,
				   &resp_msg,
				   cmd->print);

	char *resp;
	int resp_len = 0;
	if (resp_msg && zmsg_size(resp_msg) > 0) {
		zframe_t *frame = zmsg_first(resp_msg);
		resp = (char *)zframe_data(frame);
		resp_len = zframe_size(frame);
	}

	if (resp_len > 0)
		cmd->result = cmd->pb_func(resp, resp_len, cmd->pb_arg);

	zmsg_destroy(&resp_msg);

	/* return -1 to stop if we got what we want or run out of retries */
	return (cmd->result ||
		(cmd->poll_cnt == 0)) ? -1 : 0;
}

static bool
dp_test_wait_for_expected_json(struct dp_test_show_cmd_poll_state *cmd,
			       json_object **actual_resp,
			       unsigned int poll_interval)
{
	zloop_t *loop = zloop_new();
	int timer;

	assert(loop);

	/*
	 * loop every millisec, for up to dp_test_wait_sec.
	 */
	timer = zloop_timer(loop, poll_interval, 0,
			    poll_for_matching_state, cmd);
	dp_test_assert_internal(timer >= 0);

	zloop_start(loop);
	zloop_destroy(&loop);

	dp_test_wait_sec = DP_TEST_WAIT_SEC_DEFAULT;

	if (actual_resp)
		*actual_resp = cmd->json_resp;

	return cmd->result;
}

static bool
dp_test_wait_for_expected_pb(struct dp_test_show_cmd_poll_state *cmd)
{
	zloop_t *loop = zloop_new();
	int timer;

	assert(loop);

	/*
	 * loop every millisec, for up to dp_test_wait_sec.
	 */
	timer = zloop_timer(loop, dp_test_wait_sec, 0,
			    poll_for_matching_state_pb, cmd);
	dp_test_assert_internal(timer >= 0);

	zloop_start(loop);
	zloop_destroy(&loop);

	dp_test_wait_sec = DP_TEST_WAIT_SEC_DEFAULT;

	return cmd->result;
}

static void
_dp_test_check_json_poll_state_internal(const char *cmd_str,
					json_object *expected_json,
					json_object *filter_json,
					enum dp_test_check_json_mode mode,
					bool negate_match, int poll_cnt,
					unsigned int poll_interval,
					const char *file,
					const char *func __unused,
					int line)
{
	if (!poll_cnt)
		poll_cnt = DP_TEST_POLL_COUNT;
	struct dp_test_show_cmd_poll_state cmd = {
		.print = false,
		.json_resp = NULL,
		.required_superset = NULL,
		.required_subset = NULL,
		.required_exact = NULL,
		.negate_match = negate_match,
		.poll_cnt = poll_cnt,
		.mismatches = NULL,
		.result = false,
		.filter = filter_json,
	};

	json_object *actual_json;
	bool result;

	strncpy(cmd.request_str, cmd_str, sizeof(cmd.request_str));
	cmd.request_str[sizeof(cmd.request_str) - 1] = '\0';

	switch (mode) {
	case DP_TEST_JSON_CHECK_SUBSET:
		cmd.required_subset = expected_json;
		break;
	case DP_TEST_JSON_CHECK_EXACT:
		cmd.required_exact = expected_json;
		break;
	case DP_TEST_JSON_CHECK_SUPERSET:
		cmd.required_superset = expected_json;
		break;
	}

	result = dp_test_wait_for_expected_json(&cmd, &actual_json,
						poll_interval);
	if (cmd.mismatches)
		dp_test_json_mismatch_print(cmd.mismatches, 2, mismatch_str,
					    sizeof(mismatch_str));
	if (cmd.negate_match)
		_dp_test_fail_unless(result,
				     file, line,
				     "\n'show %s'- "
				     "\ndid not expect to find:\n  '%s'"
				     "\ngot:\n  '%s'",
				     cmd.request_str,
				     json_object_to_json_string(expected_json),
				     actual_json ?
				     json_object_to_json_string(actual_json) :
				     "<nothing>");
	else
		_dp_test_fail_unless(result,
				     file, line,
				     "\n'show %s'- "
				     "\nmismatches:\n'%s'"
				     "\nexpected (at least):\n  '%s'"
				     "\ngot:\n  '%s'",
				     cmd.request_str,
				     mismatch_str,
				     json_object_to_json_string(expected_json),
				     actual_json ?
				     json_object_to_json_string(actual_json) :
				     "<nothing>");

	dp_test_json_mismatch_free(cmd.mismatches);
	json_object_put(actual_json);
}

void
_dp_test_check_json_poll_state(const char *cmd_str, json_object *expected_json,
			       json_object *filter_json,
			       enum dp_test_check_json_mode mode,
			       bool negate_match, int poll_cnt,
			       const char *file, const char *func,
			       int line)
{
	_dp_test_check_json_poll_state_internal(cmd_str, expected_json,
						filter_json, mode, negate_match,
						poll_cnt, DP_TEST_POLL_INTERVAL,
						file, func, line);
}

void
_dp_test_check_json_poll_state_interval(const char *cmd_str,
					json_object *expected_json,
					json_object *filter_json,
					enum dp_test_check_json_mode mode,
					bool negate_match, int poll_cnt,
					unsigned int poll_interval,
					const char *file, const char *func,
					int line)
{
	_dp_test_check_json_poll_state_internal(cmd_str, expected_json,
						filter_json, mode, negate_match,
						poll_cnt, poll_interval,
						file, func, line);
}

void
_dp_test_check_pb_poll_state(void *cmd, int len,
			     dp_test_state_pb_cb cb,
			     void *arg,
			     int poll_cnt,
			     const char *file, const char *func __unused,
			     int line)
{
	if (!poll_cnt)
		poll_cnt = DP_TEST_POLL_COUNT;
	struct dp_test_show_cmd_poll_state show_cmd = {
		.pb_req = cmd,
		.pb_req_len = len,
		.pb_func = cb,
		.pb_arg = arg,
		.print = false,
		.json_resp = NULL,
		.required_superset = NULL,
		.required_subset = NULL,
		.required_exact = NULL,
		.poll_cnt = poll_cnt,
		.mismatches = NULL,
		.result = false,
	};

	bool result = dp_test_wait_for_expected_pb(&show_cmd);
	if (!result) {
		printf("failed to get response\n");
		abort();
	}
}

void
_dp_test_check_json_state(const char *cmd_str, json_object *expected_json,
			  json_object *filter_json,
			  enum dp_test_check_json_mode mode,
			  bool negate_match,
			  const char *file, const char *func __unused,
			  int line)
{
	_dp_test_check_json_poll_state(cmd_str, expected_json, filter_json,
				       mode, negate_match, DP_TEST_POLL_COUNT,
				       file, func, line);
}

void
_dp_test_check_pb_state(void *buf, int len,
			dp_test_state_pb_cb cb,
			void *arg,
			const char *file, const char *func __unused,
			int line)
{
	_dp_test_check_pb_poll_state(buf, len,
				     cb, arg,
				     DP_TEST_POLL_COUNT,
				     file, func, line);
}

/*
 * Construct a route show json object without any nexthop information.
 * Nexthop info can be added via dp_test_json_route_add_nh()
 */
json_object *
dp_test_json_route_add(json_object *route_set,
		       const struct dp_test_route *route, bool lookup)
{
	const char *route_lookup_str;
	const char *route_show_str;
	char temp_str[DP_TEST_TMP_BUF];
	json_object *routes;
	json_object *json_route;

	if (route->prefix.addr.family == AF_MPLS) {
		json_object *mpls_tables_json;
		json_object *mpls_table_json;

		json_route = dp_test_json_create(
			"{ "
			"\"address\": %u, "
			"\"next_hop\": "
			"  [ "
			"  ], "
			"} ",
			mpls_ls_get_label(route->prefix.addr.addr.mpls));
		if (!json_object_object_get_ex(route_set, "mpls_tables",
					       &mpls_tables_json))
			dp_test_assert_internal(0);

		mpls_table_json = json_object_array_get_idx(
			mpls_tables_json, 0);
		if (!json_object_object_get_ex(mpls_table_json,
					       "mpls_routes", &routes))
			dp_test_assert_internal(0);
	} else {
		if (route->prefix.addr.family == AF_INET) {
			route_lookup_str = "route_lookup";
			route_show_str = "route_show";
		} else {
			route_lookup_str = "route6_lookup";
			route_show_str = "route6_show";
		}

		if (lookup) {
			json_route = dp_test_json_create(
				"    {"
				"       \"address\": \"%s\","
				"       \"next_hop\": "
				"       [ "
				"       ] "
				"    } ",
				dp_test_addr_to_str(
					&route->prefix.addr,
					temp_str,
					sizeof(temp_str)));
			/*
			 * Now add it to the set of routes
			 */
			if (!json_object_object_get_ex(route_set,
						       route_lookup_str,
						       &routes))
				dp_test_assert_internal(0);
		} else {
			json_route = dp_test_json_create(
				"    {"
				"       \"prefix\": \"%s/%d\","
				"       \"scope\": %d,"
				"       \"next_hop\": "
				"       [ "
				"       ] "
				"    } ",
				dp_test_addr_to_str(
					&route->prefix.addr,
					temp_str,
					sizeof(temp_str)),
				route->prefix.len,
				route->scope);
			if (!json_object_object_get_ex(route_set,
						       route_show_str,
						       &routes))
				dp_test_assert_internal(0);
		}
	}

	if (json_object_array_add(routes, json_route) != 0)
		dp_test_assert_internal(0);
	return json_route;
}

json_object *
dp_test_json_route_set_create(bool lookup, int family)
{
	const char *route_af_str;
	json_object *route_set;

	if (family == AF_MPLS) {
		route_set = dp_test_json_create("{ "
						"  \"mpls_tables\":"
						"  ["
						"    { "
						"      \"lblspc\": 0, "
						"      \"mpls_routes\": [] "
						"    } "
						"  ]"
						"}");
		return route_set;
	}

	if (family == AF_INET)
		route_af_str = "route";
	else
		route_af_str = "route6";

	if (lookup)
		route_set = dp_test_json_create(
						"{ \"%s_lookup\": "
						"  [ "
						"  ] "
						"}",
						route_af_str);
	else
		route_set = dp_test_json_create(
						"{ \"%s_show\": "
						"  [ "
						"  ] "
						"}",
						route_af_str);
	return route_set;
};

/*
 * Add a nexthop object to an existing route show's next_hop list.
 */
void
dp_test_json_route_add_nh(json_object *route_show, int route_family,
			  struct dp_test_nh *nh)
{
	json_object *nh_obj;
	char json_str[DP_TEST_TMP_BUF];
	char temp_str[DP_TEST_TMP_BUF];
	int written = 0;
	const char *state_str;
	json_object *nh_list;
	char real_ifname[IFNAMSIZ];
	char *nh_int_orig = nh->nh_int;
	bool free_nh_int_orig = false;
	int i;

	/*
	 * Loopback interface isn't counted as a slowpath interface
	 * when used to transition between IPv4/IPv6 and MPLS label
	 * path, and in the MPLS label forwarding code (where it means
	 * do a pop and lookup the resulting packet).
	 */
	if (nh->nh_int &&
	    (dp_test_intf_type(nh->nh_int) == DP_TEST_INTF_TYPE_NON_DP ||
	    ((nh->num_labels == 0 || route_family == AF_MPLS) &&
		    dp_test_intf_type(nh->nh_int) == DP_TEST_INTF_TYPE_LO))) {
		free_nh_int_orig = true;
		nh->nh_int = NULL;
	}

	if (nh->nh_int)
		dp_test_intf_real(nh->nh_int, real_ifname);
	else
		real_ifname[0] = '\0';

	written = 0;
	if (nh->nh_int) {
		const char *backup_str;
		const char *neigh;

		if (nh->neigh_created)
			neigh = "              \"neigh_created\": true, ";
		else if (nh->neigh_present)
			neigh = "              \"neigh_present\": true, ";
		else
			neigh = "";

		if (nh->backup)
			backup_str = "              \"backup\": true, ";
		else
			backup_str = "";

		if (nh->nh_addr.family == AF_UNSPEC)
			state_str = "directly connected";
		else
			state_str = "gateway";
		written += spush(json_str + written, sizeof(json_str) - written,
				 "          {"
				 "              \"state\": \"%s\", "
				 "%s"
				 "%s"
				 "              \"ifname\": \"%s\", ",
				 state_str,
				 neigh,
				 backup_str,
				 real_ifname);
	} else {
		if (route_family == AF_MPLS &&
		    dp_test_intf_type(nh_int_orig) == DP_TEST_INTF_TYPE_LO)
			state_str = "gateway";
		else
			state_str = "non-dataplane interface";
		written += spush(json_str + written, sizeof(json_str) - written,
				 "          {"
				 "              \"state\": \"%s\", ",
				 state_str);
	}

	if (free_nh_int_orig)
		free(nh_int_orig);

	if (nh->nh_int && nh->nh_addr.family != AF_UNSPEC)
		written += spush(json_str + written,
				 sizeof(json_str) - written,
				 "              \"via\": \"%s\", ",
				 dp_test_addr_to_str(&nh->nh_addr, temp_str,
						     sizeof(temp_str)));

	if (nh->num_labels) {
		written += spush(json_str + written, sizeof(json_str)
				 - written,
				 "          \"labels\": [");
		for (i = 0; i < nh->num_labels; i++)
			written += spush(json_str + written,
					 sizeof(json_str) - written,
					 " %d,", nh->labels[i]);
		written += spush(json_str + written, sizeof(json_str)
				 - written,
				 "                  ],");
	}
	written += spush(json_str + written, sizeof(json_str) - written,
			 "          } ");

	nh_obj = dp_test_json_create("%s", json_str);

	/* add to the route show object */
	if (!json_object_object_get_ex(route_show, "next_hop", &nh_list))
		assert(0);

	if (json_object_array_add(nh_list, nh_obj) != 0)
		assert(0);
}

/* Take an ip_nh address and intf, do a neighbour lookup, and return
 * neighbour as a string
 *
 * Example JSON response
 * /opt/vyatta/bin/vplsh -l -c nd6 dp0s4
 * {"nd6":[{"ip":"10:0:101::1","flags":"VALID","state":"REACHABLE",
 *          "mac":"52:54:0:40:fb:2d","ifname":"dp0s4"},
 *         {"ip":"fe80::5054:ff:fe40:fb2d","flags":"VALID","state":"REACHABLE",
 *          "mac":"52:54:0:40:fb:2d","ifname":"dp0s4"}]}
 *
 * /opt/vyatta/bin/vplsh -l -c arp dp0s4
 * {"arp":[{"ip":"10.0.101.1","flags":"VALID","mac":"52:54:0:40:fb:2d",
 *          "ifname":"dp0s4"}]}
 *
 */
void
_dp_test_lookup_neigh(const struct dp_test_addr *ip_nh, const char *ifname,
		      char *mac_str, size_t mac_str_sz,
		      const char *file, const char *func, int line)
{
	char cmd[DP_TEST_TMP_BUF_SMALL];
	char ip_nh_str[DP_TEST_TMP_BUF_SMALL];
	json_object *j_resp;
	const char *neigh_cmd, *neigh_field;
	char *nh_key;
	char *response;
	bool err;

	dp_test_addr_to_str(ip_nh, ip_nh_str, sizeof(ip_nh_str));
	nh_key = ip_nh_str;

	/* Get neigh object */
	switch (ip_nh->family) {
	case AF_INET:
		neigh_cmd = "arp show";
		neigh_field = "arp";
		break;
	case AF_INET6:
		neigh_cmd = "nd6 show";
		neigh_field = "nd6";
		break;
	default:
		dp_test_assert_internal(false);
		break;
	}
	snprintf(cmd, sizeof(cmd), "%s %s", neigh_cmd, ifname);
	response = dp_test_console_request_w_err(cmd, &err, false);
	_dp_test_fail_unless(err == 0, file, line, "Error %i\n", err);
	_dp_test_fail_unless(response != NULL, file, line,
			     "Missing response\n");
	j_resp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);
	_dp_test_fail_unless(j_resp != NULL, file, line, "Missing j_resp\n");

	/* Get mac object */
	json_object *j_mac;
	const char *found_mac_str;
	struct dp_test_json_find_key neigh_key[] = {
		{ neigh_field, NULL },
		{ "ip", nh_key },
		{ "mac", NULL },
	};

	j_mac = dp_test_json_find(j_resp, neigh_key, ARRAY_SIZE(neigh_key));
	_dp_test_fail_unless(j_mac, file, line, "Can't find json mac obj\n");

	found_mac_str = json_object_to_json_string_ext(j_mac,
						       JSON_C_TO_STRING_PLAIN);
	strncpy(mac_str, found_mac_str, mac_str_sz);
	dp_test_str_trim(mac_str, 1, 1); /* remove extra quotes */

	json_object_put(j_mac);
	json_object_put(j_resp);
}

/*
 * Take an ip_dst address, do a route lookup and find and return the ip_nh.
 * TODO: PBR table number.
 */
void
_dp_test_lookup_nh(const struct dp_test_addr *ip_dst, uint32_t vrf_id,
		   char *ip_nh, size_t ip_nh_sz,
		   const char *file, const char *func, int line)
{
	char cmd[DP_TEST_TMP_BUF_SMALL];
	char ip_dst_str[DP_TEST_TMP_BUF_SMALL];
	json_object *j_resp;
	const char *route_cmd, *route_lookup_key;
	char *response;
	bool err;

	/* Get route object */
	switch (ip_dst->family) {
	case AF_INET:
		route_cmd = "route";
		route_lookup_key = "route_lookup";
		break;
	case AF_INET6:
		route_cmd = "route6";
		route_lookup_key = "route6_lookup";
		break;
	default:
		dp_test_assert_internal(false);
		break;
	}
	dp_test_addr_to_str(ip_dst, ip_dst_str, sizeof(ip_dst_str));
	snprintf(cmd, sizeof(cmd), "%s vrf_id %u table 254 lookup %s",
		 route_cmd, vrf_id, ip_dst_str);
	response = dp_test_console_request_w_err(cmd, &err, false);
	_dp_test_fail_unless(err == 0, file, line, "Error %i\n", err);
	_dp_test_fail_unless(response != NULL, file, line,
			     "Missing response\n");
	j_resp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);
	_dp_test_fail_unless(j_resp != NULL, file, line, "Missing j_resp\n");

	/* Get next_hop object */
	json_object *j_next_hop, *j_state, *j_via;
	struct dp_test_json_find_key next_hop_key[] = {
		{ route_lookup_key, NULL },
		{ "next_hop", NULL },
	};

	j_next_hop = dp_test_json_find(j_resp, next_hop_key,
				       ARRAY_SIZE(next_hop_key));
	_dp_test_fail_unless(j_next_hop, file, line,
			     "Can't find json nh obj\n");

	/* Find next hop state */
	const char *state_str;
	struct dp_test_json_find_key state_key[] = {
		{"state", NULL},
	};
	j_state = dp_test_json_find(j_next_hop, state_key,
				    ARRAY_SIZE(state_key));
	_dp_test_fail_unless(j_next_hop, file, line,
			     "Can't find json state obj\n");
	state_str = json_object_to_json_string_ext(j_state, 0);
	_dp_test_fail_unless(state_str, file, line,
			     "Can't find json state str\n");
	if (strcmp(state_str, "\"directly connected\"") == 0 ||
	    strcmp(state_str, "\"local\"") == 0) {
		/* Destination is next hop */
		strncpy(ip_nh, ip_dst_str, ip_nh_sz);
		goto out;
	}

	/* Gateway is next hop */
	_dp_test_fail_unless(strcmp(state_str, "\"gateway\"") == 0,
			     file, line,
			     "Unexpected state_str %s\n", state_str);

	struct dp_test_json_find_key via_key[] = {
		{"via", NULL},
	};
	const char *nh_str;

	j_via = dp_test_json_find(j_next_hop, via_key, ARRAY_SIZE(via_key));
	_dp_test_fail_unless(j_via, file, line, "Can't find json via obj\n");
	nh_str = json_object_to_json_string_ext(j_via, JSON_C_TO_STRING_PLAIN);
	_dp_test_fail_unless(nh_str, file, line, "Can't find json via str\n");
	strncpy(ip_nh, nh_str, ip_nh_sz);
	dp_test_str_trim(ip_nh, 1, 1); /* remove extra quotes */

	json_object_put(j_via);

out:
	json_object_put(j_next_hop);
	json_object_put(j_state);
	json_object_put(j_resp);
}

 /*
  * lookup: Use 'route lookup <addr>' cmd. dataplane does LPM -> rt_show
  *         else use 'route show' cmd. dataplane does walk -> rt_display
  */
static void
dp_test_wait_for_route_internal(const char *route_string, bool match_nh,
				bool gone, bool lookup, bool all,
				const char *file, const char *func, int line)

{
	struct dp_test_route *route = dp_test_parse_route(route_string);
	json_object *expected_json; /* json representation of all the routes */
	json_object *route_json;    /* json representation of a route */
	char oper_state_req[DP_TEST_TMP_BUF];
	char route_addr[DP_TEST_MAX_PREFIX_STRING_LEN];
	char cmd[20];
	const char *show_all = "";

	if (all)
		show_all = "all";

	/* no separate local table in dataplane */
	if (route->tableid == RT_TABLE_LOCAL)
		route->tableid = RT_TABLE_MAIN;

	dp_test_addr_to_str(&route->prefix.addr, route_addr,
			    sizeof(route_addr));

	if (route->prefix.addr.family == AF_MPLS) {
		snprintf(oper_state_req, sizeof(oper_state_req),
			 "mpls show tables");
	} else {
		if (route->prefix.addr.family == AF_INET) {
			if (route->vrf_id == VRF_DEFAULT_ID) {
				snprintf(cmd, sizeof(cmd), "route %s",
					 show_all);
			} else {
				vrfid_t vrf_id =
					dp_test_translate_vrf_id(route->vrf_id);
				snprintf(cmd, sizeof(cmd), "route vrf_id %d %s",
					 vrf_id, show_all);
			}
		} else {
			if (route->vrf_id == VRF_DEFAULT_ID) {
			  snprintf(cmd, sizeof(cmd), "route6 %s",
				   show_all);
			} else {
				vrfid_t vrf_id =
					dp_test_translate_vrf_id(route->vrf_id);
				snprintf(cmd, sizeof(cmd), "route6 vrf_id %d %s",
					 vrf_id, show_all);
			}
		}

		/*
		 * issue a route lookup/show and wait for json back
		 * which contains the route_lookup object for the
		 * relevant prefix (i.e. has the partial route_lookup
		 * as a subset).
		 */
		if (lookup)
			snprintf(oper_state_req, sizeof(oper_state_req),
				 "%s table %u lookup %s", cmd, route->tableid,
				 route_addr);
		else
			snprintf(oper_state_req, sizeof(oper_state_req),
				 "%s table %u show", cmd, route->tableid);
	}

	expected_json = dp_test_json_route_set_create(
		lookup, route->prefix.addr.family);
	route_json =
		dp_test_json_route_add(expected_json, route, lookup);
	if (match_nh) {
		unsigned int i;

		if (route->type == RTN_BLACKHOLE ||
		    route->type == RTN_UNREACHABLE) {
			json_object *nh_obj;
			json_object *nh_list;

			nh_obj = dp_test_json_create(
				"{"
				"  \"state\": \"%s\", "
				"}",
				route->type == RTN_BLACKHOLE ? "blackhole" :
				"unreachable");

			/* add to the route show object */
			if (!json_object_object_get_ex(route_json, "next_hop",
						       &nh_list))
				assert(0);

			if (json_object_array_add(nh_list, nh_obj) != 0)
				assert(0);
		} else {
			for (i = 0; i < route->nh_cnt; i++) {
				dp_test_json_route_add_nh(
					route_json,
					route->prefix.addr.family,
					&route->nh[i]);
			}
		}
	}

	_dp_test_check_json_state(oper_state_req, expected_json,
				  NULL, DP_TEST_JSON_CHECK_SUBSET,
				  gone, file, func, line);
	json_object_put(expected_json);
	dp_test_free_route(route);
}

/*
 * Look for route using "route show"
 */
void
_dp_test_wait_for_route(const char *route_string, bool match_nh, bool all,
			const char *file, const char *func, int line)
{
	/* route_show walk route table */
	dp_test_wait_for_route_internal(route_string, match_nh, false,
					false, all, file, func, line);
}

void
dp_test_wait_for_route_gone(const char *route_string, bool match_nh,
			    const char *file, const char *func, int line)
{
	/* route_show walk route table */
	dp_test_wait_for_route_internal(route_string, match_nh, true,
					false, false, file, func, line);
}

void
_dp_test_wait_for_route_lookup(const char *route_string, bool match_nh,
			       const char *file, const char *func, int line)
{
	/* route_show walk route table */
	dp_test_wait_for_route_internal(route_string, match_nh, false,
					true, false, file, func, line);
}

json_object *
dp_test_json_intf_set_create(void)
{
	return dp_test_json_create(
		"{ \"interfaces\": "
		"  [ "
		"  ] "
		"}");
}

static char *dp_test_exp_ipv4_val_feat(void)
{
	static char feat[100];

	feat[0] = '\0';

	return feat;
}

static const char *dp_test_exp_ipv4_out_feat(void)
{
	static char feat[100];

	feat[0] = '\0';

	return feat;
}

static const char *dp_test_exp_ipv6_val_feat(void)
{
	static char feat[100];

	feat[0] = '\0';

	return feat;
}

static const char *dp_test_exp_ipv6_out_feat(void)
{
	static char feat[100];

	feat[0] = '\0';

	return feat;
}

/*
 * Construct an interface show json object
 */
json_object *
dp_test_json_intf_add(json_object *intf_set, const char *ifname,
		      const char *addr_prefix, bool uplink)
{
	struct rte_ether_addr *mac_addr;
	char real_ifname[IFNAMSIZ];
	const char *link_str;
	json_object *intfs;
	char addr_str[256];
	json_object *intf;
	char port_str[32];
	char ebuf[32];

	dp_test_intf_real(ifname, real_ifname);
	mac_addr = dp_test_intf_name2mac(real_ifname);

	if (!json_object_object_get_ex(intf_set, "interfaces",
				       &intfs))
		dp_test_assert_internal(0);

	link_str =
	"  \"link\": "
	"  { "
	"    \"up\": true, "
	"    \"duplex\": \"full\", "
	"    \"speed\": 10000 "
	"  }, ";
	snprintf(port_str, sizeof(port_str), "  \"port\": %u, ",
			dp_test_intf_name2port(real_ifname));

	addr_str[0] = 0;
	if (addr_prefix) {
		struct dp_test_prefix prefix;
		char bcast_str[32];

		dp_test_prefix_str_to_prefix(addr_prefix,
					     &prefix);
		prefix.addr.addr.ipv4 = dp_test_ipv4_addr_to_bcast(
			prefix.addr.addr.ipv4,
			prefix.len);
		snprintf(addr_str, sizeof(addr_str),
			 "{ \"inet\": \"%s\", \"broadcast\": \"%s\" }",
			 addr_prefix,
			 dp_test_addr_to_str(&prefix.addr, bcast_str,
					     sizeof(bcast_str)));
	}

	uint32_t vrf_id = VRF_DEFAULT_ID;
	if (uplink)
		vrf_id = VRF_UPLINK_ID;
	unsigned int role = 1; /* See IF_ROLE */
	unsigned int ip_forwarding = 0;
	unsigned int ifindex = dp_test_intf_name2index(real_ifname);
	enum cont_src_en cont_src = dp_test_cont_src_get();

	ifindex = dp_test_cont_src_ifindex(ifindex);

	const char *ether_lookup_feats = "";
	const char *ea = ether_ntoa_r(mac_addr, ebuf);

	intf = dp_test_json_create(
		"{ "
		"  \"name\": \"%s\", "
		"  \"vrf_id\": %d, "
		"  \"dp_id\": %d, "
		"%s"
		"  \"ifindex\": %u, "
		"  \"cont_src\": %i, "
		"  \"role\": %u, "
		"  \"mtu\": 1500, "
		"  \"flags\": 69699, "
		"  \"hw_forwarding\": 0, "
		"  \"hw_l3\": 0, "
		"  \"tpid_offloaded\": 1, "
		"  \"ip_forwarding\": %u, "
		"  \"ip_proxy_arp\": 0, "
		"  \"ip_mc_forwarding\": 0, "
		"  \"ip_rp_filter\": 0, "
		"  \"ip6_forwarding\": 0, "
		"  \"ip6_mc_forwarding\": 0, "
		"  \"ether\": \"%s\", "
		"  \"perm_addr\": \"%s\", "
		"  \"ether_lookup_features\": [ %s ], "
		"  \"type\": \"ether\", "
		"%s"
		"  \"addresses\": [ %s ], "
		"  \"ipv4\":"
		"  {"
		"    \"forwarding\": %u,"
		"    \"proxy_arp\": 0,"
		"    \"garp_req_op\": \"Update\", "
		"    \"garp_rep_op\": \"Update\", "
		"    \"mc_forwarding\": 0,"
		"    \"redirects\": 1,"
		"    \"rp_filter\": 0,"
		"    \"validate_features\": ["
		"        %s%s%s%s%s],"
		"    \"out_features\": [ %s],"
		"  },"
		"  \"ipv6\":"
		"  {"
		"    \"forwarding\": 0,"
		"    \"mc_forwarding\": 0,"
		"    \"redirects\": 1,"
		"    \"validate_features\": ["
		"        %s%s\"vyatta:ipv6-in-no-address\","
		"        \"vyatta:ipv6-in-no-forwarding\"],"
		"    \"out_features\": [ %s],"
		"  },"
		"}",
		real_ifname,
		vrf_id,
		dp_test_intf2default_dpid(ifname),
		port_str,
		ifindex,
		cont_src,
		role, ip_forwarding,
		ea, ea,
		ether_lookup_feats,
		link_str,
		addr_str,
		ip_forwarding,
		dp_test_exp_ipv4_val_feat(),
		(strlen(dp_test_exp_ipv4_val_feat()) && !strlen(addr_str)) ?
			", " : "",
		strlen(addr_str) ? "" : "\"vyatta:ipv4-in-no-address\"",
		(strlen(dp_test_exp_ipv4_val_feat()) || !strlen(addr_str)) &&
		!ip_forwarding ? ", " : "",
		!ip_forwarding ? "\"vyatta:ipv4-in-no-forwarding\"" : "",
		dp_test_exp_ipv4_out_feat(),
		dp_test_exp_ipv6_val_feat(),
		strlen(dp_test_exp_ipv6_val_feat()) ? ", " : "",
		dp_test_exp_ipv6_out_feat());

	if (json_object_array_add(intfs, intf) != 0)
		dp_test_assert_internal(0);

	return intf;
}

json_object *
dp_test_json_intf_add_lo(json_object *intf_set, const char *ifname)
{
	json_object *intf, *intfs;
	enum cont_src_en cont_src = dp_test_cont_src_get();
	unsigned int ifindex = dp_test_intf_name2index(ifname);
	vrfid_t vrf_id;

	ifindex = dp_test_cont_src_ifindex(ifindex);
	switch (cont_src) {
	case CONT_SRC_MAIN:
		vrf_id = VRF_DEFAULT_ID;
		break;
	case CONT_SRC_UPLINK:
		vrf_id = VRF_UPLINK_ID;
		break;
	default:
		vrf_id = VRF_INVALID_ID;
		break;
	}

	if (!json_object_object_get_ex(intf_set, "interfaces",
				       &intfs))
		dp_test_assert_internal(0);

	intf = dp_test_json_create("{"
				   "  \"name\": \"%s\","
				   "  \"type\": \"loopback\","
				   "  \"vrf_id\": %d, "
				   "  \"dp_id\": %d, "
				   "  \"ifindex\": %u, "
				   "  \"cont_src\": %i, "
				   "  \"role\": 0, "
				   "  \"mtu\": 0, "
				   "  \"flags\": 73, "
				   "  \"hw_forwarding\": 0, "
				   "  \"hw_l3\": 0, "
				   "  \"tpid_offloaded\": 1, "
				   "  \"ip_forwarding\": 0, "
				   "  \"ip_proxy_arp\": 0, "
				   "  \"ip_mc_forwarding\": 0, "
				   "  \"ip_rp_filter\": 0, "
				   "  \"ip6_forwarding\": 0, "
				   "  \"ip6_mc_forwarding\": 0, "
				   "  \"ether\": \"0:0:0:0:0:0\", "
				   "  \"link\":"
				   "  {"
				   "    \"up\": true,"
				   "  },"
				   "  \"ether_lookup_features\": [ ],"
				   "  \"addresses\": [ ], "
				   "  \"ipv4\":"
				   "  {"
				   "    \"forwarding\": 0,"
				   "    \"proxy_arp\": 0,"
				   "    \"garp_req_op\": \"Update\", "
				   "    \"garp_rep_op\": \"Update\", "
				   "    \"mc_forwarding\": 0,"
				   "    \"redirects\": 1,"
				   "    \"rp_filter\": 0,"
				   "    \"validate_features\": ["
				   "        %s%s\"vyatta:ipv4-in-no-address\","
				   "        \"vyatta:ipv4-in-no-forwarding\"],"
				   "    \"out_features\": [ %s],"
				   "  },"
				   "  \"ipv6\":"
				   "  {"
				   "    \"forwarding\": 0,"
				   "    \"mc_forwarding\": 0,"
				   "    \"redirects\": 1,"
				   "    \"validate_features\": ["
				   "        %s%s\"vyatta:ipv6-in-no-address\","
				   "        \"vyatta:ipv6-in-no-forwarding\"],"
				   "    \"out_features\": [ %s],"
				   "  },"
				   "}",
				   ifname,
				   vrf_id,
				   dp_test_intf2default_dpid(ifname),
				   ifindex,
				   cont_src,
				   dp_test_exp_ipv4_val_feat(),
				strlen(dp_test_exp_ipv4_val_feat()) ? ", " : "",
				   dp_test_exp_ipv4_out_feat(),
				   dp_test_exp_ipv6_val_feat(),
				strlen(dp_test_exp_ipv6_val_feat()) ? ", " : "",
				   dp_test_exp_ipv6_out_feat());

	dp_test_assert_internal(intf);

	if (json_object_array_add(intfs, intf) != 0)
		dp_test_assert_internal(0);

	return intf;
}

void
dp_test_set_expected_ifconfig(json_object *intf_set)
{
	strncpy(expected_ifconfig_str, json_object_to_json_string(intf_set),
		sizeof(expected_ifconfig_str) - 1);
	expected_ifconfig_str[sizeof(expected_ifconfig_str) - 1] = 0;
}

void
dp_test_set_expected_route(json_object *route_set)
{
	strncpy(expected_route_str, json_object_to_json_string(route_set),
		sizeof(expected_route_str) - 1);
	expected_route_str[sizeof(expected_route_str) - 1] = 0;
}

void
dp_test_set_expected_npf_fw_portmap(void)
{
	const char *exp_str;

	exp_str = DP_TEST_EXP_NPF_FW_PORTMAP_VR_STR;
	strncpy(expected_npf_fw_portmap_str, exp_str,
		sizeof(expected_npf_fw_portmap_str) - 1);
	expected_npf_fw_portmap_str[sizeof(expected_npf_fw_portmap_str) - 1]
		= '\0';
}

void
dp_test_set_expected_vrf(void)
{
	const char *exp_str;

	exp_str = DP_TEST_EXP_VRF_VR_STR;
	strncpy(expected_vrf_str, exp_str,
		sizeof(expected_vrf_str) - 1);
	expected_vrf_str[sizeof(expected_vrf_str) - 1] = '\0';
}

void
dp_test_set_expected_route_stats(void)
{
	const char *exp_str;

	exp_str = DP_TEST_EXP_ROUTE_STATS_VR_STR;
	strncpy(expected_route_stats_str, exp_str,
		sizeof(expected_route_stats_str) - 1);
	expected_route_stats_str[sizeof(expected_route_stats_str) - 1] = '\0';
}

void
_dp_test_wait_for_vrf(uint32_t vrf_id,
		      unsigned int refcount,
		      const char *file, const char *func, int line)
{
	json_object *expected_json; /* json representation of all vrfs */
	char oper_state_req[DP_TEST_TMP_BUF];

	/*
	 * issue a show vrf and wait for json back.
	 *
	 * If expected refcount != 0 then expect an entry for the
	 * corresponding vrf id and verify that its refcount is as
	 * expected.
	 * Otherwise verify that there is no such VRF id in the table.
	 */
	snprintf(oper_state_req, sizeof(oper_state_req),
		 "vrf");

	vrf_id = dp_test_translate_vrf_id(vrf_id);

	if (refcount)
		expected_json =
			dp_test_json_create(
				"{ \"vrf_table\": [ { \"vrf_id\": %d, \"ref_count\": %u, }, ] }",
				vrf_id,
				refcount);
	else
		expected_json =
			dp_test_json_create(
				"{ \"vrf_table\": [ { \"vrf_id\": %d, }, ] }",
				vrf_id);

	_dp_test_check_json_state(oper_state_req, expected_json,
				  NULL,
				  DP_TEST_JSON_CHECK_SUBSET,
				  (refcount == 0), file, func, line);
	json_object_put(expected_json);
}

void
_dp_test_wait_for_local_addr(const char *addr_str, uint32_t vrf_id,
			     bool gone, const char *file, const char *func,
			     int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	char expected[TEST_MAX_REPLY_LEN];
	char *end = strchr(addr_str, '/');

	strncpy(expected, addr_str, end - addr_str);
	expected[end - addr_str] = '\0';

	if (vrf_id == VRF_DEFAULT_ID) {
		snprintf(cmd, TEST_MAX_CMD_LEN, "local");
	} else {
		vrf_id = dp_test_translate_vrf_id(vrf_id);
		snprintf(cmd, TEST_MAX_CMD_LEN, "local vrf_id %d",
			 vrf_id);
	}

	if (gone)
		_dp_test_check_state_gone_show(file, line,
					       cmd, expected, 0,
					       DP_TEST_CHECK_STR_SUBSET);
	else
		_dp_test_check_state_show(file, line, cmd, expected, 0,
					  DP_TEST_CHECK_STR_SUBSET);
}

void
_dp_test_wait_for_pl_feat(const char *intf, const char *feature, const
			  char *feature_point, bool gone,
			  const char *file, const char *func, int line)
{
	json_object *expected_json;
	char real_ifname[IFNAMSIZ];
	const char *field_name;
	const char *af_str;

	dp_test_intf_real(intf, real_ifname);

	if (!strcmp(feature_point, "ipv4-validate")) {
		af_str = "ipv4";
		field_name = "validate_features";
	} else if (!strcmp(feature_point, "ipv4-out")) {
		af_str = "ipv4";
		field_name = "out_features";
	} else if (!strcmp(feature_point, "ipv6-validate")) {
		af_str = "ipv6";
		field_name = "validate_features";
	} else if (!strcmp(feature_point, "ipv6-out")) {
		af_str = "ipv6";
		field_name = "out_features";
	} else {
		af_str = "";
		field_name = "";
		_dp_test_fail(file, line, "unknown feature point: %s",
			      feature_point);
	}

	expected_json = dp_test_json_create(
		"{"
		"  \"interfaces\":"
		"  ["
		"    { "
		"      \"name\": \"%s\", "
		"      \"%s\":"
		"      {"
		"        \"%s\":"
		"        ["
		"          %s%s%s"
		"        ]"
		"      },"
		"    }"
		"  ]"
		"}",
		real_ifname, af_str, field_name,
		gone ? "" : "\"",
		gone ? "" : feature,
		gone ?  "" : "\",");
	_dp_test_check_json_state("ifconfig", expected_json,
				  NULL, DP_TEST_JSON_CHECK_SUBSET,
				  false, file, func, line);
	json_object_put(expected_json);
}

void _dp_test_verify_neigh_present_count(int count, int af, const char *file,
					 const char *func, int line)
{
	char cmd[100];
	char expected[100];

	if (af == AF_INET) {
		snprintf(cmd, sizeof(cmd), "route summary");
	} else {
		snprintf(cmd, sizeof(cmd), "route6 summary");
	}
	snprintf(expected, sizeof(expected), "\"neigh_present\":%d", count);

	_dp_test_check_state_show(file, line, cmd, expected, false,
				  DP_TEST_CHECK_STR_SUBSET);
}

void _dp_test_verify_neigh_created_count(int count, int af, const char *file,
					 const char *func, int line)
{
	char cmd[100];
	char expected[100];


	if (af == AF_INET) {
		snprintf(cmd, sizeof(cmd), "route summary");
	} else {
		snprintf(cmd, sizeof(cmd), "route6 summary");
	}
	snprintf(expected, sizeof(expected), "\"neigh_created\":%d", count);

	_dp_test_check_state_show(file, line, cmd, expected, false,
				  DP_TEST_CHECK_STR_SUBSET);
}


void _dp_test_verify_route_no_neigh_present(const char *route,
					    const char *file,
					    const char *func, int line)
{
	char cmd[100];
	char expected[100];
	struct dp_test_addr addr;

	dp_test_addr_str_to_addr(route, &addr);

	if (addr.family == AF_INET)
		snprintf(cmd, sizeof(cmd), "route lookup %s", route);
	if (addr.family == AF_INET6)
		snprintf(cmd, sizeof(cmd), "route6 lookup %s", route);

	snprintf(expected, sizeof(expected), "\"neigh_present\":true");

	_dp_test_check_state_gone_show(file, line, cmd, expected, false,
				       DP_TEST_CHECK_STR_SUBSET);
}

void _dp_test_verify_route_neigh_present(const char *route,
					 const char *interface,
					 bool set,
					 const char *file,
					 const char *func, int line)
{
	char cmd[100];
	char expected[100];
	char real_ifname[IFNAMSIZ];
	struct dp_test_addr addr;

	dp_test_addr_str_to_addr(route, &addr);
	dp_test_intf_real(interface, real_ifname);
	if (addr.family == AF_INET)
		snprintf(cmd, sizeof(cmd), "route lookup %s", route);
	if (addr.family == AF_INET6)
		snprintf(cmd, sizeof(cmd), "route6 lookup %s", route);
	snprintf(expected, sizeof(expected),
		 "\"neigh_present\":true,\"ifname\":\"%s\"", real_ifname);

	if (set)
		_dp_test_check_state_show(file, line, cmd, expected, false,
					  DP_TEST_CHECK_STR_SUBSET);
	else
		_dp_test_check_state_gone_show(file, line, cmd, expected, false,
					       DP_TEST_CHECK_STR_SUBSET);
}

void _dp_test_verify_route_no_neigh_created(const char *route,
					    const char *file,
					    const char *func, int line)
{
	char cmd[100];
	char expected[100];
	struct dp_test_addr addr;

	dp_test_addr_str_to_addr(route, &addr);
	if (addr.family == AF_INET)
		snprintf(cmd, sizeof(cmd), "route lookup %s", route);
	if (addr.family == AF_INET6)
		snprintf(cmd, sizeof(cmd), "route6 lookup %s", route);

	snprintf(expected, sizeof(expected), "\"neigh_created\":true");

	_dp_test_check_state_gone_show(file, line, cmd, expected, false,
				       DP_TEST_CHECK_STR_SUBSET);
}

void _dp_test_verify_route_neigh_created(const char *route,
					 const char *interface,
					 bool set,
					 const char *file,
					 const char *func, int line)
{
	char cmd[100];
	char expected[100];
	char real_ifname[IFNAMSIZ];
	struct dp_test_addr addr;

	dp_test_addr_str_to_addr(route, &addr);
	dp_test_intf_real(interface, real_ifname);

	if (addr.family == AF_INET)
		snprintf(cmd, sizeof(cmd), "route lookup %s", route);
	if (addr.family == AF_INET6)
		snprintf(cmd, sizeof(cmd), "route6 lookup %s", route);

	snprintf(expected, sizeof(expected),
		 "\"neigh_created\":true,\"ifname\":\"%s\"", real_ifname);

	if (set)
		_dp_test_check_state_show(file, line, cmd, expected, false,
					  DP_TEST_CHECK_STR_SUBSET);
	else
		_dp_test_check_state_gone_show(file, line, cmd, expected, false,
					       DP_TEST_CHECK_STR_SUBSET);
}

int _dp_test_get_nh_idx(const char *route, const char *file,
			 const char *func, int line)
{
	char cmd[100];
	struct dp_test_addr addr;
	json_object *jarray;
	json_object *jvalue;
	json_object *jresp;
	char *response;
	bool err;
	int nh_index;

	dp_test_addr_str_to_addr(route, &addr);

	if (addr.family == AF_INET)
		snprintf(cmd, sizeof(cmd), "route lookup %s", route);
	if (addr.family == AF_INET6)
		snprintf(cmd, sizeof(cmd), "route6 lookup %s", route);

	response = dp_test_console_request_w_err(cmd, &err, false);
	jresp = parse_json(response, NULL, 0);
	free(response);

	if (!jresp)
		goto fail;

	if (!json_object_object_get_ex(jresp, "route_lookup", &jarray))
		goto fail;

	if (json_object_get_type(jarray) != json_type_array)
		goto fail;

	jvalue = json_object_array_get_idx(jarray, 0);

	if (!dp_test_json_int_field_from_obj(jvalue, "nh_index", &nh_index))
		goto fail;

	json_object_put(jresp);
	return nh_index;
fail:
	json_object_put(jresp);
	return -1;
}

int _dp_test_get_vrf_stat(vrfid_t vrfid, int af, int stat,
			  const char *file, int line)
{
	char cmd[100];
	json_object *jobj;
	json_object *jresp;
	char *response;
	bool err;
	const char *obj_str;
	int val;

	vrfid = dp_test_translate_vrf_id(vrfid);

	snprintf(cmd, sizeof(cmd), "netstat vrf_id %d", vrfid);
	response = dp_test_console_request_w_err(cmd, &err, false);
	jresp = parse_json(response, NULL, 0);
	free(response);

	if (!jresp)
		goto fail;

	switch (af) {
	case AF_INET:
		obj_str = "ip";
		break;
	case AF_INET6:
		obj_str = "ip6";
		break;
	default:
		goto fail;
	}

	if (!json_object_object_get_ex(jresp, obj_str, &jobj))
		goto fail;

	if (!dp_test_json_int_field_from_obj(jobj, ipstat_mib_names[stat],
					     &val))
		goto fail;

	json_object_put(jresp);
	return val;
fail:
	json_object_put(jresp);
	_dp_test_fail(file, line, "Failed to get vrf counter af %d counter %d",
		      af, stat);
	return 0;
}
