/*
 * Copyright (c) 2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>

#include "dp_test.h"
#include "dp_test_lib.h"
#include "dp_test_cmd_check.h"
#include "dp_test_console.h"
#include "dp_test_lib_intf.h"
#include "dp_test_json_utils.h"

#define POLL_CNT	1

struct dp_test_command_t {
	const char *cmd;
	const char *exp_reply;
	bool exp_ok;
	bool exp_json;
};

/*
 * List of configuration commands and associated responses. Note that
 * the normal "cstore" interface (dp_test_send_config_src()) does not
 * provide any feedback (error returns), instead the tests use the
 * console interface with a different topic (mstp vs mstp-ut).
 */
static const struct dp_test_command_t mstp_cstore_cmds[] = {
{
	"mstp-ut sw0 config action update region name Reg1 revision 1",
	"",
	true,
	false
},
{
	"mstp-ut sw0 config action update msti 1",
	"",
	true,
	false
},
{
	"mstp-ut sw0 config action update msti 1 vlans 10:20:30",
	"",
	true,
	false
},

{
	"mstp-ut sw0 config action update state 3 port dpT10 msti 1",
	"",
	true,
	false
},
{
	"mstp-ut sw0 config action delete state 3 port dpT10 msti 1",
	"",
	true,
	false
},
{
	"mstp-ut sw0 config action delete msti 1",
	"",
	true,
	false
},
{
	"mstp-ut sw0 config action delete region name Reg1",
	"",
	true,
	false
},
{
	"mstp-ut sw0 foo",
	"cmd_mstp: missing arguments: 3",
	false,
	false
},
{
	"mstp-ut sw0 config act",
	"missing action keyword",
	false,
	false
},
{
	"mstp-ut sw0 config action foo",
	"unknown action",
	false,
	false
},
{
	"mstp-ut sw0 config action update",
	"missing configuration object",
	false,
	false
},
{
	"mstp-ut sw0 config action update region",
	"missing region parameters",
	false,
	false
},
{
	"mstp-ut sw0 config action update region Reg1",
	"MSTP missing region parameters: 2",
	false,
	false
},
{
	"mstp-ut sw0 config action update region name Reg1 revision",
	"missing region revision",
	false,
	false
},
{
	"mstp-ut sw0 config action update region name Reg1 revision foo",
	"invalid revision string",
	false,
	false
},
{
	"mstp-ut sw0 config action update region name Reg1 revision 65537",
	"invalid revision number",
	false,
	false
},
{
	"mstp-ut sw0 config action update msti bar",
	"invalid MSTI string",
	false,
	false
},
{
	"mstp-ut sw0 config action update msti 4096",
	"MSTP invalid MSTI number: 4096",
	false,
	false,
},
{
	"mstp-ut sw0 config action update msti 2 vlan-list",
	"unknown MSTI keyword",
	false,
	false
},
{
	"mstp-ut sw0 config action update msti 2 vlans",
	"STP missing list of VLAN-IDs",
	false,
	false
},
{
	"mstp-ut sw0 config update state 99 port dpT10 msti 2",
	"MSTP missing action keyword: 'update'",
	false,
	false
},
{
	"mstp-ut sw0 config update state blocking port dpT10 msti 2",
	"MSTP missing action keyword: 'update'",
	false,
	false
},
};

DP_DECL_TEST_SUITE(mstp_cmds);

DP_DECL_TEST_CASE(mstp_cmds, mstpcmds, NULL, NULL);

DP_START_TEST(mstpcmds, cfg_cmds)
{
	size_t i;

	dp_test_intf_bridge_create("sw0");
	dp_test_intf_bridge_add_port("sw0", "dp1T0");
	for (i = 0; i < ARRAY_SIZE(mstp_cstore_cmds); i++) {
		dp_test_check_state_poll_show(
			mstp_cstore_cmds[i].cmd,
			mstp_cstore_cmds[i].exp_reply,
			mstp_cstore_cmds[i].exp_ok, false, 1);

	}
	dp_test_intf_bridge_remove_port("sw0", "dp1T0");
	dp_test_intf_bridge_del("sw0");

} DP_END_TEST;

static const struct dp_test_command_t mstp_oper_cmds[] = {
{
	"mstp-ut sw0 config action update region name Reg1 revision 1",
	"",
	true,
	false
},
{
	"mstp-op sw0 show state",
	"{"
	"\"region\":{\"switch\":\"sw0\",\"name\":\"Reg1\",\"revision\":1,\"msti-count\":0},"
	"\"switch-ports\":[{\"port\":\"dpT10\",\"state\":\"FORWARDING\"}],"
	"\"msti-list\":[],"
	"\"vlan-list\":[]"
	"}",
	true,
	true
},
{
	"mstp-ut sw0 config action update msti 99 vlans 10:20:30",
	"",
	true,
	false
},
{
	"mstp-op sw0 clear macs port dpT10 msti 99",
	"",
	true,
	false
},
{
	"mstp-op sw0 show state",
	"{"
	"\"region\":{\"switch\":\"sw0\",\"name\":\"Reg1\",\"revision\":1,\"msti-count\":1},"
	"\"switch-ports\":[{\"port\":\"dpT10\",\"state\":\"FORWARDING\"}],"
	"\"msti-list\":[{\"mstid\":99,\"mstid-index\":1,\"vlans\":[10,20,30]}],"
	"\"vlan-list\":["
	"	{\"vlanid\":10,\"mstid\":99,"
	"        \"switch-ports\":[{\"port\":\"dpT10\",\"state\":\"DISABLED\"}]},"
	"       {\"vlanid\":20,\"mstid\":99,"
	"        \"switch-ports\":[{\"port\":\"dpT10\",\"state\":\"DISABLED\"}]},"
	"	{\"vlanid\":30,\"mstid\":99,"
	"        \"switch-ports\":[{\"port\":\"dpT10\",\"state\":\"DISABLED\"}]}"
	"	]"
	"}",
	true,
	true
},
{
	"mstp-op sw0 clear",
	"missing argument",
	false,
	false
},
{
	"mstp-op sw0 clear foo",
	"MSTP unknown clear command: foo",
	false,
	false
},
{
	"mstp-op sw0 clear macs mumble",
	"missing clear parameters",
	false,
	false
},
{
	"mstp-ut sw0 config action delete msti 99",
	"",
	true,
	false
},
{
	"mstp-ut sw0 config action delete region name Reg1",
	"",
	true,
	false
},
};

DP_START_TEST(mstpcmds, oper_cmds)
{
	size_t i;
	json_object *jexp;

	dp_test_intf_bridge_create("sw0");
	dp_test_intf_bridge_add_port("sw0", "dp1T0");
	for (i = 0; i < ARRAY_SIZE(mstp_oper_cmds); i++) {
		const struct dp_test_command_t *tst = &mstp_oper_cmds[i];

		if (tst->exp_json) {
			jexp = dp_test_json_create("%s", tst->exp_reply);
			dp_test_check_json_poll_state(tst->cmd, jexp,
						      DP_TEST_JSON_CHECK_SUBSET,
						      false,
						      POLL_CNT);
			json_object_put(jexp);
		} else
			dp_test_check_state_poll_show(tst->cmd,
						      tst->exp_reply,
						      tst->exp_ok,
						      false, POLL_CNT);
	}
	dp_test_intf_bridge_remove_port("sw0", "dp1T0");
	dp_test_intf_bridge_del("sw0");

} DP_END_TEST;
