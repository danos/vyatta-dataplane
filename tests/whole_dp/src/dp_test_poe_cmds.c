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

struct dp_test_command_t {
	const char *cmd;
	const char *exp_reply;
	bool exp_ok;
};

static const struct dp_test_command_t poe_cfg_cmds[] = {
	{
		"poe-ut enable dpT10",
		"",
		true,
	},
	{
		"poe-ut disable dpT10",
		"",
		true,
	},
	{
		"poe-ut enable dpT10 priority low",
		"",
		true,
	},
	{
		"poe-ut enable dpT10 priority high",
		"",
		true,
	},
	{
		"poe-ut enable dpT10 priority critical",
		"",
		true,
	},
	{
		"poe-ut enable foo",
		"failed to find",
		false,
	},
	{
		"poe-ut disable foo",
		"failed to find",
		false,
	},
	{
		"poe-ut enable",
		"usage",
		false,
	},
	{
		"poe-ut disable",
		"usage",
		false,
	},
	{
		"poe-ut enable dpT10 priority",
		"usage",
		false,
	},
};

DP_DECL_TEST_SUITE(poe_cmds);

DP_DECL_TEST_CASE(poe_cmds, poecmds, NULL, NULL);

DP_START_TEST(poecmds, cfg_cmds)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(poe_cfg_cmds); i++) {
		const struct dp_test_command_t *tst = &poe_cfg_cmds[i];

		dp_test_check_state_poll_show(tst->cmd,
					      tst->exp_reply,
					      tst->exp_ok,
					      false, 1);
	}
} DP_END_TEST;
