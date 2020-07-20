/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT console commands
 */
#include "dp_test_lib_cmd.h"

#include "dp_test.h"
#include "dp_test_console.h"
#include "dp_test_lib_intf_internal.h"

/* reset connection to the main vplaned */
void
_dp_test_cmd_reset(const char *file, const char *func, int line)
{
	const char *cmd = "reset", *check_cmd = "main state";
	json_object *expected;
	static uint32_t ready_count = 1; /* No. times in ready state */

	expected = dp_test_json_create("{ \"main_state\":"
				       "  {"
				       "    \"vplaned\":"
				       "      { \"ready\": %u },"
				       "    \"vplaned-local\":"
				       "      { \"ready\": 1 }"
				       "   }"
				       "}",
				       ready_count);

	/* We expect the dataplane to be in READY state before reset */
	_dp_test_check_json_state(check_cmd, expected, NULL,
				  DP_TEST_JSON_CHECK_EXACT,
				  false,
				  file, func, line);
	json_object_put(expected);

	dp_test_console_request_reply(cmd, false);

	/* We expect the dataplane to come back to READY state after reset */
	ready_count++;
	/* Reset is expected to take some time.  On laptop it always completes
	 * in < 2s (even with 10 x UT running in parallel).  Be conservative for
	 * slow / busy hosts and set to 5.
	 */
	dp_test_wait_set(5);
	expected = dp_test_json_create("{ \"main_state\":"
				       "  {"
				       "    \"vplaned\":"
				       "      { \"ready\": %u },"
				       "    \"vplaned-local\":"
				       "      { \"ready\": 1 }"
				       "   }"
				       "}",
				       ready_count);
	_dp_test_check_json_state(check_cmd, expected, NULL,
				  DP_TEST_JSON_CHECK_EXACT,
				  false,
				  file, func, line);
	json_object_put(expected);

	/* Recreate the interfaces expected in 'clean' state. */
	dp_test_intf_create_default_set(NULL);
}
