/*
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Tests that are supposed to fail to exercise UT infra and
 * other uts that are testing the infra itself.
 * Tests that cause failures are declared as DONT_RUN.
 * Any tests that do run are expected to pass.
 * Please investigate and fix any failures and fix any
 * compile errors in all tests.
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state.h"
#include "dp_test_lib.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_lib_intf.h"

DP_DECL_TEST_SUITE(failure_suite);

DP_DECL_TEST_CASE(failure_suite, internals, NULL, NULL);
DP_START_TEST(internals, string_overflow)
{
	unsigned int written = 0;
	char buffer_ut[20];

	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s%d", "fit", 1);
	ck_assert(written == 4);
	ck_assert(strcmp(buffer_ut,
			 "fit1") == 0);
	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s%d", "fit", 2);
	ck_assert(written == 8);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2") == 0);

	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s%d%s%d", "fit", 3, "fit", 4);
	ck_assert(written == 16);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2fit3fit4") == 0);

	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s", "fit");

	/* this looks odd - but spush should return 20 rather than 19
	 * because trailing '\0' takes up the last char so no point
	 * returning size-1 forever
	 */
	ck_assert(written == 20);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2fit3fit4fit") == 0);
	/*
	 * More stuff from here makes no difference
	 */
	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%d%s%d", 5, "fit", 6);
	ck_assert(written == 20);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2fit3fit4fit") == 0);
	/*
	 * Now reset to empty and try a huge string
	 */
	written = 0;
	written += spush(buffer_ut + written, sizeof(buffer_ut) - written,
			 "%s%d%s%d", "fit", 1,
			 "fit2fit3fit4fit5fit6fit7fit8fit9fit", 10);
	ck_assert(written == 20);
	ck_assert(strcmp(buffer_ut,
			 "fit1fit2fit3fit4fit") == 0);
} DP_END_TEST;
