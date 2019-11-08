/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Test dataplane bitmask_t functionality
 */

#include "dp_test_controller.h"
#include "dp_test_lib_cmd.h"
#include "dp_test_macros.h"

#include "bitmask.h"

DP_DECL_TEST_SUITE(bitmask);

DP_DECL_TEST_CASE(bitmask, basic_tests, NULL, NULL);
DP_START_TEST(basic_tests, basic_tests)
{
	bitmask_t a, b, c;

	bitmask_zero(&a);
	bitmask_zero(&b);
	bitmask_zero(&c);

	dp_test_fail_unless((bitmask_isempty(&a) == true),
						"bitmask a is not empty\n");
	dp_test_fail_unless((bitmask_numset(&a) == 0),
						"numset bitmask a is not 0\n");

	/* bitmask_t should always hold more than 64 bits so
	 * we test just a little bit past that point.
	 */

	for (unsigned int i = 0; i < 72; i++) {
		bitmask_set(&a, i);
		dp_test_fail_unless((bitmask_isset(&a, i) == true),
						"incremental set failed\n");
		dp_test_fail_unless((bitmask_numset(&a) == (i + 1)),
						"incremental set failed\n");
	}

	for (unsigned int i = 0; i < 72; i++) {
		bitmask_clear(&a, i);
		dp_test_fail_unless((bitmask_isset(&a, i) == false),
						"incremental clear failed\n");
		dp_test_fail_unless((bitmask_numset(&a) == (72 - (i + 1))),
						"incremental clear failed\n");
	}

	bitmask_zero(&a);
	bitmask_zero(&b);
	bitmask_zero(&c);

	for (unsigned int i = 0; i < 72; i++) {
		bitmask_set(&a, i);	/* single bit moving left */
		bitmask_set(&b, i);	/* slowly filling */
		bitmask_and(&c, &a, &b);

		dp_test_fail_unless((bitmask_numset(&c) == 1),
						"incremental 1&1 and failed\n");
		dp_test_fail_unless((bitmask_isset(&c, i) == true),
						"incremental 1&1 and failed\n");

		bitmask_clear(&a, i);
	}

	bitmask_zero(&a);
	for (unsigned int i = 0; i < 72; i++) {
		bitmask_set(&b, i);	/* slowly filling */
		bitmask_and(&c, &a, &b);

		dp_test_fail_unless((bitmask_isempty(&c) == true),
					"incremental 1&0 c is not empty\n");
		dp_test_fail_unless((bitmask_numset(&c) == 0),
						"incremental 1&0 and failed\n");
		dp_test_fail_unless((bitmask_isset(&c, i) == false),
						"incremental 1&0 and failed\n");
	}
} DP_END_TEST;

DP_DECL_TEST_CASE(bitmask, parsing, NULL, NULL);
DP_START_TEST(parsing, parsing)
{
	bitmask_t a;

	/* check 0-f */
	for (unsigned int i = 0; i < 16; i++) {
		char tmp[16];

		snprintf(tmp, sizeof(tmp), "%x", i);

		dp_test_fail_unless(bitmask_parse(&a, tmp) == 0,
					"parsing bitmask %s failed", tmp);

		for (unsigned int j = 0; j < 8; j++) {
			unsigned int bit = (1 << j);

			if (i & bit)
				dp_test_fail_unless(
					bitmask_isset(&a, j) == true,
					"parsing bitmask %s failed", tmp);
		}
	}

	dp_test_fail_unless((bitmask_parse(&a, "nothex") == -1),
					"failed to reject parsing invalid hex");

	dp_test_fail_unless((bitmask_parse(&a, "ffffffff"
					       "ffffffff" /* 64 */
					       "ffffffff"
					       "ffffffff" /* 128 */
					       "ffffffff"
					       "ffffffff" /* 192 */
					       "ffffffff"
					       "ffffffff" /* 256 */
					       "ffffffff") == -1),
				"failed to reject parsing too long bitmask");

	for (unsigned int i = 0; i < 64; i++) {
		char tmp[BITMASK_STRSZ];

		snprintf(tmp, sizeof(tmp), "%llx", 1ull << i);
		bitmask_parse(&a, tmp);
		dp_test_fail_unless((bitmask_isset(&a, i) == true),
				"bitmask_parse failed for 1ul << %d", i);
	}

	bitmask_parse(&a, "10000000000000000");
	dp_test_fail_unless((bitmask_isset(&a, 64) == true),
			"bitmask_parse failed for 1ul << 64");

	bitmask_parse(&a, "20000000000000000");
	dp_test_fail_unless((bitmask_isset(&a, 65) == true),
			"bitmask_parse failed for 1ul << 65");

	bitmask_parse(&a, "40000000000000000");
	dp_test_fail_unless((bitmask_isset(&a, 66) == true),
			"bitmask_parse failed for 1ul << 66");

	bitmask_parse(&a, "80000000000000000");
	dp_test_fail_unless((bitmask_isset(&a, 67) == true),
			"bitmask_parse failed for 1ul << 67");

} DP_END_TEST;

DP_DECL_TEST_CASE(bitmask, printing, NULL, NULL);
DP_START_TEST(printing, printing)
{
	bitmask_t a;
	char tmp1[16], tmp2[BITMASK_STRSZ];

	for (unsigned int i = 0; i < 32; i++) {
		snprintf(tmp1, sizeof(tmp1), "%x", 1 << i);
		bitmask_zero(&a);
		bitmask_set(&a, i);
		bitmask_sprint(&a, tmp2, sizeof(tmp2));
		dp_test_fail_unless((strcmp(tmp1, tmp2) == 0),
				"bitmask_sprint failed %s != %s", tmp1, tmp2);
	}
} DP_END_TEST;
