/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include "util.h"

#include "dp_test.h"
#include "npf/bstr.h"

DP_DECL_TEST_SUITE(bstr);

/*
 * bstr1. Basic tests of an unmanaged string
 */
DP_DECL_TEST_CASE(bstr, bstr1, NULL, NULL);
DP_START_TEST(bstr1, test)
{
	const char *const_buf = "abcdef:123456";
	struct bstr b = BSTR_INIT;
	struct bstr head, tail;
	char buf[200];
	bool ok;
	int rv;

	/* bstr_attach_unmanaged */

	ok = bstr_attach_unmanaged(&b, buf, 0, sizeof(buf));
	dp_test_fail_unless(ok, "error bstr_attach_unmanaged");

	/* bstr_addstr */

	ok = bstr_addstr(&b, const_buf);
	dp_test_fail_unless(ok, "error bstr_addstr");

	/* bstr_avail */

	/* bstr_avail returns one less than actual, to allow for NULL char */
	uint tmp = sizeof(buf) - strlen(const_buf) - 1;
	dp_test_fail_unless(bstr_avail(&b) == (int)tmp,
			    "error bstr_avail expected %d got %u", bstr_avail(&b), tmp);

	/* bstr_addch */

	ok = bstr_addch(&b, '7');
	dp_test_fail_unless(ok, "error bstr_addch");

	/* Verify contents of b */

	const char *exp_str = "abcdef:1234567";
	int exp_len = strlen(exp_str);

	dp_test_fail_unless(b.len == exp_len, "error bstr_addch");
	rv = memcmp(b.buf, exp_str, exp_len);
	dp_test_fail_unless(rv == 0, "error");

	/* bstr_find_term */

	rv = bstr_find_term(&b, ':');
	dp_test_fail_unless(rv == 6, "error bstr_find_term");

	/* bstr_find_str */

	rv = bstr_find_str(&b, BSTRL("123"));
	dp_test_fail_unless(rv == 7, "error bstr_find_str");

	/* bstr_split_term */

	ok = bstr_split_term(&b, ':', &head, &tail);
	dp_test_fail_unless(ok, "error bstr_split_term");

	ok = bstr_eq(&head, BSTRL("abcdef:"));
	dp_test_fail_unless(ok, "error with head after split, "
			    "exp \"abcdef:\" got \"%*.*s\"",
			    head.len, head.len, head.buf);

	ok = bstr_eq(&tail, BSTRL("1234567"));
	dp_test_fail_unless(ok, "error with tail after split, "
			    "exp \"1234567:\" got \"%*.*s\"",
			    tail.len, tail.len, tail.buf);

} DP_END_TEST;
