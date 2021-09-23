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

/*
 * bstr2. Tests whitespace trimming with bstr_ltrim and bstr_rtrim
 */
DP_DECL_TEST_CASE(bstr, bstr2, NULL, NULL);
DP_START_TEST(bstr2, test)
{
	const char *const_buf = " \t abcdef:123456\t  ";
	struct bstr b = BSTR_INIT;
	int len = strlen(const_buf);
	char buf[200];
	bool ok;

	/* bstr_attach_unmanaged */

	ok = bstr_attach_unmanaged(&b, buf, 0, sizeof(buf));
	dp_test_fail_unless(ok, "error bstr_attach_unmanaged");

	/* bstr_addstr */

	ok = bstr_addstr(&b, const_buf);
	dp_test_fail_unless(ok, "error bstr_addstr");
	dp_test_fail_unless(b.len == len, "b len exp %d, got %d", len, b.len);

	/* bstr_ltrim */

	ok = bstr_ltrim(&b);
	dp_test_fail_unless(ok, "error bstr_ltrim");

	ok = bstr_eq(&b, BSTRL("abcdef:123456\t  "));
	dp_test_fail_unless(ok, "error with b after ltrim, "
			    "exp \"abcdef:123456\t  \" got \"%*.*s\"",
			    b.len, b.len, b.buf);

	len -= 3;
	dp_test_fail_unless(b.len == len, "b len exp %d, got %d", len, b.len);

	/* bstr_rtrim */

	ok = bstr_rtrim(&b);
	dp_test_fail_unless(ok, "error bstr_rtrim");

	ok = bstr_eq(&b, BSTRL("abcdef:123456"));
	dp_test_fail_unless(ok, "error with b after rtrim, "
			    "exp \"abcdef:123456\" got \"%*.*s\"",
			    b.len, b.len, b.buf);

	len -= 3;
	dp_test_fail_unless(b.len == len, "b len exp %d, got %d", len, b.len);

	/*
	 * bstr_lws_ltrim
	 */
	struct bstr b2 = BSTR_K(" \r\n\tabcdef:123456\t \r\n  ");

	len = strlen(" \r\n\tabcdef:123456\t \r\n  ");
	dp_test_fail_unless(b2.len == len, "b2 len exp %d, got %d", len, b2.len);

	ok = bstr_lws_ltrim(&b2);
	dp_test_fail_unless(ok, "error bstr_lws_ltrim");

	len -= 4;
	dp_test_fail_unless(b2.len == len, "b2 len exp %d, got %d", len, b2.len);

	ok = bstr_eq(&b2, BSTRL("abcdef:123456\t \r\n  "));

	dp_test_fail_unless(ok, "error with b2 after lws ltrim, "
			    "exp \"abcdef:123456\t \r\n  \" got \"%*.*s\"",
			    b2.len, b2.len, b2.buf);

	/* bstr_lws_rtrim */

	ok = bstr_lws_rtrim(&b2);
	dp_test_fail_unless(ok, "error bstr_lws_rtrim");

	ok = bstr_eq(&b2, BSTRL("abcdef:123456"));
	dp_test_fail_unless(ok, "error with b2 after lws rtrim, "
			    "exp \"abcdef:123456\" got \"%*.*s\"",
			    b2.len, b2.len, b2.buf);

	/*
	 * bstr_lws_rtrim and "A  "
	 */
	struct bstr b3 = BSTR_K("A  ");

	bstr_lws_rtrim(&b3);
	ok = bstr_eq(&b3, BSTRL("A"));
	dp_test_fail_unless(ok, "error with b3 after lws rtrim, "
			    "exp \"A\" got \"%*.*s\"",
			    b3.len, b3.len, b3.buf);

	/*
	 * bstr_lws_rtrim and "  "
	 */
	struct bstr b4 = BSTR_K("  ");

	bstr_lws_rtrim(&b4);
	ok = bstr_eq(&b4, BSTRL(""));
	dp_test_fail_unless(ok, "error with b4 after lws rtrim, "
			    "exp \"\" got \"%*.*s\"",
			    b4.len, b4.len, b4.buf);

	/*
	 * bstr_lws_rtrim and "\r\n "
	 */
	struct bstr b5 = BSTR_K("\r\n ");

	bstr_lws_rtrim(&b5);
	ok = bstr_eq(&b5, BSTRL(""));
	dp_test_fail_unless(ok, "error with b5 after lws rtrim, "
			    "exp \"\" got \"%*.*s\"",
			    b5.len, b5.len, b5.buf);

	/*
	 * bstr_lws_ltrim and "  A"
	 */
	struct bstr b6 = BSTR_K("  A");

	bstr_lws_ltrim(&b6);
	ok = bstr_eq(&b6, BSTRL("A"));
	dp_test_fail_unless(ok, "error with b6 after lws ltrim, "
			    "exp \"A\" got \"%*.*s\"",
			    b6.len, b6.len, b6.buf);

	/*
	 * bstr_lws_ltrim and "  "
	 */
	struct bstr b7 = BSTR_K("  ");

	bstr_lws_ltrim(&b7);
	ok = bstr_eq(&b7, BSTRL(""));
	dp_test_fail_unless(ok, "error with b7 after lws ltrim, "
			    "exp \"\" got \"%*.*s\"",
			    b7.len, b7.len, b7.buf);

	/*
	 * bstr_lws_ltrim and "\r\n "
	 */
	struct bstr b8 = BSTR_K("\r\n ");

	bstr_lws_ltrim(&b8);
	ok = bstr_eq(&b8, BSTRL(""));
	dp_test_fail_unless(ok, "error with b8 after lws ltrim, "
			    "exp \"\" got \"%*.*s\"",
			    b8.len, b8.len, b8.buf);

} DP_END_TEST;

/*
 * bstr3. Tests bstr_prefix_ascii_case
 */
DP_DECL_TEST_CASE(bstr, bstr3, NULL, NULL);
DP_START_TEST(bstr3, test)
{
	struct bstr b1 = BSTR_K("Call-ID:");
	struct bstr b2 = BSTR_K("call-id :");
	bool ok;

	ok = bstr_prefix_ascii_case(&b1, BSTRL("Call-ID"));
	dp_test_fail_unless(ok, "error bstr_prefix_ascii_case");

	ok = bstr_prefix_ascii_case(&b2, BSTRL("Call-ID"));
	dp_test_fail_unless(ok, "error bstr_prefix_ascii_case");

} DP_END_TEST;

/*
 * bstr4. Tests bstr_split_ascii_non_alpha
 */
DP_DECL_TEST_CASE(bstr, bstr4, NULL, NULL);
DP_START_TEST(bstr4, test)
{
	struct bstr b = BSTR_K("Abcdef; xxx");
	struct bstr head, tail;
	bool ok;

	/* Test split *after* first non-alphanumeric char */

	ok = bstr_split_ascii_non_alpha_after(&b, &head, &tail);
	dp_test_fail_unless(ok, "error bstr_split_ascii_non_alpha");

	ok = bstr_eq(&head, BSTRL("Abcdef;"));
	dp_test_fail_unless(ok, "error after non-alpha split,"
			    "exp \"Abcdef;\" got \"%*.*s\"",
			    head.len, head.len, head.buf);

	ok = bstr_eq(&tail, BSTRL(" xxx"));
	dp_test_fail_unless(ok, "error after non-alpha split,"
			    "exp \" xxx\" got \"%*.*s\"",
			    tail.len, tail.len, tail.buf);

	/* Test split *before* first non-alphanumeric char */

	head = BSTR_INIT;
	tail = BSTR_INIT;

	ok = bstr_split_ascii_non_alpha_before(&b, &head, &tail);
	dp_test_fail_unless(ok, "error bstr_split_ascii_non_alpha");

	ok = bstr_eq(&head, BSTRL("Abcdef"));
	dp_test_fail_unless(ok, "error after non-alpha split,"
			    "exp \"Abcdef\" got \"%*.*s\"",
			    head.len, head.len, head.buf);

	ok = bstr_eq(&tail, BSTRL("; xxx"));
	dp_test_fail_unless(ok, "error after non-alpha split,"
			    "exp \"; xxx\" got \"%*.*s\"",
			    tail.len, tail.len, tail.buf);

} DP_END_TEST;

/*
 * bstr5. Tests  bstr_to_ipaddr and bstr_to_port
 */
DP_DECL_TEST_CASE(bstr, bstr5, NULL, NULL);
DP_START_TEST(bstr5, test)
{
	struct bstr a1 = BSTR_K("10.0.0.1");
	uint32_t a;
	bool ok;

	ok = bstr_to_ipaddr(&a1, &a);
	dp_test_fail_unless(ok, "bstr_to_ipaddr failed");
	dp_test_fail_unless(a == 0x0a000001, "Exp 0x0a000001, got 0x%08x", a);

	struct bstr p1 = BSTR_K("5060");
	uint16_t p;

	ok = bstr_to_port(&p1, &p);
	dp_test_fail_unless(ok, "bstr_to_port failed");
	dp_test_fail_unless(p == 5060, "Exp 5060, got %u", p);

} DP_END_TEST;

