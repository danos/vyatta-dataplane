/*
 * Copyright (c) 2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Macros for defining unit-tests.
 *
 * These build on top of the Check unit test libraries own API and
 * implement a 'self-registration' mechanism (via the gcc constructor
 * attribute) that allow new unit tests to be added without requiring
 * any changes to be made to the core dp_test code.
 *
 * These macros assume that each module will contain tests for a
 * single test suite. But they then allow the declaration of multiple
 * test cases which in turn may contain multiple tests.
 *
 * In future these macros may also allow us to insert further common
 * functionality like an automatic cleanup or cleanness checker
 * function.
 */
#ifndef __DP_TEST_MACROS_H__
#define __DP_TEST_MACROS_H__

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#include <check.h>

#include "dp_test_cmd_check.h"

Suite * dp_test_get_suite(const char *filename);

/* Private helper macro */
#define _DP_TEST_FNAME_ (strrchr(__FILE__, '/') ?                     \
			 (strrchr(__FILE__, '/') + 1) : (__FILE__))

/*
 * Declare a test suite.
 *
 * SUITE shold be the name of the suite.
 */
#define DP_DECL_TEST_SUITE(SUITE)                      \
	static Suite *dp_tsuite_##SUITE##_ptr

/*
 * Declare a test case and its associated setup and teardown routines.
 *
 * A test case is a collection of tests which share common setup and
 * teardown and which currently form the smallest unit that can be
 * individually executed by the UT infra.
 *
 * SUITE - is the name of the parent test suite which should already have
 *         been declared using DP_DECL_TEST_SUITE above.
 * TESTCASE - is the name of the test case (will be turned into a string).
 * SETUP, TEARDOWN - should be an (*SFun) (i.e a void func(void)) but
 *                   can take the value NULL if no handling is desired.
 */
#define DP_DECL_TEST_CASE(SUITE, TESTCASE, SETUP, TEARDOWN)		    \
	static TCase *dp_tcase_##TESTCASE##_ptr;			    \
	static void (*dp_test_##TESTCASE##_teardown_fn)(void) = TEARDOWN;   \
									    \
	TCase *get_tcase_##TESTCASE(void);				    \
									    \
	static void dp_tcase_##TESTCASE##_teardown(void)		    \
	{								    \
		if (dp_test_##TESTCASE##_teardown_fn) {			    \
			dp_test_##TESTCASE##_teardown_fn();		    \
			dp_test_check_state_clean(false);		    \
		}							    \
	}								    \
									    \
	TCase *get_tcase_##TESTCASE(void)				    \
	{								    \
		if (!dp_tcase_##TESTCASE##_ptr) {			    \
			dp_tcase_##TESTCASE##_ptr =			    \
				tcase_create(#TESTCASE);		    \
			tcase_add_checked_fixture(			    \
				dp_tcase_##TESTCASE##_ptr,		    \
				SETUP, dp_tcase_##TESTCASE##_teardown);	    \
			if (!dp_tsuite_##SUITE##_ptr)			    \
				dp_tsuite_##SUITE##_ptr =		    \
					dp_test_get_suite(_DP_TEST_FNAME_); \
			suite_add_tcase(dp_tsuite_##SUITE##_ptr,	    \
					dp_tcase_##TESTCASE##_ptr);	    \
		}							    \
		return dp_tcase_##TESTCASE##_ptr;			    \
	}

/*
 * Start defining a test function.
 *
 * Use this before the opening '{' of a test function.
 *
 * TESTCASE - is the name of the parent test case which should have already
 *            been declared using DP_DECL_TEST_CASE above.
 * TEST     - is the name of the individual test being applied.
 */
 #if ((CHECK_MAJOR_VERSION > 0) || (CHECK_MINOR_VERSION >= 13))

#define _DP_START_TEST(TESTCASE, TEST, CONSTRUCT)		 \
	void dp_test_##TESTCASE##_##TEST##_register(void);	 \
								 \
	static void dp_test_##TESTCASE##_##TEST##_fn(int);	 \
								 \
	static const TTest dp_test_##TESTCASE##_##TEST##_ttest	 \
		= {"dp_test_##TESTCASE##_##TEST",		 \
		   dp_test_##TESTCASE##_##TEST##_fn,		 \
		   __FILE__, __LINE__};				 \
	static const TTest * dp_test_##TESTCASE##_##TEST = 	 \
		& dp_test_##TESTCASE##_##TEST##_ttest;		 \
								 \
	CONSTRUCT                                                \
	void							 \
	dp_test_##TESTCASE##_##TEST##_register(void)		 \
	{							 \
		TCase *tc = get_tcase_##TESTCASE();		 \
		tcase_add_test(tc, dp_test_##TESTCASE##_##TEST); \
	}							 \
								 \
	static void dp_test_##TESTCASE##_##TEST##_fn		 \
		(int _i CK_ATTRIBUTE_UNUSED)			 \
	{							 \
		bool _do_clean_check =				 \
			!dp_test_##TESTCASE##_teardown_fn;	 \
								 \
		dp_test_tcase_mark(true, __func__);              \

#else

#define _DP_START_TEST(TESTCASE, TEST, CONSTRUCT)		 \
	void dp_test_##TESTCASE##_##TEST##_register(void);	 \
								 \
	static void dp_test_##TESTCASE##_##TEST(int);		 \
								 \
	CONSTRUCT                                                \
	void							 \
	dp_test_##TESTCASE##_##TEST##_register(void)		 \
	{							 \
		TCase *tc = get_tcase_##TESTCASE();		 \
		tcase_add_test(tc, dp_test_##TESTCASE##_##TEST); \
	}							 \
								 \
	START_TEST(dp_test_##TESTCASE##_##TEST)			 \
	{							 \
		bool _do_clean_check =				 \
			!dp_test_##TESTCASE##_teardown_fn;	 \
								 \
		dp_test_tcase_mark(true, __func__);              \


#endif

/*
 * Start defining a test function.
 *
 * Use this before the opening '{' of a test function.
 *
 * TESTCASE - is the name of the parent test case which should have already
 *            been declared using DP_DECL_TEST_CASE above.
 * TEST     - is the name of the individual test being applied.
 */
#define DP_START_TEST(TESTCASE, TEST)                            \
	_DP_START_TEST(TESTCASE, TEST, __attribute__((constructor)))

#define DONT_RUN
#define DP_START_TEST_DONT_RUN(TESTCASE, TEST)			 \
	_DP_START_TEST(TESTCASE, TEST, DONT_RUN)

/*
 * Only run the FULL_RUN tests if FULL_RUN is defined
 */
#ifdef DP_TEST_FULL_RUN
#define DP_START_TEST_FULL_RUN(TESTCASE, TEST)			 \
	_DP_START_TEST(TESTCASE, TEST, __attribute__((constructor)))
#else
#define DP_START_TEST_FULL_RUN(TESTCASE, TEST)			 \
	_DP_START_TEST(TESTCASE, TEST, DONT_RUN)
#endif






/*
 * Define the end of the test - verify that the dplane config has been put back.
 */
#define DP_END_TEST \
		mark_point();					\
		if (_do_clean_check)				\
			dp_test_check_state_clean(false);	\
								\
		dp_test_tcase_mark(false, __func__);            \
	}							\
	END_TEST

#define TEXT_BOLD    "\033[1m"
#define TEXT_INVERSE "\033[7m"
#define TEXT_RED     "\033[31m"
#define TEXT_GREEN   "\033[32m"
#define TEXT_BLUE    "\033[34m"
#define TEXT_RESET   "\033[0m"

/*
 * Macros for checking test conditions
 */

extern bool dp_test_abort_on_fail;

/* Always fail */
#define dp_test_fail(msg, ...)			\
	_dp_test_fail_unless(0, __FILE__, __LINE__, msg, ## __VA_ARGS__)

#define _dp_test_fail(file, line, msg, ...)				\
	_dp_test_fail_unless(0, file, line, msg, ## __VA_ARGS__)

/* Enable this version if you want to assert on first failure */
static inline void _dp_test_fail_unless(bool condition, const char *file,
					int line, const char *fmt, ...)
	__attribute__ ((__format__(printf, 4, 5)));
static inline void _dp_test_fail_unless(bool condition, const char *file,
					int line, const char *fmt, ...)
{
	if (!condition) {
		char tmp_str[20000];
		va_list ap;

		va_start(ap, fmt);
		vsnprintf(tmp_str, sizeof(tmp_str), fmt, ap);
		va_end(ap);

		if (dp_test_abort_on_fail) {
			/* file and line number are in bold red text */
			printf(TEXT_BOLD TEXT_RED "%s %i" TEXT_RESET " %s\n",
			       file, line, tmp_str);
			abort();
		}

#if ((CHECK_MAJOR_VERSION > 0) || (CHECK_MINOR_VERSION >= 15))
		_ck_assert_failed(file, line, "", "%s",  tmp_str);
#elif ((CHECK_MAJOR_VERSION > 0) || (CHECK_MINOR_VERSION > 9) || \
	(CHECK_MICRO_VERSION >= 13))
		_ck_assert_failed(file, line, "%s",  tmp_str);
#elif ((CHECK_MAJOR_VERSION > 0) || (CHECK_MINOR_VERSION > 9) || \
	(CHECK_MICRO_VERSION > 9))
		_ck_assert_msg((condition), file, line, "%s", tmp_str);
#else
		_fail_unless(condition, file, line, "%s", tmp_str);
#endif
	}
}

#define dp_test_fail_unless(cond, fmt, ...) \
	_dp_test_fail_unless(cond, __FILE__, __LINE__, fmt, ## __VA_ARGS__)

#endif /*__DP_TEST_MACROS_H__ */
