/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VYATTA_DATAPLANE_COMPILER_H
#define VYATTA_DATAPLANE_COMPILER_H

/* For CLANG vs GCC differences */
#ifdef __clang__
	#define __cold_label
	#define __cold_func __attribute__((cold))
	#define __hot_label
	#define __hot_func __attribute__((hot))
	#define __noinline __attribute__((noinline))
	#define ALWAYS_INLINE inline __attribute__((always_inline))
	#define __unroll_loops
	#define __hot_data __attribute__((section("hot")))
	#define __unused __attribute__ ((unused))
	#define __externally_visible
	#define expect_hint(expr, c) __builtin_expect(expr, c)
	#define __FOR_EXPORT __attribute__((visibility("default")))
#else /* ! __clang__ */
# ifdef __GNUC__
	#define __cold_label __attribute__((cold))
	#define __cold_func __attribute__((cold))
	#define __hot_label __attribute__((hot))
	#define __hot_func __attribute__((hot))
	#define __noinline __attribute__((noinline))
	#define ALWAYS_INLINE inline __attribute__((always_inline))
	#define __unroll_loops __attribute__((optimize("unroll-loops")))
	#define __hot_data __attribute__((section("hot")))
	#define __unused __attribute__ ((unused))
	#define __externally_visible __attribute__ ((externally_visible))
	#define expect_hint(expr, c) __builtin_expect(expr, c)
	#define __FOR_EXPORT __attribute__((visibility("default")))
# else /* ! __GNUC__ */
	#define __cold_label
	#define __cold_func
	#define __hot_label
	#define __hot_func
	#define __noinline
	#define ALWAYS_INLINE inline
	#define __unroll_loops
	#define __hot_data
	#define __unused
	#define __externally_visible
	#define expect_hint(expr, c) expr
	#define __FOR_EXPORT
# endif
#endif /* __clang__ */

#ifndef likely
#define likely(expr) expect_hint((expr), 1)
#endif /* likely */

#ifndef unlikely
#define unlikely(expr) expect_hint((expr), 0)
#endif /* unlikely */

#endif /* VYATTA_DATAPLANE_COMPILER_H */
