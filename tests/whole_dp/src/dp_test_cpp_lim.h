/*
 * Copyright (c) 2019,2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _DP_TEST_CPP_LIM_H_
#define _DP_TEST_CPP_LIM_H_

int create_and_commit_cpp_rate_limiter(void);
void remove_and_commit_cpp_rate_limiter(void);
void check_cpp_rate_limiter_stats(void);

#endif /* DP_TEST_CPP_LIM_H */
