/*
 * Copyright (c) 2017, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT console commands
 */

#ifndef _DP_TEST_LIB_CMD_H_
#define _DP_TEST_LIB_CMD_H_

void
_dp_test_cmd_reset(const char *file, const char *func, int line);
#define dp_test_cmd_reset(void) \
	_dp_test_cmd_reset(__FILE__, __func__, __LINE__)

#endif /* _DP_TEST_LIB_CMD_H_ */
