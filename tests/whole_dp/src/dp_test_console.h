/*-
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A test console for the dataplane test harness.
 */

#ifndef _DP_TEST_CONSOLE_H_
#define _DP_TEST_CONSOLE_H_

char *dp_test_console_request(const char *request, bool print);
char *dp_test_console_request_src(enum cont_src_en cont_src,
				  const char *request, bool print);
char *dp_test_console_request_w_err(const char *request, bool *err_ret,
				    bool print);
char *dp_test_console_request_w_err_src(enum cont_src_en cont_src,
					const char *request, bool *err_ret,
					bool print);
void dp_test_console_request_reply(const char *cmd, bool print);
void dp_test_console_request_reply_src(enum cont_src_en cont_src,
				       const char *cmd, bool print);
char *dp_test_console_set_endpoint(enum cont_src_en cont_src);

#endif /* _DP_TEST_CONSOLE_H_ */
