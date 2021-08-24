/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include "util.h"

#include "npf/cgnat/cgn_test.h"
#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/alg/alg_rc.h"
#include "npf/cgnat/alg/sip/csip_defs.h"
#include "npf/cgnat/alg/sip/csip_parse_sip.h"
#include "npf/cgnat/alg/sip/csip_parse_utils.h"
#include "npf/bstr.h"

#include "dp_test.h"
#include "dp_test_netlink_state.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"

#include "dp_test_npf_alg_sip_data.h"

/*
 * meson test -v --test-args='-d0' dp_test_npf_cgnat_sip.c
 *
 */

DP_DECL_TEST_SUITE(cgn_sip);

/*
 * sip1. Tests finding the EOL sequence at the end of a SIP message header
 * field.
 */
DP_DECL_TEST_CASE(cgn_sip, sip1, NULL, NULL);
DP_START_TEST(sip1, test)
{
	struct bstr head, tail;
	bool ok;

	/* Line 1 */
	static const struct bstr line1
		= BSTR_K("sip:example.com:321;tag=76341\r\n");

	ok = csip_get_hline(&line1, &head, &tail);
	dp_test_fail_unless(ok && head.len == 31 && tail.len == 0,
			    "Failed to find EOL in line1 \"%s\"", line1.buf);

	/* Line 2 */
	static const struct bstr line2 = BSTR_K("sip:example.co");

	ok = csip_get_hline(&line2, &head, &tail);
	dp_test_fail_unless(ok == false,
			    "line2 does not contain a cr");

	/* Line 3 */
	static const struct bstr line3 = BSTR_K("10.0.0.1:5060\n");

	ok = csip_get_hline(&line3, &head, &tail);
	dp_test_fail_unless(!ok, "Misinterpreted CR as CRLF in line3 \"%s\"",
			    line3.buf);

	/* Line 4 */
	static const struct bstr line4 = BSTR_K("10.0.0.1\n\n");

	ok = csip_get_hline(&line4, &head, &tail);
	dp_test_fail_unless(!ok, "Misinterpreted CRCR as CRLF in line4 \"%s\"",
			    line4.buf);

	/* Line 5 - Continuation line with SPC */
	static const struct bstr line5 = BSTR_K("Via:\r\n 1.1.1.1\r\n");

	ok = csip_get_hline(&line5, &head, &tail);
	dp_test_fail_unless(ok && head.len == 16 && tail.len == 0,
			    "Failed to find EOL in line5 \"%s\"", line5.buf);

	/* Line 6 - Continuation line with SPC */
	static const struct bstr line6 = BSTR_K("Via:\r\n 1.1.100.100\r\n");

	ok = csip_get_hline(&line6, &head, &tail);
	dp_test_fail_unless(ok && head.len == 20 && tail.len == 0,
			    "Failed to find EOL in line6 \"%s\"", line6.buf);

	/* Line 7 - Continuation line with TAB */
	static const struct bstr line7 = BSTR_K("Via:\r\n\t1.1.100.100\r\n");

	ok = csip_get_hline(&line7, &head, &tail);
	dp_test_fail_unless(ok && head.len == 20 && tail.len == 0,
			    "Failed to find EOL in line7 \"%s\"", line7.buf);

	/* Line 8 - Continuation line with SPC x 2 */
	static const struct bstr line8 = BSTR_K("Via:\r\n  1.1.100.100\r\n");

	ok = csip_get_hline(&line8, &head, &tail);
	dp_test_fail_unless(ok && head.len == 21 && tail.len == 0,
			    "Failed to find EOL in line8 \"%s\"", line8.buf);

} DP_END_TEST;

/*
 * sip2. Tests parsing the SIP message start-line
 */
DP_DECL_TEST_CASE(cgn_sip, sip2, NULL, NULL);
DP_START_TEST(sip2, test)
{
	enum csip_req req = SIP_REQ_NONE;
	uint resp_code = 0;
	struct bstr sl = BSTR_INIT;
	bool ok;
	int rc;

	/* Request start-line #1 */

	ok = bstr_addbuf(&sl, BSTRL("INVITE sip:I.Wilson@192.0.2.1 SIP/2.0\r\n"));
	dp_test_fail_unless(ok, "Failed to copy request start-line #1");

	rc = csip_parse_start_line(&sl, &req, &resp_code);
	dp_test_fail_unless(rc == 0, "Failed to parse \"%s\"", sl.buf);
	dp_test_fail_unless(req == SIP_REQ_INVITE,
			    "Failed to identify Invite");
	bstr_release(&sl);

	/* Request start-line #2 */

	ok = bstr_addbuf(&sl, BSTRL("INVITE sip:I.Wilson@192.0.2.1 SIP/1.0\r\n"));
	dp_test_fail_unless(ok, "Failed to copy request start-line #2");

	rc = csip_parse_start_line(&sl, &req, &resp_code);
	dp_test_fail_unless(rc == -ALG_ERR_SIP_UNSP,
			    "Failed to detect wrong unsupported version");
	bstr_release(&sl);

	/* Response start-line #1 */

	/* Does not need to write to the buffer */
	struct bstr const *slp = BSTRL("SIP/2.0 200 OK\r\n");

	rc = csip_parse_start_line(slp, &req, &resp_code);
	dp_test_fail_unless(rc == 0, "Failed to parse \"%s\"", slp->buf);
	dp_test_fail_unless(resp_code == 200,
			    "Failed to identify Response code");

} DP_END_TEST;
