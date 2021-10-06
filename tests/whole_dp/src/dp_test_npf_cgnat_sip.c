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

/* Create a printable string in the provided buffer (similar to inet_ntop) */
static const char *bstr_stop(struct bstr const *b, char *dst, int size)
{
	int len = b->len;

	if (len >= size)
		len = size-1;

	snprintf(dst, size, "%*.*s", len, len, b->buf);

	return dst;
}

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

/*
 * Test strings containing SIP URIs
 */
struct ut_sip_uri {
	const struct bstr orig;	/* original SIP msg line */
	const struct bstr host;	/* host sub-string in orig */
	const struct bstr port;	/* port sub-string in orig */
	const struct bstr trans; /* SIP msg line after translation/copying */
	bool ok;		/* Does orig contain a SIP URI? */
};

const struct ut_sip_uri uris[] = {
	{ .orig = BSTR_K("sip:atlanta.com"),
	  .host = BSTR_K("atlanta.com"),
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:atlanta.com"),
	  .ok = true },

	{ .orig = BSTR_K("sip:192.0.2.4"),
	  .host = BSTR_K("192.0.2.4"),
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:1.1.1.1"),
	  .ok = true },

	{ .orig = BSTR_K("INVITE sip:192.0.2.4:5060 SIP/2.0\r\n"),
	  .host = BSTR_K("192.0.2.4"),
	  .port = BSTR_K("5060"),
	  .trans = BSTR_K("INVITE sip:1.1.1.1:1024 SIP/2.0\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("INVITE sip:192.0.2.5:5060 SIP/2.0\r\n"),
	  .host = BSTR_K("192.0.2.5"),
	  .port = BSTR_K("5060"),
	  .trans = BSTR_K("INVITE sip:192.0.2.5:1024 SIP/2.0\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("INVITE sip:192.0.2.4:5061 SIP/2.0\r\n"),
	  .host = BSTR_K("192.0.2.4"),
	  .port = BSTR_K("5061"),
	  .trans = BSTR_K("INVITE sip:1.1.1.1:5061 SIP/2.0\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("sip:alice@atlanta.com"),
	  .host = BSTR_K("atlanta.com"),
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:alice@atlanta.com"),
	  .ok = true },

	{ .orig = BSTR_K("INVITE sip:alice@192.0.2.4 SIP/2.0\r\n"),
	  .host = BSTR_K("192.0.2.4"),
	  .port = BSTR_INIT,
	  .trans = BSTR_K("INVITE sip:alice@1.1.1.1 SIP/2.0\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("sip:alice@atlanta.com:5060"),
	  .host = BSTR_K("atlanta.com"),
	  .port = BSTR_K("5060"),
	  .trans = BSTR_K("sip:alice@atlanta.com:1024"),
	  .ok = true },

	{ .orig = BSTR_K("sip:alice@192.0.2.4:5060"),
	  .host = BSTR_K("192.0.2.4"),
	  .port = BSTR_K("5060"),
	  .trans = BSTR_K("sip:alice@1.1.1.1:1024"),
	  .ok = true },

	{ .orig = BSTR_K(" sip:example.com:5060;tag=76341\r\n"),
	  .host = BSTR_K("example.com"),
	  .port = BSTR_K("5060"),
	  .trans = BSTR_K(" sip:example.com:1024;tag=76341\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("<sip:example.com:321>;tag=76341\r\n"),
	  .host = BSTR_K("example.com"),
	  .port = BSTR_K("321"),
	  .trans = BSTR_K("<sip:example.com:321>;tag=76341\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("<sip:192.0.2.4:321>;tag=76341\r\n"),
	  .host = BSTR_K("192.0.2.4"),
	  .port = BSTR_K("321"),
	  .trans = BSTR_K("<sip:1.1.1.1:321>;tag=76341\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("sip:john:passwd@example.com;tag=76341\r\n"),
	  .host = BSTR_K("example.com"),
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:john:passwd@example.com;tag=76341\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("sip:john:passwd@192.0.2.4;tag=76341\r\n"),
	  .host = BSTR_K("192.0.2.4"),
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:john:passwd@1.1.1.1;tag=76341\r\n"),
	  .ok = true },

	{ .orig = BSTR_K("sip:alice@atlanta.com\n\n"),
	  .host = BSTR_K("atlanta.com"),
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:alice@atlanta.com\n\n"),
	  .ok = true },

	{ .orig = BSTR_K("sip:alice.smith@192.0.2.4?subject=test\r\n"),
	  .host = BSTR_K("192.0.2.4"),
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:alice.smith@1.1.1.1?subject=test\r\n"),
	  .ok = true },

	/* do not translate if URI scheme is not 'sip' */
	{ .orig = BSTR_K("INVITE foo:192.0.2.4:5060 SIP/2.0\r\n"),
	  .host = BSTR_INIT,
	  .port = BSTR_INIT,
	  .trans = BSTR_K("INVITE foo:192.0.2.4:5060 SIP/2.0\r\n"),
	  .ok = false },

	/* do not translate if URI scheme is not 'sip' */
	{ .orig = BSTR_K("INVITE foo:alice@192.0.2.4:5060 SIP/2.0\r\n"),
	  .host = BSTR_INIT,
	  .port = BSTR_INIT,
	  .trans = BSTR_K("INVITE foo:alice@192.0.2.4:5060 SIP/2.0\r\n"),
	  .ok = false },

	/* do not translate IPv6 URI */
	{ .orig = BSTR_K("sip:6000@[2620:0:2ef0:7070:250:60ff:fe03:32b7]:5060\r\n"),
	  .host = BSTR_INIT,
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:6000@[2620:0:2ef0:7070:250:60ff:fe03:32b7]:5060\r\n"),
	  .ok = false },

	/* do not translate IPv6 URI */
	{ .orig = BSTR_K("sip:6000@[2620:0:2ef0:7070:250:60ff:fe03:32b7];tag=76341\r\n"),
	  .host = BSTR_INIT,
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:6000@[2620:0:2ef0:7070:250:60ff:fe03:32b7];tag=76341\r\n"),
	  .ok = false },
};

/*
 * sip3. Tests parsing of SIP URIs
 */
DP_DECL_TEST_CASE(cgn_sip, sip3, NULL, NULL);
DP_START_TEST(sip3, test)
{
	uint i;

	for (i = 0; i < ARRAY_SIZE(uris); i++) {

		struct bstr pre = BSTR_INIT;	/* string before the host */
		struct bstr host = BSTR_INIT;	/* host string */
		struct bstr port = BSTR_INIT;	/* port string */
		struct bstr post = BSTR_INIT;	/* string after the host/port */
		char str1[70];
		char str2[70];
		bool ok;

		ok = csip_find_uri(&uris[i].orig, &pre, &host, &port, &post);

		dp_test_fail_unless(uris[i].ok == ok, "\"%*.*s\" Expected %u, got %u",
				    uris[i].orig.len, uris[i].orig.len, uris[i].orig.buf,
				    uris[i].ok, ok);

		/* Verify host and port have been located */

		dp_test_fail_unless(bstr_eq(&uris[i].host, &host),
				    "Host exp \"%s\", got \"%s\"\n",
				    bstr_stop(&uris[i].host, str1, sizeof(str1)),
				    bstr_stop(&host, str2, sizeof(str2)));

		dp_test_fail_unless(bstr_eq(&uris[i].port, &port),
				    "Port exp \"%s\", got \"%s\"\n",
				    bstr_stop(&uris[i].port, str1, sizeof(str1)),
				    bstr_stop(&port, str2, sizeof(str2)));

		/*
		 * Re-constitute the line, and verify against original
		 */
		struct bstr b;
		char buf[200];

		b = BSTR_INIT;
		ok = bstr_attach_unmanaged(&b, buf, 0, sizeof(buf));
		dp_test_fail_unless(ok, "Failed to create unmanaged buffer");

		if (pre.len > 0) {
			ok = bstr_addbuf(&b, &pre);
			dp_test_fail_unless(ok, "Failed to add pre \"%s\"",
				bstr_stop(&pre, str1, sizeof(str1)));
		}

		if (host.len > 0) {
			ok = bstr_addbuf(&b, &host);
			dp_test_fail_unless(ok, "Failed to add host \"%s\" to \"%s\"",
					    bstr_stop(&host, str1, sizeof(str1)),
					    bstr_stop(&b, str2, sizeof(str2)));
		}

		if (port.len > 0) {
			ok = bstr_addstr(&b, ":");
			dp_test_fail_unless(ok, "Failed to add colon to \"%s\"",
					    bstr_stop(&b, str1, sizeof(str1)));

			ok = bstr_addbuf(&b, &port);
			dp_test_fail_unless(ok, "Failed to add port \"%s\" to \"%s\"",
					    bstr_stop(&port, str1, sizeof(str1)),
					    bstr_stop(&b, str2, sizeof(str2)));
		}

		if (post.len > 0) {
			ok = bstr_addbuf(&b, &post);
			dp_test_fail_unless(ok, "Failed to add post \"%s\" to \"%s\"",
					    bstr_stop(&post, str1, sizeof(str1)),
					    bstr_stop(&b, str2, sizeof(str2)));
		}

		dp_test_fail_unless(bstr_eq(&uris[i].orig, &b),
				    "Reconstituted line, exp \"%s\" got \"%s\"",
				    bstr_stop(&uris[i].orig, str1, sizeof(str1)),
				    bstr_stop(&b, str2, sizeof(str2)));

	}

} DP_END_TEST;

/*
 * sip4. Tests parsing and translating of SIP URIs
 */
DP_DECL_TEST_CASE(cgn_sip, sip4, NULL, NULL);
DP_START_TEST(sip4, test)
{
	uint i;

	for (i = 0; i < ARRAY_SIZE(uris); i++) {

		struct bstr pre = BSTR_INIT;	/* string before the host */
		struct bstr host = BSTR_INIT;	/* host string */
		struct bstr port = BSTR_INIT;	/* port string */
		struct bstr post = BSTR_INIT;	/* string after the host/port */
		bool ok;
		char str1[70];
		char str2[70];

		ok = csip_find_uri(&uris[i].orig, &pre, &host, &port, &post);

		dp_test_fail_unless(uris[i].ok == ok, "\"%*.*s\" Expected %u, got %u",
				    uris[i].orig.len, uris[i].orig.len, uris[i].orig.buf,
				    uris[i].ok, ok);

		/* Verify host and port have been extracted */
		dp_test_fail_unless(bstr_eq(&uris[i].host, &host),
				    "Host exp \"%s\", got \"%s\"\n",
				    bstr_stop(&uris[i].host, str1, sizeof(str1)),
				    bstr_stop(&host, str2, sizeof(str2)));

		dp_test_fail_unless(bstr_eq(&uris[i].port, &port),
				    "Port exp \"%s\", got \"%s\"\n",
				    bstr_stop(&uris[i].port, str1, sizeof(str1)),
				    bstr_stop(&port, str2, sizeof(str2)));

		/*
		 * Translate the line
		 */
		struct bstr new;
		char buf[200];
		struct bstr oaddr = BSTR_K("192.0.2.4");
		struct bstr oport = BSTR_K("5060");
		struct bstr taddr = BSTR_K("1.1.1.1");
		struct bstr tport = BSTR_K("1024");

		new = BSTR_INIT;
		ok = bstr_attach_unmanaged(&new, buf, 0, sizeof(buf));
		dp_test_fail_unless(ok, "error bstr_attach_unmanaged");

		csip_find_and_translate_uri(&uris[i].orig, &new, &oaddr, &oport,
					    &taddr, &tport);

		dp_test_fail_unless(bstr_eq(&uris[i].trans, &new),
				    "Translated line, exp \"%s\" got \"%s\"",
				    bstr_stop(&uris[i].trans, str1, sizeof(str1)),
				    bstr_stop(&new, str2, sizeof(str2)));
	}

} DP_END_TEST;


#define CGN_SIP_TEST1_SZ 1

const char *sipd1_pre_cgnat[CGN_SIP_TEST1_SZ] = {
	/*
	 * 0. INVITE. Forward (inside)
	 */
	"INVITE sip:B.Boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:1.1.1.2;lr>\r\n"
	"From: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"To: B.Boss <sip:B.Boss@work.co.uk>\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"User-agent: Cisco-SIPGateway/IOS-12.x\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:workman@1.1.1.2>\r\n"
	"Content-Type: application/sdp\r\n"
	"Max-forwards: 70\r\n"
	"Subject: About That Power Outage...\r\n"
	"Content-Length: 168\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Workman 2890844526 2890844526 IN IP4 1.1.1.2\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 1.1.1.2\r\n"
	"t=0 0\r\n"
	"m=audio 10000 RTP/AVP 0\r\n"
	"a=rtcp:10001 IN IP4 1.1.1.2\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",
};

/*
 * Only the 'From' line is translated in this example.
 */
const char *sipd1_post_cgnat_x[CGN_SIP_TEST1_SZ] = {
	/*
	 * 0. INVITE. Forward (outside)
	 */
	"INVITE sip:B.Boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:1.1.1.2;lr>\r\n"
	"From: A. Workman <sip:workman@30.30.30.2>;tag=76341\r\n"
	"To: B.Boss <sip:B.Boss@work.co.uk>\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"User-agent: Cisco-SIPGateway/IOS-12.x\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:workman@1.1.1.2>\r\n"
	"Content-Type: application/sdp\r\n"
	"Max-forwards: 70\r\n"
	"Subject: About That Power Outage...\r\n"
	"Content-Length: 168\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Workman 2890844526 2890844526 IN IP4 1.1.1.2\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 1.1.1.2\r\n"
	"t=0 0\r\n"
	"m=audio 10000 RTP/AVP 0\r\n"
	"a=rtcp:10001 IN IP4 1.1.1.2\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",
};

#define SIP_BSTR_MAX	100
#define SIP_BSTR_SZ	(SIP_BSTR_MAX + 1)

/*
 * sip5.  Tests splitting a SIP message into an array of 'lines'.
 */
DP_DECL_TEST_CASE(cgn_sip, sip5, NULL, NULL);
DP_START_TEST(sip5, test)
{
	struct bstr orig = BSTR_INIT;
	char orig_buf[2000];
	bool ok;

	struct {
		struct csip_lines_meta meta;
		struct bstr arr[SIP_BSTR_SZ];
	} line_array;

	line_array.meta.used = 0;
	line_array.meta.capacity = ARRAY_SIZE(line_array.arr);

	struct csip_lines *sip_lines = (struct csip_lines *)&line_array;

	/*
	 * A real message would be in a packet buffer, not a const string, so
	 * copy it to orig_buf.  This is necessary since bstr_attach_unmanaged
	 * adds a '\0'.
	 */
	dp_test_fail_unless(strlen(sipd1_pre_cgnat[0]) < sizeof(orig_buf) - 15,
		"orig_buf is too small for the SIP msg");

	memcpy(orig_buf, sipd1_pre_cgnat[0], strlen(sipd1_pre_cgnat[0]));

	/* Set 'orig' bstr to point to the SIP msg in 'orig_buf' */

	ok = bstr_attach_unmanaged(&orig, orig_buf, strlen(sipd1_pre_cgnat[0]),
				   sizeof(orig_buf));
	dp_test_fail_unless(ok, "Failed to create bstr 'orig' from SIP msg");

	/* Check orig and the SIP message are identical */

	dp_test_fail_unless(strlen(sipd1_pre_cgnat[0]) == (uint)orig.len,
			    "Expected %lu, got %d", strlen(sipd1_pre_cgnat[0]), orig.len);
	dp_test_fail_unless(!memcmp(sipd1_pre_cgnat[0], orig.buf, orig.len),
			    "bstr 'orig' not same as SIP msg");

	/*
	 * Parse SIP message and store each line as a bstr in the sip_lines[]
	 * array.
	 */
	ok = csip_split_lines(&orig, sip_lines);
	dp_test_fail_unless(ok, "Failed to split lines");

	dp_test_fail_unless(sip_lines->m.used == 22,
			    "Expected 22 lines, got %u", sip_lines->m.used);

} DP_END_TEST;


/*
 * sip6.  This test demonstrates how a SIP Invite message would be parsed and
 * translated.
 */
DP_DECL_TEST_CASE(cgn_sip, sip6, NULL, NULL);
DP_START_TEST(sip6, test)
{
	struct bstr orig = BSTR_INIT;
	char orig_buf[2000];
	bool ok;
	uint32_t i;

	struct {
		struct csip_lines_meta meta;
		struct bstr arr[SIP_BSTR_SZ];
	} line_array;

	line_array.meta.used = 0;
	line_array.meta.capacity = ARRAY_SIZE(line_array.arr);

	struct csip_lines *sip_lines = (struct csip_lines *)&line_array;

	/*
	 * A real message would be in a packet buffer, not a const string, so
	 * copy it to orig_buf.  This is necessary since bstr_attach_unmanaged
	 * adds a '\0'.
	 */
	dp_test_fail_unless(strlen(sipd1_pre_cgnat[0]) < sizeof(orig_buf) - 15,
		"orig_buf is too small for the SIP msg");

	memcpy(orig_buf, sipd1_pre_cgnat[0], strlen(sipd1_pre_cgnat[0]));

	/* Set 'orig' bstr to point to the SIP msg in 'orig_buf' */

	ok = bstr_attach_unmanaged(&orig, orig_buf, strlen(sipd1_pre_cgnat[0]),
				   sizeof(orig_buf));
	dp_test_fail_unless(ok, "Failed to create bstr 'orig' from SIP msg");

	/* Check orig and the SIP message are identical */

	dp_test_fail_unless(strlen(sipd1_pre_cgnat[0]) == (uint)orig.len,
			    "Expected %lu, got %d", strlen(sipd1_pre_cgnat[0]), orig.len);
	dp_test_fail_unless(!memcmp(sipd1_pre_cgnat[0], orig.buf, orig.len),
			    "bstr 'orig' not same as SIP msg");

	/*
	 * Parse SIP message and store each line as a bstr in the sip_lines[]
	 * array.
	 */
	ok = csip_split_lines(&orig, sip_lines);
	dp_test_fail_unless(ok, "Failed to split lines");

	dp_test_fail_unless(sip_lines->m.used == 22,
			    "Expected 22 lines, got %u", sip_lines->m.used);


	/*
	 * For each line of orig SIP message, translate the 'From' line and
	 * copy remaining lines into a new buffer.
	 */
	const struct bstr from = BSTR_K("From:");
	struct bstr oaddr = BSTR_K("1.1.1.2");
	struct bstr oport = BSTR_K("5060");
	struct bstr taddr = BSTR_K("30.30.30.2");
	struct bstr tport = BSTR_K("1024");
	struct bstr *lines = sip_lines->lines;
	uint32_t nlines = sip_lines->m.used;
	char new_buf[2000];
	struct bstr new;
	int offs;

	/* Create a counted string using new_buf[] storage */
	ok = bstr_attach_unmanaged(&new, new_buf, 0, sizeof(new_buf));
	dp_test_fail_unless(ok, "Failed to create bstr 'new'");

	for (i = 0; i < nlines; i++) {

		/* Look for 'From' header */
		offs = bstr_find_str(&lines[i], &from);

		/* We expect the 'From' string at the start of the line */
		if (offs == 0) {
			ok = csip_find_and_translate_uri(&lines[i], &new,
							 &oaddr, &oport, &taddr, &tport);
			dp_test_fail_unless(ok, "Failed to translate 'From'");
		} else {
			ok = bstr_addbuf(&new, &lines[i]);
			dp_test_fail_unless(ok, "Failed to copy line");
		}
	}

	/*
	 * Copmare new message with the expected translated message
	 */
	char str1[1000];
	char str2[1000];
	struct bstr trans = {.buf = (uint8_t *)(sipd1_post_cgnat_x[0]),
			     .len = strlen(sipd1_post_cgnat_x[0]),
			     .allocated = strlen(sipd1_post_cgnat_x[0]) + 1};

	dp_test_fail_unless(bstr_eq(&trans, &new),
			    "Translated line, exp \"%s\" got \"%s\"",
			    bstr_stop(&trans, str1, sizeof(str1)),
			    bstr_stop(&new, str2, sizeof(str2)));

} DP_END_TEST;

