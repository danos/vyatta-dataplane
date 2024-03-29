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
#include "npf/cgnat/alg/sip/csip_parse_sdp.h"
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
	int rc;

	/* Request start-line #1 */

	const struct bstr sl1 = BSTR_K("INVITE sip:I.Wilson@192.0.2.1 SIP/2.0\r\n");

	rc = csip_parse_start_line(&sl1, &req, &resp_code);
	dp_test_fail_unless(rc == 0, "Failed to parse \"%s\"", sl1.buf);
	dp_test_fail_unless(req == SIP_REQ_INVITE,
			    "Failed to identify Invite");

	/* Request start-line #2 */

	const struct bstr sl2 = BSTR_K("INVITE sip:I.Wilson@192.0.2.1 SIP/1.0\r\n");

	rc = csip_parse_start_line(&sl2, &req, &resp_code);
	dp_test_fail_unless(rc == -ALG_ERR_SIP_UNSP,
			    "Failed to detect wrong unsupported version");

	/* Response start-line #1 */

	struct bstr const sl3 = BSTR_K("SIP/2.0 200 OK\r\n");

	rc = csip_parse_start_line(&sl3, &req, &resp_code);
	dp_test_fail_unless(rc == 0, "Failed to parse \"%s\"", sl3.buf);
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
	{ .orig = BSTR_K("sip:6000@[3620:0:2ef0:7070:250:60ff:fe03:32b7];tag=76341\r\n"),
	  .host = BSTR_INIT,
	  .port = BSTR_INIT,
	  .trans = BSTR_K("sip:6000@[3620:0:2ef0:7070:250:60ff:fe03:32b7];tag=76341\r\n"),
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

		if (!ok) {
			pre = uris[i].orig;
			host.len = 0;
			port.len = 0;
			post.len = 0;
		}

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

		if (!ok) {
			pre = uris[i].orig;
			host.len = 0;
			port.len = 0;
			post.len = 0;
		}

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

/*
 * Split a SIP message bstr into lines, and classify each line
 */
static void sip_split_and_classify(struct bstr *msg, struct csip_lines *sip_lines,
				   const char *name)
{
	uint32_t i;
	bool ok;

	/*
	 * Parse SIP message and store each line as a bstr in the sip_lines[]
	 * array.
	 */
	ok = csip_split_lines(msg, sip_lines);

	dp_test_fail_unless(ok, "%s: Failed to split lines", name);

	/*
	 * Classify the SIP message start-line
	 */
	ok = csip_classify_sip_start(sip_lines);

	dp_test_fail_unless(ok, "%s: Failed to classify SIP start-line", name);
	dp_test_fail_unless(sip_lines->lines[0].type == SIP_LINE_REQ,
			    "%s: Line 0, expected REQ", name);

	/*
	 * Classify the SIP lines
	 */
	for (i = sip_lines->m.sip_first; i <= sip_lines->m.sip_last; i++) {
		ok = csip_classify_sip(sip_lines, i);
		dp_test_fail_unless(ok, "%s: Failed to classify SIP line %u", name, i);
	}

	/*
	 * Classify the SDP lines
	 */
	for (i = sip_lines->m.sdp_first; i <= sip_lines->m.sdp_last; i++) {
		ok = csip_classify_sdp(sip_lines, i);
		dp_test_fail_unless(ok, "%s: Failed to classify SDP line %u", name, i);
	}
}


#define CGN_SIP_TEST1_SZ 1

const char *sipd1_pre_cgnat[CGN_SIP_TEST1_SZ] = {
	/*
	 * 0. INVITE. Forward (inside)
	 */
	"INVITE sip:B.Boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:1.1.1.2;lr>\r\n"
	"From: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"t : B.Boss <sip:B.Boss@work.co.uk>\r\n"
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
	"t : B.Boss <sip:B.Boss@work.co.uk>\r\n"
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
	uint32_t i;
	bool ok;

	struct {
		struct csip_lines_meta meta;
		struct csip_line arr[SIP_BSTR_SZ];
	} line_array;

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

	dp_test_fail_unless(sip_lines->m.sip_first == 1,
			    "SIP first, expected 1 got %u",
			    sip_lines->m.sip_first);

	dp_test_fail_unless(sip_lines->m.sip_last == 12,
			    "SIP last, expected 12 got %u",
			    sip_lines->m.sip_last);

	dp_test_fail_unless(sip_lines->m.sdp_first == 14,
			    "SDP first, expected 14 got %u",
			    sip_lines->m.sdp_first);

	dp_test_fail_unless(sip_lines->m.sdp_last == 21,
			    "SDP last, expected 21 got %u",
			    sip_lines->m.sdp_last);

	/* Check a selection of lines */
	dp_test_fail_unless(sip_lines->lines[1].type == SIP_LINE_SIP,
			    "Line 1, expected SIP");

	dp_test_fail_unless(sip_lines->lines[13].type == SIP_LINE_SEPARATOR,
			    "Line 13, expected separator");

	dp_test_fail_unless(sip_lines->lines[19].type == SIP_LINE_SDP,
			    "Line 19, expected SDP");

	/* Classify the SIP message start-line */
	ok = csip_classify_sip_start(sip_lines);

	dp_test_fail_unless(ok, "Failed to classify SIP start-line");
	dp_test_fail_unless(sip_lines->lines[0].type == SIP_LINE_REQ,
			    "Line 0, expected REQ");

	/* Classify the SIP lines */

	for (i = sip_lines->m.sip_first; i <= sip_lines->m.sip_last - 1; i++) {
		ok = csip_classify_sip(sip_lines, i);
		dp_test_fail_unless(ok, "Failed to classify SIP line %u", i);
	}

	dp_test_fail_unless(sip_lines->lines[1].sip == SIP_HDR_VIA,
			    "Line 1, expected Via");

	dp_test_fail_unless(sip_lines->m.sip_index[SIP_HDR_VIA] == 1,
			    "Via index, expected 1 got %u",
			    sip_lines->m.sip_index[SIP_HDR_VIA]);

	dp_test_fail_unless(sip_lines->lines[4].sip == SIP_HDR_TO,
			    "Line 5, expected To");

	dp_test_fail_unless(sip_lines->lines[5].sip == SIP_HDR_CALLID,
			    "Line 5, expected CallID");

	dp_test_fail_unless(sip_lines->m.sip_index[SIP_HDR_CALLID] == 5,
			    "CallID index, expected 5 got %u",
			    sip_lines->m.sip_index[SIP_HDR_CALLID]);

	/* Classify the SDP lines */

	for (i = sip_lines->m.sdp_first; i <= sip_lines->m.sdp_last; i++) {
		ok = csip_classify_sdp(sip_lines, i);
		dp_test_fail_unless(ok, "Failed to classify SDP line %u", i);
	}

	dp_test_fail_unless(sip_lines->lines[19].sdp == SDP_HDR_MEDIA,
			    "Line 19, expected SDP Media");

	dp_test_fail_unless(sip_lines->lines[20].sdp == SDP_HDR_ATTR_RTCP,
			    "Line 20, expected SDP Attr rtcp");

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
		struct csip_line arr[SIP_BSTR_SZ];
	} line_array;

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
	sip_split_and_classify(&orig, sip_lines, "sip6");

	dp_test_fail_unless(sip_lines->m.sip_first == 1,
			    "SIP first, expected 1 got %u",
			    sip_lines->m.sip_first);

	dp_test_fail_unless(sip_lines->m.sip_last == 12,
			    "SIP last, expected 12 got %u",
			    sip_lines->m.sip_last);

	dp_test_fail_unless(sip_lines->m.sdp_first == 14,
			    "SDP first, expected 14 got %u",
			    sip_lines->m.sdp_first);

	dp_test_fail_unless(sip_lines->m.sdp_last == 21,
			    "SDP last, expected 21 got %u",
			    sip_lines->m.sdp_last);

	dp_test_fail_unless(sip_lines->lines[3].type == SIP_LINE_SIP,
			    "Line 3, expected SIP");

	dp_test_fail_unless(sip_lines->lines[3].sip == SIP_HDR_FROM,
			    "Line 3, expected From");

	dp_test_fail_unless(sip_lines->m.sip_index[SIP_HDR_FROM] == 3,
			    "From index, expected 3 got %u",
			    sip_lines->m.sip_index[SIP_HDR_FROM]);

	/*
	 * For each line of orig SIP message, translate the 'From' line and
	 * copy remaining lines into a new buffer.
	 */
	struct bstr oaddr = BSTR_K("1.1.1.2");
	struct bstr oport = BSTR_K("5060");
	struct bstr taddr = BSTR_K("30.30.30.2");
	struct bstr tport = BSTR_K("1024");
	struct csip_line *lines = sip_lines->lines;
	char new_buf[2000];
	struct bstr new;

	/* Create a counted string using new_buf[] storage */
	ok = bstr_attach_unmanaged(&new, new_buf, 0, sizeof(new_buf));
	dp_test_fail_unless(ok, "Failed to create bstr 'new'");

	/*
	 * For all lines (initial line, SIP lines and SDP lines)
	 */
	for (i = 0; i <= sip_lines->m.sdp_last; i++) {

		/* 'From' header line? */
		if (sip_lines->lines[i].type == SIP_LINE_SIP &&
		    sip_lines->lines[i].sip == SIP_HDR_FROM) {
			ok = csip_find_and_translate_uri(&lines[i].b, &new,
							 &oaddr, &oport, &taddr, &tport);
			dp_test_fail_unless(ok, "Failed to translate 'From'");
		} else {
			ok = bstr_addbuf(&new, &lines[i].b);
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

/*
 * sip7. Tests csip_via_find_host_port
 */
DP_DECL_TEST_CASE(cgn_sip, sip7, NULL, NULL);
DP_START_TEST(sip7, test)
{
	struct bstr pre = BSTR_INIT;
	struct bstr host = BSTR_INIT;
	struct bstr port = BSTR_INIT;
	struct bstr post = BSTR_INIT;
	bool ok;

	/* IP addr + port */

	ok = csip_via_find_host_port(BSTRL("Via: SIP/2.0/UDP"
					   " 192.0.2.103:5060;branch=z9hG4bKfw19b\r\n"),
				 &pre, &host, &port, &post);
	dp_test_fail_unless(ok, "Failed to find IP address and port");

	ok = bstr_eq(&pre, BSTRL("Via: SIP/2.0/UDP "));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Pre exp \"%s\" got \"%*.*s\"",
			    "Via: SIP/2.0/UDP ", pre.len, pre.len, pre.buf);

	ok = bstr_eq(&host, BSTRL("192.0.2.103"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Host exp \"%s\" got \"%*.*s\"",
			    "192.0.2.103", host.len, host.len, host.buf);

	ok = bstr_eq(&port, BSTRL("5060"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Port exp \"%s\" got \"%*.*s\"",
			    "5060", port.len, port.len, port.buf);

	ok = bstr_eq(&post, BSTRL(";branch=z9hG4bKfw19b\r\n"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Post exp \"%s\" got \"%*.*s\"",
			    ";branch=z9hG4bKfw19b\r\n",
			    post.len, post.len, post.buf);

	/* IP addr */

	pre = BSTR_INIT;
	host = BSTR_INIT;
	port = BSTR_INIT;
	post = BSTR_INIT;

	ok = csip_via_find_host_port(BSTRL("Via: SIP/2.0/TCP 192.0.2.103;branch=z9hG4bKfw19b\r\n"),
				 &pre, &host, &port, &post);
	dp_test_fail_unless(ok, "Failed to find IP address and port");

	ok = bstr_eq(&pre, BSTRL("Via: SIP/2.0/TCP "));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Pre exp \"%s\" got \"%*.*s\"",
			    "Via: SIP/2.0/TCP ", pre.len, pre.len, pre.buf);

	ok = bstr_eq(&host, BSTRL("192.0.2.103"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Host exp \"%s\" got \"%*.*s\"",
			    "192.0.2.103", host.len, host.len, host.buf);

	dp_test_fail_unless(port.len == 0, "Port len exp 0, got %d", port.len);

	ok = bstr_eq(&post, BSTRL(";branch=z9hG4bKfw19b\r\n"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Post exp \"%s\" got \"%*.*s\"",
			    ";branch=z9hG4bKfw19b\r\n",
			    post.len, post.len, post.buf);
	/* FQDN + port */

	pre = BSTR_INIT;
	host = BSTR_INIT;
	port = BSTR_INIT;
	post = BSTR_INIT;

	ok = csip_via_find_host_port(BSTRL("Via: SIP/2.0/ UDP"
					   " foo.bar.com:65512\r\n"),
				 &pre, &host, &port, &post);
	dp_test_fail_unless(ok, "Failed to find IP address and port");

	ok = bstr_eq(&pre, BSTRL("Via: SIP/2.0/ UDP "));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Pre exp \"%s\" got \"%*.*s\"",
			    "Via: SIP/2.0/ UDP ", pre.len, pre.len, pre.buf);

	ok = bstr_eq(&host, BSTRL("foo.bar.com"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Host exp \"%s\" got \"%*.*s\"",
			    "foo.bar.com", host.len, host.len, host.buf);

	ok = bstr_eq(&port, BSTRL("65512"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Port exp \"%s\" got \"%*.*s\"",
			    "65512", port.len, port.len, port.buf);

	ok = bstr_eq(&post, BSTRL("\r\n"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Post exp \"%s\" got \"%*.*s\"",
			    "\r\n", post.len, post.len, post.buf);

	/* FQDN + port */

	pre = BSTR_INIT;
	host = BSTR_INIT;
	port = BSTR_INIT;
	post = BSTR_INIT;

	ok = csip_via_find_host_port(BSTRL("Via: SIP/2.0/UDP\r\n"
					   " foo.bar.com:65512\r\n"),
				 &pre, &host, &port, &post);
	dp_test_fail_unless(ok, "Failed to find IP address and port");

	ok = bstr_eq(&pre, BSTRL("Via: SIP/2.0/UDP\r\n "));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Pre exp \"%s\" got \"%*.*s\"",
			    "Via: SIP/2.0/UDP\r\n ", pre.len, pre.len, pre.buf);

	ok = bstr_eq(&host, BSTRL("foo.bar.com"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Host exp \"%s\" got \"%*.*s\"",
			    "foo.bar.com", host.len, host.len, host.buf);

	ok = bstr_eq(&port, BSTRL("65512"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Port exp \"%s\" got \"%*.*s\"",
			    "65512", port.len, port.len, port.buf);

	ok = bstr_eq(&post, BSTRL("\r\n"));
	dp_test_fail_unless(ok, "Failed locating IP addr and port, "
			    "Post exp \"%s\" got \"%*.*s\"",
			    "\r\n", post.len, post.len, post.buf);

} DP_END_TEST;

/*
 * Parse Content-Type header.  We interested to know if the sub-type is 'sdp'
 * or not.
 *
 * Note: This could be greatly simplified (albeit with a lack of precision) by
 * simply searching for the string 'sdp' in the line.
 *
 * Format:  "Content-Type: (type)/(subtype)"
 */
static bool csip_parse_sip_content_type(struct bstr const *line, struct bstr *type,
					struct bstr *sub_type)
{
	struct bstr head, tail;

	/* Split on colon after method name */
	if (!bstr_split_term_after(line, ':', &head, &tail))
		return false;

	/*
	 * There may be linear whitespace at the start of tail if there is a
	 * continuation line.  Remove it.
	 */
	bstr_lws_ltrim(&tail);

	/* Split of the '/' between the type and sub-type */
	if (!bstr_split_term_after(&tail, '/', type, &tail))
		return false;

	/* Drop the '/' */
	bstr_drop_right(type, 1);

	/*
	 * At the very least, 'tail' will end with CRLF and we will split on
	 * the CR.  However there might also something line: "sdp; sdp-type=foo",
	 * in which case we will split on the ';'.
	 */
	if (!bstr_split_ascii_non_alpha_before(&tail, sub_type, &tail))
		return false;

	return true;
}

/*
 * sip8.  Parse SIP lines
 */
DP_DECL_TEST_CASE(cgn_sip, sip8, NULL, NULL);
DP_START_TEST(sip8, test)
{
	struct bstr callid;
	bool ok;

	/* Parse Call ID 1 */

	struct bstr line1 = BSTR_K("Call-ID: j2qu348ek2328ws@foo.com\r\n");

	ok = csip_parse_sip_callid(&line1, &callid);
	dp_test_fail_unless(ok, "Failed to parse Call ID in line1");

	ok = bstr_eq(&callid, BSTRL("j2qu348ek2328ws"));
	dp_test_fail_unless(ok, "Call ID ex \"j2qu348ek2328ws\", got \"%*.*s\"",
			    callid.len, callid.len, callid.buf);

	/* Parse Call ID 2 */

	struct bstr line2 = BSTR_K("Call-ID : \r\n j2qu348ek2328wsABC@foo.com\r\n");

	ok = csip_parse_sip_callid(&line2, &callid);
	dp_test_fail_unless(ok, "Failed to parse Call ID in line2");

	/* Call ID should be truncated to CSIP_CALLID_SZ */
	ok = bstr_eq(&callid, BSTRL("j2qu348ek2328wsA"));
	dp_test_fail_unless(ok, "Call ID ex \"j2qu348ek2328wsA\", got \"%*.*s\"",
			    callid.len, callid.len, callid.buf);

	/* Parse Content-Type 1 */

	struct bstr line3 = BSTR_K("Content-Type: application/sdp\r\n");
	struct bstr type = BSTR_INIT, sub_type = BSTR_INIT;

	ok = csip_parse_sip_content_type(&line3, &type, &sub_type);
	dp_test_fail_unless(ok, "Failed to parse Content-Type in line3");

	ok = bstr_eq(&type, BSTRL("application"));
	dp_test_fail_unless(ok, "Content-Type ex \"application\", got \"%*.*s\"",
			    type.len, type.len, type.buf);

	ok = bstr_eq(&sub_type, BSTRL("sdp"));
	dp_test_fail_unless(ok, "Content-Type ex \"sdp\", got \"%*.*s\"",
			    sub_type.len, sub_type.len, sub_type.buf);

	ok = csip_sip_content_type_is_sdp(&line3);
	dp_test_fail_unless(ok, "Failed csip_sip_content_type_is_sdp");

	/* Parse Content-Type 2 */

	struct bstr line4 = BSTR_K("Content-Type: application/sdp; sdp-type=foo\r\n");

	ok = csip_parse_sip_content_type(&line4, &type, &sub_type);
	dp_test_fail_unless(ok, "Failed to parse Content-Type in line4");

	ok = bstr_eq(&type, BSTRL("application"));
	dp_test_fail_unless(ok, "Content-Type ex \"application\", got \"%*.*s\"",
			    type.len, type.len, type.buf);

	ok = bstr_eq(&sub_type, BSTRL("sdp"));
	dp_test_fail_unless(ok, "Content-Type ex \"sdp\", got \"%*.*s\"",
			    sub_type.len, sub_type.len, sub_type.buf);

	/* Parse User-Agent */

	struct bstr line5 = BSTR_K("User-Agent: Csco-SIPGateway/IOS-12.x\r\n");
	struct bstr user_agent = BSTR_INIT;

	ok = csip_parse_sip_user_agent(&line5, &user_agent);
	dp_test_fail_unless(ok, "Failed to parse User-Agent in line5");

	ok = bstr_eq(&user_agent, BSTRL("Csco-SIPGateway/IOS-12.x"));
	dp_test_fail_unless(ok, "User-Agent exp "
			    "\"Csco-SIPGateway/IOS-12.x\", got \"%*.*s\"",
			    user_agent.len, user_agent.len, user_agent.buf);

} DP_END_TEST;
