/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "dp_test_npf_alg_sip_data.h"

/*
 * SIP Data Set #1.
 *
 * Simple SIP Session
 *
 *   Client                                        Rcvr
 *
 *   1.1.1.2                                   22.22.22.2
 *   sip:workman@home.com                B.Boss@work.co.uk
 *   (snat trans addr 30.30.30.2)
 *
 *       |                   INVITE                     |
 *       |--------------------------------------------->|
 *       |                 180 Ringing                  |
 *       |<---------------------------------------------|
 *       |                   200 OK                     |
 *       |<---------------------------------------------|
 *       |                    ACK                       |
 *       |--------------------------------------------->|
 *       |                Media Session                 |
 *       |<============================================>|
 *       |                    BYE                       |
 *       |<---------------------------------------------|
 *       |                  200 OK                      |
 *       |--------------------------------------------->|
 *       |                                              |
 *
 * Notes:
 *
 * The 'From' and 'To' headers are always the same as the INVITE or BYE
 * request that started the msg exchange.  They do *not* always reflect who
 * sent any given message.
 */

/*
 * These data set arrays are purposefully kept very simple.  asserts in the
 * test code ensure they are the same size.
 */
const bool sipd1_dir[SIPD1_SZ] = {
	SIP_FORW, SIP_BACK, SIP_BACK, SIP_FORW, SIP_BACK, SIP_FORW,
};

/*
 * Indicates after which SIP message the data stream should occur (first msg
 * is index 0).
 */
const uint sipd1_rtp_index = 3;

/*
 * SIP messages without any NAT
 */
const char *sipd1[SIPD1_SZ] = {
	/*
	 * 0. Forward. INVITE
	 */
	"INVITE sip:B.Boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:1.1.1.2;lr>\r\n"
	"From: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"To: B.Boss <sip:B.Boss@work.co.uk>\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:workman@1.1.1.2>\r\n"
	"Content-Type: application/sdp\r\n"
	"P-asserted-identity: \"Workman\" <sip:workman@1.1.1.2>\r\n"
	"Max-forwards: 70\r\n"
	"Subject: About That Power Outage...\r\n"
	"Content-Length:   135\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Doe 2890844526 2890844526 IN IP4 1.1.1.2\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 1.1.1.2\r\n"
	"t=0 0\r\n"
	"m=audio 10000 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 1. Back.  180 Ringing
	 */
	"SIP/2.0 180 Ringing\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:22.22.22.2;lr>\r\n"
	"From: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"To: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:boss@22.22.22.2>\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 2. Back. 200 OK
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"From: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"To: B.Boss <sip:boss@work.co.uk>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:boss@22.22.22.2>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length:   144\r\n"
	"\r\n"
	"v=0\r\n"
	"o=B.Boss 2890844528 2890844528 IN IP4 22.22.22.2\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 22.22.22.2\r\n"
	"t=0 0\r\n"
	"m=audio 60000 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 3. Forward. ACK
	 */
	"ACK sip:boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bK321g\r\n"
	"From: A. Workman <sip:workman@home.com>;tag=76341\r\n"
	"To: B.Boss <sip:boss@work.co.uk>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 ACK\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 4. Back: BYE
	 */
	"BYE sip:workman@1.1.1.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 22.22.22.2:5060;branch=z9hG4bK392kf\r\n"
	"From: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"To: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1392 BYE\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 5. Forward. 200 OK
	 *
	 * Record-route
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 22.22.22.2:5060;branch=z9hG4bK392kf\r\n"
	"From: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"To: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1392 BYE\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
};

/*
 * SNAT
 */
const char *sipd1_pre_snat[SIPD1_SZ] = {
	/*
	 * 0. INVITE. Forward (inside)
	 */
	"INVITE sip:B.Boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:1.1.1.2;lr>\r\n"
	"From: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"To: B.Boss <sip:B.Boss@work.co.uk>\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:workman@1.1.1.2>\r\n"
	"Content-Type: application/sdp\r\n"
	"P-asserted-identity: \"Workman\" <sip:workman@1.1.1.2>\r\n"
	"Max-forwards: 70\r\n"
	"Subject: About That Power Outage...\r\n"
	"Content-Length:   139\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Workman 2890844526 2890844526 IN IP4 1.1.1.2\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 1.1.1.2\r\n"
	"t=0 0\r\n"
	"m=audio 10000 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 1. 180 Ringing. Back (outside)
	 */
	"SIP/2.0 180 Ringing\r\n"
	"Via: SIP/2.0/UDP 30.30.30.2:1024;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:22.22.22.2;lr>\r\n"
	"From: A. Workman <sip:workman@30.30.30.2>;tag=76341\r\n"
	"To: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:boss@22.22.22.2>\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 2. 200 OK. Back
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 30.30.30.2:1024;branch=z9hG4bKfw19b\r\n"
	"From: A. Workman <sip:workman@30.30.30.2>;tag=76341\r\n"
	"To: B.Boss <sip:boss@work.co.uk>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:boss@22.22.22.2>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length:   144\r\n"
	"\r\n"
	"v=0\r\n"
	"o=B.Boss 2890844528 2890844528 IN IP4 22.22.22.2\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 22.22.22.2\r\n"
	"t=0 0\r\n"
	"m=audio 60000 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 3. ACK. Forward
	 */
	"ACK sip:boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bK321g\r\n"
	"From: A. Workman <sip:workman@home.com>;tag=76341\r\n"
	"To: B.Boss <sip:boss@work.co.uk>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 ACK\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 4. BYE. Back
	 */
	"BYE sip:workman@30.30.30.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 22.22.22.2:5060;branch=z9hG4bK392kf\r\n"
	"From: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"To: A. Workman <sip:workman@30.30.30.2>;tag=76341\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1392 BYE\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
	/*
	 * 5. Forward
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 22.22.22.2:5060;branch=z9hG4bK392kf\r\n"
	"From: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"To: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1392 BYE\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
};

const char *sipd1_post_snat[SIPD1_SZ] = {
	/*
	 * 0. INVITE. Forward (outside)
	 */
	"INVITE sip:B.Boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 30.30.30.2:1024;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:30.30.30.2;lr>\r\n"
	"From: A. Workman <sip:workman@30.30.30.2>;tag=76341\r\n"
	"To: B.Boss <sip:B.Boss@work.co.uk>\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:workman@30.30.30.2>\r\n"
	"Content-Type: application/sdp\r\n"
	"P-asserted-identity: \"Workman\" <sip:workman@30.30.30.2>\r\n"
	"Max-forwards: 70\r\n"
	"Subject: About That Power Outage...\r\n"
	"Content-Length:   144\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Workman 2890844526 2890844526 IN IP4 30.30.30.2\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 30.30.30.2\r\n"
	"t=0 0\r\n"
	"m=audio 1026 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 1. 180 Ringing. Back (inside)
	 */
	"SIP/2.0 180 Ringing\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"Record-Route: <sip:22.22.22.2;lr>\r\n"
	"From: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"To: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:boss@22.22.22.2>\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 2. 200 OK. Back
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 1.1.1.2:5060;branch=z9hG4bKfw19b\r\n"
	"From: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"To: B.Boss <sip:boss@work.co.uk>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:boss@22.22.22.2>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length:   144\r\n"
	"\r\n"
	"v=0\r\n"
	"o=B.Boss 2890844528 2890844528 IN IP4 22.22.22.2\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 22.22.22.2\r\n"
	"t=0 0\r\n"
	"m=audio 60000 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 3. ACK. Forward
	 */
	"ACK sip:boss@22.22.22.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 30.30.30.2:1024;branch=z9hG4bK321g\r\n"
	"From: A. Workman <sip:workman@home.com>;tag=76341\r\n"
	"To: B.Boss <sip:boss@work.co.uk>;tag=a53e42\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1 ACK\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 4. BYE. Back
	 */
	"BYE sip:workman@1.1.1.2 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 22.22.22.2:5060;branch=z9hG4bK392kf\r\n"
	"From: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"To: A. Workman <sip:workman@1.1.1.2>;tag=76341\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1392 BYE\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 5. 200 OK. Forward
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 22.22.22.2:5060;branch=z9hG4bK392kf\r\n"
	"From: B.Boss <sip:boss@22.22.22.2>;tag=a53e42\r\n"
	"To: A. Workman <sip:workman@30.30.30.2>;tag=76341\r\n"
	"Call-ID: j2qu348ek2328ws\r\n"
	"CSeq: 1392 BYE\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
};

