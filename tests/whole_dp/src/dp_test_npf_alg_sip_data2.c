/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "dp_test_npf_alg_sip_data.h"

/*
 * SIP Data Set #2.  (uut is between Caller and Proxy server)
 *
 *
 * Caller                          Proxy Server                     Callee
 * 100.101.102.103                 200.201.202.205          200.201.202.203
 *
 *    |            INVITE (M1)         |
 *    |----[uut]---------------------->|               INVITE (M2)
 *    |                                |-------------------------------->|
 *    |                                |            180 Ringing (M3)     |
 *    |            180 Ringing (M4)    |<--------------------------------|
 *    |<---[uut]-----------------------|                                 |
 *    |                                |              200 OK (M5)        |
 *    |              200 OK (M6)       |<--------------------------------|
 *    |<---[uut]-----------------------|                                 |
 *    |                                                                  |
 *    |                               ACK (M7)                           |
 *    |----[uut]-------------------------------------------------------->|
 *    |                           Media Session                          |
 *    |<===[uut]========================================================>|
 *    |                               BYE (M8)                           |
 *    |<---[uut]---------------------------------------------------------|
 *    |                              200 OK (M9)                         |
 *    |----[uut]-------------------------------------------------------->|
 *    |                                                                  |
 *
 * Note: with SNAT, ACK (M7) will create a new session.
 */

/*
 * These data set arrays are purposefully kept very simple.  asserts in the
 * test code ensure they are the same size.
 */
const bool sipd2_dir[SIPD2_SZ] = {
	SIP_FORW, SIP_BACK, SIP_BACK, SIP_FORW, SIP_BACK, SIP_FORW
};

/*
 * Indicates after which SIP message the data stream should occur (first msg
 * is index 0).
 */
const uint sipd2_rtp_index = 3;

/*
 * SIP messages without any NAT
 */
const char *sipd2[SIPD2_SZ] = {
	/*
	 * 0. Forward. INVITE (M1)
	 */
	"INVITE sip:joe.bloggs@200.201.202.203 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
	"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
	"To: Bloggs <sip:joe.bloggs@200.201.202.203>\r\n"
	"Call-ID: 4827311-391-32934\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:doe123@pc33.example.com>\r\n"
	"Content-Type: application/sdp\r\n"
	"Max-forwards: 70\r\n"
	"Subject: Where are you exactly?\r\n"
	"Content-Length:   154\r\n"
	"\r\n"
	"v=0\r\n"
	"o=doe123 2890844526 2890844526 IN IP4 100.101.102.103\r\n"
	"s=Phone Call\r\n"
	"c=IN IP4 100.101.102.103\r\n"
	"t=0 0\r\n"
	"m=audio 10000 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 1. Back. 180 RINGING (M4)
	 */
	"SIP/2.0 180 Ringing\r\n"
	"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
	"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
	"To: Bloggs <sip:joe.bloggs@200.201.202.203>;"
	"tag=314159\r\n"
	"Call-ID: 4827311-391-32934\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:joe.bloggs@200.201.202.203>\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 2. Back. 200 OK (M6)
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
	"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
	"To: Bloggs <sip:joe.bloggs@200.201.202.203>;"
	"tag=314159\r\n"
	"Call-ID: 4827311-391-32934\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:joe.bloggs@200.201.202.203>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length:   154\r\n"
	"\r\n"
	"v=0\r\n"
	"o=bloggs 2890844526 2890844526 IN IP4 200.201.202.203\r\n"
	"s=phone call\r\n"
	"c=IN IP4 200.201.202.203\r\n"
	"t=0 0\r\n"
	"m=audio 60000 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 3. Forw. ACK (M7).  Caller to Callee.
	 */
	"ACK sip:joe.bloggs@200.201.202.203 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKka42\r\n"
	"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
	"To: Bloggs <sip:joe.bloggs@200.201.202.203>;"
	"tag=314159\r\n"
	"Call-ID: 4827311-391-32934\r\n"
	"CSeq: 1 ACK\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/* Data flow occurs here */

	/*
	 * 4. Back. BYE (M8)
	 */
	"BYE sip:doe123@pc33.example.com SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 200.201.202.203:5060;branch=z9hG4bK4332\r\n"
	"From: Bloggs <sip:joe.bloggs@200.201.202.203>;"
	"tag=314159\r\n"
	"To: J. Doe <sip:doe123@example.com>;tag=42\r\n"
	"Call-ID: 4827311-391-32934\r\n"
	"CSeq: 2000 BYE\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 5. Forw. 200 OK (M9)
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 200.201.202.203:5060;branch=z9hG4bK4332\r\n"
	"From: Bloggs <sip:joe.bloggs@200.201.202.203>;"
	"tag=314159\r\n"
	"To: J. Doe <sip:doe123@example.com>;tag=42\r\n"
	"Call-ID: 4827311-391-32934\r\n"
	"CSeq: 2000 BYE\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
};
