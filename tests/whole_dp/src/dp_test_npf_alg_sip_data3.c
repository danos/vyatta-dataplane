/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "dp_test_npf_alg_sip_data.h"

/*
 * SIP Data Set #3.  SIP to PSTN Call Through Gateway
 *
 * (only Caller to GW messages are shown)
 *
 *  SIP Caller                                   SIP/PSTN Gateway
 *  8.19.19.6                                    50.60.70.80
 *
 *
 *    |                    INVITE (M1)                   |
 *    |------------------------------------------------->|  IAM (M2)
 *    |                                                  |----------->
 *    |                                                  |  ACM (M3)
 *    |               183 Session Progress (M4)          |<-----------
 *    |<-------------------------------------------------|
 *    |                    PRACK (M5)                    |
 *    |------------------------------------------------->|
 *    |                    200 OK (M6)                   |
 *    |<-------------------------------------------------|  ring tone
 *    |                  RTP Early Media (one way)       |<------------
 *    |<=================================================|  ANM (M7)
 *    |                    200 OK (M8)                   |<------------
 *    |<-------------------------------------------------|
 *    |                      ACK (M9)                    |
 *    |------------------------------------------------->|
 *    |                     RTP Media (speech)           |
 *    |<================================================>|
 *    |                     BYE (M10)                    |
 *    |------------------------------------------------->|  REL (M11)
 *    |                    200 OK (M12)                  |----------->
 *    |<-------------------------------------------------|  RLC (M13)
 *    |                                                  |<-----------
 *    |                                                  |
 *
 *
 * Calls from SIP to the PSTN through a gateway often make use of early
 * media. Early media is RTP media sent prior to the call being answered.
 *
 * In SIP, this means media sent prior to the 200 OK response. This is usually
 * done in SIP by the gateway sending a 183 Session Progress response, which
 * creates an early dialog. RTP media is then sent from the gateway to the
 * UA. Often early media carries special ringback tones to recorded
 * announcements and tones.
 *
 * The call completes when the called party answers the telephone, which
 * causes the telephone switch to send an answer message (ANM) to the gateway.
 * The gateway then cuts the PSTN audio connection through in both directions
 * and sends a 200 OK response to the caller. Because the RTP media path is
 * already established, the gateway echoes the SDP in the 183 but causes no
 * changes to the RTP connection.
 */

/*
 * These data set arrays are purposefully kept very simple.  asserts in the
 * test code ensure they are the same size.
 */
const bool sipd3_dir[SIPD3_SZ] = {
	SIP_FORW, SIP_BACK, SIP_FORW, SIP_BACK, SIP_BACK, SIP_FORW,
	SIP_FORW, SIP_BACK
};

/*
 * Indicates after which SIP message the data stream should occur (first msg
 * is index 0).
 */
const uint sipd3_rtp_early_media_index = 3;
const uint sipd3_rtp_media_index = 5;

/*
 * SIP messages pre
 */
const char *sipd3_pre_snat[SIPD3_SZ] = {
	/*
	 * 0. Forward. INVITE (M1)
	 */
	"INVITE sip:+12025551313@test.org;user=phone SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK4545\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:john.doe@studio.example.com>\r\n"
	"Content-Type: application/sdp\r\n"
	"Supported: 100rel\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length:   153\r\n"
	"\r\n"
	"v=0\r\n"
	"o=FF 2890844535 2890844535 IN IP4 8.19.19.6\r\n"
	"s=-\r\n"
	"c=IN IP4 8.19.19.6\r\n"
	"t=0 0\r\n"
	"m=audio 50004 RTP/AVP 0 8\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:8 PCMA/8000\r\n",

	/*
	 * 1. Back. 183 Session Progress (M4)
	 */
	"SIP/2.0 183 Session Progress\r\n"
	"Via: SIP/2.0/UDP 50.60.70.1:5060;branch=z9hG4bK4545\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:50.60.70.80>\r\n"
	"Content-Type: application/sdp\r\n"
	"Rseq: 08071\r\n"
	"Content-Length:   139\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Port1723 2890844535 2890844535 IN IP4 50.60.70.80\r\n"
	"s=-\r\n"
	"c=IN IP4 50.60.70.80\r\n"
	"t=0 0\r\n"
	"m=audio 62002 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 2. Forw. PRACK (M5)
	 */
	"PRACK sip:50.60.70.80 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK454\r\n"
	"From: <sip:john.doe@example.com>;tag=37\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=12\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 2 PRACK\r\n"
	"Contact: <sip:john.doe@studio.example.com>\r\n"
	"Max-forwards: 70\r\n"
	"Rack: 08071 1 INVITE\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 3. Back. 200 OK (M6)
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 50.60.70.1:5060;branch=z9hG4bK4545\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:50.60.70.80>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length:   139\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Port1723 2890844535 2890844535 IN IP4 50.60.70.80\r\n"
	"s=-\r\n"
	"c=IN IP4 50.60.70.80\r\n"
	"t=0 0\r\n"
	"m=audio 62002 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*===== RTP Early Media (one way) =====*/

	/*
	 * 4. Back. 200 OK (M8)
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 50.60.70.1:5060;branch=z9hG4bK4545\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:50.60.70.80>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length:   139\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Port1723 2890844535 2890844535 IN IP4 50.60.70.80\r\n"
	"s=-\r\n"
	"c=IN IP4 50.60.70.80\r\n"
	"t=0 0\r\n"
	"m=audio 62002 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 5. Forw. ACK (M9)
	 */
	"ACK sip:50.60.70.80 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bKfgrw\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 ACK\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*===== RTP Media (speech) =====*/

	/*
	 * 6. Forw. BYE (M10)
	 */
	"BYE sip:50.60.70.80 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK321\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 3 BYE\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 7. Back. 200 OK (M12)
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 50.60.70.1:5060;branch=z9hG4bK321\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 3 BYE\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
};

/*
 * SIP messages post
 */
const char *sipd3_post_snat[SIPD3_SZ] = {
	/*
	 * 0. Forward. INVITE (M1)
	 */
	"INVITE sip:+12025551313@test.org;user=phone SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 50.60.70.1:5060;branch=z9hG4bK4545\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:john.doe@studio.example.com>\r\n"
	"Content-Type: application/sdp\r\n"
	"Supported: 100rel\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length:   155\r\n"
	"\r\n"
	"v=0\r\n"
	"o=FF 2890844535 2890844535 IN IP4 50.60.70.1\r\n"
	"s=-\r\n"
	"c=IN IP4 50.60.70.1\r\n"
	"t=0 0\r\n"
	"m=audio 50004 RTP/AVP 0 8\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"a=rtpmap:8 PCMA/8000\r\n",

	/*
	 * 1. Back. 183 Session Progress (M4)
	 */
	"SIP/2.0 183 Session Progress\r\n"
	"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK4545\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:50.60.70.80>\r\n"
	"Content-Type: application/sdp\r\n"
	"Rseq: 08071\r\n"
	"Content-Length:   139\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Port1723 2890844535 2890844535 IN IP4 50.60.70.80\r\n"
	"s=-\r\n"
	"c=IN IP4 50.60.70.80\r\n"
	"t=0 0\r\n"
	"m=audio 62002 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 2. Forw. PRACK (M5)
	 */
	"PRACK sip:50.60.70.80 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 50.60.70.1:5060;branch=z9hG4bK454\r\n"
	"From: <sip:john.doe@example.com>;tag=37\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=12\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 2 PRACK\r\n"
	"Contact: <sip:john.doe@studio.example.com>\r\n"
	"Max-forwards: 70\r\n"
	"Rack: 08071 1 INVITE\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 3. Back. 200 OK (M6)
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK4545\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:50.60.70.80>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length:   139\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Port1723 2890844535 2890844535 IN IP4 50.60.70.80\r\n"
	"s=-\r\n"
	"c=IN IP4 50.60.70.80\r\n"
	"t=0 0\r\n"
	"m=audio 62002 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*===== RTP Early Media (one way) =====*/

	/*
	 * 4. Back. 200 OK (M8)
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK4545\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 INVITE\r\n"
	"Contact: <sip:50.60.70.80>\r\n"
	"Content-Type: application/sdp\r\n"
	"Content-Length:   139\r\n"
	"\r\n"
	"v=0\r\n"
	"o=Port1723 2890844535 2890844535 IN IP4 50.60.70.80\r\n"
	"s=-\r\n"
	"c=IN IP4 50.60.70.80\r\n"
	"t=0 0\r\n"
	"m=audio 62002 RTP/AVP 0\r\n"
	"a=rtpmap:0 PCMU/8000\r\n",

	/*
	 * 5. Forw. ACK (M9)
	 */
	"ACK sip:50.60.70.80 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 50.60.70.1:5060;branch=z9hG4bKfgrw\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 1 ACK\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*===== RTP Media (speech) =====*/

	/*
	 * 6. Forw. BYE (M10)
	 */
	"BYE sip:50.60.70.80 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 50.60.70.1:5060;branch=z9hG4bK321\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 3 BYE\r\n"
	"Max-forwards: 70\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/*
	 * 7. Back. 200 OK (M12)
	 */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK321\r\n"
	"From: <sip:john.doe@example.com>;tag=12\r\n"
	"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
	"Call-ID: 49235243082018498\r\n"
	"CSeq: 3 BYE\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
};

