/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "dp_test_npf_alg_sip_data.h"

/*
 * SIP Invite from 18.33.0.200
 *
 *                              <===== FORWARDS DIR
 *
 *                              +-------+
 * 16.33.0.200      16.33.0.220 |       | 18.33.0.220        18.33.0.200
 * -----------------------------+       +-------------------------------
 *                        dp1T0 |       | dp1T1
 *                              +-------+
 *                                     <----  DNAT, 77.1.1.1    -> 16.33.0.200
 *                                                  16.33.0.200 -> 77.1.1.1
 *
 * SIP Call.  This is taken directly from the pcap of an issue, however the
 * order and format is changed to match the order that the osip library
 * re-writes a SIP packet.
 */

const bool sipd4_dir[SIPD4_SZ] = {
	SIP_FORW, SIP_BACK, SIP_BACK, SIP_BACK, SIP_FORW, SIP_FORW, SIP_BACK
};

/*
 * Indicates after which SIP message the data stream should occur (first msg
 * is index 0).
 */
const uint sipd4_rtp_early_media_index = 3;
const uint sipd4_rtp_media_index = 5;

/*
 * SIP messages pre
 */
const char *sipd4_pre_dnat[SIPD4_SZ] = {
	/* 0. Forward. INVITE (M1) */
	"INVITE sip:5000@77.1.1.1:5060 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@77.1.1.1>\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 INVITE\r\n"
	"Contact: <sip:7777@18.33.0.200:5060>\r\n"
	"Content-Type: application/sdp\r\n"
	"Supported: timer\r\n"
	"Supported: resource-priority\r\n"
	"Supported: replaces\r\n"
	"Supported: sdp-anat\r\n"
	"Min-se: 900\r\n"
	"Cisco-guid: 0640716367-0256512488-2160589700-2994101442\r\n"
	"User-agent: Cisco-SIPGateway/IOS-15.5.3.M1\r\n"
	"Max-forwards: 70\r\n"
	"Timestamp: 1518453580\r\n"
	"Expires: 180\r\n"
	"allow-events: telephone-event\r\n"
	"Content-disposition: session;handling=required\r\n"
	"Content-Length:   279\r\n"
	"\r\n"
	"v=0\r\n"
	"o=CiscoSystemsSIP-GW-UserAgent 4600 9437 IN IP4 18.33.0.200\r\n"
	"s=SIP Call\r\n"
	"c=IN IP4 18.33.0.200\r\n"
	"t=0 0\r\n"
	"m=audio 16440 RTP/AVP 18 100\r\n"
	"c=IN IP4 18.33.0.200\r\n"
	"a=rtpmap:18 G729/8000\r\n"
	"a=fmtp:18 annexb=no\r\n"
	"a=rtpmap:100 telephone-event/8000\r\n"
	"a=fmtp:100 0-16\r\n"
	"a=ptime:30\r\n"
	"a=ptime:30\r\n",

	/* 1. Back. 100 Trying */
	"SIP/2.0 100 Trying\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@16.33.0.200>\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 INVITE\r\n"
	"Timestamp: 1518453580\r\n"
	"allow-events: telephone-event\r\n"
	"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
	"Session-id: 00000000000000000000000000000000;"
	"remote=7121b823d210540b859a0d21af34a724\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/* 2. Back. 183 Session Progress */
	"SIP/2.0 183 Session Progress\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@16.33.0.200>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 INVITE\r\n"
	"Contact: <sip:5000@16.33.0.200:5060>\r\n"
	"Content-Type: application/sdp\r\n"
	"allow-events: telephone-event\r\n"
	"P-asserted-identity: <sip:5000@16.33.0.200>\r\n"
	"Supported: sdp-anat\r\n"
	"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
	"Session-id: a3c87797321e51d085c9b6346ba8c710;"
	"remote=7121b823d210540b859a0d21af34a724\r\n"
	"Content-disposition: session;handling=required\r\n"
	"Content-Length:   253\r\n"
	"\r\n"
	"v=0\r\n"
	"o=CiscoSystemsSIP-GW-UserAgent 4551 177 IN IP4 16.33.0.200\r\n"
	"s=SIP Call\r\n"
	"c=IN IP4 16.33.0.200\r\n"
	"t=0 0\r\n"
	"m=audio 8038 RTP/AVP 18 100\r\n"
	"c=IN IP4 16.33.0.200\r\n"
	"a=rtpmap:18 G729/8000\r\n"
	"a=fmtp:18 annexb=no\r\n"
	"a=rtpmap:100 telephone-event/8000\r\n"
	"a=fmtp:100 0-16\r\n",

	/* 3. Back. 200 OK */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@16.33.0.200>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 INVITE\r\n"
	"Contact: <sip:5000@16.33.0.200:5060>\r\n"
	"Content-Type: application/sdp\r\n"
	"allow-events: telephone-event\r\n"
	/* Not translated, but not expected to be? */
	"P-asserted-identity: <sip:5000@16.33.0.200>\r\n"
	"Supported: replaces\r\n"
	"Supported: sdp-anat\r\n"
	"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
	"Session-id: a3c87797321e51d085c9b6346ba8c710;"
	"remote=7121b823d210540b859a0d21af34a724\r\n"
	"Supported: timer\r\n"
	"Content-disposition: session;handling=required\r\n"
	"Content-Length:   253\r\n"
	"\r\n"
	"v=0\r\n"
	/* Not translated, but not expected to be? */
	"o=CiscoSystemsSIP-GW-UserAgent 4551 177 IN IP4 16.33.0.200\r\n"
	"s=SIP Call\r\n"
	"c=IN IP4 16.33.0.200\r\n"
	"t=0 0\r\n"
	"m=audio 8038 RTP/AVP 18 100\r\n"
	"c=IN IP4 16.33.0.200\r\n"
	"a=rtpmap:18 G729/8000\r\n"
	"a=fmtp:18 annexb=no\r\n"
	"a=rtpmap:100 telephone-event/8000\r\n"
	"a=fmtp:100 0-16\r\n",

	/* 4. Forw. ACK */
	"ACK sip:5000@77.1.1.1:5060 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK26CF6\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@77.1.1.1>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 ACK\r\n"
	"Max-forwards: 70\r\n"
	"allow-events: telephone-event\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/* 5. Forw. BYE. */
	"BYE sip:5000@77.1.1.1:5060 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2740D\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@77.1.1.1>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 102 BYE\r\n"
	"User-agent: Cisco-SIPGateway/IOS-15.5.3.M1\r\n"
	"Max-forwards: 70\r\n"
	"Timestamp: 1518453588\r\n"
	"Reason: Q.850;cause=16\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/* 6. Back. 200 ACK */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2740D\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@16.33.0.200>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 102 BYE\r\n"
	"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
	"Timestamp: 1518453588\r\n"
	"Reason: Q.850;cause=16\r\n"
	"Session-id: 7121b823d210540b859a0d21af34a724;"
	"remote=a3c87797321e51d085c9b6346ba8c710\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
};

/*
 * SIP messages post
 */
const char *sipd4_post_dnat[SIPD4_SZ] = {
	/* 0. Forward. INVITE (M1) */
	"INVITE sip:5000@16.33.0.200:5060 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@16.33.0.200>\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 INVITE\r\n"
	"Contact: <sip:7777@18.33.0.200:5060>\r\n"
	"Content-Type: application/sdp\r\n"
	"Supported: timer\r\n"
	"Supported: resource-priority\r\n"
	"Supported: replaces\r\n"
	"Supported: sdp-anat\r\n"
	"Min-se: 900\r\n"
	"Cisco-guid: 0640716367-0256512488-2160589700-2994101442\r\n"
	"User-agent: Cisco-SIPGateway/IOS-15.5.3.M1\r\n"
	"Max-forwards: 70\r\n"
	"Timestamp: 1518453580\r\n"
	"Expires: 180\r\n"
	"allow-events: telephone-event\r\n"
	"Content-disposition: session;handling=required\r\n"
	"Content-Length:   279\r\n"
	"\r\n"
	"v=0\r\n"
	"o=CiscoSystemsSIP-GW-UserAgent 4600 9437 IN IP4 18.33.0.200\r\n"
	"s=SIP Call\r\n"
	"c=IN IP4 18.33.0.200\r\n"
	"t=0 0\r\n"
	"m=audio 16440 RTP/AVP 18 100\r\n"
	"c=IN IP4 18.33.0.200\r\n"
	"a=rtpmap:18 G729/8000\r\n"
	"a=fmtp:18 annexb=no\r\n"
	"a=rtpmap:100 telephone-event/8000\r\n"
	"a=fmtp:100 0-16\r\n"
	"a=ptime:30\r\n"
	"a=ptime:30\r\n",

	/* 1. Back. 100 Trying */
	"SIP/2.0 100 Trying\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@77.1.1.1>\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 INVITE\r\n"
	"Timestamp: 1518453580\r\n"
	"allow-events: telephone-event\r\n"
	"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
	"Session-id: 00000000000000000000000000000000;"
	"remote=7121b823d210540b859a0d21af34a724\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/* 2. Back. 183 Session Progress */
	"SIP/2.0 183 Session Progress\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@77.1.1.1>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 INVITE\r\n"
	"Contact: <sip:5000@77.1.1.1:5060>\r\n"
	"Content-Type: application/sdp\r\n"
	"allow-events: telephone-event\r\n"
	"P-asserted-identity: <sip:5000@16.33.0.200>\r\n"
	"Supported: sdp-anat\r\n"
	"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
	"Session-id: a3c87797321e51d085c9b6346ba8c710;"
	"remote=7121b823d210540b859a0d21af34a724\r\n"
	"Content-disposition: session;handling=required\r\n"
	"Content-Length:   247\r\n"
	"\r\n"
	"v=0\r\n"
	/* Not translated, but not expected to be? */
	"o=CiscoSystemsSIP-GW-UserAgent 4551 177 IN IP4 16.33.0.200\r\n"
	"s=SIP Call\r\n"
	"c=IN IP4 77.1.1.1\r\n"
	"t=0 0\r\n"
	"m=audio 8038 RTP/AVP 18 100\r\n"
	"c=IN IP4 77.1.1.1\r\n"
	"a=rtpmap:18 G729/8000\r\n"
	"a=fmtp:18 annexb=no\r\n"
	"a=rtpmap:100 telephone-event/8000\r\n"
	"a=fmtp:100 0-16\r\n",

	/* 3. Back. 200 OK */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@77.1.1.1>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 INVITE\r\n"
	"Contact: <sip:5000@77.1.1.1:5060>\r\n"
	"Content-Type: application/sdp\r\n"
	"allow-events: telephone-event\r\n"
	/* Not translated, but not expected to be */
	"P-asserted-identity: <sip:5000@16.33.0.200>\r\n"
	"Supported: replaces\r\n"
	"Supported: sdp-anat\r\n"
	"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
	"Session-id: a3c87797321e51d085c9b6346ba8c710;"
	"remote=7121b823d210540b859a0d21af34a724\r\n"
	"Supported: timer\r\n"
	"Content-disposition: session;handling=required\r\n"
	"Content-Length:   247\r\n"
	"\r\n"
	"v=0\r\n"
	/* Not translated, but not expected to be */
	"o=CiscoSystemsSIP-GW-UserAgent 4551 177 IN IP4 16.33.0.200\r\n"
	"s=SIP Call\r\n"
	"c=IN IP4 77.1.1.1\r\n"
	"t=0 0\r\n"
	"m=audio 8038 RTP/AVP 18 100\r\n"
	"c=IN IP4 77.1.1.1\r\n"
	"a=rtpmap:18 G729/8000\r\n"
	"a=fmtp:18 annexb=no\r\n"
	"a=rtpmap:100 telephone-event/8000\r\n"
	"a=fmtp:100 0-16\r\n",

	/* 4. Forw. ACK */
	"ACK sip:5000@16.33.0.200:5060 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK26CF6\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@16.33.0.200>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 101 ACK\r\n"
	"Max-forwards: 70\r\n"
	"allow-events: telephone-event\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/* 5. Forw. BYE. */
	"BYE sip:5000@16.33.0.200:5060 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2740D\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@16.33.0.200>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 102 BYE\r\n"
	"User-agent: Cisco-SIPGateway/IOS-15.5.3.M1\r\n"
	"Max-forwards: 70\r\n"
	"Timestamp: 1518453588\r\n"
	"Reason: Q.850;cause=16\r\n"
	"Content-Length: 0\r\n"
	"\r\n",

	/* 6. Back. 200 OK */
	"SIP/2.0 200 OK\r\n"
	"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2740D\r\n"
	"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
	"To: <sip:5000@77.1.1.1>;tag=757787AF-E66\r\n"
	"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
	"CSeq: 102 BYE\r\n"
	"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
	"Timestamp: 1518453588\r\n"
	"Reason: Q.850;cause=16\r\n"
	"Session-id: 7121b823d210540b859a0d21af34a724;"
	"remote=a3c87797321e51d085c9b6346ba8c710\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
};
