/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane SIP ALG tests for SIP Proxy configuration
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_str.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_alg_lib.h"
#include "dp_test_npf_alg_sip_lib.h"
#include "dp_test_npf_alg_sip_call.h"

/*
 * sip2_1 - No NAT config.
 * sip2_2 - SNAT masquerade.
 * sip2_3 - SNAT masquerade.  Initial RTP pkt in reverse direction.
 * sip2_4 - SNAT masquerade.  Random source port from proxy server.
 */

static void dpt_alg_sip_setup(void);
static void dpt_alg_sip_teardown(void);

DP_DECL_TEST_SUITE(npf_sip2);

/*
 * SIP Call with a Proxy Server
 *
 * Caller                          Proxy Server                     Callee
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
 * For ease of test setup, the address of the proxy server will either be
 * 100.101.102.105 or 200.201.202.205 dependent on the position of the UUT.
 *
 *
 * SNAT Notes:
 *
 * 1. We correctly setup the media tuples using the media connection
 * information ("c=") in the SDP message body, therefore the RTP and RTCP
 * session are correctly established regardless of the direction of the
 * initial media packet.
 *
 * 2. SNAT works for non-media messages between the User Agents (Doe
 * and Bloggs) because the ACK (M7) message creates a new NAT session
 * (trans port 5061) for the UA-to-UA SIP *forwards* packet flow, thus
 * allowing the BYE (M9) message in the reverse direction.
 *
 */

static struct dp_test_sip_pkt_t sip_call[] = {
	{
		.descr = "INVITE (M1)",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_PRE_PROXY,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"INVITE sip:joe.bloggs@test.org SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
		"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"To: Bloggs <sip:joe.bloggs@test.org>\r\n"
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
		"a=rtpmap:0 PCMU/8000\r\n"
	},

	{
		.descr = "INVITE (M2)",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_POST_PROXY,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"INVITE sip:joe.bloggs@200.201.202.203 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP proxy.test.org:5060;"
		"branch=z9hG4bK83842.1\r\n"
		"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
		"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"To: Bloggs <sip:joe.bloggs@test.org>\r\n"
		"Call-ID: 4827311-391-32934\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:doe123@pc33.example.com>\r\n"
		"Content-Type: application/sdp\r\n"
		"Max-forwards: 69\r\n"
		"Subject: Where are you exactly?\r\n"
		"Content-Length:   159\r\n"
		"\r\n"
		"v=0\r\n"
		"o=doe123 2890844526 2890844526 IN IP4 100.101.102.103\r\n"
		"s=Phone Call\r\n"
		"c=IN IP4 100.101.102.103\r\n"
		"t=0 0\r\n"
		"m=audio 10000 RTP/AVP 0\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
	},

	{
		.descr = "180 RINGING (M3)",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_POST_PROXY,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 180 Ringing\r\n"
		"Via: SIP/2.0/UDP proxy.test.org:5060;branch=z9hG4bK83842.1;"
		"received=200.201.202.205\r\n"
		"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
		"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"To: Bloggs <sip:joe.bloggs@test.org>;"
		"tag=314159\r\n"
		"Call-ID: 4827311-391-32934\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:joe.bloggs@200.201.202.203>\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},

	{
		.descr = "180 RINGING (M4)",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_PRE_PROXY,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 180 Ringing\r\n"
		"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
		"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"To: Bloggs <sip:joe.bloggs@test.org>;"
		"tag=314159\r\n"
		"Call-ID: 4827311-391-32934\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:joe.bloggs@200.201.202.203>\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},

	{
		.descr = "200 OK (M5)",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_POST_PROXY,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP proxy.test.org:5060;branch=z9hG4bK83842.1;"
		"received=200.201.202.205\r\n"
		"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
		"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"To: Bloggs <sip:joe.bloggs@test.org>;"
		"tag=314159\r\n"
		"Call-ID: 4827311-391-32934\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:joe.bloggs@200.201.202.203>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length:   154\r\n"
		"\r\n"
		"v=0\r\n"
		"o=bloggs 2890844526 2890844526 IN IP4 200.201.202.203\r\n"
		"s=Phone Call\r\n"
		"c=IN IP4 200.201.202.203\r\n"
		"t=0 0\r\n"
		"m=audio 60000 RTP/AVP 0\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
	},

	{
		.descr = "200 OK (M6)",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_PRE_PROXY,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKmp17a\r\n"
		"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"To: Bloggs <sip:joe.bloggs@test.org>;"
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
		"a=rtpmap:0 PCMU/8000\r\n"
	},

	{
		.descr = "ACK (M7)",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"ACK sip:joe.bloggs@200.201.202.203 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKka42\r\n"
		"From: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"To: Bloggs <sip:joe.bloggs@test.org>;"
		"tag=314159\r\n"
		"Call-ID: 4827311-391-32934\r\n"
		"CSeq: 1 ACK\r\n"
		"Max-forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},

	{
		.descr = "BYE (M8)",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = true,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"BYE sip:doe123@pc33.example.com SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 200.201.202.203:5060;branch=z9hG4bK4332\r\n"
		"From: Bloggs <sip:joe.bloggs@test.org>;"
		"tag=314159\r\n"
		"To: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"Call-ID: 4827311-391-32934\r\n"
		"CSeq: 2000 BYE\r\n"
		"Max-forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},

	{
		.descr = "200 OK (M9)",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 200.201.202.203:5060;branch=z9hG4bK4332\r\n"
		"From: Bloggs <sip:joe.bloggs@test.org>;"
		"tag=314159\r\n"
		"To: J. Doe <sip:doe123@example.com>;tag=42\r\n"
		"Call-ID: 4827311-391-32934\r\n"
		"CSeq: 2000 BYE\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	}
};


/*
 * sip2_1 - SIP call. No NAT config.
 */
DP_DECL_TEST_CASE(npf_sip2, sip2_1, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip2_1, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 5060,
		dp1T0_mac, "200.201.202.205", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "100.101.102.103", 5060,
		"aa:bb:cc:18:0:5", "200.201.202.205", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:5", "200.201.202.205", 5060,
		dp2T1_mac, "100.101.102.103", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "200.201.202.205", 5060,
		"aa:bb:cc:16:0:20", "100.101.102.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP caller to proxy (M1, M4, M6).
	 *
	 * We loop through the first 6 msgs in the array, but only send 3 of
	 * them, i.e. the ones labelled DP_TEST_SIP_LOC_PRE_PROXY.
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 5,
			 DP_TEST_SIP_LOC_PRE_PROXY,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	/*
	 * Remainder of msgs are between caller and callee, bypassing the
	 * proxy.
	 */
	ins_pre->l3_dst = "200.201.202.203";
	ins_post->l3_dst = "200.201.202.203";
	ins_post->l2_dst = "aa:bb:cc:18:0:1";

	outs_pre->l3_src = "200.201.202.203";
	outs_pre->l2_src = "aa:bb:cc:18:0:1";
	outs_post->l3_src = "200.201.202.203";

	/*
	 * SIP caller to callee (M7).
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 6, 6,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"100.101.102.103", 10000, "200.201.202.203", 60000,
		"100.101.102.103", 10000, "200.201.202.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"200.201.202.203", 60000, "100.101.102.103", 10000,
		"200.201.202.203", 60000, "100.101.102.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call end.  caller to callee (M8, M9).
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 7, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

} DP_END_TEST;


/*
 * sip2_2 - SIP call. SNAT masquerade.
 */
DP_DECL_TEST_CASE(npf_sip2, sip2_2, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip2_2, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "100.101.102.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 200.201.202.1 */
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 5060,
		dp1T0_mac, "200.201.202.205", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "200.201.202.1", 5060,
		"aa:bb:cc:18:0:5", "200.201.202.205", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:5", "200.201.202.205", 5060,
		dp2T1_mac, "200.201.202.1", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "200.201.202.205", 5060,
		"aa:bb:cc:16:0:20", "100.101.102.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP caller to proxy (M1, M4, M6).
	 *
	 * We loop through the first 6 msgs in the array, but only send 3 of
	 * them, i.e. the ones labelled DP_TEST_SIP_LOC_PRE_PROXY.
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 5,
			 DP_TEST_SIP_LOC_PRE_PROXY,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * Remainder of msgs are between caller and callee, bypassing the
	 * proxy.
	 */
	ins_pre->l3_dst = "200.201.202.203";
	ins_post->l3_dst = "200.201.202.203";
	ins_post->l2_dst = "aa:bb:cc:18:0:1";

	outs_pre->l3_src = "200.201.202.203";
	outs_pre->l2_src = "aa:bb:cc:18:0:1";
	outs_post->l3_src = "200.201.202.203";

	/*
	 * SIP caller to callee (M7).
	 */
	/*
	 * The destination address of M7 is different, so a new SNAT session
	 * is created with trans port 5061.  Therefore need to change the Via
	 * port to 5061 in ACK (M7)
	 *
	 * "Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKka42\r\n"
	 */
	dp_test_sip_pkt_via_replace_str(&sip_call[6], "5060", "5061");

	ins_post->l4.udp.sport = 5061;
	outs_pre->l4.udp.dport = 5061;

	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 6, 6,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"100.101.102.103", 10000, "200.201.202.203", 60000,
		"200.201.202.1", 10000, "200.201.202.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"200.201.202.203", 60000, "200.201.202.1", 10000,
		"200.201.202.203", 60000, "100.101.102.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call end.  caller to callee (M8, M9).
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 7, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

} DP_END_TEST;


/*
 * sip2_3 - SIP call. SNAT masquerade.  Initial RTP pkt in reverse direction.
 */
DP_DECL_TEST_CASE(npf_sip2, sip2_3, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip2_3, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "100.101.102.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 200.201.202.1 */
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 5060,
		dp1T0_mac, "200.201.202.205", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "200.201.202.1", 5060,
		"aa:bb:cc:18:0:5", "200.201.202.205", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:5", "200.201.202.205", 5060,
		dp2T1_mac, "200.201.202.1", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "200.201.202.205", 5060,
		"aa:bb:cc:16:0:20", "100.101.102.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP caller to proxy (M1, M4, M6).
	 *
	 * We loop through the first 6 msgs in the array, but only send 3 of
	 * them, i.e. the ones labelled DP_TEST_SIP_LOC_PRE_PROXY.
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 5,
			 DP_TEST_SIP_LOC_PRE_PROXY,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * Remainder of msgs are between caller and callee, bypassing the
	 * proxy.
	 */
	ins_pre->l3_dst = "200.201.202.203";
	ins_post->l3_dst = "200.201.202.203";
	ins_post->l2_dst = "aa:bb:cc:18:0:1";

	outs_pre->l3_src = "200.201.202.203";
	outs_pre->l2_src = "aa:bb:cc:18:0:1";
	outs_post->l3_src = "200.201.202.203";

	/*
	 * SIP caller to callee (M7).
	 */
	/*
	 * The destination address of M7 is different, so a new SNAT session
	 * is created with trans port 5061.  Therefore need to change the Via
	 * port to 5061 in ACK (M7)
	 *
	 * "Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKka42\r\n"
	 */
	dp_test_sip_pkt_via_replace_str(&sip_call[6], "5060", "5061");

	ins_post->l4.udp.sport = 5061;
	outs_pre->l4.udp.dport = 5061;

	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 6, 6,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	/* RTP Back (Initial) */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"200.201.202.203", 60000, "200.201.202.1", 10000,
		"200.201.202.203", 60000, "100.101.102.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/* RTP Forw */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"100.101.102.103", 10000, "200.201.202.203", 60000,
		"200.201.202.1", 10000, "200.201.202.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call end.  caller to callee (M8, M9).
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 7, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

} DP_END_TEST;


/*
 * sip2_4 - SIP call. SNAT masquerade.  Random source port from proxy server.
 */
DP_DECL_TEST_CASE(npf_sip2, sip2_4, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip2_4, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "100.101.102.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 200.201.202.1 */
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 5060,
		dp1T0_mac, "200.201.202.205", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "200.201.202.1", 5060,
		"aa:bb:cc:18:0:5", "200.201.202.205", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:5", "200.201.202.205", 64232,
		dp2T1_mac, "200.201.202.1", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "200.201.202.205", 64232,
		"aa:bb:cc:16:0:20", "100.101.102.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP caller to proxy (M1, M4, M6).
	 *
	 * We loop through the first 6 msgs in the array, but only send 3 of
	 * them, i.e. the ones labelled DP_TEST_SIP_LOC_PRE_PROXY.
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 5,
			 DP_TEST_SIP_LOC_PRE_PROXY,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * Remainder of msgs are between caller and callee, bypassing the
	 * proxy.
	 */
	ins_pre->l3_dst = "200.201.202.203";
	ins_post->l3_dst = "200.201.202.203";
	ins_post->l2_dst = "aa:bb:cc:18:0:1";

	outs_pre->l3_src = "200.201.202.203";
	outs_pre->l2_src = "aa:bb:cc:18:0:1";
	outs_post->l3_src = "200.201.202.203";

	/*
	 * SIP caller to callee (M7).
	 */
	/*
	 * The destination address of M7 is different, so a new SNAT session
	 * is created with trans port 5061.  Therefore need to change the Via
	 * port to 5061 in ACK (M7)
	 *
	 * "Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKka42\r\n"
	 */
	dp_test_sip_pkt_via_replace_str(&sip_call[6], "5060", "5061");

	ins_post->l4.udp.sport = 5061;
	outs_pre->l4.udp.dport = 5061;

	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 6, 6,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"100.101.102.103", 10000, "200.201.202.203", 60000,
		"200.201.202.1", 10000, "200.201.202.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"200.201.202.203", 60000, "200.201.202.1", 10000,
		"200.201.202.203", 60000, "100.101.102.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call end.  caller to callee (M8, M9).
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 7, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

} DP_END_TEST;


static void dpt_alg_sip_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	/* Proxy server */
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.205",
				  "aa:bb:cc:18:0:5");
}

static void dpt_alg_sip_teardown(void)
{
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	/* Proxy server */
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.205",
				  "aa:bb:cc:18:0:5");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");
}
