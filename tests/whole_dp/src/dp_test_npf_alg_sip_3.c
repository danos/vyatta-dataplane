/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane SIP ALG tests for SIP to PSTN Call through a Gateway
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


static void dpt_alg_sip_setup(void);
static void dpt_alg_sip_teardown(void);

DP_DECL_TEST_SUITE(npf_sip3);

/*
 * SIP to PSTN Call Through Gateway
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
 *
 */


/*
 * SIP call.
 *
 * In this context, a SIP call comprises an array of SIP messages where *no*
 * NAT translations are in place here.
 *
 * Couple of notes re. the osip2 library which we use to rewrite the SIP
 * message:
 *
 * 1. The osip2 library re-writes the SIP message in a certain order, so we
 *    need to follow that here in order for the packet verification to work.
 *
 * 2. osip2 seems to allow for 5 characters of Content-length value (plus one
 *    space between these 5 chars and the colon), whilst writing the value at
 *    the end of these 5 bytes, e.g.  "Content-Length:   158\r\n".
 */
static struct dp_test_sip_pkt_t sip_call[] = {
	{
		.descr = "INVITE (M1)",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
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
		"a=rtpmap:8 PCMA/8000\r\n"
	},

	{
		.descr = "183 SESSION PROGRESS (M4)",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
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
		"a=rtpmap:0 PCMU/8000\r\n"
	},

	{
		.descr = "PRACK (M5)",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
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
		"\r\n"
	},

	{
		.descr = "200 OK (M8)",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = true,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
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
		"a=rtpmap:0 PCMU/8000\r\n"
	},

	{
		.descr = "ACK (M9)",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"ACK sip:50.60.70.80 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bKfgrw\r\n"
		"From: <sip:john.doe@example.com>;tag=12\r\n"
		"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
		"Call-ID: 49235243082018498\r\n"
		"CSeq: 1 ACK\r\n"
		"Max-forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},

	{
		.descr = "BYE (M10)",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = true,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"BYE sip:50.60.70.80 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK321\r\n"
		"From: <sip:john.doe@example.com>;tag=12\r\n"
		"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
		"Call-ID: 49235243082018498\r\n"
		"CSeq: 3 BYE\r\n"
		"Max-forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},

	{
		.descr = "200 OK (M12)",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 8.19.19.6:5060;branch=z9hG4bK321\r\n"
		"From: <sip:john.doe@example.com>;tag=12\r\n"
		"To: <sip:+12025551313@test.org;user=phone>;tag=37\r\n"
		"Call-ID: 49235243082018498\r\n"
		"CSeq: 3 BYE\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	}
};


/*
 * sip3_1 - No NAT config.
 */
DP_DECL_TEST_CASE(npf_sip3, sip3_1, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip3_1, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "8.19.19.6", 5060,
		dp1T0_mac, "50.60.70.80", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "8.19.19.6", 5060,
		"aa:bb:cc:18:0:1", "50.60.70.80", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "50.60.70.80", 5060,
		dp2T1_mac, "8.19.19.6", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "50.60.70.80", 5060,
		"aa:bb:cc:16:0:20", "8.19.19.6", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP call (msgs M1, M4, M5)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 2,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	/* RTP Early media */

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"50.60.70.80", 62002, "8.19.19.6", 50004,
		"50.60.70.80", 62002, "8.19.19.6", 50004,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call (msgs M8, M9)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 3, 4,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	/* RTP media */

	/* RTP Forw */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"8.19.19.6", 50004, "50.60.70.80", 62002,
		"8.19.19.6", 50004, "50.60.70.80", 62002,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"50.60.70.80", 62002, "8.19.19.6", 50004,
		"50.60.70.80", 62002, "8.19.19.6", 50004,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call (msgs M10, M12)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 5, 6,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

} DP_END_TEST;


/*
 * sip3_2 - SNAT masquerade.
 */
DP_DECL_TEST_CASE(npf_sip3, sip3_2, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip3_2, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "8.19.19.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 50.60.70.1 */
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "8.19.19.6", 5060,
		dp1T0_mac, "50.60.70.80", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "50.60.70.1", 5060,
		"aa:bb:cc:18:0:1", "50.60.70.80", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "50.60.70.80", 5060,
		dp2T1_mac, "50.60.70.1", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "50.60.70.80", 5060,
		"aa:bb:cc:16:0:20", "8.19.19.6", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP call (msgs M1, M4, M5)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 2,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/* RTP Early media */

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"50.60.70.80", 62002, "50.60.70.1", 50004,
		"50.60.70.80", 62002, "8.19.19.6", 50004,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call (msgs M8, M9)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 3, 4,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/* RTP media */

	/* RTP Forw */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"8.19.19.6", 50004, "50.60.70.80", 62002,
		"50.60.70.1", 50004, "50.60.70.80", 62002,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"50.60.70.80", 62002, "50.60.70.1", 50004,
		"50.60.70.80", 62002, "8.19.19.6", 50004,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call (msgs M10, M12)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 5, 6,
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
 * sip3_3 - SNAT masquerade.
 */
DP_DECL_TEST_CASE(npf_sip3, sip3_3, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip3_3, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "8.19.19.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 50.60.70.1 */
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "8.19.19.6", 5060,
		dp1T0_mac, "50.60.70.80", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "50.60.70.1", 5060,
		"aa:bb:cc:18:0:1", "50.60.70.80", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "50.60.70.80", 5060,
		dp2T1_mac, "50.60.70.1", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "50.60.70.80", 5060,
		"aa:bb:cc:16:0:20", "8.19.19.6", 5060,
		"dp2T1", "dp1T0");

	/* copy msg to msg_pre and msg_post */
	dp_test_npf_sip_call_dup(sip_call, ARRAY_SIZE(sip_call));

	dp_test_sip_call_replace_ins_fqdn(&sip_call[0], ARRAY_SIZE(sip_call),
					  true,
					  "pc.example.com",
					  "8.19.19.6",
					  "8.19.19.6",
					  "50.60.70.1");

	dp_test_sip_call_replace_outs_fqdn(&sip_call[0], ARRAY_SIZE(sip_call),
					   true,
					   "client1.test.org",
					   "50.60.70.80",
					   "8.19.19.6",
					   "50.60.70.1");

	/*
	 * SIP call (msgs M1, M4, M5)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 2,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/* RTP Early media */

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"50.60.70.80", 62002, "50.60.70.1", 50004,
		"50.60.70.80", 62002, "8.19.19.6", 50004,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call (msgs M8, M9)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 3, 4,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/* RTP media */

	/* RTP Forw */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"8.19.19.6", 50004, "50.60.70.80", 62002,
		"50.60.70.1", 50004, "50.60.70.80", 62002,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"50.60.70.80", 62002, "50.60.70.1", 50004,
		"50.60.70.80", 62002, "8.19.19.6", 50004,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP call (msgs M10, M12)
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 5, 6,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_sip_call_free(sip_call, ARRAY_SIZE(sip_call));

} DP_END_TEST;


static void dpt_alg_sip_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "8.19.19.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "50.60.70.1/24");

	dp_test_netlink_add_neigh("dp1T0", "8.19.19.6",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "50.60.70.80",
				  "aa:bb:cc:18:0:1");
}

static void dpt_alg_sip_teardown(void)
{
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "8.19.19.6",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "50.60.70.80",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "8.19.19.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "50.60.70.1/24");
}
