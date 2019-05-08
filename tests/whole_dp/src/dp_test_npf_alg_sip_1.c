/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane SIP ALG tests
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
#include "dp_test_npf_sess_lib.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_alg_lib.h"
#include "dp_test_npf_alg_sip_lib.h"
#include "dp_test_npf_alg_sip_call.h"

/*
 * sip1_1  - No NAT.
 * sip1_1b - No NAT. Stateful firewall.
 *
 * sip1_2 - SNAT masquerade.
 *
 * sip1_3 - SNAT masquerade.  Start RTP and RTCP flows in reverse direction.
 *
 * sip1_4 - SNAT one-to-one.  Replace FQDN's with IP addresses in the SIP
 * call.
 *
 * sip1_5 - SNAT Many-to-one.  Replace FQDN's with IP addresses in the SIP
 * call.  VRF.  Delete VRF when there are ALG sessions.
 *
 * sip1_6 - DNAT.
 *
 * sip1_7 - DNAT.  Start RTP and RTCP flows in reverse direction.
 *
 * sip1_8 - DNAT. Replace FQDN's with IP addresses in the SIP call.
 *
 * sip1_9 - SNAT One-to-one. CGNAT matching on same source.
 */

static void dpt_alg_sip_setup(void);
static void dpt_alg_sip_teardown(void);
static void dpt_alg_sip_vrf_setup(void);
static void dpt_alg_sip_vrf_teardown(void);

/*
 * Simple SIP Session
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
 */

DP_DECL_TEST_SUITE(npf_sip1);

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
		.descr = "INVITE",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"INVITE sip:Bloggs@test.org SIP/2.0\r\n"
		"Via: SIP/2.0/UDP foo.example.com:5060;"
		"branch=z9hG4bKfw19b\r\n"
		"From: John Doe <sip:j.doe@example.com>;"
		"tag=76341\r\n"
		"To: J. Bloggs <sip:Bloggs@test.org>\r\n"
		"Call-ID: j2qu348ek2328ws\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:j.doe@foo.example.com>\r\n"
		"Content-Type: application/sdp\r\n"
		"Max-forwards: 70\r\n"
		"Subject: About That Power Outage...\r\n"
		"Content-Length:   147\r\n"
		"\r\n"
		"v=0\r\n"
		"o=Doe 2890844526 2890844526 IN IP4 foo.example.com\r\n"
		"s=Phone Call\r\n"
		"c=IN IP4 192.0.2.103\r\n"
		"t=0 0\r\n"
		"m=audio 10000 RTP/AVP 0\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
	},
	{
		.descr = "180 RINGING",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 180 Ringing\r\n"
		"Via: SIP/2.0/UDP foo.example.com:5060;"
		"branch=z9hG4bKfw19b\r\n"
		"From: John Doe <sip:j.doe@example.com>;"
		"tag=76341\r\n"
		"To: J. Bloggs <sip:bloggs@test.org>;tag=a53e42\r\n"
		"Call-ID: j2qu348ek2328ws\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:bloggs@bar.test.org>\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},
	{
		.descr = "200 OK",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP foo.example.com:5060;"
		"branch=z9hG4bKfw19b\r\n"
		"From: John Doe <sip:j.doe@example.com>;"
		"tag=76341\r\n"
		"To: J. Bloggs <sip:bloggs@test.org>;tag=a53e42\r\n"
		"Call-ID: j2qu348ek2328ws\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:bloggs@bar.test.org>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length:   149\r\n"
		"\r\n"
		"v=0\r\n"
		"o=Bloggs 2890844528 2890844528 IN IP4 bar.test.org\r\n"
		"s=Phone Call\r\n"
		"c=IN IP4 203.0.113.203\r\n"
		"t=0 0\r\n"
		"m=audio 60000 RTP/AVP 0\r\n"
		"a=rtpmap:0 PCMU/8000\r\n"
	},
	{
		.descr = "ACK",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"ACK sip:bloggs@bar.test.org SIP/2.0\r\n"
		"Via: SIP/2.0/UDP foo.example.com:5060;"
		"branch=z9hG4bK321g\r\n"
		"From: John Doe <sip:j.doe@example.com>;"
		"tag=76341\r\n"
		"To: J. Bloggs <sip:bloggs@test.org>;tag=a53e42\r\n"
		"Call-ID: j2qu348ek2328ws\r\n"
		"CSeq: 1 ACK\r\n"
		"Max-forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},
	{
		.descr = "BYE",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = true,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"BYE sip:j.doe@foo.example.com SIP/2.0\r\n"
		"Via: SIP/2.0/UDP bar.test.org:5060;branch=z9hG4bK392kf\r\n"
		"From: J. Bloggs <sip:bloggs@test.org>;tag=a53e42\r\n"
		"To: John Doe <sip:j.doe@example.com>;tag=76341\r\n"
		"Call-ID: j2qu348ek2328ws\r\n"
		"CSeq: 1392 BYE\r\n"
		"Max-forwards: 70\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},
	{
		.descr = "200 OK",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP bar.test.org:5060;branch=z9hG4bK392kf\r\n"
		"From: J. Bloggs <sip:bloggs@test.org>;tag=a53e42\r\n"
		"To: John Doe <sip:j.doe@example.com>;tag=76341\r\n"
		"Call-ID: j2qu348ek2328ws\r\n"
		"CSeq: 1392 BYE\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	}
};


/*
 * sip1_1 - SIP call. No NAT config.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_1, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_1, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "192.0.2.103", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.113.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

} DP_END_TEST;


/*
 * sip1_1b - No NAT config.  Stateful firewall.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_1b, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_1b, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/*
	 * Stateful firewall rule to match on TCP pkts to port 21.  This
	 * matches the ctrl flow but not the data flow.  The data flow only
	 * gets through because of the alg child session.
	 */
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = true,
			.npf      = "proto-final=17 dst-port=5060"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "OUT_FW",
		.enable = 1,
		.attach_point = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rset
	};

	dp_test_npf_fw_add(&fw, false);

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "192.0.2.103", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.113.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_NONE, VRF_DEFAULT_ID);

	dp_test_npf_fw_del(&fw, false);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

} DP_END_TEST;


/*
 * sip1_2 - SIP call. SNAT masquerade.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_2, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_2, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "192.0.2.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 203.0.113.1 */
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "203.0.113.1", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "203.0.113.1", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.113.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60000,	/* Ins pre dst port */
				     10000,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"203.0.113.1", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "203.0.113.1", 10000,
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * RTCP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60001,	/* Ins pre dst port */
				     10001,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTCP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10001, "203.0.113.203", 60001,
		"203.0.113.1", 10001, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTCP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "203.0.113.1", 10001,
		"203.0.113.203", 60001, "192.0.2.103", 10001,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
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
 * sip1_3 - SIP call. SNAT masquerade.  Start RTP and RTCP flows in reverse
 * direction.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_3, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_3, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "192.0.2.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 203.0.113.1 */
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "203.0.113.1", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "203.0.113.1", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.113.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60000,	/* Ins pre dst port */
				     10000,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTP Back (Initial) */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "203.0.113.1", 10000,
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/* RTP Forw */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"203.0.113.1", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/*
	 * RTCP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60001,	/* Ins pre dst port */
				     10001,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTCP Back (Initial) */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "203.0.113.1", 10001,
		"203.0.113.203", 60001, "192.0.2.103", 10001,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/* RTCP Forw */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10001, "203.0.113.203", 60001,
		"203.0.113.1", 10001, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
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
 * sip1_4 - SIP call. One-to-one SNAT.  Replace FQDN's with IP addresses in
 * the SIP call.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_4, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_4, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "192.0.2.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "203.0.113.100",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "203.0.113.100", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "203.0.113.100", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.113.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * Copy SIP call, and replace FQDN's with IP addresses
	 */
	dp_test_npf_sip_call_dup(sip_call, ARRAY_SIZE(sip_call));

	/*
	 * Forw        - replaces Inside FQDN with Inside IP
	 * Back + snat - replaces Inside FQDN with Trans
	 * Back + dnat - replaces Inside FQDN with Inside IP
	 */
	dp_test_sip_call_replace_ins_fqdn(
		&sip_call[0], ARRAY_SIZE(sip_call), true,
		"foo.example.com",	/* Inside FQDN */
		"192.0.2.103",		/* Inside IP */
		"192.0.2.103",		/* Target */
		"203.0.113.103");	/* Trans */

	/*
	 * Forw + snat        - replaces Outside FQDN with Outside IP
	 * Forw + dnat + req  - replaces Outside FQDN with Target
	 * Forw + snat + !req - replaces Outside FQDN with Outside IP
	 * Back               - replaces Outside FQDN with Outside IP
	 */
	dp_test_sip_call_replace_outs_fqdn(
		&sip_call[0], ARRAY_SIZE(sip_call), true,
		"bar.test.org",
		"203.0.113.203",
		"192.0.2.103",
		"203.0.113.103");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60000,	/* Ins pre dst port */
				     10000,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"203.0.113.100", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "203.0.113.100", 10000,
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * RTCP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60001,	/* Ins pre dst port */
				     10001,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTCP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10001, "203.0.113.203", 60001,
		"203.0.113.100", 10001, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTCP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "203.0.113.100", 10001,
		"203.0.113.203", 60001, "192.0.2.103", 10001,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
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


/*
 * sip1_5 - SIP call. Many-to-one SNAT.  Replace FQDN's with IP addresses in
 * the SIP call.  VRF.  Delete VRF when there are ALG sessions.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_5, dpt_alg_sip_vrf_setup, NULL);
DP_START_TEST(sip1_5, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "192.0.2.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "203.0.113.100",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "203.0.113.100", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "203.0.113.100", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.113.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * Copy SIP call, and replace FQDN's with IP addresses
	 */
	dp_test_npf_sip_call_dup(sip_call, ARRAY_SIZE(sip_call));

	/*
	 * Forw        - replaces Inside FQDN with Inside IP
	 * Back + snat - replaces Inside FQDN with Trans
	 * Back + dnat - replaces Inside FQDN with Inside IP
	 */
	dp_test_sip_call_replace_ins_fqdn(
		&sip_call[0], ARRAY_SIZE(sip_call), true,
		"foo.example.com",	/* Inside FQDN */
		"192.0.2.103",		/* Inside IP */
		"192.0.2.103",		/* Target */
		"203.0.113.103");	/* Trans */

	/*
	 * Forw + snat        - replaces Outside FQDN with Outside IP
	 * Forw + dnat + req  - replaces Outside FQDN with Target
	 * Forw + snat + !req - replaces Outside FQDN with Outside IP
	 * Back               - replaces Outside FQDN with Outside IP
	 */
	dp_test_sip_call_replace_outs_fqdn(
		&sip_call[0], ARRAY_SIZE(sip_call), true,
		"bar.test.org",
		"203.0.113.203",
		"192.0.2.103",
		"203.0.113.103");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	dp_test_npf_alg_tuple_verify(1001, "sip", IPPROTO_UDP,
				     60000,	/* Ins pre dst port */
				     10000,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"203.0.113.100", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "203.0.113.100", 10000,
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * RTCP
	 */
	dp_test_npf_alg_tuple_verify(1001, "sip", IPPROTO_UDP,
				     60001,	/* Ins pre dst port */
				     10001,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTCP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10001, "203.0.113.203", 60001,
		"203.0.113.100", 10001, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTCP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "203.0.113.100", 10001,
		"203.0.113.203", 60001, "192.0.2.103", 10001,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/* Delete the VRF before unconfiguring SNAT */
	dpt_alg_sip_vrf_teardown();

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_sip_call_free(sip_call, ARRAY_SIZE(sip_call));

} DP_END_TEST;


/*
 * sip1_6 - DNAT.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_6, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_6, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "203.0.114.0/24",
		.to_port	= NULL,
		.trans_addr	= "203.0.113.0/24",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.114.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "192.0.2.103", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.114.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_DNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60000,	/* Ins pre dst port */
				     10000,	/* Ins pre src port */
				     "203.0.114.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.114.203", 60000,
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"203.0.114.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * RTCP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60001,	/* Ins pre dst port */
				     10001,	/* Ins pre src port */
				     "203.0.114.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTCP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10001, "203.0.114.203", 60001,
		"192.0.2.103", 10001, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTCP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "192.0.2.103", 10001,
		"203.0.114.203", 60001, "192.0.2.103", 10001,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_DNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

} DP_END_TEST;


/*
 * sip1_7 - DNAT.  Start RTP and RTCP flows in reverse direction.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_7, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_7, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "203.0.114.0/24",
		.to_port	= NULL,
		.trans_addr	= "203.0.113.0/24",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.114.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "192.0.2.103", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.114.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_DNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60000,	/* Ins pre dst port */
				     10000,	/* Ins pre src port */
				     "203.0.114.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTP Back (Initial) */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"203.0.114.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/* RTP Forw */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.114.203", 60000,
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/*
	 * RTCP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60001,	/* Ins pre dst port */
				     10001,	/* Ins pre src port */
				     "203.0.114.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTCP Back (Initial) */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "192.0.2.103", 10001,
		"203.0.114.203", 60001, "192.0.2.103", 10001,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/* RTCP Forw */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10001, "203.0.114.203", 60001,
		"192.0.2.103", 10001, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_DNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

} DP_END_TEST;


/*
 * sip1_8 - DNAT. Replace FQDN's with IP addresses in the SIP call.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_8, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_8, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "203.0.114.0/24",
		.to_port	= NULL,
		.trans_addr	= "203.0.113.0/24",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.114.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "192.0.2.103", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.114.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * Copy SIP call, and replace FQDN's with IP addresses
	 */
	dp_test_npf_sip_call_dup(sip_call, ARRAY_SIZE(sip_call));

	/*
	 * Forw        - replaces Inside FQDN with Inside IP
	 * Back + snat - replaces Inside FQDN with Trans
	 * Back + dnat - replaces Inside FQDN with Inside IP
	 */
	dp_test_sip_call_replace_ins_fqdn(
		&sip_call[0], ARRAY_SIZE(sip_call), false,
		"foo.example.com",	/* Inside FQDN */
		"192.0.2.103",		/* Inside IP */
		"192.0.2.103",		/* Target */
		"192.0.2.103");		/* Trans */

	/*
	 * Forw + snat        - replaces Outside FQDN with Outside IP
	 * Forw + dnat + req  - replaces Outside FQDN with Target
	 * Forw + snat + !req - replaces Outside FQDN with Outside IP
	 * Back               - replaces Outside FQDN with Outside IP
	 */
	dp_test_sip_call_replace_outs_fqdn(
		&sip_call[0], ARRAY_SIZE(sip_call), false,
		"bar.test.org",		/* Outside FQDN */
		"203.0.113.203",	/* Outside IP */
		"203.0.114.203",	/* Target */
		"203.0.113.203");	/* Trans */

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_DNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60000,	/* Ins pre dst port */
				     10000,	/* Ins pre src port */
				     "203.0.114.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.114.203", 60000,
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"203.0.114.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * RTCP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60001,	/* Ins pre dst port */
				     10001,	/* Ins pre src port */
				     "203.0.114.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTCP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10001, "203.0.114.203", 60001,
		"192.0.2.103", 10001, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTCP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "192.0.2.103", 10001,
		"203.0.114.203", 60001, "192.0.2.103", 10001,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_DNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);
	dp_test_npf_sip_call_free(sip_call, ARRAY_SIZE(sip_call));

} DP_END_TEST;


/*
 * sip1_9 - SIP call. One-to-one SNAT. CGNAT matching on same source.
 */
DP_DECL_TEST_CASE(npf_sip1, sip1_9, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip1_9, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "192.0.2.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "203.0.113.100",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * Add CGNAT config.  Matches on same source addresses as SNAT, but
	 * maps to different addresses.
	 */
	dp_test_npf_cmd_fmt(
		false,
		"nat-ut pool add POOL1 type=cgnat "
		"address-range=RANGE1/203.0.113.101-203.0.113.110");

	cgnat_policy_add2("POLICY1", 10, "192.0.2.0/24", "POOL1",
			  "dp2T1", NULL);

	dp_test_npf_cmd_fmt(false, "cgn-ut snat-alg-bypass on");

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		dp1T0_mac, "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp2T1_mac, "203.0.113.100", 5060,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"aa:bb:cc:18:0:1", "203.0.113.203", 5060,
		dp2T1_mac, "203.0.113.100", 5060,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T0_mac, "203.0.113.203", 5060,
		"aa:bb:cc:16:0:20", "192.0.2.103", 5060,
		"dp2T1", "dp1T0");

	/*
	 * SIP Call start
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, 3,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	/*
	 * RTP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60000,	/* Ins pre dst port */
				     10000,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10000, "203.0.113.203", 60000,
		"203.0.113.100", 10000, "203.0.113.203", 60000,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60000, "203.0.113.100", 10000,
		"203.0.113.203", 60000, "192.0.2.103", 10000,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * RTCP
	 */
	dp_test_npf_alg_tuple_verify(VRF_DEFAULT_ID,
				     "sip", IPPROTO_UDP,
				     60001,	/* Ins pre dst port */
				     10001,	/* Ins pre src port */
				     "203.0.113.203",	/* Ins pre dst addr */
				     "192.0.2.103");	/* Ins pre src addr */

	/* RTCP Forw (Initial) */
	dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
		"192.0.2.103", 10001, "203.0.113.203", 60001,
		"203.0.113.100", 10001, "203.0.113.203", 60001,
		"aa:bb:cc:18:0:1", "dp2T1",
		DP_TEST_FWD_FORWARDED);

	/* RTCP Back */
	dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
		"203.0.113.203", 60001, "203.0.113.100", 10001,
		"203.0.113.203", 60001, "192.0.2.103", 10001,
		"aa:bb:cc:16:0:20", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * SIP Call end
	 */
	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 4, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_SNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/* Delete CGNAT config */
	dp_test_npf_cmd_fmt(false, "cgn-ut snat-alg-bypass off");
	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

} DP_END_TEST;


static void dpt_alg_sip_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "192.0.2.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "203.0.113.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "203.0.114.1/24");

	dp_test_netlink_add_neigh("dp1T0", "192.0.2.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "203.0.113.203",
				  "aa:bb:cc:18:0:1");
	dp_test_netlink_add_neigh("dp2T1", "203.0.114.203",
				  "aa:bb:cc:18:0:1");
}

static void dpt_alg_sip_teardown(void)
{
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "192.0.2.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "203.0.113.203",
				  "aa:bb:cc:18:0:1");
	dp_test_netlink_del_neigh("dp2T1", "203.0.114.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "192.0.2.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "203.0.113.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "203.0.114.1/24");
}

static void dpt_alg_sip_vrf_setup(void)
{
	dp_test_netlink_add_vrf(69, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "192.0.2.1/24", 69);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp2T1", "203.0.113.1/24", 69);

	dp_test_netlink_add_neigh("dp1T0", "192.0.2.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "203.0.113.203",
				  "aa:bb:cc:18:0:1");
}

static void dpt_alg_sip_vrf_teardown(void)
{
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "192.0.2.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "203.0.113.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "192.0.2.1/24", 69);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp2T1", "203.0.113.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
}
