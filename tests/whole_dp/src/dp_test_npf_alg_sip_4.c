/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane SIP ALG tests.
 *
 * This tests SNAT when the SIP call includes both a 183 and a 200 response in
 * the backwards direction.  Previously we only translated the SDP
 * media address in the 183 Response and not the 200 Response.
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
 *                                     -----> SNAT, 16.33.0.200 -> 77.1.1.1
 *
 */

DP_DECL_TEST_SUITE(npf_sip4);

/*
 * SIP Call.  This is taken directly from the pcap of an issue, however the
 * order and format is changed to match the order that the osip library
 * re-writes a SIP packet.
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
		"INVITE sip:5000@77.1.1.1:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
		"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
		"To: <sip:5000@77.1.1.1>\r\n"
/*		"Date: Mon, 12 Feb 2018 16:39:40 GMT\r\n" */
		"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
		"CSeq: 101 INVITE\r\n"
		"Contact: <sip:7777@18.33.0.200:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Allow: INVITE\r\n"
		"Allow: OPTIONS\r\n"
		"Allow: BYE\r\n"
		"Allow: CANCEL\r\n"
		"Allow: ACK\r\n"
		"Allow: PRACK\r\n"
		"Allow: UPDATE\r\n"
		"Allow: REFER\r\n"
		"Allow: SUBSCRIBE\r\n"
		"Allow: NOTIFY\r\n"
		"Allow: INFO\r\n"
		"Allow: REGISTER\r\n"
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
		"a=ptime:30\r\n"
	},

	{
		.descr = "100 Trying",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 100 Trying\r\n"
		"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
		"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
		"To: <sip:5000@16.33.0.200>\r\n"
/*		"Date: Mon, 12 Feb 2018 11:54:26 EST\r\n" */
		"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
		"CSeq: 101 INVITE\r\n"
		"Timestamp: 1518453580\r\n"
		"allow-events: telephone-event\r\n"
		"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
		"Session-id: 00000000000000000000000000000000;"
		"remote=7121b823d210540b859a0d21af34a724\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},

	{
		.descr = "183 Session Progress",
		.dir = DP_TEST_SIP_DIR_BACK,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"SIP/2.0 183 Session Progress\r\n"
		"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
		"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
		"To: <sip:5000@16.33.0.200>;tag=757787AF-E66\r\n"
/*		"Date: Mon, 12 Feb 2018 11:54:26 EST\r\n" */
		"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
		"CSeq: 101 INVITE\r\n"
		"Contact: <sip:5000@16.33.0.200:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Allow: INVITE\r\n"
		"Allow: OPTIONS\r\n"
		"Allow: BYE\r\n"
		"Allow: CANCEL\r\n"
		"Allow: ACK\r\n"
		"Allow: PRACK\r\n"
		"Allow: UPDATE\r\n"
		"Allow: REFER\r\n"
		"Allow: SUBSCRIBE\r\n"
		"Allow: NOTIFY\r\n"
		"Allow: INFO\r\n"
		"Allow: REGISTER\r\n"
/*		"Timestamp: 1518453580\r\n" */
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
		"a=fmtp:100 0-16\r\n"
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
		"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2567F\r\n"
		"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
		"To: <sip:5000@16.33.0.200>;tag=757787AF-E66\r\n"
/*		"Date: Mon, 12 Feb 2018 11:54:26 EST\r\n" */
		"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
		"CSeq: 101 INVITE\r\n"
		"Contact: <sip:5000@16.33.0.200:5060>\r\n"
		"Content-Type: application/sdp\r\n"
/*		"Timestamp: 1518453580\r\n" */
		"Allow: INVITE\r\n"
		"Allow: OPTIONS\r\n"
		"Allow: BYE\r\n"
		"Allow: CANCEL\r\n"
		"Allow: ACK\r\n"
		"Allow: PRACK\r\n"
		"Allow: UPDATE\r\n"
		"Allow: REFER\r\n"
		"Allow: SUBSCRIBE\r\n"
		"Allow: NOTIFY\r\n"
		"Allow: INFO\r\n"
		"Allow: REGISTER\r\n"
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
		"Content-Length:   253\r\n"
		"\r\n"
		"v=0\r\n"
		/* Not translated, but not expected to be */
		"o=CiscoSystemsSIP-GW-UserAgent 4551 177 IN IP4 16.33.0.200\r\n"
		"s=SIP Call\r\n"
		/* Not translated, but expected to be!!! */
		"c=IN IP4 16.33.0.200\r\n"
		"t=0 0\r\n"
		"m=audio 8038 RTP/AVP 18 100\r\n"
		/* Not translated, but expected to be!!! */
		"c=IN IP4 16.33.0.200\r\n"
		"a=rtpmap:18 G729/8000\r\n"
		"a=fmtp:18 annexb=no\r\n"
		"a=rtpmap:100 telephone-event/8000\r\n"
		"a=fmtp:100 0-16\r\n"
	},

	{
		.descr = "ACK",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"ACK sip:5000@77.1.1.1:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK26CF6\r\n"
		"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
		"To: <sip:5000@77.1.1.1>;tag=757787AF-E66\r\n"
/*		"Date: Mon, 12 Feb 2018 16:39:40 GMT\r\n" */
		"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
		"CSeq: 101 ACK\r\n"
		"Max-forwards: 70\r\n"
		"allow-events: telephone-event\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},

	{
		.descr = "BYE",
		.dir = DP_TEST_SIP_DIR_FORW,
		.loc = DP_TEST_SIP_LOC_DIRECT,
		.media = false,
		.msg_pre = NULL,
		.msg_post = NULL,
		.msg =
		"BYE sip:5000@77.1.1.1:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2740D\r\n"
		"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
		"To: <sip:5000@77.1.1.1>;tag=757787AF-E66\r\n"
/*		"Date: Mon, 12 Feb 2018 16:39:40 GMT\r\n" */
		"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
		"CSeq: 102 BYE\r\n"
		"User-agent: Cisco-SIPGateway/IOS-15.5.3.M1\r\n"
		"Max-forwards: 70\r\n"
		"Timestamp: 1518453588\r\n"
		"Reason: Q.850;cause=16\r\n"
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
		"Via: SIP/2.0/UDP 18.33.0.200:5060;branch=z9hG4bK2740D\r\n"
		"From: <sip:7777@18.33.0.200>;tag=1871EFF8-AE1\r\n"
		"To: <sip:5000@16.33.0.200>;tag=757787AF-E66\r\n"
/*		"Date: Mon, 12 Feb 2018 11:54:33 EST\r\n" */
		"Call-ID: 27DDA24D-F4A11E8-80CCFB84-B2765CC2@18.33.0.200\r\n"
		"CSeq: 102 BYE\r\n"
		"Server: Cisco-SIPGateway/IOS-16.6.1\r\n"
		"Timestamp: 1518453588\r\n"
		"Reason: Q.850;cause=16\r\n"
		"Session-id: 7121b823d210540b859a0d21af34a724;"
		"remote=a3c87797321e51d085c9b6346ba8c710\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	},
};

DP_DECL_TEST_CASE(npf_sip4, sip4_1, dpt_alg_sip_setup, dpt_alg_sip_teardown);
DP_START_TEST(sip4_1, test)
{
	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp1T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "16.33.0.200",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "77.1.1.1",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "DNAT rule",
		.rule		= "1",
		.ifname		= "dp1T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "77.1.1.1",
		.to_port	= NULL,
		.trans_addr	= "16.33.0.200",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	char *dp1T1_mac = dp_test_intf_name2mac_str("dp1T1");
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_UDP,
		"7c:69:f6:4a:3a:50", "18.33.0.200", 60673,
		dp1T1_mac, "77.1.1.1", 5060,
		"dp1T1", "dp1T0");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_UDP,
		dp1T0_mac, "18.33.0.200", 60673,
		"70:6e:6d:88:55:80", "16.33.0.200", 5060,
		"dp1T1", "dp1T0");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_UDP,
		"70:6e:6d:88:55:80", "16.33.0.200", 5060,
		dp1T0_mac, "18.33.0.200", 60673,
		"dp1T0", "dp1T1");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_UDP,
		dp1T1_mac, "77.1.1.1", 5060,
		"7c:69:f6:4a:3a:50", "18.33.0.200", 60673,
		"dp1T0", "dp1T1");

	dpt_npf_sip_call(sip_call, ARRAY_SIZE(sip_call),
			 0, ARRAY_SIZE(sip_call) - 1,
			 DP_TEST_SIP_LOC_DIRECT,
			 ins_pre, ins_post, outs_pre, outs_post,
			 DP_TEST_TRANS_DNAT, VRF_DEFAULT_ID);

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

} DP_END_TEST;


static void dpt_alg_sip_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "16.33.0.220/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "18.33.0.220/24");

	dp_test_netlink_add_neigh("dp1T0", "16.33.0.200",
				  "70:6e:6d:88:55:80");
	dp_test_netlink_add_neigh("dp1T1", "18.33.0.200",
				  "7c:69:f6:4a:3a:50");
}

static void dpt_alg_sip_teardown(void)
{
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "16.33.0.200",
				  "70:6e:6d:88:55:80");
	dp_test_netlink_del_neigh("dp1T1", "18.33.0.200",
				  "7c:69:f6:4a:3a:50");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "16.33.0.220/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "18.33.0.220/24");

}
