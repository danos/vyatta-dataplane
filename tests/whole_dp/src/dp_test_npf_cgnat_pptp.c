/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf alg PPTP tests.
 */
#include "in_cksum.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_str.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_alg_lib.h"

#include "npf/cgnat/cgn_mbuf.h"

struct pptp_start_req {
	uint16_t	pptp_length;
	uint16_t	pptp_type;
	uint32_t	pptp_magic_cookie;
	uint16_t	pptp_ctrl_type;
	uint16_t	pptp_reserved0;
	uint16_t	pptp_version;
	uint16_t	pptp_reserved1;
	uint32_t	pptp_framing_cap;
	uint32_t	pptp_bearer_cap;
	uint16_t	pptp_max_channels;
	uint16_t	pptp_firmware;
	char		pptp_host_name[64];
	char		pptp_vendor_name[64];
};

struct pptp_start_reply {
	uint16_t	pptp_length;
	uint16_t	pptp_type;
	uint32_t	pptp_magic_cookie;
	uint16_t	pptp_ctrl_type;
	uint16_t	pptp_reserved;
	uint16_t	pptp_version;
	uint8_t		pptp_result_code;
	uint8_t		pptp_error_code;
	uint32_t	pptp_framing_cap;
	uint32_t	pptp_bearer_cap;
	uint16_t	pptp_max_channels;
	uint16_t	pptp_firmware;
	char		pptp_host_name[64];
	char		pptp_vendor_name[64];
};

struct pptp_call_req {
	uint16_t	pptp_length;
	uint16_t	pptp_type;
	uint32_t	pptp_magic_cookie;
	uint16_t	pptp_ctrl_type;
	uint16_t	pptp_reserved0;

	uint16_t	pptp_call_id;
	uint16_t	pptp_call_serial_number;
	uint32_t	pptp_min_bps;
	uint32_t	pptp_max_bps;
	uint32_t	pptp_bearer_type;
	uint32_t	pptp_framing_type;
	uint16_t	pptp_window;
	uint16_t	pptp_delay;
	uint16_t	pptp_phone_num_len;
	uint16_t	pptp_reserved1;
	uint8_t		pptp_phone_number[64];
	uint8_t		pptp_subaddress[64];
};

struct pptp_call_reply {
	uint16_t	pptp_length;
	uint16_t	pptp_type;
	uint32_t	pptp_magic_cookie;
	uint16_t	pptp_ctrl_type;
	uint16_t	pptp_reserved0;
	uint16_t	pptp_call_id;
	uint16_t	pptp_peer_call_id;
	uint8_t		pptp_result_code;
	uint8_t		pptp_error_code;
	uint16_t	pptp_cause_code;
	uint32_t	pptp_conn_speed;
	uint16_t	pptp_window;
	uint16_t	pptp_delay;
	uint32_t	pptp_channel_id;
};

struct pptp_call_clear_req {
	uint16_t	pptp_length;
	uint16_t	pptp_type;
	uint32_t	pptp_magic_cookie;
	uint16_t	pptp_ctrl_type;
	uint16_t	pptp_reserved0;
	uint16_t	pptp_call_id;
	uint16_t	pptp_reserved1;
};

struct pptp_disc_notify {
	uint16_t	pptp_length;
	uint16_t	pptp_type;
	uint32_t	pptp_magic_cookie;
	uint16_t	pptp_ctrl_type;
	uint16_t	pptp_reserved0;
	uint16_t	pptp_call_id;
	uint8_t		pptp_result_code;
	uint8_t		pptp_error_code;
	uint16_t	pptp_cause_code;
	uint16_t	pptp_reserved1;
	char		pptp_call_stats[128];
};

DP_DECL_TEST_SUITE(cgn_pptp);

/*
 * cgn_pptp1 - No CGNAT.
 */
DP_DECL_TEST_CASE(cgn_pptp, cgn_pptp1, NULL, NULL);
DP_START_TEST(cgn_pptp1, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_netlink_add_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_add_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp on");

	ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for pptp ctrl flow
	  */
	struct dpt_tcp_flow pptp_ctrl_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(pptp_ctrl_call.text, sizeof(pptp_ctrl_call), "Ctrl");

	struct pptp_start_req start_req = {0};
	struct pptp_start_reply start_reply = {0};
	struct pptp_call_req call_req = {0};
	struct pptp_call_reply call_reply = {0};

	/* PPTP Start Request */
	start_req.pptp_length		= htons(sizeof(start_req));
	start_req.pptp_type		= htons(1);
	start_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_req.pptp_ctrl_type	= htons(1);
	start_req.pptp_version		= htons(0x100);
	start_req.pptp_framing_cap	= htonl(1);
	start_req.pptp_bearer_cap	= htonl(1);
	start_req.pptp_max_channels	= htons(65535);
	start_req.pptp_firmware		= htons(0x100);
	snprintf(start_req.pptp_host_name, 64, "local");
	snprintf(start_req.pptp_vendor_name, 64, "ixia");

	/* PPTP Start Reply */
	start_reply.pptp_length		= htons(sizeof(start_reply));
	start_reply.pptp_type		= htons(1);
	start_reply.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_reply.pptp_ctrl_type	= htons(2);
	start_reply.pptp_version	= htons(0x100);
	start_reply.pptp_result_code	= 1;
	start_reply.pptp_error_code	= 0;

	start_reply.pptp_framing_cap	= htonl(3);
	start_reply.pptp_bearer_cap	= htonl(3);
	start_reply.pptp_max_channels	= htons(0);
	start_reply.pptp_firmware	= htons(0x1200);
	snprintf(start_reply.pptp_host_name, 64, "ixro-smdev-r1");
	snprintf(start_reply.pptp_vendor_name, 64, "Cisco Systems, Inc.");

	/* Call Request */
	call_req.pptp_length		= htons(sizeof(call_req));
	call_req.pptp_type		= htons(1);
	call_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_req.pptp_ctrl_type		= htons(7);

	call_req.pptp_call_id		= htons(1);
	call_req.pptp_min_bps		= htonl(0x8000);
	call_req.pptp_max_bps		= htonl(0x80000000);
	call_req.pptp_bearer_type	= htonl(1);
	call_req.pptp_framing_type	= htonl(1);
	call_req.pptp_window		= htons(10);

	/* Call Reply */
	call_reply.pptp_length		= htons(sizeof(call_reply));
	call_reply.pptp_type		= htons(1);
	call_reply.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_reply.pptp_ctrl_type	= htons(8);
	call_reply.pptp_call_id		= htons(24);
	call_reply.pptp_peer_call_id	= htons(1);
	call_reply.pptp_result_code	= 1;
	call_reply.pptp_conn_speed	= htonl(6400);
	call_reply.pptp_window		= htons(16);

	struct dpt_tcp_flow_pkt pptp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		/* PPTP Start Control Connection Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(start_req), (char *)&start_req,
		  sizeof(start_req), (char *)&start_req
		},

		/* PPTP Start Control Connection Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(start_reply), (char *)&start_reply,
		  sizeof(start_reply), (char *)&start_reply
		},

		/* PPTP Outgoing Call Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_req), (char *)&call_req,
		  sizeof(call_req), (char *)&call_req
		},

		/* PPTP Outgoing Call Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_reply), (char *)&call_reply,
		  sizeof(call_reply), (char *)&call_reply
		},

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of pptp ctrl flow (pkts 0 - 6) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     0, 6, NULL, 0);

	/*
	 * At this point the VPN call is negotiated via PPP:
	 *  ip:gre:ppp:lcp
	 *  ip:gre:ppp:pap
	 *  ip:gre:ppp:ipcp
	 *  ip:gre:ppp:lcp
	 *
	 * After which it continues with just IP and GRE headers:
	 *  ip:gre
	 *  FORW: Call ID 24 ---->
	 *  BACK: Call ID 1  <----
	 */

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"2.0.0.20", 24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1, "2.0.0.20",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"2.0.0.20", 24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1, "2.0.0.20",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* Start of pptp ctrl flow (pkts 5 - end) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     7, 0, NULL, 0);

	/* Cleanup */
	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp off");

	dp_test_netlink_del_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_del_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

} DP_END_TEST;

#define CGN_MAX_CMD_LEN 5000

static void
_dpt_cgn_cmd(const char *cmd, bool print, bool exp,
	     const char *file, int line)
{
	char *reply;
	bool err;

	reply = dp_test_console_request_w_err(cmd, &err, print);

	/*
	 * Returned string for npf commands is just an empty string, which is
	 * of no interest
	 */
	free(reply);

	_dp_test_fail_unless(err != exp, file, line,
			     "Expd %u, got %u: \"%s\"", exp, !err, cmd);
}

static void
_dpt_cgn_cmd_fmt(bool print, bool exp,
		 const char *file, int line, const char *fmt_str, ...)
{
	char cmd[CGN_MAX_CMD_LEN];
	va_list ap;

	va_start(ap, fmt_str);
	vsnprintf(cmd, CGN_MAX_CMD_LEN, fmt_str, ap);
	_dpt_cgn_cmd(cmd, print, exp, file, line);
	va_end(ap);
}

#define dpt_cgn_cmd_fmt(print, exp, fmt_str, ...)	 \
	_dpt_cgn_cmd_fmt(print, exp, __FILE__, __LINE__, \
			 fmt_str, ##__VA_ARGS__)

/*
 * cgn_pptp2 - First GRE pkt is outbound
 *
 * Note that in this test the parent and child sessions both use trans port
 * 1024.  This is because the parent session is proto TCP and the child
 * session is proto GRE ('other').
 */
DP_DECL_TEST_CASE(cgn_pptp, cgn_pptp2, NULL, NULL);
DP_START_TEST(cgn_pptp2, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_netlink_add_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_add_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp on");

	/*
	 * Add CGNAT rule.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/1.0.0.2 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "2.0.0.20/32", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for pptp ctrl flow
	  */
	struct dpt_tcp_flow pptp_ctrl_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(pptp_ctrl_call.text, sizeof(pptp_ctrl_call), "Ctrl");

	struct pptp_start_req start_req = {0};
	struct pptp_start_reply start_reply = {0};
	struct pptp_call_req call_req_pre = {0};
	struct pptp_call_reply call_reply_pre = {0};
	struct pptp_call_req call_req_pst;
	struct pptp_call_reply call_reply_pst;


	/* PPTP Start Request */
	start_req.pptp_length	= htons(sizeof(start_req));
	start_req.pptp_type		= htons(1);
	start_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_req.pptp_ctrl_type	= htons(1);
	start_req.pptp_version	= htons(0x100);
	start_req.pptp_framing_cap	= htonl(1);
	start_req.pptp_bearer_cap	= htonl(1);
	start_req.pptp_max_channels	= htons(65535);
	start_req.pptp_firmware	= htons(0x100);
	snprintf(start_req.pptp_host_name, 64, "local");
	snprintf(start_req.pptp_vendor_name, 64, "ixia");

	/* PPTP Start Reply */
	start_reply.pptp_length	= htons(sizeof(start_reply));
	start_reply.pptp_type	= htons(1);
	start_reply.pptp_magic_cookie = htonl(0x1a2b3c4d);
	start_reply.pptp_ctrl_type	= htons(2);
	start_reply.pptp_version	= htons(0x100);
	start_reply.pptp_result_code = 1;
	start_reply.pptp_error_code	= 0;

	start_reply.pptp_framing_cap = htonl(3);
	start_reply.pptp_bearer_cap	= htonl(3);
	start_reply.pptp_max_channels = htons(0);
	start_reply.pptp_firmware	= htons(0x1200);
	snprintf(start_reply.pptp_host_name, 64, "ixro-smdev-r1");
	snprintf(start_reply.pptp_vendor_name, 64, "Cisco Systems, Inc.");

	/* Call Request */
	call_req_pre.pptp_length	= htons(sizeof(call_req_pre));
	call_req_pre.pptp_type		= htons(1);
	call_req_pre.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_req_pre.pptp_ctrl_type	= htons(7);

	call_req_pre.pptp_call_id	= htons(1);	/* Fwds 'source ID' */
	call_req_pre.pptp_min_bps	= htonl(0x8000);
	call_req_pre.pptp_max_bps	= htonl(0x80000000);
	call_req_pre.pptp_bearer_type	= htonl(1);
	call_req_pre.pptp_framing_type	= htonl(1);
	call_req_pre.pptp_window	= htons(10);

	call_req_pst = call_req_pre;
	call_req_pst.pptp_call_id = htons(1024);	/* 'src ID' NATd to 1024 */

	/* Call Reply */
	call_reply_pre.pptp_length	= htons(sizeof(call_reply_pre));
	call_reply_pre.pptp_type	= htons(1);
	call_reply_pre.pptp_magic_cookie = htonl(0x1a2b3c4d);
	call_reply_pre.pptp_ctrl_type	= htons(8);
	call_reply_pre.pptp_call_id	= htons(24);
	call_reply_pre.pptp_peer_call_id = htons(1024);
	call_reply_pre.pptp_result_code	= 1;
	call_reply_pre.pptp_conn_speed	= htonl(6400);
	call_reply_pre.pptp_window	= htons(16);

	call_reply_pst = call_reply_pre;
	call_reply_pst.pptp_peer_call_id = htons(1);

	struct dpt_tcp_flow_pkt pptp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		/* PPTP Start Control Connection Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(start_req), (char *)&start_req,
		  sizeof(start_req), (char *)&start_req
		},

		/* PPTP Start Control Connection Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(start_reply), (char *)&start_reply,
		  sizeof(start_reply), (char *)&start_reply
		},

		/* PPTP Outgoing Call Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_req_pre), (char *)&call_req_pre,
		  sizeof(call_req_pst), (char *)&call_req_pst
		},

		/* PPTP Outgoing Call Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_reply_pre), (char *)&call_reply_pre,
		  sizeof(call_reply_pst), (char *)&call_reply_pst
		},

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of pptp ctrl flow (pkts 0 - 6) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     0, 6, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/*
	 * At this point the VPN call is negotiated via PPP:
	 *  ip:gre:ppp:lcp
	 *  ip:gre:ppp:pap
	 *  ip:gre:ppp:ipcp
	 *  ip:gre:ppp:lcp
	 *
	 * After which it continues with just IP and GRE headers:
	 *  ip:gre
	 *  FORW: Call ID 24 ---->
	 *  BACK: Call ID 1  <----
	 */

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/* End of pptp ctrl flow (pkts 7 - end) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     7, 0, NULL, 0);

	/* Cleanup */
	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp off");

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_netlink_del_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_del_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * cgn_pptp3 - First GRE pkt is inbound
 *
 * Note that in this test the parent and child sessions both use trans port
 * 1024.  This is because the parent session is proto TCP and the child
 * session is proto GRE ('other').
 */
DP_DECL_TEST_CASE(cgn_pptp, cgn_pptp3, NULL, NULL);
DP_START_TEST(cgn_pptp3, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_netlink_add_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_add_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp on");

	/*
	 * Add CGNAT rule.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/1.0.0.2 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "2.0.0.20/32", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for pptp ctrl flow
	  */
	struct dpt_tcp_flow pptp_ctrl_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(pptp_ctrl_call.text, sizeof(pptp_ctrl_call), "Ctrl");

	struct pptp_start_req start_req = {0};
	struct pptp_start_reply start_reply = {0};
	struct pptp_call_req call_req_pre = {0};
	struct pptp_call_reply call_reply_pre = {0};
	struct pptp_call_req call_req_pst;
	struct pptp_call_reply call_reply_pst;


	/* PPTP Start Request */
	start_req.pptp_length	= htons(sizeof(start_req));
	start_req.pptp_type		= htons(1);
	start_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_req.pptp_ctrl_type	= htons(1);
	start_req.pptp_version	= htons(0x100);
	start_req.pptp_framing_cap	= htonl(1);
	start_req.pptp_bearer_cap	= htonl(1);
	start_req.pptp_max_channels	= htons(65535);
	start_req.pptp_firmware	= htons(0x100);
	snprintf(start_req.pptp_host_name, 64, "local");
	snprintf(start_req.pptp_vendor_name, 64, "ixia");

	/* PPTP Start Reply */
	start_reply.pptp_length	= htons(sizeof(start_reply));
	start_reply.pptp_type	= htons(1);
	start_reply.pptp_magic_cookie = htonl(0x1a2b3c4d);
	start_reply.pptp_ctrl_type	= htons(2);
	start_reply.pptp_version	= htons(0x100);
	start_reply.pptp_result_code = 1;
	start_reply.pptp_error_code	= 0;

	start_reply.pptp_framing_cap = htonl(3);
	start_reply.pptp_bearer_cap	= htonl(3);
	start_reply.pptp_max_channels = htons(0);
	start_reply.pptp_firmware	= htons(0x1200);
	snprintf(start_reply.pptp_host_name, 64, "ixro-smdev-r1");
	snprintf(start_reply.pptp_vendor_name, 64, "Cisco Systems, Inc.");

	/* Call Request */
	call_req_pre.pptp_length	= htons(sizeof(call_req_pre));
	call_req_pre.pptp_type		= htons(1);
	call_req_pre.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_req_pre.pptp_ctrl_type	= htons(7);

	call_req_pre.pptp_call_id	= htons(1);	/* Fwds 'source ID' */
	call_req_pre.pptp_min_bps	= htonl(0x8000);
	call_req_pre.pptp_max_bps	= htonl(0x80000000);
	call_req_pre.pptp_bearer_type	= htonl(1);
	call_req_pre.pptp_framing_type	= htonl(1);
	call_req_pre.pptp_window	= htons(10);

	call_req_pst = call_req_pre;
	call_req_pst.pptp_call_id = htons(1024);	/* 'src ID' NATd to 1024 */

	/* Call Reply */
	call_reply_pre.pptp_length	= htons(sizeof(call_reply_pre));
	call_reply_pre.pptp_type	= htons(1);
	call_reply_pre.pptp_magic_cookie = htonl(0x1a2b3c4d);
	call_reply_pre.pptp_ctrl_type	= htons(8);
	call_reply_pre.pptp_call_id	= htons(24);
	call_reply_pre.pptp_peer_call_id = htons(1024);
	call_reply_pre.pptp_result_code	= 1;
	call_reply_pre.pptp_conn_speed	= htonl(6400);
	call_reply_pre.pptp_window	= htons(16);

	call_reply_pst = call_reply_pre;
	call_reply_pst.pptp_peer_call_id = htons(1);

	struct dpt_tcp_flow_pkt pptp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		/* PPTP Start Control Connection Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(start_req), (char *)&start_req,
		  sizeof(start_req), (char *)&start_req
		},

		/* PPTP Start Control Connection Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(start_reply), (char *)&start_reply,
		  sizeof(start_reply), (char *)&start_reply
		},

		/* PPTP Outgoing Call Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_req_pre), (char *)&call_req_pre,
		  sizeof(call_req_pst), (char *)&call_req_pst
		},

		/* PPTP Outgoing Call Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_reply_pre), (char *)&call_reply_pre,
		  sizeof(call_reply_pst), (char *)&call_reply_pst
		},

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of pptp ctrl flow (pkts 0 - 6) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     0, 6, NULL, 0);

	/*
	 * At this point the VPN call is negotiated via PPP:
	 *  ip:gre:ppp:lcp
	 *  ip:gre:ppp:pap
	 *  ip:gre:ppp:ipcp
	 *  ip:gre:ppp:lcp
	 *
	 * After which it continues with just IP and GRE headers:
	 *  ip:gre
	 *  BACK: Call ID 1  <----
	 *  FORW: Call ID 24 ---->
	 */

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/* End of pptp ctrl flow (pkts 7 - end) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     7, 0, NULL, 0);

	/* Cleanup */
	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp off");

	dp_test_netlink_del_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_del_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * cgn_pptp4 - First GRE pkt is inbound.  Sub-session enabled.
 *
 * Note that in this test the parent and child sessions both use trans port
 * 1024.  This is because the parent session is proto TCP and the child
 * session is proto GRE ('other').
 */
DP_DECL_TEST_CASE(cgn_pptp, cgn_pptp4, NULL, NULL);
DP_START_TEST(cgn_pptp4, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_netlink_add_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_add_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp on");

	/*
	 * Add CGNAT rule.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/1.0.0.2 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "2.0.0.20/32", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);

	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for pptp ctrl flow
	  */
	struct dpt_tcp_flow pptp_ctrl_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(pptp_ctrl_call.text, sizeof(pptp_ctrl_call), "Ctrl");

	struct pptp_start_req start_req = {0};
	struct pptp_start_reply start_reply = {0};
	struct pptp_call_req call_req_pre = {0};
	struct pptp_call_reply call_reply_pre = {0};
	struct pptp_call_req call_req_pst;
	struct pptp_call_reply call_reply_pst;


	/* PPTP Start Request */
	start_req.pptp_length	= htons(sizeof(start_req));
	start_req.pptp_type		= htons(1);
	start_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_req.pptp_ctrl_type	= htons(1);
	start_req.pptp_version	= htons(0x100);
	start_req.pptp_framing_cap	= htonl(1);
	start_req.pptp_bearer_cap	= htonl(1);
	start_req.pptp_max_channels	= htons(65535);
	start_req.pptp_firmware	= htons(0x100);
	snprintf(start_req.pptp_host_name, 64, "local");
	snprintf(start_req.pptp_vendor_name, 64, "ixia");

	/* PPTP Start Reply */
	start_reply.pptp_length	= htons(sizeof(start_reply));
	start_reply.pptp_type	= htons(1);
	start_reply.pptp_magic_cookie = htonl(0x1a2b3c4d);
	start_reply.pptp_ctrl_type	= htons(2);
	start_reply.pptp_version	= htons(0x100);
	start_reply.pptp_result_code = 1;
	start_reply.pptp_error_code	= 0;

	start_reply.pptp_framing_cap = htonl(3);
	start_reply.pptp_bearer_cap	= htonl(3);
	start_reply.pptp_max_channels = htons(0);
	start_reply.pptp_firmware	= htons(0x1200);
	snprintf(start_reply.pptp_host_name, 64, "ixro-smdev-r1");
	snprintf(start_reply.pptp_vendor_name, 64, "Cisco Systems, Inc.");

	/* Call Request */
	call_req_pre.pptp_length	= htons(sizeof(call_req_pre));
	call_req_pre.pptp_type		= htons(1);
	call_req_pre.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_req_pre.pptp_ctrl_type	= htons(7);

	call_req_pre.pptp_call_id	= htons(1);	/* Fwds 'source ID' */
	call_req_pre.pptp_min_bps	= htonl(0x8000);
	call_req_pre.pptp_max_bps	= htonl(0x80000000);
	call_req_pre.pptp_bearer_type	= htonl(1);
	call_req_pre.pptp_framing_type	= htonl(1);
	call_req_pre.pptp_window	= htons(10);

	call_req_pst = call_req_pre;
	call_req_pst.pptp_call_id = htons(1024);	/* 'src ID' NATd to 1024 */

	/* Call Reply */
	call_reply_pre.pptp_length	= htons(sizeof(call_reply_pre));
	call_reply_pre.pptp_type	= htons(1);
	call_reply_pre.pptp_magic_cookie = htonl(0x1a2b3c4d);
	call_reply_pre.pptp_ctrl_type	= htons(8);
	call_reply_pre.pptp_call_id	= htons(24);
	call_reply_pre.pptp_peer_call_id = htons(1024);
	call_reply_pre.pptp_result_code	= 1;
	call_reply_pre.pptp_conn_speed	= htonl(6400);
	call_reply_pre.pptp_window	= htons(16);

	call_reply_pst = call_reply_pre;
	call_reply_pst.pptp_peer_call_id = htons(1);

	struct dpt_tcp_flow_pkt pptp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		/* PPTP Start Control Connection Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(start_req), (char *)&start_req,
		  sizeof(start_req), (char *)&start_req
		},

		/* PPTP Start Control Connection Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(start_reply), (char *)&start_reply,
		  sizeof(start_reply), (char *)&start_reply
		},

		/* PPTP Outgoing Call Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_req_pre), (char *)&call_req_pre,
		  sizeof(call_req_pst), (char *)&call_req_pst
		},

		/* PPTP Outgoing Call Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_reply_pre), (char *)&call_reply_pre,
		  sizeof(call_reply_pst), (char *)&call_reply_pst
		},

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of pptp ctrl flow (pkts 0 - 6) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     0, 6, NULL, 0);

	/*
	 * At this point the VPN call is negotiated via PPP:
	 *  ip:gre:ppp:lcp
	 *  ip:gre:ppp:pap
	 *  ip:gre:ppp:ipcp
	 *  ip:gre:ppp:lcp
	 *
	 * After which it continues with just IP and GRE headers:
	 *  ip:gre
	 *  BACK: Call ID 1  <----
	 *  FORW: Call ID 24 ---->
	 */

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/* End of pptp ctrl flow (pkts 7 - end) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     7, 0, NULL, 0);

	/* Cleanup */
	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_netlink_del_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_del_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp off");

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * cgn_pptp5 - Clear the session before the PPTP out call reply
 */
DP_DECL_TEST_CASE(cgn_pptp, cgn_pptp5, NULL, NULL);
DP_START_TEST(cgn_pptp5, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_netlink_add_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_add_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp on");

	/*
	 * Add CGNAT rule.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/1.0.0.2 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "2.0.0.20/32", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for pptp ctrl flow
	  */
	struct dpt_tcp_flow pptp_ctrl_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(pptp_ctrl_call.text, sizeof(pptp_ctrl_call), "Ctrl");

	struct pptp_start_req start_req = {0};
	struct pptp_start_reply start_reply = {0};
	struct pptp_call_req call_req_pre = {0};
	struct pptp_call_reply call_reply_pre = {0};
	struct pptp_call_req call_req_pst;
	struct pptp_call_reply call_reply_pst;


	/* PPTP Start Request */
	start_req.pptp_length	= htons(sizeof(start_req));
	start_req.pptp_type		= htons(1);
	start_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_req.pptp_ctrl_type	= htons(1);
	start_req.pptp_version	= htons(0x100);
	start_req.pptp_framing_cap	= htonl(1);
	start_req.pptp_bearer_cap	= htonl(1);
	start_req.pptp_max_channels	= htons(65535);
	start_req.pptp_firmware	= htons(0x100);
	snprintf(start_req.pptp_host_name, 64, "local");
	snprintf(start_req.pptp_vendor_name, 64, "ixia");

	/* PPTP Start Reply */
	start_reply.pptp_length	= htons(sizeof(start_reply));
	start_reply.pptp_type	= htons(1);
	start_reply.pptp_magic_cookie = htonl(0x1a2b3c4d);
	start_reply.pptp_ctrl_type	= htons(2);
	start_reply.pptp_version	= htons(0x100);
	start_reply.pptp_result_code = 1;
	start_reply.pptp_error_code	= 0;

	start_reply.pptp_framing_cap = htonl(3);
	start_reply.pptp_bearer_cap	= htonl(3);
	start_reply.pptp_max_channels = htons(0);
	start_reply.pptp_firmware	= htons(0x1200);
	snprintf(start_reply.pptp_host_name, 64, "ixro-smdev-r1");
	snprintf(start_reply.pptp_vendor_name, 64, "Cisco Systems, Inc.");

	/* Call Request */
	call_req_pre.pptp_length	= htons(sizeof(call_req_pre));
	call_req_pre.pptp_type		= htons(1);
	call_req_pre.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_req_pre.pptp_ctrl_type	= htons(7);

	call_req_pre.pptp_call_id	= htons(1);	/* Fwds 'source ID' */
	call_req_pre.pptp_min_bps	= htonl(0x8000);
	call_req_pre.pptp_max_bps	= htonl(0x80000000);
	call_req_pre.pptp_bearer_type	= htonl(1);
	call_req_pre.pptp_framing_type	= htonl(1);
	call_req_pre.pptp_window	= htons(10);

	call_req_pst = call_req_pre;
	call_req_pst.pptp_call_id = htons(1024);	/* 'src ID' NATd to 1024 */

	/* Call Reply */
	call_reply_pre.pptp_length	= htons(sizeof(call_reply_pre));
	call_reply_pre.pptp_type	= htons(1);
	call_reply_pre.pptp_magic_cookie = htonl(0x1a2b3c4d);
	call_reply_pre.pptp_ctrl_type	= htons(8);
	call_reply_pre.pptp_call_id	= htons(24);
	call_reply_pre.pptp_peer_call_id = htons(1024);
	call_reply_pre.pptp_result_code	= 1;
	call_reply_pre.pptp_conn_speed	= htonl(6400);
	call_reply_pre.pptp_window	= htons(16);

	call_reply_pst = call_reply_pre;
	call_reply_pst.pptp_peer_call_id = htons(1);

	struct dpt_tcp_flow_pkt pptp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		/* PPTP Start Control Connection Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(start_req), (char *)&start_req,
		  sizeof(start_req), (char *)&start_req
		},

		/* PPTP Start Control Connection Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(start_reply), (char *)&start_reply,
		  sizeof(start_reply), (char *)&start_reply
		},

		/* PPTP Outgoing Call Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_req_pre), (char *)&call_req_pre,
		  sizeof(call_req_pst), (char *)&call_req_pst
		},

		/* PPTP Outgoing Call Reply - Not Sent */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_reply_pre), (char *)&call_reply_pre,
		  sizeof(call_reply_pst), (char *)&call_reply_pst
		},

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/*
	 * Start of pptp ctrl flow (pkts 0 - 5).  Only sends up to the PPTP
	 * Outgoing Call Request.  This creates a mapping for the data flow,
	 * which is attached to the session ALG PPTP data.
	 */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     0, 5, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/* Clear the session */
	dp_test_npf_cmd_fmt(false, "cgn-op clear session");

	if (0)
		cgn_alg_show_sessions();

	/* Cleanup */
	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp off");

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_netlink_del_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_del_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_npf_cleanup();

} DP_END_TEST;

/*
 * cgn_pptp6 - Call setup is from server to client
 *
 * This is an unlikely scenario, but it allows testing of incoming
 * OUT_CALL_REQs without the need to clear any previous call.
 */
DP_DECL_TEST_CASE(cgn_pptp, cgn_pptp6, NULL, NULL);
DP_START_TEST(cgn_pptp6, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_netlink_add_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_add_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp on");

	/*
	 * Add CGNAT rule.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/1.0.0.2 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "2.0.0.20/32", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for pptp ctrl flow
	  */
	struct dpt_tcp_flow pptp_ctrl_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(pptp_ctrl_call.text, sizeof(pptp_ctrl_call), "Ctrl");

	struct pptp_start_req start_req = {0};
	struct pptp_start_reply start_reply = {0};
	struct pptp_call_req call_req_pre = {0};
	struct pptp_call_reply call_reply_pre = {0};
	struct pptp_call_req call_req_pst;
	struct pptp_call_reply call_reply_pst;


	/* PPTP Start Request */
	start_req.pptp_length	= htons(sizeof(start_req));
	start_req.pptp_type		= htons(1);
	start_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_req.pptp_ctrl_type	= htons(1);
	start_req.pptp_version	= htons(0x100);
	start_req.pptp_framing_cap	= htonl(1);
	start_req.pptp_bearer_cap	= htonl(1);
	start_req.pptp_max_channels	= htons(65535);
	start_req.pptp_firmware	= htons(0x100);
	snprintf(start_req.pptp_host_name, 64, "local");
	snprintf(start_req.pptp_vendor_name, 64, "ixia");

	/* PPTP Start Reply */
	start_reply.pptp_length	= htons(sizeof(start_reply));
	start_reply.pptp_type	= htons(1);
	start_reply.pptp_magic_cookie = htonl(0x1a2b3c4d);
	start_reply.pptp_ctrl_type	= htons(2);
	start_reply.pptp_version	= htons(0x100);
	start_reply.pptp_result_code = 1;
	start_reply.pptp_error_code	= 0;

	start_reply.pptp_framing_cap = htonl(3);
	start_reply.pptp_bearer_cap	= htonl(3);
	start_reply.pptp_max_channels = htons(0);
	start_reply.pptp_firmware	= htons(0x1200);
	snprintf(start_reply.pptp_host_name, 64, "ixro-smdev-r1");
	snprintf(start_reply.pptp_vendor_name, 64, "Cisco Systems, Inc.");

	/*
	 * Call Request. Server to client
	 */
	call_req_pre.pptp_length	= htons(sizeof(call_req_pre));
	call_req_pre.pptp_type		= htons(1);
	call_req_pre.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_req_pre.pptp_ctrl_type	= htons(7);

	call_req_pre.pptp_call_id	= htons(24);
	call_req_pre.pptp_min_bps	= htonl(0x8000);
	call_req_pre.pptp_max_bps	= htonl(0x80000000);
	call_req_pre.pptp_bearer_type	= htonl(1);
	call_req_pre.pptp_framing_type	= htonl(1);
	call_req_pre.pptp_window	= htons(10);

	call_req_pst = call_req_pre;
	call_req_pst.pptp_call_id = htons(24);

	/*
	 * Call Reply.  Client to server
	 */
	call_reply_pre.pptp_length	= htons(sizeof(call_reply_pre));
	call_reply_pre.pptp_type	= htons(1);
	call_reply_pre.pptp_magic_cookie = htonl(0x1a2b3c4d);
	call_reply_pre.pptp_ctrl_type	= htons(8);
	call_reply_pre.pptp_call_id	= htons(1);
	call_reply_pre.pptp_peer_call_id = htons(24);
	call_reply_pre.pptp_result_code	= 1;
	call_reply_pre.pptp_conn_speed	= htonl(6400);
	call_reply_pre.pptp_window	= htons(16);

	call_reply_pst = call_reply_pre;
	call_reply_pst.pptp_call_id = htons(1024);

	struct dpt_tcp_flow_pkt pptp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		/* PPTP Start Control Connection Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(start_req), (char *)&start_req,
		  sizeof(start_req), (char *)&start_req
		},

		/* PPTP Start Control Connection Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(start_reply), (char *)&start_reply,
		  sizeof(start_reply), (char *)&start_reply
		},

		/* PPTP Outgoing Call Request.  Inbound */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_req_pre), (char *)&call_req_pre,
		  sizeof(call_req_pst), (char *)&call_req_pst
		},

		/* PPTP Outgoing Call Reply.  Outbound */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_reply_pre), (char *)&call_reply_pre,
		  sizeof(call_reply_pst), (char *)&call_reply_pst
		},

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of pptp ctrl flow (pkts 0 - 6) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     0, 6, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/* FORW (toggle off to change direction of initial GRE pkt) */
	if (1)
		dpt_gre("dp1T0", "0:14:0:0:2:0",
			"2.0.0.20", 24, "1.0.0.20",
			"1.0.0.2",  24, "1.0.0.20",
			"0:9:e9:55:c0:1c", "dp2T1",
			DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/* End of pptp ctrl flow (pkts 7 - end) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     7, 0, NULL, 0);

	/* Cleanup */
	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp off");

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_netlink_del_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_del_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_npf_cleanup();

} DP_END_TEST;

/*
 * cgn_pptp7 - Tests call disconnect, followed by new call over same parent
 *
 * The initial call is cleared via a CLEAR_REQ from the client.  An ifdef
 * allows the call to be cleared via a DISCONN_NOTIFY from the server.
 */
DP_DECL_TEST_CASE(cgn_pptp, cgn_pptp7, NULL, NULL);
DP_START_TEST(cgn_pptp7, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_netlink_add_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_add_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp on");

	/*
	 * Add CGNAT rule.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/1.0.0.2 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "2.0.0.20/32", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for pptp ctrl flow
	  */
	struct dpt_tcp_flow pptp_ctrl_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(pptp_ctrl_call.text, sizeof(pptp_ctrl_call), "Ctrl");

	struct pptp_start_req start_req = {0};
	struct pptp_start_reply start_reply = {0};
	struct pptp_call_req call_req_pre = {0};
	struct pptp_call_reply call_reply_pre = {0};
	struct pptp_call_req call_req_pst;
	struct pptp_call_reply call_reply_pst;

	/*
	 * Comment this out to test call being cleared by a DISCONN_NOTIFY
	 * from the server.
	 */
#define PPTP7_CLEAR_REQ
#ifdef PPTP7_CLEAR_REQ
	struct pptp_call_clear_req call_clear_req_pre = {0};
	struct pptp_call_clear_req call_clear_req_pst;
#else
	struct pptp_disc_notify call_disc_notify = {0};
#endif

	/* PPTP Start Request */
	start_req.pptp_length	= htons(sizeof(start_req));
	start_req.pptp_type		= htons(1);
	start_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_req.pptp_ctrl_type	= htons(1);
	start_req.pptp_version	= htons(0x100);
	start_req.pptp_framing_cap	= htonl(1);
	start_req.pptp_bearer_cap	= htonl(1);
	start_req.pptp_max_channels	= htons(65535);
	start_req.pptp_firmware	= htons(0x100);
	snprintf(start_req.pptp_host_name, 64, "local");
	snprintf(start_req.pptp_vendor_name, 64, "ixia");

	/* PPTP Start Reply */
	start_reply.pptp_length	= htons(sizeof(start_reply));
	start_reply.pptp_type	= htons(1);
	start_reply.pptp_magic_cookie = htonl(0x1a2b3c4d);
	start_reply.pptp_ctrl_type	= htons(2);
	start_reply.pptp_version	= htons(0x100);
	start_reply.pptp_result_code = 1;
	start_reply.pptp_error_code	= 0;

	start_reply.pptp_framing_cap = htonl(3);
	start_reply.pptp_bearer_cap	= htonl(3);
	start_reply.pptp_max_channels = htons(0);
	start_reply.pptp_firmware	= htons(0x1200);
	snprintf(start_reply.pptp_host_name, 64, "ixro-smdev-r1");
	snprintf(start_reply.pptp_vendor_name, 64, "Cisco Systems, Inc.");

	/* Call Request */
	call_req_pre.pptp_length	= htons(sizeof(call_req_pre));
	call_req_pre.pptp_type		= htons(1);
	call_req_pre.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_req_pre.pptp_ctrl_type	= htons(7);

	call_req_pre.pptp_call_id	= htons(1);	/* Fwds 'source ID' */
	call_req_pre.pptp_min_bps	= htonl(0x8000);
	call_req_pre.pptp_max_bps	= htonl(0x80000000);
	call_req_pre.pptp_bearer_type	= htonl(1);
	call_req_pre.pptp_framing_type	= htonl(1);
	call_req_pre.pptp_window	= htons(10);

	call_req_pst = call_req_pre;
	call_req_pst.pptp_call_id = htons(1024);	/* 'src ID' NATd to 1024 */

	/* Call Reply */
	call_reply_pre.pptp_length	= htons(sizeof(call_reply_pre));
	call_reply_pre.pptp_type	= htons(1);
	call_reply_pre.pptp_magic_cookie = htonl(0x1a2b3c4d);
	call_reply_pre.pptp_ctrl_type	= htons(8);
	call_reply_pre.pptp_call_id	= htons(24);
	call_reply_pre.pptp_peer_call_id = htons(1024);
	call_reply_pre.pptp_result_code	= 1;
	call_reply_pre.pptp_conn_speed	= htonl(6400);
	call_reply_pre.pptp_window	= htons(16);

	call_reply_pst = call_reply_pre;
	call_reply_pst.pptp_peer_call_id = htons(1);

#ifdef PPTP7_CLEAR_REQ
	/* Call clear request */
	call_clear_req_pre.pptp_length	= htons(sizeof(call_clear_req_pre));
	call_clear_req_pre.pptp_type		= htons(1);
	call_clear_req_pre.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_clear_req_pre.pptp_ctrl_type	= htons(12);
	call_clear_req_pre.pptp_call_id	= htons(1);

	call_clear_req_pst = call_clear_req_pre;
	call_clear_req_pst.pptp_call_id = htons(1024);
#else
	/* Call disconnect notify */
	call_disc_notify.pptp_length	= htons(sizeof(call_disc_notify));
	call_disc_notify.pptp_type		= htons(1);
	call_disc_notify.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_disc_notify.pptp_ctrl_type	= htons(13);
	call_disc_notify.pptp_call_id	= htons(24);
#endif

	struct dpt_tcp_flow_pkt pptp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		/* PPTP Start Control Connection Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(start_req), (char *)&start_req,
		  sizeof(start_req), (char *)&start_req
		},

		/* PPTP Start Control Connection Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(start_reply), (char *)&start_reply,
		  sizeof(start_reply), (char *)&start_reply
		},

		/* PPTP Outgoing Call Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_req_pre), (char *)&call_req_pre,
		  sizeof(call_req_pst), (char *)&call_req_pst
		},

		/* 6. PPTP Outgoing Call Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_reply_pre), (char *)&call_reply_pre,
		  sizeof(call_reply_pst), (char *)&call_reply_pst
		},
#ifdef PPTP7_CLEAR_REQ
		/* 7. Call clear req (client to server) */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_clear_req_pre), (char *)&call_clear_req_pre,
		  sizeof(call_clear_req_pst), (char *)&call_clear_req_pst
		},
#else
		/* 7. PPTP disconnect notify (server to client) */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_disc_notify), (char *)&call_disc_notify,
		  sizeof(call_disc_notify), (char *)&call_disc_notify
		},
#endif
		/* 8, 9, 10 */
		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of pptp ctrl flow (pkts 0 - 6) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     0, 6, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/*
	 * At this point the VPN call is negotiated via PPP:
	 *  ip:gre:ppp:lcp
	 *  ip:gre:ppp:pap
	 *  ip:gre:ppp:ipcp
	 *  ip:gre:ppp:lcp
	 *
	 * After which it continues with just IP and GRE headers:
	 *  ip:gre
	 *  FORW: Call ID 24 ---->
	 *  BACK: Call ID 1  <----
	 */

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/*
	 * Call clear request or disconnect notify
	 */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     7, 7, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/****************************************************************
	 * Can we setup a second call over the same parent session?
	 */

	/*
	 * Call Request.
	 * client call ID changed from 1 to 2.  NATd to 1025
	 */
	call_req_pre.pptp_call_id = htons(2);
	call_req_pst.pptp_call_id = htons(1025);

	/*
	 * Call Reply
	 */
	call_reply_pre.pptp_call_id	= htons(25);
	call_reply_pst.pptp_call_id	= htons(25);
	call_reply_pre.pptp_peer_call_id = htons(1025);
	call_reply_pst.pptp_peer_call_id = htons(2);

	/*
	 * PPTP Call Req and Call Reply (pkts 5 - 6)
	 */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     5, 6, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 25, "1.0.0.20",
		"1.0.0.2",  25, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	if (0)
		cgn_alg_show_sessions();

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1025, "1.0.0.2",
		"1.0.0.20", 2, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* End of pptp ctrl flow (pkts 8 - end) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     8, 0, NULL, 0);

	/* Cleanup */
	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp off");

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_netlink_del_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_del_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * fw out.  Allow CGNAT src.  Drop subscriber src
 */
static void npf_fw_out(bool add)
{
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp2T1", real_ifname);

	if (add) {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:FW_OUT 10 action=accept src-addr=1.0.0.0/24");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:FW_OUT 20 action=drop src-addr=2.0.0.0/24");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut attach interface:%s fw-out fw:FW_OUT",
			real_ifname);
	} else {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut detach interface:%s fw-out fw:FW_OUT",
			real_ifname);
		dp_test_npf_cmd_fmt(false, "npf-ut delete fw:FW_OUT");
	}
	dp_test_npf_commit();
}

/*
 * fw in.  Allow subscriber src.  Drop CGNAT src
 */
static void npf_fw_in(bool add)
{
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp1T0", real_ifname);

	if (add) {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:FW_IN 10 action=drop src-addr=1.0.0.0/24");
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:FW_IN 20 action=accept src-addr=2.0.0.0/24");

		dp_test_npf_cmd_fmt(false,
				    "npf-ut attach interface:%s fw-in fw:FW_IN",
				    real_ifname);
	} else {
		dp_test_npf_cmd_fmt(false,
				    "npf-ut detach interface:%s fw-in fw:FW_IN",
				    real_ifname);
		dp_test_npf_cmd_fmt(false, "npf-ut delete fw:FW_IN");
	}
	dp_test_npf_commit();
}

/*
 * cgn_pptp8 - In and Out firewalls in outbound CGNAT pkt path
 */
DP_DECL_TEST_CASE(cgn_pptp, cgn_pptp8, NULL, NULL);
DP_START_TEST(cgn_pptp8, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_netlink_add_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_add_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp on");

	/*
	 * Add CGNAT rule.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/1.0.0.2 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "2.0.0.20/32", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	npf_fw_out(true);
	npf_fw_in(true);

	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "1.0.0.2", 1024,
		 "dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "0:9:e9:55:c0:1c", "1.0.0.20", 1723,
		 "0:14:0:0:2:0", "2.0.0.20", 1999,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for pptp ctrl flow
	  */
	struct dpt_tcp_flow pptp_ctrl_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(pptp_ctrl_call.text, sizeof(pptp_ctrl_call), "Ctrl");

	struct pptp_start_req start_req = {0};
	struct pptp_start_reply start_reply = {0};
	struct pptp_call_req call_req_pre = {0};
	struct pptp_call_reply call_reply_pre = {0};
	struct pptp_call_req call_req_pst;
	struct pptp_call_reply call_reply_pst;


	/* PPTP Start Request */
	start_req.pptp_length	= htons(sizeof(start_req));
	start_req.pptp_type		= htons(1);
	start_req.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	start_req.pptp_ctrl_type	= htons(1);
	start_req.pptp_version	= htons(0x100);
	start_req.pptp_framing_cap	= htonl(1);
	start_req.pptp_bearer_cap	= htonl(1);
	start_req.pptp_max_channels	= htons(65535);
	start_req.pptp_firmware	= htons(0x100);
	snprintf(start_req.pptp_host_name, 64, "local");
	snprintf(start_req.pptp_vendor_name, 64, "ixia");

	/* PPTP Start Reply */
	start_reply.pptp_length	= htons(sizeof(start_reply));
	start_reply.pptp_type	= htons(1);
	start_reply.pptp_magic_cookie = htonl(0x1a2b3c4d);
	start_reply.pptp_ctrl_type	= htons(2);
	start_reply.pptp_version	= htons(0x100);
	start_reply.pptp_result_code = 1;
	start_reply.pptp_error_code	= 0;

	start_reply.pptp_framing_cap = htonl(3);
	start_reply.pptp_bearer_cap	= htonl(3);
	start_reply.pptp_max_channels = htons(0);
	start_reply.pptp_firmware	= htons(0x1200);
	snprintf(start_reply.pptp_host_name, 64, "ixro-smdev-r1");
	snprintf(start_reply.pptp_vendor_name, 64, "Cisco Systems, Inc.");

	/* Call Request */
	call_req_pre.pptp_length	= htons(sizeof(call_req_pre));
	call_req_pre.pptp_type		= htons(1);
	call_req_pre.pptp_magic_cookie	= htonl(0x1a2b3c4d);
	call_req_pre.pptp_ctrl_type	= htons(7);

	call_req_pre.pptp_call_id	= htons(1);	/* Fwds 'source ID' */
	call_req_pre.pptp_min_bps	= htonl(0x8000);
	call_req_pre.pptp_max_bps	= htonl(0x80000000);
	call_req_pre.pptp_bearer_type	= htonl(1);
	call_req_pre.pptp_framing_type	= htonl(1);
	call_req_pre.pptp_window	= htons(10);

	call_req_pst = call_req_pre;
	call_req_pst.pptp_call_id = htons(1024);	/* 'src ID' NATd to 1024 */

	/* Call Reply */
	call_reply_pre.pptp_length	= htons(sizeof(call_reply_pre));
	call_reply_pre.pptp_type	= htons(1);
	call_reply_pre.pptp_magic_cookie = htonl(0x1a2b3c4d);
	call_reply_pre.pptp_ctrl_type	= htons(8);
	call_reply_pre.pptp_call_id	= htons(24);
	call_reply_pre.pptp_peer_call_id = htons(1024);
	call_reply_pre.pptp_result_code	= 1;
	call_reply_pre.pptp_conn_speed	= htonl(6400);
	call_reply_pre.pptp_window	= htons(16);

	call_reply_pst = call_reply_pre;
	call_reply_pst.pptp_peer_call_id = htons(1);

	struct dpt_tcp_flow_pkt pptp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		/* PPTP Start Control Connection Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(start_req), (char *)&start_req,
		  sizeof(start_req), (char *)&start_req
		},

		/* PPTP Start Control Connection Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(start_reply), (char *)&start_reply,
		  sizeof(start_reply), (char *)&start_reply
		},

		/* PPTP Outgoing Call Request */
		{ DPT_FORW, TH_ACK,
		  sizeof(call_req_pre), (char *)&call_req_pre,
		  sizeof(call_req_pst), (char *)&call_req_pst
		},

		/* PPTP Outgoing Call Reply */
		{ DPT_BACK, TH_ACK,
		  sizeof(call_reply_pre), (char *)&call_reply_pre,
		  sizeof(call_reply_pst), (char *)&call_reply_pst
		},

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of pptp ctrl flow (pkts 0 - 6) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     0, 6, NULL, 0);


	/*
	 * At this point the VPN call is negotiated via PPP:
	 *  ip:gre:ppp:lcp
	 *  ip:gre:ppp:pap
	 *  ip:gre:ppp:ipcp
	 *  ip:gre:ppp:lcp
	 *
	 * After which it continues with just IP and GRE headers:
	 *  ip:gre
	 *  FORW: Call ID 24 ---->
	 *  BACK: Call ID 1  <----
	 */

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* FORW */
	dpt_gre("dp1T0", "0:14:0:0:2:0",
		"2.0.0.20", 24, "1.0.0.20",
		"1.0.0.2",  24, "1.0.0.20",
		"0:9:e9:55:c0:1c", "dp2T1",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* BACK */
	dpt_gre("dp2T1", "0:9:e9:55:c0:1c",
		"1.0.0.20", 1024, "1.0.0.2",
		"1.0.0.20", 1, "2.0.0.20",
		"0:14:0:0:2:0", "dp1T0",
		DP_TEST_FWD_FORWARDED, NULL, 0);

	/* End of pptp ctrl flow (pkts 7 - end) */
	dpt_tcp_call(&pptp_ctrl_call, pptp_ctrl_pkts, ARRAY_SIZE(pptp_ctrl_pkts),
		     7, 0, NULL, 0);

	npf_fw_in(false);
	npf_fw_out(false);

	/* Cleanup */
	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	dp_test_npf_cmd_fmt(false, "cgn-ut alg pptp off");

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_netlink_del_neigh("dp1T0", "2.0.0.20", "0:14:0:0:2:0");
	dp_test_netlink_del_neigh("dp2T1", "1.0.0.20", "0:9:e9:55:c0:1c");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.0.0.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.0.0.1/24");

	dp_test_npf_cleanup();

} DP_END_TEST;
