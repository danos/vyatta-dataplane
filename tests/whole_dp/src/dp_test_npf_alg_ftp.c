/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf alg ftp tests.
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
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_alg_lib.h"


/*
 * In the SNAT tests, client is on the inside and server on the outside.
 *
 * With Passive FTP and SNAT (ftp4), the packet containing the data address
 * and port is from the server, so does not need translated.  Initial data pkt
 * is *from* the client.
 *
 * With Active FTP and SNAT (ftp7), the packet containing the data address and
 * port is from the client, so *does* need translated.  And may result in
 * change of length of payload.  Initial data pkt is *from* the server.
 *
 * With Passive FTP, the control and data flows both start in the same
 * direction (i.e. forwards).
 *
 * With Active FTP, the data flow starts in the reverse direction.
 *
 * With SNAT and Active FTP, the difference in size between the source address
 * string and the translation address string will alter the length of the TCP
 * data, and hence cause a difference in TCP seq and ack between sender and
 * receiver.  Tests ftp8 and ftp9 test that the FTP ALG adjusts the TCP header
 * accordingly.
 *
 * ftp1  ~ No NAT Passive ftp. '227' back.
 * ftp2  ~ No NAT Passive ftp. Stateful firewall. IPv4. '227' back.
 * ftp3  ~ No NAT Passive ftp. Stateful firewall. IPv6. '227' back.
 * ftp4  - SNAT   Passive ftp. '227' back.
 * ftp5  - DNAT   Passive ftp. '227' back.
 * ftp6  ~ DNAT   Passive ftp. No parenthesis in 227 message.
 * ftp7  ~ SNAT   Active ftp. 'PORT' forw.
 * ftp8  - SNAT   Active ftp. Translating to a larger address. 'PORT' forw.
 * ftp9  - SNAT   Active ftp. Translating to a smaller address. 'PORT' forw.
 * ftp10 - DNAT   Active ftp. 'PORT' forw.
 * ftp11 - SNAT   Ext. Passive ftp. Src port is outside of trans port range.
 * ftp12 - SNAT   Active ftp. Src port is outside of trans port range.
 */

static void dpt_alg_ftp_setup(void);
static void dpt_alg_ftp_teardown(void);


DP_DECL_TEST_SUITE(npf_alg_ftp);

/*
 * ftp1 - Passive ftp.  No firewall or NAT.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp1, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST_FULL_RUN(ftp1, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
		.text[0] = '\0',			/* description */
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */
		{ DPT_FORW, TH_ACK, 0,
		  (char *)"SYST\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK, 0,
		  (char *)"215 UNIX Type: L8\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK, 0,
		  (char *)"TYPE I\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK, 0,
		  (char *)"200 Switching to Binary mode.\x0d\x0a",
		  0, NULL },

		{ DPT_FORW, TH_ACK, 0,
		  (char *)"PASV\x0d\x0a", 0, NULL },

		/*
		 * #8. Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		{ DPT_BACK, TH_ACK, 0,
		  (char *)"227 Entering Passive Mode (2,2,2,11,38,91).\r\n",
		  0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',			/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 8) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 8, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 9 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     9, 0, NULL, 0);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

} DP_END_TEST;


/*
 * ftp2 - Passive ftp.  Stateful firewall on output interface.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp2, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST_FULL_RUN(ftp2, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

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
			.npf      = "proto-final=6 dst-port=21"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "OUT_FW",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rset
	};

	dp_test_npf_fw_add(&fw, false);

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */
		{ DPT_FORW, TH_ACK, 0,
		  (char *)"SYST\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK, 0,
		  (char *)"215 UNIX Type: L8\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK, 0,
		  (char *)"TYPE I\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK, 0,
		  (char *)"200 Switching to Binary mode.\x0d\x0a",
		  0, NULL },

		{ DPT_FORW, TH_ACK, 0,
		  (char *)"PASV\x0d\x0a", 0, NULL },

		/*
		 * #8. Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		{ DPT_BACK, TH_ACK, 0,
		  (char *)"227 Entering Passive Mode (2,2,2,11,38,91).\r\n",
		  0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',			/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 8) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 8, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 9 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     9, 0, NULL, 0);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_fw_del(&fw, false);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp3 - Passive ftp.  Stateful firewall. IPv6.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp3, NULL, NULL);
DP_START_TEST_FULL_RUN(ftp3, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

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
			.npf      = "proto-final=6 dst-port=21"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "OUT_FW",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rset
	};

	dp_test_npf_fw_add(&fw, false);

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v6_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:a1", "2001:1:1::2", 46682,
		 dp1T0_mac, "2002:2:2::1", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v6_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 dp2T1_mac, "2001:1:1::2", 46682,
		 "aa:bb:cc:dd:2:b1", "2002:2:2::1", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v6_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:b1", "2002:2:2::1", 21,
		 dp2T1_mac, "2001:1:1::2", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v6_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 dp1T0_mac, "2002:2:2::1", 21,
		 "aa:bb:cc:dd:1:a1", "2001:1:1::2", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v6_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:a1", "2001:1:1::2", 46682,
		 dp1T0_mac, "2002:2:2::1", data_port,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v6_create(
		 "data_fw_pst", IPPROTO_TCP,
		 dp2T1_mac, "2001:1:1::2", 46682,
		 "aa:bb:cc:dd:2:b1", "2002:2:2::1", data_port,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v6_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:b1", "2002:2:2::1", data_port,
		 dp2T1_mac, "2001:1:1::2", 46682,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v6_create(
		 "data_bk_pst", IPPROTO_TCP,
		 dp1T0_mac, "2002:2:2::1", data_port,
		 "aa:bb:cc:dd:1:a1", "2001:1:1::2", 46682,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */
		{ DPT_FORW, TH_ACK, 0,
		  (char *)"SYST\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK, 0,
		  (char *)"215 UNIX Type: L8\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK, 0,
		  (char *)"TYPE I\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK, 0,
		  (char *)"200 Switching to Binary mode.\x0d\x0a",
		  0, NULL },

		{ DPT_FORW, TH_ACK, 0,
		  (char *)"PASV\x0d\x0a", 0, NULL },

		/*
		 * #8. Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		{ DPT_BACK, TH_ACK, 0,
		  (char *)"227 Entering Passive Mode (2,2,2,11,38,91).\r\n",
		  0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',			/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL},

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 8) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 8, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 9 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     9, 0, NULL, 0);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_fw_del(&fw, false);

	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

	/* Setup interfaces and neighbours */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

} DP_END_TEST;


/*
 * ftp4 - SNAT, Passive ftp.
 *
 * The packet containing the data address and port is from the server, so does
 * not need translated.  Initial data pkt is *from* the client.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp4, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST(ftp4, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= "1.1.1.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.20",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);


	/* ftp port appears as 2 numbers in the string */
	uint16_t data_port_upr;
	uint16_t data_port_lwr;
	uint16_t data_port;

	/* Data port is 2559 */
	data_port_upr = 9;
	data_port_lwr = 255;
	data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * ftp control flow packets
	 */
	ctrl_fw_pre = dpt_pdesc_v4_create(
		"ctrl_fw_pre", IPPROTO_TCP,
		"aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		"aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		"dp1T0", "dp2T1");

	ctrl_fw_pst = dpt_pdesc_v4_create(
		"ctrl_fw_pst", IPPROTO_TCP,
		"aa:bb:cc:dd:1:11", "2.2.2.20", 46682,
		"aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		"dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		"ctrl_bk_pre", IPPROTO_TCP,
		"aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		"aa:bb:cc:dd:1:11", "2.2.2.20", 46682,
		"dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		"ctrl_bk_pst", IPPROTO_TCP,
		"aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		"aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		"dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	data_fw_pre = dpt_pdesc_v4_create(
		"data_fw_pre", IPPROTO_TCP,
		"aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		"aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		"dp1T0", "dp2T1");

	data_fw_pst = dpt_pdesc_v4_create(
		"data_fw_pst", IPPROTO_TCP,
		"aa:bb:cc:dd:1:11", "2.2.2.20", 49888,
		"aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		"dp1T0", "dp2T1");

	data_bk_pre = dpt_pdesc_v4_create(
		"data_bk_pre", IPPROTO_TCP,
		"aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		"aa:bb:cc:dd:1:11", "2.2.2.20", 49888,
		"dp2T1", "dp1T0");

	data_bk_pst = dpt_pdesc_v4_create(
		"data_bk_pst", IPPROTO_TCP,
		"aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		"aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		"dp2T1", "dp1T0");

	/*
	 * Packet descriptors for ftp ctrl flow
	 */
	struct dpt_tcp_flow ftp_ctrl_call = {
		.text[0] = '\0',	/* description */
		.isn = {0, 0},		/* initial seq no */
		.desc[DPT_FORW] = {	/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {	/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,	/* Prep and send pkt */
		.post_cb = NULL,	/* Fixup pkt exp */
	};
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call),
		 "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */
		{ DPT_FORW, TH_ACK,
		  0, (char *)"SYST\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK,
		  0, (char *)"215 UNIX Type: L8\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK,
		  0, (char *)"TYPE I\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK,
		  0,
		  (char *)"200 Switching to Binary mode.\x0d\x0a",
		  0, NULL },

		{ DPT_FORW, TH_ACK,
		  0, (char *)"PASV\x0d\x0a", 0, NULL },

		/*
		 * #8. Response: 227.  Server telling client which
		 * address and port to use for data channel.  Address
		 * is 2.2.2.11, port is 9819
		 */
		{ DPT_BACK, TH_ACK, 0,
		  (char *)"227 Entering Passive Mode (2,2,2,11,9,255).\r\n",
		  0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/*
	 * Packet descriptors for ftp data flow
	 */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',	/* description */
		.isn = {0, 0},		/* initial seq no */
		.desc[DPT_FORW] = {	/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {	/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,	/* Prep and send pkt */
		.post_cb = NULL,	/* Fixup pkt exp */
	};

	snprintf(ftp_data_call.text, sizeof(ftp_data_call),
		 "Data, port %u", data_port);

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 8) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts,
		     ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 8, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts,
		     ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 9 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts,
		     ARRAY_SIZE(ftp_ctrl_pkts),
		     9, 0, NULL, 0);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp5 - DNAT, Passive ftp.
 *
 * With Passive FTP, the control and data flows both start in the same
 * direction (i.e. forwards).
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp5, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST(ftp5, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.20",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", data_port,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", data_port,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */
		{ DPT_FORW, TH_ACK,
		  0, (char *)"SYST\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK,
		  0, (char *)"215 UNIX Type: L8\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK,
		  0, (char *)"TYPE I\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK,
		  0, (char *)"200 Switching to Binary mode.\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK,
		  0, (char *)"PASV\x0d\x0a", 0, NULL },

		/*
		 * #8. Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, which
		 * is reverse-dnatd to 2.2.2.20.  Port is 9819.  (38 == 0x26,
		 * 91 == 0x5B, 0x265B == 9819).
		 *
		 * The alg creates a tuple: "TCP 1.1.1.1:any -> 2.2.2.20:9819"
		 * in order to detect the data flow which start in the reverse
		 * direction.
		 */
		{ DPT_BACK, TH_ACK, 0,
		  (char *)"227 Entering Passive Mode (2,2,2,11,38,91).\r\n",
		  0,
		  (char *)"227 Entering Passive Mode (2,2,2,20,38,91).\r\n" },

		/* Data call is done at this point */

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 8) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 8, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 9 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     9, 0, NULL, 0);

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp6 - DNAT, Passive ftp. No parenthesis in 227 message.
 *
 * With Passive FTP, the control and data flows both start in the same
 * direction (i.e. forwards).
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp6, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST_FULL_RUN(ftp6, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.20",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", data_port,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", data_port,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */
		{ DPT_FORW, TH_ACK,
		  0, (char *)"SYST\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK,
		  0, (char *)"215 UNIX Type: L8\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK,
		  0, (char *)"TYPE I\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK,
		  0, (char *)"200 Switching to Binary mode.\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK,
		  0, (char *)"PASV\x0d\x0a", 0, NULL },

		/*
		 * #8. Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, which
		 * is reverse-dnatd to 2.2.2.20.  Port is 9819.  (38 == 0x26,
		 * 91 == 0x5B, 0x265B == 9819).
		 *
		 * The alg creates a tuple: "TCP 1.1.1.1:any -> 2.2.2.20:9819"
		 * in order to detect the data flow which start in the reverse
		 * direction.
		 */
		{ DPT_BACK, TH_ACK, 0,
		  (char *)"227 Entering Passive Mode 2,2,2,11,38,91\r\n",
		  0,
		  (char *)"227 Entering Passive Mode 2,2,2,20,38,91\r\n" },

		/* Data call is done at this point */

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',			/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 8) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 8, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 9 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     9, 0, NULL, 0);

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp7 - SNAT, Active ftp.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp7, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST_FULL_RUN(ftp7, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= "1.1.1.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.20",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "2.2.2.20", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "2.2.2.20", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "2.2.2.20", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "2.2.2.20", data_port,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */

		/*
		 * PORT command.  Client specifies which client-side port that
		 * the server should use for data flow.  Port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		{ DPT_FORW, TH_ACK, 0,
		  (char *)"PORT 1,1,1,11,38,91\x0d\x0a",
		  0,
		  (char *)"PORT 2,2,2,20,38,91\x0d\x0a" },

		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_BACK, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 4) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 4, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 5 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     5, 0, NULL, 0);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp9 - SNAT, Active ftp.  Translation address is larger.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp8, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST(ftp8, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= "1.1.1.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.200",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "2.2.2.200", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "2.2.2.200", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "2.2.2.200", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "2.2.2.200", data_port,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */

		/*
		 * PORT command.  Client specifies which client-side port that
		 * the server should use for data flow.  Port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		{ DPT_FORW, TH_ACK, 0,
		  (char *)"PORT 1,1,1,11,38,91\x0d\x0a",
		  0,
		  (char *)"PORT 2,2,2,200,38,91\x0d\x0a" },

		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_BACK, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 4) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 4, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 5 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     5, 0, NULL, 0);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp9 - SNAT, Active ftp.  Translation address is smaller.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp9, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST(ftp9, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= "1.1.1.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.5",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "2.2.2.5", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "2.2.2.5", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "2.2.2.5", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "2.2.2.5", data_port,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */

		/*
		 * PORT command.  Client specifies which client-side port that
		 * the server should use for data flow.  Port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		{ DPT_FORW, TH_ACK, 0,
		  (char *)"PORT 1,1,1,11,38,91\x0d\x0a",
		  0,
		  (char *)"PORT 2,2,2,5,38,91\x0d\x0a" },

		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_BACK, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 4) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 4, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 5 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     5, 0, NULL, 0);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp10 - DNAT, Active ftp.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp10, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST(ftp10, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.20",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", 20,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.20", 20,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
		.text[0] = '\0',			/* description */
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */
		/*
		 * PORT command.  Client specifies which client-side port that
		 * the server should use for data flow.  Port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		{ DPT_FORW, TH_ACK, 0,
		  (char *)"PORT 1,1,1,11,38,91\x0d\x0a",
		  0, NULL },

		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		/* Data call is done at this point */

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',			/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_BACK, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 4) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 4, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 5 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     5, 0, NULL, 0);

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp11 - SNAT, Extended Passive ftp.  Source port is outside of trans port
 * range.
 *
 * Earlier SNAT tests relied on 'port preservation', in that the inside port
 * was within the translation port range and hence the same same port nu,ber
 * could be used (provided it was available).
 *
 * This test forces the SNAT to change the port number during the translation.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp11, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST(ftp11, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= "sequential",
		.from_addr	= "1.1.1.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.20",
		.trans_port	= "10000-20000"
	};

	dp_test_npf_snat_add(&snat, true);

	/* Data port is 2559 */
	uint16_t data_port = 2559;

	/*
	 * ftp control flow packets
	 */
	ctrl_fw_pre = dpt_pdesc_v4_create(
		"ctrl_fw_pre", IPPROTO_TCP,
		"aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		"aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		"dp1T0", "dp2T1");

	ctrl_fw_pst = dpt_pdesc_v4_create(
		"ctrl_fw_pst", IPPROTO_TCP,
		"aa:bb:cc:dd:1:11", "2.2.2.20", 10000,
		"aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		"dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		"ctrl_bk_pre", IPPROTO_TCP,
		"aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		"aa:bb:cc:dd:1:11", "2.2.2.20", 10000,
		"dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		"ctrl_bk_pst", IPPROTO_TCP,
		"aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		"aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		"dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	data_fw_pre = dpt_pdesc_v4_create(
		"data_fw_pre", IPPROTO_TCP,
		"aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		"aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		"dp1T0", "dp2T1");

	data_fw_pst = dpt_pdesc_v4_create(
		"data_fw_pst", IPPROTO_TCP,
		"aa:bb:cc:dd:1:11", "2.2.2.20", 10001,
		"aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		"dp1T0", "dp2T1");

	data_bk_pre = dpt_pdesc_v4_create(
		"data_bk_pre", IPPROTO_TCP,
		"aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		"aa:bb:cc:dd:1:11", "2.2.2.20", 10001,
		"dp2T1", "dp1T0");

	data_bk_pst = dpt_pdesc_v4_create(
		"data_bk_pst", IPPROTO_TCP,
		"aa:bb:cc:dd:2:11", "2.2.2.11", data_port,
		"aa:bb:cc:dd:1:11", "1.1.1.11", 49888,
		"dp2T1", "dp1T0");

	/*
	 * Packet descriptors for ftp ctrl flow
	 */
	struct dpt_tcp_flow ftp_ctrl_call = {
		.text[0] = '\0',	/* description */
		.isn = {0, 0},		/* initial seq no */
		.desc[DPT_FORW] = {	/* Forw pkt descriptors */
			.pre = ctrl_fw_pre,
			.pst = ctrl_fw_pst,
		},
		.desc[DPT_BACK] = {	/* Back pkt descriptors */
			.pre = ctrl_bk_pre,
			.pst = ctrl_bk_pst,
		},
		.test_cb = NULL,	/* Prep and send pkt */
		.post_cb = NULL,	/* Fixup pkt exp */
	};
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call),
		 "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */
		{ DPT_FORW, TH_ACK,
		  0, (char *)"SYST\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK,
		  0, (char *)"215 UNIX Type: L8\x0d\x0a", 0, NULL },

		{ DPT_FORW, TH_ACK,
		  0, (char *)"TYPE I\x0d\x0a", 0, NULL },

		{ DPT_BACK, TH_ACK,
		  0,
		  (char *)"200 Switching to Binary mode.\x0d\x0a",
		  0, NULL },

		{ DPT_FORW, TH_ACK,
		  0, (char *)"EPSV\x0d\x0a", 0, NULL },

		/*
		 * #8. Response: 229.  Server telling client which
		 * address and port to use for data channel. port is 2559.
		 */
		{ DPT_BACK, TH_ACK, 0,
		  (char *)"229 Entering Extended Passive Mode (|||2559|)\r\n",
		  0,
		  (char *)"229 Entering Extended Passive Mode (|||2559|)\r\n" },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/*
	 * Packet descriptors for ftp data flow
	 */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',	/* description */
		.isn = {0, 0},		/* initial seq no */
		.desc[DPT_FORW] = {	/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {	/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,	/* Prep and send pkt */
		.post_cb = NULL,	/* Fixup pkt exp */
	};

	snprintf(ftp_data_call.text, sizeof(ftp_data_call),
		 "Data, port %u", data_port);

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 8) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts,
		     ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 8, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts,
		     ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 9 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts,
		     ARRAY_SIZE(ftp_ctrl_pkts),
		     9, 0, NULL, 0);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * ftp12 - SNAT, Active ftp.  Source port is outside of trans port range.
 */
DP_DECL_TEST_CASE(npf_alg_ftp, ftp12, dpt_alg_ftp_setup, dpt_alg_ftp_teardown);
DP_START_TEST(ftp12, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;
	struct dp_test_pkt_desc_t *data_fw_pre, *data_fw_pst;
	struct dp_test_pkt_desc_t *data_bk_pre, *data_bk_pst;

	/* ftp port appears as 2 numbers in the string */
	uint8_t data_port_upr = 38;
	uint8_t data_port_lwr = 91;
	uint16_t data_port = (data_port_upr * 256) + data_port_lwr;

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= "sequential",
		.from_addr	= "1.1.1.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.20",
		.trans_port	= "1024-1030"
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * ftp control flow packets
	 */
	 ctrl_fw_pre = dpt_pdesc_v4_create(
		 "ctrl_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_fw_pst = dpt_pdesc_v4_create(
		 "ctrl_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "2.2.2.20", 1024,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "dp1T0", "dp2T1");

	 ctrl_bk_pre = dpt_pdesc_v4_create(
		 "ctrl_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "2.2.2.20", 1024,
		 "dp2T1", "dp1T0");

	 ctrl_bk_pst = dpt_pdesc_v4_create(
		 "ctrl_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 21,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", 46682,
		 "dp2T1", "dp1T0");

	/*
	 * ftp data flow packets
	 */
	 data_fw_pre = dpt_pdesc_v4_create(
		 "data_fw_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_fw_pst = dpt_pdesc_v4_create(
		 "data_fw_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:1:11", "2.2.2.20", 1025,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "dp1T0", "dp2T1");

	 data_bk_pre = dpt_pdesc_v4_create(
		 "data_bk_pre", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "2.2.2.20", 1025,
		 "dp2T1", "dp1T0");

	 data_bk_pst = dpt_pdesc_v4_create(
		 "data_bk_pst", IPPROTO_TCP,
		 "aa:bb:cc:dd:2:11", "2.2.2.11", 20,
		 "aa:bb:cc:dd:1:11", "1.1.1.11", data_port,
		 "dp2T1", "dp1T0");

	 /*
	  * Packet descriptors for ftp ctrl flow
	  */
	struct dpt_tcp_flow ftp_ctrl_call = {
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
	snprintf(ftp_ctrl_call.text, sizeof(ftp_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for ftp ctrl flow
	 */
	struct dpt_tcp_flow_pkt ftp_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* session established */

		/*
		 * PORT command.  Client specifies which client-side port that
		 * the server should use for data flow.  Port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819).
		 * Trans port is 1024
		 */
		{ DPT_FORW, TH_ACK, 0,
		  (char *)"PORT 1,1,1,11,38,91\x0d\x0a",
		  0,
		  (char *)"PORT 2,2,2,20,4,1\x0d\x0a" },

		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	 /*
	  * Packet descriptors for ftp data flow
	  */
	struct dpt_tcp_flow ftp_data_call = {
		.text[0] = '\0',		/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DPT_FORW] = {		/* Forw pkt descriptors */
			.pre = data_fw_pre,
			.pst = data_fw_pst,
		},
		.desc[DPT_BACK] = {		/* Back pkt descriptors */
			.pre = data_bk_pre,
			.pst = data_bk_pst,
		},
		.test_cb = NULL,		/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};
	snprintf(ftp_data_call.text, sizeof(ftp_data_call), "Data");

	struct dpt_tcp_flow_pkt ftp_data_pkts[] = {
		{ DPT_BACK, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK, 100, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK, 0, NULL, 0, NULL },
	};

	/* Start of ftp ctrl flow (pkts 0 - 4) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     0, 4, NULL, 0);

	/* ftp data flow */
	dpt_tcp_call(&ftp_data_call, ftp_data_pkts, ARRAY_SIZE(ftp_data_pkts),
		     0, 0, NULL, 0);

	/* End of ftp ctrl flow (pkts 5 - end) */
	dpt_tcp_call(&ftp_ctrl_call, ftp_ctrl_pkts, ARRAY_SIZE(ftp_ctrl_pkts),
		     5, 0, NULL, 0);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

	free(data_fw_pre);
	free(data_fw_pst);
	free(data_bk_pre);
	free(data_bk_pst);

	dp_test_npf_cleanup();

} DP_END_TEST;


static void dpt_alg_ftp_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11", "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12", "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.11", "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.12", "aa:bb:cc:dd:2:12");
}

static void dpt_alg_ftp_teardown(void)
{
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11", "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12", "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.11", "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.12", "aa:bb:cc:dd:2:12");
}
