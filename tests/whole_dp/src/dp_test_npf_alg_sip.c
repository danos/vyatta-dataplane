/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>

#include "dp_test.h"
#include "dp_test_netlink_state.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_sess_lib.h"

#include "dp_test_npf_alg_sip_data.h"

static void dpt_alg_sipd1_setup(void);
static void dpt_alg_sipd1_teardown(void);

static void dpt_alg_sipd2_setup(void);
static void dpt_alg_sipd2_teardown(void);

static void dpt_alg_sipd3_setup(void);
static void dpt_alg_sipd3_teardown(void);

static void dpt_alg_sipd4_setup(void);
static void dpt_alg_sipd4_teardown(void);

DP_DECL_TEST_SUITE(sip_nat);

/*
 * sip_nat10.  Data set #1. No NAT.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat10, dpt_alg_sipd1_setup,
		  dpt_alg_sipd1_teardown);
DP_START_TEST(sip_nat10, test)
{
	const char *desc, *pload;
	bool forw;
	uint i;

	static_assert(ARRAY_SIZE(sipd1) == ARRAY_SIZE(sipd1_dir),
		      "sipd1 array size incorrect");

	/* Verify the test data */
	sipd_check_content_len("sipd1", sipd1, ARRAY_SIZE(sipd1));

	/* For each SIP msg payload */
	for (i = 0; i < ARRAY_SIZE(sipd1); i++) {
		pload = sipd1[i];
		forw = (sipd1_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pload);

		if (forw) {
			dpt_udp_pl("dp1T0", "aa:bb:cc:16:0:20",
				   "1.1.1.2", 5060, "22.22.22.2", 5060,
				   "1.1.1.2", 5060, "22.22.22.2", 5060,
				   "aa:bb:cc:18:0:1", "dp2T1",
				   DP_TEST_FWD_FORWARDED,
				   pload, strlen(pload),
				   pload, strlen(pload), desc);
		} else {
			dpt_udp_pl("dp2T1", "aa:bb:cc:18:0:1",
				   "22.22.22.2", 5060, "1.1.1.2", 5060,
				   "22.22.22.2", 5060, "1.1.1.2", 5060,
				   "aa:bb:cc:16:0:20", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pload, strlen(pload),
				   pload, strlen(pload), desc);
		}
	}

} DP_END_TEST; /* sip_nat10 */

/*
 * sip_nat11.  Data Set #1. SNAT.
 *
 * RTP flow started in forw direction.  RTCP flow started in back direction.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat11, dpt_alg_sipd1_setup,
		  dpt_alg_sipd1_teardown);
DP_START_TEST(sip_nat11, test)
{
	const char *desc, *pre_pload, *pst_pload;
	bool forw;
	uint i;

	static_assert(ARRAY_SIZE(sipd1_pre_snat) ==
		      ARRAY_SIZE(sipd1_post_snat),
		      "sipd pre and post array size don't match");
	static_assert(ARRAY_SIZE(sipd1_pre_snat) == ARRAY_SIZE(sipd1_dir),
		      "spid pre snat array size incorrect");

	/* Configure SNAT with sequential port allocation */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.port_alloc	= "sequential",
		.from_addr	= "1.1.1.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "30.30.30.2",
		.trans_port	= "1024-2000",
	};
	dp_test_npf_snat_add(&snat, true);

	/* Verify the test data */
	sipd_check_content_len("sipd1_pre_snat", sipd1_pre_snat,
			       ARRAY_SIZE(sipd1_pre_snat));
	sipd_check_content_len("sipd1_post_snat", sipd1_post_snat,
			       ARRAY_SIZE(sipd1_post_snat));

	/* For each SIP msg payload */
	for (i = 0; i < ARRAY_SIZE(sipd1_pre_snat); i++) {
		pre_pload = sipd1_pre_snat[i];
		pst_pload = sipd1_post_snat[i];
		forw = (sipd1_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		if (forw) {
			dpt_udp_pl("dp1T0", "aa:bb:cc:16:0:20",
				   "1.1.1.2", 5060, "22.22.22.2", 5060,
				   "30.30.30.2", 1024, "22.22.22.2", 5060,
				   "aa:bb:cc:18:0:1", "dp2T1",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		} else {
			dpt_udp_pl("dp2T1", "aa:bb:cc:18:0:1",
				   "22.22.22.2", 5060, "30.30.30.2", 1024,
				   "22.22.22.2", 5060, "1.1.1.2", 5060,
				   "aa:bb:cc:16:0:20", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		}

		if (i == sipd1_rtp_index) {
			/* RTP Forw (Initial) */
			dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
				"1.1.1.2", 10000, "22.22.22.2", 60000,
				"30.30.30.2", 1026, "22.22.22.2", 60000,
				"aa:bb:cc:18:0:1", "dp2T1",
				DP_TEST_FWD_FORWARDED);

			/* RTP Back */
			dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
				"22.22.22.2", 60000, "30.30.30.2", 1026,
				"22.22.22.2", 60000, "1.1.1.2", 10000,
				"aa:bb:cc:16:0:20", "dp1T0",
				DP_TEST_FWD_FORWARDED);

			/* RTCP Back  (Initial) */
			dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
				"22.22.22.2", 60001, "30.30.30.2", 1027,
				"22.22.22.2", 60001, "1.1.1.2", 10001,
				"aa:bb:cc:16:0:20", "dp1T0",
				DP_TEST_FWD_FORWARDED);

			/* RTCP Forw */
			dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
				"1.1.1.2", 10001, "22.22.22.2", 60001,
				"30.30.30.2", 1027, "22.22.22.2", 60001,
				"aa:bb:cc:18:0:1", "dp2T1",
				DP_TEST_FWD_FORWARDED);

		}
	}

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

} DP_END_TEST; /* sip_nat11 */

/*
 * sip_nat12.  Data Set #1. DNAT.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat12, dpt_alg_sipd1_setup,
		  dpt_alg_sipd1_teardown);
DP_START_TEST(sip_nat12, test)
{
	const char *desc, *pre_pload, *pst_pload;
	bool forw;
	uint i;

	static_assert(ARRAY_SIZE(sipd1_pre_dnat) ==
		      ARRAY_SIZE(sipd1_post_dnat),
		      "sipd1 pre and post dnat array size don't match");
	static_assert(ARRAY_SIZE(sipd1_pre_dnat) == ARRAY_SIZE(sipd1_dir),
		      "spid pre dnat array size incorrect");

	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "1.1.1.22/24",
		.to_port	= NULL,
		.trans_addr	= "22.22.22.2",
		.trans_port	= NULL,
		.port_alloc	= NULL,
	};
	dp_test_npf_dnat_add(&dnat, true);

	/* Verify the test data */
	sipd_check_content_len("sipd1_pre_dnat", sipd1_pre_dnat,
			       ARRAY_SIZE(sipd1_pre_dnat));
	sipd_check_content_len("sipd1_post_dnat", sipd1_post_dnat,
			       ARRAY_SIZE(sipd1_post_dnat));

	/* For each SIP msg payload */
	for (i = 0; i < ARRAY_SIZE(sipd1_pre_dnat); i++) {
		pre_pload = sipd1_pre_dnat[i];
		pst_pload = sipd1_post_dnat[i];
		forw = (sipd1_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		if (forw) {
			dpt_udp_pl("dp1T0", "aa:bb:cc:16:0:20",
				   "1.1.1.2", 5060, "1.1.1.22", 5060,
				   "1.1.1.2", 5060, "22.22.22.2", 5060,
				   "aa:bb:cc:18:0:1", "dp2T1",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		} else {
			dpt_udp_pl("dp2T1", "aa:bb:cc:18:0:1",
				   "22.22.22.2", 5060, "1.1.1.2", 5060,
				   "1.1.1.22", 5060, "1.1.1.2", 5060,
				   "aa:bb:cc:16:0:20", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		}

		if (i == sipd1_rtp_index) {
			/* RTP Forw (Initial) */
			dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
				"1.1.1.2", 10000, "1.1.1.22", 60000,
				"1.1.1.2", 10000, "22.22.22.2", 60000,
				"aa:bb:cc:18:0:1", "dp2T1",
				DP_TEST_FWD_FORWARDED);

			/* RTP Back */
			dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
				"22.22.22.2", 60000, "1.1.1.2", 10000,
				"1.1.1.22", 60000, "1.1.1.2", 10000,
				"aa:bb:cc:16:0:20", "dp1T0",
				DP_TEST_FWD_FORWARDED);

			/* RTCP Back  (Initial) */
			dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
				"22.22.22.2", 60001, "1.1.1.2", 10001,
				"1.1.1.22", 60001, "1.1.1.2", 10001,
				"aa:bb:cc:16:0:20", "dp1T0",
				DP_TEST_FWD_FORWARDED);

			/* RTCP Forw */
			dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
				"1.1.1.2", 10001, "1.1.1.22", 60001,
				"1.1.1.2", 10001, "22.22.22.2", 60001,
				"aa:bb:cc:18:0:1", "dp2T1",
				DP_TEST_FWD_FORWARDED);

		}
	}

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

} DP_END_TEST; /* sip_nat12 */


/*
 * sip_nat13.  Data Set #1. SNAT.  TCP.
 *
 * RTP flow started in forw direction.  RTCP flow started in back direction.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat13, dpt_alg_sipd1_setup,
		  dpt_alg_sipd1_teardown);
DP_START_TEST(sip_nat13, test)
{
	struct dp_test_pkt_desc_t *ctrl_fw_pre, *ctrl_fw_pst;
	struct dp_test_pkt_desc_t *ctrl_bk_pre, *ctrl_bk_pst;

	static_assert(ARRAY_SIZE(sipd1_pre_snat) ==
		      ARRAY_SIZE(sipd1_post_snat),
		      "sipd pre and post array size don't match");
	static_assert(ARRAY_SIZE(sipd1_pre_snat) == ARRAY_SIZE(sipd1_dir),
		      "spid pre snat array size incorrect");

	/* Configure SNAT with sequential port allocation */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.port_alloc	= "sequential",
		.from_addr	= "1.1.1.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "30.30.30.2",
		.trans_port	= "1024-2000",
	};
	dp_test_npf_snat_add(&snat, true);

	ctrl_fw_pre = dpt_pdesc_v4_create(
		"ctrl_fw_pre", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "1.1.1.2", 5060,
		"aa:bb:cc:18:0:1", "22.22.22.2", 5060,
		"dp1T0", "dp2T1");

	ctrl_fw_pst = dpt_pdesc_v4_create(
		"ctrl_fw_pst", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "30.30.30.2", 1024,
		"aa:bb:cc:18:0:1", "22.22.22.2", 5060,
		"dp1T0", "dp2T1");

	ctrl_bk_pre = dpt_pdesc_v4_create(
		"ctrl_bk_pre", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "22.22.22.2", 5060,
		"aa:bb:cc:16:0:20", "30.30.30.2", 1024,
		"dp2T1", "dp1T0");

	ctrl_bk_pst = dpt_pdesc_v4_create(
		"ctrl_bk_pst", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "22.22.22.2", 5060,
		"aa:bb:cc:16:0:20", "1.1.1.2", 5060,
		"dp2T1", "dp1T0");

	/*
	 * Packet descriptors for ctrl flow
	 */
	struct dpt_tcp_flow sip_ctrl_call = {
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
	snprintf(sip_ctrl_call.text, sizeof(sip_ctrl_call), "Ctrl");

	/*
	 * Per-packet flags and data for sip ctrl flow
	 */
	struct dpt_tcp_flow_pkt sip_ctrl_pkts[] = {
		{ DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },

		/* Invite */
		{ DPT_FORW, TH_ACK,
		  0, (char *)sipd1_pre_snat[0],
		  0, (char *)sipd1_post_snat[0] },

		/* 180 Ringing */
		{ DPT_BACK, TH_ACK,
		  0, (char *)sipd1_pre_snat[1],
		  0, (char *)sipd1_post_snat[1] },

		/* 200 Resp */
		{ DPT_BACK, TH_ACK,
		  0, (char *)sipd1_pre_snat[2],
		  0, (char *)sipd1_post_snat[2] },

		/* Ack */
		{ DPT_FORW, TH_ACK,
		  0, (char *)sipd1_pre_snat[3],
		  0, (char *)sipd1_post_snat[3] },

		/* Bye */
		{ DPT_BACK, TH_ACK,
		  0, (char *)sipd1_pre_snat[4],
		  0, (char *)sipd1_post_snat[4] },

		{ DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{ DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	dpt_tcp_call(&sip_ctrl_call, sip_ctrl_pkts,
		     ARRAY_SIZE(sip_ctrl_pkts),
		     0, 0, NULL, 0);

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	free(ctrl_fw_pre);
	free(ctrl_fw_pst);
	free(ctrl_bk_pre);
	free(ctrl_bk_pst);

} DP_END_TEST; /* sip_nat13 */


/*
 * sip_nat20.  Data set #2. No NAT.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat20, dpt_alg_sipd2_setup,
		  dpt_alg_sipd2_teardown);
DP_START_TEST(sip_nat20, test)
{
	const char *desc, *pload;
	bool forw;
	uint i;

	static_assert(ARRAY_SIZE(sipd2) == ARRAY_SIZE(sipd2_dir),
		      "sipd2 array size incorrect");

	/* Verify the test data */
	sipd_check_content_len("sipd2", sipd2, ARRAY_SIZE(sipd2));

	/*
	 * Caller to/from Proxy Server
	 */
#define SIPD2_PROXY_INDEX 3
	for (i = 0; i < SIPD2_PROXY_INDEX; i++) {
		pload = sipd2[i];
		forw = (sipd2_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pload);

		if (forw) {
			dpt_udp_pl("dp1T0", "aa:bb:cc:16:0:20",
				   "100.101.102.103", 5060, /* pre src */
				   "200.201.202.205", 5060, /* pre dst */
				   "100.101.102.103", 5060, /* post src */
				   "200.201.202.205", 5060, /* post dst */
				   "aa:bb:cc:18:0:5", "dp2T1",
				   DP_TEST_FWD_FORWARDED,
				   pload, strlen(pload),
				   pload, strlen(pload), desc);
		} else {
			dpt_udp_pl("dp2T1", "aa:bb:cc:18:0:5",
				   "200.201.202.205", 5060, /* pre src */
				   "100.101.102.103", 5060, /* pre dst */
				   "200.201.202.205", 5060, /* post src */
				   "100.101.102.103", 5060, /* post dst */
				   "aa:bb:cc:16:0:20", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pload, strlen(pload),
				   pload, strlen(pload), desc);
		}
	}

	/*
	 * Caller to/from Callee
	 */
	for (i = SIPD2_PROXY_INDEX; i < ARRAY_SIZE(sipd2); i++) {
		pload = sipd2[i];
		forw = (sipd2_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pload);

		if (forw) {
			dpt_udp_pl("dp1T0", "aa:bb:cc:16:0:20",
				   "100.101.102.103", 5060, /* pre src */
				   "200.201.202.203", 5060, /* pre dst */
				   "100.101.102.103", 5060, /* post src */
				   "200.201.202.203", 5060, /* post dst */
				   "aa:bb:cc:18:0:1", "dp2T1",
				   DP_TEST_FWD_FORWARDED,
				   pload, strlen(pload),
				   pload, strlen(pload), desc);
		} else {
			dpt_udp_pl("dp2T1", "aa:bb:cc:18:0:1",
				   "200.201.202.203", 5060, /* pre src */
				   "100.101.102.103", 5060, /* pre dst */
				   "200.201.202.203", 5060, /* post src */
				   "100.101.102.103", 5060, /* post dst */
				   "aa:bb:cc:16:0:20", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pload, strlen(pload),
				   pload, strlen(pload), desc);
		}
	}

} DP_END_TEST; /* sip_nat20 */


/*
 * sip_nat21.  Data set #2. SNAT.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat21, dpt_alg_sipd2_setup,
		  dpt_alg_sipd2_teardown);
DP_START_TEST(sip_nat21, test)
{
	const char *desc, *pre_pload, *pst_pload;
	bool forw;
	uint i;

	static_assert(ARRAY_SIZE(sipd2_pre_snat) ==
		      ARRAY_SIZE(sipd2_post_snat),
		      "sipd pre and post snat array size don't match");
	static_assert(ARRAY_SIZE(sipd2_pre_snat) == ARRAY_SIZE(sipd2_dir),
		      "spid2 pre snat array size incorrect");

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.port_alloc	= "sequential",
		.from_addr	= "100.101.102.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 200.201.202.1 */
		.trans_port	= "1024-65535"
	};
	dp_test_npf_snat_add(&snat, true);

	/* Verify the test data */
	sipd_check_content_len("sipd2_pre_snat", sipd2_pre_snat,
			       ARRAY_SIZE(sipd2_pre_snat));
	sipd_check_content_len("sipd2_post_snat", sipd2_post_snat,
			       ARRAY_SIZE(sipd2_post_snat));

	/*
	 * Caller to/from Proxy Server
	 */
#define SIPD2_PROXY_INDEX 3
	for (i = 0; i < SIPD2_PROXY_INDEX; i++) {
		pre_pload = sipd2_pre_snat[i];
		pst_pload = sipd2_post_snat[i];
		forw = (sipd2_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		if (forw) {
			dpt_udp_pl("dp1T0", "aa:bb:cc:16:0:20",
				   "100.101.102.103", 5060, /* pre src */
				   "200.201.202.205", 5060, /* pre dst */
				   "200.201.202.1", 5060,   /* post src */
				   "200.201.202.205", 5060, /* post dst */
				   "aa:bb:cc:18:0:5", "dp2T1",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		} else {
			dpt_udp_pl("dp2T1", "aa:bb:cc:18:0:5",
				   "200.201.202.205", 5060, /* pre src */
				   "200.201.202.1", 5060, /* pre dst */
				   "200.201.202.205", 5060, /* post src */
				   "100.101.102.103", 5060, /* post dst */
				   "aa:bb:cc:16:0:20", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		}
	}

	/*
	 * Caller to/from Callee
	 */
	for (i = SIPD2_PROXY_INDEX; i < ARRAY_SIZE(sipd2); i++) {
		pre_pload = sipd2_pre_snat[i];
		pst_pload = sipd2_post_snat[i];
		forw = (sipd2_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		if (forw) {
			dpt_udp_pl("dp1T0", "aa:bb:cc:16:0:20",
				   "100.101.102.103", 5060, /* pre src */
				   "200.201.202.203", 5060, /* pre dst */
				   "200.201.202.1", 5061, /* post src */
				   "200.201.202.203", 5060, /* post dst */
				   "aa:bb:cc:18:0:1", "dp2T1",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		} else {
			dpt_udp_pl("dp2T1", "aa:bb:cc:18:0:1",
				   "200.201.202.203", 5060, /* pre src */
				   "200.201.202.1", 5061, /* pre dst */
				   "200.201.202.203", 5060, /* post src */
				   "100.101.102.103", 5060, /* post dst */
				   "aa:bb:cc:16:0:20", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		}

		/* RTP Data flow */
		if (i == sipd2_rtp_index) {
			/* RTP Back  (Initial) */
			dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
				"200.201.202.203", 60000,
				"200.201.202.1", 10000,
				"200.201.202.203", 60000,
				"100.101.102.103", 10000,
				"aa:bb:cc:16:0:20", "dp1T0",
				DP_TEST_FWD_FORWARDED);

			/* RTP Forw */
			dpt_udp("dp1T0", "aa:bb:cc:16:0:20",
				"100.101.102.103", 10000,
				"200.201.202.203", 60000,
				"200.201.202.1", 10000,
				"200.201.202.203", 60000,
				"aa:bb:cc:18:0:1", "dp2T1",
				DP_TEST_FWD_FORWARDED);

		}
	}

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

} DP_END_TEST; /* sip_nat21 */

/*
 * sip_nat30.  Data set #3. SNAT.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat30, dpt_alg_sipd3_setup,
		  dpt_alg_sipd3_teardown);
DP_START_TEST(sip_nat30, test)
{
	const char *desc, *pre_pload, *pst_pload;
	bool forw;
	uint i;

	static_assert(ARRAY_SIZE(sipd3_pre_snat) ==
		      ARRAY_SIZE(sipd3_post_snat),
		      "sipd3 pre and post array size don't match");
	static_assert(ARRAY_SIZE(sipd3_pre_snat) == ARRAY_SIZE(sipd3_dir),
		      "spid3 pre snat array size incorrect");

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.port_alloc	= "sequential",
		.from_addr	= "8.19.19.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade", /* 50.60.70.1 */
		.trans_port	= "1024-65535"
	};
	dp_test_npf_snat_add(&snat, true);

	/* Verify the test data */
	sipd_check_content_len("sipd3_pre_snat", sipd3_pre_snat,
			       ARRAY_SIZE(sipd3_pre_snat));
	sipd_check_content_len("sipd3_post_snat", sipd3_post_snat,
			       ARRAY_SIZE(sipd3_post_snat));

	for (i = 0; i < ARRAY_SIZE(sipd3_dir); i++) {
		pre_pload = sipd3_pre_snat[i];
		pst_pload = sipd3_post_snat[i];
		forw = (sipd3_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		if (forw) {
			dpt_udp_pl("dp1T0", "aa:bb:cc:16:0:20",
				   "8.19.19.6", 5060, /* pre src */
				   "50.60.70.80", 5060, /* pre dst */
				   "50.60.70.1", 5060,   /* post src */
				   "50.60.70.80", 5060, /* post dst */
				   "aa:bb:cc:18:0:1", "dp2T1",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		} else {
			dpt_udp_pl("dp2T1", "aa:bb:cc:18:0:1",
				   "50.60.70.80", 5060, /* pre src */
				   "50.60.70.1", 5060, /* pre dst */
				   "50.60.70.80", 5060, /* post src */
				   "8.19.19.6", 5060, /* post dst */
				   "aa:bb:cc:16:0:20", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		}

		if (i == sipd3_rtp_early_media_index) {
			/* Back. RTP Early media */
			dpt_udp("dp2T1", "aa:bb:cc:18:0:1",
				"50.60.70.80", 62002, "50.60.70.1", 50004,
				"50.60.70.80", 62002, "8.19.19.6", 50004,
				"aa:bb:cc:16:0:20", "dp1T0",
				DP_TEST_FWD_FORWARDED);
		}

		if (i == sipd3_rtp_media_index) {
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
		}
	}

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

} DP_END_TEST; /* sip_nat30 */


/*
 * sip_nat40.  Data set #4. DNAT.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat40, dpt_alg_sipd4_setup,
		  dpt_alg_sipd4_teardown);
DP_START_TEST(sip_nat40, test)
{
	const char *desc, *pre_pload, *pst_pload;
	bool forw;
	uint i;

	static_assert(ARRAY_SIZE(sipd4_pre_dnat) ==
		      ARRAY_SIZE(sipd4_post_dnat),
		      "sipd4 pre and post array size don't match");
	static_assert(ARRAY_SIZE(sipd4_pre_dnat) == ARRAY_SIZE(sipd4_dir),
		      "spid4 pre dnat array size incorrect");

	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "DNAT rule",
		.rule		= "1",
		.ifname		= "dp1T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "77.1.1.1",
		.to_port	= NULL,
		.trans_addr	= "16.33.0.200",
		.trans_port	= NULL
	};
	dp_test_npf_dnat_add(&dnat, true);

	/* Verify the test data */
	sipd_check_content_len("sipd4_pre_dnat", sipd4_pre_dnat,
			       ARRAY_SIZE(sipd4_pre_dnat));
	sipd_check_content_len("sipd4_post_dnat", sipd4_post_dnat,
			       ARRAY_SIZE(sipd4_post_dnat));

	for (i = 0; i < ARRAY_SIZE(sipd4_dir); i++) {
		pre_pload = sipd4_pre_dnat[i];
		pst_pload = sipd4_post_dnat[i];
		forw = (sipd4_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		if (forw) {
			dpt_udp_pl("dp1T1", "7c:69:f6:4a:3a:50",
				   "18.33.0.200", 60673, "77.1.1.1", 5060,
				   "18.33.0.200", 60673, "16.33.0.200", 5060,
				   "70:6e:6d:88:55:80", "dp1T0",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		} else {
			dpt_udp_pl("dp1T0", "70:6e:6d:88:55:80",
				   "16.33.0.200", 5060, "18.33.0.200", 60673,
				   "77.1.1.1", 5060, "18.33.0.200", 60673,
				   "7c:69:f6:4a:3a:50", "dp1T1",
				   DP_TEST_FWD_FORWARDED,
				   pre_pload, strlen(pre_pload),
				   pst_pload, strlen(pst_pload), desc);
		}

	}

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

} DP_END_TEST; /* sip_nat40 */


static void dpt_alg_sipd1_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "22.22.22.254/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "22.22.22.2",
				  "aa:bb:cc:18:0:1");
}

static void dpt_alg_sipd1_teardown(void)
{
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "22.22.22.2",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "22.22.22.254/24");
}

static void dpt_alg_sipd2_setup(void)
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

static void dpt_alg_sipd2_teardown(void)
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

static void dpt_alg_sipd3_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "8.19.19.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "50.60.70.1/24");

	dp_test_netlink_add_neigh("dp1T0", "8.19.19.6",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "50.60.70.80",
				  "aa:bb:cc:18:0:1");
}

static void dpt_alg_sipd3_teardown(void)
{
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "8.19.19.6",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "50.60.70.80",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "8.19.19.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "50.60.70.1/24");
}

static void dpt_alg_sipd4_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "16.33.0.220/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "18.33.0.220/24");

	dp_test_netlink_add_neigh("dp1T0", "16.33.0.200",
				  "70:6e:6d:88:55:80");
	dp_test_netlink_add_neigh("dp1T1", "18.33.0.200",
				  "7c:69:f6:4a:3a:50");
}

static void dpt_alg_sipd4_teardown(void)
{
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "16.33.0.200",
				  "70:6e:6d:88:55:80");
	dp_test_netlink_del_neigh("dp1T1", "18.33.0.200",
				  "7c:69:f6:4a:3a:50");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "16.33.0.220/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "18.33.0.220/24");

}
