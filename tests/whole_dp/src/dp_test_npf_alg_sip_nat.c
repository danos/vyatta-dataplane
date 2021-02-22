/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>

#include "dp_test.h"
#include "dp_test_netlink_state.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"

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
	uint hdr_clen, body_clen;
	bool forw, rv;
	uint i;

	assert(ARRAY_SIZE(sipd1) == ARRAY_SIZE(sipd1_dir));

	/* For each SIP msg payload */
	for (i = 0; i < ARRAY_SIZE(sipd1); i++) {
		pload = sipd1[i];
		forw = (sipd1_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pload);

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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
	uint hdr_clen, body_clen;
	bool forw, rv;
	uint i;

	assert(ARRAY_SIZE(sipd1_pre_snat) == ARRAY_SIZE(sipd1_post_snat));
	assert(ARRAY_SIZE(sipd1_pre_snat) == ARRAY_SIZE(sipd1_dir));

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

	/* For each SIP msg payload */
	for (i = 0; i < ARRAY_SIZE(sipd1_pre_snat); i++) {
		pre_pload = sipd1_pre_snat[i];
		pst_pload = sipd1_post_snat[i];
		forw = (sipd1_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pre_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] Pre  hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

		rv = sipd_check_content_length(pst_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] Post hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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
	uint hdr_clen, body_clen;
	bool forw, rv;
	uint i;

	assert(ARRAY_SIZE(sipd1_pre_dnat) == ARRAY_SIZE(sipd1_post_dnat));
	assert(ARRAY_SIZE(sipd1_pre_dnat) == ARRAY_SIZE(sipd1_dir));

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

	/* For each SIP msg payload */
	for (i = 0; i < ARRAY_SIZE(sipd1_pre_dnat); i++) {
		pre_pload = sipd1_pre_dnat[i];
		pst_pload = sipd1_post_dnat[i];
		forw = (sipd1_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pre_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] Pre hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

		rv = sipd_check_content_length(pst_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] Post hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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
 * sip_nat20.  Data set #2. No NAT.
 */
DP_DECL_TEST_CASE(sip_nat, sip_nat20, dpt_alg_sipd2_setup,
		  dpt_alg_sipd2_teardown);
DP_START_TEST(sip_nat20, test)
{
	const char *desc, *pload;
	uint hdr_clen, body_clen;
	bool forw, rv;
	uint i;

	assert(ARRAY_SIZE(sipd2) == ARRAY_SIZE(sipd2_dir));

	/*
	 * Caller to/from Proxy Server
	 */
#define SIPD2_PROXY_INDEX 3
	for (i = 0; i < SIPD2_PROXY_INDEX; i++) {
		pload = sipd2[i];
		forw = (sipd2_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pload);

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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
	uint hdr_clen, body_clen;
	bool forw, rv;
	uint i;

	assert(ARRAY_SIZE(sipd2_pre_snat) == ARRAY_SIZE(sipd2_post_snat));
	assert(ARRAY_SIZE(sipd2_pre_snat) == ARRAY_SIZE(sipd2_dir));

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

	/*
	 * Caller to/from Proxy Server
	 */
#define SIPD2_PROXY_INDEX 3
	for (i = 0; i < SIPD2_PROXY_INDEX; i++) {
		pre_pload = sipd2_pre_snat[i];
		pst_pload = sipd2_post_snat[i];
		forw = (sipd2_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pre_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

		rv = sipd_check_content_length(pst_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pre_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

		rv = sipd_check_content_length(pst_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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
	uint hdr_clen, body_clen;
	bool forw, rv;
	uint i;

	assert(ARRAY_SIZE(sipd3_pre_snat) == ARRAY_SIZE(sipd3_post_snat));
	assert(ARRAY_SIZE(sipd3_pre_snat) == ARRAY_SIZE(sipd3_dir));

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

	for (i = 0; i < ARRAY_SIZE(sipd3_dir); i++) {
		pre_pload = sipd3_pre_snat[i];
		pst_pload = sipd3_post_snat[i];
		forw = (sipd3_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pre_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

		rv = sipd_check_content_length(pst_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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
	uint hdr_clen, body_clen;
	bool forw, rv;
	uint i;

	assert(ARRAY_SIZE(sipd4_pre_dnat) == ARRAY_SIZE(sipd4_post_dnat));
	assert(ARRAY_SIZE(sipd4_pre_dnat) == ARRAY_SIZE(sipd4_dir));

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

	for (i = 0; i < ARRAY_SIZE(sipd4_dir); i++) {
		pre_pload = sipd4_pre_dnat[i];
		pst_pload = sipd4_post_dnat[i];
		forw = (sipd4_dir[i] == SIP_FORW);
		desc = sipd_descr(i, forw, pst_pload);

		/* Check content-length value matches actual content-length */
		rv = sipd_check_content_length(pre_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

		rv = sipd_check_content_length(pst_pload, &hdr_clen,
					       &body_clen);
		dp_test_fail_unless(rv, "[%s] hdr=%u, body=%u",
				    desc, hdr_clen, body_clen);

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
