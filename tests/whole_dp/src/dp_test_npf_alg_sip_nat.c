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
