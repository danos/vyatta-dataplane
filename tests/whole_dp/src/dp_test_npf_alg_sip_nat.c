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