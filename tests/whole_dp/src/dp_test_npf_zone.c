/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane Zone Firewall tests
 */

#include <libmnl/libmnl.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_nat_lib.h"



/* Forward declarations */
static void zone_setup(void);
static void zone_teardown(void);
static void zone_setup6(void);
static void zone_teardown6(void);

DP_DECL_TEST_SUITE(npf_zone);

/*
 * zone1 - Zone to zone, Stateless, simple ruleset
 */
DP_DECL_TEST_CASE(npf_zone, zone1, zone_setup, zone_teardown);
DP_START_TEST(zone1, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "src-addr=1.1.1.11",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * PRIVATE -> PRIVATE, Intra-zone
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "1.1.1.11", 41000, "2.2.2.11", 1000,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:2:a1", "dp1T1",
		 DP_TEST_FWD_FORWARDED);

	/*
	 * PRIVATE -> PUBLIC, src-addr matches PASS rule
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "1.1.1.11", 41001, "3.3.3.11", 1001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:3:a1", "dp1T2",
		 DP_TEST_FWD_FORWARDED);

	/*
	 * PRIVATE -> PUBLIC, src-addr does *not* PASS rule
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a2",
		 "1.1.1.12", 41002, "3.3.3.11", 1002,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:3:a1", "dp1T2",
		 DP_TEST_FWD_DROPPED);

	/*
	 * PUBLIC -> PRIVATE (reverse packet off PRIVATE -> PUBLIC)
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		 "3.3.3.11", 1001, "1.1.1.11", 41001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:1:a1", "dp1T0",
		 DP_TEST_FWD_DROPPED);


	/* Cleanup */
	dpt_zone_cfg(&cfg, false, debug);

	/* zone1 */
} DP_END_TEST;


/*
 * zone2 - Zone to zone, "PRIVATE->PUBLIC" is Stateful, simple ruleset
 */
DP_DECL_TEST_CASE(npf_zone, zone2, zone_setup, zone_teardown);
DP_START_TEST(zone2, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATEFUL,
			.npf		= "dst-addr=3.3.3.11",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * 1. PRIVATE -> PUBLIC, dst-addr matches stateful PASS rule.  Session
	 * will be created on dp1T2.
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "1.1.1.11", 41001, "3.3.3.11", 1001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:3:a1", "dp1T2",
		 DP_TEST_FWD_FORWARDED);

	/*
	 * 2. PRIVATE -> PUBLIC, dst-addr does not match PASS rule
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "1.1.1.11", 41002, "3.3.3.12", 1002,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:3:a2", "dp1T2",
		 DP_TEST_FWD_DROPPED);

	/*
	 * 3. PUBLIC -> PRIVATE.  Reverse of pkt #1.  Zone has block rule on
	 * output, but pkt matches reverse session on input so is forwarded.
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		 "3.3.3.11", 1001, "1.1.1.11", 41001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:1:a1", "dp1T0",
		 DP_TEST_FWD_FORWARDED);

	/* Cleanup */
	dpt_zone_cfg(&cfg, false, debug);

	/* zone2 */
} DP_END_TEST;


/*
 * zone3 - Zone to/from non-zone
 */
DP_DECL_TEST_CASE(npf_zone, zone3, zone_setup, zone_teardown);
DP_START_TEST(zone3, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * 1. PRIVATE -> Non-zone
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "1.1.1.11", 41001, "5.5.5.11", 1001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:5:a1", "dp2T1",
		 DP_TEST_FWD_DROPPED);

	/*
	 * 2. Non-zone -> PRIVATE (reverse packet #1)
	 */
	dpt_udp("dp2T1", "aa:bb:cc:dd:5:a1",
		 "5.5.5.11", 1001, "1.1.1.11", 41001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:1:a1", "dp1T0",
		 DP_TEST_FWD_DROPPED);

	/*
	 * Local -> PRIVATE. No local zone is cfgd, so should default to
	 * FORWARDED.
	 */
	dpt_udp(NULL, "00:00:00:00:00:00",
		"1.1.1.1", 41002, "1.1.1.11", 1002,
		NULL, 0, NULL, 0,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/* Cleanup */
	dpt_zone_cfg(&cfg, false, debug);

	/* zone3 */
} DP_END_TEST;


/*
 * zone4 - Zones and SNAT
 *
 * We add a ZBF src-addr rule for PRIVATE -> PUBLIC traffic.  This matches the
 * post-SNAT source address.
 */
DP_DECL_TEST_CASE(npf_zone, zone4, zone_setup, zone_teardown);
DP_START_TEST(zone4, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			/* SNAT address */
			.npf		= "src-addr=3.3.3.102",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/* SNAT on PRIVATE intf dp1T1 */
	dpt_snat_cfg("dp1T1", IPPROTO_UDP, NULL, "2.2.2.64/26", true);

	/* SNAT on PUBLIC intf dp1T2 */
	dpt_snat_cfg("dp1T2", IPPROTO_UDP, NULL, "3.3.3.64/26", true);

	/* SNAT on non-zone intf dp2T1 */
	dpt_snat_cfg("dp2T1", IPPROTO_UDP, NULL, "5.5.5.64/26", true);

	/*
	 * 1. PRIVATE -> PRIVATE/snat
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 41000, "2.2.2.11", 1000,
		"2.2.2.102", 41000, "2.2.2.11", 1000,
		"aa:bb:cc:dd:2:a1", "dp1T1",
		DP_TEST_FWD_FORWARDED);

	/*
	 * 2. PRIVATE/snat -> PRIVATE
	 */
	dpt_udp("dp1T1", "aa:bb:cc:dd:2:a1",
		"2.2.2.11", 1000, "2.2.2.102", 41000,
		"2.2.2.11", 1000, "1.1.1.11", 41000,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * 3. PRIVATE -> PUBLIC/snat
	 *
	 * SNAT'd src addr matches PRIV_TO_PUB pass rule.  SNAT session
	 * created on dp1T2.
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 41001, "3.3.3.11", 1001,
		"3.3.3.102", 41001, "3.3.3.11", 1001,
		"aa:bb:cc:dd:3:a1", "dp1T2",
		DP_TEST_FWD_FORWARDED);

	/*
	 * 4. PRIVATE -> PUBLIC/snat
	 *
	 * SNAT'd src addr does *not* match PRIV_TO_PUB pass rule
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a2",
		"1.1.1.12", 41001, "3.3.3.11", 1001,
		"3.3.3.103", 41001, "3.3.3.11", 1001,
		"aa:bb:cc:dd:3:a1", "dp1T2",
		DP_TEST_FWD_DROPPED);

	/*
	 * 5. PUBLIC/rev-snat -> PRIVATE.  Reverse of #3.  Pkt matches reverse
	 * SNAT session on input on dp1T2.  PUB_TO_PRIV has block rule, but
	 * NAT-pinhole overrides that and pkt is forwarded.
	 *
	 * Compare this to pkt zone 5 #4.  A NAT session in matched on input,
	 * and a zone pass is not matched on output.  That pkt is blocked
	 * whereas here the pkt is forwarded.  Only difference is that zone 5
	 * pkt #4 matches a reverse NAT session whereas this pkt matched a
	 * forwards NAT session.
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		"3.3.3.11", 1001, "3.3.3.102", 41001,
		"3.3.3.11", 1001, "1.1.1.11", 41001,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * PRIVATE -> Non-zone/snat
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "1.1.1.11", 41001, "5.5.5.11", 1001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:5:a1", "dp2T1",
		 DP_TEST_FWD_DROPPED);

	/* Cleanup */
	dpt_snat_cfg("dp1T1", IPPROTO_UDP, NULL, "2.2.2.64/26", false);
	dpt_snat_cfg("dp1T2", IPPROTO_UDP, NULL, "3.3.3.64/26", false);
	dpt_snat_cfg("dp2T1", IPPROTO_UDP, NULL, "5.5.5.64/26", false);
	dpt_zone_cfg(&cfg, false, debug);

	/* zone4 */
} DP_END_TEST;


/*
 * zone5 - Zones and DNAT
 */
DP_DECL_TEST_CASE(npf_zone, zone5, zone_setup, zone_teardown);
DP_START_TEST(zone5, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			/* Post-DNAT address */
			.npf		= "dst-addr=3.3.3.12",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * 1. PRIVATE/dnat -> PRIVATE.  dst addr is DNAT'd on input.
	 */
	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "2.2.2.11", "2.2.2.12", true);
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 41000, "2.2.2.11", 1000,
		"1.1.1.11", 41000, "2.2.2.12", 1000,
		"aa:bb:cc:dd:2:a2", "dp1T1",
		DP_TEST_FWD_FORWARDED);
	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "2.2.2.11", "2.2.2.12", false);

	/*
	 * 2. PRIVATE/dnat -> PUBLIC.  Pkt is DNAT'd at input and session
	 * created on dp1T0.  At output, DNAT'd dest addr matches zone pass
	 * rule.
	 */
	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "3.3.3.11", "3.3.3.12", true);

	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 41001, "3.3.3.11", 1001,
		"1.1.1.11", 41001, "3.3.3.12", 1001,
		"aa:bb:cc:dd:3:a2", "dp1T2",
		DP_TEST_FWD_FORWARDED);

	/*
	 * 3. PUBLIC -> PRIVATE/rev-dnat.  Zone has block rule.  Pkt matches
	 * reverse DNAT session of pkt #2 at output on dp1T0.
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a2",
		"3.3.3.12", 1001, "1.1.1.11", 41001,
		"3.3.3.11", 1001, "1.1.1.11", 41001,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "3.3.3.11", "3.3.3.12", false);

	/*
	 * 4. PRIVATE/dnat -> PUBLIC.  Pkts is DNAT'd at input.  At output,
	 * DNAT'd dest addr does *not* match zone pass rule.
	 */
	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "4.4.4.11", "4.4.4.12", true);

	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 41001, "4.4.4.11", 1001,
		"1.1.1.11", 41001, "4.4.4.12", 1001,
		"aa:bb:cc:dd:4:a2", "dp1T3",
		DP_TEST_FWD_DROPPED);

	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "4.4.4.11", "4.4.4.12", false);


	/*
	 * 5. PRIVATE/dnat -> Non-zone
	 *
	 * These next two tests are odd.  The PRIVATE/dnat -> Non-zone creates
	 * a DNAT session at input, but the packet is dropped by ZBF at
	 * output.
	 *
	 * However the subsequent packet (#6) is FORWARDED because of
	 * nat-pinhole even though it is rcvd on a non-zone interface.
	 */
	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "5.5.5.11", "5.5.5.12", true);

	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 41001, "5.5.5.11", 1001,
		"1.1.1.11", 41001, "5.5.5.12", 1001,
		"aa:bb:cc:dd:3:a2", "dp2T1",
		DP_TEST_FWD_DROPPED);

	/*
	 * 6. Non-zone -> PRIVATE/rev-dnat
	 *
	 * This is forwarded because npf_session_is_nat_pinhole() returns true
	 * in npf_hook_track in fw_out.  Pkt matches reverse session created
	 * by pkt #5.
	 */
	dpt_udp("dp2T1", "aa:bb:cc:dd:1:a2",
		"5.5.5.12", 1001, "1.1.1.11", 41001,
		"5.5.5.11", 1001, "1.1.1.11", 41001,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "5.5.5.11", "5.5.5.12", false);

	/* Cleanup */
	dpt_zone_cfg(&cfg, false, debug);

	/* zone5 */
} DP_END_TEST;


/*
 * zone6 - Zones and local
 */
DP_DECL_TEST_CASE(npf_zone, zone6, zone_setup, zone_teardown);
DP_START_TEST(zone6, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = {
			.name = "LOCAL",
			.intf = { NULL, NULL, NULL },
			.local = true,
		},
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = {
			.name		= "LOCAL_TO_PRIV",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "dst-addr=1.1.1.11",
		},
		.priv_to_local = {
			.name		= "PRIV_TO_LOCAL",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "src-addr=1.1.1.12",
		},
		.local_to_pub = { 0 },
		.pub_to_local = {
			.name		= "PUB_TO_LOCAL",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * Local -> PRIVATE.  dst addr matches pass rule.
	 */
	dpt_udp(NULL, "00:00:00:00:00:00",
		"1.1.1.1", 41001, "1.1.1.11", 1001,
		NULL, 0, NULL, 0,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * PRIVATE -> Local.  src addr matches pass rule.
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a2",
		"1.1.1.12", 1002, "1.1.1.1", 41002,
		NULL, 0, NULL, 0,
		"00:00:00:00:00:00", NULL,
		DP_TEST_FWD_LOCAL);

	/*
	 * Local -> PUBLIC.  No ruleset.
	 */
	dpt_udp(NULL, "00:00:00:00:00:00",
		"1.1.1.1", 41003, "3.3.3.11", 1003,
		NULL, 0, NULL, 0,
		"aa:bb:cc:dd:3:a1", "dp1T2",
		DP_TEST_FWD_FORWARDED);

	/*
	 * PUBLIC -> Local. Block rule.
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		"3.3.3.11", 1003, "1.1.1.1", 41003,
		NULL, 0, NULL, 0,
		"00:00:00:00:00:00", NULL,
		DP_TEST_FWD_DROPPED);

	/* Cleanup */
	dpt_zone_cfg(&cfg, false, debug);

	/* zone6 */
} DP_END_TEST;


/*
 * zone7 - Zones and local, SNAT
 */
DP_DECL_TEST_CASE(npf_zone, zone7, zone_setup, zone_teardown);
DP_START_TEST(zone7, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = {
			.name = "LOCAL",
			.intf = { NULL, NULL, NULL },
			.local = true,
		},
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = {
			.name		= "LOCAL_TO_PRIV",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "src-addr=1.1.1.92",
		},
		.priv_to_local = {
			.name		= "PRIV_TO_LOCAL",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_pub = {
			.name		= "LOCAL_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.pub_to_local = {
			.name		= "PUB_TO_LOCAL",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
	};

	dpt_zone_cfg(&cfg, true, debug);

	/* Add SNAT to a PUBLIC interface. */
	dpt_snat_cfg("dp1T2", IPPROTO_UDP, NULL, "3.3.3.64/26", true);

	/*
	 * 1. Local -> PUBLIC
	 */
	dpt_udp(NULL, "00:00:00:00:00:00",
		"1.1.1.1", 41003, "3.3.3.11", 1003,
		"3.3.3.92", 41003, "3.3.3.11", 1003,
		"aa:bb:cc:dd:3:a1", "dp1T2",
		DP_TEST_FWD_FORWARDED);

	/*
	 * 2. PUBLIC -> Local.  PUB_TO_LOCAL has a BLOCK rule but NAT pinhole
	 * from pkt #1 allows return packet to bypass ZBF.
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		"3.3.3.11", 1003, "3.3.3.92", 41003,
		"3.3.3.11", 1003, "1.1.1.1", 41003,
		"00:00:00:00:00:00", NULL,
		DP_TEST_FWD_LOCAL);

	dpt_snat_cfg("dp1T2", IPPROTO_UDP, NULL, "3.3.3.64/26", false);

	/* Add SNAT to a PRIVATE interface. */
	dpt_snat_cfg("dp1T0", IPPROTO_UDP, NULL, "1.1.1.64/26", true);

	/*
	 * 3. Local -> PRIVATE. Pkts is SNAT'd.  SNAT src addr matches zone
	 * rule.
	 */
	dpt_udp(NULL, "00:00:00:00:00:00",
		"1.1.1.1", 41004, "1.1.1.11", 1004,
		"1.1.1.92", 41004, "1.1.1.11", 1004,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * 4. PRIVATE -> Local.  Reverse of pkt #3.  PRIV_TO_LOCAL has a block
	 * rule, but pkt matches reverse SNAT session.
	 */
	dpt_udp("dp1T0", "00:00:00:00:00:00",
		"1.1.1.11", 1004, "1.1.1.92", 41004,
		"1.1.1.11", 1004, "1.1.1.1", 41004,
		"aa:bb:cc:dd:1:a1", NULL,
		DP_TEST_FWD_FORWARDED);


	dpt_snat_cfg("dp1T0", IPPROTO_UDP, NULL, "1.1.1.64/26", false);

	/* Cleanup */
	dpt_zone_cfg(&cfg, false, debug);

	/* zone7 */
} DP_END_TEST;


/*
 * zone8 - Zones and local, DNAT
 */
DP_DECL_TEST_CASE(npf_zone, zone8, zone_setup, zone_teardown);
DP_START_TEST(zone8, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = {
			.name = "LOCAL",
			.intf = { NULL, NULL, NULL },
			.local = true,
		},
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = {
			.name		= "LOCAL_TO_PRIV",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "dst-addr=1.1.1.12",
		},
		.priv_to_local = {
			.name		= "PRIV_TO_LOCAL",
			.pass		= PASS,
			.stateful	= STATELESS,
			/*
			 * dst-addr rule matches *pre* DNAT address.  The DNAT
			 * is reversed in the slow path in order to run the
			 * ZBF.
			 */
			.npf		= "dst-addr=1.1.1.21",
		},
		.local_to_pub = {
			.name		= "LOCAL_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.pub_to_local = {
			.name		= "PUB_TO_LOCAL",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
	};

	dpt_zone_cfg(&cfg, true, debug);

	/* Add DNAT to a PRIVATE interface */
	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "1.1.1.21", "1.1.1.1", true);

	/* Add DNAT to a PUBLIC interface */
	dpt_dnat_cfg("dp1T2", IPPROTO_UDP, "3.3.3.21", "3.3.3.3", true);

	/*
	 * 1. PRIVATE to Local.
	 *
	 * Pkt is DNATd on input. At this point dst addr does *not* match
	 * PRIV_TO_LOCAL rule.  Pkt must have the DNAT reversed in the
	 * slowpatch before a ruleset lookup is done.
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 1003, "1.1.1.21", 41003,
		"1.1.1.11", 1003, "1.1.1.1", 41003,
		"00:00:00:00:00:00", NULL,
		DP_TEST_FWD_LOCAL);

	/*
	 * 2. Local to PRIVATE.  Reverse of #1.  dst addr does *not* match
	 * zone rule, but pkt matches reverse session of pkt #1.
	 */
	dpt_udp(NULL, "00:00:00:00:00:00",
		"1.1.1.1", 41003, "1.1.1.11", 1003,
		"1.1.1.21", 41003, "1.1.1.11", 1003,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);

	/*
	 * PUBLIC to Local.  Block rule.
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		"3.3.3.11", 1004, "3.3.3.21", 41004,
		"3.3.3.11", 1004, "3.3.3.3", 41004,
		"00:00:00:00:00:00", NULL,
		DP_TEST_FWD_DROPPED);

	/* Cleanup */
	dpt_dnat_cfg("dp1T0", IPPROTO_UDP, "1.1.1.21", "1.1.1.1", false);
	dpt_dnat_cfg("dp1T2", IPPROTO_UDP, "3.3.3.21", "3.3.3.3", false);
	dpt_zone_cfg(&cfg, false, debug);

	/* zone8 */
} DP_END_TEST;

/*
 * zone9 - Stateful zones and SNAT
 */
DP_DECL_TEST_CASE(npf_zone, zone9, zone_setup, zone_teardown);
DP_START_TEST(zone9, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATEFUL,
			.npf		= "src-addr=3.3.3.100",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/* SNAT on PUBLIC intf dp1T2 */
	dpt_snat_cfg("dp1T2", IPPROTO_UDP, NULL, "3.3.3.100", true);

	/*
	 * 1. PRIVATE -> PUBLIC.  SNAT and stateful zone rule on same
	 * interface.
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 41001, "3.3.3.11", 1001,
		"3.3.3.100", 41001, "3.3.3.11", 1001,
		"aa:bb:cc:dd:3:a1", "dp1T2",
		DP_TEST_FWD_FORWARDED);

	/*
	 * 2. PUBLIC -> PRIVATE
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		"3.3.3.11", 1001, "3.3.3.100", 41001,
		"3.3.3.11", 1001, "1.1.1.11", 41001,
		"aa:bb:cc:dd:1:a1", "dp1T0",
		DP_TEST_FWD_FORWARDED);


	dpt_snat_cfg("dp1T2", IPPROTO_UDP, NULL, "3.3.3.100", false);

	dpt_zone_cfg(&cfg, false, debug);

	/* zone9 */
} DP_END_TEST;

/*
 * zone10 - Stateful zones and DNAT
 */
DP_DECL_TEST_CASE(npf_zone, zone10, zone_setup, zone_teardown);
DP_START_TEST(zone10, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	dpt_zone_cfg(&cfg, false, debug);

	/* zone10 */
} DP_END_TEST;

/*
 * zone11 - Zone block rule after SNAT
 */
DP_DECL_TEST_CASE(npf_zone, zone11, zone_setup, zone_teardown);
DP_START_TEST(zone11, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/* SNAT on PUBLIC intf dp1T2 */
	dpt_snat_cfg("dp1T2", IPPROTO_UDP, NULL, "3.3.3.100", true);

	/*
	 * 1. PRIVATE -> PUBLIC.  src addr is SNATd and session created.  But
	 * zone has block rule so SNAT session is *not* activated.
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		"1.1.1.11", 41001, "3.3.3.11", 1001,
		"3.3.3.100", 41001, "3.3.3.11", 1001,
		"aa:bb:cc:dd:3:a1", "dp1T2",
		DP_TEST_FWD_DROPPED);

	/*
	 * If there is a session then that means the SNAT rule was activated
	 * even though zones fw dropped the packet.  This is BAD, as it means
	 * a NAT pinhole has been wrongly opened for return traffic.
	 */
	dp_test_npf_session_count_verify(0);

	dpt_snat_cfg("dp1T2", IPPROTO_UDP, NULL, "3.3.3.100", false);

	dpt_zone_cfg(&cfg, false, debug);

	/* zone11 */
} DP_END_TEST;


/*
 * zone12 - Stateful rule in one direction, block rule in reverse direction.
 */
DP_DECL_TEST_CASE(npf_zone, zone12, zone_setup, zone_teardown);
DP_START_TEST(zone12, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATEFUL,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	/*
	 * 1. PUBLIC -> PRIVATE.  Block rule.
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		 "3.3.3.11", 1001, "1.1.1.11", 41001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:1:a1", "dp1T0",
		 DP_TEST_FWD_DROPPED);

	/*
	 * 2. PRIVATE -> PUBLIC.  Reverse of #1.  Will match stateful rule and
	 * create a session.
	 */
	dpt_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		 "1.1.1.11", 41001, "3.3.3.11", 1001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:3:a1", "dp1T2",
		 DP_TEST_FWD_FORWARDED);

	/*
	 * 3. PUBLIC -> PRIVATE.  Repeat of #1.  Reverse of #2.  Will match
	 * zones session on input, which will override block rule.
	 */
	dpt_udp("dp1T2", "aa:bb:cc:dd:3:a1",
		 "3.3.3.11", 1001, "1.1.1.11", 41001,
		 NULL, 0, NULL, 0,
		 "aa:bb:cc:dd:1:a1", "dp1T0",
		 DP_TEST_FWD_FORWARDED);

	dpt_zone_cfg(&cfg, false, debug);

	/* zone12 */
} DP_END_TEST;


/*
 * zone19 - Zone to zone, VIF interface
 */
DP_DECL_TEST_CASE(npf_zone, zone19, zone_setup, zone_teardown);
DP_START_TEST(zone19, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1.100", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	/*
	 * Create an incomplete vif interface *before* Zone cfg
	 */
	dp_test_intf_vif_create_incmpl("dp1T1.100", "dp1T1", 100);

	dpt_zone_cfg(&cfg, true, debug);

	/* Complete the vif interface */
	dp_test_intf_vif_create_incmpl_fin("dp1T1.100", "dp1T1", 100);

	dp_test_nl_add_ip_addr_and_connected("dp1T1.100", "2.2.3.2/24");
	dp_test_netlink_add_neigh("dp1T1.100", "2.2.3.11", "aa:bb:cc:3:2:a1");

	/*
	 * PRIVATE -> PRIVATE
	 */
	dpt_vlan_udp("dp1T0", "aa:bb:cc:dd:1:a1",
		     "1.1.1.11", 41000, "2.2.3.11", 1000,
		     NULL, 0, NULL, 0,
		     "aa:bb:cc:3:2:a1", "dp1T1",
		     DP_TEST_FWD_FORWARDED, 0, 100);


	/* Cleanup */
	dpt_zone_cfg(&cfg, false, debug);

	dp_test_netlink_del_neigh("dp1T1.100", "2.2.3.11",
				  "aa:bb:cc:3:2:a1");
	dp_test_nl_del_ip_addr_and_connected("dp1T1.100", "2.2.3.2/24");
	dp_test_intf_vif_del("dp1T1.100", 100);

	/* zone9 */
} DP_END_TEST;


/*
 * zone20 - Zones and IPv6
 */
DP_DECL_TEST_CASE(npf_zone, zone20, zone_setup6, zone_teardown6);
DP_START_TEST(zone20, test)
{
	bool debug = false;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = {
			.name = "PUBLIC",
			.intf = { "dp1T2", "dp1T3", NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "PUB_TO_PRIV",
			.pass		= BLOCK,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "PRIV_TO_PUB",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, debug);

	struct dp_test_pkt_desc_t udp_pkt = {
		.text       = "UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1::11",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2::11",
		.l2_dst     = "aa:bb:cc:dd:2:a1",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD,
				.dport = 0xBEEF,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};
	struct rte_mbuf *pak;
	struct dp_test_expected *exp;

	/*
	 * PRIVATE -> PRIVATE
	 */
	pak  = dp_test_v6_pkt_from_desc(&udp_pkt);
	exp = dp_test_exp_from_desc(pak, &udp_pkt);
	dp_test_pak_receive(pak, udp_pkt.rx_intf, exp);

	/*
	 * PRIVATE -> PUBLIC
	 */
	udp_pkt.l3_dst = "2001:101:3::11";
	udp_pkt.l2_dst = "aa:bb:cc:dd:3:a1";
	udp_pkt.tx_intf = "dp1T2";
	pak  = dp_test_v6_pkt_from_desc(&udp_pkt);
	exp = dp_test_exp_from_desc(pak, &udp_pkt);
	dp_test_pak_receive(pak, udp_pkt.rx_intf, exp);

	/*
	 * PUBLIC -> PRIVATE
	 */
	udp_pkt.l3_src = "2001:101:3::11";
	udp_pkt.l2_src = "aa:bb:cc:dd:3:a1";
	udp_pkt.rx_intf = "dp1T2";

	udp_pkt.l3_dst = "2001:101:1::11";
	udp_pkt.l2_dst = "aa:bb:cc:dd:1:a1";
	udp_pkt.tx_intf = "dp1T0";

	pak  = dp_test_v6_pkt_from_desc(&udp_pkt);
	exp = dp_test_exp_from_desc(pak, &udp_pkt);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(pak, udp_pkt.rx_intf, exp);


	/* Cleanup */
	dpt_zone_cfg(&cfg, false, debug);

	/* zone20 */
} DP_END_TEST;


/*
 * Interface and address setup for above tests
 */
static void zone_setup(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T3", "4.4.4.4/24");

	/* Non-zone interfaces */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "5.5.5.5/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "6.6.6.6/24");

	/* PRIVATE interfaces */
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12", "aa:bb:cc:dd:1:a2");

	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11", "aa:bb:cc:dd:2:a1");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.12", "aa:bb:cc:dd:2:a2");

	/* PUBLIC interfaces */
	dp_test_netlink_add_neigh("dp1T2", "3.3.3.11", "aa:bb:cc:dd:3:a1");
	dp_test_netlink_add_neigh("dp1T2", "3.3.3.12", "aa:bb:cc:dd:3:a2");

	dp_test_netlink_add_neigh("dp1T3", "4.4.4.11", "aa:bb:cc:dd:4:a1");
	dp_test_netlink_add_neigh("dp1T3", "4.4.4.12", "aa:bb:cc:dd:4:a2");

	/* Non-zone interfaces */
	dp_test_netlink_add_neigh("dp2T1", "5.5.5.11", "aa:bb:cc:dd:5:a1");
	dp_test_netlink_add_neigh("dp2T1", "5.5.5.12", "aa:bb:cc:dd:5:a2");

	dp_test_netlink_add_neigh("dp2T2", "6.6.6.11", "aa:bb:cc:dd:6:a1");
}

static void zone_teardown(void)
{
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12", "aa:bb:cc:dd:1:a2");

	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11", "aa:bb:cc:dd:2:a1");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.12", "aa:bb:cc:dd:2:a2");

	dp_test_netlink_del_neigh("dp1T2", "3.3.3.11", "aa:bb:cc:dd:3:a1");
	dp_test_netlink_del_neigh("dp1T2", "3.3.3.12", "aa:bb:cc:dd:3:a2");

	dp_test_netlink_del_neigh("dp1T3", "4.4.4.11", "aa:bb:cc:dd:4:a1");
	dp_test_netlink_del_neigh("dp1T3", "4.4.4.12", "aa:bb:cc:dd:4:a2");

	dp_test_netlink_del_neigh("dp2T1", "5.5.5.11", "aa:bb:cc:dd:5:a1");
	dp_test_netlink_del_neigh("dp2T1", "5.5.5.12", "aa:bb:cc:dd:5:a2");

	dp_test_netlink_del_neigh("dp2T2", "6.6.6.11", "aa:bb:cc:dd:6:a1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "4.4.4.4/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "5.5.5.5/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "6.6.6.6/24");

	dp_test_npf_cleanup();
}

static void zone_setup6(void)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::1/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:101:2::1/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2001:101:3::1/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T3", "2001:101:4::1/96");

	/* Non-zone interfaces */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2001:101:5::1/96");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2001:101:6::1/96");

	/* PRIVATE interfaces */
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::12",
				  "aa:bb:cc:dd:1:a2");

	dp_test_netlink_add_neigh("dp1T1", "2001:101:2::11",
				  "aa:bb:cc:dd:2:a1");
	dp_test_netlink_add_neigh("dp1T1", "2001:101:2::12",
				  "aa:bb:cc:dd:2:a2");

	/* PUBLIC interfaces */
	dp_test_netlink_add_neigh("dp1T2", "2001:101:3::11",
				  "aa:bb:cc:dd:3:a1");
	dp_test_netlink_add_neigh("dp1T2", "2001:101:3::12",
				  "aa:bb:cc:dd:3:a2");

	dp_test_netlink_add_neigh("dp1T3", "2001:101:4::11",
				  "aa:bb:cc:dd:4:a1");
	dp_test_netlink_add_neigh("dp1T3", "2001:101:4::12",
				  "aa:bb:cc:dd:4:a2");

	/* Non-zone interfaces */
	dp_test_netlink_add_neigh("dp2T1", "2001:101:5::11",
				  "aa:bb:cc:dd:5:a1");
	dp_test_netlink_add_neigh("dp2T1", "2001:101:5::12",
				  "aa:bb:cc:dd:5:a2");

	dp_test_netlink_add_neigh("dp2T2", "2001:101:6::11",
				  "aa:bb:cc:dd:6:a1");
}

static void zone_teardown6(void)
{
	/* PRIVATE interfaces */
	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::11",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::12",
				  "aa:bb:cc:dd:1:a2");

	dp_test_netlink_del_neigh("dp1T1", "2001:101:2::11",
				  "aa:bb:cc:dd:2:a1");
	dp_test_netlink_del_neigh("dp1T1", "2001:101:2::12",
				  "aa:bb:cc:dd:2:a2");

	/* PUBLIC interfaces */
	dp_test_netlink_del_neigh("dp1T2", "2001:101:3::11",
				  "aa:bb:cc:dd:3:a1");
	dp_test_netlink_del_neigh("dp1T2", "2001:101:3::12",
				  "aa:bb:cc:dd:3:a2");

	dp_test_netlink_del_neigh("dp1T3", "2001:101:4::11",
				  "aa:bb:cc:dd:4:a1");
	dp_test_netlink_del_neigh("dp1T3", "2001:101:4::12",
				  "aa:bb:cc:dd:4:a2");

	/* Non-zone interfaces */
	dp_test_netlink_del_neigh("dp2T1", "2001:101:5::11",
				  "aa:bb:cc:dd:5:a1");
	dp_test_netlink_del_neigh("dp2T1", "2001:101:5::12",
				  "aa:bb:cc:dd:5:a2");

	dp_test_netlink_del_neigh("dp2T2", "2001:101:6::11",
				  "aa:bb:cc:dd:6:a1");

	/* Setup interfaces and neighbours */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::1/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:101:2::1/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2001:101:3::1/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "2001:101:4::1/96");

	/* Non-zone interfaces */
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2001:101:5::1/96");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2001:101:6::1/96");

	dp_test_npf_cleanup();
}


/*
 * TEST: decrypt_a_packet
 *
 * This test checks that an encrypted packet received on a
 * VTI interface is correctly decrypted and and forwarded.
 */
#include "dp_test_crypto_utils.h"

#define SPI_OUTBOUND 0xd43d87c7
#define SPI_INBOUND 0x10203040
#define VTI_TUN_REQID 1234

#define NETWORK_WEST  "10.10.1.0"
#define CLIENT_LOCAL  "10.10.1.1"
#define NETWORK_LOCAL "10.10.1.0"
#define PORT_WEST     "10.10.1.2"
#define CLIENT_LOCAL_MAC_ADDR "aa:bb:cc:dd:1:1"

#define NETWORK_EAST   "10.10.2.0"
#define PEER           "10.10.2.3"
#define PEER_MAC_ADDR  "aa:bb:cc:dd:2:3"
#define PORT_EAST      "10.10.2.2"
#define NETWORK_REMOTE "10.10.3.0"

#define OUTPUT_MARK 100
#define INPUT_MARK  100

#define CLIENT_REMOTE  "10.10.3.4"

#define TEST_VRF_ID 55

/*
 * Crypto policy definitions used by the tests in this module
 */
static struct dp_test_crypto_policy output_policy = {
	.d_prefix = "0.0.0.0/0",
	.s_prefix = "0.0.0.0/0",
	.proto = 0,
	.dst = PEER,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = VTI_TUN_REQID,
	.priority = 0,
	.mark = OUTPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy input_policy = {
	.d_prefix = "0.0.0.0/0",
	.s_prefix = "0.0.0.0/0",
	.proto = 0,
	.dst = PORT_EAST,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = VTI_TUN_REQID,
	.priority = 0,
	.mark = INPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

/*
 * Crypto SA definitions used by the tests in this module
 */
static struct dp_test_crypto_sa output_sa = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_OUTBOUND,
	.d_addr = PEER,
	.s_addr = PORT_EAST,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = VTI_TUN_REQID,
	.mark = OUTPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa input_sa = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_INBOUND,
	.d_addr = PORT_EAST,
	.s_addr = PEER,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = VTI_TUN_REQID,
	.mark = INPUT_MARK,
	.vrfid = VRF_DEFAULT_ID
};

static void vti_setup_policies_and_sas(vrfid_t vrfid)
{
	input_policy.vrfid = vrfid;
	output_policy.vrfid = vrfid;
	dp_test_crypto_create_policy(&input_policy);
	dp_test_crypto_create_policy(&output_policy);

	input_sa.vrfid = vrfid;
	output_sa.vrfid = vrfid;
	dp_test_crypto_create_sa(&input_sa);
	dp_test_crypto_create_sa(&output_sa);
}

static void vti_teardown_sas_and_policy(void)
{
	dp_test_crypto_delete_policy(&input_policy);
	dp_test_crypto_delete_policy(&output_policy);

	dp_test_crypto_delete_sa(&input_sa);
	dp_test_crypto_delete_sa(&output_sa);
}

static void vti_setup_tunnel(vrfid_t vrf_id, uint16_t mark_out)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	if (vrf_id != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrf_id, 1);

	/* Input interface and connected route is in the requested VRF */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1",
						 "10.10.1.2/24", vrf_id);
	dp_test_netlink_add_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR);

	/* Output interface and connected route are in default VRF */
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "10.10.2.2/24");
	dp_test_netlink_add_neigh("dp2T2", "10.10.2.3", PEER_MAC_ADDR);

	dp_test_intf_vti_create("vti0", "10.10.2.2", "10.10.2.3",
				mark_out, vrf_id);
	dp_test_netlink_add_ip_address_vrf("vti0", "5.5.5.5/24", vrf_id);
	snprintf(route_name, sizeof(route_name), "vrf:%d %s nh %s int:vti0",
		 vrf_id, "10.10.3.0/24", PEER);
	dp_test_netlink_add_route(route_name);

	dp_test_crypto_check_sa_count(vrf_id, 0);
}

static void vti_teardown_tunnel(vrfid_t vrf_id)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	snprintf(route_name, sizeof(route_name), "vrf:%d %s nh %s int:vti0",
		 vrf_id, "10.10.3.0/24", PEER);
	dp_test_netlink_del_route(route_name);

	dp_test_netlink_del_ip_address_vrf("vti0", "5.5.5.5/24", vrf_id);
	dp_test_intf_vti_delete("vti0", PORT_EAST, PEER, 10, vrf_id);
	dp_test_netlink_del_neigh("dp2T2", PEER, PEER_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "10.10.2.2/24");
	dp_test_netlink_del_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "10.10.1.2/24",
						 vrf_id);

	if (vrf_id != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrf_id, 0);
}

static void vti_count(struct ifnet *ifp, void *arg)
{
	int *count = (int *)arg;

	if (ifp->if_type == IFT_TUNNEL_VTI)
		(*count)++;
}

static int vti_count_of_vtis(void)
{
	int count = 0;

	dp_ifnet_walk(vti_count, &count);
	return count;
}

/*
 * build_encrypted_input_packet()
 *
 * This helper function creates an input ESP packet containing
 * an encrypted ICMP ping packet from 10.10.3.4 to 10.10.1.1.
 */
static struct rte_mbuf *build_encrypted_input_packet(void)
{
	int payload_len;
	const char encrypted_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6, 0xb1, 0x0c,
		0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3, 0xe4, 0xac, 0x69, 0xfb,
		0x6e, 0xf2, 0x98, 0x2c, 0x4e, 0x19, 0xd6, 0x8f, 0xd1, 0x72,
		0xfb, 0x67, 0x3c, 0x14, 0xc8, 0x00, 0x34, 0x4a, 0x08, 0x3d,
		0xe6, 0x3d, 0xeb, 0x3b, 0xeb, 0x90, 0xd8, 0xe1, 0x28, 0xa5,
		0xd2, 0x1b, 0xa1, 0xb1, 0xcf, 0xf4, 0xf4, 0x3e, 0x1d, 0x6b,
		0xa2, 0x8d, 0xb2, 0x2c, 0x5e, 0x60, 0x7f, 0x81, 0x3b, 0x79,
		0xb5, 0x10, 0xe2, 0x78, 0x7c, 0xd7, 0x19, 0xcf, 0x14, 0x80,
		0xca, 0x31, 0xa8, 0x4d, 0xf8, 0xde, 0x31, 0x3d, 0x61, 0x4d,
		0x5d, 0xed, 0x02, 0x1a, 0x91, 0x5d, 0x7c, 0x36, 0x9d, 0xce,
		0x2f, 0x1c, 0x57, 0x75, 0x8b, 0xe2, 0xa1, 0xdc, 0xf9, 0x4a,
		0x33, 0x97, 0x2a, 0x71, 0x7b, 0x16, 0x88, 0x59, 0x3d, 0x09,
		0xc8, 0x89, 0xa8, 0x31
	};

	payload_len = sizeof(encrypted_payload);

	return dp_test_create_esp_ipv4_pak(PEER, PORT_EAST, 1,
					   &payload_len,
					   encrypted_payload,
					   SPI_INBOUND,
					   1 /* seq no */,
					   0 /* ip ID */,
					   63 /* ttl */,
					   NULL /* udp/esp */,
					   NULL /* transport_hdr*/);
}

/*
 * build_expected_icmp_packet()
 *
 * This helper function builds an output ICMP packet that
 * corresponds to the encrypted payload in the ESP packet
 * built by build_encrypted_input_packet().
 */
static struct rte_mbuf *build_expected_icmp_packet(int *payload_len)
{
	struct iphdr *ip;
	struct rte_mbuf *packet;
	const uint8_t payload[] = {
		0x2c, 0x57, 0xba, 0x55, 0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04
	};

	*payload_len = sizeof(payload);

	packet = dp_test_create_icmp_ipv4_pak(CLIENT_REMOTE, CLIENT_LOCAL,
					      ICMP_ECHO /* echo request */,
					      0 /* no code */,
					      DPT_ICMP_ECHO_DATA(0xac9, 1),
					      1 /* one mbuf */,
					      payload_len,
					      payload,
					      &ip, NULL);

	/*
	 * The resulting ICMP packet isn't exactly as
	 * we want, so tickle a few bits into shape
	 */
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_IP_ID, 0xea53);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 2);

	return packet;
}


/*
 *     Zone "EAST"            Zone "WEST"
 *
 *          rx ->             tx ->
 *                +---------+
 *          dp2T2 |         | dp1T1
 *      ----------+         +----------
 *          vti0  |         |
 *                +---------+
 *
 */
DP_DECL_TEST_CASE(npf_zone, zone50, NULL, NULL);
DP_START_TEST(zone50, test)
{
	struct rte_mbuf *output_packet;
	struct rte_mbuf *input_packet;
	struct dp_test_expected *exp;
	int decrypted_payload_len;

	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "EAST",
			.intf = { "vti0", NULL, NULL },
			.local = false,
		},
		.public = {
			.name = "WEST",
			.intf = { "dp1T1", NULL, NULL },
			.local = false,
		},
		.local = { 0 },
		.pub_to_priv = {
			.name		= "EAST_TO_WEST",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.priv_to_pub = {
			.name		= "WEST_TO_EAST",
			.pass		= PASS,
			.stateful	= STATELESS,
			.npf		= "",
		},
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	vti_setup_tunnel(VRF_DEFAULT_ID, OUTPUT_MARK);
	vti_setup_policies_and_sas(VRF_DEFAULT_ID);
	dp_test_fail_unless((vti_count_of_vtis() == 1),
			    "Expected VTI to be created");

	/*
	 * Create the input encrypted packet.
	 */
	input_packet = build_encrypted_input_packet();
	(void)dp_test_pktmbuf_eth_init(input_packet,
				       dp_test_intf_name2mac_str("dp2T2"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Ceate the expected decrypted ping packet
	 */
	output_packet = build_expected_icmp_packet(&decrypted_payload_len);
	(void)dp_test_pktmbuf_eth_init(output_packet,
				       CLIENT_LOCAL_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV4);

	/* Add zones config */
	dpt_zone_cfg(&cfg, true, false);

	/*
	 * Create an expectation for the decypted ICMP ping packet on dp1T1.
	 */
	exp = dp_test_exp_create(output_packet);
	rte_pktmbuf_free(output_packet);

	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(input_packet, "dp2T2", exp);
	dp_test_crypto_check_sad_packets(VRF_DEFAULT_ID, 1, 84);

	/* Remove zones config */
	dpt_zone_cfg(&cfg, false, false);

	vti_teardown_tunnel(VRF_DEFAULT_ID);
	vti_teardown_sas_and_policy();
	dp_test_fail_unless((vti_count_of_vtis() == 0),
			    "Expected VTI to be deleted");

} DP_END_TEST;

