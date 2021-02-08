/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property. All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf golden unit-tests
 *
 * There are a set of short, simple, test-cases what exercise one aspect
 * related to npf.  They may be used as either a quick test run, or to help
 * debug something, or as templates to copy for further tests.
 */

#include <libmnl/libmnl.h>
#include <netinet/ip_icmp.h>

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


/*
 * There are 6 main tests, each with multiple sub-tests (49 total).  Each test
 * runs 2 pkts - 1 fwd and 1 reverse.  The descriptions below show what
 * happens in the forwards direction only.
 *
 * 1. IPv4, rx on Dp1T0 and tx on dp1T1
 * 2. IPv6, rx on Dp1T0 and tx on dp1T1
 * 3. IPv4 Local to network
 * 4. IPv4 Network to local
 * 5. IPv6 Local to network
 * 6. IPv6 Network to local
 *
 * To run a test case:
 *   make -j4 dataplane_test_run CK_RUN_CASE=npf_golden1a
 *
 *              /------------- In -----------\  /------ Out ---------\
 * Test Case	FW/Zone	sfull	DNAT	NAT64	SNAT	FW/Zone	sfull
 * npf_golden1	0	0	0	-	0	0	0
 * npf_golden1a	1	0	0	-	0	0	0
 * npf_golden1b	1	1	0	-	0	0	0
 * npf_golden1c	0	0	1	-	0	0	0
 * npf_golden1d	1	0	1	-	0	0	0
 * npf_golden1e	1	1	1	-	0	0	0
 * npf_golden1f	0	0	0	-	1	0	0
 * npf_golden1g	0	0	0	-	1	1	0
 * npf_golden1h	0	0	0	-	1	1	1
 * npf_golden1i	0	0	1	-	1	0	0
 * npf_golden1j	0	1	1	-	1	1	1
 * npf_golden1k	1	1	0	-	0	1	1
 *
 * npf_golden1l	0	0	0	-	0	Zn	0
 * npf_golden1m	Zn	0	0	-	0	0	0
 * npf_golden1n	Zn	0	0	-	0	Zn	0
 * npf_golden1o	Zn	0	0	-	0	Zn	0 unm pkt
 * npf_golden1p	Zn	0	1	-	0	Zn	0
 * npf_golden1q	Zn	0	0	-	1	Zn	0
 * npf_golden1r	Zn	0	0	-	0	Zn	1
 * npf_golden1s	Zn	0	1	-	0	Zn	1
 * npf_golden1t	Zn	0	0	-	1	Zn	1
 * npf_golden1u	Zn	0	1	-	1	Zn	1
 *
 * npf_golden2	0	0	-	0	-	0	0
 * npf_golden2a	1	0	-	0	-	0	0
 * npf_golden2b	1	1	-	0	-	0	0
 * npf_golden2c	0	0	-	0	-	1	1
 * npf_golden2d	0	0	-	1	0	0	0
 * npf_golden2e	1	0	-	1	0	0	0
 * npf_golden2f	1	1	-	1	0	0	0
 * npf_golden2g	0	0	-	1	0	1	1
 * npf_golden2h	0	0	-	1	1	1	1
 * npf_golden2i	1	1	-	1	1	1	1
 *
 * npf_golden2l	0	0	-	0	-	Zn	0
 * npf_golden2m	Zn	0	-	0	-	0	0
 * npf_golden2n	Zn	0	-	0	-	Zn	0
 * npf_golden2o	Zn	0	-	1	0	Zn	0
 * npf_golden2p	Zn	0	-	1	1	Zn	0
 * npf_golden2q	Zn	0	-	0	-	Zn	1
 * npf_golden2s	Zn	0	-	1	1	Zn	1
 *
 * npf_golden3	-	-	-	-	0	0	0
 * npf_golden3a	-	-	-	-	0	1	0
 * npf_golden3b	-	-	-	-	0	1	1
 * npf_golden3c	-	-	-	-	1	0	0
 * npf_golden3d	-	-	-	-	1	1	0
 * npf_golden3e	-	-	-	-	1	1	1
 *
 * npf_golden3j	-	-	-	-	0	1	0 blk pkt
 * npf_golden3k	-	-	-	-	0	1	1 blk pkt
 * npf_golden3l	-	-	-	-	0	1	0 unm pkt
 * npf_golden3m	-	-	-	-	0	1	1 unm pkt

 * npf_golden3f	-	-	-	-	0	Zn	0
 * npf_golden3g	-	-	-	-	0	Zn	1
 * npf_golden3h	-	-	-	-	1	Zn	0
 * npf_golden3i	-	-	-	-	1	Zn	1
 *
 * npf_golden3n	local	-	-	-	0	Zn	0 !zp pub-to-loc
 * npf_golden3q	local	-	-	-	0	Zn	1 !zp pub-to-loc
 * npf_golden3r	local	-	-	-	1	Zn	0 !zp pub-to-loc
 * npf_golden3s	local	-	-	-	1	Zn	1 !zp pub-to-loc
 * npf_golden3t	local	-	-	-	0	Zn	0 zp pub-to-loc
 * npf_golden3u	local	-	-	-	0	Zn	1 zp pub-to-loc
 * npf_golden3v	local	-	-	-	1	Zn	0 zp pub-to-loc
 * npf_golden3w	local	-	-	-	1	Zn	1 zp pub-to-loc
 *
 * npf_golden4	0	0	0	0	-	-	-
 * npf_golden4a	1	0	0	0	-	-	-
 * npf_golden4b	1	1	0	0	-	-	-
 * npf_golden4c	0	0	1	0	-	-	-
 * npf_golden4d	1	0	1	0	-	-	-
 * npf_golden4e	1	1	1	0	-	-	-
 * npf_golden4f	Zn	0	0	0	-	-	-
 * npf_golden4g	0	0	0	0	-	Zn	- local zone
 * npf_golden4h	Zn	0	0	0	-	Zn	- priv to local
 * npf_golden4i	Zn	0	0	0	-	Zn	- pass rule
 * npf_golden4j	Zn	0	0	0	-	Zn	- drop rule
 * npf_golden4k	Zn	0	0	0	-	Zn	- unmatched
 * npf_golden4l	Zn	0	0	0	-	Zn	- stateful
 *
 * npf_golden5	-	-	-	-	-	0	0
 * npf_golden5a	-	-	-	-	-	1	0
 * npf_golden5b	-	-	-	-	-	1	1
 * npf_golden5f	-	-	-	-	-	Zn	0
 *
 * npf_golden6	0	0	-	0	-	-	-
 * npf_golden6a	1	0	-	0	-	-	-
 * npf_golden6b	1	1	-	0	-	-	-
 *
 * make -j4 dataplane_test_run CK_RUN_SUITE=dp_test_npf_golden.c
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_golden1a
 */


/*
 * FWD  - Received on dp1T0, transmitted on dp1T1 (if not dropped)
 * BCK  - Received on dp1T1, transmitted on dp1T0 (if not dropped)
 * S    - Stateful
 */
enum dp_test_golden_flags {
	/* Input firewall on dp1T0 */
	DPT_IN_FW		= 1 << 0,
	DPT_IN_FW_S		= 1 << 1,
	DPT_IN_FW_UNM		= 1 << 2,
	DPT_IN_FW_BLK		= 1 << 3,

	/* Output firewall on dp1T1 */
	DPT_OUT_FW		= 1 << 4,
	DPT_OUT_FW_S		= 1 << 5,
	DPT_OUT_FW_UNM		= 1 << 6,
	DPT_OUT_FW_BLK		= 1 << 7,

	/* DNAT on input on dp1T0 */
	DPT_IN_DNAT		= 1 << 8,
	DPT_IN_DNAT_LOCAL	= 1 << 9,

	/* SNAT on output on dp1T1 */
	DPT_OUT_SNAT		= 1 << 10,
	DPT_OUT_SNAT_LOCAL	= 1 << 11,

	/* NAT64 on input on dp1T0 */
	DPT_IN_NAT64		= 1 << 12,

	/* Zone PRIVATE, dp1T0 */
	DPT_ZONE_PRIV		= 1 << 16,
	DPT_ZONE_PRIV_S		= 1 << 17,
	DPT_ZONE_PRIV_UNM	= 1 << 18,
	DPT_ZONE_PRIV_BLK	= 1 << 19,

	/* Zone PUBLIC, dp1T1 */
	DPT_ZONE_PUB		= 1 << 20,
	DPT_ZONE_PUB_S		= 1 << 21,
	DPT_ZONE_PUB_UNM	= 1 << 22,
	DPT_ZONE_PUB_BLK	= 1 << 23,

	/* Local zone */
	DPT_ZONE_LOCAL		= 1 << 24,
	DPT_ZP_PUB_TO_LOCAL	= 1 << 25,
	DPT_ZP_PUB_TO_LOCAL_S	= 1 << 26,
	DPT_ZP_PUB_TO_LOCAL_BLK	= 1 << 27,
	DPT_ZP_PRIV_TO_LOCAL	= 1 << 28,
	DPT_ZP_PRIV_TO_LOCAL_S	= 1 << 29,
	DPT_ZP_PRIV_TO_LOCAL_BLK = 1 << 30,
	DPT_ZP_PRIV_TO_LOCAL_UNM = 1 << 31,
};

#define DPT_ZONE (DPT_ZONE_PRIV | DPT_ZONE_PUB | DPT_ZONE_LOCAL)

#define DPT_DIFF_ZONES(ctx) (((ctx)->flags & DPT_ZONE) &&    \
			     (!((ctx)->flags & DPT_ZONE_PUB) ^	\
			      !((ctx)->flags & DPT_ZONE_PRIV)))

/* Same or no zones */
#define DPT_SAME_ZONE(ctx) !DPT_DIFF_ZONES(ctx)


struct dp_test_golden_ctx {
	uint32_t     flags;
	uint         count;  /* repeat count */
	uint         fw_in;  /* expected pkt counts on rule */
	uint         fw_out; /* expected pkt counts on rule */
	int          exp_fwd; /* Forwarding expect status for fwd pkt */
	int          exp_back;/* Forwarding expect status for fwd pkt */
	uint         exp_session;
};

enum test_fw {
	TEST_FW_ADD,
	TEST_FW_REMOVE,
	TEST_FW_VERIFY
};

/*
 * Firewall on input
 */
static void
npf_golden_in_fw(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if ((ctx->flags & DPT_IN_FW) == 0)
		return;

	/* UDP */
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = (ctx->flags & DPT_IN_FW_S) != 0,
			.npf      = "proto-final=17 dst-port=48879"
		},
		{
			.rule     = "20",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=17 dst-port=48878"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	/* To get an "unmatched" result, remove the default block rule */
	if (ctx->flags & DPT_IN_FW_UNM) {
		rset[2].rule = NULL;
		rset[2].npf = NULL;
	}

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "IN_FW",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rset
	};

	if (action == TEST_FW_ADD)
		dp_test_npf_fw_add(&fw, false);

	if (action == TEST_FW_REMOVE)
		dp_test_npf_fw_del(&fw, false);

	if (action == TEST_FW_VERIFY)
		dp_test_npf_verify_rule_pkt_count(NULL, &fw,
						  fw.rules[0].rule,
						  ctx->fw_in);
}

/*
 * Firewall on output
 */
static void
npf_golden_out_fw(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if ((ctx->flags & DPT_OUT_FW) == 0)
		return;

	/* UDP */
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = (ctx->flags & DPT_OUT_FW_S) != 0,
			.npf      = "proto-final=17 src-port=57005"
		},
		{
			.rule     = "20",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=17 src-port=57004"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	/* To get an "unmatched" result, remove the default block rule */
	if (ctx->flags & DPT_OUT_FW_UNM) {
		rset[2].rule = NULL;
		rset[2].npf = NULL;
	}

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "OUT_FW",
		.enable = 1,
		.attach_point   = "dp1T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rset
	};

	if (action == TEST_FW_ADD)
		dp_test_npf_fw_add(&fw, false);

	if (action == TEST_FW_REMOVE)
		dp_test_npf_fw_del(&fw, false);

	if (action == TEST_FW_VERIFY) {
		if ((ctx->flags &
		     (DPT_OUT_FW_BLK | DPT_OUT_FW_UNM)) == 0)
			dp_test_npf_verify_rule_pkt_count(NULL, &fw,
							  fw.rules[0].rule,
							  ctx->fw_out);
		if ((ctx->flags & DPT_OUT_FW_BLK) != 0) {
			dp_test_npf_verify_rule_pkt_count(NULL, &fw,
							  fw.rules[0].rule,
							  0);
			dp_test_npf_verify_rule_pkt_count(NULL, &fw,
							  fw.rules[1].rule,
							  ctx->fw_out);
		}
	}
}

static void
npf_golden_in_dnat(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if ((ctx->flags & DPT_IN_DNAT) == 0)
		return;

	/*
	 * Add DNAT rule. Change dest addr from 2.2.2.12 to 2.2.2.11
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.12",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	if (action == TEST_FW_ADD)
		dp_test_npf_dnat_add(&dnat, true);

	if (action == TEST_FW_REMOVE)
		dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);
}

static void
npf_golden_in_dnat_local(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if ((ctx->flags & DPT_IN_DNAT_LOCAL) == 0)
		return;

	/*
	 * Add DNAT rule. Change dest addr from 1.1.1.2 to 1.1.1.1
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "1.1.1.2",
		.to_port	= NULL,
		.trans_addr	= "1.1.1.1",
		.trans_port	= NULL
	};

	if (action == TEST_FW_ADD)
		dp_test_npf_dnat_add(&dnat, true);

	if (action == TEST_FW_REMOVE)
		dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);
}

static void
npf_golden_out_snat(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if ((ctx->flags & DPT_OUT_SNAT) == 0)
		return;

	/*
	 * Add SNAT rule. Change source addr from 1.1.1.11 to 1.1.1.13
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp1T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= "1.1.1.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "1.1.1.13",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	if (action == TEST_FW_ADD)
		dp_test_npf_snat_add(&snat, true);

	if (action == TEST_FW_REMOVE)
		dp_test_npf_snat_del(snat.ifname, snat.rule, true);
}

static void
npf_golden_out_snat_local(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if ((ctx->flags & DPT_OUT_SNAT_LOCAL) == 0)
		return;

	/*
	 * Add SNAT rule. Change source addr from 2.2.2.2 to 2.2.2.3
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp1T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.port_alloc	= NULL,
		.from_addr	= "2.2.2.2",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.3",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	if (action == TEST_FW_ADD)
		dp_test_npf_snat_add(&snat, true);

	if (action == TEST_FW_REMOVE)
		dp_test_npf_snat_del(snat.ifname, snat.rule, true);
}

static void
npf_golden_in_nat64(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if ((ctx->flags & DPT_IN_NAT64) == 0)
		return;

	const struct dp_test_npf_nat64_rule_t rule96 = {
		.rule		= "1",
		.ifname		= "dp1T0",
		.from_addr	= "2001:101:1::/96",
		.to_addr	= "2001:101:2::/96",
		.spl		= 96,
		.dpl		= 96
	};

	if (action == TEST_FW_ADD) {
		dp_test_npf_nat64_add(&rule96, true);
		dp_test_npf_commit();
	}

	if (action == TEST_FW_REMOVE) {
		dp_test_npf_nat64_del(&rule96, true);
		dp_test_npf_commit();
	}
}

/***********************************************************
 * Zone PUBLIC
 ***********************************************************/
static void
npf_golden_zone_public(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	uint i;
	const char *intf;

	/* List of interfaces in PUBLIC zone */
	const char * const intf_public[] = {
		"dp1T1",
		"dp1T2",
		"dp2T2",
		NULL
	};

	if (action == TEST_FW_ADD) {

		dp_test_zone_add("PUBLIC");

		/* Add interfaces to zone PUBLIC */
		for (i = 0; i < ARRAY_SIZE(intf_public); i++) {
			intf = intf_public[i];
			if (intf)
				dp_test_zone_intf_add("PUBLIC", intf);
		}
	}

	if (action == TEST_FW_REMOVE) {

		for (i = 0; i < ARRAY_SIZE(intf_public); i++) {
			intf = intf_public[i];
			if (intf)
				dp_test_zone_intf_del("PUBLIC", intf);
		}

		dp_test_zone_remove("PUBLIC");
	}
}

/***********************************************************
 * Zone PRIVATE
 ***********************************************************/
static void
npf_golden_zone_private(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	uint i;
	const char *intf;

	/* List of interfaces in PRIVATE zone */
	const char * const intf_private[] = {
		"dp1T0",
		NULL
	};

	if (action == TEST_FW_ADD) {
		dp_test_zone_add("PRIVATE");

		/* Add interfaces to zone PRIVATE */
		for (i = 0; i < ARRAY_SIZE(intf_private); i++) {
			intf = intf_private[i];
			if (intf)
				dp_test_zone_intf_add("PRIVATE", intf);
		}
	}

	if (action == TEST_FW_REMOVE) {

		for (i = 0; i < ARRAY_SIZE(intf_private); i++) {
			intf = intf_private[i];
			if (intf)
				dp_test_zone_intf_del("PRIVATE", intf);
		}

		dp_test_zone_remove("PRIVATE");
	}
}

/***********************************************************
 * Zone _local
 ***********************************************************/
static void
npf_golden_zone_local(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if (action == TEST_FW_ADD) {
		dp_test_zone_add("LOCAL");
		dp_test_zone_local("LOCAL", true);
	}

	if (action == TEST_FW_REMOVE) {
		dp_test_zone_local("LOCAL", false);
		dp_test_zone_remove("LOCAL");
	}
}

/*
 * Zone policy for forwards pkts (PRIVATE to PUBLIC zones).
 */
static void
npf_golden_zone_policy_priv_to_pub(enum test_fw action,
			    struct dp_test_golden_ctx *ctx)
{
	struct dp_test_npf_rule_t  rule_priv_to_pub[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = (ctx->flags & DPT_ZONE_PRIV_S) != 0,
			.npf      = "proto-final=17 src-port=57005"
		},
		{
			.rule     = "20",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=17 src-port=57004"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	if (ctx->flags & DPT_ZONE_PRIV_UNM) {
		rule_priv_to_pub[2].rule = NULL;
		rule_priv_to_pub[2].npf = NULL;
	}

	struct dp_test_npf_ruleset_t rlset_priv_to_pub = {
		.rstype = "zone",
		.name = "PRIV_TO_PUB",
		.enable = 1,
		.attach_point   = "PRIVATE>PUBLIC",
		.fwd    = 0,
		.dir    = "out",
		.rules  = rule_priv_to_pub
	};

	if (action == TEST_FW_ADD) {
		dp_test_zone_policy_add("PRIVATE", "PUBLIC");

		/* Add ruleset, and attach to attach point */
		dp_test_npf_fw_add(&rlset_priv_to_pub, false);
	}

	if (action == TEST_FW_REMOVE) {
		/* detach and delete ruleset */
		dp_test_npf_fw_del(&rlset_priv_to_pub, false);

		dp_test_zone_policy_del("PRIVATE", "PUBLIC");
	}
}

/*
 * Zone policy for reverse pkts (PUBLIC to PRIVATE zones).
 */
static void
npf_golden_zone_policy_pub_to_priv(enum test_fw action,
			    struct dp_test_golden_ctx *ctx)
{
	struct dp_test_npf_rule_t  rule_pub_to_priv[] = {
		{
			.rule     = "1",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = ""
		},
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t rlset_pub_to_priv = {
		.rstype = "zone",
		.name = "PUB_TO_PRIV",
		.enable = 1,
		.attach_point = "PUBLIC>PRIVATE",
		.fwd    = 0,
		.dir    = "out",
		.rules  = rule_pub_to_priv
	};

	if (action == TEST_FW_ADD) {

		dp_test_zone_policy_add("PUBLIC", "PRIVATE");

		/* Add ruleset, and attach to attach point */
		dp_test_npf_fw_add(&rlset_pub_to_priv, false);
	}

	if (action == TEST_FW_REMOVE) {

		/* detach and delete ruleset */
		dp_test_npf_fw_del(&rlset_pub_to_priv, false);

		dp_test_zone_policy_del("PUBLIC", "PRIVATE");
	}
}

static void
npf_golden_zone_policy_local_to_pub(enum test_fw action,
			     struct dp_test_golden_ctx *ctx)
{
	struct dp_test_npf_rule_t  rule_local_to_pub[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = (ctx->flags & DPT_ZONE_PUB_S) != 0,
			.npf      = "proto-final=17 src-port=57005"
		},
		{
			.rule     = "20",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=17 src-port=57004"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	if (ctx->flags & DPT_ZONE_PUB_UNM) {
		rule_local_to_pub[2].rule = NULL;
		rule_local_to_pub[2].npf = NULL;
	}

	struct dp_test_npf_ruleset_t rlset_local_to_pub = {
		.rstype = "zone",
		.name = "LOCAL_TO_PUB",
		.enable = 1,
		.attach_point   = "LOCAL>PUBLIC",
		.fwd    = 0,
		.dir    = "out",
		.rules  = rule_local_to_pub
	};


	if (action == TEST_FW_ADD) {
		dp_test_zone_policy_add("LOCAL", "PUBLIC");

		/* Add ruleset, and attach to attach point */
		dp_test_npf_fw_add(&rlset_local_to_pub, false);
	}

	if (action == TEST_FW_REMOVE) {
		/* detach and delete ruleset */
		dp_test_npf_fw_del(&rlset_local_to_pub, false);

		dp_test_zone_policy_del("LOCAL", "PUBLIC");
	}
}

static void
npf_golden_zone_policy_pub_to_local(enum test_fw action,
			     struct dp_test_golden_ctx *ctx)
{
	struct dp_test_npf_rule_t  rule_pub_to_local[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = (ctx->flags & DPT_ZP_PUB_TO_LOCAL_S) != 0,
			.npf      = "proto-final=17 src-port=48879"
		},
		{
			.rule     = "20",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=17 src-port=48878"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t rlset_pub_to_local = {
		.rstype = "zone",
		.name = "PUB_TO_LOCAL",
		.enable = 1,
		.attach_point   = "PUBLIC>LOCAL",
		.fwd    = 0,
		.dir    = "out",
		.rules  = rule_pub_to_local
	};

	if (action == TEST_FW_ADD) {
		dp_test_zone_policy_add("PUBLIC", "LOCAL");

		/* Add ruleset, and attach to attach point */
		dp_test_npf_fw_add(&rlset_pub_to_local, false);
	}

	if (action == TEST_FW_REMOVE) {

		/* detach and delete ruleset */
		dp_test_npf_fw_del(&rlset_pub_to_local, false);

		dp_test_zone_policy_del("PUBLIC", "LOCAL");
	}
}

static void
npf_golden_zone_policy_local_to_priv(enum test_fw action,
			     struct dp_test_golden_ctx *ctx)
{
	struct dp_test_npf_rule_t  rule_local_to_priv[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = (ctx->flags & DPT_ZONE_PRIV_S) != 0,
			.npf      = "proto-final=17 src-port=48879"
		},
		{
			.rule     = "20",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=17 src-port=48878"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	if (ctx->flags & DPT_ZONE_PRIV_UNM) {
		rule_local_to_priv[2].rule = NULL;
		rule_local_to_priv[2].npf = NULL;
	}

	struct dp_test_npf_ruleset_t rlset_local_to_priv = {
		.rstype = "zone",
		.name = "LOCAL_TO_PRIV",
		.enable = 1,
		.attach_point   = "LOCAL>PRIVATE",
		.fwd    = 0,
		.dir    = "out",
		.rules  = rule_local_to_priv
	};


	if (action == TEST_FW_ADD) {
		dp_test_zone_policy_add("LOCAL", "PRIVATE");

		/* Add ruleset, and attach to attach point */
		dp_test_npf_fw_add(&rlset_local_to_priv, false);
	}

	if (action == TEST_FW_REMOVE) {
		/* detach and delete ruleset */
		dp_test_npf_fw_del(&rlset_local_to_priv, false);

		dp_test_zone_policy_del("LOCAL", "PRIVATE");
	}
}

static void
npf_golden_zone_policy_priv_to_local(enum test_fw action,
			     struct dp_test_golden_ctx *ctx)
{
	struct dp_test_npf_rule_t  rule_priv_to_local[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = (ctx->flags & DPT_ZP_PRIV_TO_LOCAL_S) != 0,
			.npf      = "proto-final=17 src-port=57005"
		},
		{
			.rule     = "20",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "proto-final=17 src-port=57004"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	if (ctx->flags & DPT_ZP_PRIV_TO_LOCAL_UNM) {
		rule_priv_to_local[2].rule = NULL;
		rule_priv_to_local[2].npf = NULL;
	}

	struct dp_test_npf_ruleset_t rlset_priv_to_local = {
		.rstype = "zone",
		.name = "PRIV_TO_LOCAL",
		.enable = 1,
		.attach_point   = "PRIVATE>LOCAL",
		.fwd    = 0,
		.dir    = "out",
		.rules  = rule_priv_to_local
	};

	if (action == TEST_FW_ADD) {
		dp_test_zone_policy_add("PRIVATE", "LOCAL");

		/* Add ruleset, and attach to attach point */
		dp_test_npf_fw_add(&rlset_priv_to_local, false);
	}

	if (action == TEST_FW_REMOVE) {

		/* detach and delete ruleset */
		dp_test_npf_fw_del(&rlset_priv_to_local, false);

		dp_test_zone_policy_del("PRIVATE", "LOCAL");
	}
}

static void
npf_golden_zone(enum test_fw action, struct dp_test_golden_ctx *ctx)
{
	if ((ctx->flags & DPT_ZONE) == 0)
		return;

	if ((ctx->flags & (DPT_IN_FW | DPT_OUT_FW)))
		dp_test_fail("Cannot cfg zones and fw at same time");

	if (action == TEST_FW_ADD) {
		if (ctx->flags & DPT_ZONE_PUB) {
			npf_golden_zone_public(action, ctx);
			npf_golden_zone_policy_pub_to_priv(action, ctx);

			if (ctx->flags & DPT_ZP_PUB_TO_LOCAL)
				npf_golden_zone_policy_pub_to_local(action,
								    ctx);
		}

		if (ctx->flags & DPT_ZONE_PRIV) {
			npf_golden_zone_private(action, ctx);
			npf_golden_zone_policy_priv_to_pub(action, ctx);

			if (ctx->flags & DPT_ZP_PRIV_TO_LOCAL)
				npf_golden_zone_policy_priv_to_local(action,
								    ctx);
		}

		if (ctx->flags & DPT_ZONE_LOCAL) {
			npf_golden_zone_local(action, ctx);

			if (ctx->flags & DPT_ZONE_PUB)
				npf_golden_zone_policy_local_to_pub(action,
								    ctx);
			if (ctx->flags & DPT_ZONE_PRIV)
				npf_golden_zone_policy_local_to_priv(action,
								    ctx);
		}
	}

	if (action == TEST_FW_REMOVE) {
		if (ctx->flags & DPT_ZONE_PUB) {
			if (ctx->flags & DPT_ZP_PUB_TO_LOCAL)
				npf_golden_zone_policy_pub_to_local(action,
								    ctx);

			npf_golden_zone_policy_pub_to_priv(action, ctx);
			npf_golden_zone_public(action, ctx);
		}

		if (ctx->flags & DPT_ZONE_PRIV) {
			if (ctx->flags & DPT_ZP_PRIV_TO_LOCAL)
				npf_golden_zone_policy_priv_to_local(action,
								    ctx);

			npf_golden_zone_policy_priv_to_pub(action, ctx);
			npf_golden_zone_private(action, ctx);
		}

		if (ctx->flags & DPT_ZONE_LOCAL) {
			if (ctx->flags & DPT_ZONE_PUB)
				npf_golden_zone_policy_local_to_pub(action,
								    ctx);

			if (ctx->flags & DPT_ZONE_PRIV)
				npf_golden_zone_policy_local_to_priv(action,
								     ctx);

			npf_golden_zone_local(action, ctx);
		}
	}
}

/*
 * Simple custom timeout for UDP to exercise tag rproc and custom timeout
 * ruleset
 */
static void npf_custom_timeout(bool enable)
{
	if (enable)
		dp_test_npf_cmd_fmt(
			false,
		"npf-ut add custom-timeout:1 1 proto-final=17 handle=tag(50)");
	else
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut delete custom-timeout:1 1");

	dp_test_npf_commit();
}

/*
 * IPv4 Tests, Forwards pkt from interface dp1T0 to dp1T1, then reverse
 * packet.
 */
static void _dp_test_npf_golden_1(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func);
#define dp_test_npf_golden_1(ctx) \
	_dp_test_npf_golden_1(ctx, __FILE__, __func__)

static void _dp_test_npf_golden_1(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T2", "3.3.3.11",
				  "aa:bb:cc:dd:3:11");

	/* Add one or more firewalls dependent on ctx flags */
	npf_golden_in_fw(TEST_FW_ADD, ctx);
	npf_golden_in_dnat(TEST_FW_ADD, ctx);
	npf_golden_out_snat(TEST_FW_ADD, ctx);
	npf_golden_out_fw(TEST_FW_ADD, ctx);
	npf_golden_zone(TEST_FW_ADD, ctx);

	/*
	 * UDP packet
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD, /* 57005 */
				.dport = 0xBEEF, /* 48879 */
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T1"
	};

	if ((ctx->flags & DPT_IN_FW_BLK) != 0)
		pre_pkt.l4.udp.dport = 48878;
	else if ((ctx->flags & DPT_IN_FW_UNM) != 0)
		pre_pkt.l4.udp.dport = 48877;

	if ((ctx->flags & DPT_OUT_FW_BLK) != 0)
		pre_pkt.l4.udp.sport = 57004;
	else if ((ctx->flags & DPT_OUT_FW_UNM) != 0 ||
		 (ctx->flags & DPT_ZONE_PRIV_UNM) != 0)
		pre_pkt.l4.udp.sport = 57003;

	struct dp_test_pkt_desc_t post_pkt;
	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

	uint repeat_count = ctx->count;
	bool first_time = true;

repeat:
	post_pkt = pre_pkt;
	pre_desc = &pre_pkt;
	post_desc = &post_pkt;

	if ((ctx->flags & DPT_IN_DNAT) != 0)
		/* DNAT 2.2.2.12 -> 2.2.2.11 */
		pre_desc->l3_dst = "2.2.2.12";

	if ((ctx->flags & DPT_OUT_SNAT) != 0)
		/* SNAT 1.1.1.11 ->  1.1.1.13 */
		post_desc->l3_src = "1.1.1.13";

	/*
	 * Forwards packet
	 */
	pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
	post_pak = dp_test_v4_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_from_desc(post_pak, post_desc);
	rte_pktmbuf_free(post_pak);

	/* If in-fw and dnat are cfgd, then they use the same session */
	if (first_time && ctx->exp_fwd == DP_TEST_FWD_FORWARDED)
		first_time = false;

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_fwd);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards, exp %s", func,
	       ctx->exp_fwd == DP_TEST_FWD_FORWARDED ? "FORW":"DROP");

	/* Run the test */
	_dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp,
			     file, func, __LINE__);

	/* Check fw counts for first pkt */
	if (repeat_count == ctx->count) {
		npf_golden_in_fw(TEST_FW_VERIFY, ctx);
		npf_golden_out_fw(TEST_FW_VERIFY, ctx);
	}

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (ctx->exp_session) {
		if ((ctx->flags & DPT_IN_FW_S) != 0) {
			if ((ctx->flags & DPT_IN_DNAT) != 0)
				dp_test_nat_session_verify_desc(
					false, 0x0D, pre_desc, post_desc);
			else
				dp_test_npf_session_verify_desc(
					NULL, pre_desc, pre_desc->rx_intf,
					SE_ACTIVE, SE_FLAGS_AE, true);
		}

		if ((ctx->flags & DPT_IN_FW_S) != 0 ||
		    (ctx->flags & DPT_IN_DNAT) != 0) {

			dp_test_npf_session_verify_desc(
				NULL, pre_desc,	pre_desc->rx_intf,
				SE_ACTIVE, SE_FLAGS_AE, true);

		} else if ((ctx->flags & DPT_OUT_FW_S) != 0 ||
			   (ctx->flags & DPT_OUT_SNAT) != 0 ||
			   (ctx->flags & DPT_ZONE_PRIV_S) != 0) {

			dp_test_npf_session_verify_desc(
				NULL, pre_desc,	pre_desc->tx_intf,
				SE_ACTIVE, SE_FLAGS_AE, true);
		}
	}

	/*
	 * Reverse packet
	 */
	pre_pak  = dp_test_reverse_v4_pkt_from_desc(post_desc);
	post_pak = dp_test_reverse_v4_pkt_from_desc(pre_desc);

	test_exp = dp_test_reverse_exp_from_desc(post_pak, pre_desc);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_back);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Reverse, exp %s", func,
	      ctx->exp_back == DP_TEST_FWD_FORWARDED ? "FORW":"DROP");

	/* Run the test */
	_dp_test_pak_receive(pre_pak, pre_desc->tx_intf, test_exp,
			     file, func, __LINE__);

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (ctx->count > 1) {
		ctx->count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_in_fw(TEST_FW_REMOVE, ctx);
	npf_golden_in_dnat(TEST_FW_REMOVE, ctx);
	npf_golden_out_snat(TEST_FW_REMOVE, ctx);
	npf_golden_out_fw(TEST_FW_REMOVE, ctx);
	npf_golden_zone(TEST_FW_REMOVE, ctx);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T2", "3.3.3.11",
				  "aa:bb:cc:dd:3:11");
}


DP_DECL_TEST_SUITE(npf_golden);

/*
 * IPv4, no npf
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1, NULL, NULL);
DP_START_TEST(npf_golden1, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 * IPv4, In FW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1a, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0,
		.count = 1,
		.fw_in = 1,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 * IPv4, In sFW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1b, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0,
		.count = 1,
		.fw_in = 1,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 *
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1c, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1c, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_DNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 *
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1d, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1d, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0,
		.count = 1,
		.fw_in = 1,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_DNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 *
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1e, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1e, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0,
		.count = 1,
		.fw_in = 1,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;
	ctx.flags |= DPT_IN_DNAT;

	npf_custom_timeout(true);

	dp_test_npf_golden_1(&ctx);

	npf_custom_timeout(false);

} DP_END_TEST;

/*
 *
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1f, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1f, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 *
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1g, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1g, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_OUT_SNAT;
	ctx.flags |= DPT_OUT_FW;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 *
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1h, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1h, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_OUT_SNAT;
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;


/*
 * v4: In -> DNAT -> Out -> SNAT
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1i, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1i, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_DNAT;
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 * v4: In -> sFW -> DNAT -> Out -> SNAT -> sFW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1j, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1j, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0,
		.count = 1,
		.fw_in = 1,
		.fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;
	ctx.flags |= DPT_IN_DNAT;
	ctx.flags |= DPT_OUT_SNAT;
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 * v4: In -> sFW -> Out -> sFW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1k, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1k, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0,
		.count = 2,
		.fw_in = 1,
		.fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 * non-zone to zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1l, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1l, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PRIV;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

/*
 * Zone to non-zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden1m, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1m, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden1n, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1n, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden1o, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1o, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_PRIV_UNM;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden1p, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1p, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_IN_DNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden1q, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1q, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden1r, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1r, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_PRIV_S;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden1s, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1s, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_PRIV_S;
	ctx.flags |= DPT_IN_DNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden1t, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1t, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_PRIV_S;
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden1u, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden1u, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_PRIV_S;
	ctx.flags |= DPT_IN_DNAT;
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_1(&ctx);

} DP_END_TEST;


/*
 * IPv6 Tests, Forwards pkt from interface dp1T0 to dp1T1, then reverse
 * packet.
 */
static void _dp_test_npf_golden_2(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func);
#define dp_test_npf_golden_2(ctx) \
	_dp_test_npf_golden_2(ctx, __FILE__, __func__)

static void _dp_test_npf_golden_2(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::101:101/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:101:2::202:202/96");

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::101:10b",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");

	dp_test_netlink_add_neigh("dp1T1", "2001:101:2::202:20b",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	npf_golden_in_fw(TEST_FW_ADD, ctx);
	npf_golden_out_fw(TEST_FW_ADD, ctx);

	if ((ctx->flags & DPT_IN_NAT64) != 0) {
		npf_golden_in_nat64(TEST_FW_ADD, ctx);

		if ((ctx->flags & DPT_OUT_SNAT) != 0)
			npf_golden_out_snat(TEST_FW_ADD, ctx);
	}

	npf_golden_zone(TEST_FW_ADD, ctx);

	/*
	 * UDP packet
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1::101:10b",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "2001:101:2::202:20b",
		.l2_dst     = "aa:bb:cc:dd:2:11",
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

	if ((ctx->flags & DPT_IN_FW_BLK) != 0)
		pre_pkt.l4.udp.dport = 48878;
	else if ((ctx->flags & DPT_IN_FW_UNM) != 0)
		pre_pkt.l4.udp.dport = 48877;

	if ((ctx->flags & DPT_OUT_FW_BLK) != 0)
		pre_pkt.l4.udp.sport = 57004;
	else if ((ctx->flags & DPT_OUT_FW_UNM) != 0)
		pre_pkt.l4.udp.sport = 57003;

	struct dp_test_pkt_desc_t post_pkt;
	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

	uint repeat_count = ctx->count;
	bool first_time = true;

repeat:
	post_pkt = pre_pkt;
	pre_desc = &pre_pkt;
	post_desc = &post_pkt;

	if ((ctx->flags & DPT_IN_NAT64) != 0) {
		post_desc->ether_type = RTE_ETHER_TYPE_IPV4;

		if ((ctx->flags & DPT_OUT_SNAT) != 0)
			post_desc->l3_src     = "1.1.1.13";
		else
			post_desc->l3_src     = "1.1.1.11";

		post_desc->l3_dst     = "2.2.2.11";
	}

	/*
	 * Forwards packet
	 */
	pre_pak  = dp_test_v6_pkt_from_desc(pre_desc);
	post_pak = dp_test_v6_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_from_desc(post_pak, post_desc);
	rte_pktmbuf_free(post_pak);

	/* If in-fw and dnat are cfgd, then they use the same session */
	if (first_time && ctx->exp_fwd == DP_TEST_FWD_FORWARDED)
		first_time = false;

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_fwd);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards, exp %s", func,
	      ctx->exp_fwd == DP_TEST_FWD_FORWARDED ? "FORW":"DROP");

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre_desc->rx_intf, test_exp);

	/* Check fw counts for first pkt */
	if (repeat_count == ctx->count) {
		if ((ctx->flags & DPT_IN_FW) != 0)
			npf_golden_in_fw(TEST_FW_VERIFY, ctx);

		if ((ctx->flags & DPT_OUT_FW) != 0)
			npf_golden_out_fw(TEST_FW_VERIFY, ctx);
	}

	// dp_test_npf_print_session_table(true);
	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (ctx->exp_session) {
		if ((ctx->flags & DPT_IN_NAT64) == 0) {
			/* Temporarily ignore sessions if nat64 cfgd */
			if ((ctx->flags & DPT_IN_FW_S) != 0) {

				dp_test_npf_session_verify_desc(
					NULL, pre_desc, pre_desc->rx_intf,
					SE_ACTIVE, SE_FLAGS_AE, true);

			} else if ((ctx->flags & DPT_OUT_FW_S) != 0 ||
				   (ctx->flags & DPT_ZONE_PRIV_S) != 0) {

				dp_test_npf_session_verify_desc(
					NULL, post_desc, post_desc->tx_intf,
					SE_ACTIVE, SE_FLAGS_AE, true);
			}
		}
	}

	/*
	 * Reverse packet
	 */
	pre_pak  = dp_test_reverse_v6_pkt_from_desc(post_desc);
	post_pak = dp_test_reverse_v6_pkt_from_desc(pre_desc);

	test_exp = dp_test_reverse_exp_from_desc(post_pak, pre_desc);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_back);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Reverse, exp %s", func,
	      ctx->exp_back == DP_TEST_FWD_FORWARDED ? "FORW":"DROP");

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre_desc->tx_intf, test_exp);

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (ctx->count > 1) {
		ctx->count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_in_fw(TEST_FW_REMOVE, ctx);
	npf_golden_out_fw(TEST_FW_REMOVE, ctx);

	if ((ctx->flags & DPT_IN_NAT64) != 0) {
		npf_golden_in_nat64(TEST_FW_REMOVE, ctx);

		if ((ctx->flags & DPT_OUT_SNAT) != 0)
			npf_golden_out_snat(TEST_FW_REMOVE, ctx);
	}

	npf_golden_zone(TEST_FW_REMOVE, ctx);

	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::101:10b",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");

	dp_test_netlink_del_neigh("dp1T1", "2001:101:2::202:20b",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::101:101/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:101:2::202:202/96");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

}

/*
 * IPv6, no npf
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2, NULL, NULL);
DP_START_TEST(npf_golden2, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0,
		.count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};


	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2a, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2b, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2c, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2c, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2d, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2d, test)
{
	struct dp_test_golden_ctx ctx = {
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
		.exp_session = 2,
	};
	ctx.flags |= DPT_IN_NAT64;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2e, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2e, test)
{
	struct dp_test_golden_ctx ctx = {
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
		.exp_session = 2,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_NAT64;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2f, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2f, test)
{
	/*
	 * Not working yet with the new session code.  If an input fw session
	 * exists and nat64 is enabled, then the return pkt fails to find the
	 * nat64 session.
	 */
	struct dp_test_golden_ctx ctx = {
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
		.exp_session = 2,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;
	ctx.flags |= DPT_IN_NAT64;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2g, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2g, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_NAT64;
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2h, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2h, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_NAT64;
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * IPv6
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2i, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2i, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;
	ctx.flags |= DPT_IN_NAT64;
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * non-zone to zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2l, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2l, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PRIV;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

/*
 * Zone to non-zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden2m, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2m, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden2n, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2n, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden2o, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2o, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_IN_NAT64;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden2p, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2p, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_IN_NAT64;
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden2q, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2q, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_PRIV_S;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden2s, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden2s, test)
{
	/*
	 * Reverse pkt is blocked due to the PUB to PRIV zone rule.  session
	 * inspect does not find a session, so there is no automatic pass.
	 */
	struct dp_test_golden_ctx ctx = {
		.exp_session = 2, .flags = 0,
		.count = 1,
		.fw_in = 0,
		.fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_PRIV_S;
	ctx.flags |= DPT_IN_NAT64;
	ctx.flags |= DPT_OUT_SNAT;

	dp_test_npf_golden_2(&ctx);

} DP_END_TEST;


/*
 * IPv4, local to net (dp1T1, zone PUBLIC)
 */
static void _dp_test_npf_golden_3(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func);
#define dp_test_npf_golden_3(ctx) \
	_dp_test_npf_golden_3(ctx, __FILE__, __func__)

static void _dp_test_npf_golden_3(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	npf_golden_out_snat_local(TEST_FW_ADD, ctx);
	npf_golden_out_fw(TEST_FW_ADD, ctx);
	npf_golden_zone(TEST_FW_ADD, ctx);

	/*
	 * UDP packet.  Local to net
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "2.2.2.2",
		.l2_src     = "0:0:a4:0:0:65",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD, /* 57005 */
				.dport = 0xBEEF,
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T1"
	};

	if ((ctx->flags & DPT_IN_FW_BLK) != 0)
		pre_pkt.l4.udp.dport = 48878;
	else if ((ctx->flags & DPT_IN_FW_UNM) != 0)
		pre_pkt.l4.udp.dport = 48877;

	if ((ctx->flags & DPT_OUT_FW_BLK) != 0 ||
	    (ctx->flags & DPT_ZONE_PUB_BLK) != 0)
		pre_pkt.l4.udp.sport = 57004;
	else if ((ctx->flags & DPT_OUT_FW_UNM) != 0 ||
		 (ctx->flags & DPT_ZONE_PUB_UNM) != 0)
		pre_pkt.l4.udp.sport = 57003;

	struct dp_test_pkt_desc_t post_pkt;
	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

repeat:
	post_pkt = pre_pkt;
	pre_desc = &pre_pkt;
	post_desc = &post_pkt;

	if ((ctx->flags & DPT_OUT_SNAT_LOCAL) != 0)
		/* SNAT  2.2.2.2 to 2.2.2.3*/
		post_desc->l3_src = "2.2.2.3";

	pre_pak  = dp_test_from_spath_v4_pkt_from_desc(pre_desc);
	post_pak = dp_test_from_spath_v4_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_fwd);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards", func);

	/* Run the test */
	dp_test_send_slowpath_pkt(pre_pak, test_exp);

	if ((ctx->flags & DPT_IN_FW) != 0)
		npf_golden_in_fw(TEST_FW_VERIFY, ctx);

	if ((ctx->flags & DPT_OUT_FW) != 0)
		npf_golden_out_fw(TEST_FW_VERIFY, ctx);

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (ctx->exp_session) {
		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->tx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	}

	pre_pak  = dp_test_reverse_v4_pkt_from_desc(post_desc);
	post_pak = dp_test_reverse_v4_pkt_from_desc(pre_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_back);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Reverse", func);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre_desc->tx_intf, test_exp);

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (ctx->count > 1) {
		ctx->count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_out_snat_local(TEST_FW_REMOVE, ctx);
	npf_golden_out_fw(TEST_FW_REMOVE, ctx);
	npf_golden_zone(TEST_FW_REMOVE, ctx);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

}

/*
 * IPv4, local, no npf
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3, NULL, NULL);
DP_START_TEST(npf_golden3, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out FW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3a, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_FW;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out sFW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3b, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out SNAT
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3c, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3c, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_SNAT_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out SNAT -> FW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3d, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3d, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_SNAT_LOCAL;
	ctx.flags |= DPT_OUT_FW;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out SNAT -> FW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3e, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3e, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1, .flags = 0,
		.count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_SNAT_LOCAL;
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3f, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3f, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0,
		.count = 1, .fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3g, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3g, test)
{
	/* no session is created for local to network traffic */
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_S;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out SNAT -> Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3h, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3h, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_OUT_SNAT_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local, Out SNAT -> Zone, stateful
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3i, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3i, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_S;
	ctx.flags |= DPT_OUT_SNAT_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;


/*
 * 3j: IPv4, local, Out sFW, pkt matching block rule
 *
 * Packet will be sent, but no firewall rule stats will be incremented
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3j, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3j, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 0,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_BLK;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * 3k: IPv4, local, Out sFW, pkt matching block rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3k, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3k, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;
	ctx.flags |= DPT_OUT_FW_BLK;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * 3l: IPv4, local, Out sFW, pkt matching no rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3l, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3l, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_UNM;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * 3m: IPv4, local, Out sFW, pkt matching no rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3m, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3m, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;
	ctx.flags |= DPT_OUT_FW_UNM;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone to Public Zone.  There is no zone policy for PUB to local,
 * so the reverse packet is dropped.
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3n, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3n, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone to Public Zone, unmatched
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3o, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3o, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_UNM;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone to Public zone, block
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3p, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3p, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_BLK;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone to Public Zone (stateful)
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3q, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3q, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB_S;
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone, Out SNAT -> Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3r, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3r, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_OUT_SNAT_LOCAL;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone, Out SNAT -> Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3s, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3s, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_S;
	ctx.flags |= DPT_OUT_SNAT_LOCAL;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone to Public Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3t, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3t, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PUB_TO_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone to Public Zone (stateful)
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3u, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3u, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB_S;
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PUB_TO_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone, Out SNAT -> Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3v, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3v, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_OUT_SNAT_LOCAL;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PUB_TO_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone, Out SNAT -> Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3w, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3w, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_S;
	ctx.flags |= DPT_OUT_SNAT_LOCAL;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PUB_TO_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;

/*
 * IPv4, local zone to non-zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden3x, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden3x, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_3(&ctx);

} DP_END_TEST;


/*
 * IPv4, net (dp1T0, zone PRIVATE) to local
 */
static void _dp_test_npf_golden_4(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func);
#define dp_test_npf_golden_4(ctx) \
	_dp_test_npf_golden_4(ctx, __FILE__, __func__)

static void _dp_test_npf_golden_4(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	npf_golden_in_fw(TEST_FW_ADD, ctx);
	npf_golden_in_dnat_local(TEST_FW_ADD, ctx);
	npf_golden_zone(TEST_FW_ADD, ctx);

	/*
	 * UDP packet.  Net to local
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "1.1.1.1",
		.l2_dst     = "0:0:a4:0:0:65",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD, /* 57005 */
				.dport = 0xBEEF, /* 48879 */
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	if ((ctx->flags & DPT_IN_FW_BLK) != 0)
		pre_pkt.l4.udp.dport = 48878;
	else if ((ctx->flags & DPT_IN_FW_UNM) != 0)
		pre_pkt.l4.udp.dport = 48877;

	if ((ctx->flags & DPT_ZP_PRIV_TO_LOCAL_BLK) != 0)
		pre_pkt.l4.udp.sport = 57004;
	else if ((ctx->flags & DPT_ZP_PRIV_TO_LOCAL_UNM) != 0)
		pre_pkt.l4.udp.sport = 57003;

	struct dp_test_pkt_desc_t post_pkt;
	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

repeat:
	post_pkt = pre_pkt;
	pre_desc = &pre_pkt;
	post_desc = &post_pkt;

	if ((ctx->flags & DPT_IN_DNAT_LOCAL) != 0)
		/* DNAT 1.1.1.2 -> 1.1.1.1 */
		pre_desc->l3_dst = "1.1.1.2";

	pre_pak  = dp_test_v4_pkt_from_desc(pre_desc);
	post_pak = dp_test_v4_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_fwd);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards", func);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre_desc->tx_intf, test_exp);

	if ((ctx->flags & DPT_IN_FW) != 0)
		npf_golden_in_fw(TEST_FW_VERIFY, ctx);

	if ((ctx->flags & DPT_OUT_FW) != 0)
		npf_golden_out_fw(TEST_FW_VERIFY, ctx);

	bool exp_zone_sess = false;

	if ((ctx->flags & DPT_ZONE_PRIV) != 0 &&
	    (ctx->flags & DPT_ZONE_LOCAL) != 0 &&
	    (ctx->flags & DPT_ZP_PRIV_TO_LOCAL) != 0 &&
	    (ctx->flags & DPT_ZP_PRIV_TO_LOCAL_S) != 0)
		exp_zone_sess = true;

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if ((ctx->flags & DPT_IN_FW_S) != 0 || exp_zone_sess) {
		if ((ctx->flags & DPT_IN_DNAT_LOCAL) != 0)
			dp_test_nat_session_verify_desc(false, 0x0D,
							pre_desc, post_desc);
		else
			dp_test_npf_session_verify_desc(NULL, pre_desc,
							pre_desc->rx_intf,
							SE_ACTIVE,
							SE_FLAGS_AE, true);
	}

	if ((ctx->flags & DPT_IN_FW_S) != 0 ||
	    (ctx->flags & DPT_IN_DNAT_LOCAL) != 0) {

		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->rx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	} else if ((ctx->flags & DPT_OUT_FW_S) != 0 ||
		 (ctx->flags & DPT_OUT_SNAT) != 0 ||
		 (ctx->flags & DPT_ZONE_PRIV_S) != 0) {
		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->tx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	}

	/*
	 * UDP packet.  Local to Net
	 */
	struct dp_test_pkt_desc_t pre_pkt2 = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.1",
		.l2_src     = "0:0:a4:0:0:65",
		.l3_dst     = "1.1.1.11",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xBEEF, /* 48879 */
				.dport = 0xDEAD, /* 57005 */
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t post_pkt2 = pre_pkt2;
	pre_desc = &pre_pkt2;
	post_desc = &post_pkt2;

	if ((ctx->flags & DPT_IN_DNAT_LOCAL) != 0)
		/* Reverse DNAT, src 1.1.1.1 -> 1.1.1.2 */
		post_desc->l3_src = "1.1.1.2";

	pre_pak  = dp_test_from_spath_v4_pkt_from_desc(pre_desc);
	post_pak = dp_test_from_spath_v4_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, ctx->exp_back);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Reverse", func);

	/* Run the test */
	dp_test_send_slowpath_pkt(pre_pak, test_exp);


	if (ctx->count > 1) {
		ctx->count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_in_fw(TEST_FW_REMOVE, ctx);
	npf_golden_in_dnat_local(TEST_FW_REMOVE, ctx);
	npf_golden_zone(TEST_FW_REMOVE, ctx);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
}


/*
 * IPv4, Net to local
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4, NULL, NULL);
DP_START_TEST(npf_golden4, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, In FW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4a, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, In sFW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4b, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, In DNAT
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4c, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4c, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_DNAT_LOCAL;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, In FW -> DNAT
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4d, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4d, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_DNAT_LOCAL;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, In sFW -> DNAT
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4e, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4e, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;
	ctx.flags |= DPT_IN_DNAT_LOCAL;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, In zone to non-zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4f, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4f, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PRIV;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, non-zone to zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4g, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4g, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, zone to zone, no ruleset
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4h, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4h, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, zone to zone, matching pass rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4i, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4i, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PRIV_TO_LOCAL;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, zone to zone, matching drop rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4j, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4j, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PRIV_TO_LOCAL;
	ctx.flags |= DPT_ZP_PRIV_TO_LOCAL_BLK;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, zone to zone, no matching rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4k, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4k, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PRIV_TO_LOCAL;
	ctx.flags |= DPT_ZP_PRIV_TO_LOCAL_UNM;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;

/*
 * IPv4, Net to local, zone to zone, matching stateful rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden4l, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden4l, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_ZONE_PRIV;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PRIV_TO_LOCAL;
	ctx.flags |= DPT_ZP_PRIV_TO_LOCAL_S;

	dp_test_npf_golden_4(&ctx);
} DP_END_TEST;


/*
 * IPv6, local to net
 */
static void _dp_test_npf_golden_5(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func);
#define dp_test_npf_golden_5(ctx) \
	_dp_test_npf_golden_5(ctx, __FILE__, __func__)

static void _dp_test_npf_golden_5(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::101:101/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:101:2::202:202/96");

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::101:10b",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");

	dp_test_netlink_add_neigh("dp1T1", "2001:101:2::202:20b",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	npf_golden_out_fw(TEST_FW_ADD, ctx);
	npf_golden_zone(TEST_FW_ADD, ctx);


	/*
	 * UDP packet.  Local to net
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:2::202:202",
		.l2_src     = "0:0:a4:0:0:65",
		.l3_dst     = "2001:101:2::202:20b",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD, /* 57005 */
				.dport = 0xBEEF,
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T1"
	};

	if ((ctx->flags & DPT_IN_FW_BLK) != 0)
		pre_pkt.l4.udp.dport = 48878;
	else if ((ctx->flags & DPT_IN_FW_UNM) != 0)
		pre_pkt.l4.udp.dport = 48877;

	if ((ctx->flags & DPT_OUT_FW_BLK) != 0 ||
	    (ctx->flags & DPT_ZONE_PUB_BLK) != 0)
		pre_pkt.l4.udp.sport = 57004;
	else if ((ctx->flags & DPT_OUT_FW_UNM) != 0 ||
		 (ctx->flags & DPT_ZONE_PUB_UNM) != 0)
		pre_pkt.l4.udp.sport = 57003;

	struct dp_test_pkt_desc_t post_pkt;
	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

repeat:
	post_pkt = pre_pkt;
	pre_desc = &pre_pkt;
	post_desc = &post_pkt;

	pre_pak  = dp_test_from_spath_pkt_from_desc(pre_desc);
	post_pak = dp_test_from_spath_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, ctx->exp_fwd);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards", func);

	/* Run the test */
	dp_test_send_slowpath_pkt(pre_pak, test_exp);

	if ((ctx->flags & DPT_IN_FW) != 0)
		npf_golden_in_fw(TEST_FW_VERIFY, ctx);

	if ((ctx->flags & DPT_OUT_FW) != 0)
		npf_golden_out_fw(TEST_FW_VERIFY, ctx);

	uint sess_out_exp = 0;

	if (((ctx->flags & DPT_OUT_FW_S) != 0 &&
	     (ctx->flags & (DPT_OUT_FW_BLK | DPT_OUT_FW_UNM)) == 0) ||
	    (ctx->flags & DPT_OUT_SNAT_LOCAL) != 0 ||
	    ((ctx->flags & DPT_ZONE_PUB_S) != 0 &&
	     (ctx->flags & DPT_ZONE_LOCAL) != 0)) {
		sess_out_exp++;
	}

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (sess_out_exp)
		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->tx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);

	pre_pak  = dp_test_reverse_v6_pkt_from_desc(post_desc);
	post_pak = dp_test_reverse_v6_pkt_from_desc(pre_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_back);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Reverse", func);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre_desc->tx_intf, test_exp);

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (ctx->count > 1) {
		ctx->count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_out_fw(TEST_FW_REMOVE, ctx);
	npf_golden_zone(TEST_FW_REMOVE, ctx);

	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::101:10b",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");

	dp_test_netlink_del_neigh("dp1T1", "2001:101:2::202:20b",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::101:101/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:101:2::202:202/96");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
}

/*
 * IPv6, local, no npf
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5, NULL, NULL);
DP_START_TEST(npf_golden5, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};

	dp_test_npf_golden_5(&ctx);
} DP_END_TEST;

/*
 * IPv6, local, Out FW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5a, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_FW;

	dp_test_npf_golden_5(&ctx);
} DP_END_TEST;

/*
 * IPv6, local, Out sFW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5b, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;

	dp_test_npf_golden_5(&ctx);
} DP_END_TEST;

/*
 * IPv6, local, Out Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5f, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5f, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;

	dp_test_npf_golden_5(&ctx);
} DP_END_TEST;

/*
 * IPv6, local, Out Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5g, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5g, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_S;

	dp_test_npf_golden_5(&ctx);
} DP_END_TEST;

/*
 * 5j: IPv6, local, Out sFW, pkt matching block rule
 *
 * Packet will be sent, but no firewall rule stats will be incremented
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5j, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5j, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 0,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_BLK;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

DP_DECL_TEST_CASE(npf_golden, npf_golden5k, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5k, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 0,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;
	ctx.flags |= DPT_OUT_FW_BLK;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * 5l: IPv4, local, Out sFW, pkt matching no rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5l, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5l, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_UNM;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * 5m: IPv6, local, Out sFW, pkt matching no rule
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5m, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5m, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_S;
	ctx.flags |= DPT_OUT_FW_UNM;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * IPv6, local zone to Public Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5n, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5n, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * IPv6, local zone to Public Zone, unmatched
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5o, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5o, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_UNM;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * IPv6, local zone to Public zone, block
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5p, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5p, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_DROPPED,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_PUB_BLK;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * IPv6, local zone to Public Zone (stateful)
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5q, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5q, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB_S;
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * IPv6, local zone to Public Zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5t, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5t, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PUB_TO_LOCAL;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * IPv6, local zone to Public Zone (stateful)
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5u, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5u, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_PUB_S;
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;
	ctx.flags |= DPT_ZP_PUB_TO_LOCAL;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;

/*
 * IPv6, local zone to non-zone
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden5x, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden5x, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_5(&ctx);

} DP_END_TEST;


/*
 * IPv6, net to local
 */
static void _dp_test_npf_golden_6(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func);
#define dp_test_npf_golden_6(ctx) \
	_dp_test_npf_golden_6(ctx, __FILE__, __func__)

static void _dp_test_npf_golden_6(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::101:101/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:101:2::202:202/96");

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::101:10b",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");

	dp_test_netlink_add_neigh("dp1T1", "2001:101:2::202:20b",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	npf_golden_in_fw(TEST_FW_ADD, ctx);
	npf_golden_zone(TEST_FW_ADD, ctx);


	/*
	 * UDP packet.  Net to local
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:2::202:20b",
		.l2_src     = "aa:bb:cc:dd:2:11",
		.l3_dst     = "2001:101:2::202:202",
		.l2_dst     = "0:0:a4:0:0:65",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD,
				.dport = 0xBEEF,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};

	if ((ctx->flags & DPT_IN_FW_BLK) != 0)
		pre_pkt.l4.udp.dport = 48878;
	else if ((ctx->flags & DPT_IN_FW_UNM) != 0)
		pre_pkt.l4.udp.dport = 48877;

	if ((ctx->flags & DPT_OUT_FW_BLK) != 0)
		pre_pkt.l4.udp.sport = 57004;
	else if ((ctx->flags & DPT_OUT_FW_UNM) != 0)
		pre_pkt.l4.udp.sport = 57003;

	struct dp_test_pkt_desc_t post_pkt;
	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

repeat:
	post_pkt = pre_pkt;
	pre_desc = &pre_pkt;
	post_desc = &post_pkt;

	pre_pak  = dp_test_v6_pkt_from_desc(pre_desc);
	post_pak = dp_test_v6_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_fwd);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards", func);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre_desc->tx_intf, test_exp);

	if ((ctx->flags & DPT_IN_FW) != 0)
		npf_golden_in_fw(TEST_FW_VERIFY, ctx);

	if ((ctx->flags & DPT_OUT_FW) != 0)
		npf_golden_out_fw(TEST_FW_VERIFY, ctx);

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if ((ctx->flags & DPT_IN_FW_S) != 0) {
		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->rx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	}

	if ((ctx->flags & DPT_IN_FW_S) != 0 ||
	    (ctx->flags & DPT_IN_DNAT) != 0) {

		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->rx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	} else if ((ctx->flags & DPT_OUT_FW_S) != 0 ||
		 (ctx->flags & DPT_OUT_SNAT) != 0 ||
		 (ctx->flags & DPT_ZONE_PRIV_S) != 0) {
		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->tx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	}

	/*
	 * UDP packet.  Local to Net
	 */
	struct dp_test_pkt_desc_t pre_pkt2 = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:2::202:202",
		.l2_src     = "0:0:a4:0:0:65",
		.l3_dst     = "2001:101:2::202:20b",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xBEEF,
				.dport = 0xDEAD,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp1T0"
	};
	struct dp_test_pkt_desc_t post_pkt2 = pre_pkt2;
	pre_desc = &pre_pkt2;
	post_desc = &post_pkt2;

	pre_pak  = dp_test_from_spath_pkt_from_desc(pre_desc);
	post_pak = dp_test_from_spath_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_back);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Reverse", func);

	/* Run the test */
	dp_test_send_slowpath_pkt(pre_pak, test_exp);

	if (ctx->count > 1) {
		ctx->count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_in_fw(TEST_FW_REMOVE, ctx);
	npf_golden_zone(TEST_FW_REMOVE, ctx);

	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::101:10b",
				  "aa:bb:cc:dd:1:11");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	dp_test_netlink_del_neigh("dp1T1", "2001:101:2::202:20b",
				  "aa:bb:cc:dd:2:11");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::101:101/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:101:2::202:202/96");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
}


/*
 * IPv6, Net to local
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden6, NULL, NULL);
DP_START_TEST(npf_golden6, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};

	dp_test_npf_golden_6(&ctx);
} DP_END_TEST;

/*
 * IPv6, Net to local, In FW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden6a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden6a, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;

	dp_test_npf_golden_6(&ctx);
} DP_END_TEST;

/*
 * IPv6, Net to local, In sFW
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden6b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden6b, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 1,
		.flags = 0, .count = 1,
		.fw_in = 1, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_LOCAL,
		.exp_back = DP_TEST_FWD_FORWARDED,
	};
	ctx.flags |= DPT_IN_FW;
	ctx.flags |= DPT_IN_FW_S;

	dp_test_npf_golden_6(&ctx);
} DP_END_TEST;

/*
 * IPv4, Local (kernel forwarded) to Net
 */
static void _dp_test_npf_golden_7(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func);
#define dp_test_npf_golden_7(ctx) \
	_dp_test_npf_golden_7(ctx, __FILE__, __func__)

static void _dp_test_npf_golden_7(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	npf_golden_out_fw(TEST_FW_ADD, ctx);
	npf_golden_zone(TEST_FW_ADD, ctx);


	/*
	 * UDP packet.  Src address in *not* a router address
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD,
				.dport = 0xBEEF,
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T1"
	};

	if ((ctx->flags & DPT_OUT_FW_UNM) != 0)
		pre_pkt.l4.udp.sport = 57003;
	else if ((ctx->flags & DPT_OUT_FW_BLK) != 0)
		pre_pkt.l4.udp.sport = 57004;

	struct dp_test_pkt_desc_t post_pkt;
	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

repeat:
	post_pkt = pre_pkt;
	pre_desc = &pre_pkt;
	post_desc = &post_pkt;

	pre_pak  = dp_test_from_spath_v4_pkt_from_desc(pre_desc);
	post_pak = dp_test_from_spath_v4_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_fwd);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards", func);

	/* Run the test */
	dp_test_send_slowpath_pkt(pre_pak, test_exp);

	if ((ctx->flags & DPT_OUT_FW) != 0)
		npf_golden_out_fw(TEST_FW_VERIFY, ctx);

	uint sess_out_exp = 0;

	if (((ctx->flags & DPT_OUT_FW_S) != 0 &&
	     (ctx->flags & (DPT_OUT_FW_BLK | DPT_OUT_FW_UNM)) == 0) ||
	    (ctx->flags & DPT_OUT_SNAT) != 0) {
		sess_out_exp++;
	}

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (sess_out_exp) {
		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->tx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	}

	if (ctx->count > 1) {
		ctx->count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_out_fw(TEST_FW_REMOVE, ctx);
	npf_golden_zone(TEST_FW_REMOVE, ctx);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
}


/*
 * IPv4, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden7, NULL, NULL);
DP_START_TEST(npf_golden7, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
	};


	dp_test_npf_golden_7(&ctx);

} DP_END_TEST;

/*
 * IPv4, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden7a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden7a, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
	};

	ctx.flags |= DPT_OUT_FW;

	dp_test_npf_golden_7(&ctx);

} DP_END_TEST;

/*
 * IPv4, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden7b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden7b, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_DROPPED,
	};

	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_BLK;

	dp_test_npf_golden_7(&ctx);

} DP_END_TEST;

/*
 * IPv4, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden7c, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden7c, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_DROPPED,
	};

	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_UNM;

	dp_test_npf_golden_7(&ctx);

} DP_END_TEST;

/*
 * IPv4, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden7d, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden7d, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
	};

	ctx.flags |= DPT_ZONE_PUB;

	dp_test_npf_golden_7(&ctx);

} DP_END_TEST;

/*
 * IPv4, Local (kernel forwarded) to Net.  This qualifies as non-zone to zone,
 * so id dropped.
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden7e, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden7e, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
	};

	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_7(&ctx);

} DP_END_TEST;


/*
 * IPv6, Local (kernel forwarded) to Net
 */
static void _dp_test_npf_golden_8(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func);
#define dp_test_npf_golden_8(ctx) \
	_dp_test_npf_golden_8(ctx, __FILE__, __func__)

static void _dp_test_npf_golden_8(struct dp_test_golden_ctx *ctx,
				  const char *file, const char *func)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::101:101/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:101:2::202:202/96");

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::101:10b",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");

	dp_test_netlink_add_neigh("dp1T1", "2001:101:2::202:20b",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	npf_golden_out_fw(TEST_FW_ADD, ctx);
	npf_golden_zone(TEST_FW_ADD, ctx);


	/*
	 * UDP packet.  Local to net
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1::101:10b",
		.l2_src     = "aa:bb:cc:dd:1:11",
		.l3_dst     = "2001:101:2::202:20b",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD,
				.dport = 0xBEEF,
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T1"
	};

	if ((ctx->flags & DPT_OUT_FW_UNM) != 0)
		pre_pkt.l4.udp.sport = 57003;
	else if ((ctx->flags & DPT_OUT_FW_BLK) != 0)
		pre_pkt.l4.udp.sport = 57004;

	struct dp_test_pkt_desc_t post_pkt;
	struct dp_test_pkt_desc_t *pre_desc;
	struct dp_test_pkt_desc_t *post_desc;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

repeat:
	post_pkt = pre_pkt;
	pre_desc = &pre_pkt;
	post_desc = &post_pkt;

	pre_pak  = dp_test_from_spath_pkt_from_desc(pre_desc);
	post_pak = dp_test_from_spath_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx->exp_fwd);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards", func);

	/* Run the test */
	dp_test_send_slowpath_pkt(pre_pak, test_exp);

	if ((ctx->flags & DPT_OUT_FW) != 0)
		npf_golden_out_fw(TEST_FW_VERIFY, ctx);

	uint sess_out_exp = 0;

	if (((ctx->flags & DPT_OUT_FW_S) != 0 &&
	     (ctx->flags & (DPT_OUT_FW_BLK | DPT_OUT_FW_UNM)) == 0) ||
	    (ctx->flags & DPT_OUT_SNAT) != 0) {
		sess_out_exp++;
	}

	_dp_test_npf_session_count_verify(ctx->exp_session, false,
					  file, func, __LINE__);

	if (sess_out_exp) {
		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->tx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	}

	if (ctx->count > 1) {
		ctx->count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_out_fw(TEST_FW_REMOVE, ctx);
	npf_golden_zone(TEST_FW_REMOVE, ctx);

	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::101:10b",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");

	dp_test_netlink_del_neigh("dp1T1", "2001:101:2::202:20b",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::101:101/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:101:2::202:202/96");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
}

/*
 * IPv6, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden8, NULL, NULL);
DP_START_TEST(npf_golden8, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
	};


	dp_test_npf_golden_8(&ctx);

} DP_END_TEST;

/*
 * IPv6, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden8a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden8a, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
	};

	ctx.flags |= DPT_OUT_FW;

	dp_test_npf_golden_8(&ctx);

} DP_END_TEST;

/*
 * IPv6, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden8b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden8b, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_DROPPED,
	};

	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_BLK;

	dp_test_npf_golden_8(&ctx);

} DP_END_TEST;

/*
 * IPv6, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden8c, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden8c, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 1,
		.exp_fwd = DP_TEST_FWD_DROPPED,
	};

	ctx.flags |= DPT_OUT_FW;
	ctx.flags |= DPT_OUT_FW_UNM;

	dp_test_npf_golden_8(&ctx);

} DP_END_TEST;

/*
 * IPv6, Local (kernel forwarded) to Net
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden8d, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden8d, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
	};

	ctx.flags |= DPT_ZONE_PUB;

	dp_test_npf_golden_8(&ctx);

} DP_END_TEST;

/*
 * IPv6, Local (kernel forwarded) to Net.  Non-zone to zone.
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden8e, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_golden8e, test)
{
	struct dp_test_golden_ctx ctx = {
		.exp_session = 0, .flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_DROPPED,
	};

	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZONE_LOCAL;

	dp_test_npf_golden_8(&ctx);

} DP_END_TEST;

/*
 * This tests that an SNATd packet from the router creates a NAT pinhole for
 * return traffic that would otherwise be blocked by the local zone firewall.
 */
DP_DECL_TEST_CASE(npf_golden, npf_golden9, NULL, NULL);
DP_START_TEST(npf_golden9, test)
{
	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");

	struct dp_test_golden_ctx ctx = {
		.exp_session = 0,
		.flags = 0, .count = 1,
		.fw_in = 0, .fw_out = 0,
		.exp_fwd = DP_TEST_FWD_FORWARDED,
		.exp_back = DP_TEST_FWD_LOCAL,
	};

	/*
	 * Change source addr from 2.2.2.2 to 2.2.2.3 for traffic out dp1T1
	 */
	ctx.flags |= DPT_OUT_SNAT_LOCAL;
	npf_golden_out_snat_local(TEST_FW_ADD, &ctx);

	/*
	 * Zone fw.
	 * Local to PUBLIC - PASS for src-port 57005, BLOCK for 57004.
	 * PUBLIC to local - PASS for src-port 48879, BLOCK for 48878.
	 */
	ctx.flags |= DPT_ZONE_PUB;
	ctx.flags |= DPT_ZP_PUB_TO_LOCAL;

	npf_golden_zone_public(TEST_FW_ADD, &ctx);
	npf_golden_zone_local(TEST_FW_ADD, &ctx);
	npf_golden_zone_policy_pub_to_local(TEST_FW_ADD, &ctx);
	npf_golden_zone_policy_local_to_pub(TEST_FW_ADD, &ctx);


	/*
	 * UDP packet.  Local to net
	 */
	struct dp_test_pkt_desc_t pre_pkt = {
		.text       = "Pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "2.2.2.2",
		.l2_src     = "0:0:a4:0:0:65",
		.l3_dst     = "2.2.2.11",
		.l2_dst     = "aa:bb:cc:dd:2:11",
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 0xDEAD, /* 57005 */
				.dport = 0xBEEF, /* 48879 */
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T1"
	};

	pre_pkt.l4.udp.dport = 48878;

	struct dp_test_pkt_desc_t post_pkt = pre_pkt;
	struct dp_test_pkt_desc_t *pre_desc = &pre_pkt;
	struct dp_test_pkt_desc_t *post_desc = &post_pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *pre_pak, *post_pak;

	if ((ctx.flags & DPT_OUT_SNAT_LOCAL) != 0)
		/* SNAT  2.2.2.2 to 2.2.2.3*/
		post_desc->l3_src = "2.2.2.3";

repeat:
	pre_pak  = dp_test_from_spath_v4_pkt_from_desc(pre_desc);
	post_pak = dp_test_from_spath_v4_pkt_from_desc(post_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx.exp_fwd);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Forwards", __func__);

	/* Run the test */
	dp_test_send_slowpath_pkt(pre_pak, test_exp);

	uint sess_out_exp = 1;

	dp_test_npf_session_count_verify(sess_out_exp);

	if (sess_out_exp) {
		dp_test_npf_session_verify_desc(NULL, pre_desc,
						pre_desc->tx_intf,
						SE_ACTIVE,
						SE_FLAGS_AE, true);
	}

	pre_pak  = dp_test_reverse_v4_pkt_from_desc(post_desc);
	post_pak = dp_test_reverse_v4_pkt_from_desc(pre_desc);

	test_exp = dp_test_exp_create(post_pak);
	rte_pktmbuf_free(post_pak);

	dp_test_exp_set_fwd_status(test_exp, ctx.exp_back);
	dp_test_exp_set_oif_name(test_exp, pre_desc->tx_intf);

	spush(test_exp->description, sizeof(test_exp->description),
	      "\nTest: \"%s\", Reverse", __func__);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre_desc->tx_intf, test_exp);

	dp_test_npf_session_count_verify(sess_out_exp);

	if (ctx.count > 1) {
		ctx.count--;
		goto repeat;
	}

	/* Cleanup */

	npf_golden_zone_policy_pub_to_local(TEST_FW_REMOVE, &ctx);
	npf_golden_zone_policy_local_to_pub(TEST_FW_REMOVE, &ctx);
	npf_golden_zone_public(TEST_FW_REMOVE, &ctx);
	npf_golden_zone_local(TEST_FW_REMOVE, &ctx);
	npf_golden_out_snat_local(TEST_FW_REMOVE, &ctx);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
} DP_END_TEST;
