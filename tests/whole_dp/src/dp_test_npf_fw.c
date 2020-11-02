/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf firewall tests
 */

#include <libmnl/libmnl.h>
#include <netinet/icmp6.h>
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
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"

static bool npf_fw_debug;

/*
 * Firewall expectation after a packet has been injected
 *
 * session - set true if we expect the pkt to create a session
 * pkts    - expected pkt count.  Will be 0 or 1 as we clear counts
 *           between pkts
 * rule    - rule number string.  The rule to look for the expected pkt count
 *           on e.g. "10".  May be NULL, is which case pkt count for all rules
 *           is summed.
 */
struct dp_test_npf_fw_exp_t {
	bool        session;
	int         pkts;
	const char *rule;
};

#define NULL_FW_EXP {false, 0, NULL}

/*
 * The following relates to the test array, fw_fwd_tests[]
 */

/* Number of firewalls */
#define FW_TEST_NFWS 4

/* Number of packets */
#define FW_TEST_NPKTS 4

/*
 * Expectation for each firewall after a packet
 *
 * fwd_status - DP_TEST_FWD_FORWARDED or DP_TEST_FWD_DROPPED
 */
struct dp_test_npf_fw_pkt_exp_t {
	enum dp_test_fwd_result_e   fwd_status;
	struct dp_test_npf_fw_exp_t fw_exp[FW_TEST_NFWS];
};

/* Expectation when there is no packet */
#define PKT_EXP_NULL {0, {NULL_FW_EXP, NULL_FW_EXP,		\
				NULL_FW_EXP, NULL_FW_EXP } }

/* Expectation when there is a packet, but no firewalls */
#define PKT_EXP_EMPTY {DP_TEST_FWD_FORWARDED, {NULL_FW_EXP, NULL_FW_EXP, \
				NULL_FW_EXP, NULL_FW_EXP } }

struct dp_test_npf_fw_test_t {
	const char                     *desc;
	struct dp_test_npf_ruleset_t       fw[FW_TEST_NFWS];
	struct dp_test_npf_fw_pkt_exp_t pkt_exp[FW_TEST_NPKTS];
};

struct dp_test_npf_fw_pkt_t {
	struct dp_test_pkt_desc_t *desc;
	struct rte_mbuf           *mbuf;
};

/*
 * Firewall forwarding test matrix.  Suitable for IPv4 and IPv6 since rule
 * lists are AF agnostic.
 *
 * There are up to 4 firewalls on input and output of both interfaces.  The
 * per array element description describes if a firewall is specified or not.
 * It is of the format:
 *
 *     "1. FW1_IN/FW1_OUT, 2: FW2_IN/FW2_OUT"
 *
 * e.g.  "1: Empty/Empty, 2: Empty/Pass".  Means there is one firewall on the
 * output of interface 2, and its a stateless firewall with a rule to pass the
 * default packet.
 *
 * Empty    - No firewall
 * Pass     - Stateless firewall with 2 rules, a pass rule for pkts that match,
 *            and a default block rule.
 * Block    - Stateless firewall with 2 rules, a block rule for pkts that match,
 *            and a default pass rule.
 * Stateful - Stateful firewall with 2 rules, a pass rule for pkts that match,
 *            and a default block rule.
 *
 * Up to four packets may be used for each set of tests.  The following
 * indicates the packet sequence, and their direction.
 *
 * Packet A is received on interface 1 and, dependent on firewall, is
 * forwarded to interface 2.
 *
 * Packet B is the reverse of packet A.  This is mostly useful in testing
 * stateful firewalls and npf sessions.  i.e. Packet A creates the session,
 * and packet B matches the session created by packet A.
 *
 * Packet C is not used in these tests, but will be by future tests.
 *
 * Packet D is a "new flow" in the same direction as packet B.  This is useful
 * for testing packets that *do not* match the session created by packet A.
 *
 *  Packet A           -->          -->
 *                     <--          <--        Packet B
 *  Packet C           -->          -->
 *                     <--          <--        Packet D
 *
 *                  1.1.1.1 +-----+ 2.2.2.2
 *              2001:1:1::1 |     | 2002:2:2::2
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 *
 *                 FW1_IN ->     -> FW2_OUT
 *                FW2_OUT <-     <- FW2_IN
 *
 * In all cases, the nest-hop is simply the destination from the packet
 * template.
 *
 * The initializers following the description are two main blocks.  The first
 * is the initializers for each of the four firewalls.
 *
 * The second is the per-packet expectation for each packet.  With 4 firewalls
 * and 4 packets, up to 16 expectations may need specified.  The expectation
 * allows the test to check: 1. That the pkt was forwarded or dropped, 2. The
 * correct firewall rule packet count was incremented or not, and 3. verifies
 * a session, if expected
 */

static struct dp_test_npf_fw_test_t fw_fwd_tests[] = {
	/*
	 * 1: Empty/Empty, 2: Empty/Empty
	 *
	 *                   Intf 1        Intf 2
	 * A New  flow       -        ->   -
	 * B Rev  flow       -        <-   -
	 * C -
	 * D New  flow       -        <-   -
	 *
	 * Prep test with *no* firewalls
	 */
	{"1: Empty/Empty, 2: Empty/Empty",
	 {NULL_FW, NULL_FW, NULL_FW, NULL_FW },
	 {PKT_EXP_EMPTY,
	  PKT_EXP_EMPTY,
	  PKT_EXP_NULL,
	  PKT_EXP_EMPTY} },
	/*
	 * 1: Pass/Empty, 2: Empty/Empty
	 *
	 *                   Intf 1        Intf 2
	 * A New  flow       Pass     ->   -
	 * B Rev  flow       -        <-   -
	 * C -
	 * D New  flow       -        <-   -
	 */
	{"1: Pass/Empty, 2: Empty/Empty",
	 {{"fw-in", "FW1_IN", 1, NULL, FWD, "in",  rule_10_pass_udp},
	  NULL_FW, NULL_FW, NULL_FW },
	 {{DP_TEST_FWD_FORWARDED,			/* pkt A */
	   {{false, 1, "10"}, NULL_FW_EXP,		/*  FW1_IN, FW2_OUT */
	    NULL_FW_EXP, NULL_FW_EXP } },		/*  FW2_IN, FW1_OUT */
	  {DP_TEST_FWD_FORWARDED,			/* pkt B */
	   {{false, 0, "10"}, NULL_FW_EXP,
	    NULL_FW_EXP, NULL_FW_EXP } },
	  PKT_EXP_NULL,
	  {DP_TEST_FWD_FORWARDED,			/* pkt D */
	   {{false, 0, "10"}, NULL_FW_EXP,
	    NULL_FW_EXP, NULL_FW_EXP } } } },
	/*
	 * 1: Empty/Empty, 2: Empty/Pass
	 *
	 *                   Intf 1        Intf 2
	 * A New  flow       -        ->   Pass
	 * B Rev  flow       -        <-   -
	 * C -
	 * D New  flow       -        <-   -
	 */
	{"1: Empty/Empty, 2: Empty/Pass",
	 {NULL_FW,
	  {"fw-out", "FW2_OUT", 1, NULL, FWD, "out", rule_10_pass_udp},
	  NULL_FW, NULL_FW },
	 {{DP_TEST_FWD_FORWARDED,			/* pkt  */
	   {NULL_FW_EXP, {false, 1, "10"},
	    NULL_FW_EXP, NULL_FW_EXP } },
	  PKT_EXP_EMPTY,
	  {DP_TEST_FWD_FORWARDED,			/* pkt  */
	   {NULL_FW_EXP, {false, 0, "10"},
	    NULL_FW_EXP, NULL_FW_EXP } },
	  {DP_TEST_FWD_FORWARDED,			/* pkt  */
	   {NULL_FW_EXP, {false, 0, "10"},
	    NULL_FW_EXP, NULL_FW_EXP } } } },
	/*
	 * 1: Pass/Pass, 2: Pass/Pass
	 *
	 *                   Intf 1        Intf 2
	 * A New  flow       Pass     ->   Pass
	 * B Rev  flow       Pass     <-   Pass
	 * C -
	 * D New  flow       Pass     <-   Pass
	 */
	{"1: Pass/Pass, 2: Pass/Pass",
	 {{"fw-in",  "FW1_IN",  1, NULL, FWD, "in",  rule_10_pass_udp},
	  {"fw-out", "FW2_OUT", 1, NULL, FWD, "out", rule_10_pass_udp},
	  {"fw-in",  "FW2_IN",  1, NULL, REV, "in",  rule_10_pass_udp},
	  {"fw-out", "FW1_OUT", 1, NULL, REV, "out", rule_10_pass_udp} },
	 {{DP_TEST_FWD_FORWARDED,			/* pkt A */
	   {{false, 1, "10"}, {false, 1, "10"},		/*  FW1_IN, FW2_OUT */
	    {false, 0, "10"}, {false, 0, "10"} } },	/*  FW2_IN, FW1_OUT */
	  {DP_TEST_FWD_FORWARDED,			/* pkt B */
	   {{false, 0, "10"}, {false, 0, "10"},
	    {false, 1, "10"}, {false, 1, "10"} } },
	  PKT_EXP_NULL,					/* pkt C */
	  {DP_TEST_FWD_FORWARDED,			/* pkt D */
	   {{false, 0, "10"}, {false, 0, "10"},
	    {false, 1, "10"}, {false, 1, "10"} } } } },
	/*
	 * 1: Empty/Empty, 2: Empty/Stateful
	 *
	 *                   Intf 1        Intf 2
	 * A New  flow       -        ->   Sess
	 * B Rev  flow       -        <-   Skip
	 * C -
	 * D New  flow       -        <-   Drop
	 */
	{"1: Empty/Empty, 2: Empty/Stateful",
	 {NULL_FW,
	  {"fw-out", "FW2_OUT", 1, NULL, FWD, "out", rule_10_pass_udp_sf},
	  NULL_FW,
	  NULL_FW },
	 { {DP_TEST_FWD_FORWARDED,			/* pkt A */
	    {NULL_FW_EXP, {true, 1, "10"},		/*  FW1_IN, FW2_OUT */
	     NULL_FW_EXP, NULL_FW_EXP } },		/*  FW2_IN, FW1_OUT */
	   {DP_TEST_FWD_FORWARDED,			/* pkt B */
	    {NULL_FW_EXP, {false, 0, "10"},
	     NULL_FW_EXP, NULL_FW_EXP } },
	   PKT_EXP_NULL,				/* pkt C */
	   {DP_TEST_FWD_DROPPED,			/* pkt D */
	    {NULL_FW_EXP, {false, 0, "10"},
	     NULL_FW_EXP, NULL_FW_EXP } } } },
	/*
	 * 1: Empty/Empty, 2: Block/Stateful
	 *
	 *                   Intf 1        Intf 2
	 * A New  flow       -        ->   Sess
	 * B Rev  flow       -        <-   Skip
	 * C -
	 * D New  flow       -        <-   Drop
	 */
	{"1: Empty/Empty, 2: Block/Stateful",
	 {NULL_FW,
	  {"fw-out", "FW2_OUT", 1, NULL, FWD, "out", rule_10_pass_udp_sf},
	  {"fw-in",  "FW2_IN",  1, NULL, REV, "in",  rule_def_block},
	  NULL_FW },
	 { {DP_TEST_FWD_FORWARDED,			/* pkt A */
	    {NULL_FW_EXP, {true, 1, "10"},		/*  FW1_IN, FW2_OUT */
	     {false, 0, "10000"}, NULL_FW_EXP } },	/*  FW2_IN, FW1_OUT */
	   {DP_TEST_FWD_FORWARDED,			/* pkt B */
	    {NULL_FW_EXP, {false, 0, "10"},
	     {false, 0, "10000"}, NULL_FW_EXP } },
	   PKT_EXP_NULL,				/* pkt C */
	   {DP_TEST_FWD_DROPPED,			/* pkt D */
	    {NULL_FW_EXP, {false, 0, "10"},
	     {false, 1, "10000"}, NULL_FW_EXP } } } },
	/*
	 * 1: Pass/Empty, 2: Block/Stateful
	 *
	 *                   Intf 1        Intf 2
	 * A New  flow       Pass     ->   Sess
	 * B Rev  flow       -        <-   Skip
	 * C -
	 * D New  flow       -        <-   Drop
	 */
	{"1: Pass/Empty, 2: Block/Stateful",
	 {{"fw-in",  "FW1_IN",  1, NULL, FWD, "in",  rule_10_pass_udp},
	  {"fw-out", "FW2_OUT", 1, NULL, FWD, "out", rule_10_pass_udp_sf},
	  {"fw-in",  "FW2_IN",  1, NULL, REV, "in",  rule_def_block},
	  NULL_FW },
	 { {DP_TEST_FWD_FORWARDED,			/* pkt A */
	    {{false, 1, "10"}, {true, 1, "10"},		/*  FW1_IN, FW2_OUT */
	     {false, 0, "10000"}, NULL_FW_EXP } },	/*  FW2_IN, FW1_OUT */
	   {DP_TEST_FWD_FORWARDED,			/* pkt B */
	    {{false, 0, "10"}, {false, 0, "10"},
	     {false, 0, "10000"}, NULL_FW_EXP } },
	   PKT_EXP_NULL,				/* pkt C */
	   {DP_TEST_FWD_DROPPED,			/* pkt D */
	    {{false, 0, "10"}, {false, 0, "10"},
	     {false, 1, "10000"}, NULL_FW_EXP } } } }
};

/*
 * Verify a firewalls expectations after packet has been injected
 *
 * pkt  - Template for packet that has just been injected
 * fw   - The firewall template
 * exp  - Expectation, i.e. Lookup the packet count on rule exp->rule and
 *        verify it matches exp->pkts.  If exp->session is true, then verify
 *        that the packet created a session.
 * session_count - Sessions are not cleared between packets, so we need to
 *        pass in the current session count, and increment if necessary
 */
static void
dp_test_npf_fw_test_pkt_verify(char *desc,
			       struct dp_test_pkt_desc_t *pkt,
			       struct dp_test_npf_ruleset_t *fw,
			       struct dp_test_npf_fw_exp_t *exp,
			       uint *session_count)
{
	if (!fw->enable || !exp->rule)
		return;

	if (npf_fw_debug)
		printf("    Verify fw %-8s rule %5s pkts %d session %s\n",
		       fw->name, exp->rule, exp->pkts,
		       exp->session ? "Yes" : "No");

	dp_test_npf_verify_rule_pkt_count(desc, fw, exp->rule, exp->pkts);

	if (exp->session) {
		*session_count += 1;
		dp_test_npf_session_verify_desc(desc, pkt, fw->attach_point,
						SE_ACTIVE, SE_FLAGS_AE, true);
	}
}

/*
 * Inject test packet and verify expectations.
 */
static void
dp_test_npf_fw_test_pkt(struct dp_test_npf_fw_test_t *test,
			struct dp_test_npf_fw_pkt_t *fw_pkt,
			struct dp_test_npf_fw_pkt_exp_t *pkt_exp,
			uint *session_count)
{
	struct dp_test_expected *test_exp;
	struct dp_test_pkt_desc_t *pkt = fw_pkt->desc;
	char desc[100];
	struct rte_mbuf *test_pak;
	uint i;

	snprintf(desc, sizeof(desc), "Test: [%s] Pkt: [%s]",
		 test->desc, pkt->text);

	if (npf_fw_debug)
		printf("  %s\n", desc);

	test_pak = dp_test_cp_pak(fw_pkt->mbuf);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	snprintf(test_exp->description, sizeof(test_exp->description),
		 "%s", desc);

	/* Set forwarded/dropped/local expectation */
	dp_test_exp_set_fwd_status(test_exp, pkt_exp->fwd_status);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify each firewall per-packet expectation */
	for (i = 0; i < ARRAY_SIZE(test->fw); i++)
		dp_test_npf_fw_test_pkt_verify(desc, pkt, &test->fw[i],
					       &pkt_exp->fw_exp[i],
					       session_count);

	/* Clear firewall counters between packets */
	dp_test_npf_clear("fw-in fw-out");
}

/*
 * Run one test from the IPv4/IPv6 dp_test_npf_fw_test_t test array.
 */
static void
dp_test_npf_fw_test(struct dp_test_npf_fw_test_t *test,
		    struct dp_test_npf_fw_pkt_t *fw_pkts, uint npkts)
{
	uint i;
	uint session_count = 0;

	if (npf_fw_debug)
		printf("%s\n", test->desc);

	/* Add firewalls and assign to intf */
	for (i = 0; i < ARRAY_SIZE(test->fw); i++)
		dp_test_npf_fw_add(&test->fw[i], npf_fw_debug);

	/*
	 * Run test for each packet
	 */
	for (i = 0; i < npkts; i++) {
		if (fw_pkts[i].desc)
			dp_test_npf_fw_test_pkt(test, &fw_pkts[i],
						&test->pkt_exp[i],
						&session_count);
	}

	/* Only clear session table after all packets */
	dp_test_npf_clear_sessions();

	/* Delete firewalls */
	for (i = 0; i < ARRAY_SIZE(test->fw); i++)
		dp_test_npf_fw_del(&test->fw[i], npf_fw_debug);
}

DP_DECL_TEST_SUITE(npf_fw);

DP_DECL_TEST_CASE(npf_fw, fw_ipv4, NULL, NULL);

/*
 * IPv4 forwarding tests.
 *
 *  Tests packet handling in the dataplane, i.e. is packet forwarded or
 * dropped, is correct packet count incremented, is a session created etc.
 */
DP_START_TEST(fw_ipv4, fwd)
{
	uint i, j, nfwd = ARRAY_SIZE(fw_fwd_tests);
	struct dp_test_npf_fw_test_t *test;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.3",
				  "aa:bb:cc:dd:1:a3");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.3",
				  "aa:bb:cc:dd:2:b3");

	struct dp_test_pkt_desc_t v4_pktA = {
		.text       = "A fwd IPv4 n1->n1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 1000
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* reverse of A */
	struct dp_test_pkt_desc_t v4_pktB = {
		.text       = "B rev IPv4 n1->n1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "2.2.2.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "1.1.1.2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 1000,
				.dport = 41000
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v4_pktD = {
		.text       = "D rev IPv4 n2->n2",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "2.2.2.3",
		.l2_src     = "aa:bb:cc:dd:2:b3",
		.l3_dst     = "1.1.1.3",
		.l2_dst     = "aa:bb:cc:dd:1:a3",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 1001,
				.dport = 41001
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_npf_fw_pkt_t fw_pkts[FW_TEST_NPKTS] = {
		{&v4_pktA, NULL},
		{&v4_pktB, NULL},
		{NULL, NULL},
		{&v4_pktD, NULL}
	};

	/*
	 * Setup test packets, and store pointer in the the pkt template.
	 * dp_test_npf_fw_test will make a copy of this, and use the copy
	 * to inject into the dataplane.
	 */
	for (i = 0; i < ARRAY_SIZE(fw_pkts); i++) {
		if (!fw_pkts[i].desc)
			continue;
		fw_pkts[i].mbuf = dp_test_v4_pkt_from_desc(fw_pkts[i].desc);
	}

	/*
	 * For each test in the IPv4 test matrix ...
	 */
	for (i = 0; i < nfwd; i++) {
		test = &fw_fwd_tests[i];

		/*
		 * Firewall interfaces are address family specific, so we need
		 * to set the pointers to the dp_test_npf_intf_t structures in
		 * each firewall here.
		 */
		for (j = 0; j < ARRAY_SIZE(test->fw); j++) {
			if ((test->fw[j].fwd == FWD &&
			     !strcmp(test->fw[j].dir, "in")) ||
			    (test->fw[j].fwd == REV &&
			     !strcmp(test->fw[j].dir, "out")))
				test->fw[j].attach_point = "dp1T0";
			else
				test->fw[j].attach_point = "dp2T1";
		}

		dp_test_npf_fw_test(test, fw_pkts, ARRAY_SIZE(fw_pkts));
	}

	for (i = 0; i < ARRAY_SIZE(fw_pkts); i++) {
		if (!fw_pkts[i].mbuf)
			continue;
		rte_pktmbuf_free(fw_pkts[i].mbuf);
		fw_pkts[i].mbuf = NULL;
	}

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.3",
				  "aa:bb:cc:dd:1:a3");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.3",
				  "aa:bb:cc:dd:2:b3");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

} DP_END_TEST;


DP_DECL_TEST_CASE(npf_fw, fw_ipv6, NULL, NULL);

/*
 * IPv6 forwarding tests.
 *
 * Tests packet handling in the dataplane, i.e. is packet forwarded or
 * dropped, is correct packet count incremented, is a session created etc.
 */
DP_START_TEST(fw_ipv6, fwd)
{
	uint i, j, nfwd = ARRAY_SIZE(fw_fwd_tests);
	struct dp_test_npf_fw_test_t *test;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::3",
				  "aa:bb:cc:dd:1:a3");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::3",
				  "aa:bb:cc:dd:2:b3");

	struct dp_test_pkt_desc_t v6_pktA = {
		.text       = "A fwd IPv6 n1->n1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 1000,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* reverse of A */
	struct dp_test_pkt_desc_t v6_pktB = {
		.text       = "B rev IPv6 n1->n1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2002:2:2::1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:1:1::2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 1000,
				.dport = 41000,
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t v6_pktD = {
		.text       = "D fwd IPv6 n2->n2",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2002:2:2::3",
		.l2_src     = "aa:bb:cc:dd:2:b3",
		.l3_dst     = "2001:1:1::3",
		.l2_dst     = "aa:bb:cc:dd:1:a3",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 1001,
				.dport = 41001,
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_npf_fw_pkt_t fw_pkts[FW_TEST_NPKTS] = {
		{&v6_pktA, NULL},
		{&v6_pktB, NULL},
		{NULL, NULL},
		{&v6_pktD, NULL}
	};

	/*
	 * Setup test packets, and store pointer in the the pkt template.
	 * dp_test_npf_fw_test will make a copy of this, and use the copy
	 * to inject into the dataplane.
	 */
	for (i = 0; i < ARRAY_SIZE(fw_pkts); i++) {
		if (!fw_pkts[i].desc)
			continue;
		fw_pkts[i].mbuf = dp_test_v6_pkt_from_desc(fw_pkts[i].desc);
	}

	/*
	 * For each test in the IPv6 test matrix ...
	 */
	for (i = 0; i < nfwd; i++) {
		test = &fw_fwd_tests[i];

		/*
		 * Firewall interfaces are address family specific, so we need
		 * to set the pointers to the dp_test_npf_intf_t structures in
		 * each firewall here.
		 */
		for (j = 0; j < ARRAY_SIZE(test->fw); j++) {
			if ((test->fw[j].fwd == FWD &&
			     !strcmp(test->fw[j].dir, "in")) ||
			    (test->fw[j].fwd == REV &&
			     !strcmp(test->fw[j].dir, "out")))
				test->fw[j].attach_point = "dp1T0";
			else
				test->fw[j].attach_point = "dp2T1";
		}

		dp_test_npf_fw_test(test, fw_pkts, ARRAY_SIZE(fw_pkts));
	}

	for (i = 0; i < ARRAY_SIZE(fw_pkts); i++) {
		if (!fw_pkts[i].mbuf)
			continue;
		rte_pktmbuf_free(fw_pkts[i].mbuf);
		fw_pkts[i].mbuf = NULL;
	}

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::3",
				  "aa:bb:cc:dd:1:a3");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::3",
				  "aa:bb:cc:dd:2:b3");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

} DP_END_TEST;

/*
 * Test IPv4 protocol, address and port matching
 *
 * Use a single firewall group template, and vary the npf code from a table
 * for each test TCP packet.
 */

struct dp_test_npf_npf_t {
	/* DP_TEST_FWD_FORWARDED or DP_TEST_FWD_DROPPED */
	enum dp_test_fwd_result_e fwd_status;
	const char *npf;
};

DP_START_TEST(fw_ipv4, matching)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	uint i;

	struct dp_test_pkt_desc_t v4_pkt = {
		.text       = "IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 1000,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt;

	/*
	 * 6  - tcp
	 * 17 - udp
	 */
	struct dp_test_npf_npf_t npf_ipv4_addr[] = {
		{DP_TEST_FWD_FORWARDED, ""},
		{DP_TEST_FWD_FORWARDED, "proto-final=17"},
		{DP_TEST_FWD_FORWARDED, "src-addr=1.1.1.0/24"},
		{DP_TEST_FWD_FORWARDED, "src-addr=!2.1.1.0/24"},
		{DP_TEST_FWD_FORWARDED, "src-addr=1.1.1.2"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2.2.2.0/24"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2.2.2.1"},
		{DP_TEST_FWD_FORWARDED,
			"src-addr=1.1.1.0/24 dst-addr=2.2.2.0/24"},
		{DP_TEST_FWD_FORWARDED, "src-addr=1.1.1.2 dst-addr=2.2.2.1"},
		{DP_TEST_FWD_FORWARDED, "src-addr=!1.1.4.0/24"},
		{DP_TEST_FWD_FORWARDED, "src-addr=!1.1.4.2"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 src-addr=1.1.1.2 "
			"src-port=41000 dst-addr=2.2.2.1 dst-port=1000"},
		{DP_TEST_FWD_FORWARDED, "src-addr-group=ADDR_GRP0"},
		{DP_TEST_FWD_FORWARDED, "dst-addr-group=ADDR_GRP1"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 src-port=41000"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 dst-port=1000"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 src-port-group=PG1"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 dst-port-group=PG2"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 dst-port-group=PG3"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 dst-port-group=PG5"},
		{DP_TEST_FWD_DROPPED, "proto-final=6"},
		{DP_TEST_FWD_DROPPED, "src-addr=1.1.2.0/24"},
		{DP_TEST_FWD_DROPPED, "src-addr=!1.1.1.0/24"},
		{DP_TEST_FWD_DROPPED, "src-addr=1.1.1.3"},
		{DP_TEST_FWD_DROPPED, "dst-addr=2.2.1.0/24"},
		{DP_TEST_FWD_DROPPED, "dst-addr=2.2.2.3"},
		{DP_TEST_FWD_DROPPED,
			"src-addr=1.1.1.0/24 dst-addr=2.2.1.0/24"},
		{DP_TEST_FWD_DROPPED, "src-addr=1.1.1.3 dst-addr=2.2.2.1"},
		{DP_TEST_FWD_DROPPED, "proto-final=17 src-addr=1.1.1.2 "
			"src-port=41001 dst-addr=2.2.2.1 dst-port=1000"},
		{DP_TEST_FWD_DROPPED, "src-addr-group=ADDR_GRP2"},
		{DP_TEST_FWD_DROPPED, "dst-addr-group=ADDR_GRP3"},
		{DP_TEST_FWD_DROPPED, "proto-final=17 src-port=41001"},
		{DP_TEST_FWD_DROPPED, "proto-final=17 dst-port=1001"},
		{DP_TEST_FWD_DROPPED, "proto-final=17 dst-port-group=PG4"},
	};

	struct dp_test_npf_rule_t rules[] = {
		{"10", PASS, STATELESS, NULL},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name = "FW1_IN",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd = FWD,
		.dir = "in",
		.rules = rules
	};

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.3",
				  "aa:bb:cc:dd:1:a3");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.3",
				  "aa:bb:cc:dd:2:b3");

	/* Create address-groups */
	dp_test_npf_fw_addr_group_add("ADDR_GRP0");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", "1.1.1.0/24");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", "2.2.2.0/24");
	dp_test_npf_fw_addr_group_add("ADDR_GRP1");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "1.1.1.2");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "2.2.2.1");
	dp_test_npf_fw_addr_group_add("ADDR_GRP2");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP2", "1.1.2.0/24");
	dp_test_npf_fw_addr_group_add("ADDR_GRP3");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP3", "1.1.1.5");

	/* Create port groups */
	dp_test_npf_fw_port_group_add("PG1", "41000");
	dp_test_npf_fw_port_group_add("PG2", "1000");
	dp_test_npf_fw_port_group_add("PG3", "1000-1010");
	dp_test_npf_fw_port_group_add("PG4", "1001-1010");
	dp_test_npf_fw_port_group_add("PG5", "999-1010");

	/*
	 * Run the test for npf each rule
	 */
	for (i = 0; i < ARRAY_SIZE(npf_ipv4_addr); i++) {
		char desc[50];

		snprintf(desc, sizeof(desc), "%s", npf_ipv4_addr[i].npf);
		fw.rules[0].npf = npf_ipv4_addr[i].npf;
		dp_test_npf_fw_add(&fw, npf_fw_debug);

		test_pak = dp_test_v4_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);
		spush(test_exp->description, sizeof(test_exp->description),
		      "%s", desc);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_ipv4_addr[i].fwd_status);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify */
		dp_test_npf_verify_rule_pkt_count(desc, &fw, fw.rules[0].rule,
					   npf_ipv4_addr[i].fwd_status ==
					   DP_TEST_FWD_FORWARDED ? 1 : 0);

		dp_test_npf_fw_del(&fw, npf_fw_debug);
	}

	/* Delete address groups */
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", "1.1.1.0/24");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", "2.2.2.0/24");
	dp_test_npf_fw_addr_group_del("ADDR_GRP0");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP1", "1.1.1.2");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP1", "2.2.2.1");
	dp_test_npf_fw_addr_group_del("ADDR_GRP1");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP2", "1.1.2.0/24");
	dp_test_npf_fw_addr_group_del("ADDR_GRP2");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP3", "1.1.1.5");
	dp_test_npf_fw_addr_group_del("ADDR_GRP3");

	dp_test_npf_fw_port_group_del("PG1");
	dp_test_npf_fw_port_group_del("PG2");
	dp_test_npf_fw_port_group_del("PG3");
	dp_test_npf_fw_port_group_del("PG4");
	dp_test_npf_fw_port_group_del("PG5");

	/* Cleanup */
	dp_test_npf_clear_sessions();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.3",
				  "aa:bb:cc:dd:1:a3");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.3",
				  "aa:bb:cc:dd:2:b3");
} DP_END_TEST;

/*
 * Test IPv6 protocol, address and port matching
 *
 * Use a single firewall group template, and vary the npf code from a table
 * for each test UDP packet.
 */
DP_START_TEST(fw_ipv6, matching)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	uint i;

	struct dp_test_pkt_desc_t v6_pkt = {
		.text       = "IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 1000,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v6_pkt;

	/*
	 * 6  - tcp
	 * 17 - udp
	 */
	struct dp_test_npf_npf_t npf_ipv6_addr[] = {
		{DP_TEST_FWD_FORWARDED, ""},
		{DP_TEST_FWD_FORWARDED, "proto-final=17"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/64"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::2"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/126"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/125"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/124"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/123"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/122"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/121"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/120"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/99"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/88"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/81"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/65"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/63"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1:1::/49"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1::/47"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1::/45"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001:1::/33"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001::/31"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001::/28"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001::/17"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2001::/16"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2000::/15"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2000::/13"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2000::/9"},
		{DP_TEST_FWD_FORWARDED, "src-addr=2000::/4"},
		{DP_TEST_FWD_FORWARDED, "src-addr=0000::/1"},
		{DP_TEST_FWD_FORWARDED, "src-addr=0000::/0"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/64"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::1"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/127"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/119"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/113"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/112"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/105"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/95"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/75"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/61"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/50"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2:2::/47"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2::/46"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2::/43"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2::/35"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002:2::/31"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002::/30"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002::/25"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002::/18"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2002::/15"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2000::/14"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2000::/10"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2000::/7"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=2000::/3"},
		{DP_TEST_FWD_FORWARDED, "dst-addr=0000::/2"},
		{DP_TEST_FWD_FORWARDED,
		 "src-addr=2001:1:1::/64 dst-addr=2002:2:2::/64"},
		{DP_TEST_FWD_FORWARDED,
		 "src-addr=2001:1:1::2 dst-addr=2002:2:2::1"},
		{DP_TEST_FWD_FORWARDED, "src-addr=!2001:1:4::/64"},
		{DP_TEST_FWD_FORWARDED,
		 "proto-final=17 src-addr=2001:1:1::2 src-port=41000 "
		 "dst-addr=2002:2:2::1 dst-port=1000"},
		{DP_TEST_FWD_FORWARDED, "src-addr-group=ADDR_GRP0"},
		{DP_TEST_FWD_FORWARDED, "dst-addr-group=ADDR_GRP1"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 src-port=41000"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 dst-port=1000"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 src-port-group=PG1"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 dst-port-group=PG2"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 dst-port-group=PG3"},
		{DP_TEST_FWD_FORWARDED, "proto-final=17 dst-port-group=PG5"},
		{DP_TEST_FWD_FORWARDED, "src-addr=!2001:1:1::3"},
		{DP_TEST_FWD_DROPPED, "proto-final=6"},
		{DP_TEST_FWD_DROPPED, "src-addr=2001:1:2::/64"},
		{DP_TEST_FWD_DROPPED, "src-addr=2001:1:1::3"},
		{DP_TEST_FWD_DROPPED, "dst-addr=2002:2:1::/64"},
		{DP_TEST_FWD_DROPPED, "dst-addr=2002:2:2::3"},
		{DP_TEST_FWD_DROPPED,
		 "src-addr=2001:1:1::/64 dst-addr=2002:2:1::/64"},
		{DP_TEST_FWD_DROPPED,
		 "src-addr=2001:1:1::3 dst-addr=2002:2:2::1"},
		{DP_TEST_FWD_DROPPED,
		 "proto-final=17 src-addr=2001:1:1::2 src-port=41001 "
		 "dst-addr=2002:2:2::1 dst-port=1000"},
		{DP_TEST_FWD_DROPPED, "src-addr-group=ADDR_GRP2"},
		{DP_TEST_FWD_DROPPED, "dst-addr-group=ADDR_GRP3"},
		{DP_TEST_FWD_DROPPED, "proto-final=17 src-port=41001"},
		{DP_TEST_FWD_DROPPED, "proto-final=17 dst-port=1001"},
		{DP_TEST_FWD_DROPPED, "proto-final=17 dst-port-group=PG4"},
		{DP_TEST_FWD_DROPPED, "src-addr=!2001:1:1::2"},
	};

	struct dp_test_npf_rule_t rules[] = {
		{"10", PASS, STATELESS, NULL},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name = "FW1_IN", .enable = 1,
		.attach_point = "dp1T0", .fwd = FWD, .dir = "in",
		.rules = rules
	};

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::3",
				  "aa:bb:cc:dd:1:a3");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::3",
				  "aa:bb:cc:dd:2:b3");

	/* Create address-groups */
	dp_test_npf_fw_addr_group_add("ADDR_GRP0");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", "2001:1:1::/64");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP0", "2002:2:2::/64");
	dp_test_npf_fw_addr_group_add("ADDR_GRP1");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "2001:1:1::2");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP1", "2002:2:2::1");
	dp_test_npf_fw_addr_group_add("ADDR_GRP2");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP2", "2001:1:2::/64");
	dp_test_npf_fw_addr_group_add("ADDR_GRP3");
	dp_test_npf_fw_addr_group_addr_add("ADDR_GRP3", "2001:1:1::5");

	/* Create port groups */
	dp_test_npf_fw_port_group_add("PG1", "41000");
	dp_test_npf_fw_port_group_add("PG2", "1000");
	dp_test_npf_fw_port_group_add("PG3", "1000-1010");
	dp_test_npf_fw_port_group_add("PG4", "1001-1010");
	dp_test_npf_fw_port_group_add("PG5", "999-1010");

	/*
	 * Run the test for npf each rule
	 */
	for (i = 0; i < ARRAY_SIZE(npf_ipv6_addr); i++) {
		char desc[50];

		snprintf(desc, sizeof(desc), "%s", npf_ipv6_addr[i].npf);
		fw.rules[0].npf = npf_ipv6_addr[i].npf;
		dp_test_npf_fw_add(&fw, npf_fw_debug);

		test_pak = dp_test_v6_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);
		spush(test_exp->description, sizeof(test_exp->description),
		      "%s", desc);

		dp_test_exp_set_fwd_status(test_exp,
					   npf_ipv6_addr[i].fwd_status);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		/* Verify */
		dp_test_npf_verify_rule_pkt_count(desc, &fw, fw.rules[0].rule,
					   npf_ipv6_addr[i].fwd_status ==
					   DP_TEST_FWD_FORWARDED ? 1 : 0);

		dp_test_npf_fw_del(&fw, npf_fw_debug);
	}

	/* Delete address groups */
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", "2001:1:1::/64");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP0", "2002:2:2::/64");
	dp_test_npf_fw_addr_group_del("ADDR_GRP0");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP1", "2001:1:1::2");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP1", "2002:2:2::1");
	dp_test_npf_fw_addr_group_del("ADDR_GRP1");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP2", "2001:1:2::/64");
	dp_test_npf_fw_addr_group_del("ADDR_GRP2");
	dp_test_npf_fw_addr_group_addr_del("ADDR_GRP3", "2001:1:1::5");
	dp_test_npf_fw_addr_group_del("ADDR_GRP3");

	dp_test_npf_fw_port_group_del("PG1");
	dp_test_npf_fw_port_group_del("PG2");
	dp_test_npf_fw_port_group_del("PG3");
	dp_test_npf_fw_port_group_del("PG4");
	dp_test_npf_fw_port_group_del("PG5");

	/* Cleanup */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::3",
				  "aa:bb:cc:dd:1:a3");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::3",
				  "aa:bb:cc:dd:2:b3");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");
} DP_END_TEST;

/*
 * Stateful firewalls
 *
 *                  1.1.1.1 +-----+ 2.2.2.2
 *                          |     |
 *          ----------------| uut |----------------
 *                    dp1T0 |     | dp2T1
 *                    intf1 +-----+ intf2
 */
DP_START_TEST(fw_ipv4, stateful)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = ""
		},
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	/* Setup firewall */
	dp_test_npf_fw_add(&fw, false);

	/*
	 * 1. Forwards flow packet
	 */
	struct dp_test_pkt_desc_t v4_pktA = {
		.text       = "A fwd IPv4 n1->n1",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 1000,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pktA;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify the firewall rule matched the packet */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 1);

	/* Verify a session was created */
	dp_test_npf_session_verify_desc(NULL, pkt, fw.attach_point,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*
	 * 2. Reverse flow packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(pkt);
	test_exp = dp_test_reverse_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->tx_intf, test_exp);

	/*
	 * 3. Reverse flow packet; expired session -> pkt should now be
	 * dropped
	 */
	dp_test_npf_expire_sessions();

	test_pak = dp_test_reverse_v4_pkt_from_desc(pkt);
	test_exp = dp_test_reverse_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->tx_intf, test_exp);

	/*
	 * 4. Repeat forwards flow packet; A new session should be
	 * created. There will be two sessions now.  An expired one and an
	 * active one.
	 */
	pkt = &v4_pktA;

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/* Verify the firewall rule matched the packet */
	dp_test_npf_verify_rule_pkt_count(NULL, &fw, fw.rules[0].rule, 2);

	/* Verify we can find the new session */
	dp_test_npf_session_verify_desc(NULL, pkt, fw.attach_point,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*
	 * 5. Reverse flow packet; new session should mean pkt is forwarded
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(pkt);
	test_exp = dp_test_reverse_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->tx_intf, test_exp);


	/* Cleanup */
	dp_test_npf_clear_sessions();
	dp_test_npf_fw_del(&fw, false);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

} DP_END_TEST;

/*
 * Test with more than 64 rules in a group.  The grouper table uses bit map
 * chunks of 64 bits.
 */
DP_START_TEST(fw_ipv4, large_ruleset)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	struct dp_test_pkt_desc_t v4_pkt = {
		.text       = "IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 1000,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt;

	struct dp_test_npf_rule_t rules[] = {
		{"1",  PASS, STATELESS, "src-addr=1.1.1.1"},
		{"2",  PASS, STATELESS, "src-addr=1.1.1.2"},
		{"3",  PASS, STATELESS, "src-addr=1.1.1.3"},
		{"4",  PASS, STATELESS, "src-addr=1.1.1.4"},
		{"5",  PASS, STATELESS, "src-addr=1.1.1.5"},
		{"6",  PASS, STATELESS, "src-addr=1.1.1.6"},
		{"7",  PASS, STATELESS, "src-addr=1.1.1.7"},
		{"8",  PASS, STATELESS, "src-addr=1.1.1.8"},
		{"9",  PASS, STATELESS, "src-addr=1.1.1.9"},
		{"10", PASS, STATELESS, "src-addr=1.1.1.10"},
		{"11", PASS, STATELESS, "src-addr=1.1.1.11"},
		{"12", PASS, STATELESS, "src-addr=1.1.1.12"},
		{"13", PASS, STATELESS, "src-addr=1.1.1.13"},
		{"14", PASS, STATELESS, "src-addr=1.1.1.14"},
		{"15", PASS, STATELESS, "src-addr=1.1.1.15"},
		{"16", PASS, STATELESS, "src-addr=1.1.1.16"},
		{"17", PASS, STATELESS, "src-addr=1.1.1.17"},
		{"18", PASS, STATELESS, "src-addr=1.1.1.18"},
		{"19", PASS, STATELESS, "src-addr=1.1.1.19"},
		{"20", PASS, STATELESS, "src-addr=1.1.1.20"},
		{"21", PASS, STATELESS, "src-addr=1.1.1.21"},
		{"22", PASS, STATELESS, "src-addr=1.1.1.22"},
		{"23", PASS, STATELESS, "src-addr=1.1.1.23"},
		{"24", PASS, STATELESS, "src-addr=1.1.1.24"},
		{"25", PASS, STATELESS, "src-addr=1.1.1.25"},
		{"26", PASS, STATELESS, "src-addr=1.1.1.26"},
		{"27", PASS, STATELESS, "src-addr=1.1.1.27"},
		{"28", PASS, STATELESS, "src-addr=1.1.1.28"},
		{"29", PASS, STATELESS, "src-addr=1.1.1.29"},
		{"30", PASS, STATELESS, "src-addr=1.1.1.30"},
		{"31", PASS, STATELESS, "src-addr=1.1.1.31"},
		{"32", PASS, STATELESS, "src-addr=1.1.1.32"},
		{"33", PASS, STATELESS, "src-addr=1.1.1.33"},
		{"34", PASS, STATELESS, "src-addr=1.1.1.34"},
		{"35", PASS, STATELESS, "src-addr=1.1.1.35"},
		{"36", PASS, STATELESS, "src-addr=1.1.1.36"},
		{"37", PASS, STATELESS, "src-addr=1.1.1.37"},
		{"38", PASS, STATELESS, "src-addr=1.1.1.38"},
		{"39", PASS, STATELESS, "src-addr=1.1.1.39"},
		{"40", PASS, STATELESS, "src-addr=1.1.1.40"},
		{"41", PASS, STATELESS, "src-addr=1.1.1.41"},
		{"42", PASS, STATELESS, "src-addr=1.1.1.42"},
		{"43", PASS, STATELESS, "src-addr=1.1.1.43"},
		{"44", PASS, STATELESS, "src-addr=1.1.1.44"},
		{"45", PASS, STATELESS, "src-addr=1.1.1.45"},
		{"46", PASS, STATELESS, "src-addr=1.1.1.46"},
		{"47", PASS, STATELESS, "src-addr=1.1.1.47"},
		{"48", PASS, STATELESS, "src-addr=1.1.1.48"},
		{"49", PASS, STATELESS, "src-addr=1.1.1.49"},
		{"50", PASS, STATELESS, "src-addr=1.1.1.50"},
		{"51", PASS, STATELESS, "src-addr=1.1.1.51"},
		{"52", PASS, STATELESS, "src-addr=1.1.1.52"},
		{"53", PASS, STATELESS, "src-addr=1.1.1.53"},
		{"54", PASS, STATELESS, "src-addr=1.1.1.54"},
		{"55", PASS, STATELESS, "src-addr=1.1.1.55"},
		{"56", PASS, STATELESS, "src-addr=1.1.1.56"},
		{"57", PASS, STATELESS, "src-addr=1.1.1.57"},
		{"58", PASS, STATELESS, "src-addr=1.1.1.58"},
		{"59", PASS, STATELESS, "src-addr=1.1.1.59"},
		{"60", PASS, STATELESS, "src-addr=1.1.1.60"},
		{"61", PASS, STATELESS, "src-addr=1.1.1.61"},
		{"62", PASS, STATELESS, "src-addr=1.1.1.62"},
		{"63", PASS, STATELESS, "src-addr=1.1.1.63"},
		{"64", PASS, STATELESS, "src-addr=1.1.1.64"},
		{"65", PASS, STATELESS, "src-addr=1.1.1.65"},
		{"66", PASS, STATELESS, "src-addr=1.1.1.66"},
		{"67", PASS, STATELESS, "src-addr=1.1.1.67"},
		{"68", PASS, STATELESS, "src-addr=1.1.1.68"},
		{"69", PASS, STATELESS, "src-addr=1.1.1.69"},
		{"70", PASS, STATELESS, "src-addr=1.1.1.70"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name = "FW1_IN", .enable = 1,
		.attach_point = "dp1T0", .fwd = FWD, .dir = "in",
		.rules = rules
	};

	dp_test_npf_fw_add(&fw, npf_fw_debug);

	/*
	 * Setup interfaces and neighbours
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.250/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", "aa:bb:cc:dd:2:b1");

	pkt->l3_dst = "2.2.2.1";
	pkt->l2_dst = "aa:bb:cc:dd:2:b1";

	uint i;
	in_addr_t saddr = 0x01010100;

	for (i = 1; i <= 70; i++) {
		char addr[16];
		in_addr_t tmp;

		saddr++;
		tmp = htonl(saddr);

		inet_ntop(AF_INET, &tmp, addr, sizeof(addr));

		dp_test_netlink_add_neigh("dp1T0", addr,
					  "aa:bb:cc:dd:1:65");
		pkt->l3_src = addr;
		pkt->l2_src = "aa:bb:cc:dd:1:65";

		test_pak = dp_test_v4_pkt_from_desc(pkt);
		test_exp = dp_test_exp_from_desc(test_pak, pkt);

		spush(test_exp->description, sizeof(test_exp->description),
		      "Packet %u from %s", i, addr);

		/* Run the test */
		dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

		dp_test_netlink_del_neigh("dp1T0", addr,
					  "aa:bb:cc:dd:1:65");
	}

	/* Cleanup */
	dp_test_npf_fw_del(&fw, npf_fw_debug);
	dp_test_npf_clear_sessions();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.250/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", "aa:bb:cc:dd:2:b1");

} DP_END_TEST;


/*
 * Tests a port range that spans the one byte boundary.
 *
 * Use port range 255-256, and two firewall setups - 1. when we pass ports
 * that match the range, and 2. block ports that match the range.
 */
DP_START_TEST(fw_ipv4, port_range1)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	struct dp_test_pkt_desc_t v4_pkt = {
		.text       = "IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 254,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt;

	struct dp_test_npf_rule_t ruleset1[] = {
		{"10", PASS, STATELESS,
		 "proto-final=17 dst-addr=2.2.2.1 dst-port-group=PG1"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_rule_t ruleset2[] = {
		{"10", BLOCK, STATELESS,
		 "proto-final=17 dst-addr=2.2.2.1 dst-port-group=PG1"},
		RULE_DEF_PASS,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name = "FW1_IN", .enable = 1,
		.attach_point = "dp1T0", .fwd = FWD, .dir = "in",
		.rules = ruleset1
	};

	dp_test_npf_fw_port_group_add("PG1", "255-256");

	dp_test_npf_fw_add(&fw, npf_fw_debug);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Dest port 254 (0x00FE)
	 */
	pkt->l4.udp.dport = 254;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/*
	 * Dest port 255 (0x00FF)
	 */
	pkt->l4.udp.dport = 255;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/*
	 * Dest port 256 (0x0100)
	 */
	pkt->l4.udp.dport = 256;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/*
	 * Dest port 257 (0x0101)
	 */
	pkt->l4.udp.dport = 257;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/*
	 * Dest port 511  (0x01FF)
	 */
	pkt->l4.udp.dport = 511;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/*
	 * Change rule to block on a match
	 */
	dp_test_npf_fw_del(&fw, npf_fw_debug);
	fw.rules = ruleset2;
	dp_test_npf_fw_add(&fw, npf_fw_debug);

	/*
	 * Dest port 254 (0x00FE)
	 */
	pkt->l4.udp.dport = 254;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/*
	 * Dest port 255 (0x00FF)
	 */
	pkt->l4.udp.dport = 255;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/*
	 * Dest port 256 (0x0100)
	 */
	pkt->l4.udp.dport = 256;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/*
	 * Dest port 257 (0x0101)
	 */
	pkt->l4.udp.dport = 257;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	/*
	 * Dest port 511  (0x01FF)
	 */
	pkt->l4.udp.dport = 511;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);


	/* Cleanup */
	dp_test_npf_fw_del(&fw, npf_fw_debug);
	dp_test_npf_fw_port_group_del("PG1");
	dp_test_npf_clear_sessions();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");

} DP_END_TEST;

/*
 * This test adds testing of rulesets with multiple rules.
 */
DP_START_TEST(fw_ipv4, mrules)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	struct dp_test_pkt_desc_t v4_pkt1 = {
		.text       = "IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 80,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v4_pkt2 = {
		.text       = "ICMP IPv4",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.3",
		.l2_dst     = "aa:bb:cc:dd:2:b3",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = 0,
					.dpt_icmp_seq = 0
				},
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_npf_rule_t ruleset1[] = {
		{"10", PASS, STATEFUL,
			"proto-final=17 dst-addr=2.2.2.1 dst-port=81"},
		{"20", PASS, STATEFUL,
			"proto-final=17 dst-addr=2.2.2.1 dst-port=80"},
		{"30", PASS, STATEFUL, "proto-final=1 dst-addr=2.2.2.3"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name = "FW1_IN", .enable = 1,
		.attach_point = "dp1T0", .fwd = FWD, .dir = "in",
		.rules = ruleset1
	};

	dp_test_npf_fw_add(&fw, npf_fw_debug);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.3",
				  "aa:bb:cc:dd:2:b3");

	/*
	 * to proto 17, dest 2.2.2.1 port 80
	 */
	pkt = &v4_pkt1;
	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count(
				"to proto-final 17, dest 2.2.2.1 port 80",
				   &fw, fw.rules[1].rule, 1);

	/* Verify a session was created */
	dp_test_npf_session_verify_desc(NULL, pkt, fw.attach_point,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*
	 * to proto 1, dest 2.2.2.3
	 */
	pkt = &v4_pkt2;
	pkt->l3_dst = "2.2.2.3";
	pkt->l2_dst = "aa:bb:cc:dd:2:b3";

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count("to proto-final 1, dest 2.2.2.3",
				   &fw, fw.rules[2].rule, 1);

	/* Verify a session was created */
	dp_test_npf_session_verify_desc(NULL, pkt, fw.attach_point,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*
	 * to proto 1, dest 2.2.2.1
	 */
	pkt = &v4_pkt2;
	pkt->l3_dst = "2.2.2.1";
	pkt->l2_dst = "aa:bb:cc:dd:2:b1";

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count("to proto-final 1, dest 2.2.2.1",
				   &fw, fw.rules[3].rule, 1);


	/* Cleanup */
	dp_test_npf_fw_del(&fw, npf_fw_debug);
	dp_test_npf_clear_sessions();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.3",
				  "aa:bb:cc:dd:2:b3");

} DP_END_TEST;

/*
 * This test adds testing of rulesets with multiple rules.
 */
DP_START_TEST(fw_ipv6, mrules)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	struct dp_test_pkt_desc_t v6_pkt1 = {
		.text       = "IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 80,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t v6_pkt2 = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::3",
		.l2_dst     = "aa:bb:cc:dd:2:b3",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{ .udata32 = 0 },
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_npf_rule_t ruleset1[] = {
		{"10", PASS, STATEFUL,
		 "proto-final=17 dst-addr=2002:2:2::1 dst-port=81"},
		{"20", PASS, STATEFUL,
		 "proto-final=17 dst-addr=2002:2:2::1 dst-port=80"},
		{"30", PASS, STATEFUL, "proto-final=58 dst-addr=2002:2:2::3"},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name = "FW1_IN", .enable = 1,
		.attach_point = "dp1T0", .fwd = FWD, .dir = "in",
		.rules = ruleset1
	};

	dp_test_npf_fw_add(&fw, npf_fw_debug);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::3",
				  "aa:bb:cc:dd:2:b3");

	/*
	 * to proto 17, dest 2002:2:2::1 port 80
	 */
	pkt = &v6_pkt1;
	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count(
		"to proto-final 17, dest 2002:2:2::1 port 80",
		&fw, fw.rules[1].rule, 1);

	/* Verify a session was created */
	dp_test_npf_session_verify_desc(NULL, pkt, fw.attach_point,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*
	 * to proto 58, dest 2002:2:2::3
	 */
	pkt = &v6_pkt2;
	pkt->l3_dst = "2002:2:2::3";
	pkt->l2_dst = "aa:bb:cc:dd:2:b3";

	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count("to proto-final 58, dest 2002:2:2::3",
				   &fw, fw.rules[2].rule, 1);

	/* Verify a session was created */
	dp_test_npf_session_verify_desc(NULL, pkt, fw.attach_point,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*
	 * to proto 58, dest 2002:2:2::1
	 */
	pkt = &v6_pkt2;
	pkt->l3_dst = "2002:2:2::1";
	pkt->l2_dst = "aa:bb:cc:dd:2:b1";

	test_pak = dp_test_v6_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count("to proto-final 58, dest 2002:2:2::1",
				   &fw, fw.rules[3].rule, 1);


	/* Cleanup */
	dp_test_npf_fw_del(&fw, npf_fw_debug);
	dp_test_npf_clear_sessions();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::3",
				  "aa:bb:cc:dd:2:b3");

} DP_END_TEST;

/*
 * Address groups
 */
DP_START_TEST(fw_ipv4, address_groups)
{
	struct dp_test_pkt_desc_t *pkt;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;

	struct dp_test_pkt_desc_t v4_pkt1 = {
		.text       = "IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2.2.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 41000,
				.dport = 80,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};
	pkt = &v4_pkt1;

	struct dp_test_npf_rule_t ruleset1[] = {
		{"10", PASS, STATELESS, NULL},
		RULE_DEF_BLOCK,
		NULL_RULE };

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name = "FW1_IN", .enable = 1,
		.attach_point = "dp1T0", .fwd = FWD, .dir = "in",
		.rules = ruleset1
	};

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.3",
				  "aa:bb:cc:dd:2:b3");

	/*
	 * We are repeatedly deleting and adding an address-group, and the RCU
	 * grace period delay means we need to use a different name each time.
	 */
	char addr_group[15];
	char npf[32];
	uint addr_group_num = 0;

	spush(addr_group, sizeof(addr_group), "ADDR_GRP%u", addr_group_num);
	spush(npf, sizeof(npf), "dst-addr-group=%s", addr_group);
	fw.rules[0].npf = npf;

	dp_test_npf_fw_addr_group_add(addr_group);
	dp_test_npf_fw_addr_group_addr_add(addr_group, "2.2.2.1");

	/*
	 * Repeat the test 3 times, forcing the tableset table ID value to:
	 *
	 * 1. < 1024
	 * 2. > 1024 and < 2048
	 * 3. exceed 2048 and wrap back to < 1024
	 */
	uint pass = 0;
repeat_test:
	pass++;

	/* Add firewall */
	dp_test_npf_fw_add(&fw, npf_fw_debug);

	/*
	 * To 2.2.2.1
	 */
	pkt->l3_dst = "2.2.2.1";
	pkt->l2_dst = "aa:bb:cc:dd:2:b1";

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count("to 2.2.2.1", &fw,
					  fw.rules[0].rule, 1);

	/*
	 * To 2.2.2.3
	 */
	pkt->l3_dst = "2.2.2.3";
	pkt->l2_dst = "aa:bb:cc:dd:2:b3";

	test_pak = dp_test_v4_pkt_from_desc(pkt);
	test_exp = dp_test_exp_from_desc(test_pak, pkt);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	/* Run the test */
	dp_test_pak_receive(test_pak, pkt->rx_intf, test_exp);

	dp_test_npf_verify_rule_pkt_count("to 2.2.2.3", &fw,
					  fw.rules[1].rule, 1);

	/* Delete firewall */
	dp_test_npf_fw_del(&fw, npf_fw_debug);

	/*
	 * On first pass, we push the tableset table ID to > 1024 but < 2048.
	 * On second pass we cause the table ID to reach 2048 and wrap back to
	 * 0.
	 */
	if (pass < 3) {
		dp_test_npf_fw_addr_group_addr_del(addr_group, "2.2.2.1");
		dp_test_npf_fw_addr_group_del(addr_group);

		uint i;

		for (i = 0; i < 1030; i++) {
			addr_group_num += 1;
			spush(addr_group, sizeof(addr_group), "ADDR_GRP%u",
			      addr_group_num);
			spush(npf, sizeof(npf), "dst-addr-group=%s",
			      addr_group);

			dp_test_npf_fw_addr_group_add(addr_group);
			dp_test_npf_fw_addr_group_del(addr_group);
		}

		addr_group_num += 1;
		spush(addr_group, sizeof(addr_group), "ADDR_GRP%u",
		      addr_group_num);
		spush(npf, sizeof(npf), "dst-addr-group=%s", addr_group);

		dp_test_npf_fw_addr_group_add(addr_group);
		dp_test_npf_fw_addr_group_addr_add(addr_group, "2.2.2.1");

		goto repeat_test;
	}

	dp_test_npf_fw_addr_group_addr_del(addr_group, "2.2.2.1");
	dp_test_npf_fw_addr_group_del(addr_group);

	/* Cleanup */
	dp_test_npf_clear_sessions();

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.3",
				  "aa:bb:cc:dd:2:b3");

} DP_END_TEST;

DP_START_TEST(fw_ipv4, macvlan)
{
	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "5000",
			.pass     = BLOCK,
			.stateful = STATELESS,
			.npf      = "dst-addr=2.2.2.0/24",
		},
		NULL_RULE
	};
	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1",
		.enable = 1,
		.attach_point   = "dp1T3",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *macvlan_mac = "00:00:5E:00:01:03";
	const char *nh_mac_str = "aa:bb:cc:dd:ee:11";
	int len = 22;

	dp_test_intf_macvlan_create("dp1vrrp1", "dp1T3", macvlan_mac);

	dp_test_nl_add_ip_addr_and_connected("dp1T3", "1.1.1.1/24");
	dp_test_netlink_add_ip_address("dp1vrrp1", "1.1.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	/* Add the nh arp we want the packet to follow */
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	dp_test_npf_fw_add(&fw, false);

	/*
	 * Verify that the firewall rules are picked up from the
	 * physical even though the packet is destined to the macvlan
	 * address and thus that the packet is dropped
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "2.2.2.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 macvlan_mac,
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T3", exp);

	dp_test_npf_fw_del(&fw, false);

	/*
	 * Sanity check that removing the firewall rule now allows
	 * packet to be forwarded.
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "2.2.2.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 macvlan_mac,
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str,
				 dp_test_intf_name2mac_str("dp2T1"),
				 RTE_ETHER_TYPE_IPV4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_exp_set_oif_name(exp, "dp2T1");

	dp_test_pak_receive(test_pak, "dp1T3", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_netlink_del_ip_address("dp1vrrp1", "1.1.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "1.1.1.1/24");

	dp_test_intf_macvlan_del("dp1vrrp1");
} DP_END_TEST;

DP_START_TEST(fw_ipv4, macvlan_multicast)
{
	struct dp_test_npf_rule_t rules[] = {
		RULE_DEF_BLOCK,
		NULL_RULE
	};
	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW1",
		.enable = 1,
		.attach_point   = "dp1T3",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *macvlan_mac = "00:00:5E:00:01:03";
	const char *vrrp_multicast_mac = "01:00:5E:00:00:12";
	const char *nh_mac_str = "aa:bb:cc:dd:ee:11";
	int len = 22;

	dp_test_intf_macvlan_create("dp1vrrp1", "dp1T3", macvlan_mac);

	dp_test_nl_add_ip_addr_and_connected("dp1T3", "1.1.1.1/24");
	dp_test_netlink_add_ip_address("dp1vrrp1", "1.1.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	/* Add the nh arp we want the packet to follow */
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	dp_test_npf_fw_add(&fw, false);

	/*
	 * Verify that the firewall rules are picked up from the
	 * physical even though the packet is destined to the macvlan
	 * address and thus that the packet is dropped
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.1",
					   1, &len);
	/*
	 * This IP packet which is sent to a multicast mac address only appears
	 * on the receiving interface where the firewall is configured, and
	 * hence this packet will be dropped.
	 */
	dp_test_pktmbuf_eth_init(test_pak,
				 vrrp_multicast_mac,
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(test_pak, "dp1T3", exp);

	dp_test_npf_fw_del(&fw, false);

	/*
	 * Sanity check that removing the firewall rule now allows
	 * packet to be forwarded.
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.1",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 vrrp_multicast_mac,
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				 nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T1"),
				 RTE_ETHER_TYPE_IPV4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_pak_receive(test_pak, "dp1T3", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_netlink_del_ip_address("dp1vrrp1", "1.1.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "1.1.1.1/24");

	dp_test_intf_macvlan_del("dp1vrrp1");
} DP_END_TEST;
