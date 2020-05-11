/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf Session Limiter tests
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
#include "dp_test_lib_tcp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_nat_lib.h"

/*
 * Get session limiter rule json object
 */
static json_object *
dp_test_npf_json_sess_limit_rule(const char *real_ifname, const char *rule)
{
	json_object *jresp;
	json_object *jrule;
	struct dp_test_json_find_key key[] = { {"config", NULL},
					       {"attach_type", "interface"},
					       {"attach_point", real_ifname},
					       {"rulesets", NULL},
					       {"ruleset_type",
						"session-rproc"},
					       {"groups", NULL},
					       {"rules", NULL},
					       {rule, NULL} };
	char *response;
	bool err;

	response = dp_test_console_request_w_err(
		"npf-op show all: session-rproc", &err, false);
	if (!response || err)
		return NULL;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return NULL;

	jrule = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
	json_object_put(jresp);

	return jrule;
}

/*
 * Get session limiter parameter json object
 */
static json_object *
dp_test_npf_json_sess_limit_param(const char *param)
{
	json_object *jresp;
	json_object *jobj;
	struct dp_test_json_find_key key[] = { {"session-limit", NULL},
					       {"parameter", NULL},
					       {param, NULL},
					       {"summary", NULL} };
	char *response;
	bool err;
	char cmd[100];

	spush(cmd, sizeof(cmd),
	      "npf-op fw show session-limit name %s summary", param);

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err)
		return NULL;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return NULL;

	jobj = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
	json_object_put(jresp);

	return jobj;
}

/*
 * Get the packets, allowed and dropped counts from a session limiter rule.
 */
static bool
dp_test_npf_sess_limit_rule_counts(const char *intf, const char *rule,
				   int *packets, int *allowed, int *dropped)
{
	json_object *jrule;
	bool rv;

	jrule = dp_test_npf_json_sess_limit_rule(dp_test_intf_real_buf(intf),
						 rule);
	if (!jrule)
		return false;

	/*
	 * Packet count is number of sessions seen by the session limiter
	 */
	rv = dp_test_json_int_field_from_obj(jrule, "packets", packets);
	if (!rv) {
		json_object_put(jrule);
		return false;
	}

	/*
	 * The 'bytes' field for session limiter rules is used to count the
	 * number of session allowed.
	 */
	rv = dp_test_json_int_field_from_obj(jrule, "bytes", allowed);
	if (!rv) {
		json_object_put(jrule);
		return false;
	}

	*dropped = *packets - *allowed;

	json_object_put(jrule);
	return true;
}

/*
 * Get the session counts (new, established, and terminating) from a session
 * limiter parameter.
 */
static bool
dp_test_npf_sess_limit_sess_counts(const char *param, int *new, int *estbd,
				   int *term)
{
	json_object *jobj;
	bool rv;

	jobj = dp_test_npf_json_sess_limit_param(param);
	if (!jobj)
		return false;

	rv = dp_test_json_int_field_from_obj(jobj, "new_ct", new);
	if (!rv) {
		json_object_put(jobj);
		return false;
	}

	rv = dp_test_json_int_field_from_obj(jobj, "estab_ct", estbd);
	if (!rv) {
		json_object_put(jobj);
		return false;
	}

	rv = dp_test_json_int_field_from_obj(jobj, "term_ct", term);
	if (!rv) {
		json_object_put(jobj);
		return false;
	}

	json_object_put(jobj);
	return rv;
}

static void
print_sess_limiter(void)
{
	json_object *jobj;
	struct dp_test_json_mismatches *mismatches = NULL;
	const char *str;

	jobj = dp_test_json_do_show_cmd(
		"npf-op fw show session-limit name PARAM1 summary",
		&mismatches, false);

	if (jobj) {
		str = json_object_to_json_string_ext(jobj,
						     JSON_C_TO_STRING_PRETTY);
		if (str)
			printf("%s\n", str);
		json_object_put(jobj);
	}

	jobj = dp_test_json_do_show_cmd(
		"npf-op show all: session-rproc",
		&mismatches, false);

	if (jobj) {
		str = json_object_to_json_string_ext(jobj,
						     JSON_C_TO_STRING_PRETTY);
		if (str)
			printf("%s\n", str);
		json_object_put(jobj);
	}

}

/*
 * Callback from dp_test_tcp_pak_receive
 */
static void forwarded_cb(const char *str,
			 uint pktno, bool forw,
			 uint8_t flags,
			 struct dp_test_pkt_desc_t *pre,
			 struct dp_test_pkt_desc_t *post,
			 void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	struct dp_test_pkt_desc_t post_copy;

	post_copy = *post;

	/*
	 * Fixup MAC header
	 */
	if (forw) {
		post_copy.l2_src = dp_test_intf_name2mac_str("dp2T1");
		post_copy.l2_dst = "aa:bb:cc:18:0:1";
	} else {
		post_copy.l2_src = dp_test_intf_name2mac_str("dp1T0");
		post_copy.l2_dst = "aa:bb:cc:16:0:20";
	}

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(&post_copy);


	test_exp = dp_test_exp_from_desc(post_pak, &post_copy);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}

/*
 * Callback from dp_test_tcp_pak_receive
 */
static void dropped_cb(const char *str,
		       uint pktno, bool forw,
		       uint8_t flags,
		       struct dp_test_pkt_desc_t *pre,
		       struct dp_test_pkt_desc_t *post,
		       void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	struct dp_test_pkt_desc_t post_copy;

	post_copy = *post;

	/*
	 * Fixup MAC header
	 */
	if (forw) {
		post_copy.l2_src = dp_test_intf_name2mac_str("dp2T1");
		post_copy.l2_dst = "aa:bb:cc:18:0:1";
	} else {
		post_copy.l2_src = dp_test_intf_name2mac_str("dp1T0");
		post_copy.l2_dst = "aa:bb:cc:16:0:20";
	}

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(&post_copy);


	test_exp = dp_test_exp_from_desc(post_pak, &post_copy);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}

/*
 * Create a number of established or half-open TCP sessions
 *
 * nsessions    - Number of sessions to create
 * halfopen     - True for halfopen, false for established
 * exp_sessions - Number of sessions we expect to be created
 */
static void
_dp_test_create_tcp_sessions(uint nsessions, const char *exp_state,
			     uint exp_sessions, uint16_t dport,
			     const char *file, int line)
{
	static uint src_port = 49152;
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");
	uint npkts = 0, i;

	/*
	 * TCP packet
	 */
	struct dp_test_pkt_desc_t *fwd_pkt, *back_pkt;

	fwd_pkt = dpt_pdesc_v4_create(
		"Fwd", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		dp1T0_mac, "200.201.202.203", dport,
		"dp1T0", "dp2T1");

	back_pkt = dpt_pdesc_v4_create(
		"Back", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "200.201.202.203", dport,
		dp2T1_mac, "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	struct dpt_tcp_flow tcp_call = {
		.text[0] = '\0',	/* description */
		.isn = {0, 0},		/* initial seq no */
		.desc[DPT_FORW] = {	/* Forw pkt descriptors */
			.pre = fwd_pkt,
			.pst = fwd_pkt,
		},
		.desc[DPT_BACK] = {	/* Back pkt descriptors */
			.pre = back_pkt,
			.pst = back_pkt,
		},
		.test_cb = forwarded_cb, /* Prep and send pkt */
		.post_cb = NULL,	/* Fixup pkt exp */
	};

	/*
	 * State we expect the session to be in after each of the packets in
	 * the tcp_pkt1 array.  This uses the logging string.  See
	 * npf_state_tcp_name[] in npf_state.c
	 */
	static const char * const tcp_pkt1_state[] = {
		"SYN-SENT",
		"SYN-RECEIVED",
		"ESTABLISHED",
		"ESTABLISHED",
		"ESTABLISHED",
		"FIN-SENT",
		"FIN-SENT",
		"FIN-SENT",
		"FIN-WAIT",
		"FIN-WAIT",
		"LAST-ACK",
		"TIME-WAIT",
	};

	/*
	 * How many pkts do we need to send to get session in required state?
	 */
	for (i = 0; i < ARRAY_SIZE(tcp_pkt1_state); i++) {
		if (!strcmp(exp_state, tcp_pkt1_state[i])) {
			npkts = i + 1;
			break;
		}
	}

	if (npkts == 0) {
		_dp_test_fail(file, line,
			      "Expected state %s not found in tcp_pkt1_state[]",
			      exp_state);
		return;
	}

	/*
	 * TCP call packets
	 */
	struct dpt_tcp_flow_pkt tcp_pkt1[] = {
		{DPT_FORW, TH_SYN, 0, NULL, 0, NULL },
		{DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL },
		{DPT_FORW, TH_ACK, 0, NULL, 0, NULL }, /* ESTABLISHED */
		{DPT_BACK, TH_ACK, 20, NULL, 0, NULL },
		{DPT_FORW, TH_ACK, 50, NULL, 0, NULL },
		{DPT_FORW, TH_ACK | TH_FIN, 10, NULL, 0, NULL },
		{DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
		{DPT_FORW, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{DPT_BACK, TH_ACK, 0, NULL, 0, NULL },
		{DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
		{DPT_BACK, TH_ACK | TH_FIN, 0, NULL, 0, NULL },
		{DPT_FORW, TH_ACK, 0, NULL, 0, NULL },
	};

	dp_test_fail_unless(
		ARRAY_SIZE(tcp_pkt1_state) == ARRAY_SIZE(tcp_pkt1),
		"tcp_pkt1_state[] and tcp_pkt1[] are different sizes");

	uint state;
	const char *state_str;

	for (i = 0; i < nsessions; i++) {
		bool exp_created = i < exp_sessions;

		fwd_pkt->l4.tcp.sport = src_port++;
		back_pkt->l4.tcp.dport = fwd_pkt->l4.tcp.sport;

		/* Do we expect this session to be created or dropped? */
		if (exp_created)
			tcp_call.test_cb = forwarded_cb;
		else
			tcp_call.test_cb = dropped_cb;

		spush(tcp_call.text, sizeof(tcp_call.text),
		      "%s %d: TCP Sess %u, port %u, exp to be %s (%s), "
		      "npkts %u",
		      basename(file), line, i+1, fwd_pkt->l4.tcp.sport,
		      exp_created ? "created" : "dropped", exp_state, npkts);

		/* Create the session */
		dpt_tcp_call(&tcp_call, tcp_pkt1, npkts, 0, 0, NULL, 0);

		/* Do we expect session to be created? */
		if (exp_created) {
			/* Verify the session exists and is active */
			dp_test_npf_session_verify_desc(NULL, fwd_pkt,
							fwd_pkt->rx_intf,
							SE_ACTIVE,
							SE_FLAGS_AE, true);
			/* Verify the session state */
			dp_test_npf_session_state(fwd_pkt->l3_src,
						  fwd_pkt->l4.tcp.sport,
						  fwd_pkt->l3_dst,
						  fwd_pkt->l4.tcp.dport,
						  IPPROTO_TCP,
						  fwd_pkt->rx_intf, &state);

			state_str = dp_test_npf_sess_state_str(IPPROTO_TCP,
							       state);

			dp_test_fail_unless(!strcmp(state_str,
						    tcp_pkt1_state[npkts-1]),
					    "State %s, expected %s", state_str,
					    tcp_pkt1_state[npkts-1]);
		} else {
			/* Verify the session does *not* exist */
			dp_test_npf_session_verify_desc(NULL, fwd_pkt,
							fwd_pkt->rx_intf,
							0, 0, false);
		}

		if (0)
			print_sess_limiter();
	}

	free(fwd_pkt);
	free(back_pkt);
}

#define dp_test_create_tcp_sessions(n, h, exp, dport)		\
	_dp_test_create_tcp_sessions(n, h, exp, dport,		\
				     __BASE_FILE__, __LINE__)


/*
 * Create a number of established or half-open UDP sessions
 *
 * nsessions    - Number of sessions to create
 * halfopen     - True for halfopen, false for established
 * exp_sessions - Number of sessions we expect to be created
 */
static void
_dp_test_create_udp_sessions(uint nsessions, bool halfopen,
			     uint exp_sessions,
			     const char *file, int line)
{
	static uint src_port = 1000;
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");
	uint i;

	/*
	 * UDP packet
	 */
	struct dp_test_pkt_desc_t fwd_pkt = {
		.text       = "Fwd",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = src_port,
				.dport = 80,
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t back_pkt = {
		.text       = "Back",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_UDP,
		.l4	 = {
			.udp = {
				.sport = 80,
				.dport = src_port,
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t pkt_copy;
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	char desc[120];

	for (i = 0; i < nsessions; i++) {
		bool exp_created = i < exp_sessions;

		fwd_pkt.l4.udp.sport = src_port++;
		back_pkt.l4.udp.dport = fwd_pkt.l4.udp.sport;

		/*
		 * Forwards packet
		 */
		test_pak = dp_test_v4_pkt_from_desc(&fwd_pkt);

		pkt_copy = fwd_pkt;
		pkt_copy.l2_src = dp2T1_mac;
		pkt_copy.l2_dst = "aa:bb:cc:18:0:1";

		test_exp = dp_test_exp_from_desc(test_pak, &pkt_copy);

		if (exp_created)
			dp_test_exp_set_fwd_status(test_exp,
						   DP_TEST_FWD_FORWARDED);
		else
			dp_test_exp_set_fwd_status(test_exp,
						   DP_TEST_FWD_DROPPED);

		spush(desc, sizeof(desc),
		      "%s %d: UDP Sess %u, port %u, exp to be %s (%s)",
		      basename(file), line, i+1, fwd_pkt.l4.udp.sport,
		      exp_created ? "created" : "dropped",
		      halfopen ? "HO" : "EST");

		dp_test_pak_receive(test_pak, "dp1T0", test_exp);

		/*
		 * Backwards packet
		 */
		if (exp_created && !halfopen) {
			test_pak = dp_test_v4_pkt_from_desc(&back_pkt);

			pkt_copy = back_pkt;
			pkt_copy.l2_src = dp1T0_mac;
			pkt_copy.l2_dst = "aa:bb:cc:16:0:20";

			test_exp = dp_test_exp_from_desc(test_pak, &pkt_copy);

			dp_test_exp_set_fwd_status(test_exp,
						   DP_TEST_FWD_FORWARDED);

			/* Run the test */
			dp_test_pak_receive(test_pak, "dp2T1", test_exp);
		}
	}
}

#define dp_test_create_udp_sessions(n, h, exp)				\
	_dp_test_create_udp_sessions(n, h, exp, __BASE_FILE__, __LINE__)



DP_DECL_TEST_SUITE(npf_sess_limit);

/*
 * Test session limiter max-halfopen feature
 */
DP_DECL_TEST_CASE(npf_sess_limit, sess_limit_tcp, NULL, NULL);
DP_START_TEST(sess_limit_tcp, max_halfopen)
{
	int packets = 0, allowed = 0, dropped = 0;
	int new = 0, estbd = 0, term = 0;
	bool rv;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	/*
	 * Ruleset
	 */
	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t rset = {
		.rstype = "fw-in",
		.name   = "FW1",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&rset, false);

	/*
	 * Add session limiter
	 */
	uint max_halfopen = 2;

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param add name PARAM1");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param add name PARAM1 maxhalfopen %u",
		max_halfopen);

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add session-limiter:GROUP1 10 "
		"action=accept "
		"proto=6 dst-addr=200.201.202.203 dst-port=80 "
		"handle=session-limiter(parameter=PARAM1)");

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:%s "
		"session-rproc session-limiter:GROUP1",
		dp_test_intf_real_buf("dp1T0"));

	dp_test_npf_commit();

	/*
	 * Create and verify 6 ESTABLISHED sessions
	 */
	dp_test_create_tcp_sessions(6, "ESTABLISHED", 6, 80);

	rv = dp_test_npf_sess_limit_rule_counts("dp1T0", "10",
						&packets, &allowed,
						&dropped);
	dp_test_fail_unless(rv, "Session limit rule not found");

	dp_test_fail_unless(packets == 6,
			    "Session limit rule packet count %d, "
			    "expected 6", packets);
	dp_test_fail_unless(allowed == 6,
			    "Session limit rule allowed count %d, "
			    "expected 6", allowed);
	dp_test_fail_unless(dropped == 0,
			    "Session limit rule dropped count %d, "
			    "expected 0", dropped);

	rv = dp_test_npf_sess_limit_sess_counts("PARAM1", &new, &estbd, &term);
	dp_test_fail_unless(rv, "Session limit param not found");

	dp_test_fail_unless(new == 0,
			    "Session limit param new count %d, "
			    "expected 0", new);
	dp_test_fail_unless(estbd == 6,
			    "Session limit param established count %d, "
			    "expected 6", estbd);
	dp_test_fail_unless(term == 0,
			    "Session limit param terminating count %d, "
			    "expected 0", term);

	/*
	 * Create 4 half-open sessions.  Expect 2 to be created, and 2
	 * dropped.
	 */
	dp_test_create_tcp_sessions(4, "SYN-SENT", max_halfopen, 80);

	rv = dp_test_npf_sess_limit_rule_counts("dp1T0", "10",
						&packets, &allowed,
						&dropped);
	dp_test_fail_unless(rv, "Session limit rule not found");

	dp_test_fail_unless(packets == 10,
			    "Session limit rule packet count %d, "
			    "expected 10", packets);
	dp_test_fail_unless(allowed == 8,
			    "Session limit rule allowed count %d, "
			    "expected 8", allowed);
	dp_test_fail_unless(dropped == 2,
			    "Session limit rule dropped count %d, "
			    "expected 2", dropped);

	rv = dp_test_npf_sess_limit_sess_counts("PARAM1", &new, &estbd, &term);
	dp_test_fail_unless(rv, "Session limit param not found");

	dp_test_fail_unless(new == 2,
			    "Session limit param new count %d, "
			    "expected 2", new);
	dp_test_fail_unless(estbd == 6,
			    "Session limit param established count %d, "
			    "expected 6", estbd);
	dp_test_fail_unless(term == 0,
			    "Session limit param terminating count %d, "
			    "expected 0", term);


	/*
	 * Create 4 half-open sessions, but change dest-port from 80 to 81.
	 * Expect all 4 to be created since the packet no longer matched the
	 * session limiter rule.  session limiter counts all remain unchanged.
	 */
	dp_test_create_tcp_sessions(4, "SYN-SENT", 4, 81);

	rv = dp_test_npf_sess_limit_rule_counts("dp1T0", "10",
						&packets, &allowed,
						&dropped);
	dp_test_fail_unless(rv, "Session limit rule not found");

	dp_test_fail_unless(packets == 10,
			    "Session limit rule packet count %d, "
			    "expected 10", packets);
	dp_test_fail_unless(allowed == 8,
			    "Session limit rule allowed count %d, "
			    "expected 8", allowed);
	dp_test_fail_unless(dropped == 2,
			    "Session limit rule dropped count %d, "
			    "expected 2", dropped);

	rv = dp_test_npf_sess_limit_sess_counts("PARAM1", &new, &estbd, &term);
	dp_test_fail_unless(rv, "Session limit param not found");

	dp_test_fail_unless(new == 2,
			    "Session limit param new count %d, "
			    "expected 2", new);
	dp_test_fail_unless(estbd == 6,
			    "Session limit param established count %d, "
			    "expected 6", estbd);
	dp_test_fail_unless(term == 0,
			    "Session limit param terminating count %d, "
			    "expected 0", term);

	/*
	 * Delete session limiter
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:%s "
		"session-rproc session-limiter:GROUP1",
		dp_test_intf_real_buf("dp1T0"));
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut delete session-limiter:GROUP1");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param delete name PARAM1 maxhalfopen");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param delete name PARAM1");
	dp_test_npf_commit();


	/* Cleanup */

	dp_test_npf_fw_del(&rset, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;

/*
 * Test session limiter max-rate feature
 */
DP_START_TEST(sess_limit_tcp, max_rate)
{
	int packets = 0, allowed = 0, dropped = 0;
	int new = 0, estbd = 0, term = 0;
	bool rv;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	/*
	 * Ruleset
	 */
	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t rset = {
		.rstype = "fw-in",
		.name   = "FW1",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&rset, false);

	/*
	 * Add session limiter
	 */
	uint max_rate = 4;

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param add name PARAM1");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param add name PARAM1 ratelimit rate %u",
		max_rate);

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add session-limiter:GROUP1 10 "
		"action=accept "
		"proto=6 dst-addr=200.201.202.203 dst-port=80 "
		"handle=session-limiter(parameter=PARAM1)");

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:%s "
		"session-rproc session-limiter:GROUP1",
		dp_test_intf_real_buf("dp1T0"));

	dp_test_npf_commit();

	dp_test_enable_soft_tick_override();

	/*
	 * Create and verify 4 ESTABLISHED sessions
	 */
	dp_test_create_tcp_sessions(4, "ESTABLISHED", 4, 80);

	rv = dp_test_npf_sess_limit_rule_counts("dp1T0", "10",
						&packets, &allowed,
						&dropped);
	dp_test_fail_unless(rv, "Session limit rule not found");

	dp_test_fail_unless(packets == 4,
			    "Session limit rule packet count %d, "
			    "expected 4", packets);
	dp_test_fail_unless(allowed == 4,
			    "Session limit rule allowed count %d, "
			    "expected 4", allowed);
	dp_test_fail_unless(dropped == 0,
			    "Session limit rule dropped count %d, "
			    "expected 0", dropped);

	rv = dp_test_npf_sess_limit_sess_counts("PARAM1", &new, &estbd, &term);
	dp_test_fail_unless(rv, "Session limit param not found");

	dp_test_fail_unless(new == 0,
			    "Session limit param new count %d, "
			    "expected 0", new);
	dp_test_fail_unless(estbd == 4,
			    "Session limit param established count %d, "
			    "expected 4", estbd);
	dp_test_fail_unless(term == 0,
			    "Session limit param terminating count %d, "
			    "expected 0", term);

	/*
	 * Create 2 half-open sessions.  Expect 0 to be created, and 2
	 * dropped.
	 */
	dp_test_create_tcp_sessions(2, "SYN-SENT", 0, 80);

	rv = dp_test_npf_sess_limit_rule_counts("dp1T0", "10",
						&packets, &allowed,
						&dropped);
	dp_test_fail_unless(rv, "Session limit rule not found");

	dp_test_fail_unless(packets == 6,
			    "Session limit rule packet count %d, "
			    "expected 6", packets);
	dp_test_fail_unless(allowed == 4,
			    "Session limit rule allowed count %d, "
			    "expected 4", allowed);
	dp_test_fail_unless(dropped == 2,
			    "Session limit rule dropped count %d, "
			    "expected 2", dropped);

	rv = dp_test_npf_sess_limit_sess_counts("PARAM1", &new, &estbd, &term);
	dp_test_fail_unless(rv, "Session limit param not found");

	dp_test_fail_unless(new == 0,
			    "Session limit param new count %d, "
			    "expected 0", new);
	dp_test_fail_unless(estbd == 4,
			    "Session limit param established count %d, "
			    "expected 4", estbd);
	dp_test_fail_unless(term == 0,
			    "Session limit param terminating count %d, "
			    "expected 0", term);

	/*
	 * Delete session limiter
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:%s "
		"session-rproc session-limiter:GROUP1",
		dp_test_intf_real_buf("dp1T0"));
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut delete session-limiter:GROUP1");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param delete name PARAM1 ratelimit");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param delete name PARAM1");
	dp_test_npf_commit();


	/* Cleanup */
	dp_test_disable_soft_tick_override();
	dp_test_npf_fw_del(&rset, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;



/*
 * Test session limiter with UDP sessions.
 */
DP_DECL_TEST_CASE(npf_sess_limit, sess_limit_udp, NULL, NULL);
DP_START_TEST(sess_limit_udp, max_halfopen)
{
	int packets = 0, allowed = 0, dropped = 0;
	int new = 0, estbd = 0, term = 0;
	bool rv;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	/*
	 * Ruleset
	 */
	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t rset = {
		.rstype = "fw-in",
		.name   = "FW1",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rules
	};

	dp_test_npf_fw_add(&rset, false);

	/*
	 * Add session limiter
	 */
	uint max_halfopen = 2;

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param add name PARAM1");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param add name PARAM1 maxhalfopen %u",
		max_halfopen);

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add session-limiter:GROUP1 10 "
		"action=accept "
		"proto=17 dst-addr=200.201.202.203 dst-port=80 "
		"handle=session-limiter(parameter=PARAM1)");

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:%s "
		"session-rproc session-limiter:GROUP1",
		dp_test_intf_real_buf("dp1T0"));

	dp_test_npf_commit();



	/*
	 * Create and verify 6 ESTABLISHED sessions
	 */
	dp_test_create_udp_sessions(6, false, 6);

	rv = dp_test_npf_sess_limit_rule_counts("dp1T0", "10",
						&packets, &allowed,
						&dropped);
	dp_test_fail_unless(rv, "Session limit rule not found");

	dp_test_fail_unless(packets == 6,
			    "Session limit rule packet count %d, "
			    "expected 6", packets);
	dp_test_fail_unless(allowed == 6,
			    "Session limit rule allowed count %d, "
			    "expected 6", allowed);
	dp_test_fail_unless(dropped == 0,
			    "Session limit rule dropped count %d, "
			    "expected 0", dropped);

	rv = dp_test_npf_sess_limit_sess_counts("PARAM1", &new, &estbd, &term);
	dp_test_fail_unless(rv, "Session limit param not found");

	dp_test_fail_unless(new == 0,
			    "Session limit param new count %d, "
			    "expected 0", new);
	dp_test_fail_unless(estbd == 6,
			    "Session limit param established count %d, "
			    "expected 0", estbd);
	dp_test_fail_unless(term == 0,
			    "Session limit param terminating count %d, "
			    "expected 0", term);

	/*
	 * Create 4 half-open sessions.  Expect 2 to be created, and 2
	 * dropped.
	 */
	dp_test_create_udp_sessions(4, true, max_halfopen);

	rv = dp_test_npf_sess_limit_rule_counts("dp1T0", "10",
						&packets, &allowed,
						&dropped);
	dp_test_fail_unless(rv, "Session limit rule not found");

	dp_test_fail_unless(packets == 10,
			    "Session limit rule packet count %d, "
			    "expected 10", packets);
	dp_test_fail_unless(allowed == 8,
			    "Session limit rule allowed count %d, "
			    "expected 8", allowed);
	dp_test_fail_unless(dropped == 2,
			    "Session limit rule dropped count %d, "
			    "expected 2", dropped);

	rv = dp_test_npf_sess_limit_sess_counts("PARAM1", &new, &estbd, &term);
	dp_test_fail_unless(rv, "Session limit param not found");

	dp_test_fail_unless(new == 2,
			    "Session limit param new count %d, "
			    "expected 2", new);
	dp_test_fail_unless(estbd == 6,
			    "Session limit param established count %d, "
			    "expected 0", estbd);
	dp_test_fail_unless(term == 0,
			    "Session limit param terminating count %d, "
			    "expected 0", term);

	/*
	 * Delete session limiter
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:%s "
		"session-rproc session-limiter:GROUP1",
		dp_test_intf_real_buf("dp1T0"));
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut delete session-limiter:GROUP1");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param delete name PARAM1 maxhalfopen");
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut fw session-limit param delete name PARAM1");
	dp_test_npf_commit();


	/* Cleanup */

	dp_test_npf_fw_del(&rset, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;
