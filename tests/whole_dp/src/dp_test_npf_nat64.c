/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane NAT 6-4 tests
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf/npf_cache.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_session.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_nat64.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"

/*
 * Test Cases
 *
 * All test packets are UDP unless otherwise mentioned.
 *
 * nat64_a1 - Calls mangle_hook directly. v6 in, v4 out, then repeat.
 * nat64_a2 - Calls mangle_hook directly. v4 in, v6 out, then repeats.
 * nat64_a3 - Simulates orthogonal 6-to-4 and 4-to-6 translations occurring
 *            simultaneously.
 * nat64_a4 - Simulates the first 6-to-4 packet not reaching egress, and
 *            a second packet does reach egress.
 *
 * nat64_b1 - 6-to-4, src rfc6052,    dst rfc6052
 * nat64_b2 - 6-to-4, src one-to-one, dst rfc6052
 * nat64_b3 - 6-to-4, src addr pool,  dst one-to-one
 * nat64_b4 - 6-to-4, src addr pool,  dst one-to-one, address-group for pool
 * nat64_b5 - 6-to-4, src addr pool,  dst one-to-one, map dest port
 * nat64_b6 - 6-to-4, src one-to-one, dst rfc6052, SNAT masquerade on output
 * nat64_b7 - 6-to-4, src one-to-one, dst rfc6052, stateful firewall on input
 * nat64_b8 - 6-to-4, src one-to-one, dst rfc6052, stateful firewall on output
 * nat64_b9 - 6-to-4, src one-to-one, dst one-to-one, ICMP
 *
 * nat64_c1 - 4-to-6, src rfc6052,    dst rfc6052
 * nat64_c2 - 4-to-6, src rfc6052,    dst one-to-one
 * nat64_c3 - 4-to-6, src one-to-one, dst one-to-one
 * nat64_c4 - 4-to-6, src one-to-one, dst one-to-one, DNAT on input
 * nat64_c5 - 4-to-6, src one-to-one, dst one-to-one, map dest port
 * nat64_c9 - 4-to-5, src one-to-one, dst one-to-one, ICMP
 *
 * nat64_96 - 96 prefix length; Pkt in each dir; repeat; repeat with a fw
 * nat64_64 - 64 prefix length; Pkt in each dir; repeat
 * nat64_56 - 56 prefix length; Pkt in each dir; repeat
 * nat64_48 - 48 prefix length; Pkt in each dir; repeat
 *
 * To run all test cases:
 * make -j4 dataplane_test_run CK_RUN_SUITE=dp_test_npf_nat64.c
 *
 * To run one test case:
 * make -j4 dataplane_test_run CK_RUN_CASE=nat64_96
 */

DP_DECL_TEST_SUITE(npf_nat64);

/*
 * rfc6052 IPv4-Embedded IPv6 Address Prefix and Format
 *
 *    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |PL| 0-------------32--40--48--56--64--72--80--88--96--104---------|
 *    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |32|     prefix    |v4(32)         | u | suffix                    |
 *    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |40|     prefix        |v4(24)     | u |(8)| suffix                |
 *    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |48|     prefix            |v4(16) | u | (16)  | suffix            |
 *    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |56|     prefix                |(8)| u |  v4(24)   | suffix        |
 *    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |64|     prefix                    | u |   v4(32)      | suffix    |
 *    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |96|     prefix                                    |    v4(32)     |
 *    +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *               :       :       :       : 00    :       :       :
 */

/*
 * Wrapper around nat64_hook for IPv6 input
 *
 * Scenarios:
 *
 *   1. No ingress session exists
 *   2. ingress session exists but is not a nat64 session
 *   3. ingress session exists, is a nat64 session, but it not linked
 *      to an egress peer session
 *   4. ingress session exists, is a nat64 session, and is linked to an
 *      egress session
 */
enum dp_test_n64_in_scenario {
	DPT_N64_IN_SC1,
	DPT_N64_IN_SC2,
	DPT_N64_IN_SC3,
	DPT_N64_IN_SC4,
};

static struct rte_mbuf *
nat64_nat64_hook_v6_in(const char *ifname, struct dp_test_pkt_desc_t *pdesc,
			uint16_t *npf_flags,
			enum dp_test_n64_in_scenario scenario)
{
	npf_cache_t npc_cache, *npc = &npc_cache;
	struct npf_config *npf_config;
	struct pktmbuf_mdata *mdata;
	char real_ifname[IFNAMSIZ];
	nat64_decision_t decision;
	struct rte_mbuf  *mbuf;
	npf_session_t *se6;
	struct npf_if *nif;
	struct ifnet *ifp;
	bool intl_hpin = false;
	int rc, error = 0;

	/* Get interface pointers */
	dp_test_intf_real(ifname, real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);
	dp_test_fail_unless(ifp, "ifp for %s", ifname);

	/* Get npf config pointers */
	nif = rcu_dereference(ifp->if_npf);
	npf_config = npf_if_conf(nif);
	dp_test_fail_unless(npf_config, "npf config for %s", ifname);

	/* Create IPv6 packet */
	mbuf = dp_test_v6_pkt_from_desc(pdesc);
	dp_test_fail_unless(mbuf, "IPv6 packet create");

	/* Cache IPv6 packet */
	npf_cache_init(npc);
	rc = npf_cache_all(npc, mbuf, htons(RTE_ETHER_TYPE_IPV6));
	dp_test_fail_unless(rc == 0, "packet cache");
	dp_test_fail_unless((npc->npc_info & NPC_IP6) != 0,
			    "packet cache info %x",
			    npc->npc_info);

	/*
	 * If session_expected is true then a lookup should find a session.
	 */
	se6 = npf_session_inspect_or_create(npc, mbuf, ifp, PFIL_IN,
					    npf_flags, &error, &intl_hpin);
	dp_test_fail_unless(error == 0, "error %d", error);

	if (scenario == DPT_N64_IN_SC1) {
		dp_test_fail_unless(!se6,
				    "An IPv6 session should not exist yet");
	} else {
		dp_test_fail_unless(se6,
				    "An IPv6 session should already exist");
	}
	decision = npf_nat64_6to4_in(npf_config, &se6, ifp, npc, &mbuf,
				     npf_flags, &error);

	/*
	 * Verify outcome of nat64_hook
	 */

	/* From IPv6 ... */
	dp_test_fail_unless((*npf_flags & NPF_FLAG_FROM_IPV6) != 0,
			    "npf_flags 0x%x", *npf_flags);

	/* ... going to IPv4 */
	dp_test_fail_unless(decision == NAT64_DECISION_TO_V4,
			    "Expected TO_V4, got %s",
			    nat64_decision_str(decision));

	/*
	 * If nat64 creates a session, check it is not passed back to
	 * npf_hook_track
	 */
	if (scenario == DPT_N64_IN_SC1)
		dp_test_fail_unless(
			!se6, "nat64_hook should not pass session back"
			" to hook_track");

	/*
	 * Do we expect pkt metadata?
	 */
	if (scenario != DPT_N64_IN_SC4) {
		dp_test_fail_unless(
			pktmbuf_mdata_invar_exists(mbuf,
						   PKT_MDATA_INVAR_NAT64),
			"No nat64 metadata in mbuf");

		/* First time, mdata will be added to pkt */
		mdata = pktmbuf_mdata(mbuf);
		dp_test_fail_unless(mdata, "No mdata");

		se6 = mdata->md_nat64.n64_se;
		dp_test_fail_unless(
			se6, "No IPv6 session in nat64 packet metadata");
	} else {
		dp_test_fail_unless(
			!pktmbuf_mdata_invar_exists(mbuf,
						   PKT_MDATA_INVAR_NAT64),
			"nat64 metadata in mbuf");
	}

	return mbuf;
}

enum dp_test_n64_out_scenario {
	DPT_N64_OUT_SC1,
	DPT_N64_OUT_SC2,
	DPT_N64_OUT_SC3,
	DPT_N64_OUT_SC4,
};

/*
 * Wrapper around nat64_hook for IPv4 output of a converted mbuf
 */
static npf_session_t *
nat64_nat64_hook_v4_out(const char *ifname, struct rte_mbuf *mbuf,
			uint16_t *npf_flags,
			enum dp_test_n64_out_scenario scenario)
{
	npf_cache_t npc_cache, *npc = &npc_cache;
	struct npf_config *npf_config;
	char real_ifname[IFNAMSIZ];
	nat64_decision_t decision;
	npf_session_t *se4;
	struct npf_if *nif;
	struct ifnet *ifp;
	bool intl_hpin = false;
	int rc, error = 0;

	/* Get interface pointers */
	dp_test_intf_real(ifname, real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);
	dp_test_fail_unless(ifp, "ifp for %s", ifname);

	/* Get npf config pointers */
	nif = rcu_dereference(ifp->if_npf);
	npf_config = npf_if_conf(nif);
	dp_test_fail_unless(npf_config, "npf config for %s", ifname);

	/* Cache IPv4 packet */
	npf_cache_init(npc);
	rc = npf_cache_all(npc, mbuf, htons(RTE_ETHER_TYPE_IPV4));
	dp_test_fail_unless(rc == 0, "packet cache");
	dp_test_fail_unless((npc->npc_info & NPC_IP4) != 0,
			    "packet cache info %x",
			    npc->npc_info);

	/* An IPv4 session should not exist yet */
	se4 = npf_session_inspect_or_create(npc, mbuf, ifp, PFIL_OUT,
					    npf_flags, &error, &intl_hpin);
	dp_test_fail_unless(error == 0, "error %d", error);

	if (scenario == DPT_N64_OUT_SC1)
		dp_test_fail_unless(!se4,
				    "An IPv4 session should not exist yet");
	else
		dp_test_fail_unless(se4,
				    "An IPv4 session should already exist");

	decision = npf_nat64_6to4_out(&se4, ifp, npc, &mbuf, npf_flags, &error);

	dp_test_fail_unless(decision == NAT64_DECISION_PASS,
			    "Expected PASS, got %s",
			    nat64_decision_str(decision));

	/* IPv4 session should be created by nat64_hook if necessary */
	dp_test_fail_unless(se4, "session is NULL");

	/* simulate end of npf_hook_track */
	if (decision != NAT64_DECISION_DROP && se4) {
		/* This is a noop if already active */
		error = npf_session_activate(se4, ifp, npc, mbuf);
		dp_test_fail_unless(error == 0,
				    "error activating output session");
	}

	return se4;
}

/*
 * Wrapper around nat64_hook for IPv4 input
 */
static struct rte_mbuf *
nat64_nat64_hook_v4_in(const char *ifname, struct dp_test_pkt_desc_t *pdesc,
		       uint16_t *npf_flags,
		       enum dp_test_n64_in_scenario scenario)
{
	npf_cache_t npc_cache, *npc = &npc_cache;
	struct npf_config *npf_config;
	struct pktmbuf_mdata *mdata;
	char real_ifname[IFNAMSIZ];
	nat64_decision_t decision;
	struct rte_mbuf  *mbuf;
	npf_session_t *se4;
	struct npf_if *nif;
	struct ifnet *ifp;
	bool intl_hpin = false;
	int rc, error = 0;

	/* Get interface pointers */
	dp_test_intf_real(ifname, real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);
	dp_test_fail_unless(ifp, "ifp for %s", ifname);

	/* Get npf config pointers */
	nif = rcu_dereference(ifp->if_npf);
	npf_config = npf_if_conf(nif);
	dp_test_fail_unless(npf_config, "npf config for %s", ifname);

	/* Create IPv4 packet */
	mbuf = dp_test_v4_pkt_from_desc(pdesc);
	dp_test_fail_unless(mbuf, "IPv4 packet create");

	/* Cache IPv4 packet */
	npf_cache_init(npc);
	rc = npf_cache_all(npc, mbuf, htons(RTE_ETHER_TYPE_IPV4));
	dp_test_fail_unless(rc == 0, "packet cache");
	dp_test_fail_unless((npc->npc_info & NPC_IP4) != 0,
			    "packet cache info %x",
			    npc->npc_info);

	/*
	 * If session_expected is true then a lookup should find a session.
	 */
	se4 = npf_session_inspect_or_create(npc, mbuf, ifp, PFIL_IN,
					    npf_flags, &error, &intl_hpin);
	dp_test_fail_unless(error == 0, "error %d", error);

	if (scenario == DPT_N64_IN_SC1) {
		dp_test_fail_unless(!se4,
				    "An IPv4 session should not exist yet");
	} else {
		dp_test_fail_unless(se4,
				    "An IPv4 session should already exist");
	}
	decision = npf_nat64_4to6_in(npf_config, &se4, ifp, npc, &mbuf,
				     npf_flags, &error);

	/*
	 * Verify outcome of nat64_hook
	 */

	/* From IPv4 ... */
	dp_test_fail_unless((*npf_flags & NPF_FLAG_FROM_IPV4) != 0,
			    "npf_flags 0x%x", *npf_flags);

	/* ... going to IPv6 */
	dp_test_fail_unless(decision == NAT64_DECISION_TO_V6,
			    "Expected TO_V6, got %s",
			    nat64_decision_str(decision));

	/*
	 * If nat64 creates a session, check it is not passed back to
	 * npf_hook_track
	 */
	if (scenario == DPT_N64_IN_SC1)
		dp_test_fail_unless(
			!se4, "nat64_hook should not pass session back"
			" to hook_track");

	/*
	 * Do we expect pkt metadata?
	 */
	if (scenario != DPT_N64_IN_SC4) {
		dp_test_fail_unless(
			pktmbuf_mdata_invar_exists(mbuf,
						   PKT_MDATA_INVAR_NAT64),
			"No nat64 metadata in mbuf");

		/* First time, mdata will be added to pkt */
		mdata = pktmbuf_mdata(mbuf);
		dp_test_fail_unless(mdata, "No mdata");

		se4 = mdata->md_nat64.n64_se;
		dp_test_fail_unless(
			se4, "No IPv4 session in nat64 packet metadata");
	} else {
		dp_test_fail_unless(
			!pktmbuf_mdata_invar_exists(mbuf,
						   PKT_MDATA_INVAR_NAT64),
			"nat64 metadata in mbuf");
	}

	return mbuf;
}

/*
 * Wrapper around nat64_hook for IPv6 output of a converted mbuf
 */
static npf_session_t *
nat64_nat64_hook_v6_out(const char *ifname, struct rte_mbuf *mbuf,
			uint16_t *npf_flags,
			enum dp_test_n64_out_scenario scenario)
{
	npf_cache_t npc_cache, *npc = &npc_cache;
	struct npf_config *npf_config;
	char real_ifname[IFNAMSIZ];
	nat64_decision_t decision;
	npf_session_t *se6;
	struct npf_if *nif;
	struct ifnet *ifp;
	bool intl_hpin = false;
	int rc, error = 0;

	/* Get interface pointers */
	dp_test_intf_real(ifname, real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);
	dp_test_fail_unless(ifp, "ifp for %s", ifname);

	/* Get npf config pointers */
	nif = rcu_dereference(ifp->if_npf);
	npf_config = npf_if_conf(nif);
	dp_test_fail_unless(npf_config, "npf config for %s", ifname);

	/* Cache IPv6 packet */
	npf_cache_init(npc);
	rc = npf_cache_all(npc, mbuf, htons(RTE_ETHER_TYPE_IPV6));
	dp_test_fail_unless(rc == 0, "packet cache");
	dp_test_fail_unless((npc->npc_info & NPC_IP6) != 0,
			    "packet cache info %x",
			    npc->npc_info);

	/* An IPv6 session should not exist yet */
	se6 = npf_session_inspect_or_create(npc, mbuf, ifp, PFIL_OUT,
					    npf_flags, &error, &intl_hpin);
	dp_test_fail_unless(error == 0, "error %d", error);

	if (scenario == DPT_N64_OUT_SC1)
		dp_test_fail_unless(!se6,
				    "An IPv6 session should not exist yet");
	else
		dp_test_fail_unless(se6,
				    "An IPv6 session should already exist");

	decision = npf_nat64_4to6_out(&se6, ifp, npc, &mbuf, npf_flags, &error);

	dp_test_fail_unless(decision == NAT64_DECISION_PASS,
			    "Expected PASS, got %s",
			    nat64_decision_str(decision));

	/* IPv6 session should be created by nat64_hook */
	dp_test_fail_unless(se6, "session is NULL");

	/* simulate end of npf_hook_track */
	if (decision != NAT64_DECISION_DROP && se6) {
		error = npf_session_activate(se6, ifp, npc, mbuf);
		dp_test_fail_unless(error == 0,
				    "error activating output session");
	}

	return se6;
}

/*
 * nat64_a1
 *
 * Calls nat64_hook directly for IPv6 to IPv4 translation.
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_a1, NULL, NULL);
DP_START_TEST(nat64_a1, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc to dp1T0.
	 *
	 * src 2001:101:1::a0a:101 is mapped to 10.10.1.1
	 * dst 2001:101:2::a0a:201 is mapped to 10.10.2.1
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::a0a:101/128 "
		"dst-addr=2001:101:2::a0a:201/128 "
		"handle=nat64("
		"stype=one2one,saddr=10.10.1.1/32,"
		"dtype=one2one,daddr=10.10.2.1/32)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1::a0a:101",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2::a0a:201",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 1001,
				.dport = 2001
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct rte_mbuf  *mbuf1, *mbuf2;
	struct pktmbuf_mdata *mdata;
	uint16_t npf_flags = 0;
	npf_session_t *se6, *se4;

	/*
	 * Call nat64_hook for IPv6 input to simulate a v6 pkt ingress
	 */
	mbuf1 = nat64_nat64_hook_v6_in("dp1T0", &v6_pktA_UDP, &npf_flags,
				       DPT_N64_IN_SC1);

	mdata = pktmbuf_mdata(mbuf1);
	dp_test_fail_unless(mdata, "No packet metadata");

	se6 = mdata->md_nat64.n64_se;
	dp_test_fail_unless(se6, "No IPv6 session in nat64 packet metadata");

	/*
	 * Call nat64_hook for IPv4 output to simulate a v4 pkt egress
	 */
	se4 = nat64_nat64_hook_v4_out("dp2T1", mbuf1, &npf_flags,
				      DPT_N64_OUT_SC1);
	dp_test_fail_unless(se4, "IPv4 session is NULL");

	/*
	 * Verify that dataplane sessions have been created, and that the v6
	 * session is the parent.
	 */
	struct session *ds6 = npf_session_get_dp_session(se6);
	struct session *ds4 = npf_session_get_dp_session(se4);
	bool rv;

	dp_test_fail_unless(ds6 != NULL, "IPv6 dataplane session");
	dp_test_fail_unless(ds4 != NULL, "IPv4 dataplane session");

	struct session *bp4 = session_base_parent(ds4);

	dp_test_fail_unless(bp4 == ds6,
			    "v6 dataplane sess should be parent of v4 sess");

	/*
	 * Repeat nat64_hook for IPv6 input.  No nat64 metadata should be
	 * added to packet.
	 */
	mbuf2 = nat64_nat64_hook_v6_in("dp1T0", &v6_pktA_UDP, &npf_flags,
					DPT_N64_IN_SC4);
	rv = pktmbuf_mdata_invar_exists(mbuf2, PKT_MDATA_INVAR_NAT64),
	dp_test_fail_unless(!rv, "Packet has nat64 metadata");

	/* Note, nat64_hook is not called for repeat packet */


	/***************************************************************
	 * Cleanup
	 */

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/* Cleanup */
	rte_pktmbuf_free(mbuf1);
	rte_pktmbuf_free(mbuf2);

	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*
 * nat64_a2
 *
 * Calls nat64_hook directly for IPv4 to IPv6 translation
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_a2, NULL, NULL);
DP_START_TEST(nat64_a2, test)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat46 rproc to dp2T1
	 *
	 * src 10.10.2.1 is mapped to 2001:101:2::a0a:201
	 * dst 10.10.1.1 is mapped to 2001:101:1::a0a:101
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat46:NAT46_GRP2 20 action=accept "
		"src-addr=10.10.2.1/32 dst-addr=10.10.1.1/32 "
		"handle=nat46("
		"stype=one2one,saddr=2001:101:2::a0a:201/128,"
		"dtype=one2one,daddr=2001:101:1::a0a:101/128)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	/* IPv4 UDP packet */
	struct dp_test_pkt_desc_t v4_pktA_UDP = {
		.text       = "Packet A, IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.2.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 2001,
				.dport = 1001
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct rte_mbuf  *mbuf1, *mbuf2;
	struct pktmbuf_mdata *mdata;
	uint16_t npf_flags = 0;
	npf_session_t *se6, *se4;

	/*
	 * Call nat64_hook for IPv4 input to simulate a v4 pkt ingress
	 */
	mbuf1 = nat64_nat64_hook_v4_in("dp2T1", &v4_pktA_UDP, &npf_flags,
				       DPT_N64_IN_SC1);

	mdata = pktmbuf_mdata(mbuf1);
	dp_test_fail_unless(mdata, "No packet metadata");

	se4 = mdata->md_nat64.n64_se;
	dp_test_fail_unless(se4, "No IPv4 session in nat64 packet metadata");

	/*
	 * Call nat64_hook for IPv6 output to simulate a v6 pkt egress
	 */
	se6 = nat64_nat64_hook_v6_out("dp1T0", mbuf1, &npf_flags,
				      DPT_N64_OUT_SC1);
	dp_test_fail_unless(se6, "IPv6 session is NULL");

	/*
	 * Verify that dataplane sessions have been created, and that the v4
	 * session is the parent.
	 */
	struct session *ds6 = npf_session_get_dp_session(se6);
	struct session *ds4 = npf_session_get_dp_session(se4);
	bool rv;

	dp_test_fail_unless(ds6 != NULL, "IPv6 dataplane session");
	dp_test_fail_unless(ds4 != NULL, "IPv4 dataplane session");

	struct session *bp6 = session_base_parent(ds6);

	dp_test_fail_unless(bp6 == ds4,
			    "v4 dataplane sess should be parent of v6 sess");

	/*
	 * Repeat nat64_hook for IPv4 input.  No nat64 metadata should be
	 * added to packet.
	 */
	mbuf2 = nat64_nat64_hook_v4_in("dp2T1", &v4_pktA_UDP, &npf_flags,
					DPT_N64_IN_SC4);
	rv = pktmbuf_mdata_invar_exists(mbuf2, PKT_MDATA_INVAR_NAT64),
	dp_test_fail_unless(!rv, "Packet has nat64 metadata");

	/* Note, nat64_hook is not called for repeat packet */


	/***************************************************************
	 * Cleanup
	 */

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat46:NAT46_GRP2 20");
	dp_test_npf_commit();

	/* Cleanup */
	rte_pktmbuf_free(mbuf1);
	rte_pktmbuf_free(mbuf2);

	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*
 * nat64_a3
 *
 * Tests orthogonal nat64 and nat46 translations occurring simultaneously on
 * ingress.  We then allow the 6-to-4 packet to reach egresss first, followed
 * by the 4-to-6 packet.
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_a3, NULL, NULL);
DP_START_TEST(nat64_a3, test)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc to dp1T0.
	 *
	 * src 2001:101:1::a0a:101 is mapped to 10.10.1.1
	 * dst 2001:101:2::a0a:201 is mapped to 10.10.2.1
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::a0a:101/128 "
		"dst-addr=2001:101:2::a0a:201/128 "
		"handle=nat64("
		"stype=one2one,saddr=10.10.1.1/32,"
		"dtype=one2one,daddr=10.10.2.1/32)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/*
	 * Add nat46 rproc to dp2T1.  This is the opposite of the above.
	 *
	 * src 10.10.2.1 is mapped to 2001:101:2::a0a:201
	 * dst 10.10.1.1 is mapped to 2001:101:1::a0a:101
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat46:NAT46_GRP2 20 action=accept "
		"src-addr=10.10.2.1/32 dst-addr=10.10.1.1/32 "
		"handle=nat46("
		"stype=one2one,saddr=2001:101:2::a0a:201/128,"
		"dtype=one2one,daddr=2001:101:1::a0a:101/128)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1::a0a:101",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2::a0a:201",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 1001,
				.dport = 2001
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* IPv4 UDP packet */
	struct dp_test_pkt_desc_t v4_pktA_UDP = {
		.text       = "Packet A, IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.2.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 2001,
				.dport = 1001
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct pktmbuf_mdata *mdata;
	uint16_t npf_flags1 = 0;
	uint16_t npf_flags2 = 0;
	struct rte_mbuf  *mbuf4;
	struct rte_mbuf  *mbuf6;
	npf_session_t *se4, *se6, *se;

	/*
	 * IPv6 to IPv4, Input
	 */
	mbuf4 = nat64_nat64_hook_v6_in("dp1T0", &v6_pktA_UDP, &npf_flags1,
					DPT_N64_IN_SC1);

	mdata = pktmbuf_mdata(mbuf4);
	se6 = mdata->md_nat64.n64_se;
	dp_test_fail_unless(se6, "No IPv6 session in nat64 packet metadata");


	/*
	 * IPv4 to IPv6, Input
	 */
	mbuf6 = nat64_nat64_hook_v4_in("dp2T1", &v4_pktA_UDP, &npf_flags2,
				       DPT_N64_IN_SC1);

	mdata = pktmbuf_mdata(mbuf6);
	se4 = mdata->md_nat64.n64_se;
	dp_test_fail_unless(se4, "No IPv4 session in nat64 packet metadata");

	/*
	 * IPv6 to IPv4, Output
	 *
	 * Now if we present the 6-to-4 mbuf to the output, it will find the
	 * session created by the 4-to-6 packet.
	 */
	se = nat64_nat64_hook_v4_out("dp2T1", mbuf4, &npf_flags1,
				     DPT_N64_OUT_SC3);
	dp_test_fail_unless(se, "IPv4 session is NULL");


	/*
	 * IPv4 to IPv6, Output
	 */
	se = nat64_nat64_hook_v6_out("dp1T0", mbuf6, &npf_flags2,
				     DPT_N64_OUT_SC4);
	dp_test_fail_unless(se, "IPv6 session is NULL");


	struct session *ds6 = npf_session_get_dp_session(se6);
	struct session *ds4 = npf_session_get_dp_session(se4);

	dp_test_fail_unless(ds6 != NULL, "IPv6 dataplane session");
	dp_test_fail_unless(ds4 != NULL, "IPv4 dataplane session");

	struct session *bp4 = session_base_parent(ds4);

	/*
	 * The IPv6 to IPv4 packet was the first to reach egress, so the v6
	 * session should be parent.
	 */
	dp_test_fail_unless(bp4 == ds6,
			    "v6 dataplane sess should be parent of v4 sess");

	/***************************************************************
	 * Cleanup
	 */

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat46:NAT46_GRP2 20");
	dp_test_npf_commit();

	/* Cleanup */
	rte_pktmbuf_free(mbuf4);
	rte_pktmbuf_free(mbuf6);

	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;

/*
 * nat64_a4
 *
 * Calls nat64_hook directly for IPv6 to IPv4 translation.
 *
 * This simulates what happens if for whatever reason an egress session is not
 * created by the first packet in the flow.
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_a4, NULL, NULL);
DP_START_TEST(nat64_a4, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc to dp1T0.
	 *
	 * src 2001:101:1::a0a:101 is mapped to 10.10.1.1
	 * dst 2001:101:2::a0a:201 is mapped to 10.10.2.1
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::a0a:101/128 "
		"dst-addr=2001:101:2::a0a:201/128 "
		"handle=nat64("
		"stype=one2one,saddr=10.10.1.1/32,"
		"dtype=one2one,daddr=10.10.2.1/32)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1::a0a:101",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2::a0a:201",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 1001,
				.dport = 2001
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct pktmbuf_mdata *mdata;
	uint16_t npf_flags = 0;
	struct rte_mbuf  *mbuf1, *mbuf2;
	npf_session_t *se6, *se4;

	/*
	 * Call nat64_hook for IPv6 input to simulate a v6 pkt ingress
	 */
	mbuf1 = nat64_nat64_hook_v6_in("dp1T0", &v6_pktA_UDP, &npf_flags,
				       DPT_N64_IN_SC1);

	mdata = pktmbuf_mdata(mbuf1);
	dp_test_fail_unless(mdata, "No packet metadata in initial pkt");

	se6 = mdata->md_nat64.n64_se;
	dp_test_fail_unless(se6, "No IPv6 session in nat64 packet metadata");

	/* Note we do *not* all the output hook here */

	/*
	 * Repeat nat64_hook for IPv6 input.
	 */
	mbuf2 = nat64_nat64_hook_v6_in("dp1T0", &v6_pktA_UDP, &npf_flags,
					DPT_N64_IN_SC3);

	mdata = pktmbuf_mdata(mbuf2);
	dp_test_fail_unless(mdata, "No packet metadata in 2nd pkt");

	se6 = mdata->md_nat64.n64_se;
	dp_test_fail_unless(se6, "No IPv6 session in nat64 packet 2 metadata");

	/*
	 * Call nat64_hook for IPv4 output to simulate v4 pkt egress of mbuf2
	 */
	se4 = nat64_nat64_hook_v4_out("dp2T1", mbuf2, &npf_flags,
				      DPT_N64_OUT_SC1);
	dp_test_fail_unless(se4, "IPv4 session is NULL");

	/*
	 * Verify that dataplane sessions have been created, and that the v6
	 * session is the parent.
	 */
	struct session *ds6 = npf_session_get_dp_session(se6);
	struct session *ds4 = npf_session_get_dp_session(se4);

	dp_test_fail_unless(ds6 != NULL, "IPv6 dataplane session");
	dp_test_fail_unless(ds4 != NULL, "IPv4 dataplane session");

	struct session *bp4 = session_base_parent(ds4);

	dp_test_fail_unless(bp4 == ds6,
			    "v6 dataplane sess should be parent of v4 sess");


	/***************************************************************
	 * Cleanup
	 */

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/* Cleanup */
	rte_pktmbuf_free(mbuf1);
	rte_pktmbuf_free(mbuf2);

	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*
 * IPv6 packet in, IPv4 packet out
 */
static void _nat64_v6_to_v4_udp(uint16_t pre_sport, uint16_t pre_dport,
				uint16_t post_sport, uint16_t post_dport,
				const char *v6_saddr, const char *v6_daddr,
				const char *v4_saddr, const char *v4_daddr,
				const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	/* IPv6 UDP packet */
	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "Packet A, IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = v6_saddr,
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = v6_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = pre_sport,
				.dport = pre_dport
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* UDP packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_UDP = {
		.text       = "Packet A, IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = v4_saddr,
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = v4_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = post_sport,
				.dport = post_dport
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_UDP);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	_dp_test_pak_receive(test_pak, "dp1T0", test_exp,
			     file, func, line);
}

#define nat64_v6_to_v4_udp(_a, _b, _c, _d, _e, _f, _g, _h)		\
	_nat64_v6_to_v4_udp(_a, _b, _c, _d, _e, _f, _g, _h,		\
			    __FILE__, __func__, __LINE__)

/*
 * IPv4 packet in, IPv6 packet out
 */
static void _nat64_v4_to_v6_udp(uint16_t pre_sport, uint16_t pre_dport,
				uint16_t post_sport, uint16_t post_dport,
				const char *v4_saddr, const char *v4_daddr,
				const char *v6_saddr, const char *v6_daddr,
				const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	/* IPv4 UDP packet */
	struct dp_test_pkt_desc_t v4_pktA_UDP = {
		.text       = "Packet A, IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = v4_saddr,
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = v4_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = pre_sport,
				.dport = pre_dport
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	/* IPv6 UDP packet after NAT64 */
	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "Packet A, IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = v6_saddr,
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = v6_daddr,
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = post_sport,
				.dport = post_dport
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	test_pak = dp_test_v4_pkt_from_desc(&v4_pktA_UDP);

	/* Create temp IPv6 packet in order to create test_exp object */
	exp_pak = dp_test_v6_pkt_from_desc(&v6_pktA_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v6_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	_dp_test_pak_receive(test_pak, "dp2T1", test_exp,
			     file, func, line);
}

#define nat64_v4_to_v6_udp(_a, _b, _c, _d, _e, _f, _g, _h)		\
	_nat64_v4_to_v6_udp(_a, _b, _c, _d, _e, _f, _g, _h,		\
			    __FILE__, __func__, __LINE__)


/*
 * ICMP Echo, IPv6 packet in, IPv4 packet out
 */
static void _nat64_v6_to_v4_icmp(uint8_t icmp_type,
				 uint16_t pre_id, uint16_t pre_seq,
				 uint16_t post_id, uint16_t post_seq,
				 const char *v6_saddr, const char *v6_daddr,
				 const char *v4_saddr, const char *v4_daddr,
				 const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	uint8_t v4_type = (icmp_type == ICMP6_ECHO_REQUEST) ?
		ICMP_ECHO : ICMP_ECHOREPLY;

	/* IPv6 ICMP packet */
	struct dp_test_pkt_desc_t v6_pktA_ICMP = {
		.text       = "Packet A, IPv6 ICMP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = v6_saddr,
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = v6_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = icmp_type,
				.code = 0,
				{
					.dpt_icmp_id = pre_id,
					.dpt_icmp_seq = pre_seq,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* ICMP packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_ICMP = {
		.text       = "Packet A, IPv4 ICMP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = v4_saddr,
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = v4_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = v4_type,
				.code = 0,
				{
					.dpt_icmp_id = post_id,
					.dpt_icmp_seq = post_seq,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_ICMP);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_ICMP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_ICMP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	_dp_test_pak_receive(test_pak, "dp1T0", test_exp,
			     file, func, line);
}

#define nat64_v6_to_v4_icmp(_a, _b, _c, _d, _e, _f, _g, _h, _i)		\
	_nat64_v6_to_v4_icmp(_a, _b, _c, _d, _e, _f, _g, _h, _i,	\
			    __FILE__, __func__, __LINE__)

/*
 * ICMP Echo IPv4 packet in, IPv6 packet out
 */
static void _nat64_v4_to_v6_icmp(uint8_t icmp_type,
				 uint16_t pre_id, uint16_t pre_seq,
				 uint16_t post_id, uint16_t post_seq,
				 const char *v4_saddr, const char *v4_daddr,
				 const char *v6_saddr, const char *v6_daddr,
				 const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	uint8_t v6_type = (icmp_type == ICMP_ECHO) ?
		ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY;

	/* IPv4 ICMP packet */
	struct dp_test_pkt_desc_t v4_pktA_ICMP = {
		.text       = "Packet A, IPv4 ICMP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = v4_saddr,
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = v4_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = icmp_type,
				.code = 0,
				{
					.dpt_icmp_id = pre_id,
					.dpt_icmp_seq = pre_seq,
				}
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	/* IPv6 ICMP packet after NAT64 */
	struct dp_test_pkt_desc_t v6_pktA_ICMP = {
		.text       = "Packet A, IPv6 ICMP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = v6_saddr,
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = v6_daddr,
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = v6_type,
				.code = 0,
				{
					.dpt_icmp_id = post_id,
					.dpt_icmp_seq = post_seq,
				}
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	test_pak = dp_test_v4_pkt_from_desc(&v4_pktA_ICMP);

	/* Create temp IPv6 packet in order to create test_exp object */
	exp_pak = dp_test_v6_pkt_from_desc(&v6_pktA_ICMP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v6_pktA_ICMP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	_dp_test_pak_receive(test_pak, "dp2T1", test_exp,
			     file, func, line);
}

#define nat64_v4_to_v6_icmp(_a, _b, _c, _d, _e, _f, _g, _h, _i)		\
	_nat64_v4_to_v6_icmp(_a, _b, _c, _d, _e, _f, _g, _h, _i,	\
			    __FILE__, __func__, __LINE__)


/*************************************************************************
 * nat64_b1, 6-to-4, rfc6052 for src and dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 * IPv6 Src:   WKP + embedded Iv4 address
 * IPv6 Dest:  WKP + embedded Iv4 address
 */

#define LINK_LOCAL  "169.254.0.1/32"
#define LINK_LOCAL6 "fe80::1/128"

DP_DECL_TEST_CASE(npf_nat64, nat64_b1, NULL, NULL);
DP_START_TEST(nat64_b1, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 "
		"handle=nat64("
		"stype=rfc6052,spl=96,"
		"dtype=rfc6052,dpl=96)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 49152,
				   "2001:101:2::a0a:201", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 49152,
				   "10.10.2.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Repeat rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Repeat IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_b2, 6-to-4, one-to-one mapping for src, rfc6052 for dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_b2, NULL, NULL);
DP_START_TEST(nat64_b2, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 "
		"handle=nat64("
		"stype=one2one,saddr=10.10.1.1/32,"
		"dtype=rfc6052,dpl=96,"
		"log=1)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 49152,
				   "2001:101:2::a0a:201", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 49152,
				   "10.10.2.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Repeat rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;

/*************************************************************************
 * nat64_b3, 6-to-4, v4 address-pool for for src, one-to-one for dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_b3, NULL, NULL);
DP_START_TEST(nat64_b3, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 "
		"handle=nat64("
		"stype=overload,saddr=10.10.1.0/28,"
		"dtype=one2one,daddr=10.10.2.1/32)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 49152,
				   "2001:101:2::a0a:201", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 49152,
				   "10.10.2.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 82, 49153, 82,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_b4, 6-to-4, v4 address-pool for for src, one-to-one for dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_b4, NULL, NULL);
DP_START_TEST(nat64_b4, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/* Create address-group */
	dp_test_npf_fw_addr_group_add("ADDR_GRP1");
	dp_test_npf_fw_addr_group_range_add("ADDR_GRP1",
					    "10.10.1.1", "10.10.1.8");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 "
		"handle=nat64("
		"stype=overload,sgroup=ADDR_GRP1,"
		"dtype=one2one,daddr=10.10.2.1/32)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 49152,
				   "2001:101:2::a0a:201", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 49152,
				   "10.10.2.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 82, 49153, 82,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	dp_test_npf_fw_addr_group_range_del("ADDR_GRP1",
					    "10.10.1.1", "10.10.1.8");
	dp_test_npf_fw_addr_group_del("ADDR_GRP1");

	/*
	 * Cleanup
	 */
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_b5, 6-to-4, v4 address-pool for for src, one-to-one for dst
 *
 * Match on dest addr and port.  Translate dest port 80 to 8080.
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_b5, NULL, NULL);
DP_START_TEST(nat64_b5, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 dst-port=80 "
		"handle=nat64("
		"stype=overload,srange=10.10.1.1-10.10.1.8,"
		"dtype=one2one,daddr=10.10.2.1/32,dport=8080)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 8080,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 49152,
				   "2001:101:2::a0a:201", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 49152,
				   "10.10.2.1", 8080,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(8080, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 8080,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");


} DP_END_TEST;


/*************************************************************************
 * nat64_b6, 6-to-4, one-to-one mapping for src, rfc6052 for dst
 *
 * Variation: SNAT masquerade on output in fwds direction
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_b6, NULL, NULL);
DP_START_TEST(nat64_b6, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 "
		"handle=nat64("
		"stype=one2one,saddr=10.10.1.1/32,"
		"dtype=rfc6052,dpl=96)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/*
	 * SNAT
	 *
	 * Src addr: 2001:101:1::a0a:101 -> 10.10.1.1 -> 10.10.2.254
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= "10.10.1.1",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade",
		.trans_port	= NULL
	};
	dp_test_npf_snat_add(&snat, true);

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.2.254", "10.10.2.1");

	/*
	 * Verify npf sessions.  We still only expect 2 sessions.  SNAT and
	 * the nat64 IPv4 egress session will be one in the same.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 49152,
				   "2001:101:2::a0a:201", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 49152,
				   "10.10.2.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_nat_session_verify(NULL,
				       "10.10.1.1", 49152,
				       "10.10.2.1", 80,
				       IPPROTO_UDP,
				       "10.10.2.254", 49152,
				       TRANS_TYPE_NATOUT,
				       "dp2T1",
				       SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				       true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.2.254",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.2.254", "10.10.2.1");

	/* Delete snat */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;

/*************************************************************************
 * nat64_b7, 6-to-4, one-to-one mapping for src, rfc6052 for dst
 *
 * Variation: Stateful firewall on input
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_b7, NULL, NULL);
DP_START_TEST(nat64_b7, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 "
		"handle=nat64("
		"stype=one2one,saddr=10.10.1.1/32,"
		"dtype=rfc6052,dpl=96)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATEFUL,
			.npf      = ""
		},
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "FW_IN",
		.enable = 1,
		.attach_point   = "dp1T0",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rset
	};
	dp_test_npf_fw_add(&fw, false);

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/*
	 * Verify npf sessions.  We still only expect 2 sessions.  Stateful
	 * input firewall and the nat64 IPv6 ingress session will be one in the
	 * same.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 49152,
				   "2001:101:2::a0a:201", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 49152,
				   "10.10.2.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	dp_test_npf_fw_del(&fw, false);

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;

/*************************************************************************
 * nat64_b8, 6-to-4, one-to-one mapping for src, rfc6052 for dst
 *
 * Variation: Stateful firewall on output
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_b8, NULL, NULL);
DP_START_TEST(nat64_b8, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 "
		"handle=nat64("
		"stype=one2one,saddr=10.10.1.1/32,"
		"dtype=rfc6052,dpl=96)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATEFUL,
			.npf      = ""
		},
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rset
	};
	dp_test_npf_fw_add(&fw, false);

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/*
	 * Verify npf sessions.  We still only expect 2 sessions.  Stateful
	 * output firewall and the nat64 IPv4 egress session will be one in the
	 * same.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 49152,
				   "2001:101:2::a0a:201", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 49152,
				   "10.10.2.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(80, 49152, 80, 49152,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(49152, 80, 49152, 80,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	dp_test_npf_fw_del(&fw, false);

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_b9, ICMP, 6-to-4, v4 one-to-one for for src, one-to-one for dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_b9, NULL, NULL);
DP_START_TEST(nat64_b9, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat64 rproc
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat64:NAT64_GRP1 10 action=accept "
		"src-addr=2001:101:1::/96 dst-addr=2001:101:2::/96 "
		"handle=nat64("
		"stype=one2one,saddr=10.10.1.1/32,"
		"dtype=one2one,daddr=10.10.2.1/32)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	/* 1. Rcv IPv6 ICMP Req pkt on dp1T0 */
	nat64_v6_to_v4_icmp(ICMP6_ECHO_REQUEST, 1000, 1, 1000, 1,
			    "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			    "10.10.1.1", "10.10.2.1");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "2001:101:1::a0a:101", 1000,
				   "2001:101:2::a0a:201", 1000,
				   IPPROTO_ICMPV6, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "10.10.1.1", 1000,
				   "10.10.2.1", 1000,
				   IPPROTO_ICMP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* 2. Rcv IPv4 ICMP pkt on dp2T1 */
	nat64_v4_to_v6_icmp(ICMP_ECHOREPLY, 1000, 1, 1000, 1,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* 3. Repeat IPv6 ICMP pkt on dp1T0 */
	nat64_v6_to_v4_icmp(ICMP6_ECHO_REQUEST, 1000, 2, 1000, 2,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* 4. Rcv IPv4 ICMP pkt on dp2T1 */
	nat64_v4_to_v6_icmp(ICMP_ECHOREPLY, 1000, 2, 1000, 2,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT10 nat64 nat64:NAT64_GRP1");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat64:NAT64_GRP1 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_cleanup();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_c1, 4-to-6, rfc6052 for src and dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */

DP_DECL_TEST_CASE(npf_nat64, nat64_c1, NULL, NULL);
DP_START_TEST(nat64_c1, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat46 rproc to dpT21
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat46:NAT46_GRP2 10 action=accept "
		"dst-addr=10.10.1.1/32 "
		"handle=nat46("
		"stype=rfc6052,saddr=2001:101:2::/96,"
		"dtype=rfc6052,daddr=2001:101:1::/96)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 80,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "10.10.2.1", 49152,
				   "10.10.1.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "2001:101:2::a0a:201", 49152,
				   "2001:101:1::a0a:101", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(80, 49152, 80, 49152,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Repeat Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 80,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Repeat IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(80, 49152, 80, 49152,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat46:NAT46_GRP2 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_c2, 4-to-6, rfc6052 for src, one-to-one mapping for dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */

DP_DECL_TEST_CASE(npf_nat64, nat64_c2, NULL, NULL);
DP_START_TEST(nat64_c2, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat46 rproc to dpT21
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat46:NAT46_GRP2 10 action=accept "
		"dst-addr=10.10.1.1/32 "
		"handle=nat46("
		"stype=rfc6052,saddr=2001:101:2::/96,"
		"dtype=one2one,daddr=2001:101:1::a0a:101/128,log=1)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 80,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "10.10.2.1", 49152,
				   "10.10.1.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "2001:101:2::a0a:201", 49152,
				   "2001:101:1::a0a:101", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(80, 49152, 80, 49152,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Repeat Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 80,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat46:NAT46_GRP2 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_c3, 4-to-6, one-to-one for src, one-to-one for dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */

DP_DECL_TEST_CASE(npf_nat64, nat64_c3, NULL, NULL);
DP_START_TEST(nat64_c3, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat46 rproc to dpT21
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat46:NAT46_GRP2 10 action=accept "
		"src-addr=10.10.2.1/32 "
		"dst-addr=10.10.1.1/32 "
		"handle=nat46("
		"stype=one2one,saddr=2001:101:2::a0a:201/128,"
		"dtype=one2one,daddr=2001:101:1::a0a:101/128)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 80,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "10.10.2.1", 49152,
				   "10.10.1.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "2001:101:2::a0a:201", 49152,
				   "2001:101:1::a0a:101", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(80, 49152, 80, 49152,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Repeat Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 80,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat46:NAT46_GRP2 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_c4, 4-to-6, one-to-one for src, one-to-one for dst
 *
 * Variation: DNAT on input
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */

DP_DECL_TEST_CASE(npf_nat64, nat64_c4, NULL, NULL);
DP_START_TEST(nat64_c4, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat46 rproc to dpT21
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat46:NAT46_GRP2 10 action=accept "
		"src-addr=10.10.2.1/32 "
		"dst-addr=10.10.1.1/32 "
		"handle=nat46("
		"stype=one2one,saddr=2001:101:2::a0a:201/128,"
		"dtype=one2one,daddr=2001:101:1::a0a:101/128)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	/*
	 * DNAT
	 *
	 * Dst addr: 10.10.1.254 -> 10.10.1.1 -> 2001:101:1::a0a:101
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= NAT_NULL_PROTO,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "10.10.1.254",
		.to_port	= NULL,
		.trans_addr	= "10.10.1.1",
		.trans_port	= NULL
	};
	dp_test_npf_dnat_add(&dnat, true);

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 80,
			   "10.10.2.1", "10.10.1.254",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/*
	 * Verify npf sessions.  We still only expect 2 sessions.  DNAT and
	 * the nat64 IPv4 ingress session will be one in the same.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "10.10.2.1", 49152,
				   "10.10.1.254", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_nat_session_verify(NULL,
				       "10.10.2.1", 49152,
				       "10.10.1.254", 80,
				       IPPROTO_UDP,
				       "10.10.1.1", 80,
				       TRANS_TYPE_NATIN,
				       "dp2T1",
				       SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				       true);
	dp_test_npf_session_verify(NULL,
				   "2001:101:2::a0a:201", 49152,
				   "2001:101:1::a0a:101", 80,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(80, 49152, 80, 49152,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.254", "10.10.2.1");

	/* Repeat Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 80,
			   "10.10.2.1", "10.10.1.254",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Delete dnat */
	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat46:NAT46_GRP2 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_c5, 4-to-6, one-to-one for src, one-to-one for dst
 *
 * Match on dest addr and port.  Translate dest port 80 to 8080.
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */

DP_DECL_TEST_CASE(npf_nat64, nat64_c5, NULL, NULL);
DP_START_TEST(nat64_c5, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat46 rproc to dpT21
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat46:NAT46_GRP2 10 action=accept "
		"src-addr=10.10.2.1/32 "
		"dst-addr=10.10.1.1/32 dst-port=80 "
		"handle=nat46("
		"stype=one2one,saddr=2001:101:2::a0a:201/128,"
		"dtype=one2one,daddr=2001:101:1::a0a:101/128,dport=8080)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	/* Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 8080,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "10.10.2.1", 49152,
				   "10.10.1.1", 80,
				   IPPROTO_UDP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "2001:101:2::a0a:201", 49152,
				   "2001:101:1::a0a:101", 8080,
				   IPPROTO_UDP, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* Rcv IPv6 UDP pkt on dp1T0 */
	nat64_v6_to_v4_udp(8080, 49152, 80, 49152,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Repeat Rcv IPv4 UDP pkt on dp2T1 */
	nat64_v4_to_v6_udp(49152, 80, 49152, 8080,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat46:NAT46_GRP2 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*************************************************************************
 * nat64_c9, ICMP, 4-to-6, one-to-one for src, one-to-one for dst
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 *
 */

DP_DECL_TEST_CASE(npf_nat64, nat64_c9, NULL, NULL);
DP_START_TEST(nat64_c9, test1)
{
	/*
	 * IPv6 on dp1T0
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");

	/*
	 * IPv4 on dp2T1
	 */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Add nat46 rproc to dpT21
	 */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut add nat46:NAT46_GRP2 10 action=accept "
		"src-addr=10.10.2.1/32 "
		"dst-addr=10.10.1.1/32 "
		"handle=nat46("
		"stype=one2one,saddr=2001:101:2::a0a:201/128,"
		"dtype=one2one,daddr=2001:101:1::a0a:101/128)");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(
		false,
		"npf-ut attach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	/* 1. Rcv IPv4 ICMP pkt on dp2T1 */
	nat64_v4_to_v6_icmp(ICMP_ECHO, 1000, 1, 1000, 1,
			    "10.10.2.1", "10.10.1.1",
			    "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/*
	 * Verify npf sessions.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify(NULL,
				   "10.10.2.1", 1000,
				   "10.10.1.1", 1000,
				   IPPROTO_ICMP, "dp2T1",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);
	dp_test_npf_session_verify(NULL,
				   "2001:101:2::a0a:201", 1000,
				   "2001:101:1::a0a:101", 1000,
				   IPPROTO_ICMPV6, "dp1T0",
				   SE_ACTIVE | SE_PASS, SE_FLAGS_MASK,
				   true);

	/* 2. Rcv IPv6 ICMP pkt on dp1T0 */
	nat64_v6_to_v4_icmp(ICMP6_ECHO_REPLY, 1000, 1, 1000, 1,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* 3. Repeat Rcv IPv4 ICMP pkt on dp2T1 */
	nat64_v4_to_v6_icmp(ICMP_ECHO, 1000, 2, 1000, 2,
			   "10.10.2.1", "10.10.1.1",
			   "2001:101:2::a0a:201", "2001:101:1::a0a:101");

	/* 4. Rcv IPv6 ICMP pkt on dp1T0 */
	nat64_v6_to_v4_icmp(ICMP6_ECHO_REPLY, 1000, 2, 1000, 2,
			   "2001:101:1::a0a:101", "2001:101:2::a0a:201",
			   "10.10.1.1", "10.10.2.1");

	/* Delete nat64 rule and rproc */
	dp_test_npf_cmd_fmt(
		false,
		"npf-ut detach interface:dpT21 nat46 nat46:NAT46_GRP2");
	dp_test_npf_commit();

	dp_test_npf_cmd_fmt(false, "npf-ut delete nat46:NAT46_GRP2 10");
	dp_test_npf_commit();

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");

} DP_END_TEST;


/*
 * Nat64 (prefix96)
 *
 *                        inside         outside
 *
 *        2001:101:1::a0a:1fe/96 +-----+ 2001:101:2::a0a:2fe/96
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *   IPv6  ----------------------| uut |--------------------------- IPv4
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_96, NULL, NULL);
DP_START_TEST(nat64_96, test1)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/* IPv6 UDP packet */
	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "Packet A, IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1::a0a:101",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2::a0a:201",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* UDP packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_UDP = {
		.text       = "Packet A, IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* IPv6 PING packet */
	struct dp_test_pkt_desc_t v6_pktA_PING = {
		.text       = "Packet A, IPv6 PING",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1::a0a:101",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2::a0a:201",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{
					.dpt_icmp_id = 100,
					.dpt_icmp_seq = 200,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* PING packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_PING = {
		.text       = "Packet A, IPv4 PING",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = 100,
					.dpt_icmp_seq = 200,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2001:101:2::a0a:2fe/96");

	dp_test_netlink_add_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Translate any packets from prefix 2001:101:1::/96 to prefix
	 * 2001:101:2::/96 that are received on dp1T0
	 */
	const struct dp_test_npf_nat64_rule_t rule96 = {
		.rule		= "1",
		.ifname		= v6_pktA_UDP.rx_intf,
		.from_addr	= "2001:101:1::/96",
		.to_addr	= "2001:101:2::/96",
		.spl		= 96,
		.dpl		= 96
	};
	dp_test_npf_nat64_add(&rule96, true);
	dp_test_npf_commit();

	/*****************************************************************
	 * Forwards flow, UDP IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 UDP packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_UDP);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 * Note, this is a normal session, not a nat session
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_UDP,
					v4_pktA_UDP.tx_intf,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*****************************************************************
	 * Reverse flow, UDP IPv4 -> IPv6
	 *****************************************************************/

	/*
	 * Create IPv4 packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(&v4_pktA_UDP);

	/* Create temp IPv6 UDP packet in order to create test_exp object */
	exp_pak = dp_test_reverse_v6_pkt_from_desc(&v6_pktA_UDP);
	test_exp = dp_test_reverse_exp_from_desc(exp_pak, &v6_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/*
	 * Clear the session and counters.
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_clear("nat64");


	/*****************************************************************
	 * Forwards flow PING, IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 PING packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_PING);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_PING);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 * Note, this is a normal session, not a nat session
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_PING,
					v4_pktA_PING.tx_intf,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*****************************************************************
	 * Reverse flow, PING IPv4 -> IPv6
	 *****************************************************************/

	/*
	 * Create IPv4 PING packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(&v4_pktA_PING);

	/* Create temp IPv6 PING packet in order to create test_exp object */
	exp_pak = dp_test_reverse_v6_pkt_from_desc(&v6_pktA_PING);
	test_exp = dp_test_reverse_exp_from_desc(exp_pak, &v6_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/*
	 * Clear the session and counters.
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_clear("nat64");

	/*****************************************************************
	 * Repeat but with a stateful firewall also present
	 *****************************************************************/

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = ""
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW2_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};
	dp_test_npf_fw_add(&fw, false);

	/*****************************************************************
	 * Repeat forwards flow pkt, UDP IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 UDP packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_UDP);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_UDP,
				       v4_pktA_UDP.tx_intf,
				       SE_ACTIVE, SE_FLAGS_AE, true);
	/*
	 * Clear the session and counters.
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_clear("nat64");

	/*****************************************************************
	 * Repeat forwards flow pkt, PING IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 PING packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_PING);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_PING);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_PING,
				       v4_pktA_PING.tx_intf,
				       SE_ACTIVE, SE_FLAGS_AE, true);

	/*
	 * Cleanup
	 */
	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_npf_nat64_del(&rule96, true);
	dp_test_npf_commit();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1::a0a:101",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2001:101:2::a0a:2fe/96");

} DP_END_TEST;


/*
 * Nat64 (prefix64)
 *
 *
 *                       inside          outside
 *
 *  2001:101:1:0:a:a01:fe00:2/64 +-----+ 2001:101:2:0:a:a02:fe00:2/64
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *         ----------------------| uut |-----------------------------
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_64, NULL, NULL);
DP_START_TEST(nat64_64, test1)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/* IPv6 UDP packet */
	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "Packet A, IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1:0:a:a01:100:1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2:0:a:a02:100:1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* UDP packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_UDP = {
		.text       = "Packet A, IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* IPv6 PING packet */
	struct dp_test_pkt_desc_t v6_pktA_PING = {
		.text       = "Packet A, IPv6 PING",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1:0:a:a01:100:1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2:0:a:a02:100:1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{
					.dpt_icmp_id = 300,
					.dpt_icmp_seq = 400,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* PING packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_PING = {
		.text       = "Packet A, IPv4 PING",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = 300,
					.dpt_icmp_seq = 400,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",
					     "2001:101:1:0:a:a01:fe00:fe/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1",
					     "2001:101:2:0:a:a02:fe00:fe/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:101:1:0:a:a01:100:1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Translate any packets from prefix 2001:101:1::/64 to prefix
	 * 2001:101:2::/64 that are received on dp1T0
	 */
	const struct dp_test_npf_nat64_rule_t rule64 = {
		.rule		= "1",
		.ifname		= v6_pktA_UDP.rx_intf,
		.from_addr	= "2001:101:1::/64",
		.to_addr	= "2001:101:2::/64",
		.spl		= 64,
		.dpl		= 64
	};
	dp_test_npf_nat64_add(&rule64, true);
	dp_test_npf_commit();

	/*****************************************************************
	 * Forwards flow, UDP IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 UDP packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_UDP);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_UDP,
				       v4_pktA_UDP.tx_intf,
				       SE_ACTIVE, SE_FLAGS_AE, true);

	/*****************************************************************
	 * Reverse flow, UDP IPv4 -> IPv6
	 *****************************************************************/

	/*
	 * Create IPv4 packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(&v4_pktA_UDP);

	exp_pak = dp_test_reverse_v6_pkt_from_desc(&v6_pktA_UDP);
	test_exp = dp_test_reverse_exp_from_desc(exp_pak, &v6_pktA_UDP);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/*
	 * Clear the session and counters.
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_clear("nat64");


	/*****************************************************************
	 * Forwards flow PING, IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 PING packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_PING);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_PING);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_PING,
					v4_pktA_PING.tx_intf,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*****************************************************************
	 * Reverse flow, PING IPv4 -> IPv6
	 *****************************************************************/

	/*
	 * Create IPv4 PING packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(&v4_pktA_PING);

	/* Create temp IPv6 PING packet in order to create test_exp object */
	exp_pak = dp_test_reverse_v6_pkt_from_desc(&v6_pktA_PING);
	test_exp = dp_test_reverse_exp_from_desc(exp_pak, &v6_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_nat64_del(&rule64, true);
	dp_test_npf_commit();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1:0:a:a01:100:1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0",
					     "2001:101:1:0:a:a01:fe00:fe/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1",
					     "2001:101:2:0:a:a02:fe00:fe/64");

} DP_END_TEST;

/*
 * Nat64 (prefix56)
 *
 *
 *                       inside          outside
 *
 *     2001:101:1:a:a:1fe:0:2/56 +-----+ 2001:101:2:a:a:2fe:0:2/56
 *                10.10.1.254/24 |     | 10.10.2.254/24
 *         ----------------------| uut |-----------------------------
 *                         dp1T0 |     | dp2T1
 *                               +-----+
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_56, NULL, NULL);
DP_START_TEST(nat64_56, test1)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/* IPv6 UDP packet */
	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "Packet A, IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1:a:a:101:0:1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2:a:a:201:0:1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* UDP packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_UDP = {
		.text       = "Packet A, IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* IPv6 PING packet */
	struct dp_test_pkt_desc_t v6_pktA_PING = {
		.text       = "Packet A, IPv6 PING",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1:a:a:101:0:1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2:a:a:201:0:1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{
					.dpt_icmp_id = 500,
					.dpt_icmp_seq = 600,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* PING packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_PING = {
		.text       = "Packet A, IPv4 PING",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = 500,
					.dpt_icmp_seq = 600,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",
					     "2001:101:1:a:a:1fe:0:fe/56");
	dp_test_nl_add_ip_addr_and_connected("dp2T1",
					     "2001:101:2:a:a:2fe:0:fe/56");

	dp_test_netlink_add_neigh("dp1T0", "2001:101:1:a:a:101:0:1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Translate any packets from prefix 2001:101:1::/56 to prefix
	 * 2001:101:2::/56 that are received on dp1T0
	 */
	const struct dp_test_npf_nat64_rule_t rule56 = {
		.rule		= "1",
		.ifname		= v6_pktA_UDP.rx_intf,
		.from_addr	= "2001:101:1::/56",
		.to_addr	= "2001:101:2::/56",
		.spl		= 56,
		.dpl		= 56
	};
	dp_test_npf_nat64_add(&rule56, true);
	dp_test_npf_commit();

	/*****************************************************************
	 * Forwards flow, UDP IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 UDP packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_UDP);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_UDP,
				       v4_pktA_UDP.tx_intf,
				       SE_ACTIVE, SE_FLAGS_AE, true);

	/*****************************************************************
	 * Reverse flow, UDP IPv4 -> IPv6
	 *****************************************************************/

	/*
	 * Create UDP IPv4 packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(&v4_pktA_UDP);

	/* Create temp IPv6 UDP packet in order to create test_exp object */
	exp_pak = dp_test_reverse_v6_pkt_from_desc(&v6_pktA_UDP);
	test_exp = dp_test_reverse_exp_from_desc(exp_pak, &v6_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/*
	 * Clear the session and counters.
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_clear("nat64");


	/*****************************************************************
	 * Forwards flow PING, IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 PING packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_PING);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_PING);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 * Note, this is a normal session, not a nat session
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_PING,
					v4_pktA_PING.tx_intf,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*****************************************************************
	 * Reverse flow, PING IPv4 -> IPv6
	 *****************************************************************/

	/*
	 * Create IPv4 PING packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(&v4_pktA_PING);

	/* Create temp IPv6 PING packet in order to create test_exp object */
	exp_pak = dp_test_reverse_v6_pkt_from_desc(&v6_pktA_PING);
	test_exp = dp_test_reverse_exp_from_desc(exp_pak, &v6_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_nat64_del(&rule56, true);
	dp_test_npf_commit();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1:a:a:101:0:1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0",
					     "2001:101:1:a:a:1fe:0:fe/56");
	dp_test_nl_del_ip_addr_and_connected("dp2T1",
					     "2001:101:2:a:a:2fe:0:fe/56");

} DP_END_TEST;

/*
 * Nat64 (prefix48)
 *
 *
 *                         inside         outside
 *
 *   2001:101:1:a0a:1:fe00:0:2/48 +-----+ 2001:101:2:a0a:2:fe00:0:2/48
 *                 10.10.1.254/24 |     | 10.10.2.254/24
 *       -------------------------| uut |-----------------------------
 *                          dp1T0 |     | dp2T1
 *                                +-----+
 */
DP_DECL_TEST_CASE(npf_nat64, nat64_48, NULL, NULL);
DP_START_TEST(nat64_48, test1)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *exp_pak;

	/* IPv6 UDP packet */
	struct dp_test_pkt_desc_t v6_pktA_UDP = {
		.text       = "Packet A, IPv6 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1:a0a:1:100:0:1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2:a0a:2:100:0:1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* UDP packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_UDP = {
		.text       = "Packet A, IPv4 UDP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* IPv6 PING packet */
	struct dp_test_pkt_desc_t v6_pktA_PING = {
		.text       = "Packet A, IPv6 PING",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = "2001:101:1:a0a:1:100:0:1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2001:101:2:a0a:2:100:0:1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = ICMP6_ECHO_REQUEST,
				.code = 0,
				{
					.dpt_icmp_id = 700,
					.dpt_icmp_seq = 800,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* PING packet after NAT 6-4 */
	struct dp_test_pkt_desc_t v4_pktA_PING = {
		.text       = "Packet A, IPv4 PING",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "10.10.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "10.10.2.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = ICMP_ECHO,
				.code = 0,
				{
					.dpt_icmp_id = 700,
					.dpt_icmp_seq = 800,
				}
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/*
	 * Setup interfaces
	 */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0",
					     "2001:101:1:a0a:1:fe00:0:fe/48");
	dp_test_nl_add_ip_addr_and_connected("dp2T1",
					     "2001:101:2:a0a:2:fe00:0:fe/48");

	dp_test_netlink_add_neigh("dp1T0", "2001:101:1:a0a:1:100:0:1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	/*
	 * Translate any packets from prefix 2001:101:1::/48 to prefix
	 * 2001:101:2::/48 that are received on dp1T0
	 */
	const struct dp_test_npf_nat64_rule_t rule48 = {
		.rule		= "1",
		.ifname		= v6_pktA_UDP.rx_intf,
		.from_addr	= "2001:101:1::/48",
		.to_addr	= "2001:101:2::/48",
		.spl		= 48,
		.dpl		= 48
	};
	dp_test_npf_nat64_add(&rule48, true);
	dp_test_npf_commit();

	/*****************************************************************
	 * Forwards flow, UDP IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 UDP packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_UDP);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_UDP,
				       v4_pktA_UDP.tx_intf,
				       SE_ACTIVE, SE_FLAGS_AE, true);

	/*****************************************************************
	 * Reverse flow, UDP IPv4 -> IPv6
	 *****************************************************************/

	/*
	 * Create UDP IPv4 packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(&v4_pktA_UDP);

	/* Create temp IPv6 UDP packet in order to create test_exp object */
	exp_pak = dp_test_reverse_v6_pkt_from_desc(&v6_pktA_UDP);
	test_exp = dp_test_reverse_exp_from_desc(exp_pak, &v6_pktA_UDP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/*
	 * Clear the session and counters.
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_clear("nat64");


	/*****************************************************************
	 * Forwards flow PING, IPv6 -> IPv4
	 *****************************************************************/

	/*
	 * Create IPv6 PING packet
	 */
	test_pak = dp_test_v6_pkt_from_desc(&v6_pktA_PING);

	/* Create temp IPv4 packet in order to create test_exp object */
	exp_pak = dp_test_v4_pkt_from_desc(&v4_pktA_PING);
	test_exp = dp_test_exp_from_desc(exp_pak, &v4_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Verify npf session.  Session exists on the outbound interface.
	 * Note, this is a normal session, not a nat session
	 */
	dp_test_npf_session_count_verify(2);
	dp_test_npf_session_verify_desc(NULL, &v4_pktA_PING,
					v4_pktA_PING.tx_intf,
					SE_ACTIVE, SE_FLAGS_AE, true);

	/*****************************************************************
	 * Reverse flow, PING IPv4 -> IPv6
	 *****************************************************************/

	/*
	 * Create IPv4 PING packet
	 */
	test_pak = dp_test_reverse_v4_pkt_from_desc(&v4_pktA_PING);

	/* Create temp IPv6 PING packet in order to create test_exp object */
	exp_pak = dp_test_reverse_v6_pkt_from_desc(&v6_pktA_PING);
	test_exp = dp_test_reverse_exp_from_desc(exp_pak, &v6_pktA_PING);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(test_pak, "dp2T1", test_exp);

	/*
	 * Cleanup
	 */
	dp_test_npf_clear_sessions();
	dp_test_npf_nat64_del(&rule48, true);
	dp_test_npf_commit();

	dp_test_netlink_del_neigh("dp1T0", "2001:101:1:a0a:1:100:0:1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "10.10.2.1",
				  "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.10.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "10.10.2.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0",
					     "2001:101:1:a0a:1:fe00:0:fe/48");
	dp_test_nl_del_ip_addr_and_connected("dp2T1",
					     "2001:101:2:a0a:2:fe00:0:fe/48");

} DP_END_TEST;

