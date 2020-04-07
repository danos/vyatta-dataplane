/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT ARP tests
 */

#include <net/if_arp.h>
#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "arp.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pb.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_cmd_state.h"

#include "protobuf/GArpConfig.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

/*
 * Arp for interface address
 *    - no existing arp entry - create and reply
 *    - existing entry same - no change and reply
 *    - existing entry different peer mac - update and reply
 * Arp for address on other int
 *    - Ignore.
 * Arp for add on no int
 *    - Ignore.
 * unsolicited Arp response
 *    - check arp table not updated.
 *
 */

#define IIFNAME "dp1T0"
#define IIFNAME2 "dp1T1"
#define PEER_MAC "be:ef:60:d:f0:d"
#define PEER_MAC2 "be:ef:c0:1:f0:d"
#define BCAST_MAC "ff:ff:ff:ff:ff:ff"
#define PEER_IP "1.1.1.2"
#define OUR_IP  "1.1.1.1"
#define OUR_IP2  "2.2.2.1"
#define NOT_OUR_IP  "1.1.1.3"
#define DONTCARE_MAC "0:0:0:0:0:0"

struct ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	struct ether_addr arp_sha;      /* sender hardware address */
	in_addr_t arp_spa;		/* sender protocol address */
	struct ether_addr arp_tha;      /* target hardware address */
	in_addr_t arp_tpa;		/* target protocol address */
} __attribute__ ((__packed__));

static struct ether_addr peer_mac, peer_mac2;
static in_addr_t peer_ip, not_our_ip;
static const char *iifmac;
static struct arp_stats zero_arp_stats;

static void
dp_test_zero_arp_stats(const char *ifname)
{
	int ifindex;
	struct ifnet *ifp;
	struct vrf *vrf;

	ifindex = dp_test_intf_name2index(ifname);
	ifp = dp_ifnet_byifindex(ifindex);
	vrf = dp_vrf_get_rcu_from_external(ifp->if_vrfid);

	if (vrf)
		memset(&vrf->v_arpstat, 0, sizeof(vrf->v_arpstat));
}

#define DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(ifname, stat, value)		\
	{								\
		int ifindex;						\
		struct ifnet *ifp;					\
		struct vrf *vrf;					\
									\
		ifindex = dp_test_intf_name2index(ifname);		\
		ifp = dp_ifnet_byifindex(ifindex);			\
		vrf = dp_vrf_get_rcu_from_external(ifp->if_vrfid);	\
									\
		if (vrf) {						\
			dp_test_fail_unless(vrf->v_arpstat.stat == value, \
					    "\nIncorrect ARP stats counter " \
					    #stat			\
					    " %"PRIu64" - should be %d\n", \
					    vrf->v_arpstat.stat, (value)); \
			vrf->v_arpstat.stat = 0;			\
		}							\
	}

static void _dp_test_verify_all_arp_stats_zero(const char *ifname,
					       const char *file,
					       int line)
{
	int ifindex;
	struct ifnet *ifp;
	struct vrf *vrf;

	ifindex = dp_test_intf_name2index(ifname);
	ifp = dp_ifnet_byifindex(ifindex);
	vrf = dp_vrf_get_rcu_from_external(ifp->if_vrfid);

	if (vrf) {
		_dp_test_fail_unless(
			memcmp(&vrf->v_arpstat,
			       &zero_arp_stats,
			       sizeof(vrf->v_arpstat)) == 0,
			file, line,
			"\nARP stats incorrectly incremented");
	}
}
#define dp_test_verify_all_arp_stats_zero(ifname) \
	_dp_test_verify_all_arp_stats_zero(ifname, __FILE__, __LINE__)

static uint16_t setup_count, teardown_count;
/*
 * Setup for all tests
 */
static void
_dp_test_arp_setup(const char *file, const int line)
{
	static bool one_time;

	if (!one_time) {
		_dp_test_fail_unless(ether_aton_r(PEER_MAC, &peer_mac) != NULL,
				     file, line,
				     "failed to parse mac address %s",
				     PEER_MAC);
		_dp_test_fail_unless(ether_aton_r(PEER_MAC2, &peer_mac2) !=
				     NULL,
				     file, line,
				     "failed to parse mac address %s",
				     PEER_MAC2);
		_dp_test_fail_unless(inet_pton(AF_INET, PEER_IP, &peer_ip) == 1,
				     file, line,
				     "failed to parse ip address %s", PEER_IP);
		_dp_test_fail_unless(inet_pton(AF_INET, NOT_OUR_IP, &not_our_ip)
				     == 1,
				     file, line,
				     "failed to parse ip address %s",
				     NOT_OUR_IP);
		one_time = true;
	}

	memset(&zero_arp_stats, 0, sizeof(zero_arp_stats));
	dp_test_zero_arp_stats(IIFNAME);

	setup_count++;
	/* Make sure _teardown has been called for every _setup */
	_dp_test_fail_unless(setup_count == teardown_count + 1,
			     file, line,
			     "setup: setup %d teardown %d mismatch",
			     setup_count, teardown_count);
	iifmac = dp_test_intf_name2mac_str(IIFNAME);
}
#define dp_test_arp_setup() \
	_dp_test_arp_setup(__FILE__, __LINE__)

static void
_dp_test_arp_teardown(const char *file, const int line)
{
	teardown_count++;
	/* Make sure _setup has been called for every _teardown */
	_dp_test_fail_unless(setup_count == teardown_count,
			     file, line,
			    "teardown: setup %d teardown %d mismatch",
			    setup_count, teardown_count);
	_dp_test_verify_all_arp_stats_zero(IIFNAME, file, line);
	iifmac = NULL;
}
#define dp_test_arp_teardown() \
	_dp_test_arp_teardown(__FILE__, __LINE__)

DP_DECL_TEST_SUITE(arp_suite);

DP_DECL_TEST_CASE(arp_suite, valid_arp, NULL, NULL);

/*
 * Test that ARP request for interface address is responded to.
 * Verify that sender's entry is updated in ARP table.
 */
DP_START_TEST(valid_arp, request_ouraddr_rx_int)
{

	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *exp_pak;

	dp_test_arp_setup();
	dp_test_nl_add_ip_addr_and_connected(IIFNAME, OUR_IP "/24");

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, "", true);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC, BCAST_MAC,
					  PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, IIFNAME);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	/*
	 * Now there should be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, PEER_MAC, false);

	/*
	 * 3 (and ONLY 3!) counters should have incrememted.
	 */
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/*
	 * Do it again and check ARP entry is still there.
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC, BCAST_MAC,
					  PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, IIFNAME);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	/*
	 * Should still be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, PEER_MAC, false);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/*
	 * Send another ARP request from peer but change its
	 * mac address. Check that we update it.
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC2, BCAST_MAC,
					  PEER_MAC2, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC2,
					 iifmac, PEER_MAC2,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, IIFNAME);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	/*
	 * ARP entry for PEER_MAC should have been updated to PEER_MAC2
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, PEER_MAC, true);
	dp_test_verify_neigh(IIFNAME, PEER_IP, PEER_MAC2, false);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/* Clean Up */
	dp_test_neigh_clear_entry(IIFNAME, PEER_IP);

	dp_test_nl_del_ip_addr_and_connected(IIFNAME, OUR_IP "/24");
	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Test that ARP request for address on interface OTHER than the
 * that on which request was received is NOT responded to.
 * Verify that sender's entry is updated in ARP table.
 */
DP_START_TEST(valid_arp, request_ouraddr_other_int)
{

	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;

	dp_test_arp_setup();
	dp_test_nl_add_ip_addr_and_connected(IIFNAME, OUR_IP "/24");
	dp_test_nl_add_ip_addr_and_connected(IIFNAME2, OUR_IP2 "/24");

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, "", true);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC, BCAST_MAC,
					  PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP2, 0);

	/* Create pak we expect to see in reply */
	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_oif_name(exp, IIFNAME);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	/*
	 * There should still NOT be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, "", true);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxignored, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected(IIFNAME, OUR_IP "/24");
	dp_test_nl_del_ip_addr_and_connected(IIFNAME2, OUR_IP2 "/24");

	dp_test_arp_teardown();
} DP_END_TEST;

DP_START_TEST(valid_arp, request_not_ouraddr)
{

	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;

	dp_test_arp_setup();
	dp_test_nl_add_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC, BCAST_MAC,
					  PEER_MAC, DONTCARE_MAC,
					 PEER_IP, NOT_OUR_IP, 0);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxignored, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");

	dp_test_arp_teardown();
} DP_END_TEST;

DP_DECL_TEST_CASE(arp_suite, garp, NULL, NULL);

struct garp_test_ctx {
	const char *file;
	const char *func;
	int line;
	const char *ifname;
	const char *req_str;
	const char *rep_str;
};

static void dp_test_verify_intf_garp_state(struct ifnet *ifp,
					   void *param)
{
	struct garp_test_ctx *ctx = param;
	json_object *jexp;
	char cmd_str[30];

	jexp = dp_test_json_create(
		"{"
		"  \"interfaces\": "
		"  [ "
		"     { "
		"        \"name\": \"%s\", "
		"        \"ipv4\": {"
		"           \"garp_req_op\": \"%s\","
		"           \"garp_rep_op\": \"%s\","
		"         }"
		"     } "
		"  ] "
		"}",
		ifp->if_name, ctx->req_str,
		ctx->rep_str);

	snprintf(cmd_str, 30, "ifconfig %s", ifp->if_name);

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, ctx->file,
				       ctx->func, ctx->line);

	json_object_put(jexp);
}

static void dp_test_verify_garp_state(const char *file, const char *func,
				      int line, const char *ifname,
				      const char *garp_req_str,
				      const char *garp_rep_str)
{
	struct garp_test_ctx ctx;
	struct ifnet *ifp;

	ctx.file = file;
	ctx.func = func;
	ctx.line = line;
	ctx.ifname = ifname;
	ctx.req_str = garp_req_str;
	ctx.rep_str = garp_rep_str;

	if (ifname) {
		ifp = dp_ifnet_byifname(ifname);
		dp_test_verify_intf_garp_state(ifp, &ctx);
	} else
		dp_ifnet_walk(dp_test_verify_intf_garp_state, &ctx);
}

static void
dp_test_create_and_send_garp_msg(const char *ifname,
				 const bool set,
				 const GArpConfig__ArpOp op,
				 const GArpConfig__GarpPktAction action)
{
	int len;
	GArpConfig garp = GARP_CONFIG__INIT;
	garp.ifname = (char *)ifname;
	garp.set = set;
	garp.has_set = true;
	garp.op = op;
	garp.has_op = true;
	garp.action = action;
	garp.has_action = true;

	len = garp_config__get_packed_size(&garp);

	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	garp_config__pack(&garp, buf2);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:cmd_arp_cfg", buf2, len);
}

static void
dp_test_garp_execute(const char *ifname,
		     const bool set,
		     const GArpConfig__ArpOp op,
		     const GArpConfig__GarpPktAction action)
{
	dp_test_create_and_send_garp_msg(ifname, set, op, action);
}

static void dp_test_garp_drop(int arp_op, const char *peer_mac,
			      const char *exp_peer_mac,
			      const char *file, const char *function, int line)
{
	const char *exp_req, *exp_rep;
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	char real_ifname[IFNAMSIZ];
	GArpConfig__ArpOp garp_op;

	if (arp_op == ARPOP_REQUEST) {
		garp_op = GARP_CONFIG__ARP_OP__ARPOP_REQUEST;
		exp_req = "Drop";
		exp_rep = "Update";
	} else {
		garp_op = GARP_CONFIG__ARP_OP__ARPOP_REPLY;
		exp_req = "Update";
		exp_rep = "Drop";
	}

	/* set default action to drop */
	dp_test_garp_execute(dp_test_intf_real(IIFNAME, real_ifname),
			     true, garp_op,
			     GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_DROP);

	dp_test_verify_garp_state(file, function, line,
				  real_ifname, exp_req, exp_rep);

	/* Try GARP reply with PEER_MAC2 */
	arp_pak = dp_test_create_arp_pak(arp_op,
					 peer_mac, BCAST_MAC,
					 peer_mac, iifmac,
					 PEER_IP, PEER_IP, 0);

	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	_dp_test_pak_receive(arp_pak, IIFNAME, exp, file, function, line);

	/* ARP entry should still have PEER_MAC */
	dp_test_verify_neigh(IIFNAME, PEER_IP, exp_peer_mac, false);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	if (arp_op == ARPOP_REQUEST) {
		DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, garp_reqs_dropped,
						  1);
	} else {
		DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxreplies, 1);
		DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, garp_reps_dropped,
						  1);
	}
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/* restore default operation */
	dp_test_garp_execute(dp_test_intf_real(IIFNAME, real_ifname),
			     false, garp_op,
			     GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_DROP);
	dp_test_verify_garp_state(file, function, line,
				  real_ifname, "Update", "Update");
}

DP_START_TEST(garp, gratuitous_request)
{

	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak, *exp_pak;

	dp_test_arp_setup();
	dp_test_nl_add_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");

	/*
	 * First try gratuitous ARP from peer for whom we have no
	 * ARP entry. We should ignore it.
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, iifmac,
					 PEER_IP, PEER_IP, 0);

	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, garp_reqs_dropped, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/*
	 * There should NOT be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, "", true);


	/*
	 * Generate a legitimate ARP request from peer in order to
	 * populate an ARP entry for it.
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC, BCAST_MAC,
					  PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, IIFNAME);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/*
	 * Check we have an ARP entry for peer, then generate
	 * a gratuitous ARP with an updated mac and verify
	 * it gets updated in ARP table.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, PEER_MAC, false);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC2, BCAST_MAC,
					 PEER_MAC2, iifmac,
					 PEER_IP, PEER_IP, 0);

	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/*
	 * ARP entry for peer should have been updated to PEER_MAC2.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, PEER_MAC, true);
	dp_test_verify_neigh(IIFNAME, PEER_IP, PEER_MAC2, false);

	/* test GARP drop command on interface */
	dp_test_garp_drop(ARPOP_REQUEST, PEER_MAC, PEER_MAC2,
			  __FILE__, __func__, __LINE__);

	dp_test_neigh_clear_entry(IIFNAME, PEER_IP);

	/*
	 * Now try a gratuitous ARP using a source address which
	 * is ours. Should get dropped.
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC2, BCAST_MAC,
					 PEER_MAC2, iifmac,
					 OUR_IP, OUR_IP, 0);

	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxignored, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, dupips, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");

	dp_test_arp_teardown();
} DP_END_TEST;

DP_START_TEST(garp, gratuitous_reply)
{

	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;

	dp_test_arp_setup();
	dp_test_nl_add_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");

	arp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 PEER_MAC, iifmac,
					 PEER_MAC, iifmac,
					 PEER_IP, OUR_IP, 0);

	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	/*
	 * There should NOT be an ARP entry for PEER_MAC.
	 * RIGHT NOW THERE IS A BUG AND THE UNSOL ARP IS ACCEPTED.
	 */
	dp_test_verify_neigh(IIFNAME, PEER_IP, PEER_MAC, false);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, rxreplies, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/* test GARP drop command on interface */
	dp_test_garp_drop(ARPOP_REPLY, PEER_MAC2, PEER_MAC,
			  __FILE__, __func__, __LINE__);

	dp_test_neigh_clear_entry(IIFNAME, PEER_IP);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");

	dp_test_arp_teardown();
} DP_END_TEST;

DP_START_TEST(garp, garp_cmd)
{
	char real_ifname[IFNAMSIZ];

	/* set default action to drop */
	dp_test_garp_execute("", true, GARP_CONFIG__ARP_OP__ARPOP_REQUEST,
			     GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_DROP);

	dp_test_garp_execute("", true, GARP_CONFIG__ARP_OP__ARPOP_REPLY,
			     GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_DROP);

	dp_test_verify_garp_state(__FILE__, __func__, __LINE__, NULL,
				  "Drop", "Drop");

	/* override one action on one interface */
	dp_test_intf_real("dp1T3", real_ifname);

	dp_test_garp_execute(real_ifname, true,
			     GARP_CONFIG__ARP_OP__ARPOP_REQUEST,
			     GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_UPDATE);

	dp_test_verify_garp_state(__FILE__, __func__, __LINE__, real_ifname,
				  "Update", "Drop");

	/* clear one action on one interface */
	dp_test_garp_execute(real_ifname, false,
			     GARP_CONFIG__ARP_OP__ARPOP_REQUEST,
			     GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_UPDATE);

	dp_test_verify_garp_state(__FILE__, __func__, __LINE__, real_ifname,
				  "Drop", "Drop");

	/* restore default action */
	dp_test_garp_execute("", false, GARP_CONFIG__ARP_OP__ARPOP_REQUEST,
			     GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_DROP);
	dp_test_garp_execute("", false, GARP_CONFIG__ARP_OP__ARPOP_REPLY,
			     GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_DROP);
	dp_test_verify_garp_state(__FILE__, __func__, __LINE__, NULL,
				  "Update", "Update");
} DP_END_TEST;

/*
 * Test ARP for bridge IP address, with a dataplane bridge port
 */
DP_DECL_TEST_CASE(arp_suite, bridge_arp, NULL, NULL);
DP_START_TEST(bridge_arp, eth_port)
{
	const char *bname = "br1";
	const char *bport = "dp1T0";
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *exp_pak;

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_bridge_create(bname);
	dp_test_intf_bridge_add_port(bname, bport);

	dp_test_nl_add_ip_addr_and_connected(bname, OUR_IP "/24");

	iifmac = dp_test_intf_name2mac_str(bname);

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, true);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC, BCAST_MAC,
					  PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, bport);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, bport, exp);

	/*
	 * Now there should be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, false);

	/*
	 * 3 (and ONLY 3!) counters should have incrememted.
	 */
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(bname);

	/*
	 * Do it again and check ARP entry is still there.
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC, BCAST_MAC,
					  PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, bport);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, bport, exp);

	/*
	 * Should still be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, false);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(bname);

	/*
	 * Send another ARP request from peer but change its
	 * mac address. Check that we update it.
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					  PEER_MAC2, BCAST_MAC,
					  PEER_MAC2, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC2,
					 iifmac, PEER_MAC2,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, bport);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, bport, exp);

	/*
	 * ARP entry for PEER_MAC should have been updated to PEER_MAC2
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, true);
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC2, false);


	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(bname);

	/* Clean Up */
	dp_test_neigh_clear_entry(bname, PEER_IP);

	dp_test_nl_del_ip_addr_and_connected(bname, OUR_IP "/24");

	dp_test_intf_bridge_remove_port(bname, bport);
	dp_test_intf_bridge_del(bname);

	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Test ARP for IP address on L3 vlan (vif) interface
 */
DP_DECL_TEST_CASE(arp_suite, l3_arp_vlan, NULL, NULL);
DP_START_TEST(l3_arp_vlan, l3_arp_vlan)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *exp_pak;

	const char *l3_intf = "dp1T3";
	const char *l3_vif_intf = "dp1T3.20";
	uint16_t vlan_id = 20;

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_vif_create(l3_vif_intf, l3_intf, vlan_id);

	dp_test_nl_add_ip_addr_and_connected(l3_vif_intf, OUR_IP "/24");

	iifmac = dp_test_intf_name2mac_str(l3_intf);

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(l3_vif_intf, PEER_IP, PEER_MAC, true);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, vlan_id);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 OUR_IP, PEER_IP, vlan_id);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, l3_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_vlan_tci(exp, vlan_id);

	dp_test_pak_receive(arp_pak, l3_intf, exp);

	/*
	 * Now there should be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(l3_vif_intf, PEER_IP, PEER_MAC, false);

	/*
	 * 3 (and ONLY 3!) counters should have incremented.
	 */
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_vif_intf, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_vif_intf, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_vif_intf, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(l3_vif_intf);

	/* Clean Up */
	dp_test_neigh_clear_entry(l3_vif_intf, PEER_IP);

	dp_test_nl_del_ip_addr_and_connected(l3_vif_intf, OUR_IP "/24");

	dp_test_intf_vif_del(l3_vif_intf, vlan_id);

	dp_test_arp_teardown();
} DP_END_TEST;


/*
 * Test ARP for IP address on L3 vlan (vif) interface with non-default proto
 */
DP_DECL_TEST_CASE(arp_suite, l3_arp_vlan_proto, NULL, NULL);
DP_START_TEST(l3_arp_vlan, l3_arp_vlan_proto)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *exp_pak;

	const char *l3_intf = "dp1T3";
	const char *l3_vif_intf = "dp1T3.20";
	uint16_t vlan_id = 20;

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_vif_create_tag_proto(l3_vif_intf, l3_intf, vlan_id,
					  ETH_P_8021AD);

	dp_test_nl_add_ip_addr_and_connected(l3_vif_intf, OUR_IP "/24");

	iifmac = dp_test_intf_name2mac_str(l3_intf);

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(l3_vif_intf, PEER_IP, PEER_MAC, true);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);
	dp_test_insert_8021q_hdr(arp_pak, vlan_id, ETH_P_8021AD,
				 ETHER_TYPE_ARP);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 OUR_IP, PEER_IP, 0);
	dp_test_insert_8021q_hdr(exp_pak, vlan_id, ETH_P_8021AD,
				 ETHER_TYPE_ARP);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, l3_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, l3_intf, exp);

	/*
	 * Now there should be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(l3_vif_intf, PEER_IP, PEER_MAC, false);

	/*
	 * 3 (and ONLY 3!) counters should have incremented.
	 */
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_vif_intf, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_vif_intf, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_vif_intf, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(l3_vif_intf);

	/*
	 * Now send a double-tagged packet - should be dropped
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);
	dp_test_insert_8021q_hdr(arp_pak, vlan_id, ETH_P_8021AD,
				 ETHER_TYPE_ARP);
	dp_test_insert_8021q_hdr(arp_pak, vlan_id, ETH_P_8021AD,
				 ETH_P_8021AD);

	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(arp_pak, l3_intf, exp);

	dp_test_verify_all_arp_stats_zero(l3_vif_intf);

	/* Clean Up */
	dp_test_neigh_clear_entry(l3_vif_intf, PEER_IP);

	dp_test_nl_del_ip_addr_and_connected(l3_vif_intf, OUR_IP "/24");

	dp_test_intf_vif_del_tag_proto(l3_vif_intf, vlan_id, ETH_P_8021AD);

	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Test ARP for IP address on main interface with vlan-tagged packet
 */
DP_START_TEST(l3_arp_vlan, invalid_vlan)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	const char *l3_intf = "dp1T3";
	uint16_t vlan_id = 20;

	/* Setup */
	dp_test_arp_setup();

	dp_test_nl_add_ip_addr_and_connected(l3_intf, OUR_IP "/24");

	iifmac = dp_test_intf_name2mac_str(l3_intf);

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(l3_intf, PEER_IP, PEER_MAC, true);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, vlan_id);

	exp = dp_test_exp_create(arp_pak);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_pak_receive(arp_pak, l3_intf, exp);

	/*
	 * Verify still no ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(l3_intf, PEER_IP, PEER_MAC, true);

	/*
	 * Dropped before ARP sees the packet
	 */
	dp_test_verify_all_arp_stats_zero(l3_intf);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected(l3_intf, OUR_IP "/24");

	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Test ARP reply for IP address on macvlan interface with dataplane
 * parent interface, with request coming from peer and reply
 * generated.
 */
DP_DECL_TEST_CASE(arp_suite, arp_macvlan, NULL, NULL);
DP_START_TEST(arp_macvlan, reply_dp_parent)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *exp_pak;

	const char *l3_intf = "dp1T3";
	const char *l3_macvlan_intf = "dp1vrrp3";
	const char *macvlan_mac = "00:00:5E:00:01:03";

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_macvlan_create(l3_macvlan_intf, l3_intf, macvlan_mac);

	dp_test_nl_add_ip_addr_and_connected(l3_intf, "1.1.1.99/24");
	dp_test_netlink_add_ip_address(l3_macvlan_intf, OUR_IP "/24");

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(l3_macvlan_intf, PEER_IP, PEER_MAC, true);

	/*
	 * Test broadcast ARP request
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 macvlan_mac, PEER_MAC,
					 macvlan_mac, PEER_MAC,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, l3_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, l3_intf, exp);

	/*
	 * Now there should be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(l3_macvlan_intf, PEER_IP, PEER_MAC, false);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(l3_macvlan_intf);

	/*
	 * Test unicast ARP request
	 */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, macvlan_mac,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 macvlan_mac, PEER_MAC,
					 macvlan_mac, PEER_MAC,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, l3_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, l3_intf, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, txreplies, 1);

	/* Clean Up */
	dp_test_neigh_clear_entry(l3_macvlan_intf, PEER_IP);

	dp_test_netlink_del_ip_address(l3_macvlan_intf, OUR_IP "/24");
	dp_test_nl_del_ip_addr_and_connected(l3_intf, "1.1.1.99/24");

	dp_test_intf_macvlan_del(l3_macvlan_intf);

	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Test originating ARP request for IP address out of macvlan
 * interface with dataplane parent interface
 */
DP_START_TEST(arp_macvlan, req_dp_parent)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *ip_pak;
	struct rte_mbuf *exp_pak;
	const char *l3_intf = "dp1T3";
	const char *l3_macvlan_intf = "dp1vrrp3";
	const char *macvlan_mac = "00:00:5E:00:01:03";
	int len = 64;

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_macvlan_create(l3_macvlan_intf, l3_intf, macvlan_mac);

	dp_test_nl_add_ip_addr_and_connected(IIFNAME2, OUR_IP2 "/24");
	dp_test_nl_add_ip_addr_and_connected(l3_macvlan_intf, OUR_IP "/24");
	dp_test_nl_add_ip_addr_and_connected(l3_intf, "2.1.1.99/24");

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(l3_macvlan_intf, PEER_IP, PEER_MAC, true);

	/* Create IP pak to L3 route and cause arp request for PEER_IP */
	ip_pak = dp_test_create_ipv4_pak("10.42.42.42", PEER_IP,
					 1, &len);
	dp_test_pktmbuf_eth_init(ip_pak,
				 dp_test_intf_name2mac_str(IIFNAME2),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 ETHER_TYPE_IPv4);

	exp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 macvlan_mac, BCAST_MAC,
					 macvlan_mac, DONTCARE_MAC,
					 OUR_IP, PEER_IP, 0);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, l3_intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(ip_pak, IIFNAME2, exp);

	/* Now complete it */
	arp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 PEER_MAC, macvlan_mac,
					 PEER_MAC, macvlan_mac,
					 PEER_IP, OUR_IP, 0);
	exp_pak = dp_test_create_ipv4_pak("10.42.42.42", PEER_IP,
					  1, &len);
	dp_test_pktmbuf_eth_init(exp_pak, PEER_MAC, macvlan_mac,
				 ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(exp_pak);

	exp = dp_test_exp_create_m(NULL, 2);

	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_pak_m(exp, 0, dp_test_cp_pak(arp_pak));
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, l3_intf);
	dp_test_exp_set_pak_m(exp, 1, exp_pak);

	dp_test_pak_receive(arp_pak, l3_intf, exp);

	/*
	 * Now there should be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(l3_macvlan_intf, PEER_IP, PEER_MAC, false);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, txrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(l3_macvlan_intf, rxreplies, 1);
	dp_test_verify_all_arp_stats_zero(l3_macvlan_intf);

	/* Clean Up */
	dp_test_neigh_clear_entry(l3_macvlan_intf, PEER_IP);

	dp_test_nl_del_ip_addr_and_connected(l3_macvlan_intf, OUR_IP "/24");
	dp_test_nl_del_ip_addr_and_connected(l3_intf, "2.1.1.99/24");
	dp_test_nl_del_ip_addr_and_connected(IIFNAME2, OUR_IP2 "/24");

	dp_test_intf_macvlan_del(l3_macvlan_intf);

	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Test ARP for bridge IP address, with an 802.1Q bridge port
 */
DP_DECL_TEST_CASE(arp_suite, bridge_arp_vlan, NULL, NULL);
DP_START_TEST(bridge_arp_vlan, vlan_port)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *exp_pak;

	const char *bname = "br1";
	const char *bport = "dp1T0.10";
	const char *intf = "dp1T0";
	uint16_t vlan_id = 10;

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_vif_create(bport, intf, vlan_id);
	dp_test_intf_bridge_create(bname);
	dp_test_intf_bridge_add_port(bname, bport);

	dp_test_nl_add_ip_addr_and_connected(bname, OUR_IP "/24");

	iifmac = dp_test_intf_name2mac_str(bname);

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, true);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, OUR_IP, vlan_id);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 OUR_IP, PEER_IP, vlan_id);

	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, intf);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_vlan_tci(exp, vlan_id);

	dp_test_pak_receive(arp_pak, intf, exp);

	/*
	 * Now there should be an ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, false);

	/*
	 * 3 (and ONLY 3!) counters should have incrememted.
	 */
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, rxrequests, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, txreplies, 1);
	dp_test_verify_all_arp_stats_zero(bname);

	/* Clean Up */
	dp_test_neigh_clear_entry(bname, PEER_IP);

	dp_test_nl_del_ip_addr_and_connected(bname, OUR_IP "/24");

	dp_test_intf_bridge_remove_port(bname, bport);
	dp_test_intf_bridge_del(bname);
	dp_test_intf_vif_del(bport, vlan_id);

	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Check an arp request that is not for our IP, is transparently bridged
 * i.e. forwarded with no changes and no ARP processing.
 */
DP_DECL_TEST_CASE(arp_suite, bridge_arp_not_ouraddr, NULL, NULL);
DP_START_TEST(bridge_arp_not_ouraddr, bridge_arp_not_ouraddr)
{
	const char *bname = "br1";
	const char *bport = "dp1T0", *bport_tx = "dp2T1";
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_bridge_create(bname);
	dp_test_intf_bridge_add_port(bname, bport);
	dp_test_intf_bridge_add_port(bname, bport_tx);

	dp_test_nl_add_ip_addr_and_connected(bname, OUR_IP "/24");

	iifmac = dp_test_intf_name2mac_str(bname);

	/*
	 * There should not be any ARP entry for NOT_OUR_IP
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, true);

	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, NOT_OUR_IP, 0);

	/*
	 * Slowpath arp should be dropped (same as L3 interface).  Frame should
	 * be flooded across transparent bridge.
	 */
	exp = dp_test_exp_create_m(arp_pak, 2);

	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_DROPPED);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, bport_tx);

	dp_test_pak_receive(arp_pak, bport, exp);

	/*
	 * There should not be any ARP entry for NOT_OUR_IP
	 */
	dp_test_verify_neigh(bname, NOT_OUR_IP, "", true);

	/* No counters should have incremented */
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, rxignored, 1);
	dp_test_verify_all_arp_stats_zero(bname);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected(bname, OUR_IP "/24");
	dp_test_intf_bridge_remove_port(bname, bport_tx);
	dp_test_intf_bridge_remove_port(bname, bport);
	dp_test_intf_bridge_del(bname);

	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Test that ARP request is generated on bridge interface when traffic comes
 * in on a L3 port and is routed out of the bridge interface.
 */
DP_DECL_TEST_CASE(arp_suite, bridge_arp_req_l3_fwd, NULL, NULL);
DP_START_TEST(bridge_arp_req_l3_fwd, bridge_arp_req_l3_fwd)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *ip_pak, *exp_pak;
	const char *bname = "br1";
	const char *bport = "dp1T0";
	int len = 64;

	dp_test_arp_setup();
	dp_test_intf_bridge_create(bname);
	dp_test_intf_bridge_add_port(bname, bport);
	dp_test_nl_add_ip_addr_and_connected(bname, OUR_IP "/24");
	dp_test_nl_add_ip_addr_and_connected(IIFNAME2, OUR_IP2 "/24");

	/*
	 * There should not be any ARP entry for PEER_MAC.
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, true);

	/* Create IP pak to L3 route and cause arp request for PEER_IP */
	ip_pak = dp_test_create_ipv4_pak("10.42.42.42", PEER_IP,
					 1, &len);
	(void)dp_test_pktmbuf_eth_init(ip_pak,
				       dp_test_intf_name2mac_str(IIFNAME2),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	exp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 dp_test_intf_name2mac_str(bname),
					 BCAST_MAC,
					 dp_test_intf_name2mac_str(bname),
					 DONTCARE_MAC,
					 OUR_IP, PEER_IP, 0);
	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, bport);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(ip_pak, IIFNAME2, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, txrequests, 1);
	dp_test_verify_all_arp_stats_zero(bname);

	/* Clean Up */
	dp_test_neigh_clear_entry(bname, PEER_IP);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, dropped, 1);

	dp_test_nl_del_ip_addr_and_connected(bname, OUR_IP "/24");
	dp_test_nl_del_ip_addr_and_connected(IIFNAME2, OUR_IP2 "/24");
	dp_test_intf_bridge_remove_port(bname, bport);
	dp_test_intf_bridge_del(bname);

	dp_test_arp_teardown();
} DP_END_TEST;

DP_DECL_TEST_CASE(arp_suite, proxy_arp, NULL, NULL);

/*
 * Test that an ARP request for an address for which we have a route
 * is responded to provided proxy arp is enabled.
 */
DP_START_TEST(proxy_arp, route_exists)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *exp_pak;
	struct rte_mbuf *arp_pak;

	dp_test_arp_setup();
	iifmac = dp_test_intf_name2mac_str(IIFNAME);

	dp_test_nl_add_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");
	/* enable proxy arp on IIFNAME
	 * NB/ this needs to be after the set addr or that will overwrite it
	 * and before the add_route to prevent race condition as its not
	 * verified.
	 */
	dp_test_netlink_set_proxy_arp(IIFNAME, true);
	/* add an external prefix */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	/* arp for address in that prefix */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, "10.73.2.1", 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 "10.73.2.1", PEER_IP, 0);
	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, IIFNAME);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, txreplies, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, proxy, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/* Clean Up */
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_set_proxy_arp(IIFNAME, false);
	dp_test_neigh_clear_entry(IIFNAME, PEER_IP);
	dp_test_nl_del_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");

	dp_test_arp_teardown();

} DP_END_TEST;


/*
 * Test that an ARP request for an address for which we have a route
 * in a VRF is responded to provided proxy arp is enabled.
 */
#define TEST_VRF 50

DP_START_TEST(proxy_arp, route_exists_vrf)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *exp_pak;
	struct rte_mbuf *arp_pak;
	char route1[TEST_MAX_CMD_LEN];

	dp_test_arp_setup();
	iifmac = dp_test_intf_name2mac_str(IIFNAME);

	dp_test_netlink_add_vrf(TEST_VRF, 1);
	dp_test_netlink_set_interface_vrf(IIFNAME, TEST_VRF);
	dp_test_nl_add_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");
	/* enable proxy arp on IIFNAME
	 * NB/ this needs to be after the set addr or that will overwrite it
	 * and before the add_route to prevent race condition as its not
	 * verified.
	 */
	dp_test_netlink_set_proxy_arp(IIFNAME, true);
	/* add an external prefix */
	dp_test_netlink_set_interface_vrf("dp2T1", TEST_VRF);
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	snprintf(route1, sizeof(route1),
		 "vrf:%d 10.73.2.0/24 nh 2.2.2.1 int:dp2T1",
		 TEST_VRF);
	dp_test_netlink_add_route(route1);
	/* arp for address in that prefix */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, "10.73.2.1", 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 "10.73.2.1", PEER_IP, 0);
	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, IIFNAME);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, IIFNAME, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, txreplies, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(IIFNAME, proxy, 1);
	dp_test_verify_all_arp_stats_zero(IIFNAME);

	/* Clean Up */
	dp_test_netlink_del_route(route1);
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_set_proxy_arp(IIFNAME, false);
	dp_test_neigh_clear_entry(IIFNAME, PEER_IP);
	dp_test_nl_del_ip_addr_and_connected(IIFNAME, "1.1.1.1/24");
	dp_test_netlink_set_interface_vrf(IIFNAME, VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp2T1", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF, 0);
	dp_test_arp_teardown();

} DP_END_TEST;

/*
 * Test that an ARP request coming in on a bridge for an address for
 * which we have a route is responded to with proxy arp enabled.
 */
DP_START_TEST(proxy_arp, bridge_route_exists)
{
	const char *bname = "br1";
	const char *bport = "dp1T0";
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *exp_pak;

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_bridge_create(bname);
	dp_test_intf_bridge_add_port(bname, bport);

	dp_test_nl_add_ip_addr_and_connected(bname, "1.1.1.1/24");

	iifmac = dp_test_intf_name2mac_str(bname);

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, true);
	/* enable proxy arp on bridge
	 * NB/ this needs to be after the set addr or that will overwrite it
	 * and before the add_route to prevent race condition as its not
	 * verified.
	 */
	dp_test_netlink_set_proxy_arp(bname, true);
	/* add an external prefix */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	/* arp for address in that prefix */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, "10.73.2.1", 0);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 "10.73.2.1", PEER_IP, 0);
	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, bport);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(arp_pak, bport, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, txreplies, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bname, proxy, 1);
	dp_test_verify_all_arp_stats_zero(bname);
	dp_test_verify_neigh(bname, PEER_IP, PEER_MAC, true);

	/* Clean Up */
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_set_proxy_arp(bname, false);
	dp_test_neigh_clear_entry(bname, PEER_IP);
	dp_test_nl_del_ip_addr_and_connected(bname, "1.1.1.1/24");

	dp_test_intf_bridge_remove_port(bname, bport);
	dp_test_intf_bridge_del(bname);

	dp_test_arp_teardown();
} DP_END_TEST;

/*
 * Test that an ARP request coming in on a bridge for an address for
 * which we have a route is responded to with proxy arp enabled.
 */
DP_START_TEST(proxy_arp, bridge_vlan_route_exists)
{
	struct bridge_vlan_set *vlans = bridge_vlan_set_create();
	const char *bname = "br1";
	const char *bvif = "br1.10";
	const char *bport = "dp1T0";
	struct dp_test_expected *exp;
	struct rte_mbuf *arp_pak;
	struct rte_mbuf *exp_pak;

	/* Setup */
	dp_test_arp_setup();
	dp_test_intf_bridge_create(bname);
	dp_test_intf_bridge_enable_vlan_filter(bname);
	dp_test_intf_bridge_add_port(bname, bport);
	dp_test_intf_vif_create(bvif, bname, 10);
	bridge_vlan_set_add(vlans, 10);
	dp_test_intf_bridge_port_set_vlans(bname, bport, 0, vlans,
		NULL);

	dp_test_nl_add_ip_addr_and_connected(bname, "1.1.1.1/24");

	iifmac = dp_test_intf_name2mac_str(bname);

	/*
	 * There should not be any ARP entry for PEER_MAC yet.
	 */
	dp_test_verify_neigh(bvif, PEER_IP, PEER_MAC, true);
	/* enable proxy arp on bridge and vif
	 * NB/ this needs to be after the set addr or that will overwrite it
	 * and before the add_route to prevent race condition as its not
	 * verified.
	 */
	dp_test_netlink_set_proxy_arp(bname, true);
	dp_test_netlink_set_proxy_arp(bvif, true);
	/* add an external prefix */
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	/* arp for address in that prefix */
	arp_pak = dp_test_create_arp_pak(ARPOP_REQUEST,
					 PEER_MAC, BCAST_MAC,
					 PEER_MAC, DONTCARE_MAC,
					 PEER_IP, "10.73.2.1", 0);
	dp_test_pktmbuf_vlan_init(arp_pak, 10);

	exp_pak = dp_test_create_arp_pak(ARPOP_REPLY,
					 iifmac, PEER_MAC,
					 iifmac, PEER_MAC,
					 "10.73.2.1", PEER_IP, 0);
	exp = dp_test_exp_create_with_packet(exp_pak);

	dp_test_exp_set_oif_name(exp, bport);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_vlan_tci(exp, 10);

	dp_test_pak_receive(arp_pak, bport, exp);

	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bvif, received, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bvif, txreplies, 1);
	DP_TEST_VERIFY_AND_CLEAR_ARP_STAT(bvif, proxy, 1);
	dp_test_verify_all_arp_stats_zero(bvif);
	dp_test_verify_all_arp_stats_zero(bname);
	dp_test_verify_neigh(bvif, PEER_IP, PEER_MAC, true);

	/* Clean Up */
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_set_proxy_arp(bname, false);
	dp_test_neigh_clear_entry(bname, PEER_IP);
	dp_test_nl_del_ip_addr_and_connected(bname, "1.1.1.1/24");

	dp_test_intf_vif_del(bvif, 10);
	dp_test_intf_bridge_remove_port(bname, bport);
	dp_test_intf_bridge_del(bname);

	bridge_vlan_set_free(vlans);
	dp_test_arp_teardown();
} DP_END_TEST;
