/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Minimal tests for the ALG APT databases.  Main testing for this occurs via
 * the ALG tests.
 */

#include "netinet6/in6.h"

#include "npf/alg/apt/apt_public.h"
#include "npf/alg/apt/apt.h"
#include "npf/alg/apt/apt_dport.h"
#include "npf/alg/apt/apt_tuple.h"

#include "dp_test.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"

static void apt_setup(void);
static void apt_teardown(void);

DP_DECL_TEST_SUITE(npf_apt);

/*
 * apt1.  Simple test of dport table.
 */
DP_DECL_TEST_CASE(npf_apt, apt1, apt_setup, apt_teardown);
DP_START_TEST(apt1, test)
{
	char real_ifname[IFNAMSIZ];
	struct apt_instance *ai;
	struct ifnet *ifp;
	struct vrf *vrf;
	vrfid_t vrf_id;
	void *ctx, *rp;
	uint32_t init_count, count;
	int rc;

	dp_test_intf_real("dp2T1", real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);

	vrf_id = if_vrfid(ifp);
	vrf = get_vrf(vrf_id);

	dp_test_fail_unless(vrf != NULL, "get_vrf(%u) == NULL", vrf_id);

	/* Get apt instance */
	ai = apt_instance_find_or_create(vrf);
	dp_test_fail_unless(ai, "apt_instance_find_or_create");

	/* There should be either 0 or 6 entries by default */
	init_count = apt_dport_tbl_count(ai, ALG_FEAT_NPF);
	dp_test_fail_unless(init_count == 6 || init_count == 0,
			    "apt_dport_tbl_count %u", init_count);

	/*
	 * Add dest port.  calloc a dport context.
	 */
	ctx = calloc(1, 16);
	rc = apt_dport_add(ai, ALG_FEAT_NPF, ctx,
			   IPPROTO_TCP, htons(1000), "SIP");
	dp_test_fail_unless(rc == 0, "apt_dport_add");

	/*
	 * Lookup dest port
	 */
	rp = apt_dport_lookup(ai, ALG_FEAT_NPF, IPPROTO_TCP,
			      htons(1000), true);
	dp_test_fail_unless(rp == ctx, "apt_dport_lookup");

	/*
	 * The above lookup will have incremented the dport entry count
	 */
	count = apt_dport_tbl_count(ai, ALG_FEAT_NPF);
	dp_test_fail_unless(count == init_count + 1,
			    "apt_dport_tbl_count %u", count);

	/*
	 * Delete dest port
	 */
	rc = apt_dport_lookup_and_expire(ai, ALG_FEAT_NPF, IPPROTO_TCP,
					 htons(1000));
	dp_test_fail_unless(rc == 0, "apt_dport_lookup_and_expire");

	/*
	 * Lookup dest port.  Should no longer be found.
	 */
	rp = apt_dport_lookup(ai, ALG_FEAT_NPF,
			      IPPROTO_TCP, htons(1000), true);
	dp_test_fail_unless(!rp, "apt_dport_lookup");

} DP_END_TEST;


/*
 * apt2.  Simple test of tuple table.
 */
DP_DECL_TEST_CASE(npf_apt, apt2, apt_setup, apt_teardown);
DP_START_TEST(apt2, test)
{
	char real_ifname[IFNAMSIZ];
	struct apt_instance *ai;
	struct apt_tuple *te;
	struct ifnet *ifp;
	struct vrf *vrf;
	vrfid_t vrf_id;
	void *ctx, *rp;
	int rc;

	dp_test_intf_real("dp2T1", real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);

	vrf_id = if_vrfid(ifp);
	vrf = get_vrf(vrf_id);

	dp_test_fail_unless(vrf != NULL, "get_vrf(%u) == NULL", vrf_id);

	/* Get apt instance */
	ai = apt_instance_find_or_create(vrf);
	dp_test_fail_unless(ai, "apt_instance_find_or_create");

	/* This is a 'any src port' key initially */
	struct apt_key key = {
		.v4_key.k4_ifindex = dp_test_intf_name2index(real_ifname),
		.v4_key.k4_proto = IPPROTO_TCP,
		.v4_key.k4_dport = htons(1000),
		.v4_key.k4_sport = 0,
		.v4_key.k4_daddr = htonl(0x0a000001),
		.v4_key.k4_saddr = htonl(0x0a000002),
		.v4_key.k4_alen  = 4,
	};

	/* Add tuple */
	ctx = calloc(1, 16);
	rc = 0;
	apt_tuple_add(ai, ALG_FEAT_NPF, ctx, &key, 0, true, false, &rc);
	dp_test_fail_unless(rc == 0, "apt_tuple_v4_add");

	/* Lookup tuple */
	te = apt_tuple_v4_lookup(ai, ALG_FEAT_NPF, &key.v4_key);
	dp_test_fail_unless(te, "apt_tuple_v4_lookup");

	/* Get tuple context */
	rp = apt_tuple_get_feat_ctx(te);
	dp_test_fail_unless(rp == ctx, "apt_tuple_get_feat_ctx");

	/* Set sport in the lookup key, and lookup again */
	key.v4_key.k4_sport = htons(12345);

	/* Lookup and expire the tuple */
	te = apt_tuple_lookup_and_expire(ai, ALG_FEAT_NPF, &key, NULL);
	dp_test_fail_unless(te, "apt_tuple_v4_lookup");

	/* Expired tuple should no longer be found */
	te = apt_tuple_v4_lookup(ai, ALG_FEAT_NPF, &key.v4_key);
	dp_test_fail_unless(!te, "apt_tuple_v4_lookup");

} DP_END_TEST;


/*
 * apt3.  Tests a non-default vrf with dport and tuple entries being deleted
 * *before* the entries are removed by the ALG or by gc.
 */
DP_DECL_TEST_CASE(npf_apt, apt3, NULL, NULL);
DP_START_TEST(apt3, test)
{
	char real_ifname[IFNAMSIZ];
	struct apt_instance *ai;
	vrfid_t test_vrf = 42;
	struct ifnet *ifp;
	struct vrf *vrf;
	vrfid_t vrf_id;
	void *ctx;
	int rc;

	/*
	 * Add vrf
	 */
	dp_test_netlink_add_vrf(test_vrf, 1);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp2T1",
						 "1.1.1.254/24", test_vrf);
	dp_test_intf_real("dp2T1", real_ifname);
	ifp = dp_ifnet_byifname(real_ifname);

	vrf_id = if_vrfid(ifp);
	vrf = get_vrf(vrf_id);

	dp_test_fail_unless(vrf != NULL, "get_vrf(%u) == NULL", vrf_id);

	ai = apt_instance_find_or_create(vrf);
	dp_test_fail_unless(ai, "apt_instance_find_or_create");

	/* Add dest port  */
	ctx = calloc(1, 16);
	rc = apt_dport_add(ai, ALG_FEAT_NPF, ctx,
			   IPPROTO_TCP, htons(1000), "SIP");
	dp_test_fail_unless(rc == 0, "apt_dport_add");

	struct apt_key key = {
		.v4_key.k4_ifindex = dp_test_intf_name2index(real_ifname),
		.v4_key.k4_proto = IPPROTO_TCP,
		.v4_key.k4_dport = htons(1000),
		.v4_key.k4_sport = 0,
		.v4_key.k4_daddr = htonl(0x0a000001),
		.v4_key.k4_saddr = htonl(0x0a000002),
		.v4_key.k4_alen  = 4,
	};

	/* Add tuple */
	ctx = calloc(1, 16);
	rc = 0;
	apt_tuple_add(ai, ALG_FEAT_NPF, ctx, &key, 0, true, false, &rc);
	dp_test_fail_unless(rc == 0, "apt_tuple_v4_add");

	/*
	 * Delete the apt instance directly
	 */
	dpt_apt_vrf_delete(vrf_id);

	dp_test_nl_del_ip_addr_and_connected_vrf("dp2T1",
						 "1.1.1.254/24", test_vrf);
	dp_test_netlink_del_vrf(test_vrf, 0);

} DP_END_TEST;


static void apt_setup(void)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.2.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.64.0.254/16");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.254/24");

	/*
	 * Inside
	 */
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.2",
				  "aa:bb:cc:dd:1:a2");
	dp_test_netlink_add_neigh("dp1T0", "100.64.1.1",
				  "aa:bb:cc:dd:1:a3");

	dp_test_netlink_add_neigh("dp1T0", "2.2.2.1",
				  "aa:bb:cc:dd:1:a4");

	/*
	 * Outside
	 */
	dp_test_netlink_add_neigh("dp2T1", "1.1.1.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "1.1.1.2",
				  "aa:bb:cc:dd:2:b2");

}

static void apt_teardown(void)
{
	/* Cleanup */
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.1", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.2", "aa:bb:cc:dd:1:a2");
	dp_test_netlink_del_neigh("dp1T0", "100.64.1.1", "aa:bb:cc:dd:1:a3");
	dp_test_netlink_del_neigh("dp1T0", "2.2.2.1", "aa:bb:cc:dd:1:a4");

	dp_test_netlink_del_neigh("dp2T1", "1.1.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "1.1.1.2", "aa:bb:cc:dd:2:b2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.64.0.254/16");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.2.2.254/24");
}
