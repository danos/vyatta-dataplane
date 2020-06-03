/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * dataplane UT VRF tests
 */
#include <libmnl/libmnl.h>
#include <linux/random.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "vrf_internal.h"

#define TEST_VRF 50

DP_DECL_TEST_SUITE(vrf_suite);

DP_DECL_TEST_CASE(vrf_suite, vrf_if_cfg, NULL, NULL);

/*
 * Show that we can create an interface in a non-default VRF
 * and that the VRF will be created and its refcount will be
 * correct.
 */
DP_START_TEST(vrf_if_cfg, create_in_vrf)
{
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "1.1.2.1/24");

	dp_test_intf_gre_create("tun1", "1.1.2.1", "1.1.2.2", 0,
				TEST_VRF);

	dp_test_wait_for_vrf(TEST_VRF, 2);

	dp_test_intf_gre_delete("tun1", "1.1.2.1", "1.1.2.2", 0,
				TEST_VRF);

	dp_test_wait_for_vrf(TEST_VRF, 1);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "1.1.2.1/24");

	dp_test_netlink_del_vrf(TEST_VRF, 0);

} DP_END_TEST;


/*
 * Show that VRF default stays around even if all the interfaces
 * end up somewhere else.
 */
DP_START_TEST(vrf_if_cfg, default_stays)
{
	char if_name[IFNAMSIZ];
	int i;

	dp_test_wait_for_vrf(VRF_DEFAULT_ID,
			     dp_test_default_vrf_clean_count());

	dp_test_netlink_add_vrf(TEST_VRF, 1);

	for (i = 0; i < dp_test_intf_count(); i++) {
		dp_test_intf_port2name(i, if_name);
		/* put all interface into VRF 1 */
		dp_test_netlink_set_interface_vrf(if_name, TEST_VRF);

		dp_test_wait_for_vrf(TEST_VRF, i+2);
		dp_test_wait_for_vrf(VRF_DEFAULT_ID,
				     dp_test_default_vrf_clean_count() -
				     (i+1));
	}

	/*
	 * Verify default vrf table still exists as well as new vrf.
	 * dp_test_default_vrf_clean_count() return includes the switch port
	 * count and so that needs to be deducted from expected results.
	 */
	dp_test_wait_for_vrf(TEST_VRF,
			     dp_test_default_vrf_clean_count() - 1 -
			     dp_test_intf_switch_port_count());
	dp_test_wait_for_vrf(VRF_DEFAULT_ID,
			     dp_test_intf_switch_port_count() + 2);

	/* put an interface back into the default VRF */
	for (i = 0; i < dp_test_intf_count(); i++) {
		dp_test_wait_for_vrf(
			TEST_VRF,
			dp_test_default_vrf_clean_count() - i - 1 -
			dp_test_intf_switch_port_count());

		dp_test_intf_port2name(i, if_name);
		dp_test_netlink_set_interface_vrf(if_name, VRF_DEFAULT_ID);
		dp_test_wait_for_vrf(VRF_DEFAULT_ID,
				     dp_test_intf_switch_port_count() + i + 3);
	}

	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;

/*
 * Show that we can assign IP address to an interface in a
 * non-default vrf
 */
DP_START_TEST(vrf_if_cfg, ip_configure)
{
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* put an interface into TEST_VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", TEST_VRF);

	/* assign IP to this interface */
	dp_test_netlink_add_ip_address_vrf("dp1T1", "1.1.1.1/24", TEST_VRF);

	/* remove IP from this interface */
	dp_test_netlink_del_ip_address_vrf("dp1T1", "1.1.1.1/24", TEST_VRF);

	/* put an interface back into the default VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;


/* Show that we can configure same IP on interfaces
 *  in different VRFs.
 */
DP_START_TEST(vrf_if_cfg, duplicate_ip)
{
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* put another interface into TEST_VRF */
	dp_test_netlink_set_interface_vrf("dp2T2", TEST_VRF);

	/* assign IP to the interface which is in DEFAULT_VRF */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/* assign same IP to the interface in TEST_VRF */
	dp_test_netlink_add_ip_address_vrf("dp2T2", "1.1.1.1/24", TEST_VRF);

	/* remove IP from dp1T1 interface */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");

	/* remove IP from dp2T2 interface */
	dp_test_netlink_del_ip_address_vrf("dp2T2", "1.1.1.1/24", TEST_VRF);

	/* put an interface back into the default VRF */
	dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;

DP_DECL_TEST_CASE(vrf_suite, vrf_ip_route, NULL, NULL);

/*
 *  Simple case to test route addition and deletion in a VRF
 */
DP_START_TEST(vrf_ip_route, route_add_delete)
{
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* put an interface into TEST_VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", TEST_VRF);

	/* Add route */
	dp_test_netlink_add_route("vrf:50 2.2.2.0/24 nh int:dp1T1");

	dp_test_wait_for_vrf(TEST_VRF, 2);

	/* Delete route */
	dp_test_netlink_del_route("vrf:50 2.2.2.0/24 nh int:dp1T1");

	dp_test_wait_for_vrf(TEST_VRF, 2);

	/* put the interface back into the default VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;

/*
 *  Show that the route having nh in other VRF can be added in a VRF
 */
DP_START_TEST(vrf_ip_route, inter_vrf_route)
{
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* put an interface into TEST_VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", TEST_VRF);

	/* Add route pointing to interface in VRF_DEFAULT */
	dp_test_netlink_add_route("vrf:50 2.2.2.0/24 nh int:dp2T2");

	/* Delete route */
	dp_test_netlink_del_route("vrf:50 2.2.2.0/24 nh int:dp2T2");

	/* put the interface back into the default VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;


/* Delete an interface with a static route via it in another VRF
 * and check if static and connected routes are deleted
 */
DP_START_TEST(vrf_ip_route, vrf_if_del_static)
{
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "1.1.2.1/24");

	dp_test_intf_gre_create("tun1", "1.1.2.1", "1.1.2.2", 0,
				TEST_VRF);

	/* assign same IP to the interface in TEST_VRF */
	dp_test_netlink_add_ip_address_vrf("tun1", "2.2.2.2/24", TEST_VRF);

	/* Add a connected route */
	dp_test_netlink_add_route("vrf:50 2.2.2.0/24 nh int:tun1");

	/* Add static route via this interface in DEFAULT_VRF */
	dp_test_netlink_add_route("10.0.0.0/8 nh 2.2.2.3 int:tun1");

	/* Delete the interface and its local address */
	dp_test_netlink_del_ip_address_vrf("tun1", "2.2.2.2/24", TEST_VRF);
	dp_test_intf_gre_delete("tun1", "1.1.2.1", "1.1.2.2", 0,
				TEST_VRF);

	/* Check if the connected route is removed
	 * static route deletion is tested in END macro
	 */
	dp_test_verify_del_route("vrf:50 2.2.2.0/24 nh int:tun1", false);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "1.1.2.1/24");

	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;

/*
 *  Test case to ensure ref count only increments on the first route and
 *  decrements on the last route del.
 */
DP_START_TEST(vrf_ip_route, multi_route_add_delete)
{
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* put an interface into TEST_VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", TEST_VRF);

	/* Add route */
	dp_test_netlink_add_route("vrf:50 2.2.2.0/24 nh int:dp1T1");

	dp_test_wait_for_vrf(TEST_VRF, 2);

	/* Add few more routes */
	dp_test_netlink_add_route("vrf:50 3.2.2.0/24 nh int:dp1T1");
	dp_test_netlink_add_route("vrf:50 4.2.2.0/24 nh int:dp1T1");

	/* Verify that refcount remains the same */
	dp_test_wait_for_vrf(TEST_VRF, 2);

	/* Delete couple of routes */
	dp_test_netlink_del_route("vrf:50 2.2.2.0/24 nh int:dp1T1");
	dp_test_netlink_del_route("vrf:50 3.2.2.0/24 nh int:dp1T1");

	/* Verify that refcount remains the same */
	dp_test_wait_for_vrf(TEST_VRF, 2);

	/* Remove last route */
	dp_test_netlink_del_route("vrf:50 4.2.2.0/24 nh int:dp1T1");

	/* Verify that refcount is decremented */
	dp_test_wait_for_vrf(TEST_VRF, 2);

	/* put the interface back into the default VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;

DP_DECL_TEST_CASE(vrf_suite, vrf_cfg, NULL, NULL);

/*
 * Test the scenario whereby routes for a VRF arrive before the VRF
 * master link creation
 *
 * Due to the presence of the broker, there is a chance that route
 * updates for a table that is the main table for a VRF could arrive
 * before the link message advising the dataplane of the VRF master
 * interface and its association with the table.
 *
 * Verify that in this sequence of events when the VRF master device
 * is signalled that the routes make it into the VRF. Just for good
 * measure, check that a delete and recreate works too.
 */
DP_START_TEST(vrf_cfg, out_of_seq_vrfmaster_v4)
{
	char vrf_name[IFNAMSIZ + 1];
	uint32_t tableid;
	bool ret;

	/* Get the table id for the VRF table */
	ret = dp_test_upstream_vrf_add_db(TEST_VRF, vrf_name, &tableid);
	dp_test_fail_unless(ret, "maximum vrf limit reached\n");

	/* Add the VRF route, although we don't know it's a VRF route yet */
	dp_test_nl_add_route_incomplete_fmt(
		"tbl:%d 2.2.2.0/24 nh int:dp1T1", tableid);

	/* The route shouldn't be there */
	dp_test_wait_for_route_gone("vrf:50 2.2.2.0/24 nh int:dp1T1", true,
				    __FILE__, __func__, __LINE__);

	/* Now add the VRF */
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* Check that it now appears in the VRF */
	dp_test_wait_for_route("vrf:50 2.2.2.0/24 nh int:dp1T1", true);

	/* Delete and recreate the VRF */
	_dp_test_intf_vrf_master_delete(vrf_name, TEST_VRF,
					tableid, __FILE__, __LINE__);
	_dp_test_intf_vrf_master_create(vrf_name, TEST_VRF,
					tableid, __FILE__, __LINE__);

	/* Check the route has been deleted */
	dp_test_wait_for_route_gone("vrf:50 2.2.2.0/24 nh int:dp1T1", true,
				    __FILE__, __func__, __LINE__);

	dp_test_netlink_del_vrf(TEST_VRF, 1);
} DP_END_TEST;

DP_START_TEST(vrf_cfg, out_of_seq_vrfmaster_v6)
{
	char vrf_name[IFNAMSIZ + 1];
	uint32_t tableid;
	bool ret;

	/* Get the table id for the VRF table */
	ret = dp_test_upstream_vrf_add_db(TEST_VRF, vrf_name, &tableid);
	dp_test_fail_unless(ret, "maximum vrf limit reached\n");

	/* Add the VRF route, although we don't know it's a VRF route yet */
	dp_test_nl_add_route_incomplete_fmt(
		"tbl:%d 2:2:2::/64 nh int:dp1T1", tableid);

	/* The route shouldn't be there */
	dp_test_wait_for_route_gone("vrf:50 2:2:2::/64 nh int:dp1T1", true,
				    __FILE__, __func__, __LINE__);

	/* Now add the VRF */
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* Check that it now appears in the VRF */
	dp_test_wait_for_route("vrf:50 2:2:2::/64 nh int:dp1T1", true);

	/* Delete and recreate the VRF */
	_dp_test_intf_vrf_master_delete(vrf_name, TEST_VRF,
					tableid, __FILE__, __LINE__);
	_dp_test_intf_vrf_master_create(vrf_name, TEST_VRF,
					tableid, __FILE__, __LINE__);

	/* Check the route has been deleted */
	dp_test_wait_for_route_gone("vrf:50 2:2:2::/64 nh int:dp1T1", true,
				    __FILE__, __func__, __LINE__);

	dp_test_netlink_del_vrf(TEST_VRF, 1);
} DP_END_TEST;

DP_DECL_TEST_CASE(vrf_suite, vrf_ip6_cfg, NULL, NULL);

/*
 * Check that we can add and delete ipv6 routes to a VRF
 */
DP_START_TEST(vrf_ip6_cfg, route_add_del)
{
	dp_test_netlink_add_vrf(TEST_VRF, 1);

	/* put an interface into TEST_VRF */
	dp_test_netlink_set_interface_vrf("dp1T0", TEST_VRF);
	dp_test_netlink_set_interface_vrf("dp2T1", TEST_VRF);

	/* Verify that VRF is created and refcount is 3 after interface bind */
	dp_test_wait_for_vrf(TEST_VRF, 3);

	/* Set up the interface addresses */
	dp_test_netlink_add_ip_address_vrf("dp1T0", "2001:1:1::1/64", TEST_VRF);
	/* Verify that refcount is the same after 1st interface IP add */
	dp_test_wait_for_vrf(TEST_VRF, 3);

	dp_test_netlink_add_route("vrf:50 2001:1:1::/64 nh int:dp1T0");
	/* Verify that refcount doesn't increment */
	dp_test_wait_for_vrf(TEST_VRF, 3);

	dp_test_netlink_add_ip_address_vrf("dp2T1", "2002:2:2::2/64", TEST_VRF);
	dp_test_netlink_add_route("vrf:50 2002:2:2::/64 nh int:dp2T1");

	/* Add a route and check it */
	dp_test_netlink_add_route(/* Just to keep checkpatch happy */
				  "vrf:50 2010:73:2::/48 nh 2002:2:2::1 int:dp2T1"
				 );

	/* Now remove the route and check it has gone */
	dp_test_netlink_del_route(
				  "vrf:50 2010:73:2::/48 nh 2002:2:2::1 int:dp2T1"
				 );

	/* Clean Up */
	dp_test_netlink_del_route("vrf:50 2001:1:1::/64 nh int:dp1T0");
	dp_test_netlink_del_ip_address_vrf("dp1T0", "2001:1:1::1/64", TEST_VRF);
	dp_test_netlink_del_route("vrf:50 2002:2:2::/64 nh int:dp2T1");

	/* Verify that refcount doesn't decrement after route deletion */
	dp_test_wait_for_vrf(TEST_VRF, 3);

	dp_test_netlink_del_ip_address_vrf("dp2T1", "2002:2:2::2/64", TEST_VRF);

	/* Verify that refcount remains the same after last intf IP delete */
	dp_test_wait_for_vrf(TEST_VRF, 3);

	dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp2T1", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF, 0);
} DP_END_TEST;

DP_DECL_TEST_CASE(vrf_suite, vrf_ip_fwd, NULL, NULL);

#define TEST_VRF2 55

DP_START_TEST(vrf_ip_fwd, vrf_basic_ipv4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	dp_test_netlink_add_vrf(TEST_VRF2, 1);

	/* Set up the interface addresses */
	dp_test_netlink_set_interface_vrf("dp1T0", TEST_VRF2);

	dp_test_netlink_add_ip_address_vrf("dp1T0", "1.1.1.1/24", TEST_VRF2);
	dp_test_netlink_add_route("vrf:55 1.1.1.0/24 nh int:dp1T0");

	dp_test_netlink_set_interface_vrf("dp1T1", TEST_VRF2);

	dp_test_netlink_add_ip_address_vrf("dp2T1", "2.2.2.2/24", TEST_VRF2);
	dp_test_netlink_add_route("vrf:55 2.2.2.0/24 nh int:dp2T1");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("vrf:55 10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("vrf:55 10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_netlink_del_route("vrf:55 2.2.2.0/24 nh int:dp2T1");
	dp_test_netlink_del_route("vrf:55 1.1.1.0/24 nh int:dp1T0");
	dp_test_netlink_del_ip_address_vrf("dp1T0", "1.1.1.1/24", TEST_VRF2);
	dp_test_netlink_del_ip_address_vrf("dp2T1", "2.2.2.2/24", TEST_VRF2);
	/* put an interface back into DEFAULT_VRF */
	dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
	/* put an interface back into DEFAULT_VRF */
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF2, 0);
} DP_END_TEST;

DP_START_TEST(vrf_ip_fwd, vrf_basic_ipv6)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];
	char route3[TEST_MAX_CMD_LEN];

	dp_test_netlink_add_vrf(TEST_VRF2, 1);

	/* Set up the interface addresses */
	dp_test_netlink_set_interface_vrf("dp1T0", TEST_VRF2);
	dp_test_netlink_add_ip_address_vrf("dp1T0", "2001:1:1::1/64",
					   TEST_VRF2);
	snprintf(route1, sizeof(route1), "vrf:%d 2001:1:1::0/64 nh int:dp1T0",
		 TEST_VRF2);
	dp_test_netlink_add_route(route1);

	dp_test_netlink_set_interface_vrf("dp2T1", TEST_VRF2);
	dp_test_netlink_add_ip_address_vrf("dp2T1", "2002:2:2::2/64",
					   TEST_VRF2);
	snprintf(route2, sizeof(route2), "vrf:%d 2002:2:2::0/64 nh int:dp2T1",
		 TEST_VRF2);
	dp_test_netlink_add_route(route2);

	/* Add the route / nh arp we want the packet to follow */
	snprintf(route3, sizeof(route3),
		 "vrf:%d 2010:73:2::/48 nh 2002:2:2::1 int:dp2T1", TEST_VRF2);
	dp_test_netlink_add_route(route3);

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv6_pak("2010:73::", "2010:73:2::",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T0"),
				 NULL, ETHER_TYPE_IPv6);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str("dp2T1"),
				       ETHER_TYPE_IPv6);

	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1", nh_mac_str);

	dp_test_netlink_del_route(route3);
	dp_test_netlink_del_route(route2);
	dp_test_netlink_del_route(route1);
	dp_test_netlink_del_ip_address_vrf("dp1T0", "2001:1:1::1/64",
					   TEST_VRF2);
	dp_test_netlink_del_ip_address_vrf("dp2T1", "2002:2:2::2/64",
					   TEST_VRF2);
	/* put an interface back into DEFAULT_VRF */
	dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
	/* put an interface back into DEFAULT_VRF */
	dp_test_netlink_set_interface_vrf("dp2T1", VRF_DEFAULT_ID);

	dp_test_netlink_del_vrf(TEST_VRF2, 0);
} DP_END_TEST;

DP_DECL_TEST_CASE(vrf_suite, vrf_ip_fwd2, NULL, NULL);

/*
 * Add a v6 connected and address, and the v6 multicast route. Then add a
 * neighbour.
 *
 * Delete the interface route, and verify that it can all be tidied. The
 * multicast route is modified as part of the tidy. This maps to a set of
 * updates that were seen to cause an issue in the live system.
 */
DP_START_TEST(vrf_ip_fwd2, vrf_basic_ipv6)
{
	const char *nh_mac_str;

	dp_test_netlink_add_vrf(TEST_VRF2, 1);


	dp_test_netlink_set_interface_vrf("dp2T1", TEST_VRF2);
	dp_test_netlink_set_interface_vrf("dp1T1", TEST_VRF2);

	/* Link local (ours) */
	dp_test_netlink_add_ip_address_vrf("dp1T1",
					   "fe80::4056:1ff:fee8:101/128",
					   TEST_VRF2);

	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "2012::1/24",
						 TEST_VRF2);

	/* mcast via dp1T1 and dp2T1 */
	dp_test_netlink_replace_route_nv(
		"vrf:55 ff00::/8 nh int:dp1T1 nh int:dp2T1");

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "2012::2", nh_mac_str);

	/*
	 * Now start deleting.
	 */
	dp_test_netlink_del_route("vrf:55 2012::/24 scope:253 nh int:dp1T1");

	dp_test_netlink_replace_route_nv("vrf:55 ff00::/8 nh int:dp1T1");

	dp_test_netlink_del_ip_address_vrf("dp1T1", "2012::1/24",
					   TEST_VRF2);
	dp_test_netlink_del_neigh("dp1T1", "2012::2", nh_mac_str);

	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);
	dp_test_netlink_del_ip_address_vrf("dp1T1",
					   "fe80::4056:1ff:fee8:101/128",
					   TEST_VRF2);

	dp_test_netlink_set_interface_vrf("dp2T1", VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);
	dp_test_netlink_del_vrf(TEST_VRF2, 0);

} DP_END_TEST;


DP_DECL_TEST_CASE(vrf_suite, vrf_vif_ipv4, NULL, NULL)
DP_START_TEST(vrf_vif_ipv4, vrf_vif_ipv4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	const char *l3_intf = "dp1T3"; /* default vrf */
	const char *l3_vif_intf = "dp1T3.20"; /* non default vrf */
	uint16_t vlan_id = 20;
	const char *l3_intf_tx = "dp2T1";

	dp_test_intf_vif_create(l3_vif_intf, l3_intf, vlan_id);

	dp_test_netlink_add_vrf(TEST_VRF2, 1);

	/* Set up the interface addresses */
	dp_test_netlink_set_interface_vrf(l3_vif_intf, TEST_VRF2);
	dp_test_netlink_add_ip_address_vrf(l3_vif_intf, "1.1.1.1/24",
					   TEST_VRF2);
	dp_test_netlink_add_route("vrf:55 1.1.1.0/24 nh int:dp1T3.20");

	dp_test_netlink_set_interface_vrf(l3_intf_tx, TEST_VRF2);
	dp_test_netlink_add_ip_address_vrf(l3_intf_tx, "2.2.2.2/24", TEST_VRF2);
	dp_test_netlink_add_route("vrf:55 2.2.2.0/24 nh int:dp2T1");

	/* Add the route / nh arp we want the packet to follow */
	dp_test_netlink_add_route("vrf:55 10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh(l3_intf_tx, "2.2.2.1", nh_mac_str);

	/* Create pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0",
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str(l3_vif_intf),
				 NULL, ETHER_TYPE_IPv4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, l3_intf_tx);

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str,
				       dp_test_intf_name2mac_str(l3_intf_tx),
				       ETHER_TYPE_IPv4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pktmbuf_vlan_init(test_pak, vlan_id);
	dp_test_pak_receive(test_pak, l3_intf, exp);

	/* Clean Up */
	dp_test_netlink_del_neigh(l3_intf_tx, "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("vrf:55 10.73.2.0/24 nh 2.2.2.1 int:dp2T1");
	dp_test_netlink_del_route("vrf:55 2.2.2.0/24 nh int:dp2T1");
	dp_test_netlink_del_route("vrf:55 1.1.1.0/24 nh int:dp1T3.20");
	dp_test_netlink_del_ip_address_vrf(l3_vif_intf, "1.1.1.1/24",
					   TEST_VRF2);
	dp_test_netlink_del_ip_address_vrf(l3_intf_tx, "2.2.2.2/24", TEST_VRF2);
	dp_test_netlink_set_interface_vrf(l3_vif_intf, VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf(l3_intf_tx, VRF_DEFAULT_ID);
	dp_test_intf_vif_del(l3_vif_intf, vlan_id);

	dp_test_netlink_del_vrf(TEST_VRF2, 0);
} DP_END_TEST;
