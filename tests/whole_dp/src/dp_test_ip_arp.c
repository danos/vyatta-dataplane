/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <net/if_arp.h>
#include <libmnl/libmnl.h>
#include <linux/random.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_cmd_state.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"

struct nh_info {
	const char *nh_int;
	const char *nh_mac_str;
	const char *gw;
	bool arp;
	bool drop;
};

#define BCAST_MAC "ff:ff:ff:ff:ff:ff"
#define DONTCARE_MAC "0:0:0:0:0:0"
static void _build_and_send_pak(const char *src_addr, const char *dest_addr,
				struct nh_info nh, const char *func, int line)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	struct rte_mbuf *exp_pak;
	const char *dest = dest_addr;

	test_pak = dp_test_create_ipv4_pak(src_addr, dest_addr,
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV4);
	if (nh.arp) {
		char intf_addr[INET_ADDRSTRLEN];


		dp_test_intf_name2addr_str(nh.nh_int, AF_INET, intf_addr,
					   INET_ADDRSTRLEN);
		if (nh.gw)
			dest = nh.gw;
		/* We don't know how to reach this address, so send an arp */
		exp_pak = dp_test_create_arp_pak(
			ARPOP_REQUEST,
			dp_test_intf_name2mac_str(nh.nh_int),
			BCAST_MAC,
			dp_test_intf_name2mac_str(nh.nh_int), DONTCARE_MAC,
			intf_addr, dest, 0);

		exp = dp_test_exp_create_with_packet(exp_pak);
		dp_test_exp_set_oif_name(exp, nh.nh_int);
	} else if (nh.drop) {
		exp = dp_test_exp_create(test_pak);
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	} else {
		/* Create pak we expect to receive on the tx ring */
		exp = dp_test_exp_create(test_pak);
		(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
					       nh.nh_mac_str,
					       dp_test_intf_name2mac_str(
						       nh.nh_int),
					       RTE_ETHER_TYPE_IPV4);
		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
		dp_test_exp_set_oif_name(exp, nh.nh_int);
	}

	_dp_test_pak_receive(test_pak, "dp1T0", exp, __FILE__, func, line);

	if (nh.arp) {
		/* Clear up the arp entry we just created by sending the req */
		dp_test_neigh_clear_entry(nh.nh_int, dest);
	}
}

#define build_and_send_pak(src_addr, dest_addr, nh) \
	_build_and_send_pak(src_addr, dest_addr, nh, __func__, __LINE__)

DP_DECL_TEST_SUITE(ip_arp_suite);

DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_32_connected, NULL, NULL);
/*
 * Add a connected /32 and check that we get an arp shortcut and that we
 * can send a packet to the destination.
 *
 * Verify that it does not override a local route.
 *
 * Check that we don't modify a /32 when we get an arp for that addr on
 * a different interface.
 */
DP_START_TEST(ip_arp_32_connected, ip_arp_32_connected)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str,
			      .nh_int = "dp1T1"};
	struct nh_info nh_arp = {.nh_int = "dp1T1",
				 .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	/* Add a route and check it */
	dp_test_netlink_add_route("2.2.2.1/32 nh int:dp1T1");

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	dp_test_verify_route_neigh_present("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(0);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp);

	/* Now remove the route and check it has gone */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str);
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_netlink_del_route("2.2.2.1/32 nh int:dp1T1");
	dp_test_verify_neigh_created_count(0);

	/*
	 * Add an arp entry for the local address and make sure that
	 * it does not take precedence over the local entry.
	 */
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.2", nh_mac_str2);
	dp_test_verify_route_no_neigh_present("2.2.2.2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.2", nh_mac_str2);

	/*
	 * Verify that the neigh does not override a /32 on a different
	 * interface.
	 */
	dp_test_netlink_add_route("3.3.3.0/24 nh int:dp1T1");
	dp_test_netlink_add_route("3.3.3.3/32 nh 2.2.2.2 int:dp1T2");
	dp_test_netlink_add_neigh("dp1T1", "3.3.3.3", nh_mac_str2);
	dp_test_verify_route_no_neigh_present("3.3.3.3");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 nh 2.2.2.2 int:dp1T2", true);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T1", "3.3.3.3", nh_mac_str2);
	dp_test_netlink_del_route("3.3.3.0/24 nh int:dp1T1");
	dp_test_netlink_del_route("3.3.3.3/32 nh 2.2.2.2 int:dp1T2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
} DP_END_TEST;

/*
 * This time add the connected, add the neigh, delete the connected
 * then delete the neigh
 */
DP_START_TEST(ip_arp_32_connected, ip_arp_32_connected_2)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	/* Add neigh */
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	/* Delete connected */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	/* Delete neigh */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str);
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_32_create, NULL, NULL);
/*
 * Create an arp entry with a connected cover and check that a /32 is
 * created for us.
 */
DP_START_TEST(ip_arp_32_connected, ip_arp_32_create)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str,
			      .nh_int = "dp1T1"};
	struct nh_info nh_arp = {.nh_int = "dp1T1",
				 .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp);

	/* Now remove the neigh and check the /32 has gone */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str);

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

} DP_END_TEST;


DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_gw_link, NULL, NULL);
/*
 * Create an arp entry for an address within a connected /24.
 * have a route via a GW in that /24 where the arp address is
 * that of the GW.
 *
 * connected: 2.2.2.2/24
 * route with GW of 2.2.2.1
 * add arp entry for 2.2.2.1
 */
DP_START_TEST(ip_arp_gw_link, ip_arp_gw_link)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str,
			      .nh_int = "dp1T1"};
	struct nh_info nh_arp = {.nh_int = "dp1T1",
				 .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_netlink_add_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");

	dp_test_verify_route_no_neigh_present("10.73.2.0");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str);
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T1", true);
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);

	/*
	 * nh for 10.73.2.0 should be neigh present
	 * nh for 2.2.2.1 should be neigh created
	 */
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp);
	build_and_send_pak("10.73.0.0", "10.73.2.2", nh1);

	/* Now remove the neigh and check the neigh info has gone */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_present("10.73.2.0");
	dp_test_verify_route_no_neigh_present("2.2.2.1");

	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
} DP_END_TEST;


DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_32_create_change_cover, NULL, NULL);
/*
 * Create an arp entry with a connected /24 cover and check that a /32 is
 * created for us. Add a new /28 route to be the new cover and check
 * all variations.
 *
 * connected 2.2.2.0/24 dp1T1
 * arp 2.2.2.1 on dp1T1, /32 for 2.2.2.1 created
 * arp 2.2.2.3 on dp1T2, no changes due to this
 * add 2.2.2.0/28 dp1T1 - keep the interface the same - /32 stays
 * add 2.2.2.0/26 dp1T2 - /32 stays (as /28 is the cover of /32)
 * remove /28 - the /26 now becomes the cover, so /32 goes
 * remove /26 - the /24 now becomes the cover, so /32 comes back.
 *
 */
DP_START_TEST(ip_arp_32_connected, ip_arp_32_create_change_cover)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:fe";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:ff";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};
	struct nh_info nh2 = {.nh_mac_str = nh_mac_str2,
			      .nh_int = "dp1T2"};
	struct nh_info nh_arp1 = {.nh_int = "dp1T1",
				  .arp = true};
	struct nh_info nh_arp2 = {.nh_int = "dp1T2",
				  .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_add_neigh("dp1T2", "2.2.2.3", nh_mac_str2);

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_present("2.2.2.3");
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	/*
	 * 2.2.2.3 needs to arp out of dp1T1 as that is the route, even
	 * though there is an arp entry on dp1T2.
	 */
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "2.2.2.4", nh_arp1);

	/*
	 * Add the /28 out of the same interface.
	 */
	dp_test_netlink_add_route("2.2.2.0/28 nh int:dp1T1");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "2.2.2.4", nh_arp1);

	/*
	 * Add the /26 out of a different interface. /28 changes cover.
	 */
	dp_test_netlink_add_route("2.2.2.0/26 nh int:dp1T2");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "2.2.2.4", nh_arp1);

	/*
	 * Delete the /28, the /26 becomes the cover.
	 * remove the /32 for 2.2.2.1, add a /32 for 2.2.2.3
	 */
	dp_test_netlink_del_route("2.2.2.0/28 nh int:dp1T1");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_route_neigh_created("2.2.2.3", "dp1T2", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh_arp2);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh2);
	build_and_send_pak("10.73.0.0", "2.2.2.4", nh_arp2);

	/*
	 * Delete the /26, the /24 becomes the cover.
	 * remove the /32 for 2.2.2.3, add a /32 for 2.2.2.1
	 */
	dp_test_netlink_del_route("2.2.2.0/26 nh int:dp1T2");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "2.2.2.4", nh_arp1);

	/* Now remove the neigh and check the /32 has gone */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp1T2", "2.2.2.3", nh_mac_str2);

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh_arp1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "2.2.2.4", nh_arp1);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
} DP_END_TEST;


/*
 * Create an arp entry with a connected /24 cover and check that a /32
 * is created for us. Add a new non-connected /32 route over the top
 * of the ARP entry and check that it takes precedence.
 *
 * connected 2.2.2.0/24 dp1T1
 * arp 2.2.2.1 on dp1T1, /32 for 2.2.2.1 created
 * add 2.2.2.1/32 blackhole - check it take precedence
 * remove /32 - the /24 now becomes the cover, so /32 comes back.
 */
DP_START_TEST(ip_arp_32_connected, ip_arp_32_overwrite_non_conn)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:fe";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};
	struct nh_info nh_drop = {.nh_int = "dp1T1",
				  .drop = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str1);

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);

	/*
	 * Add the /31 blackhole.
	 */
	dp_test_netlink_add_route("2.2.2.0/31 blackhole");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh_drop);

	/*
	 * Delete the /31 blackhole, the /24 becomes the cover.
	 */
	dp_test_netlink_del_route("2.2.2.0/31 blackhole");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);

	/*
	 * Add the /32 blackhole.
	 */
	dp_test_netlink_add_route("2.2.2.1/32 blackhole");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh_drop);

	/*
	 * Delete the /32 blackhole, the /24 becomes the cover.
	 */
	dp_test_netlink_del_route("2.2.2.1/32 blackhole");
	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);

	/* Now remove the neigh and check the /32 has gone */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str1);

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_32_connected_ecmp, NULL, NULL);
/*
 * Add a connected /32 and then add ecmp paths and check all is good.
 *
 * add 2.2.2.2/24 for dp1T1
 * add 2.2.2.3/32 out of dp1T1   // the connected /32
 * add neigh for 2.2.2.3 out of dp1T1  // make this neigh present
 * change 2.2.2.3/32 to be out of dp1T1 and dp1T21
 * del neigh for 2.2.2.3 out of dp1T1
 * add neigh for 2.2.2.3 out of dp1T1
 * change 2.2.2.3/32 to be out of dp1T2
 * change 2.2.2.3/32 to be out of dp1T1
 */
DP_START_TEST(ip_arp_32_connected_ecmp, ip_arp_32_connected_ecmp)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:fe";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};
	struct nh_info nh_arp1 = {.nh_int = "dp1T1",
				  .arp = true};
	struct nh_info nh_arp2 = {.nh_int = "dp1T2",
				  .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2.2.3.2/24");

	/* Add the /32 */
	dp_test_netlink_add_route("2.2.2.3/32 nh int:dp1T1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_no_neigh_present("2.2.2.3");

	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);

	/* Add the neighbour */
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.3", nh_mac_str1);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_neigh_present("2.2.2.3", "dp1T1", true);

	build_and_send_pak("10.73.0.0", "2.2.2.3", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.4", nh_arp1);

	/* Change route to be ecmp */
	dp_test_netlink_replace_route("2.2.2.3/32 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_neigh_present("2.2.2.3", "dp1T1", true);
	dp_test_verify_route_neigh_present("2.2.2.3", "dp1T2", false);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(0);

	/* hash algo takes us out of dp1T1 */
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh1);

	/* del the neighbour */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.3", nh_mac_str1);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_no_neigh_present("2.2.2.3");

	/* del then readd the route to verify route still there */
	dp_test_netlink_del_route("2.2.2.3/32 nh int:dp1T1 nh int:dp1T2");
	dp_test_netlink_add_route("2.2.2.3/32 nh int:dp1T1 nh int:dp1T2");

	/* Add the neighbour */
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.3", nh_mac_str1);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_neigh_present("2.2.2.3", "dp1T1", true);
	dp_test_verify_route_neigh_present("2.2.2.3", "dp1T2", false);

	/*
	 * Change the route to be out of interface without neigh.
	 * Arp does not override routing info, so can't link it here.
	 */
	dp_test_netlink_replace_route("2.2.2.3/32 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_no_neigh_present("2.2.2.3");

	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp2);

	/*
	 * Change the route to be out of interface with neigh.
	 */
	dp_test_netlink_replace_route("2.2.2.3/32 nh int:dp1T1");
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_neigh_present("2.2.2.3", "dp1T1", true);

	build_and_send_pak("10.73.0.0", "2.2.2.3", nh1);

	/*
	 * Delete route, the /32 becomes neigh created
	 */
	dp_test_netlink_del_route("2.2.2.3/32 nh int:dp1T1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("2.2.2.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("2.2.2.3", "dp1T2", false);
	dp_test_verify_route_no_neigh_present("2.2.2.3");

	build_and_send_pak("10.73.0.0", "2.2.2.3", nh1);

	/* Delete arp */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.3", nh_mac_str1);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("2.2.2.3");
	dp_test_verify_route_no_neigh_present("2.2.2.3");

	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2.2.3.2/24");
} DP_END_TEST;


DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_32_create_ecmp, NULL, NULL);
/*
 * Create an arp entry with a connected cover and check that a /32 is
 * created for us.
 *
 * add a connected via 2 interfaces, then add an arp entry to
 * each interface and check that the routes are as expected.
 *
 * add 3.3.3.0/24 int1
 * add 3.3.3.0/24 int2
 * add arp for 3.3.3.3 int1 - create 3.3.3.3/32, NH NEIGH_CREATED, 1 path.
 * add arp for 3.3.3.3 int2 - add 2nd NEIGH_CREATED, to NH (now 2 paths)
 * del arp for 3.3.3.3 int2 - del 2nd NEIGH_CREATED, from NH (now 1 paths)
 * del arp for 3.3.3.3 int1 - del 3.3.3.3/32 and NH.
 *
 * add arp for 3.3.3.3 int1 - create 3.3.3.3/32, NH NEIGH_CREATED, 1 path.
 * add route 3.3.3.3/32 int and int2.  NH for 3.3.3.3/32 should change to
 *                                     having 2 paths, the one via int1 being
 *                                     NEIGH_PRESENT.
 * del route 3.3.3.3/32 int and int2.  NH for 3.3.3.3/32 reverts back to 1
 *                                     path, NEIGH_CREATED.
 * add route 3.3.3.3/32 int and int2.  NH for 3.3.3.3/32 should change to
 *                                     having 2 paths, the one via int1 being
 *                                     NEIGH_PRESENT.
 * del arp for 3.3.3.3 int1.           NH for 3.3.3.3 should change to 2 path
 *                                     but no NEIGH FLAGS.
 * del route 3.3.3.3/32 int and int2.  route and NH deleted.
 *
 */
DP_START_TEST(ip_arp_32_create_ecmp, ip_arp_32_create_ecmp)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};
	struct nh_info nh_arp1 = {.nh_int = "dp1T1",
				  .arp = true};
	struct nh_info nh_arp2 = {.nh_int = "dp1T2",
				  .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2.2.3.3/24");

	dp_test_netlink_add_route("3.3.3.0/24 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	/* Add arp for first interface */
	dp_test_netlink_add_neigh("dp1T1", "3.3.3.3", nh_mac_str1);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);

	/* ecmp route hash algo picks NH1 */
	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	/* ecmp route hash algo pick dp1T2 */
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp2);
	/* ecmp route hash algo pick dp1T1 */
	build_and_send_pak("10.73.0.0", "3.3.3.5", nh_arp1);

	/*
	 * Add arp for second interface. 3.3.3.3/32 exists and has a NH
	 * for dp1T2 that was inherited from the cover. This needs to
	 * become NEIGH_CREATED as we don't have a /32 route for this NH
	 * from routing.
	 */
	dp_test_netlink_add_neigh("dp1T2", "3.3.3.3", nh_mac_str2);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", true);
	dp_test_verify_route_neigh_present("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh NC int:dp1T2", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);

	/*
	 * Delete the first arp we added. Should then revert back to
	 * two paths, the first inherited with no NEIGH flags, the second
	 * being NEIGH_CREATED.
	 */
	dp_test_netlink_del_neigh("dp1T1", "3.3.3.3", nh_mac_str1);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", false);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* And delete the other */
	dp_test_netlink_del_neigh("dp1T2", "3.3.3.3", nh_mac_str2);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("3.3.3.3");

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh_arp1);

	/* Clean Up */
	dp_test_netlink_del_route("3.3.3.0/24 nh int:dp1T1 nh int:dp1T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2.2.3.3/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_32_create_ecmp_add_route, NULL, NULL);
/*
 * Create an arp entry with a connected cover and check that a /32 is
 * created for us.
 *
 * add a connected via 2 interfaces, then add an arp entry to
 * each interface and check that the routes are as expected.
 *
 * add 3.3.3.0/24 int1
 * add 3.3.3.0/24 int2
 * add arp for 3.3.3.3 int1 - create 3.3.3.3/32, NH NEIGH_CREATED
 *                            inherit path for int2
 * add arp for 3.3.3.3 int2 - add 2nd NEIGH_CREATED, now to NC paths
 * add 3.3.3.0/28 int1 - should move to single path /32 out of int 1,
 *                       int2 NC path goes away
 * change 3.3.3.0/28 to be via int1 and int2, both paths come back
 * add add 3.3.3.0/29 int1, so back to single path with 1 NC
 * delete neighbours - /32 goes away.
 */
DP_START_TEST(ip_arp_32_create_ecmp_add_route, ip_arp_32_create_ecmp_add_route)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};
	struct nh_info nh_arp1 = {.nh_int = "dp1T1",
				  .arp = true};
	struct nh_info nh_arp2 = {.nh_int = "dp1T2",
				  .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2.2.3.3/24");

	dp_test_netlink_add_route("3.3.3.0/24 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	/* Add arp for first interface */
	dp_test_netlink_add_neigh("dp1T1", "3.3.3.3", nh_mac_str1);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);

	/* ecmp route hash algo picks NH1 */
	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	/* ecmp route hash algo pick dp1T2 */
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp2);
	/* ecmp route hash algo pick dp1T1 */
	build_and_send_pak("10.73.0.0", "3.3.3.5", nh_arp1);

	/* Add arp for second interface */
	dp_test_netlink_add_neigh("dp1T2", "3.3.3.3", nh_mac_str2);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh NC int:dp1T2", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);

	/* Insert a /28 with single path */
	dp_test_netlink_add_route("3.3.3.0/28 nh int:dp1T1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp1);

	/* Change the /28 to multi path */
	dp_test_netlink_replace_route("3.3.3.0/28 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh NC int:dp1T2", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	/* changed to ecmp and hash algo takes it out dp1T2 */
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp2);

	/* Add a /29, moving back to single path */
	dp_test_netlink_add_route("3.3.3.0/29 nh int:dp1T1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp1);

	/* delete neighbours */
	dp_test_netlink_del_neigh("dp1T1", "3.3.3.3", nh_mac_str1);
	dp_test_netlink_del_neigh("dp1T2", "3.3.3.3", nh_mac_str2);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("3.3.3.3");

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp1);

	/* Clean Up */
	dp_test_netlink_del_route("3.3.3.0/29 nh int:dp1T1");
	dp_test_netlink_del_route("3.3.3.0/28 nh int:dp1T1 nh int:dp1T2");
	dp_test_netlink_del_route("3.3.3.0/24 nh int:dp1T1 nh int:dp1T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2.2.3.3/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_gw_link_ecmp, NULL, NULL);
/*
 * Create an arp entry for an address within a connected /24.
 * have a route via a GW in that /24 where the arp address is
 * that of the GW.
 *
 * connected: 2.2.2.2/24 dp1T1
 * connected: 2.2.3.2/24 dp1T2
 * add route 10.73.2.0/24 with GW of 2.2.2.1 and 2.2.3.1
 * add arp entry for 2.2.2.1 and 2.2.3.1
 */
DP_START_TEST(ip_arp_gw_link_ecmp, ip_arp_gw_link_ecmp)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:fe";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:ff";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};
	struct nh_info nh2 = {.nh_mac_str = nh_mac_str2,
			      .nh_int = "dp1T2"};
	struct nh_info nh_arp1 = {.nh_int = "dp1T1",
				  .arp = true};

	struct nh_info nh_arp_gw1 = {.nh_int = "dp1T1",
				     .gw = "2.2.2.1",
				     .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2.2.3.2/24");

	dp_test_netlink_add_route(
		"10.73.2.0/24 nh 2.2.2.1 int:dp1T1 nh 2.2.3.1 int:dp1T2");

	dp_test_verify_route_no_neigh_present("10.73.2.0");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	/* Add neighbour for 2.2.2.1 */
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str1);
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T1", true);
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);

	/* nh for 10.73.2.0 should be neigh present */
	dp_test_verify_neigh_present_count(1);
	/* nh for 2.2.2.1 should be neigh created */
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "10.73.2.2", nh1);

	/* Now remove the neigh and check the neigh info has gone */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str1);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_present("10.73.2.0");
	dp_test_verify_route_no_neigh_present("2.2.2.1");

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh_arp1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "10.73.2.2", nh_arp_gw1);

	/* bring neigh back */
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str1);
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T1", true);
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(1);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "10.73.2.2", nh1);

	/* Add neigh for other path */
	dp_test_netlink_add_neigh("dp1T2", "2.2.3.1", nh_mac_str2);
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T1", true);
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T2", true);
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_route_neigh_created("2.2.3.1", "dp1T2", true);
	dp_test_verify_neigh_present_count(2);
	dp_test_verify_neigh_created_count(2);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "10.73.2.2", nh1);
	build_and_send_pak("10.73.0.0", "10.73.2.3", nh2);

	/* Modify route to become single path */
	dp_test_netlink_replace_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T1", true);
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T2", false);
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_route_neigh_created("2.2.3.1", "dp1T2", true);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(2);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "10.73.2.2", nh1);
	build_and_send_pak("10.73.0.0", "10.73.2.3", nh1);

	/* Modify route back to 2 paths again. */
	dp_test_netlink_replace_route(
		"10.73.2.0/24 nh 2.2.2.1 int:dp1T1 nh 2.2.3.1 int:dp1T2");
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T1", true);
	dp_test_verify_route_neigh_present("10.73.2.0", "dp1T2", true);
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	dp_test_verify_route_neigh_created("2.2.3.1", "dp1T2", true);
	dp_test_verify_neigh_present_count(2);
	dp_test_verify_neigh_created_count(2);

	build_and_send_pak("10.73.0.0", "2.2.2.1", nh1);
	build_and_send_pak("10.73.0.0", "2.2.2.3", nh_arp1);
	build_and_send_pak("10.73.0.0", "10.73.2.2", nh1);
	build_and_send_pak("10.73.0.0", "10.73.2.3", nh2);

	/* Tidy */
	dp_test_netlink_del_neigh("dp1T2", "2.2.3.1", nh_mac_str2);
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str1);
	dp_test_netlink_del_route("10.73.2.0/24 nh 2.2.2.1 int:dp1T1");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2.2.3.2/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_32_create_ecmp_change_cover, NULL, NULL);
/*
 * Create an arp entry with a connected cover and check that a /32 is
 * created for us.
 *
 * add a connected via 2 interfaces, then add an arp entry to
 * each interface and check that the routes are as expected.
 *
 * add 3.3.3.0/24 int1
 * add 3.3.3.0/24 int2
 * add arp for 3.3.3.3 int1 - create 3.3.3.3/32, 2 paths, 1 NC.
 * add arp for 3.3.3.4 int2 - create 3.3.3.4/32, 2 paths, 1 NC.
 *
 * add 3.3.3.0/28 int1 - .3/32 should become single path
 *                       .4/32 should be removed
 * change 3.3.3.0/28 to be out int1 and int2, .3/32 back to 2 path, 1NC
 *                                            .4/32 back to 2 path, 1NC
 * add 3.3.3.0/29 int1 - .3/32 should become single path
 *                       .4/32 should be removed
 * change 3.3.3.0/29 to be out int1 and int2 .3/32 back to 2 path, 1NC
 *                                           .4/32 back to 2 path, 1NC
 * change 3.3.3.0/28 to be ecmp out int1 and int3 - no change to forwarding
 * delete the /29 - .3/32 becomes 2 path 1 NC and 1 out int3
 *                  .4/32 is removed
 * re-add the /29 with 2 paths  .3/32 back to 2 path, 1NC
 *                              .4/32 back to 2 path, 1NC
 * change the /28 to be single path int1 - no forwarding changes.
 * delete neigh 3.3.3.4 - .4/32 goes
 * add neigh 3.3.3.3 int2 - now have this out int1 and int2
 *                        .3/32 2 paths, both NC
 * delete the /29 - .3/32 drops down to 1 path NC
 */
DP_START_TEST(ip_arp_32_create_ecmp_change_cover,
	      ip_arp_32_create_ecmp_change_cover)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	const char *nh_mac_str1_2 = "aa:bb:cc:dd:ee:fd";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};
	struct nh_info nh2 = {.nh_mac_str = nh_mac_str2,
			      .nh_int = "dp1T2"};
	struct nh_info nh_arp1 = {.nh_int = "dp1T1",
				  .arp = true};
	struct nh_info nh_arp2 = {.nh_int = "dp1T2",
				  .arp = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2.2.3.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T3", "2.2.4.2/24");

	dp_test_netlink_add_route("3.3.3.0/24 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	/* Add arp for first interface */
	dp_test_netlink_add_neigh("dp1T1", "3.3.3.3", nh_mac_str1);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);

	/* ecmp route hash algo picks NH1 */
	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	/* ecmp route hash algo pick dp1T2 */
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp2);
	/* ecmp route hash algo pick dp1T1 */
	build_and_send_pak("10.73.0.0", "3.3.3.5", nh_arp1);

	/*
	 * Add arp for second interface, different address selected to
	 * use different ecmp path.
	 */
	dp_test_netlink_add_neigh("dp1T2", "3.3.3.4", nh_mac_str2);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.4/32 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);

	/* Insert a /28 with single path */
	dp_test_netlink_add_route("3.3.3.0/28 nh int:dp1T1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1", true);
	dp_test_verify_route_no_neigh_created("3.3.3.4");

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp1);

	/* Change the /28 to multi path */
	dp_test_netlink_replace_route("3.3.3.0/28 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.4/32 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	/* changed to ecmp and hash algo takes it out dp1T2 */
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh2);

	/* Add a /29, moving back to single path */
	dp_test_netlink_add_route("3.3.3.0/29 nh int:dp1T1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1", true);
	dp_test_verify_route_no_neigh_created("3.3.3.4");

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh_arp1);

	/* Change /29 to be multipath */
	dp_test_netlink_replace_route("3.3.3.0/29 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.4/32 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh2);

	/* Change /28 to be ecmp but with different paths to /29 */
	dp_test_netlink_replace_route("3.3.3.0/28 nh int:dp1T1 nh int:dp1T3");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.4/32 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);
	build_and_send_pak("10.73.0.0", "3.3.3.4", nh2);

	/* Delete the /29, should now use the /28 */
	dp_test_netlink_del_route("3.3.3.0/29 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T3", true);
	dp_test_verify_route_no_neigh_created("3.3.3.4");

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh1);

	/*
	 * Now want to test a 2 path NH, where both are NEIGH_CREATED.
	 * Then remove the cover, with the new cover having no connected for
	 * one of the NEIGH_CREATED, thus forcing it to be deleted, but the
	 * other one remaining.
	 */

	dp_test_netlink_add_route("3.3.3.0/29 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.4/32 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* Change the /28 to be single path again */
	dp_test_netlink_replace_route("3.3.3.0/28 nh int:dp1T1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.4/32 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* Delete the neigh out of int2.*/
	dp_test_netlink_del_neigh("dp1T2", "3.3.3.4", nh_mac_str2);
	dp_test_verify_route_no_neigh_created("3.3.3.4");

	/* Add a neigh for 3.3.3.3 out of int2, now have that addr on 2 ints */
	dp_test_netlink_add_neigh("dp1T2", "3.3.3.3", nh_mac_str1_2);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(2);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1 nh NC int:dp1T2", true);

	/*
	 * Delete the /29, and the NEIGH_CREATED should go for dp1T2
	 * as the cover of that does not have a path out that interface.
	 */
	dp_test_netlink_del_route("3.3.3.0/29 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(1);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3.3.3.3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3.3.3.3/32 scope:253 nh NC int:dp1T1", true);

	/* delete neighbours */
	dp_test_netlink_del_neigh("dp1T1", "3.3.3.3", nh_mac_str1);
	dp_test_netlink_del_neigh("dp1T2", "3.3.3.3", nh_mac_str1_2);
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);
	dp_test_verify_route_no_neigh_created("3.3.3.3");

	build_and_send_pak("10.73.0.0", "3.3.3.3", nh_arp1);

	/* Clean Up */
	dp_test_netlink_del_route("3.3.3.0/28 nh int:dp1T1");
	dp_test_netlink_del_route("3.3.3.0/24 nh int:dp1T1 nh int:dp1T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2.2.3.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "2.2.4.2/24");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_nh_share, NULL, NULL);
DP_START_TEST(ip_arp_nh_share,
	      ip_arp_nh_share)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	int idx, idx2;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2.2.3.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T3", "2.2.4.2/24");

	dp_test_netlink_add_route(
		"3.3.3.0/24 nh 2.2.2.1 int:dp1T1 nh 2.2.3.1 int:dp1T2");
	dp_test_netlink_add_route(
		"3.3.4.0/24 nh 2.2.2.1 int:dp1T1 nh 2.2.3.1 int:dp1T2");

	/* Verify the 2 routes are sharing a NH */
	idx = dp_test_get_nh_idx("3.3.3.0");
	idx2 = dp_test_get_nh_idx("3.3.4.0");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);

	/* Add an arp entry, and then reverify */
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.1", nh_mac_str1);
	dp_test_verify_route_neigh_created("2.2.2.1", "dp1T1", true);
	idx = dp_test_get_nh_idx("3.3.3.0");
	idx2 = dp_test_get_nh_idx("3.3.4.0");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(1);

	/* Add a further route, make sure it shares too */
	dp_test_netlink_add_route(
		"3.3.5.0/24 nh 2.2.2.1 int:dp1T1 nh 2.2.3.1 int:dp1T2");
	idx = dp_test_get_nh_idx("3.3.3.0");
	idx2 = dp_test_get_nh_idx("3.3.4.0");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	idx2 = dp_test_get_nh_idx("3.3.5.0");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(1);

	/* Add a 2nd neigh */
	dp_test_netlink_add_neigh("dp1T2", "2.2.3.1", nh_mac_str2);
	idx = dp_test_get_nh_idx("3.3.3.0");
	idx2 = dp_test_get_nh_idx("3.3.4.0");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	idx2 = dp_test_get_nh_idx("3.3.5.0");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh_present_count(2);
	dp_test_verify_neigh_created_count(2);

	/* Remove a route */
	dp_test_netlink_del_route(
		"3.3.4.0/24 nh 2.2.2.1 int:dp1T1 nh 2.2.3.1 int:dp1T2");
	idx = dp_test_get_nh_idx("3.3.3.0");
	idx2 = dp_test_get_nh_idx("3.3.5.0");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh_present_count(2);
	dp_test_verify_neigh_created_count(2);

	/* Remove a neigh */
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.1", nh_mac_str1);
	idx = dp_test_get_nh_idx("3.3.3.0");
	idx2 = dp_test_get_nh_idx("3.3.5.0");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh_present_count(1);
	dp_test_verify_neigh_created_count(1);

	/* Final tidy */
	dp_test_netlink_del_neigh("dp1T2", "2.2.3.1", nh_mac_str2);
	dp_test_netlink_del_route(
		"3.3.3.0/24 nh 2.2.2.1 int:dp1T1 nh 2.2.3.1 int:dp1T2");
	dp_test_netlink_del_route(
		"3.3.5.0/24 nh 2.2.2.1 int:dp1T1 nh 2.2.3.1 int:dp1T2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2.2.3.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "2.2.4.2/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_arp_suite, ip_arp_nh_scale, NULL, NULL);
/*
 * Not run by default due to the time taken to set up and remove all
 * the neigh entries. This test is usefuls for testing efficiency of
 * the route processing code, with minor additions into the code
 * to print out time taken processing routes.
 */
DP_START_TEST_DONT_RUN(ip_arp_nh_scale,
		       ip_arp_nh_scale)
{
	char nh_mac_str[18];
	struct rte_ether_addr start_eth_addr = {
					{ 0xf0, 0x0, 0x0, 0x0, 0x0, 0x0 } };
	struct rte_ether_addr rte_ether_addr;
	int start_ip_addr = 0x02020301;
	char ip_addr_str[INET_ADDRSTRLEN];
	int ip_addr;
	int i;
	int num_neighs = 3000;
	uint32_t *ether;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.0.2/16");

	/* add neighbours */
	ip_addr = start_ip_addr;
	rte_ether_addr = start_eth_addr;
	ether = (uint32_t *)&rte_ether_addr;
	for (i = 0; i < num_neighs; i++) {
		int tmp_ip = htonl(ip_addr);
		if (!inet_ntop(AF_INET, &tmp_ip, ip_addr_str, INET_ADDRSTRLEN))
			assert(0);

		if (!ether_ntoa_r(&rte_ether_addr, nh_mac_str))
			assert(0);
		dp_test_netlink_add_neigh("dp1T1", ip_addr_str, nh_mac_str);
		ip_addr++;
		(*ether)++;
	}

	dp_test_netlink_add_route("3.3.4.0/24 nh 2.2.3.1 int:dp1T1");
	dp_test_netlink_del_route("3.3.4.0/24 nh 2.2.3.1 int:dp1T1");

	/* del neighbours */
	ip_addr = start_ip_addr;
	rte_ether_addr = start_eth_addr;
	for (i = 0; i < num_neighs; i++) {
		int tmp_ip = htonl(ip_addr);

		if (!inet_ntop(AF_INET, &tmp_ip, ip_addr_str, INET_ADDRSTRLEN))
			assert(0);

		if (!ether_ntoa_r(&rte_ether_addr, nh_mac_str))
			assert(0);

		dp_test_netlink_del_neigh("dp1T1", ip_addr_str, nh_mac_str);
		ip_addr++;
		(*ether)++;
	}

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.0.2/16");

} DP_END_TEST;
