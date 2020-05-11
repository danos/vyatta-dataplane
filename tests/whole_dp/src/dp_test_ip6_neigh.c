/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <libmnl/libmnl.h>
#include <linux/random.h>

#include "ip_funcs.h"
#include "in6.h"
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

struct nh_info {
	const char *nh_int;
	const char *nh_mac_str;
	const char *gw;
	bool drop;
	bool resolve;
};

#define BCAST_MAC "ff:ff:ff:ff:ff:ff"
#define DONTCARE_MAC "0:0:0:0:0:0"
static void _build_and_send_pak(const char *src_addr, const char *dest_addr,
				struct nh_info nh, const char *func, int line)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	const char *dest = dest_addr;

	test_pak = dp_test_create_ipv6_pak(src_addr, dest_addr,
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak,
				 dp_test_intf_name2mac_str("dp1T0"),
				 DP_TEST_INTF_DEF_SRC_MAC,
				 RTE_ETHER_TYPE_IPV6);
	if (nh.drop || nh.resolve) {
		exp = dp_test_exp_create(test_pak);
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	} else {
		/* Create pak we expect to receive on the tx ring */
		exp = dp_test_exp_create(test_pak);
		(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
					       nh.nh_mac_str,
					       dp_test_intf_name2mac_str(
						       nh.nh_int),
					       RTE_ETHER_TYPE_IPV6);
		dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));
		dp_test_exp_set_oif_name(exp, nh.nh_int);
	}

	_dp_test_pak_receive(test_pak, "dp1T0", exp, __FILE__, func, line);

	if (nh.resolve) {
		/* Clear up the arp entry we just created by sending the req */
		dp_test_neigh_clear_entry(nh.nh_int, dest);
	}
}

#define build_and_send_pak(src_addr, dest_addr, nh) \
	_build_and_send_pak(src_addr, dest_addr, nh, __func__, __LINE__)

DP_DECL_TEST_SUITE(ip_neigh_suite);

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_128_connected, NULL, NULL);
/*
 * Add a connected /128 and check that we get an neigh shortcut and that we
 * can send a packet to the destination.
 *
 * Verify that it does not override a local route.
 *
 * Check that we don't modify a /128 when we get an neigh for that addr on
 * a different interface.
 */
DP_START_TEST(ip_neigh_128_connected, ip_neigh_128_connected)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str,
			      .nh_int = "dp1T1"};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

	/* Add a route and check it */
	dp_test_netlink_add_route("2002:2:2::1/128 nh int:dp1T1");

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::1", nh_mac_str);

	dp_test_verify_route_neigh_present("2002:2:2::1", "dp1T1", true);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(0);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/* Now remove the route and check it has gone */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::1", nh_mac_str);
	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_netlink_del_route("2002:2:2::1/128 nh int:dp1T1");
	dp_test_verify_neigh6_created_count(0);

	/*
	 * Add an neigh entry for the local address and make sure that
	 * it does not take precedence over the local entry.
	 */
	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::2", nh_mac_str2);
	dp_test_verify_route_no_neigh_present("2002:2:2::2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::2", nh_mac_str2);

	/*
	 * Verify that the neigh does not override a /128 on a different
	 * interface.
	 */
	dp_test_netlink_add_route("3003:3:3::/64 nh int:dp1T1");
	dp_test_netlink_add_route("3003:3:3::3/128 nh 2002:2:2::2 int:dp1T2");
	dp_test_netlink_add_neigh("dp1T1", "3003:3:3::3", nh_mac_str2);
	dp_test_verify_route_no_neigh_present("3003:3:3::3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_add_route_all(
		"3003:3:3::3/128 nh 2002:2:2::2 int:dp1T2", true);

	/* Clean Up */
	dp_test_netlink_del_neigh("dp1T1", "3003:3:3::3", nh_mac_str2);
	dp_test_netlink_del_route("3003:3:3::3/128 nh 2002:2:2::2 int:dp1T2");
	dp_test_netlink_del_route("3003:3:3::/64 nh int:dp1T1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
} DP_END_TEST;

/*
 * This time add the connected, add the neigh, delete the connected
 * then delete the neigh
 */
DP_START_TEST(ip_neigh_128_connected, ip_neigh_128_connected_2)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

	/* Add neigh */
	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::1", nh_mac_str);
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	/* Delete connected */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* Delete neigh */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::1", nh_mac_str);
} DP_END_TEST;

/*
 * Create an neigh entry with a connected cover and check that a /128 is
 * created for us.
 */
DP_START_TEST(ip_neigh_128_connected, ip_neigh_128_create)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str,
			      .nh_int = "dp1T1"};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::1", nh_mac_str);

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	/* Create pak to match the new /128 */
	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/* Now remove the neigh and check the /128 has gone */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::1", nh_mac_str);

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

} DP_END_TEST;

/*
 * Create an ND entry with a connected /64 cover and check that a /128
 * is created for us. Add a new non-connected /128 route over the top
 * of the ND entry and check that it takes precedence.
 */
DP_START_TEST(ip_neigh_128_connected, ip_neigh_128_overwrite_non_conn)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str,
			      .nh_int = "dp1T1"};
	struct nh_info nh_drop = {.nh_int = "dp1T1",
				  .drop = true};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::1", nh_mac_str);

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	/* Create pak to match the new /128 */
	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/*
	 * Add the /127 blackhole.
	 */
	dp_test_netlink_add_route("2002:2:2::/127 blackhole");
	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh_drop);

	/*
	 * Delete the /127 blackhole, the /64 becomes the cover.
	 */
	dp_test_netlink_del_route("2002:2:2::/127 blackhole");
	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/*
	 * Add the /128 blackhole.
	 */
	dp_test_netlink_add_route("2002:2:2::1/128 blackhole");
	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_neigh_present_count(0);
	dp_test_verify_neigh_created_count(0);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh_drop);

	/*
	 * Delete the /128 blackhole, the /64 becomes the cover.
	 */
	dp_test_netlink_del_route("2002:2:2::1/128 blackhole");
	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/* Now remove the neigh and check the /128 has gone */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::1", nh_mac_str);

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_gw_link, NULL, NULL);
/*
 * Create a neigh entry for an address within a connected /64.
 * have a route via a GW in that /64 where the neigh address is
 * that of the GW.
 *
 * connected 2002:2:2::2/64
 * route with GW of 2002:2:2::100
 * add neigh entry for 2002:2:2::100
 */
DP_START_TEST(ip_neigh_gw_link, ip_neigh_gw_link)
{
	const char *nh_mac_str = "aa:bb:cc:dd:ee:ff";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str,
			      .nh_int = "dp1T1"};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

	dp_test_netlink_add_route("3000:1::/64 nh 2002:2:2::100 int:dp1T1");

	dp_test_verify_route_no_neigh_present("3000:1::0");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::100", nh_mac_str);
	dp_test_verify_route_neigh_present("3000:1::0", "dp1T1", true);
	dp_test_verify_route_neigh_created("2002:2:2::100", "dp1T1", true);

	/*
	 * nh for 3000:1::0 should be neigh present
	 * nh for 2002:2:2::100 should be neigh created
	 */
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(1);

	build_and_send_pak("2001:1:1::1", "2002:2:2::100", nh1);
	build_and_send_pak("2001:1:1::1", "3000:1::2", nh1);

	/* Now remove the neigh and check the neigh info has gone */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::100", nh_mac_str);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_present("3000:1::0");
	dp_test_verify_route_no_neigh_created("2002:2:2::100");

	dp_test_netlink_del_route("3000:1::/64 nh 2002:2:2::100 int:dp1T1");
	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_128_create_change_cover, NULL, NULL);
/*
 * Create an neigh entry with a connected /64 cover and check that a /128 is
 * created for us. Add a new /96 route to be the new cover and check
 * all variations.
 *
 * connected 2002:2:2::2/64 dp1T1
 * neigh 2002:2:2::1 on dp1T1, /128 for 2002:2:2::1 created
 * neigh 2002:2:2::2 on dp1T2, no changes due to this
 * add 2002:2:2::/96 dp1T1 - keep the interface the same - /128 stays
 * add 2002:2:2::/90 dp1T2 - /128 stays (as /96 is cover of /128)
 * remove /96 - the /90 now becomes the cover, so /128 for .1 goes
 * remove /90 - the /64 now becomes the cover, so /128 for .3 comes back.
 */
DP_START_TEST(ip_neigh_128_connected, ip_neigh_128_create_change_cover)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:fe";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:ff";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};
	struct nh_info nh2 = {.nh_mac_str = nh_mac_str2,
			      .nh_int = "dp1T2"};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::1", nh_mac_str1);
	dp_test_netlink_add_neigh("dp1T2", "2002:2:2::3", nh_mac_str2);

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_route_no_neigh_present("2002:2:2::3");
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/*
	 * Add the /96 out of the same interface.
	 */
	dp_test_netlink_add_route("2002:2:2::/96 nh int:dp1T1");
	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_route_no_neigh_present("2002:2:2::3");
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/*
	 * Add the /90 out of a different interface. /96 remains
	 * immediate cover, so no change to the neigh.
	 */
	dp_test_netlink_add_route("2002:2:2::/90 nh int:dp1T2");

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_route_no_neigh_present("2002:2:2::3");
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/*
	 * Delete the /96, the /90 becomes the cover and is using
	 * a different interface, so remove the /128 for 2002:2:2::1,
	 * add a /128 for 2002:2:2::3
	 */
	dp_test_netlink_del_route("2002:2:2::/96 nh int:dp1T1");

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_route_no_neigh_present("2002:2:2::3");
	dp_test_verify_route_neigh_created("2002:2:2::3", "dp1T2", true);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	build_and_send_pak("2001:1:1::2", "2002:2:2::3", nh2);

	/*
	 * Delete the /90, the /64 becomes the cover.
	 * remove the /128 for 2002:2:2::3 and add a /128 for 2002:2:2::1
	 */
	dp_test_netlink_del_route("2002:2:2::/90 nh int:dp1T2");

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	dp_test_verify_route_no_neigh_present("2002:2:2::3");
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);

	build_and_send_pak("2001:1:1::2", "2002:2:2::1", nh1);

	/* Now remove the neigh and check the /128 has gone */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::1", nh_mac_str1);
	dp_test_netlink_del_neigh("dp1T2", "2002:2:2::3", nh_mac_str2);

	dp_test_verify_route_no_neigh_present("2002:2:2::1");
	dp_test_verify_route_no_neigh_created("2002:2:2::1");
	dp_test_verify_route_no_neigh_present("2002:2:2::3");
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	dp_test_verify_route_no_neigh_present("2.2.2.1");
	dp_test_verify_route_no_neigh_created("2.2.2.1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_128_connected_ecmp, NULL, NULL);
/*
 * Add a connected /128 and then add ecmp paths and check all is good.
 *
 * connected 2002:2:2::2/64 dp1T1
 * add 2002:2:2::3/128 dp1T1 // the connected /128
 * add neigh for 2002:2:2::3 out of dp1T1  // make this neigh present
 * change 2002:2:2::3/128 to be out of dp1T1 and dp1T21
 * del neigh for 2002:2:2::3 out of dp1T1
 * add neigh for 2002:2:2::3 out of dp1T1
 * change 2002:2:2::3/128 to be out of dp1T2
 * change 2002:2:2::3/128 to be out of dp1T1
 */
DP_START_TEST(ip_neigh_128_connected_ecmp, ip_neigh_128_connected_ecmp)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:fe";
	struct nh_info nh1 = {.nh_mac_str = nh_mac_str1,
			      .nh_int = "dp1T1"};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");

	/* Add the /128 */
	dp_test_netlink_add_route("2002:2:2::3/128 nh int:dp1T1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_route_no_neigh_present("2002:2:2::3");

	/* Add the neighbour */
	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::3", nh_mac_str1);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_route_neigh_present("2002:2:2::3", "dp1T1", true);

	build_and_send_pak("2001:1:1::2", "2002:2:2::3", nh1);

	/* Change route to be ecmp */
	dp_test_netlink_replace_route(
		"2002:2:2::3/128 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_route_neigh_present("2002:2:2::3", "dp1T1", true);
	dp_test_verify_route_neigh_present("2002:2:2::3", "dp1T2", false);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(0);

	/* del the neighbour */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::3", nh_mac_str1);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_route_no_neigh_present("2002:2:2::3");

	/* del then readd the route to verify route still there */
	dp_test_netlink_del_route("2002:2:2::3/128 nh int:dp1T1 nh int:dp1T2");
	dp_test_netlink_add_route("2002:2:2::3/128 nh int:dp1T1 nh int:dp1T2");

	/* Add the neighbour */
	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::3", nh_mac_str1);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_route_neigh_present("2002:2:2::3", "dp1T1", true);

	/*
	 * Change the route to be out of interface without neigh.
	 * Neigh does not override routing info, so can't link it here.
	 */
	dp_test_netlink_replace_route("2002:2:2::3/128 nh int:dp1T2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_route_no_neigh_present("2002:2:2::3");

	/*
	 * Change the route to be out of interface with neigh.
	 */
	dp_test_netlink_replace_route("2002:2:2::3/128 nh int:dp1T1");
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_route_neigh_present("2002:2:2::3", "dp1T1", true);

	build_and_send_pak("2001:1:1::2", "2002:2:2::3", nh1);

	/*
	 * Delete route, the /128 becomes neigh created
	 */
	dp_test_netlink_del_route("2002:2:2::3/128 nh int:dp1T1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("2002:2:2::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("2002:2:2::3", "dp1T2", false);
	dp_test_verify_route_no_neigh_present("2002:2:2::3");

	build_and_send_pak("2001:1:1::2", "2002:2:2::3", nh1);

	/* Delete neigh */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::3", nh_mac_str1);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("2002:2:2::3");
	dp_test_verify_route_no_neigh_present("2002:2:2::3");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_128_create_ecmp, NULL, NULL);
/*
 * Create a neigh entry with a connected cover and check that a /128 is
 * created for us.
 *
 * add a connected via 2 interfaces, then add an neigh entry to
 * each interface and check that the routes are as expected.
 *
 * connected 2001:1:1::1/64 dp1T0
 * connected 2002:2:2::2/64 dp1T1
 * connected 2003:3:3::3/64 dp1T2
 *
 * add 3003:3::/64 int1/int2
 *
 * add neigh for 3003:3::3 int1 - create 3003:3::3/128, NH NEIGH_CREATED,
 *                                1 path.
 * add neigh for 3003:3::3 int2 - add 2nd NEIGH_CREATED, to NH (now 2 paths)
 * del neigh for 3003:3::3 int2 - del 2nd NEIGH_CREATED, from NH (now 1 paths)
 * del neigh for 3003:3::3 int1 - del 3003:3::3/128 and NH.
 *
 * add neigh for 3003:3::3 int1 create 3003:3::3/128, NH NEIGH_CREATED, 1 path.
 * add route 3003:3::3/128 int/int2.  NH for 3003:3::3/128 should change to
 *                                    having 2 paths, the one via int1 being
 *                                    NEIGH_PRESENT.
 * del route 3003:3::3/128 int/int2.  NH for 3003:3::3/128 reverts back to 1
 *                                    path, NEIGH_CREATED.
 * add route 3003:3::3/128 int/int2.  NH for 3003:3::3/128 should change to
 *                                    having 2 paths, the one via int1 being
 *                                    NEIGH_PRESENT.
 * del neigh for 3003:3::3 int1.      NH for 3003:3::3/128 should change to
 *                                    2 path but no NEIGH FLAGS.
 * del route 3003:3::3/128 int/int2.  route and NH deleted.
 */
DP_START_TEST(ip_neigh_128_create_ecmp, ip_neigh_128_create_ecmp)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");

	dp_test_netlink_add_route("3003:3::/64 nh int:dp1T1 nh int:dp1T2");

	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* Add arp for first interface */
	dp_test_netlink_add_neigh("dp1T1", "3003:3::3", nh_mac_str1);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);

	/*
	 * Add arp for second interface. 3003:3::3/128 exists and has a NH
	 * for dp1T2 that was inherited from the cover. This needs to
	 * become NEIGH_CREATED as we don't have a /128 route for this NH
	 * from routing.
	 */
	dp_test_netlink_add_neigh("dp1T2", "3003:3::3", nh_mac_str2);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh NC int:dp1T2",
		true);

	/*
	 * Delete the first neigh we added. Should then revert back to
	 * two paths, the first inherited with no NEIGH flags, the second
	 * being NEIGH_CREATED.
	 */
	dp_test_netlink_del_neigh("dp1T1", "3003:3::3", nh_mac_str1);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", false);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* And delete the other */
	dp_test_netlink_del_neigh("dp1T2", "3003:3::3", nh_mac_str2);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("3003:3::3");


	/* Clean Up */
	dp_test_netlink_del_route("3003:3::/64 nh int:dp1T1 nh int:dp1T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_128_create_ecmp_add_route,
		  NULL, NULL);
/*
 * Create a neigh entry with a connected cover and check that a /128 is
 * created for us.
 *
 * connected 2001:1:1::1/64 dp1T0
 * connected 2002:2:2::2/64 dp1T1
 * connected 2003:3:3::3/64 dp1T2
 *
 * add a connected via 2 interfaces, then add a neigh entry to
 * each interface and check that the routes are as expected.
 *
 * add 3003:3::/64 int1/int2
 * add neigh for 3003:3::3 int1 - create 3003:3::3/128, NEIGH_CREATED, 1 path.
 *                                inherit path for int2.
 * add neigh for 3003:3::3 int2 - change int2 path to NEIGH_CREATED
 * add 3003:3::3/96 int1 - should move to single path /32 out of int 1,
 *                         int2 NC path goes away
 * change 3003:3::3/96 to be via int1/int2, both paths come back
 * add 3003:3::3/100 int1, so back to single path with 1 NC
 */
DP_START_TEST(ip_neigh_128_create_ecmp_add_route,
	      ip_neigh_128_create_ecmp_add_route)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");

	dp_test_netlink_add_route("3003:3::/64 nh int:dp1T1 nh int:dp1T2");

	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* Add arp for first interface */
	dp_test_netlink_add_neigh("dp1T1", "3003:3::3", nh_mac_str1);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);

	/* Add arp for second interface */
	dp_test_netlink_add_neigh("dp1T2", "3003:3::3", nh_mac_str2);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh NC int:dp1T2",
		true);

	/* Insert a /96 with single path */
	dp_test_netlink_add_route("3003:3::/96 nh int:dp1T1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1", true);

	/* Change the /96 to multi path */
	dp_test_netlink_replace_route("3003:3::/96 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh NC int:dp1T2",
		true);

	/* Add a /100, moving back to single path */
	dp_test_netlink_add_route("3003:3::/100 nh int:dp1T1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1", true);


	/* delete neighbours */
	dp_test_netlink_del_neigh("dp1T1", "3003:3::3", nh_mac_str1);
	dp_test_netlink_del_neigh("dp1T2", "3003:3::3", nh_mac_str2);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("3003:3::3");

	/* Clean Up */
	dp_test_netlink_del_route("3003:3::/100 nh int:dp1T1");
	dp_test_netlink_del_route("3003:3::/96 nh int:dp1T1 nh int:dp1T2");
	dp_test_netlink_del_route("3003:3::/64 nh int:dp1T1 nh int:dp1T2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");
} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_gw_link_ecmp, NULL, NULL);
/*
 * Create a neigh entry for an address within a connected /64.
 * have a route via a GW in that /64 where the neigh address is
 * that of the GW.
 *
 * connected 2001:1:1::1/64 dp1T0
 * connected 2002:2:2::2/64 dp1T1
 * connected 2003:3:3::3/64 dp1T2
 *
 * add route 3003:3::/64 gw 2002:2::3 int1 gw 2003:3::4 int2
 * add neigh entry for 2002:2::3
 * add neigh entry for 2001:1::3
 */
DP_START_TEST(ip_neigh_gw_link_ecmp, ip_neigh_gw_link_ecmp)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:fe";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:ff";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");

	dp_test_netlink_add_route(
		"3003:3::/64 nh 2002:2:2::3 int1:dp1T1 "
		"nh 2003:3:3::4 int:dp1T2");

	dp_test_verify_route_no_neigh_present("3003:3::");
	dp_test_verify_route_no_neigh_present("2002:2:2::3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* Add neighbour for 2.2.2.1 */
	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::3", nh_mac_str1);
	dp_test_verify_route_neigh_present("3003:3::", "dp1T1", true);
	dp_test_verify_route_neigh_present("3003:3::", "dp1T2", false);
	dp_test_verify_route_neigh_created("2002:2:2::3", "dp1T1", true);

	/* nh for 3003:3::3 should be neigh present */
	dp_test_verify_neigh6_present_count(1);
	/* nh for 2002:2::3 should be neigh created */
	dp_test_verify_neigh6_created_count(1);

	/* Now remove the neigh and check the neigh info has gone */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::3", nh_mac_str1);
	dp_test_verify_route_no_neigh_present("3003:3::");
	dp_test_verify_route_no_neigh_present("2002:2:2::3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* bring neigh back */
	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::3", nh_mac_str1);
	dp_test_verify_route_neigh_present("3003:3::", "dp1T1", true);
	dp_test_verify_route_neigh_present("3003:3::", "dp1T2", false);
	dp_test_verify_route_neigh_created("2002:2:2::3", "dp1T1", true);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(1);

	/* Add neigh for other path */
	dp_test_netlink_add_neigh("dp1T2", "2003:3:3::4", nh_mac_str2);

	dp_test_verify_route_neigh_present("3003:3::", "dp1T1", true);
	dp_test_verify_route_neigh_present("3003:3::", "dp1T2", true);
	dp_test_verify_route_neigh_created("2002:2:2::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("2003:3:3::4", "dp1T2", true);
	dp_test_verify_neigh6_present_count(2);
	dp_test_verify_neigh6_created_count(2);

	/* Modify route to become single path */
	dp_test_netlink_replace_route("3003:3::/64 nh 2002:2:2::3 int:dp1T1");
	dp_test_verify_route_neigh_present("3003:3::", "dp1T1", true);
	dp_test_verify_route_neigh_present("3003:3::", "dp1T2", false);
	dp_test_verify_route_neigh_created("2002:2:2::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("2003:3:3::4", "dp1T2", true);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(2);

	/* Modify route back to 2 paths again. */
	dp_test_netlink_replace_route(
		"3003:3::/64 nh 2002:2:2::3 int:dp1T1 "
		"nh 2003:3:3::4 int:dp1T2");
	dp_test_verify_route_neigh_present("3003:3::", "dp1T1", true);
	dp_test_verify_route_neigh_present("3003:3::", "dp1T2", true);
	dp_test_verify_route_neigh_created("2002:2:2::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("2003:3:3::4", "dp1T2", true);
	dp_test_verify_neigh6_present_count(2);
	dp_test_verify_neigh6_created_count(2);

	/* Tidy */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::3", nh_mac_str1);
	dp_test_netlink_del_neigh("dp1T2", "2003:3:3::4", nh_mac_str2);
	dp_test_netlink_del_route(
		"3003:3::/64 nh 2002:2:2::3 int:dp1T1 "
		"nh 2003:3:3::4 int:dp1T2");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_128_create_ecmp_change_cover,
		  NULL, NULL);
/*
 * Create a neigh entry with a connected cover and check that a /128 is
 * created for us.
 *
 * add a connected via 2 interfaces, then add a neigh entry to
 * each interface and check that the routes are as expected.
 *
 * connected 2001:1:1::1/64 dp1T0
 * connected 2002:2:2::2/64 dp1T1
 * connected 2003:3:3::3/64 dp1T2
 *
 * add 3003:3::/64 int1/int2
 *
 * add arp for 3003:3::3 int1 - create 3003:3::3/128, 2 paths, 1 NC.
 * add arp for 3003:3::4 int2 - create 3003:3::4/128, 2 paths, 1 NC.
 *
 * add 3003:3::/96 int1 - .3/128 should become single path
 *                      .4/128 should be removed
 * change 3003:3::/96 to be out int1 and int2, .3/128 back to 2 path, 1NC
 *                                             .4/128 back to 2 path, 1NC
 * add 3003:3::/100 int1 - .3/128 should become single path
 *                         .4/128 should be removed
 * change 3003:3::/100 to be out int1 and int2 .3/128 back to 2 path, 1NC
 *                                             .4/128 back to 2 path, 1NC
 * change 3003:3::/96 to be ecmp out int1 and int3 - no change to forwarding
 * delete the /100 - .3/128 becomes 2 path 1 NC and 1 out int3
 *                   .4/128 is removed
 * re-add the /100 with 2 paths  .3/128 back to 2 path, 1NC
 *                               .4/128 back to 2 path, 1NC
 * change the /96 to be single path int1 - no forwarding changes.
 * delete neigh 3003:3::4 - .4/128 goes
 * add neigh 3003:3::3 int2 - now have this out int1 and int2
 *                            .3/128 2 paths, both NC
 * delete the /100 - .3/128 drops down to 1 path NC
 */
DP_START_TEST(ip_neigh_128_create_ecmp_change_cover,
	      ip_neigh_128_create_ecmp_change_cover)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	const char *nh_mac_str1_2 = "aa:bb:cc:dd:ee:fd";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2004:4:4::4/64");

	dp_test_netlink_add_route("3003:3::/64 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);

	/* Add neigh for first interface */
	dp_test_netlink_add_neigh("dp1T1", "3003:3::3", nh_mac_str1);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);

	/*
	 * Add neigh for second interface, different address selected to
	 * use different ecmp path.
	 */
	dp_test_netlink_add_neigh("dp1T2", "3003:3::4", nh_mac_str2);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::4/128 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);


	/* Insert a /96 with single path */
	dp_test_netlink_add_route("3003:3::/96 nh int:dp1T1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1", true);
	dp_test_verify_route_no_neigh_created("3003:3::4");

	/* Change the /96 to multi path */
	dp_test_netlink_replace_route("3003:3::/96 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::4/128 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* Add a /100, moving back to single path */
	dp_test_netlink_add_route("3003:3::/100 nh int:dp1T1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1", true);
	dp_test_verify_route_no_neigh_created("3003:3::4");

	/* Change /100 to be multipath */
	dp_test_netlink_replace_route(
		"3003:3::/100 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::4/128 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* Change /96 to be ecmp but with different paths to /100 */
	dp_test_netlink_replace_route("3003:3::/96 nh int:dp1T1 nh int:dp1T3");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::4/128 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* Delete the /100, should now use the /96 */
	dp_test_netlink_del_route("3003:3::/100 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T3", true);
	dp_test_verify_route_no_neigh_created("3003:3::4");

	/*
	 * Now want to test a 2 path NH, where both are NEIGH_CREATED.
	 * Then remove the cover, with the new cover having no connected for
	 * one of the NEIGH_CREATED, thus forcing it to be deleted, but the
	 * other one remaining.
	 */

	dp_test_netlink_add_route("3003:3::/100 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::4/128 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* Change the /96 to be single path again */
	dp_test_netlink_replace_route("3003:3::/96 nh int:dp1T1");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::4", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh int:dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::4/128 scope:253 nh int:dp1T1 nh NC int:dp1T2", true);

	/* Delete the neigh out of int2.*/
	dp_test_netlink_del_neigh("dp1T2", "3003:3::4", nh_mac_str2);
	dp_test_verify_route_no_neigh_created("3003:3::4");

	/* Add a neigh for 3003:3::3 out of int2, now that addr is on 2 ints */
	dp_test_netlink_add_neigh("dp1T2", "3003:3::3", nh_mac_str1_2);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(2);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", true);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1 nh NC int:dp1T2",
		true);

	/*
	 * Delete the /100, and the NEIGH_CREATED should go for dp1T2
	 * as the cover of that does not have a path out that interface.
	 */
	dp_test_netlink_del_route("3003:3::/100 nh int:dp1T1 nh int:dp1T2");
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(1);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T1", true);
	dp_test_verify_route_neigh_created("3003:3::3", "dp1T2", false);
	dp_test_verify_add_route_all(
		"3003:3::3/128 scope:253 nh NC int:dp1T1", true);

	/* delete neighbours */
	dp_test_netlink_del_neigh("dp1T1", "3003:3::3", nh_mac_str1);
	dp_test_netlink_del_neigh("dp1T2", "3003:3::3", nh_mac_str1_2);
	dp_test_verify_neigh6_present_count(0);
	dp_test_verify_neigh6_created_count(0);
	dp_test_verify_route_no_neigh_created("3003:3::3");

	/* Clean Up */
	dp_test_netlink_del_route("3003:3::/96 nh int:dp1T1");
	dp_test_netlink_del_route("3003:3::/64 nh int:dp1T1 nh int:dp1T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2004:4:4::4/64");

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_nh_share, NULL, NULL);
DP_START_TEST(ip_neigh_nh_share,
	      ip_neigh_nh_share)
{
	const char *nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:fe";
	int idx, idx2;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "2004:4:4::4/64");

	dp_test_netlink_add_route(
		"3003:3::/64 nh 2002:2:2::1 int:dp1T1 nh 2003:3:3::1 int:dp1T2");
	dp_test_netlink_add_route(
		"3003:4::/64 nh 2002:2:2::1 int:dp1T1 nh 2003:3:3::1 int:dp1T2");

	/* Verify the 2 routes are sharing a NH */
	idx = dp_test_get_nh_idx("3003:3::");
	idx2 = dp_test_get_nh_idx("3003:4::");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);

	/* Add an arp entry, and then reverify */
	dp_test_netlink_add_neigh("dp1T1", "2002:2:2::1", nh_mac_str1);
	dp_test_verify_route_neigh_created("2002:2:2::1", "dp1T1", true);
	idx = dp_test_get_nh_idx("3003:3::");
	idx2 = dp_test_get_nh_idx("3003:4::");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(1);

	/* Add a further route, make sure it shares too */
	dp_test_netlink_add_route(
		"3003:5::/64 nh 2002:2:2::1 int:dp1T1 nh 2003:3:3::1 int:dp1T2");
	idx = dp_test_get_nh_idx("3003:3::");
	idx2 = dp_test_get_nh_idx("3003:4::");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	idx2 = dp_test_get_nh_idx("3003:5::");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(1);

	/* Add a 2nd neigh */
	dp_test_netlink_add_neigh("dp1T2", "2003:3:3::1", nh_mac_str2);
	idx = dp_test_get_nh_idx("3003:3::");
	idx2 = dp_test_get_nh_idx("3003:4::");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	idx2 = dp_test_get_nh_idx("3003:5::");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh6_present_count(2);
	dp_test_verify_neigh6_created_count(2);

	/* Remove a route */
	dp_test_netlink_del_route(
		"3003:4::/64 nh 2002:2:2::1 int:dp1T1 nh 2003:3:3::1 int:dp1T2");
	idx = dp_test_get_nh_idx("3003:3::");
	idx2 = dp_test_get_nh_idx("3003:5::");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh6_present_count(2);
	dp_test_verify_neigh6_created_count(2);

	/* Remove a neigh */
	dp_test_netlink_del_neigh("dp1T1", "2002:2:2::1", nh_mac_str1);
	idx = dp_test_get_nh_idx("3003:3::");
	idx2 = dp_test_get_nh_idx("3003:5::");
	dp_test_fail_unless(idx == idx2,
			    "next hops not shared, %d, %d", idx, idx2);
	dp_test_verify_neigh6_present_count(1);
	dp_test_verify_neigh6_created_count(1);

	/* Final tidy */
	dp_test_netlink_del_neigh("dp1T2", "2003:3:3::1", nh_mac_str2);
	dp_test_netlink_del_route(
		"3003:3::/64 nh 2002:2:2::1 int:dp1T1 nh 2003:3:3::1 int:dp1T2");
	dp_test_netlink_del_route(
		"3003:5::/64 nh 2002:2:2::1 int:dp1T1 nh 2003:3:3::1 int:dp1T2");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2003:3:3::3/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "2004:4:4::4/64");

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_neigh_suite, ip_neigh_nh_scale, NULL, NULL);
/*
 * Not run by default due to the time taken to set up and remove all
 * the neigh entries. This test is usefuls for testing efficiency of
 * the route processing code, with minor additions into the code
 * to print out time taken processing routes.
 */
DP_START_TEST_DONT_RUN(ip_neigh_nh_scale,
		       ip_neigh_nh_scale)
{
	char nh_mac_str[18];
	struct rte_ether_addr start_eth_addr = {
		{ 0xf0, 0x0, 0x0, 0x0, 0x0, 0x0 }
	};
	struct rte_ether_addr rte_ether_addr;
	struct in6_addr ip_addr, start_ip_addr, tmp_ip_addr;
	char ip_addr_str[INET6_ADDRSTRLEN] = "2002:2:2::3";
	int i;
	int num_neighs = 3000;
	uint32_t *ether;
	uint32_t tmp_s6_addr32;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

	/* Initialise IP and MAC addresses */
	if (!inet_pton(AF_INET6, ip_addr_str, &start_ip_addr))
		assert(0);
	ip_addr = start_ip_addr;
	rte_ether_addr = start_eth_addr;
	ether = (uint32_t *)&rte_ether_addr;

	/* Add neighbours */
	for (i = 0; i < num_neighs; i++) {
		tmp_ip_addr = ip_addr;
		if (!inet_ntop(AF_INET6, &tmp_ip_addr, ip_addr_str,
			       INET6_ADDRSTRLEN))
			assert(0);
		if (!ether_ntoa_r(&rte_ether_addr, nh_mac_str))
			assert(0);
		dp_test_netlink_add_neigh("dp1T1", ip_addr_str, nh_mac_str);
		tmp_s6_addr32 = ntohl(ip_addr.s6_addr32[3]);
		ip_addr.s6_addr32[3] = htonl(++tmp_s6_addr32);
		(*ether)++;
	}

	dp_test_netlink_add_route("3003:3:3::3/128 nh 2002:2:2::3 int:dp1T1");
	dp_test_netlink_del_route("3003:3:3::3/128 nh 2002:2:2::3 int:dp1T1");

	/* Delete neighbours */
	ip_addr = start_ip_addr;
	rte_ether_addr = start_eth_addr;
	for (i = 0; i < num_neighs; i++) {
		tmp_ip_addr = ip_addr;
		if (!inet_ntop(AF_INET6, &tmp_ip_addr, ip_addr_str,
			       INET6_ADDRSTRLEN))
			assert(0);
		if (!ether_ntoa_r(&rte_ether_addr, nh_mac_str))
			assert(0);
		dp_test_netlink_del_neigh("dp1T1", ip_addr_str, nh_mac_str);
		tmp_s6_addr32 = ntohl(ip_addr.s6_addr32[3]);
		ip_addr.s6_addr32[3] = htonl(++tmp_s6_addr32);
		(*ether)++;
	}

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:2:2::2/64");

} DP_END_TEST;
