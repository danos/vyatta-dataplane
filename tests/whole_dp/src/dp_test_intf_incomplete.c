/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT test for incomplete interfaces.
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
#include "dp_test_console.h"

DP_DECL_TEST_SUITE(ip_incomplete);

struct nh_info {
	const char *nh_addr;
	const char *nh_mac_str;
	const char *nh_int;
	int nh_int_tci;
	const char *meta_oif;
	bool local;
};

static void _build_and_send_pak(const char *src_addr, const char *dest_addr,
				struct nh_info nh, const char *func, int line)
{
	int len = 22;
	struct rte_mbuf *test_pak;
	struct dp_test_expected *exp;
	const char *src_mac;
	uint32_t addr;
	bool v4;

	if (inet_pton(AF_INET, src_addr, &addr) == 1)
		v4 = true;
	else
		v4 = false;

	if (v4) {
		test_pak = dp_test_create_ipv4_pak(src_addr, dest_addr,
						   1, &len);
		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 DP_TEST_INTF_DEF_SRC_MAC,
					 RTE_ETHER_TYPE_IPV4);
	} else {
		test_pak = dp_test_create_ipv6_pak(src_addr, dest_addr,
						   1, &len);
		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 DP_TEST_INTF_DEF_SRC_MAC,
					 RTE_ETHER_TYPE_IPV6);
	}

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);

	if (nh.local) {
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	} else {
		dp_test_exp_set_oif_name(exp, nh.nh_int);
		if (nh.nh_int_tci)
			dp_test_exp_set_vlan_tci(exp, nh.nh_int_tci);
		src_mac = dp_test_intf_name2mac_str(nh.nh_int);

		if (v4) {
			(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
						       nh.nh_mac_str,
						       src_mac,
						       RTE_ETHER_TYPE_IPV4);

			dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
		} else {
			(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
						       nh.nh_mac_str,
						       src_mac,
						       RTE_ETHER_TYPE_IPV6);

			dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));
		}
	}

	_dp_test_pak_receive(test_pak, "dp1T0", exp, __FILE__, func, line);
}

#define build_and_send_pak(src_addr, dest_addr, nh) \
	_build_and_send_pak(src_addr, dest_addr, nh, __func__, __LINE__)

/*
 *                dp2T1 - 2.2.2/24
 *    UUT   .1  ---------------------- .2   mac ends :2
 *
 *                dp3t1.100 - 3.3.1/24
 *          .1  ---------------------- .2   mac ends :31
 *
 *                dp3t1.200 - 3.3.2/24
 *          .1  ---------------------- .2   mac ends :32
 *
 *                dp3t1.300 - 3.3.3/24
 *          .1  ---------------------- .2   mac ends :33
 */
DP_DECL_TEST_CASE(ip_incomplete, ipv4_incomplete, NULL, NULL);

DP_START_TEST(ipv4_incomplete, ipv4_incomplete)
{
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:2";
	const char *nh_mac_str3_1 = "aa:bb:cc:dd:ee:31";
	const char *nh_mac_str3_2 = "aa:bb:cc:dd:ee:32";

	const char route_1[] = "10.73.2.0/24 nh 3.3.1.2 int:dp3T1.100";
	const char route_1a[] = "10.73.3.0/24 nh 3.3.1.2 int:dp3T1.100";
	const char route_1b[] = "10.73.4.0/24 nh 3.3.1.2 int:dp3T1.100";
	const char route_1mod[] = "10.73.2.0/24 nh 3.3.2.2 int:dp3T1.200";

	const char route_2[] = "10.73.2.0/24 nh 3.3.2.2 int:dp3T1.200";
	const char route_nondp[] = "10.73.2.0/24 nh 3.3.1.2 int:nondp1";
	struct nh_info nh2 = {
		.nh_mac_str = nh_mac_str2,
		.nh_addr = "2.2.2.1",
		.nh_int = "dp2T1",
	};
	struct nh_info nh3_1 = {
		.nh_mac_str = nh_mac_str3_1,
		.nh_addr = "3.3.1.2",
		.nh_int = "dp3T1",
		.nh_int_tci = 100,
		.meta_oif = "dp3T1.100",
	};
	struct nh_info nh3_2 = {
		.nh_mac_str = nh_mac_str3_2,
		.nh_addr = "3.3.2.2",
		.nh_int = "dp3T1",
		.nh_int_tci = 200,
		.meta_oif = "dp3T1.200",
	};

	struct nh_info nh_local = {
		.local = true,
	};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_route("10.0.0.0/8 nh 2.2.2.1 int:dp2T1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str2);

	/* Verify that we route just added is used */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);
	/*
	 * test 1: add incomplete route and verify it is completed
	 *         when the new link arrives.
	 */

	/* Add the more specific route via an incomplete interface */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the interface, route should be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_verify_add_route(route_1, true);
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);

	/* verify it takes the new route */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_1);

	/* remove the extra interface */
	dp_test_netlink_del_route(route_1);
	dp_test_netlink_del_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);

	/* back to the initial route */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/*
	 * test 2: add incomplete route and verify we can delete it
	 *         before the new link arrives.
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* delete the incomplete route */
	dp_test_netlink_del_incmpl_route(route_1);
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Finish creating interface */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_verify_del_route(route_1, false);
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);

	/* more specific route was not installed so go via old one */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* remove extra interface */
	dp_test_netlink_del_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);

	/*
	 * test 3:  Add an incomplete route out of interface A, then
	 *          modify it to be out of interface B. Then send
	 *          interface A, then interface B, which should make
	 *          it complete.
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_intf_vif_create_incmpl("dp3T1.200", "dp3T1", 200);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* modify the route */
	dp_test_netlink_add_incmpl_route(route_2);

	/* Complete the first interface, modified route should not be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the second interface, modified route should be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.200", "dp3T1", 200);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.200", "3.3.2.1/24");
	dp_test_verify_add_route(route_2, true);
	dp_test_netlink_add_neigh("dp3T1.200", "3.3.2.2", nh_mac_str3_2);

	/* verify it takes the new route */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_2);

	/* remove the extra interfaces */
	dp_test_netlink_del_route(route_2);
	dp_test_netlink_del_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	dp_test_netlink_del_neigh("dp3T1.200", "3.3.2.2", nh_mac_str3_2);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1.200", "3.3.2.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_vif_del("dp3T1.200", 200);

	/*
	 * test 4: Add multiple incomplete routes out of the same interface
	 *         and verify they all get added
	 *
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);
	dp_test_netlink_add_incmpl_route(route_1a);
	dp_test_netlink_add_incmpl_route(route_1b);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the interface, routes should be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_verify_add_route(route_1, true);
	dp_test_verify_add_route(route_1a, true);
	dp_test_verify_add_route(route_1b, true);
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);

	/* verify it takes the new route */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_1);

	/* remove the extra interface */
	dp_test_netlink_del_route(route_1);
	dp_test_netlink_del_route(route_1a);
	dp_test_netlink_del_route(route_1b);
	dp_test_netlink_del_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);

	/*
	 * test 5: Add an incomplete route out of an interface that then goes
	 *         on to be marked as a nondp interface, and therefore the
	 *         route needs to be a slow path route.
	 */
	dp_test_intf_nondp_create_incmpl("nondp1");
	dp_test_netlink_add_incmpl_route(route_nondp);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the interface, route should be added */
	dp_test_intf_nondp_create_incmpl_fin("nondp1");

	dp_test_verify_add_route(route_nondp, true);

	/* verify it takes the new route */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh_local);

	/* remove the extra interface */
	dp_test_netlink_del_route(route_nondp);
	dp_test_intf_nondp_delete("nondp1");

	/* back to the initial route */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/*
	 * test 6: Add an incomplete route, and a new (unrelated)
	 *         link, then complete the route.
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Add an unrelated link */
	dp_test_intf_vif_create("dp3T1.200", "dp3T1", 200);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the interface, route should be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_verify_add_route(route_1, true);
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);

	/* verify it takes the new route */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_1);

	/* remove the extra interface */
	dp_test_netlink_del_route(route_1);
	dp_test_netlink_del_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_vif_del("dp3T1.200", 200);

	/*
	 * test 7: Add a route via incomplete interface, then modify route
	 *         to be via a complete interface.
	 */

	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Add 2nd interface */
	dp_test_intf_vif_create("dp3T1.200", "dp3T1", 200);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.200", "3.3.2.1/24");
	dp_test_netlink_add_neigh("dp3T1.200", "3.3.2.2", nh_mac_str3_2);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Modify route to use 2nd (complete) interface */
	dp_test_netlink_add_route(route_1mod);

	/* Verify packet takes new path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_2);

	/* Verify that the initial incoomplete is removed */
	dp_test_check_state_show("incomplete", "\"incomplete\":0", false);
	dp_test_check_state_show("incomplete", "\"ignored\":0", false);

	/* Tidy up */
	dp_test_netlink_del_route(route_1mod);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.200", "3.3.2.1/24");
	dp_test_netlink_del_neigh("dp3T1.200", "3.3.2.2", nh_mac_str3_2);

	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_intf_vif_del("dp3T1.100", 100);

	dp_test_intf_vif_del("dp3T1.200", 200);

	/* Clean Up */
	dp_test_netlink_del_route("10.0.0.0/8 nh 2.2.2.1 int:dp2T1");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str2);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

} DP_END_TEST;

/*
 *                dp2T1 - 2.2.2/24
 *    UUT   .1  ---------------------- .2  mac ends :2
 *
 *                dp3t1.100 - 3.3.1/24
 *          .1  ---------------------- .2   mac ends :31
 *
 *                dp3t1.200 - 3.3.2/24
 *          .1  ---------------------- .2   mac ends :32
 *
 *                dp3t1.300 - 3.3.3/24
 *          .1  ---------------------- .2   mac ends :33
 */

DP_START_TEST(ipv4_incomplete, ipv4_incomplete_ecmp)
{
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:2"; /* int 2 */
	const char *nh_mac_str3_1 = "aa:bb:cc:dd:ee:31"; /* int 3.100 */
	const char *nh_mac_str3_2 = "aa:bb:cc:dd:ee:32"; /* int 3.100 */
	const char *nh_mac_str3_3 = "aa:bb:cc:dd:ee:33"; /* int 3.100 */

	struct nh_info nh2 = {
		.nh_mac_str = nh_mac_str2,
		.nh_addr = "2.2.2.1",
		.nh_int = "dp2T1",
	};
	struct nh_info nh3_1 = {
		.nh_mac_str = nh_mac_str3_1,
		.nh_addr = "3.3.1.2",
		.nh_int = "dp3T1",
		.nh_int_tci = 100,
		.meta_oif = "dp3T1.100",
	};
	struct nh_info nh3_3 = {
		.nh_mac_str = nh_mac_str3_3,
		.nh_addr = "3.3.3.2",
		.nh_int = "dp3T1",
		.nh_int_tci = 300,
		.meta_oif = "dp3T1.300",
	};

	const char *route_2_paths = "10.73.2.0/24 "
				    " nh 3.3.1.2 int:dp3T1.100"
				    " nh 3.3.2.2 int:dp3T1.200";
	const char *route_2_paths_nondp = "10.73.2.0/24 "
					  " nh 3.3.1.2 int:dp3T1.100"
					  " nh 3.3.2.2 int:nondp1";
	const char *route_3_paths = "10.73.2.0/24 "
				    " nh 3.3.1.2 int:dp3T1.100"
				    " nh 3.3.2.2 int:dp3T1.200"
				    " nh 3.3.3.2 int:dp3T1.300";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_route("10.0.0.0/8 nh 2.2.2.1 int:dp2T1");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str2);

	/* Verify that we route just added is used */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/*
	 * test 1: Add a more specific ecmp route that has 1 incomplete
	 *         interface. Check forwarding, then make the route
	 *         complete and check again.
	 */
	dp_test_intf_vif_create("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);

	dp_test_intf_vif_create_incmpl("dp3T1.200", "dp3T1", 200);
	dp_test_netlink_add_incmpl_route(route_2_paths);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the interface and add NH */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.200", "dp3T1", 200);
	dp_test_verify_add_route(route_2_paths, true);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.200", "3.3.2.1/24");
	dp_test_netlink_add_neigh("dp3T1.200", "3.3.2.2", nh_mac_str3_2);

	/* Verify packet takes new path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_1);

	/* Remove the extra interfaces/routes */
	dp_test_netlink_del_route(route_2_paths);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.200", "3.3.2.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_vif_del("dp3T1.200", 200);

	/*
	 * test 2: Add a more specific ecmp route that has 2 incomplete
	 *         interfaces. Check forwarding, then make the route
	 *         complete and check again.
	 */
	dp_test_intf_vif_create("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);

	dp_test_intf_vif_create_incmpl("dp3T1.200", "dp3T1", 200);
	dp_test_intf_vif_create_incmpl("dp3T1.300", "dp3T1", 300);
	dp_test_netlink_add_incmpl_route(route_3_paths);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the first incomplete interface and add NH */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.200", "dp3T1", 200);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.200", "3.3.2.1/24");
	dp_test_netlink_add_neigh("dp3T1.200", "3.3.2.2", nh_mac_str3_2);

	/* Verify packet still takes old path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the last interface and add NH */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.300", "dp3T1", 300);
	dp_test_verify_add_route(route_3_paths, true);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.300", "3.3.3.1/24");
	dp_test_netlink_add_neigh("dp3T1.300", "3.3.3.2", nh_mac_str3_3);

	/* Verify packet takes new path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_3);

	/* Remove the extra interfaces/routes */
	dp_test_netlink_del_route(route_3_paths);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1.200", "3.3.2.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1.300", "3.3.3.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_vif_del("dp3T1.200", 200);
	dp_test_intf_vif_del("dp3T1.300", 300);

	/*
	 * test 3: Add a more specific ecmp route with one a non dp
	 *         interface and an incomplete dataplane interface.
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_intf_nondp_create("nondp1");
	dp_test_netlink_add_incmpl_route(route_2_paths_nondp);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the interface and add NH */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);

	dp_test_verify_add_route(route_2_paths_nondp, true);

	/* Verify packet takes new path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_1);

	/* Remove the extra interfaces/routes */
	dp_test_netlink_del_route(route_2_paths_nondp);
	dp_test_netlink_del_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_nondp_delete("nondp1");

	/*
	 * test 4: Add a more specific ecmp route with one a non dp
	 *         incomplete interface and a dataplane interface.
	 */
	dp_test_intf_vif_create("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_netlink_add_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	dp_test_intf_nondp_create_incmpl("nondp1");
	dp_test_netlink_add_incmpl_route(route_2_paths_nondp);

	/* Verify packet still takes original path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh2);

	/* Complete the interface */
	dp_test_intf_nondp_create_incmpl_fin("nondp1");

	dp_test_verify_add_route(route_2_paths_nondp, true);

	/* Verify packet takes new path */
	build_and_send_pak("11.73.1.1", "10.73.2.1", nh3_1);

	/* Remove the extra interfaces/routes */
	dp_test_netlink_del_route(route_2_paths_nondp);
	dp_test_netlink_del_neigh("dp3T1.100", "3.3.1.2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3.3.1.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_nondp_delete("nondp1");

	/* Clean up */
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str2);
	dp_test_netlink_del_route("10.0.0.0/8 nh 2.2.2.1 int:dp2T1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

} DP_END_TEST;

/*
 *                dp2T1 - 2:2::2/64
 *    UUT   .1  ---------------------- .2   mac ends :2
 *
 *                dp3t1.100 - 3:3:1::/64
 *          .1  ---------------------- .2   mac ends :31
 *
 *                dp3t1.200 - 3:3:2::/64
 *          .1  ---------------------- .2   mac ends :32
 *
 *                dp3t1.300 - 3:3:3/64
 *          .1  ---------------------- .2   mac ends :33
 */
DP_DECL_TEST_CASE(ip_incomplete, ipv6_incomplete, NULL, NULL);

DP_START_TEST(ipv6_incomplete, ipv6_incomplete)
{
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:2";
	const char *nh_mac_str3_1 = "aa:bb:cc:dd:ee:31";
	const char *nh_mac_str3_2 = "aa:bb:cc:dd:ee:32";

	const char route_1[] = "10:73:2::/64 nh 3:3:1::2 int:dp3T1.100";
	const char route_1a[] = "10:73:3::/64 nh 3:3:1::2 int:dp3T1.100";
	const char route_1b[] = "10:73:4::/64 nh 3:3:1::2 int:dp3T1.100";

	const char route_2[] = "10:73:2::/64 nh 3:3:2::2 int:dp3T1.200";
	const char route_nondp[] = "10:73:2::/64 nh 3:3:1::2 int:nondp1";

	struct nh_info nh2 = {
		.nh_mac_str = nh_mac_str2,
		.nh_addr = "2:2:2::2",
		.nh_int = "dp2T1",
	};
	struct nh_info nh3_1 = {
		.nh_mac_str = nh_mac_str3_1,
		.nh_addr = "3:3:1::2",
		.nh_int = "dp3T1",
		.nh_int_tci = 100,
		.meta_oif = "dp3T1.100",
	};

	struct nh_info nh3_2 = {
		.nh_mac_str = nh_mac_str3_2,
		.nh_addr = "3:3:2::2",
		.nh_int = "dp3T1",
		.nh_int_tci = 200,
		.meta_oif = "dp3T1.200",
	};

	struct nh_info nh_local = {
		.local = true,
	};

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2:2:2::1/64");

	dp_test_netlink_add_route("10::/16 nh 2:2:2::2 int:dp2T1");
	dp_test_netlink_add_neigh("dp2T1", "2:2:2::2", nh_mac_str2);

	/* Verify that we route just added is used */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/*
	 * test 1: add incomplete route and verify it is completed
	 *         when the new link arrives.
	 */

	/* Add the more specific route via an incomplete interface */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the interface, route should be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_verify_add_route(route_1, true);
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);

	/* verify it takes the new route */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh3_1);

	/* remove the extra interface */
	dp_test_netlink_del_route(route_1);
	dp_test_netlink_del_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_intf_vif_del("dp3T1.100", 100);

	/* back to the initial route */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/*
	 * test 2: add incomplete route and verify we can delete it
	 *         before the new link arrives.
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* delete the incomplete route */
	dp_test_netlink_del_incmpl_route(route_1);
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Finish creating interface */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_verify_del_route(route_1, false);
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);

	/* more specific route was not installed so go via old one */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* remove extra interface */
	dp_test_netlink_del_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_intf_vif_del("dp3T1.100", 100);

	/*
	 * test 3:  Add an incomplete route out of interface A, then
	 *          modify it to be out of interface B. Then send
	 *          interface A, then interface B, which should make
	 *          it complete.
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_intf_vif_create_incmpl("dp3T1.200", "dp3T1", 200);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* modify the route */
	dp_test_netlink_add_incmpl_route(route_2);

	/* Complete the first interface, modified route should not be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the second interface, modified route should be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.200", "dp3T1", 200);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.200", "3:3:2::1/64");
	dp_test_verify_add_route(route_2, true);
	dp_test_netlink_add_neigh("dp3T1.200", "3:3:2::2", nh_mac_str3_2);

	/* verify it takes the new route */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh3_2);

	/* remove the extra interfaces */
	dp_test_netlink_del_route(route_2);
	dp_test_netlink_del_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	dp_test_netlink_del_neigh("dp3T1.200", "3:3:2::2", nh_mac_str3_2);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T1.200", "3:3:2::1/64");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_vif_del("dp3T1.200", 200);

	/*
	 * test 4: Add multiple incomplete routes out of the same interface
	 *         and verify they all get added
	 *
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);
	dp_test_netlink_add_incmpl_route(route_1a);
	dp_test_netlink_add_incmpl_route(route_1b);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the interface, routes should be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_verify_add_route(route_1, true);
	dp_test_verify_add_route(route_1a, true);
	dp_test_verify_add_route(route_1b, true);
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);

	/* verify it takes the new route */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh3_1);

	/* remove the extra interface */
	dp_test_netlink_del_route(route_1);
	dp_test_netlink_del_route(route_1a);
	dp_test_netlink_del_route(route_1b);
	dp_test_netlink_del_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_intf_vif_del("dp3T1.100", 100);

	/*
	 * test 5: Add an incomplete route out of an interface that then goes
	 *         on to be marked as a nondp interface, and therefore the
	 *         route needs to be a slow path route.
	 */
	dp_test_intf_nondp_create_incmpl("nondp1");
	dp_test_netlink_add_incmpl_route(route_nondp);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the interface, route should be added */
	dp_test_intf_nondp_create_incmpl_fin("nondp1");

	dp_test_verify_add_route(route_nondp, true);

	/* verify it takes the new route */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh_local);

	/* remove the extra interface */
	dp_test_netlink_del_route(route_nondp);
	dp_test_intf_nondp_delete("nondp1");

	/* back to the initial route */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/*
	 * test 6: Add an incomplete route, and a new (unrelated)
	 *         link, then complete the route.
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_netlink_add_incmpl_route(route_1);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Add an unrelated link */
	dp_test_intf_vif_create("dp3T1.200", "dp3T1", 200);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the interface, route should be added */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_verify_add_route(route_1, true);
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);

	/* verify it takes the new route */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh3_1);

	/* remove the extra interface */
	dp_test_netlink_del_route(route_1);
	dp_test_netlink_del_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_vif_del("dp3T1.200", 200);

	/* Clean Up */
	dp_test_netlink_del_route("10::/16 nh 2:2:2::2 int:dp2T1");
	dp_test_netlink_del_neigh("dp2T1", "2:2:2::2", nh_mac_str2);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2:2:2::1/64");

} DP_END_TEST;

/*
 *                dp2T1 - 2:2::2/64
 *    UUT   .1  ---------------------- .2   mac ends :2
 *
 *                dp3t1.100 - 3:3:1::/64
 *          .1  ---------------------- .2   mac ends :31
 *
 *                dp3t1.200 - 3:3:2::/64
 *          .1  ---------------------- .2   mac ends :32
 *
 *                dp3t1.300 - 3:3:3/64
 *          .1  ---------------------- .2   mac ends :33
 */
DP_START_TEST(ipv6_incomplete, ipv6_incomplete_ecmp)
{
	const char *nh_mac_str2 = "aa:bb:cc:dd:ee:2"; /* int 2 */
	const char *nh_mac_str3_1 = "aa:bb:cc:dd:ee:31"; /* int 3.100 */
	const char *nh_mac_str3_2 = "aa:bb:cc:dd:ee:32"; /* int 3.100 */
	const char *nh_mac_str3_3 = "aa:bb:cc:dd:ee:33"; /* int 3.100 */

	struct nh_info nh2 = {
		.nh_mac_str = nh_mac_str2,
		.nh_addr = "2:2:2::2",
		.nh_int = "dp2T1",
	};
	struct nh_info nh3_1 = {
		.nh_mac_str = nh_mac_str3_1,
		.nh_addr = "3:3:1::2",
		.nh_int = "dp3T1",
		.nh_int_tci = 100,
		.meta_oif = "dp3T1.100",
	};
	struct nh_info nh3_3 = {
		.nh_mac_str = nh_mac_str3_3,
		.nh_addr = "3:3:3::2",
		.nh_int = "dp3T1",
		.nh_int_tci = 300,
		.meta_oif = "dp3T1.300",
	};

	const char *route_2_paths = "10:73:2::/64 "
				    " nh 3:3:1::2 int:dp3T1.100"
				    " nh 3:3:2::2 int:dp3T1.200";
	const char *route_2_paths_nondp = "10:73:2::/64 "
					  " nh 3:3:1::2 int:dp3T1.100"
					  " nh 3:3:2::2 int:nondp1";
	const char *route_3_paths = "10:73:2::/64 "
				    " nh 3:3:1::2 int:dp3T1.100"
				    " nh 3:3:2::2 int:dp3T1.200"
				    " nh 3:3:3::2 int:dp3T1.300";

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2:2:2::1/64");

	dp_test_netlink_add_route("10::/16 nh 2:2:2::2 int:dp2T1");
	dp_test_netlink_add_neigh("dp2T1", "2:2:2::2", nh_mac_str2);

	/* Verify that we route just added is used */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/*
	 * test 1: Add a more specific ecmp route that has 1 incomplete
	 *         interface. Check forwarding, then make the route
	 *         complete and check again.
	 */
	dp_test_intf_vif_create("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);

	dp_test_intf_vif_create_incmpl("dp3T1.200", "dp3T1", 200);
	dp_test_netlink_add_incmpl_route(route_2_paths);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the interface and add NH */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.200", "dp3T1", 200);
	dp_test_verify_add_route(route_2_paths, true);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.200", "3:3:2::1/64");
	dp_test_netlink_add_neigh("dp3T1.200", "3:3:2::2", nh_mac_str3_2);

	/* Verify packet takes new path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh3_1);

	/* Remove the extra interfaces/routes */
	dp_test_netlink_del_route(route_2_paths);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.200", "3:3:2::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_vif_del("dp3T1.200", 200);

	/*
	 * test 2: Add a more specific ecmp route that has 2 incomplete
	 *         interfaces. Check forwarding, then make the route
	 *         complete and check again.
	 */
	dp_test_intf_vif_create("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);

	dp_test_intf_vif_create_incmpl("dp3T1.200", "dp3T1", 200);
	dp_test_intf_vif_create_incmpl("dp3T1.300", "dp3T1", 300);
	dp_test_netlink_add_incmpl_route(route_3_paths);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the first incomplete interface and add NH */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.200", "dp3T1", 200);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.200", "3:3:2::1/64");
	dp_test_netlink_add_neigh("dp3T1.200", "3:3:2::2", nh_mac_str3_2);

	/* Verify packet still takes old path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the last interface and add NH */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.300", "dp3T1", 300);
	dp_test_verify_add_route(route_3_paths, true);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.300", "3.3.3.1/24");
	dp_test_netlink_add_neigh("dp3T1.300", "3:3:3::2", nh_mac_str3_3);

	/* Verify packet takes new path */
	build_and_send_pak("11:73:1::3", "10:73:2::2", nh3_3);

	/* Remove the extra interfaces/routes */
	dp_test_netlink_del_route(route_3_paths);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T1.200", "3:3:2::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T1.300", "3.3.3.1/24");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_vif_del("dp3T1.200", 200);
	dp_test_intf_vif_del("dp3T1.300", 300);

	/*
	 * test 3: Add a more specific ecmp route with one a non dp
	 *         interface and an incomplete dataplane interface.
	 */
	dp_test_intf_vif_create_incmpl("dp3T1.100", "dp3T1", 100);
	dp_test_intf_nondp_create("nondp1");
	dp_test_netlink_add_incmpl_route(route_2_paths_nondp);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the interface and add NH */
	dp_test_intf_vif_create_incmpl_fin("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);

	dp_test_verify_add_route(route_2_paths_nondp, true);

	/* Verify packet takes new path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh3_1);

	/* Remove the extra interfaces/routes */
	dp_test_netlink_del_route(route_2_paths_nondp);
	dp_test_netlink_del_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_nondp_delete("nondp1");

	/*
	 * test 4: Add a more specific ecmp route with one a non dp
	 *         incomplete interface and a dataplane interface.
	 */
	dp_test_intf_vif_create("dp3T1.100", "dp3T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_netlink_add_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	dp_test_intf_nondp_create_incmpl("nondp1");
	dp_test_netlink_add_incmpl_route(route_2_paths_nondp);

	/* Verify packet still takes original path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh2);

	/* Complete the interface */
	dp_test_intf_nondp_create_incmpl_fin("nondp1");

	dp_test_verify_add_route(route_2_paths_nondp, true);

	/* Verify packet takes new path */
	build_and_send_pak("11:73:1::1", "10:73:2::2", nh3_1);

	/* Remove the extra interfaces/routes */
	dp_test_netlink_del_route(route_2_paths_nondp);
	dp_test_netlink_del_neigh("dp3T1.100", "3:3:1::2", nh_mac_str3_1);
	dp_test_nl_del_ip_addr_and_connected("dp3T1.100", "3:3:1::1/64");
	dp_test_intf_vif_del("dp3T1.100", 100);
	dp_test_intf_nondp_delete("nondp1");

	/* Clean up */
	dp_test_netlink_del_route("10::/16 nh 2:2:2::2 int:dp2T1");
	dp_test_netlink_del_neigh("dp2T1", "2:2:2::2", nh_mac_str2);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2:2:2::1/64");

} DP_END_TEST;

