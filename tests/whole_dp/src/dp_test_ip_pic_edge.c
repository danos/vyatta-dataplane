/*
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT IP pic edge tests
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

static void _dp_test_verify_nh_map_count(const char *addr,
					 int count, int list[],
					 const char *file,
					 const char *func, int line)
{
	char cmd[100];
	char expected[DP_TEST_TMP_BUF];
	int written;
	int i;

	snprintf(cmd, sizeof(cmd), "route lookup %s", addr);
	written = spush(expected, sizeof(expected),
			"\"nh_map_count\":%d,"
			"\"nh_map\":[",
			count);

	for (i = 0; i < count; i++) {
		written += spush(expected + written,
				 sizeof(expected) - written,
				"%d%s",
				 list[i],
				 i == count - 1 ? "" : ",");

	}

	written += spush(expected + written, sizeof(expected) - written,
			 "],");

	_dp_test_check_state_show(file, line, cmd, expected, false,
				  DP_TEST_CHECK_STR_SUBSET);
}

#define dp_test_verify_nh_map_count(addr, count, list)			\
	_dp_test_verify_nh_map_count(addr, count, list,			\
				     __FILE__, __func__, __LINE__)


DP_DECL_TEST_SUITE(ip_pic_edge_suite);

DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge1, NULL, NULL);
DP_START_TEST(ip_pic_edge1, ip_pic_edge1)
{
	int map_list1[] = { 0 };
	int map_list2[] = { 1 };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_netlink_add_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 nh 2.2.2.1 int:dp2T1 backup");
	dp_test_verify_nh_map_count("10.0.1.0 ", 1, map_list1);
	dp_test_netlink_del_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 nh 2.2.2.1 int:dp2T1 backup");

	/* This is a full service dataplane - we support both orders! */
	dp_test_netlink_add_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 backup nh 2.2.2.1 int:dp2T1");
	dp_test_verify_nh_map_count("10.0.1.0 ", 1, map_list2);
	dp_test_netlink_del_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 backup nh 2.2.2.1 int:dp2T1");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

} DP_END_TEST;

/*
 * Check that the maps are updates correctly when 3 primary, 1 backup
 */
DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge2, NULL, NULL);
DP_START_TEST(ip_pic_edge2, ip_pic_edge2)
{
	int map_list1[] = { 0, 1, 2, 0, 1, 2 };
	int map_list2[] = { 0, 0, 2, 0, 2, 2 };
	int map_list3[] = { 2, 2, 2, 2, 2, 2 };
	int map_list4[] = { 3, 3, 3, 3, 3, 3 };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_nl_add_ip_addr_and_connected("dp4T1", "4.4.4.4/24");

	dp_test_netlink_add_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 "
		"nh 4.4.4.1 int:dp4T1 backup");

	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list1);

	/* Make a intf/nh we are not using unusable - no map change */
	dp_test_make_nh_unusable("dp2T1", "2.2.2.3");
	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list1);

	/* Make a intf we are not using unusable - no map change */
	dp_test_make_nh_unusable("dp2T2", NULL);
	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list1);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp2T1", NULL);
	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list2);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list3);

	/* Making it unusable should force a map rebuild  */
	dp_test_make_nh_unusable("dp3T1", "3.3.3.1");
	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list4);

	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 "
		"nh 4.4.4.1 int:dp4T1 backup");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T1", "4.4.4.4/24");

} DP_END_TEST;

/*
 * Check that the maps are updates correctly when 3 primary, 1 backup
 */
DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge3, NULL, NULL);
DP_START_TEST(ip_pic_edge3, ip_pic_edge3)
{
	int map_list1[] = { 0, 1, 2, 0, 1, 2 };
	int map_list2[] = { 0, 0, 2, 0, 2, 2 };
	int map_list3[] = { 2, 2, 2, 2, 2, 2 };
	int map_list4[] = { 3, 4, 3, 4, 3, 4 };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_nl_add_ip_addr_and_connected("dp4T1", "4.4.4.4/24");
	dp_test_nl_add_ip_addr_and_connected("dp4T2", "5.5.5.5/24");

	dp_test_netlink_add_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 "
		"nh 4.4.4.1 int:dp4T1 backup "
		"nh 5.5.5.1 int:dp4T2 backup");

	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list1);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp2T1", "2.2.2.1");
	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list2);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list3);

	/* Making it unusable should force a map rebuild  */
	dp_test_make_nh_unusable("dp3T1", "3.3.3.1");
	dp_test_verify_nh_map_count("10.0.1.4 ", 6, map_list4);

	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 "
		"nh 4.4.4.1 int:dp4T1 backup "
		"nh 5.5.5.1 int:dp4T2 backup");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T1", "4.4.4.4/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T2", "5.5.5.5/24");

} DP_END_TEST;

/*
 * Create multiple NHs and check that all are marked unusable when
 * the update signal arrives.
 */
DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge4, NULL, NULL);
DP_START_TEST(ip_pic_edge4, ip_pic_edge4)
{
	int map_list1[] = { 0 };
	int map_list2[] = { 1 };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

	dp_test_netlink_add_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 backup");

	dp_test_netlink_add_route(
		"10.0.2.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.3 int:dp2T1 backup");

	dp_test_verify_nh_map_count("10.0.1.0", 1, map_list1);
	dp_test_verify_nh_map_count("10.0.2.0", 1, map_list1);

	/* Making it unusable should force a map rebuild of all users */
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	dp_test_verify_nh_map_count("10.0.1.4 ", 1, map_list2);
	dp_test_verify_nh_map_count("10.0.2.4 ", 1, map_list2);

	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 backup");

	dp_test_netlink_del_route(
		"10.0.2.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.3 int:dp2T1 backup");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

} DP_END_TEST;

/*
 * Create multiple NHs and check that all are marked unusable when
 * the update signal arrives.
 */
DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge5, NULL, NULL);
DP_START_TEST(ip_pic_edge5, ip_pic_edge5)
{
	int map_list1[] = { 0 };
	int map_list2[] = { 1 };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

	dp_test_netlink_add_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 backup");

	dp_test_netlink_add_route(
		"10.0.2.0/24 "
		"nh 1.1.1.3 int:dp1T1 "
		"nh 2.2.2.3 int:dp2T1 backup");

	dp_test_verify_nh_map_count("10.0.1.0", 1, map_list1);
	dp_test_verify_nh_map_count("10.0.2.0", 1, map_list1);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	dp_test_verify_nh_map_count("10.0.1.4 ", 1, map_list2);
	/* The 10.0.2.4 route used a different nh so is not modified */
	dp_test_verify_nh_map_count("10.0.2.4 ", 1, map_list1);

	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 backup");

	dp_test_netlink_del_route(
		"10.0.2.0/24 "
		"nh 1.1.1.3 int:dp1T1 "
		"nh 2.2.2.3 int:dp2T1 backup");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

} DP_END_TEST;

/*
 * Create multiple NHs and check that all are marked unusable when
 * the update signal arrives.
 */
DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge6, NULL, NULL);
DP_START_TEST(ip_pic_edge6, ip_pic_edge6)
{
	int map_list1[] = { 0 };
	int map_list2[] = { 1 };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

	dp_test_netlink_add_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 backup");

	dp_test_netlink_add_route(
		"10.0.2.0/24 "
		"nh 1.1.1.3 int:dp1T1 "
		"nh 2.2.2.3 int:dp2T1 backup");

	dp_test_verify_nh_map_count("10.0.1.0", 1, map_list1);
	dp_test_verify_nh_map_count("10.0.2.0", 1, map_list1);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp1T1", NULL);
	dp_test_verify_nh_map_count("10.0.1.4 ", 1, map_list2);
	dp_test_verify_nh_map_count("10.0.2.4 ", 1, map_list2);

	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 backup");

	dp_test_netlink_del_route(
		"10.0.2.0/24 "
		"nh 1.1.1.3 int:dp1T1 "
		"nh 2.2.2.3 int:dp2T1 backup");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

} DP_END_TEST;

/*
 * Check that the maps are updated correctly and that traffic flows
 * change correctly.
 */
DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge7, NULL, NULL);
DP_START_TEST(ip_pic_edge7, ip_pic_edge7)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1, *nh_mac_str2, *nh_mac_str3;
	int len = 22;
	int map_list1[] = { 0, 1, };
	int map_list2[] = { 1, 1, };
	int map_list3[] = { 2, 2, };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_nl_add_ip_addr_and_connected("dp4T1", "4.4.4.4/24");

	dp_test_netlink_add_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 backup");

	dp_test_verify_nh_map_count("10.0.1.2", 2, map_list1);

	nh_mac_str1 = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str1);

	dp_test_verify_nh_map_count("10.0.1.2", 2, map_list1);

	nh_mac_str2 = "11:22:33:44:55:66";
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.1", nh_mac_str2);

	nh_mac_str3 = "22:33:44:55:66:77";
	dp_test_netlink_add_neigh("dp3T1", "3.3.3.1", nh_mac_str3);

	dp_test_verify_nh_map_count("10.0.1.2", 2, map_list1);

	/*
	 * Create pak to match the route added above, with ports
	 * carefully chosen to take path through first path.
	 */
	test_pak = dp_test_create_udp_ipv4_pak("4.4.4.5", "10.0.1.2",
					       1001, 1003, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp4T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp4T1", exp);

	/*
	 * Now bring down that path, and resend the packet - it should
	 * now use the remaining primary path
	 */
	dp_test_make_nh_unusable("dp1T1", NULL);
	dp_test_verify_nh_map_count("10.0.1.4 ", 2, map_list2);

	test_pak = dp_test_create_udp_ipv4_pak("4.4.4.5", "10.0.1.2",
					       1001, 1003, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp4T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp4T1", exp);

	/*
	 * Now bring down last primary, and resend the packet - it should
	 * now use the backup path
	 */
	dp_test_make_nh_unusable("dp2T1", NULL);
	dp_test_verify_nh_map_count("10.0.1.4 ", 2, map_list3);

	test_pak = dp_test_create_udp_ipv4_pak("4.4.4.5", "10.0.1.2",
					       1001, 1003, 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp4T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp3T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str3,
				       dp_test_intf_name2mac_str("dp3T1"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	dp_test_pak_receive(test_pak, "dp4T1", exp);

	/* Clean Up */
	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 backup");

	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str1);
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.1", nh_mac_str2);
	dp_test_netlink_del_neigh("dp3T1", "3.3.3.1", nh_mac_str3);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T1", "4.4.4.4/24");

} DP_END_TEST;
