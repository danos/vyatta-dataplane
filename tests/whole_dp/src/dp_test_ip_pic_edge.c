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

static void dp_test_map_count_build_expected(char *expected,
					     int exp_size,
					     const char *addr,
					     int count, int list[])
{
	int i;
	int written;

	written = spush(expected, exp_size,
			"\"nh_map_count\":%d,"
			"\"nh_map\":[",
			count);

	for (i = 0; i < count; i++) {
		written += spush(expected + written,
				 exp_size - written,
				"%d%s",
				 list[i],
				 i == count - 1 ? "" : ",");

	}

	written += spush(expected + written, exp_size - written,
			 "],");
}

static void _dp_test_verify_nh_map_count(const char *addr,
					 int count, int list[],
					 const char *file,
					 const char *func, int line)
{
	char cmd[100];
	char expected[DP_TEST_TMP_BUF];
	struct dp_test_addr addr_ptr;

	dp_test_assert_internal(dp_test_addr_str_to_addr(addr,  &addr_ptr));
	if (addr_ptr.family == AF_INET)
		snprintf(cmd, sizeof(cmd), "route lookup %s", addr);
	else
		snprintf(cmd, sizeof(cmd), "route6 lookup %s", addr);
	dp_test_map_count_build_expected(expected, sizeof(expected),
					 addr, count, list);

	_dp_test_check_state_show(file, line, cmd, expected, false,
				  DP_TEST_CHECK_STR_SUBSET);
}

static void _dp_test_verify_nh_map_count_one_of(const char *addr,
						int count, int list_size,
						int *lists[],
						const char *file,
						const char *func, int line)
{
	char cmd[100];
	char *expected[list_size];
	int i;

	snprintf(cmd, sizeof(cmd), "route lookup %s", addr);

	for (i = 0; i < list_size; i++) {
		expected[i] = malloc(DP_TEST_TMP_BUF);
		assert(expected[i]);

		dp_test_map_count_build_expected(expected[i],
						 DP_TEST_TMP_BUF,
						 addr, count, lists[i]);
	}

	_dp_test_check_state_show_one_of(file, line, cmd, list_size,
					 (const char **)&expected, false,
					 DP_TEST_CHECK_STR_SUBSET);
	for (i = 0; i < list_size; i++)
		free(expected[i]);
}

#define dp_test_verify_nh_map_count(addr, count, list)			\
	_dp_test_verify_nh_map_count(addr, count, list,			\
				     __FILE__, __func__, __LINE__)

#define dp_test_verify_nh_map_count_one_of(addr, count, list_size, lists) \
	_dp_test_verify_nh_map_count_one_of(addr, count, list_size, lists, \
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
	dp_test_verify_nh_map_count("10.0.1.0", 1, map_list1);
	dp_test_netlink_del_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 nh 2.2.2.1 int:dp2T1 backup");

	/* This is a full service dataplane - we support both orders! */
	dp_test_netlink_add_route(
		"10.0.1.0/24 nh 1.1.1.2 int:dp1T1 backup nh 2.2.2.1 int:dp2T1");
	dp_test_verify_nh_map_count("10.0.1.0", 1, map_list2);
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
	int map_list1a[] = { 1, 0, 1, 0, 2, 2 };
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

	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list1);

	/* Make a intf/nh we are not using unusable - no map change */
	dp_test_make_nh_unusable("dp2T1", "2.2.2.3");
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list1);

	/* Make a intf we are not using unusable - no map change */
	dp_test_make_nh_unusable("dp2T2", NULL);
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list1);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp2T1", NULL);
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list2);

	/*
	 * Make the nh usable again - does not change to the previous
	 * state - but goes to a new fair state.
	 */
	dp_test_make_nh_usable("dp2T1", NULL);
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list1a);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp2T1", NULL);
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list2);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list3);

	/* Making it unusable should force a map rebuild  */
	dp_test_make_nh_unusable("dp3T1", "3.3.3.1");
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list4);

	/* Making it usable should force a map rebuild */
	dp_test_make_nh_usable("dp3T1", "3.3.3.1");
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list3);

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
	dp_test_clear_path_unusable();

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

	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list1);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp2T1", "2.2.2.1");
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list2);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list3);

	/* Making it unusable should force a map rebuild  */
	dp_test_make_nh_unusable("dp3T1", "3.3.3.1");
	dp_test_verify_nh_map_count("10.0.1.4", 6, map_list4);

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
	dp_test_clear_path_unusable();

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
	dp_test_verify_nh_map_count("10.0.1.4", 1, map_list2);
	dp_test_verify_nh_map_count("10.0.2.4", 1, map_list2);

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
	dp_test_clear_path_unusable();

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
	dp_test_verify_nh_map_count("10.0.1.4", 1, map_list2);
	/* The 10.0.2.4 route used a different nh so is not modified */
	dp_test_verify_nh_map_count("10.0.2.4", 1, map_list1);

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
	dp_test_clear_path_unusable();

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
	dp_test_verify_nh_map_count("10.0.1.4", 1, map_list2);
	dp_test_verify_nh_map_count("10.0.2.4", 1, map_list2);

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
	dp_test_clear_path_unusable();

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
	dp_test_verify_nh_map_count("10.0.1.4", 2, map_list2);

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
	dp_test_verify_nh_map_count("10.0.1.4", 2, map_list3);

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
	dp_test_clear_path_unusable();

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge8, NULL, NULL);
DP_START_TEST(ip_pic_edge8, ip_pic_edge8)
{
	pthread_t nh_unusable_thread1;
	pthread_t nh_usable_thread1;
	int map_list1[] = { 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3 };
	/* map_list2a is when 0 and 1 have been removed. */
	int map_list2a[] = { 2, 3, 2, 3, 2, 2, 2, 3, 3, 3, 2, 3 };
	/* map_list2b is when 1 and 0 have been removed. */
	int map_list2b[] = { 2, 3, 2, 3, 2, 2, 2, 3, 3, 3, 2, 3 };
	int map_list2c[] = { 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3 };

	int *map_list2[] = {
		map_list2a,
		map_list2b,
		map_list2c,
	};

	/*
	 * For map list 3, we have one of the 3 starting points from
	 * list 2.  Each of them have 6 of 2 and 6 of 3.
	 *
	 * We are adding 0, 1 back, so there are 7 possibilities.
	 * For each of the 3 in list 2, we can do, 0 first, 1 first,
	 * or we can get a clash to give us the 7th possibility.
	 */

	/* based on list entry 2a, making 0 usable, then making 1 usable */
	int map_list3a[] = { 1, 0, 0, 0, 1, 2, 2, 1, 3, 3, 2, 3 };
	/* based on list entry 2a, making 1 usable, then making 0 usable */
	int map_list3b[] = { 0, 1, 1, 1, 0, 2, 2, 0, 3, 3, 2, 3 };
	/* based on list entry 2b, making 0 usable, then making 1 usable */
	int map_list3c[] = { 1, 0, 0, 0, 1, 2, 2, 1, 3, 3, 2, 3 };
	/* based on list entry 2b, making 1 usable, then making 0 usable */
	int map_list3d[] = { 0, 1, 1, 1, 0, 2, 2, 0, 3, 3, 2, 3 };
	/* based on list entry 2c, making 0 usable, then making 1 usable */
	int map_list3e[] = { 1, 0, 0, 0, 1, 1, 2, 3, 2, 3, 2, 3 };
	/* based on list entry 2c, making 1 usable, then making 0 usable */
	int map_list3f[] = { 0, 1, 1, 1, 0, 0, 2, 3, 2, 3, 2, 3 };
	/* A collision so refill from start */
	int map_list3g[] = { 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3 };

	int *map_list3[] = {
		map_list3a,
		map_list3b,
		map_list3c,
		map_list3d,
		map_list3e,
		map_list3f,
		map_list3g,
	};

	int map_list4[] = { 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 };
	int map_list5[] = { 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 };

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
		"nh 4.4.4.1 int:dp4T1 "
		"nh 5.5.5.1 int:dp4T2 backup");

	dp_test_verify_nh_map_count("10.0.1.4", 12, map_list1);

	dp_test_make_nh_unusable_other_thread(&nh_unusable_thread1,
					      "dp2T1", "2.2.2.1");
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	pthread_join(nh_unusable_thread1, NULL);
	dp_test_verify_nh_map_count_one_of("10.0.1.4", 12,
					   3, map_list2);

	/*
	 * Back to all being used - one via a 2nd thread.
	 */
	dp_test_make_nh_usable_other_thread(&nh_usable_thread1,
					    "dp2T1", "2.2.2.1");
	dp_test_make_nh_usable("dp1T1", "1.1.1.2");
	pthread_join(nh_usable_thread1, NULL);
	dp_test_verify_nh_map_count_one_of("10.0.1.4", 12,
					   7, map_list3);

	/* Finally make everything unusable again */
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	dp_test_make_nh_unusable("dp2T1", "2.2.2.1");
	dp_test_make_nh_unusable("dp3T1", "3.3.3.1");
	dp_test_verify_nh_map_count("10.0.1.4", 12, map_list4);
	dp_test_make_nh_unusable("dp4T1", "4.4.4.1");
	dp_test_verify_nh_map_count("10.0.1.4", 12, map_list5);

	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 "
		"nh 4.4.4.1 int:dp4T1 "
		"nh 5.5.5.1 int:dp4T2 backup");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T1", "4.4.4.4/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T2", "5.5.5.5/24");
	dp_test_clear_path_unusable();

} DP_END_TEST;

DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge9, NULL, NULL);
DP_START_TEST(ip_pic_edge9, ip_pic_edge9)
{
	pthread_t nh_unusable_thread1;
	pthread_t nh_unusable_thread2;
	int map_list1[] = { 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3 };
	int map_list2[] = { 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
	int map_list3[] = { 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 };
	int map_list4[] = { 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0 };

	/* Starting point of 4, enabling path 2 */
	int map_list5a[] = { 2, 2, 1, 1, 1, 1, 2, 2, 0, 0, 0, 0 };
	/* Starting point of 5a, disabling path 1 */
	int map_list5b[] = { 2, 2, 0, 2, 0, 2, 2, 2, 0, 0, 0, 0 };

	/* Starting point of 4, disabling path 1 */
	int map_list5c[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	/* Starting point of 4, enabling path 2 */
	int map_list5d[] = { 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0 };
	/* Initial init to paths 0 and 2 */
	int map_list5e[] = { 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2 };

	int *map_list5[] = {
		map_list5a,
		map_list5b,
		map_list5c,
		map_list5d,
		map_list5e,
	};

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
		"nh 4.4.4.1 int:dp4T1 "
		"nh 5.5.5.1 int:dp4T2 backup");

	dp_test_verify_nh_map_count("10.0.1.4", 12, map_list1);

	/* Make a intf/nh we are not using unusable - no map change */
	dp_test_make_nh_unusable_other_thread(&nh_unusable_thread1,
					      "dp2T1", "2.2.2.1");
	dp_test_make_nh_unusable_other_thread(&nh_unusable_thread2,
					      "dp4T1", "4.4.4.1");
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");
	pthread_join(nh_unusable_thread1, NULL);
	pthread_join(nh_unusable_thread2, NULL);
	dp_test_verify_nh_map_count("10.0.1.4", 12, map_list2);

	/* Making it unusable should force a map rebuild to backup */
	dp_test_make_nh_unusable("dp3T1", "3.3.3.1");
	dp_test_verify_nh_map_count("10.0.1.4", 12, map_list3);

	/* Make paths 0 and 1 usable again */
	dp_test_make_nh_usable("dp1T1", "1.1.1.2");
	dp_test_make_nh_usable("dp2T1", "2.2.2.1");
	dp_test_verify_nh_map_count("10.0.1.4", 12, map_list4);

	/* Now add path 2 while removing path 1 */
	dp_test_make_nh_unusable_other_thread(&nh_unusable_thread1,
					      "dp2T1", "2.2.2.1");
	dp_test_make_nh_usable("dp3T1", "3.3.3.1");
	pthread_join(nh_unusable_thread1, NULL);
	dp_test_verify_nh_map_count_one_of("10.0.1.4", 12,
					   5, map_list5);

	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 "
		"nh 4.4.4.1 int:dp4T1 "
		"nh 5.5.5.1 int:dp4T2 backup");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T1", "4.4.4.4/24");
	dp_test_nl_del_ip_addr_and_connected("dp4T2", "5.5.5.5/24");
	dp_test_clear_path_unusable();

} DP_END_TEST;

/*
 * Create a route with a backup and mark the primary unusable before
 * the route arrives.
 */
DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge10, NULL, NULL);
DP_START_TEST(ip_pic_edge10, ip_pic_edge10)
{
	int map_list1[] = { 1, 1 };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3.3.3.3/24");

	/* Making nh unusable before the route is added */
	dp_test_make_nh_unusable("dp1T1", "1.1.1.2");

	dp_test_netlink_add_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 backup");

	dp_test_verify_nh_map_count("10.0.1.0", 2, map_list1);

	dp_test_netlink_del_route(
		"10.0.1.0/24 "
		"nh 1.1.1.2 int:dp1T1 "
		"nh 2.2.2.1 int:dp2T1 "
		"nh 3.3.3.1 int:dp3T1 backup");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3.3.3.3/24");
	dp_test_clear_path_unusable();

} DP_END_TEST;


/*
 * Create multiple NHs and check that all are marked unusable when
 * the update signal arrives.
 *
 * This is the IPv6 version of ip_pic_edge5. As almost all the code
 * being tested here is AF independent we only need minimal
 * tests to check the differences in the hashing.
 */
DP_DECL_TEST_CASE(ip_pic_edge_suite, ip_pic_edge11, NULL, NULL);
DP_START_TEST(ip_pic_edge11, ip_pic_edge11)
{
	int map_list1[] = { 0 };
	int map_list2[] = { 1 };

	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2::2/64");
	dp_test_nl_add_ip_addr_and_connected("dp3T1", "3::3/64");

	dp_test_netlink_add_route(
		"10::/64 "
		"nh 1::2 int:dp1T1 "
		"nh 2::1 int:dp2T1 backup");

	dp_test_netlink_add_route(
		"10:1::/64 "
		"nh 1::3 int:dp1T1 "
		"nh 2::3 int:dp2T1 backup");

	dp_test_verify_nh_map_count("10::1", 1, map_list1);
	dp_test_verify_nh_map_count("10:1::1", 1, map_list1);

	/* Making it unusable should force a map rebuild */
	dp_test_make_nh_unusable("dp1T1", "1::2");
	dp_test_verify_nh_map_count("10::1", 1, map_list2);
	/* The 2nd route used a different nh so is not modified */
	dp_test_verify_nh_map_count("10:1::1", 1, map_list1);

	dp_test_netlink_del_route(
		"10::/64 "
		"nh 1::2 int:dp1T1 "
		"nh 2::1 int:dp2T1 backup");

	dp_test_netlink_del_route(
		"10:1::/64 "
		"nh 1::3 int:dp1T1 "
		"nh 2::3 int:dp2T1 backup");

	/* Clean Up */

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2::2/64");
	dp_test_nl_del_ip_addr_and_connected("dp3T1", "3::3/64");
	dp_test_clear_path_unusable();

} DP_END_TEST;

