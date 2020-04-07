/*-
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Portmonitor tests.
 */

#include <errno.h>
#include <time.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "if/gre.h"
#include "iptun_common.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_portmonitor.h"

static void
dp_test_portmonitor_setup_span_rspan(uint32_t vrfid)
{
	const char *nh_mac_str;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];

	dp_test_netlink_set_interface_vrf("dp1T1", vrfid);
	dp_test_netlink_set_interface_vrf("dp1T2", vrfid);
	dp_test_netlink_add_ip_address_vrf("dp1T1", "1.1.1.1/24", vrfid);
	snprintf(route1, sizeof(route1), "vrf:%d 1.1.1.0/24 nh int:dp1T1",
		 vrfid);
	dp_test_netlink_add_route(route1);
	dp_test_netlink_set_interface_vrf("dp2T1", vrfid);
	dp_test_netlink_add_ip_address_vrf("dp2T1", "2.2.2.2/24", vrfid);
	snprintf(route2, sizeof(route2),
		 "vrf:%d 10.0.0.0/8 nh 2.2.2.3 int:dp2T1", vrfid);
	dp_test_netlink_add_route(route2);
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str);
}

static void
dp_test_portmonitor_teardown_span_rspan(uint32_t vrfid)
{
	const char *nh_mac_str;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str);
	snprintf(route2, sizeof(route2),
		 "vrf:%d 10.0.0.0/8 nh 2.2.2.3 int:dp2T1", vrfid);
	dp_test_netlink_del_route(route2);
	snprintf(route1, sizeof(route1), "vrf:%d 1.1.1.0/24 nh int:dp1T1",
		 vrfid);
	dp_test_netlink_del_route(route1);

	dp_test_netlink_del_ip_address_vrf("dp1T1", "1.1.1.1/24", vrfid);
	dp_test_netlink_del_ip_address_vrf("dp2T1", "2.2.2.2/24", vrfid);

	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp1T2", VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp2T1", VRF_DEFAULT_ID);
}

DP_DECL_TEST_SUITE(portmonitor_suite);

DP_DECL_TEST_CASE(portmonitor_suite, mirroring, NULL, NULL);

DP_START_TEST(mirroring, span)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	dp_test_portmonitor_setup_span_rspan(VRF_DEFAULT_ID);

	/* Create span session */
	dp_test_portmonitor_create_span(1, "dp1T1", "dp1T2",
						NULL, NULL);

	/* Create pak to match dp1T1's address added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.2",
					   1, &len);
	/* Ingress dp1T1 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* We expect 2 packets, one local and one mirrored */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, "dp1T2");

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Delete SPAN session */
	dp_test_portmonitor_delete_session(1);

	/* Teardown setup */
	dp_test_portmonitor_teardown_span_rspan(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(mirroring, span_filter)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	dp_test_portmonitor_setup_span_rspan(VRF_DEFAULT_ID);

	/* Create portmonitor filter */
	dp_test_portmonitor_create_filter("PMFIN", 20, 0, "src-addr=1.1.1.2",
					  "");
	dp_test_portmonitor_create_filter("PMFOUT", 20, 0, "src-addr=1.1.1.2",
					  "");

	/* Create span session */
	dp_test_portmonitor_create_span(1, "dp1T1", "dp1T2",
						"PMFIN", "PMFOUT");

	/* Attach portmonitor filters */
	dp_test_portmonitor_attach_filter("PMFIN", "in", "dp1T1");
	dp_test_portmonitor_attach_filter("PMFOUT", "out", "dp1T1");

	/* Create pak to match dp1T1's address added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.2",
					   1, &len);
	/* Ingress dp1T1 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* We expect 1 packet, local, mirrored is blocked */
	exp = dp_test_exp_create_m(test_pak, 1);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Detach portmonitor filters */
	dp_test_portmonitor_detach_filter("PMFIN", "in", "dp1T1");
	dp_test_portmonitor_detach_filter("PMFOUT", "out", "dp1T1");

	/* Delete SPAN session */
	dp_test_portmonitor_delete_session(1);

	/* Delete portmonitor filter */
	dp_test_portmonitor_delete_filter("PMFIN");
	dp_test_portmonitor_delete_filter("PMFOUT");

	/* Teardown setup */
	dp_test_portmonitor_teardown_span_rspan(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(mirroring, rspan_source)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_portmonitor_setup_span_rspan(VRF_DEFAULT_ID);

	/* Set up vif interface */
	dp_test_intf_vif_create("dp1T3.10", "dp1T3", 10);
	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T3.10");


	/* Create rspan source session */
	dp_test_portmonitor_create_rspansrc(1, "dp1T1", "dp1T3",
						10, NULL, NULL);

	/* Create pak to match dp1T1's address added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "2.2.2.2",
					   1, &len);
	/* Ingress dp1T1 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* We expect 2 packets, one local and one mirrored */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);
	dp_test_exp_set_fwd_status_m(exp, 1, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 1, "dp1T3");
	exp->exp_pak[1]->vlan_tci = 10;

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Delete RSPAN session */
	dp_test_portmonitor_delete_session(1);

	/* Delete vif interface */
	dp_test_intf_bridge_remove_port("br1", "dp1T3.10");
	dp_test_intf_vif_del("dp1T3.10", 10);
	dp_test_intf_bridge_del("br1");

	/* Teardown setup */
	dp_test_portmonitor_teardown_span_rspan(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(mirroring, rspan_source_filter)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_portmonitor_setup_span_rspan(VRF_DEFAULT_ID);

	/* Set up vif interface */
	dp_test_intf_vif_create("dp1T3.10", "dp1T3", 10);
	dp_test_intf_bridge_create("br1");
	dp_test_intf_bridge_add_port("br1", "dp1T3.10");

	/* Create portmonitor filter */
	dp_test_portmonitor_create_filter("PMFIN", 20, 0, "src-addr=1.1.1.2",
					  "");
	dp_test_portmonitor_create_filter("PMFOUT", 20, 0, "src-addr=1.1.1.2",
					  "");

	/* Create rspan source session */
	dp_test_portmonitor_create_rspansrc(1, "dp1T1", "dp1T3",
						10, "PMFIN", "PMFOUT");

	/* Attach portmonitor filters */
	dp_test_portmonitor_attach_filter("PMFIN", "in", "dp1T1");
	dp_test_portmonitor_attach_filter("PMFOUT", "out", "dp1T1");

	/* Create pak to match dp1T1's address added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.2",
					   1, &len);
	/* Ingress dp1T1 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* We expect 1 packet, local, mirrored is blocked */
	exp = dp_test_exp_create_m(test_pak, 1);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Detach portmonitor filters */
	dp_test_portmonitor_detach_filter("PMFIN", "in", "dp1T1");
	dp_test_portmonitor_detach_filter("PMFOUT", "out", "dp1T1");

	/* Delete RSPAN session */
	dp_test_portmonitor_delete_session(1);

	/* Delete portmonitor filter */
	dp_test_portmonitor_delete_filter("PMFIN");
	dp_test_portmonitor_delete_filter("PMFOUT");

	/* Clean up vif interface */
	dp_test_intf_bridge_remove_port("br1", "dp1T3.10");
	dp_test_intf_vif_del("dp1T3.10", 10);
	dp_test_intf_bridge_del("br1");

	/* Teardown setup */
	dp_test_portmonitor_teardown_span_rspan(VRF_DEFAULT_ID);
} DP_END_TEST;

static void
dp_test_portmonitor_setup_erspan(uint32_t vrfid)
{
	const char *nh_mac_str;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];

	dp_test_netlink_set_interface_vrf("dp1T1", vrfid);
	dp_test_netlink_set_interface_vrf("dp1T2", vrfid);
	dp_test_netlink_add_ip_address_vrf("dp1T1", "1.1.1.1/24", vrfid);
	snprintf(route1, sizeof(route1), "vrf:%d 1.1.1.0/24 nh int:dp1T1",
		 vrfid);
	dp_test_netlink_add_route(route1);
	dp_test_netlink_set_interface_vrf("dp2T1", vrfid);
	dp_test_netlink_add_ip_address_vrf("dp2T1", "2.2.2.2/24", vrfid);
	snprintf(route2, sizeof(route2),
		 "vrf:%d 10.0.0.0/8 nh 2.2.2.3 int:dp2T1", vrfid);
	dp_test_netlink_add_route(route2);
	dp_test_netlink_add_ip_address("dp2T2", "1.1.2.1/24");
	dp_test_netlink_add_route("1.1.2.0/24 nh int:dp2T2");
	dp_test_intf_erspan_create("erspan1", "1.1.2.1", "1.1.2.2",
					0, 1, vrfid);
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "1.1.2.2", nh_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", nh_mac_str);
}

static void
dp_test_portmonitor_teardown_erspan(uint32_t vrfid)
{
	const char *nh_mac_str;
	char route1[TEST_MAX_CMD_LEN];
	char route2[TEST_MAX_CMD_LEN];

	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_del_neigh("dp2T2", "1.1.2.2", nh_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", nh_mac_str);
	snprintf(route2, sizeof(route2),
		 "vrf:%d 10.0.0.0/8 nh 2.2.2.3 int:dp2T1", vrfid);
	dp_test_netlink_del_route(route2);
	dp_test_netlink_del_route("1.1.2.0/24 nh int:dp2T2");
	snprintf(route1, sizeof(route1), "vrf:%d 1.1.1.0/24 nh int:dp1T1",
		 vrfid);
	dp_test_netlink_del_route(route1);

	dp_test_netlink_del_ip_address_vrf("dp1T1", "1.1.1.1/24", vrfid);
	dp_test_netlink_del_ip_address("dp2T2", "1.1.2.1/24");
	dp_test_netlink_del_ip_address_vrf("dp2T1", "2.2.2.2/24", vrfid);

	dp_test_intf_erspan_delete("erspan1", "1.1.2.1", "1.1.2.2",
					0, 1, vrfid);
	dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp1T2", VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp2T1", VRF_DEFAULT_ID);
}

static void
erspan_build_expected_pak(struct dp_test_expected **expected,
			  struct rte_mbuf *tpak,
			  uint16_t gre_prot, uint16_t erspanid,
			  uint8_t srcidx, uint8_t dir)
{
	int len;
	struct dp_test_expected *exp;
	struct iphdr *inner_ip;
	struct ether_hdr *payload;
	void *erspan_payload;
	struct rte_mbuf *m;
	uint8_t *dont_care_start;
	uint32_t dont_care_len;
	struct iphdr *outer_ip;

	exp = *expected;
	exp->oif_name[1] = "dp2T2";
	exp->fwd_result[1] = DP_TEST_FWD_FORWARDED;

	inner_ip = iphdr(tpak);
	len = ntohs(inner_ip->tot_len) + ETHER_HDR_LEN;
	m = dp_test_create_erspan_ipv4_pak("1.1.2.1", "1.1.2.2",
					   &len, gre_prot, erspanid, srcidx,
					   tpak->vlan_tci, dir,
					   &erspan_payload);
	if (!m)
		return;
	payload = rte_pktmbuf_mtod(tpak, struct ether_hdr *);
	memcpy(erspan_payload, payload, len);
	rte_pktmbuf_free(exp->exp_pak[1]);
	exp->exp_pak[1] = m;

	/* Check packet after ether hdr */
	exp->check_start[1] = dp_pktmbuf_l2_len(exp->exp_pak[1]);
	exp->check_len[1] = rte_pktmbuf_data_len(exp->exp_pak[0]) -
				exp->check_start[1];

	/* Ignore GRE sequence number */
	dont_care_len = m->l2_len + m->l3_len + 4;
	dont_care_start = rte_pktmbuf_mtod_offset(m, uint8_t *, dont_care_len);
	dp_test_exp_set_dont_care(exp, 1, dont_care_start, 4);

	/* PMTU disc on, so DF bit gets set */
	outer_ip = iphdr(m);
	dp_test_set_pak_ip_field(outer_ip, DP_TEST_SET_DF, 1);
}

DP_START_TEST(mirroring, erspan_source)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_portmonitor_setup_erspan(VRF_DEFAULT_ID);

	/* Create erspan source session */
	dp_test_portmonitor_create_erspansrc(1, "dp1T1", "erspan1",
						20, 1, NULL, NULL);

	/* Create pak to match dp1T1's address added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "2.2.2.2",
					   1, &len);
	/* Ingress dp1T1 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* We expect 2 packets, one local and one mirrored */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);

	erspan_build_expected_pak(&exp, test_pak, ETH_P_ERSPAN_TYPEII,
				  20, 1, 1);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Delete ERSPAN session */
	dp_test_portmonitor_delete_session(1);

	/* Teardown setup */
	dp_test_portmonitor_teardown_erspan(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(mirroring, erspan_source_filter)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_portmonitor_setup_erspan(VRF_DEFAULT_ID);

	/* Create portmonitor filter */
	dp_test_portmonitor_create_filter("PMFIN", 20, 0, "src-addr=1.1.1.2",
					  "");
	dp_test_portmonitor_create_filter("PMFOUT", 20, 0, "src-addr=1.1.1.2",
					  "");
	/* Create erspan source session */
	dp_test_portmonitor_create_erspansrc(1, "dp1T1", "erspan1",
						20, 1, "PMFIN", "PMFOUT");

	/* Attach portmonitor filters */
	dp_test_portmonitor_attach_filter("PMFIN", "in", "dp1T1");
	dp_test_portmonitor_attach_filter("PMFOUT", "out", "dp1T1");

	/* Create pak to match dp1T1's address added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.2", "2.2.2.2",
					   1, &len);
	/* Ingress dp1T1 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* We expect 1 packet, local, mirrored is blocked */
	exp = dp_test_exp_create_m(test_pak, 1);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* Detach portmonitor filters */
	dp_test_portmonitor_detach_filter("PMFIN", "in", "dp1T1");
	dp_test_portmonitor_detach_filter("PMFOUT", "out", "dp1T1");

	/* Delete ERSPAN session */
	dp_test_portmonitor_delete_session(1);

	/* Delete portmonitor filter */
	dp_test_portmonitor_delete_filter("PMFIN");
	dp_test_portmonitor_delete_filter("PMFOUT");

	/* Teardown setup */
	dp_test_portmonitor_teardown_erspan(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(mirroring, erspan_vlan_source)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	int len = 22;

	/* Set up the interface addresses */
	dp_test_portmonitor_setup_erspan(VRF_DEFAULT_ID);
	dp_test_intf_vif_create("dp1T1.10", "dp1T1", 10);
	dp_test_nl_add_ip_addr_and_connected("dp1T1.10", "3.3.3.3/24");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp1T1.10", "3.3.3.1", nh_mac_str);

	/* Create erspan source session */
	dp_test_portmonitor_create_erspansrc(1, "dp1T1", "erspan1",
						20, 1, NULL, NULL);

	/* RX port monitor */

	/* Create pak to match dp1T1.10's address added above */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "3.3.3.3",
					   1, &len);
	/* Ingress dp1T1 with vlan 10 */
	dp_test_pktmbuf_vlan_init(test_pak, 10);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* We expect 2 packets, one local and one mirrored */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_LOCAL);

	erspan_build_expected_pak(&exp, test_pak, ETH_P_ERSPAN_TYPEII,
				  20, 1, 1);

	dp_test_pak_receive(test_pak, "dp1T1", exp);

	/* TX port monitor */

	/* Create pak to match dp2T1's address added above */
	test_pak = dp_test_create_ipv4_pak("2.2.2.1", "3.3.3.1",
					   1, &len);
	/* Ingress dp2T1 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp2T1"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       ETHER_TYPE_IPv4);

	/* We expect 2 packets, one local and one mirrored */
	exp = dp_test_exp_create_m(test_pak, 2);
	dp_test_exp_set_fwd_status_m(exp, 0, DP_TEST_FWD_FORWARDED);
	dp_test_exp_set_oif_name_m(exp, 0, "dp1T1");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak_m(exp, 0),
				 nh_mac_str,
				 dp_test_intf_name2mac_str("dp1T1"),
				 ETHER_TYPE_IPv4);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak_m(exp, 0));
	dp_test_exp_set_vlan_tci_m(exp, 0, 10);

	erspan_build_expected_pak(&exp, dp_test_exp_get_pak_m(exp, 0),
				  ETH_P_ERSPAN_TYPEII, 20, 1, 2);
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak_m(exp, 1));

	dp_test_pak_receive(test_pak, "dp2T1", exp);

	/* Delete ERSPAN session */
	dp_test_netlink_del_neigh("dp1T1.10", "3.3.3.1", nh_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1.10", "3.3.3.3/24");
	dp_test_intf_vif_del("dp1T1.10", 10);
	dp_test_portmonitor_delete_session(1);

	/* Teardown setup */
	dp_test_portmonitor_teardown_erspan(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_DECL_TEST_CASE(portmonitor_suite, pmcleanup, NULL, NULL);

DP_START_TEST(pmcleanup, erspan_destif_del)
{
	/* Set up the interface addresses */
	dp_test_portmonitor_setup_erspan(VRF_DEFAULT_ID);

	/* Create erspan source session */
	dp_test_portmonitor_create_erspansrc(1, "dp1T1", "erspan1",
						20, 1, NULL, NULL);

	/* Teardown erspan interface first and then ERSPAN session */
	dp_test_portmonitor_teardown_erspan(VRF_DEFAULT_ID);

	/* Delete ERSPAN session */
	dp_test_portmonitor_delete_session(1);
} DP_END_TEST;

DP_START_TEST(pmcleanup, erspan_srcif_del)
{
	/* Set up the interface addresses */
	dp_test_portmonitor_setup_erspan(VRF_DEFAULT_ID);

	/* Create erspan destination session */
	dp_test_portmonitor_create_erspandst(1, "erspan1", "dp1T1",
						20, 1);

	/* Teardown erspan interface first and then ERSPAN session */
	dp_test_portmonitor_teardown_erspan(VRF_DEFAULT_ID);

	/* Delete ERSPAN session */
	dp_test_portmonitor_delete_session(1);
} DP_END_TEST;
