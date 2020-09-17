/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <errno.h>
#include <time.h>
#include <values.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_sess_lib.h"

DP_DECL_TEST_SUITE(npf_acl);

static void acl_setup(void)
{
	/* Setup v4 interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "10.0.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "20.0.2.1/24");

	dp_test_netlink_add_neigh("dp1T0", "10.0.1.2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "20.0.2.2", "aa:bb:cc:dd:2:b1");

	/* Setup v6 interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

}

static void acl_teardown(void)
{
	dp_test_netlink_del_neigh("dp1T0", "10.0.1.2", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "20.0.2.2", "aa:bb:cc:dd:2:b1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "10.0.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "20.0.2.1/24");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

}

static void _dpt_icmp6(uint8_t icmp_type, const char *rx_intf,
		       const char *pre_smac, const char *saddr, uint16_t icmpid,
		       const char *daddr, const char *post_dmac,
		       const char *tx_intf, int status,
		       const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	struct dp_test_pkt_desc_t v6_pkt = {
		.text       = "ICMP IPv6",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV6,
		.l3_src     = saddr,
		.l2_src     = pre_smac,
		.l3_dst     = daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_ICMPV6,
		.l4         = {
			.icmp = {
				.type = icmp_type,
				.code = 0,
				{
					.dpt_icmp_id = icmpid,
					.dpt_icmp_seq = 0,
				}
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	test_pak = dp_test_v6_pkt_from_desc(&v6_pkt);

	exp_pak = dp_test_v6_pkt_from_desc(&v6_pkt);
	test_exp = dp_test_exp_from_desc(exp_pak, &v6_pkt);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, status);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}

#define dpt_icmp6(_a, _b, _c, _d, _e, _f, _g, _h, _i)			\
	_dpt_icmp6(_a, _b, _c, _d, _e, _f, _g, _h, _i,			\
		   __FILE__, __func__, __LINE__)

/*
 * acl1 - v4 drop acl
 */
DP_DECL_TEST_CASE(npf_acl, acl1, acl_setup, acl_teardown);
DP_START_TEST(acl1, test)
{
	/* set security ip-packet-filter group v4test ip-version ipv4 */
	dp_test_npf_cmd("npf-ut add acl:v4test 0 family=inet", false);

	/* set security ip-packet-filter group v4test rule 10 action drop */
	dp_test_npf_cmd("npf-ut add acl:v4test 10 action=drop", false);

	/* set security ip-packet-filter interface dp0p1s1 in v4test */
	dp_test_npf_cmd("npf-ut attach interface:dpT10 acl-in acl:v4test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	dpt_icmp(ICMP_ECHO,
		 "dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.2", 10000, "20.0.2.2",
		 "10.0.1.2", 10000, "20.0.2.2",
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_DROPPED);

	dpt_icmp6(ICMP6_ECHO_REQUEST,
		  "dp1T0", "aa:bb:cc:dd:1:a1",
		  "2001:1:1::2", 10000, "2002:2:2::1",
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT10 acl-in acl:v4test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v4test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;

/*
 * acl2 - v6 drop acl
 */
DP_DECL_TEST_CASE(npf_acl, acl2, acl_setup, acl_teardown);
DP_START_TEST(acl2, test)
{
	/* set security ip-packet-filter group v6test ip-version ipv6 */
	dp_test_npf_cmd("npf-ut add acl:v6test 0 family=inet6", false);

	/* set security ip-packet-filter group v6test rule 10 action drop */
	dp_test_npf_cmd("npf-ut add acl:v6test 10 action=drop", false);

	/* set security ip-packet-filter interface dp0p1s1 in v6test */
	dp_test_npf_cmd("npf-ut attach interface:dpT10 acl-in acl:v6test",
			false);

	dp_test_npf_cmd("npf-ut commit", false);

	dpt_icmp(ICMP_ECHO,
		 "dp1T0", "aa:bb:cc:dd:1:a1",
		 "10.0.1.2", 10000, "20.0.2.2",
		 "10.0.1.2", 10000, "20.0.2.2",
		 "aa:bb:cc:dd:2:b1", "dp2T1",
		 DP_TEST_FWD_FORWARDED);

	dpt_icmp6(ICMP6_ECHO_REQUEST,
		  "dp1T0", "aa:bb:cc:dd:1:a1",
		  "2001:1:1::2", 10000, "2002:2:2::1",
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_DROPPED);

	/*****************************************************************
	 * Unconfig
	 */
	dp_test_npf_cmd("npf-ut detach interface:dpT10 acl-in acl:v6test",
			false);
	dp_test_npf_cmd("npf-ut delete acl:v6test", false);
	dp_test_npf_cmd("npf-ut commit", false);

} DP_END_TEST;
