/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf IPv6 firewall tests
 */

#include <libmnl/libmnl.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"

static bool npf_fw_debug;


DP_DECL_TEST_SUITE(npf_fw_ipv6);

DP_DECL_TEST_CASE(npf_fw_ipv6, npf_ipv6, NULL, NULL);

/*
 * This test checks that a packet with an ipv6 routing header matches
 * against a rule trying to match one. Note that the header is placed
 * as a second extension header, to ensure it is only the first header
 * that is looked at.
 */
DP_START_TEST(npf_ipv6, ipv6_routing_hdr)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *pak;
	struct udphdr *udp;
	struct ip6_hdr *ip6;
	uint16_t hlen, poff, plen, written;
	void *rp;
	int len1[] = {120};
	struct ip6_hbh *hbh;
	const int hop_by_hop_size = 16;
	struct ip6_rthdr *rtr;
	const int routing_hdr_size = 24;

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = STATELESS,
				    /*
				     * 43 is the value of protocol ipv6-route,
				     * and 1 is the ipv6-route type
				     */
			.npf      = "proto-final=43 ipv6-route=1"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name = "FW1_IN",
		.enable = 1,
		.attach_point = "dp1T0",
		.fwd = FWD,
		.dir = "in",
		.rules = rules
	};

	dp_test_npf_fw_add(&fw, npf_fw_debug);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

	/* Create mbuf chain */
	hlen = sizeof(*ip6) + sizeof(*udp);
	pak = dp_test_create_mbuf_chain(ARRAY_SIZE(len1), len1, hlen);
	dp_test_assert_internal(pak != NULL);

	rp = dp_test_pktmbuf_eth_init(pak,
				      dp_test_intf_name2mac_str("dp1T0"),
				      "aa:bb:cc:dd:1:a1", RTE_ETHER_TYPE_IPV6);
	dp_test_assert_internal(rp != NULL);

	ip6 = dp_test_pktmbuf_ip6_init(pak, "2001:1:1::2",
				       "2002:2:2::1", IPPROTO_UDP);
	dp_test_assert_internal(ip6 != NULL);

	/*
	 * Add IPPROTO_HOPOPTS ext. header
	 */
	hbh = (struct ip6_hbh *)(ip6 + 1);
	memset(hbh, 0, hop_by_hop_size);
	hbh->ip6h_nxt = IPPROTO_ROUTING;
	hbh->ip6h_len = (hop_by_hop_size / 8) - 1;
	pak->l3_len += hop_by_hop_size;

	/*
	 * Add IPPROTO_ROUTING ext. header
	 */
	rtr = (struct ip6_rthdr *)(((char *)hbh) + hop_by_hop_size);
	memset(rtr, 0, routing_hdr_size);
	rtr->ip6r_nxt = ip6->ip6_nxt;
	rtr->ip6r_len = (routing_hdr_size / 8) - 1;
	rtr->ip6r_type = 1;
	rtr->ip6r_segleft = 0;
	pak->l3_len += routing_hdr_size;

	ip6->ip6_nxt = IPPROTO_HOPOPTS;

	/* Payload offset and length */
	poff = pak->l2_len + pak->l3_len + sizeof(*udp);
	plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	written = dp_test_pktmbuf_payload_init(pak, poff, NULL, plen);
	dp_test_assert_internal(written != 0);

	udp = dp_test_pktmbuf_udp_init(pak, 41000, 80, false);
	dp_test_assert_internal(udp != NULL);

	exp = dp_test_exp_create(pak);
	dp_test_assert_internal(exp != NULL);
	dp_test_exp_set_oif_name(exp, "dp2T1");

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       "aa:bb:cc:dd:2:b1",
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV6);

	dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pak, "dp1T0", exp);

	dp_test_npf_verify_rule_pkt_count("ipv6 routing header",
					  &fw, fw.rules[0].rule, 1);

	/* Cleanup */
	dp_test_npf_fw_del(&fw, npf_fw_debug);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");
} DP_END_TEST;
