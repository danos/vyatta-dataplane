/*
 * Copyright (c) 2021, AT&T Intellectual Property. All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT Firewall tests for MPLS ICMPv4/ICMPv6 error packets.
 * originated from kernel and check the dscp marking
 */

#include <libmnl/libmnl.h>

#include "if_var.h"
#include "in_cksum.h"
#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_str.h"
#include "protobuf/ForwardingClassConfig.pb-c.h"

DP_DECL_TEST_SUITE(npf_orig);

/*
 * Test generates ICMPv4 message with TTL = 1 and as result uut generates
 * ICMPv4 message time exceed.
 *               1.1.1.1/24 +-----+ 2.2.2.2/24
 *                          |     |
 * host 10.73.0.0   --------| uut |---------------router 2.2.2.1
 *                    dp1T1 |     | dp2T2
 *                    intf1 +-----+ intf2
 *                    Route:
 *    122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22
 *    10.73.0.0/24 nh int:lo lbls 123
 *      --> Forwards (on output)
 *      L2 MPLS: Label 122, TTL 1
 *      Source 10.73.0.0 Destination 10.73.2.0 (DSCP 0xc0)
 *      <-- Back ICMP time exceeded
 *      L2 MPLS: Label 22, TTL 64
 *      Source 1.1.1.1 Destination 10.73.0.0
 */

struct mpls_icmp_subcase {
	int nlabels;
	label_t labels[4];
	uint8_t ttl[4];
	int plen;
	int exp_nlabels;
	label_t exp_labels[4];
	uint8_t exp_ttl[4];
};

/*
 * helper function to print summary of each subcase
 */
static int mpls_icmp_subcase_string(struct mpls_icmp_subcase *tc, char *descr, unsigned int sz)
{
	int written = 0;
	int i;

	written += spush(descr + written, sz - written, "pkt_len = %d lbl:(ttl) = [ ", tc->plen);
	for (i = 0; i < tc->nlabels; i++)
		written += spush(descr + written, sz - written, "%d:(%d), ", tc->labels[i],
				tc->ttl[i]);
	/* lose trailing ', '  */
	if (tc->nlabels)
		written -= 2;

	written += spush(descr + written, sz - written, "] --> [");

	for (i = 0; i < tc->exp_nlabels; i++)
		written += spush(descr + written, sz - written, "%d:(%d), ", tc->exp_labels[i],
				tc->exp_ttl[i]);
	/* lose trailing ', '  */
	if (tc->nlabels)
		written -= 2;
	written += spush(descr + written, sz - written, "]");
	return written;
}

static struct rte_mbuf *npf_orig_mpls_icmp_v4_create_exp_mpls_pack(
		const char *saddr, const char *daddr,
		uint8_t icmp_type, uint8_t icmp_code, uint32_t data,
		const char *nh_mac_str, int icmp_max_orig_pak_size,
		struct iphdr *test_pak_ip,
		struct rte_mbuf *test_pak,
		struct mpls_icmp_subcase *test_data)
{
	struct iphdr *exp_pak_ip;
	struct icmphdr *icph;
	int icmplen, icmpextlen;
	struct rte_mbuf *icmp_exp_pak;
	struct rte_mbuf *mpls_exp_pak;
	const int mpls_ext_hdr_size = 8;
	unsigned int total_payload_len;
	char *cp;

	/*
	 * Create expected icmp packet
	 * BEWARE: assumes original packet will fit within 128 offset
	 * on top of that we add 8 bytes for mpls extension header and
	 * another 4 per label.
	 * eth(mac not set, RTE_ETHER_TYPE_IPV4)
	 * ipv4 hdr
	 * icmp hdr
	 */
	icmpextlen = (test_data->nlabels * 4) + mpls_ext_hdr_size;
	icmplen = icmp_max_orig_pak_size + icmpextlen;

	icmp_exp_pak = dp_test_create_icmp_ipv4_pak(saddr, daddr, icmp_type, icmp_code, data, 1,
						    &icmplen, NULL, &exp_pak_ip, &icph);

	/* aliases the length field */
	icph->un.echo.id = htons((icmplen - icmpextlen) / 4);

	if (rte_pktmbuf_data_len(test_pak) > icmp_max_orig_pak_size)
		total_payload_len = icmp_max_orig_pak_size;
	else
		total_payload_len = rte_pktmbuf_data_len(test_pak);

	/* Original IP header goes in next
	 * eth(mac not set, RTE_ETHER_TYPE_IPV4)
	 * ipv4 hdr
	 * icmp hdr
	 * + orig packet ipv4 hdr + udp (max 128)
	 */
	memcpy(icph + 1, test_pak_ip, total_payload_len);

	/* Pad out with zeroes up to 128 bytes
	 * ipv4 hdr
	 * icmp hdr
	 * orig packet ipv4 hdr + udp (max 128)
	 * + Pad (0x00)
	 */
	memset((char *)(icph + 1) + total_payload_len, 0,
	       icmp_max_orig_pak_size - total_payload_len);

	/* Now the ICMP MPLS extended header
	 * eth(mac not set, RTE_ETHER_TYPE_IPV4)
	 * ipv4 hdr
	 * icmp hdr
	 * orig packet ipv4 hdr + udp (max 128)
	 * Pad (0x00)
	 * + ICMP MPLS EXT Header
	 * + MPLS orig stack
	 * 0                   1                   2                   3
	 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *|Version|      (Reserved)       |           Checksum            |
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	cp = (char *)(icph + 1) + icmplen - icmpextlen;
	cp[0] = 0x20;	   /* ieh_version=ICMP_EXT_HDR_VERSION */
	cp[1] = 0;	   /* ieh_res=0 */
	cp[2] = cp[3] = 0; /* ieh_cksum=0 */
	/*
	 *+-------------+-------------+-------------+-------------+
	 *|           Length          | Class-Num   | C-Type      |
	 *+-------------+-------------+-------------+-------------+
	 *|                                                       |
	 *|               // (Object contents) //                 |
	 *|                                                       |
	 *+-------------+-------------+-------------+-------------+
	 */
	cp[4] = 0; /* ieo_length=4 + label stack length */
	cp[5] = 4 + (test_data->nlabels * 4);
	cp[6] = 1; /* ieo_cnum=ICMP_EXT_MPLS */
	cp[7] = 1; /* ieo_ctype=ICMP_EXT_MPLS_INCOMING */
	/* The incoming label stack
	 */
	memcpy(&cp[8], dp_pktmbuf_mtol3(test_pak, char *), test_data->nlabels * 4);

	/* Finally the ICMP checksum fields */
	*(uint16_t *)(cp + 2) = in_cksum(cp, 4 + cp[5]);

	dp_test_set_pak_ip_field(exp_pak_ip, DP_TEST_SET_TOS, IPTOS_DSCP_AF12);

	icph->checksum = 0;
	icph->checksum = dp_test_ipv4_icmp_cksum(icmp_exp_pak, icph);

	/* Create expected mpls packet */
	mpls_exp_pak = dp_test_create_mpls_pak(test_data->exp_nlabels, test_data->exp_labels,
					       test_data->exp_ttl, icmp_exp_pak);

	rte_pktmbuf_free(icmp_exp_pak);
	dp_test_pktmbuf_eth_init(mpls_exp_pak, nh_mac_str, dp_test_intf_name2mac_str("dp2T2"),
				 RTE_ETHER_TYPE_MPLS);

	return mpls_exp_pak;
}

static struct rte_mbuf *npf_orig_mpls_icmp_v6_create_exp_mpls_pack(
		const char *saddr, const char *daddr,
		uint8_t icmp_type, uint8_t icmp_code, uint32_t data,
		const char *host_mac_str, int icmp_max_orig_pak_size,
		struct ip6_hdr *test_pak_ip,
		struct rte_mbuf *test_pak,
		struct mpls_icmp_subcase *test_data,
		const char *out_if_name)
{
	struct ip6_hdr *exp_pak_ip;
	struct icmp6_hdr *icph;
	int icmplen, icmpextlen;
	struct rte_mbuf *icmp_exp_pak;
	struct rte_mbuf *mpls_exp_pak;
	const int mpls_ext_hdr_size = 8;
	unsigned int total_payload_len;
	char *cp;

	/*
	 * Create expected icmp packet
	 * BEWARE: assumes original packet will fit within 128 offset
	 * on top of that we add 8 bytes for mpls extension header and
	 * another 4 per label.
	 * eth(mac not set, RTE_ETHER_TYPE_IPV4)
	 * ipv4 hdr
	 * icmp hdr
	 */
	icmpextlen = (test_data->nlabels * 4) + mpls_ext_hdr_size;
	icmplen = icmp_max_orig_pak_size + icmpextlen;

	icmp_exp_pak = dp_test_create_icmp_ipv6_pak(saddr, daddr, icmp_type, icmp_code, data, 1,
						    &icmplen, NULL, &exp_pak_ip, &icph);

	/* aliases the length field */
	icph->icmp6_id = htons((icmplen - icmpextlen) / 4);

	/* aliases the length field */
	if (rte_pktmbuf_data_len(test_pak) > icmp_max_orig_pak_size)
		total_payload_len = icmp_max_orig_pak_size;
	else
		total_payload_len = rte_pktmbuf_data_len(test_pak);

	/* Original IP header goes in next
	 * eth(mac not set, RTE_ETHER_TYPE_IPV4)
	 * ipv4 hdr
	 * icmp hdr
	 * + orig packet ipv4 hdr + udp (max 128)
	 */
	memcpy(icph + 1, test_pak_ip, total_payload_len);

	/* Pad out with zeroes up to 128 bytes
	 * ipv4 hdr
	 * icmp hdr
	 * orig packet ipv4 hdr + udp (max 128)
	 * + Pad (0x00)
	 */
	memset((char *)(icph + 1) + total_payload_len, 0,
	       icmp_max_orig_pak_size - total_payload_len);

	/* Now the ICMP MPLS extended header
	 * eth(mac not set, RTE_ETHER_TYPE_IPV4)
	 * ipv4 hdr
	 * icmp hdr
	 * orig packet ipv4 hdr + udp (max 128)
	 * Pad (0x00)
	 * + ICMP MPLS EXT Header
	 * + MPLS orig stack
	 * 0                   1                   2                   3
	 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *|Version|      (Reserved)       |           Checksum            |
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	cp = (char *)(icph + 1) + icmplen - icmpextlen;
	cp[0] = 0x20;	   /* ieh_version=ICMP_EXT_HDR_VERSION */
	cp[1] = 0;	   /* ieh_res=0 */
	cp[2] = cp[3] = 0; /* ieh_cksum=0 */
	/*
	 *+-------------+-------------+-------------+-------------+
	 *|           Length          | Class-Num   | C-Type      |
	 *+-------------+-------------+-------------+-------------+
	 *|                                                       |
	 *|               // (Object contents) //                 |
	 *|                                                       |
	 *+-------------+-------------+-------------+-------------+
	 */
	cp[4] = 0; /* ieo_length=4 + label stack length */
	cp[5] = 4 + (test_data->nlabels * 4);
	cp[6] = 1; /* ieo_cnum=ICMP_EXT_MPLS */
	cp[7] = 1; /* ieo_ctype=ICMP_EXT_MPLS_INCOMING */
	/* The incoming label stack
	 */
	memcpy(&cp[8], dp_pktmbuf_mtol3(test_pak, char *), test_data->nlabels * 4);

	/* Finally the ICMP checksum fields */
	*(uint16_t *)(cp + 2) = in_cksum(cp, 4 + cp[5]);

	dp_test_set_pak_ip6_field(exp_pak_ip, DP_TEST_SET_TOS, IPTOS_DSCP_AF12);

	icph->icmp6_cksum = 0;
	icph->icmp6_cksum = dp_test_ipv6_icmp_cksum(icmp_exp_pak, exp_pak_ip, icph);

	/* Create expected mpls packet */
	mpls_exp_pak = dp_test_create_mpls_pak(test_data->exp_nlabels, test_data->exp_labels,
					       test_data->exp_ttl, icmp_exp_pak);

	rte_pktmbuf_free(icmp_exp_pak);
	dp_test_pktmbuf_eth_init(mpls_exp_pak, host_mac_str, dp_test_intf_name2mac_str(out_if_name),
				 RTE_ETHER_TYPE_MPLS);

	return mpls_exp_pak;
}

DP_DECL_TEST_CASE(npf_orig, mpls_icmp_ttl_v4, NULL, NULL);

DP_START_TEST(mpls_icmp_ttl_v4, remark_dscp)
{
	struct iphdr *payload_pak_ip;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pak;
	struct rte_mbuf *payload_pak;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str;
	const int icmp_max_orig_pak_size = 128;
	struct mpls_icmp_subcase test_data = {
		.nlabels =  1,
		.labels = {122,},
		.ttl = {1,},
		.plen = 22,
		.exp_nlabels = 1,
		.exp_labels = {22,},
		.exp_ttl = {64,}
	};
	char subcase_descr[200];

	dp_test_netlink_set_mpls_forwarding("dp1T1", true);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	/* Add lswitch entries */
	dp_test_netlink_add_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	nh_mac_str = "aa:bb:cc:dd:ee:ff";
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", nh_mac_str);

	/* Create ip packet to be payload */
	payload_pak = dp_test_create_ipv4_pak("10.73.0.0", "10.73.2.0", 1, &test_data.plen);
	payload_pak_ip = iphdr(payload_pak);

	/* Create the mpls packet that encapsulates it */
	test_pak = dp_test_create_mpls_pak(test_data.nlabels, test_data.labels, test_data.ttl,
					   payload_pak);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T1"), NULL,
				 RTE_ETHER_TYPE_MPLS);

	/* Configure ICMPv4 error packets to be marked as AF12*/
	dp_test_fail_unless(
		(dp_test_ForwardingClassConfig_execute(
			 FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV4,
			 FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP, IPTOS_DSCP_AF12) == true),
		"TOS configuration is failed");
	expected_pak = npf_orig_mpls_icmp_v4_create_exp_mpls_pack(
		"1.1.1.1", "10.73.0.0", ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0, nh_mac_str,
		icmp_max_orig_pak_size, payload_pak_ip, test_pak, &test_data);

	/* content of payload_pak has been copied
	 * to expected_pak and test_pak so we don't need it anymore
	 */
	rte_pktmbuf_free(payload_pak);

	exp = dp_test_exp_create(expected_pak);
	rte_pktmbuf_free(expected_pak);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	mpls_icmp_subcase_string(&test_data, subcase_descr, sizeof(subcase_descr));

	/* Run test */
	dp_test_pak_rx_for(test_pak, "dp1T1", exp, "for subcase : %s", subcase_descr);

	/* Clean up */
	/* Configure ICMPv4 error packets to be marked as default value*/
	dp_test_fail_unless((dp_test_ForwardingClassConfig_execute(
				     FORWARDING_CLASS_CONFIG__ADDRESS_FAMILY__IPV4,
				     FORWARDING_CLASS_CONFIG__PROTOCOL_TYPE__ICMP,
				     IPTOS_PREC_INTERNETCONTROL) == true),
			    "TOS configuration is failed");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", nh_mac_str);
	dp_test_netlink_del_route("122 mpt:ipv4 nh 2.2.2.1 int:dp2T2 lbls 22");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.2/24");

	dp_test_netlink_set_mpls_forwarding("dp1T1", false);
}
DP_END_TEST;

