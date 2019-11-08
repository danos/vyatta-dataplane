/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <linux/xfrm.h>

#include "dp_test_crypto_lib.h"
#include "dp_test_pktmbuf_lib.h"

/*
 * dp_test_prefix_str_to_xfrm_addr()
 *
 * This function parses a string containing an IPv4 or IPv6 prefix
 * of the form:
 *
 *         10.11.12.14/32
 * or
 *         2001:1::15/64
 *
 * The address part is returned in the xfrm_address_t pointed
 * to by the address parameter.
 *
 * The mask length is returned in the int pointed to by
 * the mask_length parameter.
 *
 * If the prefix_string is an address without a mask, the
 * mask_length parameter may be passed as NULL.
 *
 * Returns 0 on success, -1 on failure.
 */
int dp_test_prefix_str_to_xfrm_addr(const char *prefix_str,
				    xfrm_address_t *address,
				    uint8_t *mask_length,
				    int family)
{
	char *addr_str, *plen_str, *copy;

	if (!address || !prefix_str)
		return -1;

	copy = strdup(prefix_str);
	if (!copy)
		return -1;

	plen_str = copy;

	addr_str = strsep(&plen_str, "/");
	if (!addr_str)
		goto error_ret;

	if (plen_str) {
		if (!mask_length)
			goto error_ret;
		*mask_length = (int)strtol(plen_str, NULL, 10);
	} else if (mask_length) {
		*mask_length = (family == AF_INET) ? 32 : 128;
	}

	memset(address, 0, sizeof(*address));
	if (inet_pton(family, addr_str, address) != 1)
		goto error_ret;

	free(copy);
	return 0;

error_ret:
	free(copy);
	return -1;
}

/*
 *
 * dp_test_setup_xfrm_usersa_info() ????
 */
int dp_test_setup_xfrm_usersa_info(struct xfrm_usersa_info *sa_info,
				   const char *dst,
				   const char *src,
				   uint32_t spi, /* Network byte order */
				   uint16_t family,
				   uint8_t mode,
				   uint32_t reqid,
				   uint32_t flags)
{
	xfrm_address_t daddr;
	xfrm_address_t saddr;

	if (dp_test_prefix_str_to_xfrm_addr(dst, &daddr, NULL, family) != 0)
		return -1;

	if (dp_test_prefix_str_to_xfrm_addr(src, &saddr, NULL, family) != 0)
		return -1;

	memset(sa_info, 0, sizeof(*sa_info));
	sa_info->family = family;
	sa_info->mode = mode;
	memcpy(&sa_info->saddr, &saddr, sizeof(sa_info->saddr));
	memcpy(&sa_info->id.daddr, &daddr, sizeof(sa_info->id.daddr));
	sa_info->id.spi = spi;
	sa_info->reqid = reqid;
	sa_info->flags = flags;

	return 0;
}

struct rte_mbuf *build_input_packet(const char *src_ip_addr,
				    const char *dst_ip_addr)
{
	struct iphdr *ip;
	struct rte_mbuf *packet;
	const uint8_t payload[] = {
		0x2c, 0x57, 0xba, 0x55, 0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02,
		0x03, 0x04, 0x01, 0x02, 0x03, 0x04
	};
	int payload_len = sizeof(payload);

	packet  = dp_test_create_icmp_ipv4_pak(src_ip_addr, dst_ip_addr,
					       ICMP_ECHO /* echo request */,
					       0 /* no code */,
					       DPT_ICMP_ECHO_DATA(0xac9, 1),
					       1 /* one mbuf */,
					       &payload_len,
					       payload,
					       &ip, NULL);
	if (!packet)
		return NULL;

	/*
	 * The resulting ICMP packet isn't exactly as
	 * we want, so tickle a few bits into shape
	 */
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_IP_ID, 0xea53);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	return packet;
}

struct rte_mbuf *build_input_packet6(const char *src_ip_addr,
				     const char *dst_ip_addr)
{
	struct ip6_hdr *ip6;
	struct icmp6_hdr *icmp6;
	struct rte_mbuf *packet;
	const uint8_t payload6[] = {
		0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
		0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
	};
	int payload_len6 = sizeof(payload6);

	packet  = dp_test_create_icmp_ipv6_pak(src_ip_addr, dst_ip_addr,
					       ICMP6_ECHO_REQUEST,
					       0 /* no code */,
					       DPT_ICMP6_ECHO_DATA(0, 0),
					       1 /* one mbuf */,
					       &payload_len6,
					       payload6,
					       &ip6, &icmp6);
	if (!packet)
		return NULL;

	/*
	 * The resulting ICMP ping packet isn't exactly as
	 * we want, so tickle a few bits into shape
	 */
	ip6->ip6_flow |= 0x69a80300;
	ip6->ip6_hlim = 64;
	icmp6->icmp6_id = 0x620d;
	icmp6->icmp6_seq = 0x0100;
	icmp6->icmp6_cksum = 0x4e96;

	return packet;
}

void dp_test_validate_if_stats(struct if_data *stats,
			       struct if_data *exp_stats)
{
	dp_test_assert_internal(stats->ifi_ipackets ==
			exp_stats->ifi_ipackets);
	dp_test_assert_internal(stats->ifi_ierrors  ==
			exp_stats->ifi_ierrors);
	dp_test_assert_internal(stats->ifi_opackets ==
			exp_stats->ifi_opackets);
	dp_test_assert_internal(stats->ifi_oerrors  ==
			exp_stats->ifi_oerrors);
	dp_test_assert_internal(stats->ifi_idropped ==
			exp_stats->ifi_idropped);
	dp_test_assert_internal(ifi_odropped(stats) ==
			ifi_odropped(exp_stats));
}

void dp_test_verify_vrf_stats(int inp, int inp2, int dis, int dis2,
			      int del, int del2, int exp_status)
{
	dp_test_assert_internal(inp + 1 == inp2);
	if (exp_status == DP_TEST_FWD_DROPPED) {
		dp_test_assert_internal(dis + 1 == dis2);
		dp_test_assert_internal(del == del2);
	} else {
		dp_test_assert_internal(dis == dis2);
		dp_test_assert_internal(del + 1 == del2);
	}

}
