/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _DP_TEST_GRE_H_
#define _DP_TEST_GRE_H_

void dp_test_gre_setup_tunnel(uint32_t vrfid, const char *tun_src,
			      const char *tun_dst);
void dp_test_gre_teardown_tunnel(uint32_t vrfid, const char *tun_src,
				 const char *tun_dst);

void gre_test_build_expected_pak(struct dp_test_expected **expected,
				 struct iphdr *payload[],
				 struct iphdr *outer[],
				 int num_paks);

void dp_test_gre6_setup_tunnel(uint32_t vrfid, const char *tun_src,
			       const char *tun_dst);
void dp_test_gre6_teardown_tunnel(uint32_t vrfid, const char *tun_src,
				  const char *tun_dst);

void gre6_test_build_expected_pak(struct dp_test_expected **expected,
				  struct ip6_hdr *payload,
				  struct ip6_hdr *outer);

#endif /* DP_TEST_GRE_H */
