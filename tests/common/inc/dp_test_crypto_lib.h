/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef _DP_TEST_CRYPTO_LIB_H_
#define _DP_TEST_CRYPTO_LIB_H_

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <linux/xfrm.h>
#include "../tests/whole_dp/src/dp_test_lib.h"

/*
 * A virtual feature point interface can be bound
 * to a s2s tunnel if features, eg. NAT, firewall, are required.
 */
enum vfp_presence {
	VFP_FALSE,
	VFP_TRUE
};

enum inner_validity {
	INNER_VALID,
	INNER_INVALID,
	INNER_LOCAL,
};

enum vrf_and_xfrm_order {
	VRF_XFRM_IN_ORDER,
	VRF_XFRM_OUT_OF_ORDER,
};

int dp_test_prefix_str_to_xfrm_addr(const char *prefix_str,
				    xfrm_address_t *address,
				    uint8_t *mask_length,
				    int family);

int dp_test_setup_xfrm_usersa_info(struct xfrm_usersa_info *sa_info,
				   const char *dst,
				   const char *src,
				   uint32_t spi, /* Network byte order */
				   uint16_t family,
				   uint8_t mode,
				   uint32_t reqid,
				   uint32_t flags);

struct rte_mbuf *build_input_packet(const char *src_ip_addr,
				    const char *dst_ip_addr);

struct rte_mbuf *build_input_packet6(const char *src_ip_addr,
				     const char *dst_ip_addr);

void dp_test_validate_if_stats(struct if_data *stats,
			       struct if_data *exp_stats);

void dp_test_verify_vrf_stats(int inp, int inp2, int dis, int dis2,
			      int del, int del2, int exp_status);


#endif /* _DP_TEST_CRYPTO_LIB_H_ */
