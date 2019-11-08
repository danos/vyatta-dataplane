/*-
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A library of useful functions for defining the expected
 * results from a forwarding test.
 */
#ifndef _DP_TEST_LIB_EXP_H_
#define _DP_TEST_LIB_EXP_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


#include "dp_test_lib.h"
#include "dp_test_lib_intf.h"

#define DP_TEST_MAX_EXPECTED_PAKS 10
#define DP_TEST_MAX_DONT_CARE 10 /* Number of dont care ranges */

struct dp_test_ctx_free_rec;

/*
 * The expected test result.
 *
 * Don't include any internal dataplane structures in here i.e. ifnet ifp.
 * We don't want to verify our tests by looking at internal dataplane
 * information, which might be incorrect if we have a dataplane bug.
 */
struct dp_test_dont_care_range {
	uint32_t range_start; /* Offset from m->buf_addr */
	uint32_t range_len; /* Byte count */
};

struct dp_test_expected {
	unsigned int exp_num_paks;
	struct rte_mbuf *exp_pak[DP_TEST_MAX_EXPECTED_PAKS];
	/* Packet number of rx pak, that causes the exp tx pak */
	uint32_t exp_pak_origin[DP_TEST_MAX_EXPECTED_PAKS];
	uint32_t exp_pak_origin_next;
	/* Address of the packet being processed */
	intptr_t pak_addr[DP_TEST_MAX_EXPECTED_PAKS];
	 /* Copy of original sent pack */
	struct rte_mbuf *sent_pak[DP_TEST_MAX_EXPECTED_PAKS];
	/*  Compare the addresses of send/received paks */
	bool compare_pak_addr;
	/* The array index of the last packet we checked */
	unsigned int last_checked;
	/* Length of packet to check */
	uint32_t check_len[DP_TEST_MAX_EXPECTED_PAKS];
	 /* Offset from start of packet to check from */
	uint32_t check_start[DP_TEST_MAX_EXPECTED_PAKS];
	/* Range of bytes we dont want to check */
	struct dp_test_dont_care_range
		check_dont_care[DP_TEST_MAX_EXPECTED_PAKS]
			[DP_TEST_MAX_DONT_CARE];
	uint32_t check_dont_care_cnt[DP_TEST_MAX_EXPECTED_PAKS];
	 /* Did packet arrive on Tx ring, or shadow */
	bool pak_checked[DP_TEST_MAX_EXPECTED_PAKS];
	/* Was the packet that arrived on Tx ring correct */
	bool pak_correct[DP_TEST_MAX_EXPECTED_PAKS];
	 /* forwarding result */
	enum dp_test_fwd_result_e fwd_result[DP_TEST_MAX_EXPECTED_PAKS];
	 /* Output Interface Name */
	const char *oif_name[DP_TEST_MAX_EXPECTED_PAKS];
	/* Space to let us build the real name */
	char real_oif_name[DP_TEST_MAX_EXPECTED_PAKS][IFNAMSIZ];
	/* Vlan tci stored in the mbuf not in the packet data */
	uint16_t vlan_tci[DP_TEST_MAX_EXPECTED_PAKS];
	/* Do we expect the packet to be cloned ? */
	bool cloned;
	const char *func; /* name of the test function */
	const char *file; /* name of the test file     */
	int line;         /* line of the test file     */
	char description[1000];
	/* A function that will validate received packets */
	validate_cb validate_cb;
	void *validate_ctx; /* context for validation function */
	/* List of contexts to be freed when this structure is freed */
	struct dp_test_ctx_free_rec *validate_ctx_free_list;
};

void
dp_test_exp_set_dont_care(struct dp_test_expected *exp, unsigned int check,
			  uint8_t *start, uint32_t len);

bool
dp_test_exp_care(struct dp_test_expected *exp, unsigned int check, unsigned int offset);

#endif /* _DP_TEST_LIB_EXP_H_ */
