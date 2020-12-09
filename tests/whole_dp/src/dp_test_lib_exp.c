/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A library of useful functions for defining the expected
 * results from a forwarding test.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test/dp_test_macros.h"

/*
 * struct dp_test_ctx_free_rec
 *
 * This structure is used to track validate callback contexts
 * that need to be freed before the struct dp_test_expected
 * they are associated with is freed.
 */
struct dp_test_ctx_free_rec {
	struct dp_test_ctx_free_rec *next;
	void *ctx_to_free;
};

static struct dp_test_expected *
dp_test_exp_init(void)
{
	struct dp_test_expected *exp = calloc(1, sizeof(*exp));
	int i;

	assert(exp);

	exp->exp_num_paks = 0;
	exp->exp_pak_origin_next = 0;
	exp->cloned = false;
	exp->validate_ctx_free_list = NULL;

	for (i = 0; i < DP_TEST_MAX_EXPECTED_PAKS; i++) {
		exp->check_start[i] = 0;
		exp->check_len[i] = 0;
		exp->exp_pak[i] = NULL;
		exp->exp_pak_origin[i] = 0;
		exp->fwd_result[i] = DP_TEST_FWD_UNDEFINED;
		exp->oif_name[i] = NULL;
		exp->description[i] = '\0';
		exp->check_dont_care_cnt[i] = 0;
	}
	exp->fwd_result[0] = DP_TEST_FWD_FORWARDED;

	return exp;
}

/* Create or append a struct dp_test_expected, and return a pointer to it. */
static struct dp_test_expected *
dp_test_exp_internal(struct rte_mbuf *test_pak, unsigned int count,
		     bool create, struct dp_test_expected *current_exp)
{
	struct dp_test_expected *exp;
	unsigned int i, existing_num_paks;

	assert(count <= DP_TEST_MAX_EXPECTED_PAKS);

	if (create) {
		dp_test_assert_internal(current_exp == NULL);
		exp = dp_test_exp_init();
	} else {
		dp_test_assert_internal(current_exp != NULL);
		exp = current_exp;
	}
	existing_num_paks = exp->exp_num_paks;
	exp->exp_num_paks += count;

	for (i = existing_num_paks; i < existing_num_paks + count; i++) {
		if (test_pak)
			dp_test_exp_set_pak_m(exp, i,
					      dp_test_cp_pak(test_pak));
		exp->exp_pak_origin[i] = exp->exp_pak_origin_next;
		exp->fwd_result[i] = DP_TEST_FWD_FORWARDED;
	}
	exp->exp_pak_origin_next++;

	if (count > 1)
		exp->compare_pak_addr = false;

	return exp;
}

struct dp_test_expected *
dp_test_exp_create(struct rte_mbuf *test_pak)
{
	return dp_test_exp_internal(test_pak, 1, true, NULL);
}

struct dp_test_expected *
dp_test_exp_create_m(struct rte_mbuf *test_pak, int count)
{
	return dp_test_exp_internal(test_pak, count, true, NULL);
}

void
dp_test_exp_append_m(struct dp_test_expected *exp, struct rte_mbuf *test_pak,
		     int count)
{
	dp_test_exp_internal(test_pak, count, false, exp);
}

struct dp_test_expected *
dp_test_exp_create_with_packet(struct rte_mbuf *exp_pak)
{
	struct dp_test_expected *exp;

	exp = dp_test_exp_init();
	exp->exp_num_paks = 1;
	dp_test_exp_set_pak_m(exp, 0, exp_pak);

	return exp;
}
void
dp_test_exp_delete(struct dp_test_expected *exp)
{
	struct dp_test_ctx_free_rec *ctx_free_rec;
	int i;

	assert(exp);
	for (i = 0; i < DP_TEST_MAX_EXPECTED_PAKS; i++) {
		if (exp->exp_pak[i])
			rte_pktmbuf_free(exp->exp_pak[i]);
		if (exp->sent_pak[i]) {
			rte_pktmbuf_free(exp->sent_pak[i]);
			exp->sent_pak[i] = NULL;
		}
	}

	while ((ctx_free_rec = exp->validate_ctx_free_list)) {
		exp->validate_ctx_free_list = ctx_free_rec->next;
		free(ctx_free_rec->ctx_to_free);
		free(ctx_free_rec);
	}

	free(exp);
}

static void
dp_test_exp_set_check_len_m(struct dp_test_expected *exp, unsigned int packet,
			    uint32_t len)
{
	exp->check_len[packet] = len;
}

void
dp_test_exp_set_check_len(struct dp_test_expected *exp, uint32_t len)
{
	dp_test_exp_set_check_len_m(exp, 0, len);
}

static void
dp_test_exp_set_check_start_m(struct dp_test_expected *exp, unsigned int packet,
			      uint32_t start)
{
	exp->check_start[packet] = start;
}

void
dp_test_exp_set_check_start(struct dp_test_expected *exp, uint32_t start)
{
	dp_test_exp_set_check_start_m(exp, 0, start);
}

void
dp_test_exp_set_fwd_status(struct dp_test_expected *exp, int status)
{
	dp_test_exp_set_fwd_status_m(exp, 0, status);
}

void
dp_test_exp_set_fwd_status_m(struct dp_test_expected *exp,
			     unsigned int packet, int status)
{
	dp_test_assert_internal(packet < exp->exp_num_paks);
	exp->fwd_result[packet] = status;
}

void
dp_test_exp_set_oif_name(struct dp_test_expected *exp, const char *name)
{
	unsigned int i;

	dp_test_assert_internal(name != NULL);

	for (i = 0; i < exp->exp_num_paks; i++)
		exp->oif_name[i] = name;
}

void
dp_test_exp_set_oif_name_m(struct dp_test_expected *exp,
			   unsigned int packet, const char *name)
{
	dp_test_assert_internal(packet < exp->exp_num_paks);
	exp->oif_name[packet] = name;
}

void
dp_test_exp_set_vlan_tci(struct dp_test_expected *exp, uint16_t vlan)
{
	unsigned int i;

	for (i = 0; i < exp->exp_num_paks; i++)
		exp->exp_pak[i]->vlan_tci = vlan;
}

void
dp_test_exp_set_vlan_tci_m(struct dp_test_expected *exp,
			   unsigned int packet, uint16_t vlan)
{
	dp_test_assert_internal(packet < exp->exp_num_paks);
	exp->exp_pak[packet]->vlan_tci = vlan;
}

void
dp_test_exp_set_cloned(struct dp_test_expected *exp, bool cloned)
{
	exp->cloned = cloned;
}

struct rte_mbuf *
dp_test_exp_get_sent(struct dp_test_expected *exp, unsigned int packet)
{
	dp_test_assert_internal(packet < exp->exp_num_paks);
	return exp->sent_pak[exp->exp_pak_origin[packet]];
}

void
dp_test_exp_set_sent(struct dp_test_expected *exp, unsigned int packet,
		     struct rte_mbuf *sent)
{
	dp_test_assert_internal(packet < exp->exp_num_paks);
	exp->sent_pak[exp->exp_pak_origin[packet]] = sent;
}

struct rte_mbuf *
dp_test_exp_get_pak(struct dp_test_expected *exp)
{
	return dp_test_exp_get_pak_m(exp, 0);
}

struct rte_mbuf *
dp_test_exp_get_pak_m(struct dp_test_expected *exp, unsigned int packet)
{
	dp_test_assert_internal(packet < exp->exp_num_paks);
	return exp->exp_pak[packet];
}

void
dp_test_exp_set_pak_m(struct dp_test_expected *exp, unsigned int packet,
		      struct rte_mbuf *m)
{
	dp_test_assert_internal(packet < exp->exp_num_paks);
	if (exp->exp_pak[packet])
		rte_pktmbuf_free(exp->exp_pak[packet]);
	exp->exp_pak[packet] = m;
	/*
	 * set to largest packet size, assuming that packet checking
	 * code limits the actual size it checks to that of the
	 * expected packet
	 */
	if (exp->check_len[packet] < rte_pktmbuf_pkt_len(m))
		exp->check_len[packet] = rte_pktmbuf_pkt_len(m);
}

validate_cb
dp_test_exp_get_validate_cb(struct dp_test_expected *exp)
{
	if (exp->validate_cb)
		return exp->validate_cb;

	return dp_test_pak_verify;
}

validate_cb
dp_test_exp_set_validate_cb(struct dp_test_expected *exp,
			    validate_cb new_cb)
{
	validate_cb old_cb = exp->validate_cb;

	exp->validate_cb = new_cb;

	/* return whatever would have been called */
	return old_cb ? old_cb : dp_test_pak_verify;
}

void *
dp_test_exp_get_validate_ctx(struct dp_test_expected *exp)
{
	return exp->validate_ctx;
}

void *
dp_test_exp_set_validate_ctx(struct dp_test_expected *exp, void *new_ctx,
			     bool auto_free)
{
	void *old_ctx = exp->validate_ctx;
	struct dp_test_ctx_free_rec *rec;

	if (auto_free && new_ctx) {
		rec = malloc(sizeof(*rec));
		dp_test_assert_internal(rec);
		rec->ctx_to_free = new_ctx;
		rec->next = exp->validate_ctx_free_list;
		exp->validate_ctx_free_list = rec;
	}

	exp->validate_ctx = new_ctx;
	return old_ctx;
}

/*
 * Allow ranges of bytes to be excluded, when checking the packet transmitted
 * by the dataplane.
 *
 * start: ptr to beginning of dont care range
 * len: bytes to not check starting from start
 *
 * ----------------------------------------------
 * | headroom    | pak data [   dont care   ]   |
 * | ..data_off..|          ....range_len....   |
 * | ......range_start.......                   |
 * ----------------------------------------------
 * ^                        ^
 * buf_addr                 start
 */
void
dp_test_exp_set_dont_care(struct dp_test_expected *exp, unsigned int pak_i,
			  const uint8_t *start, uint32_t len)
{
	struct dp_test_dont_care_range *range;
	struct rte_mbuf *exp_pak;

	dp_test_assert_internal(exp->check_dont_care_cnt[pak_i]
				< DP_TEST_MAX_DONT_CARE);

	exp_pak = exp->exp_pak[pak_i];
	range = &exp->check_dont_care[pak_i][exp->check_dont_care_cnt[pak_i]];

	/* Use buf_addr, will not change even on pak prepend */
	range->range_start = start - (uint8_t *)exp_pak->buf_addr;
	range->range_len = len;

	exp->check_dont_care_cnt[pak_i]++;
}

/* Return true if we care about the value of byte at offset */
bool
dp_test_exp_care(struct dp_test_expected *exp, unsigned int pak_i, unsigned int offset)
{
	struct dp_test_dont_care_range *range;
	uint32_t range_start, range_end; /* Bytes into packet */
	struct rte_mbuf *exp_pak;
	uint32_t i, check_start;

	exp_pak = exp->exp_pak[pak_i];

	check_start = exp->check_start[pak_i];

	for (i = 0; i < exp->check_dont_care_cnt[pak_i]; i++) {
		range = &exp->check_dont_care[pak_i][i];
		dp_test_assert_internal(range->range_start >
					exp_pak->data_off -
					check_start);
		range_start = range->range_start - exp_pak->data_off -
			check_start;
		range_end = range_start + range->range_len;
		if (offset >= range_start && offset < range_end)
			return false;
	}
	return true;
}
