/*
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A library of useful functions for writing dataplane tests.
 */

#ifndef _DP_TEST_LIB_TCP_H_
#define _DP_TEST_LIB_TCP_H_

#include <assert.h>
#include <stdbool.h>

#include "if_var.h"
#include "dp_test_pktmbuf_lib.h"

/*
 * dp_test_tcp_flag2str
 *
 * Returns a flags string from TCP flags.  Uses a static buffer, so string
 * should be used immediately.  If no flags are set then "0" is returned.
 */
#define DPT_TCP_FLAG_DELIM_COMMA	", "
#define DPT_TCP_FLAG_DELIM_OR		"|"

char *dp_test_tcp_flag2str(uint8_t flags, const char *delim);

/*
 * Provides a mechanism to automatically generate a TCP call, i.e. a forwards
 * and backwards flow of packets, with use specified TCP flags and automatic
 * update of seq and ack.
 */

enum dp_test_tcp_dir {
	DP_DIR_BACK,
	DP_DIR_FORW
};

#define DP_DIR_REVERSE(x) (x == DP_DIR_FORW ? DP_DIR_BACK : DP_DIR_FORW)

struct dp_test_tcp_flow_pkt {
	enum dp_test_tcp_dir	dir;
	uint8_t			flags;
	uint			dlen;
	char                   *data;
};

struct dp_test_tcp_desc {
	struct dp_test_pkt_desc_t	*pre;
	struct dp_test_pkt_desc_t	*post;
};

#define DP_TEST_TCP_CALL_DESC_LEN 120

/*
 * A TCP call comprises on a number of one or more packets in one or two
 * directions.
 */
struct dp_test_tcp_call {
	char str[DP_TEST_TCP_CALL_DESC_LEN];

	/* Packet descriptors for forw and back pkts */
	struct dp_test_tcp_desc desc[2];

	/* Initial sequence number */
	uint32_t isn[2];

	/* seq and ack; start at zero */
	uint32_t seq[2];
	uint32_t ack[2];

	void (*test_cb)(const char *desc,
			uint, enum dp_test_tcp_dir,
			uint8_t,
			struct dp_test_pkt_desc_t *,
			struct dp_test_pkt_desc_t *,
			void *, uint);
	void (*post_cb)(uint, enum dp_test_tcp_dir, uint8_t,
			struct dp_test_pkt_desc_t *,
			struct dp_test_pkt_desc_t *,
			const char *);
};

/*
 * Example / template:
 *
 *	struct dp_test_tcp_call tcp_call = {
 *		.str[0] = '\0',
 *		.initial_seq = 0,
 *		.desc[DP_DIR_FORW] = {
 *			.pre = &ins_pre,
 *			.post = &ins_post,
 *		},
 *		.desc[DP_DIR_BACK] = {
 *			.pre = &outs_pre,
 *			.post = &outs_post,
 *		},
 *		.test_cb = NULL,
 *		.post_cb = NULL,
 *	};
 *
 *	spush(tcp_call.desc, sizeof(tcp_call.desc), "npf TCP strict Test 1");
 *
 *	struct dp_test_tcp_flow_pkt tcp_pkt[] = {
 *		// 3-way setup handshake
 *		{DP_DIR_FORW, TH_SYN, 0},
 *		{DP_DIR_BACK, TH_SYN | TH_ACK, 0},
 *		{DP_DIR_FORW, TH_ACK, 0},
 *		// Data transfer
 *		{DP_DIR_FORW, TH_ACK, 40},
 *		{DP_DIR_BACK, TH_ACK, 100},
 *		{DP_DIR_FORW, TH_ACK, 30},
 *		// 4-way termination handshake
 *		{DP_DIR_FORW, TH_FIN},
 *		{DP_DIR_BACK, TH_ACK, 0},
 *		{DP_DIR_BACK, TH_FIN, 0},
 *		{DP_DIR_FORW, TH_ACK, 0},
 *	};
 *
 *	dp_test_tcp_call(&tcp_call, tcp_pkt, ARRAY_SIZE(tcp_pkt));
 */
void
dp_test_tcp_call(struct dp_test_tcp_call *call,
		 struct dp_test_tcp_flow_pkt *df_array,
		 size_t df_array_size,
		 void *ctx_ptr, uint ctx_uint);

/*
 * Write TCP payload, and re-calc checksums
 */
void dp_test_tcp_write_payload(struct rte_mbuf *m, uint plen,
			       const char *payload);

#endif /* _DP_TEST_LIB_TCP_H_ */
