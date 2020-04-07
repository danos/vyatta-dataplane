/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
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
#include "dp_test_pktmbuf_lib_internal.h"

/*
 * dp_test_tcp_flag2str
 *
 * Returns a flags string from TCP flags.  Uses a static buffer, so string
 * should be used immediately.  If no flags are set then "0" is returned.
 */
#define DPT_TCP_FLAG_DELIM_COMMA	", "
#define DPT_TCP_FLAG_DELIM_OR		"|"

char *dp_test_tcp_flag2str(uint8_t flags, const char *delim);


/***************************************************************************
 * TCP Flow Testing
 **************************************************************************/

/*
 * Provides a mechanism to automatically generate a TCP call, i.e. a forwards
 * and backwards flow of packets, with use specified TCP flags and automatic
 * update of seq and ack.
 */

#define DPT_FORW	true
#define DPT_BACK	false

/*
 * TCP flow pkt flags and data
 *
 * data pointers are pointers to arrays or strings.  If an array, then a dlen
 * must be specified.  If a string, then dlen may be specified.  If not specd,
 * then dpt_tcp_pak_receive will calculate it.
 *
 * If pst_data is NULL then the pre_data is used.  Typically only ALG tests
 * might use pst_data.
 */
struct dpt_tcp_flow_pkt {
	bool		forw;		/* true for forw, false for back */
	uint8_t		flags;		/* TCP flags */
	uint		pre_dlen;
	char		*pre_data;	/* Pre data */
	uint		pst_dlen;
	char		*pst_data;	/* Post data */
};

#define DPT_TCP_CALL_TEXT_LEN 120

/*
 * TCP flow pkt descriptors
 */
struct dpt_tcp_flow_pkt_desc {
	struct dp_test_pkt_desc_t *pre;
	struct dp_test_pkt_desc_t *pst;
};

/*
 * TCP flow.
 *
 * Keeps track of seq and ack numbers, and adds them to the test packets.
 */
struct dpt_tcp_flow {
	char	text[DPT_TCP_CALL_TEXT_LEN];

	/* Forw and back, pre and post pkt descriptors */
	struct dpt_tcp_flow_pkt_desc desc[2];

	/* Initial sequence number */
	uint32_t	isn[2];

	/* seq and ack; start at zero */
	uint32_t	seq[2];
	uint32_t	ack[2];

	void (*test_cb)(const char *desc,
			uint pktno, bool forw,
			uint8_t flags,
			struct dp_test_pkt_desc_t *pre,
			struct dp_test_pkt_desc_t *post,
			void *data, uint index);
	void (*post_cb)(uint pktno, bool forw, uint8_t flags,
			struct dp_test_pkt_desc_t *pre,
			struct dp_test_pkt_desc_t *post,
			const char *desc);
};

struct dp_test_pkt_desc_t *dpt_pdesc_v4_create(const char *text,
					       uint8_t proto,
					       const char *l2_src,
					       const char *l3_src,
					       uint16_t sport,
					       const char *l2_dst,
					       const char *l3_dst,
					       uint16_t dport,
					       const char *rx_intf,
					       const char *tx_intf);

struct dp_test_pkt_desc_t *dpt_pdesc_v6_create(const char *text,
					       uint8_t proto,
					       const char *l2_src,
					       const char *l3_src,
					       uint16_t sport,
					       const char *l2_dst,
					       const char *l3_dst,
					       uint16_t dport,
					       const char *rx_intf,
					       const char *tx_intf);

/*
 * TCP call
 *
 * call      Packet descriptors for forw and back packets
 * df_array  Array of direction, flags and pkt size tuples,
 *           one for each packet to be sent
 * df_array_size
 * first     Index of first pkt in df_array
 * last      Index of last pkt in df_array (if > 0 and < df_array_size)
 * ctx_ptr   Pointer context to pass to test_cb
 * ctx_uint  Uint context to pass to test_cb
 */
void dpt_tcp_call(struct dpt_tcp_flow *call, struct dpt_tcp_flow_pkt *df_array,
		  size_t df_array_size, uint first, uint last,
		  void *ctx_ptr, uint ctx_uint);

#endif /* _DP_TEST_LIB_TCP_H_ */
