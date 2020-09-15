/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 *
 * SIP call
 */

#ifndef __DP_TEST_NPF_ALG_SIP_CALL_H__
#define __DP_TEST_NPF_ALG_SIP_CALL_H__

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_npf_nat_lib.h"


/*
 * Packet direction relative to the initial SIP INVITE request
 */
enum dp_test_sip_dir {
	DP_TEST_SIP_DIR_FORW,
	DP_TEST_SIP_DIR_BACK
};

enum dp_test_sip_loc {
	DP_TEST_SIP_LOC_DIRECT,		/* No proxy's */
	DP_TEST_SIP_LOC_PRE_PROXY,	/* uut is before proxy */
	DP_TEST_SIP_LOC_POST_PROXY	/* uut is after proxy */
};

struct dp_test_sip_pkt_t {
	const char		*descr;	/* description */
	enum dp_test_sip_dir	dir;	/* direction */
	enum dp_test_sip_loc	loc;	/* location of uut */
	bool			media;	/* Precede with media cb */
	const char		*msg;	/* SIP message */
	/* Pointers to store alloc'd copies of msg */
	char			*msg_pre;
	char			*msg_post;
};

/*
 * A wrapper around _dp_test_pak_receive that sets up the pre and post process
 * packets and expectation.
 *
 * If NAT is taking place, then setup the validation callback, else just parse
 * the SIP payloads to check for correctness.
 */
void
_dp_test_npf_sip_pak_receive(uint seq, const char *descr,
			     struct dp_test_pkt_desc_t *pre,
			     const char *pre_payload,
			     struct dp_test_pkt_desc_t *post,
			     const char *post_payload,
			     enum dp_test_sip_dir sdir,
			     enum dp_test_nat_dir ndir,
			     enum dp_test_trans_type ttype,
			     bool verify_session,
			     const char *file, int line);

#define dp_test_npf_sip_pak_receive(seq, descr, pre, prep, post, postp, \
				    sdir, ndir, ttype, vs)		\
	_dp_test_npf_sip_pak_receive(seq, descr, pre, prep, post, postp, \
				     sdir, ndir, ttype, vs,		\
				     __FILE__, __LINE__)

struct dp_test_sip_media_ctx {
	enum dp_test_trans_type ttype;
	bool send_rtp;
	bool initial_rtp_forw;
	bool send_rtcp;
	bool initial_rtcp_forw;
	uint16_t rtp_sport;
	uint16_t rtp_dport;
	uint16_t rtcp_sport;
	uint16_t rtcp_dport;
	struct dp_test_pkt_desc_t *ins_pre;
	struct dp_test_pkt_desc_t *ins_post;
	struct dp_test_pkt_desc_t  *outs_pre;
	struct dp_test_pkt_desc_t  *outs_post;
};

/*
 * Duplicate msg in a SIP call array to msg_pre and msg_post.
 */
void
dp_test_npf_sip_call_dup(struct dp_test_sip_pkt_t *sip_call, uint nmsgs);

void
dp_test_npf_sip_call_free(struct dp_test_sip_pkt_t *sip_call, uint nmsgs);

/*
 * Change the FQDNs to IP addresses for inside hosts for all messages in a
 * call
 */
void
dp_test_sip_call_replace_ins_fqdn(struct dp_test_sip_pkt_t *sip_call,
				  uint sip_call_sz, bool snat,
				  const char *ins_fqdn, const char *ins_ip,
				  const char *tgt, const char *trans);

/*
 * Change the FQDNs to IP addresses for outside hosts for all messages in a
 * call
 */
void
dp_test_sip_call_replace_outs_fqdn(struct dp_test_sip_pkt_t *sip_call,
				   uint sip_call_sz, bool snat,
				   const char *outs_fqdn, const char *outs_ip,
				   const char *tgt, const char *trans);

void
dp_test_sip_pkt_via_replace_str(struct dp_test_sip_pkt_t *sip_pkt,
				const char *old, const char *new);

/*
 * Make a complete SIP call.
 *
 * sip_array	Array of SIP messages
 * sip_array_sz	Array size
 * first	Index of first pkt in sip_array
 * last		Index of last pkt in sip_array (if > 0 and < sip_array_size)
 * uut_loc	UUT location relative to the source UA, proxy, and dest UA
 * ins_pre	pre-NAT packet descriptor, inside to outside
 * ins_post	post-NAT packet descriptor, inside to outside
 * outs_pre	pre-NAT packet descriptor, outside to inside
 * outs_post	post-NAT packet descriptor, outside to inside
 * pre_adj_fn	Callback fn for adjusting pre-NAT SIP
 * post_adj_fn	Callback fn for adjusting post-NAT SIP
 * ttype	SNAT or DNAT
 */
void
_dpt_npf_sip_call(struct dp_test_sip_pkt_t *sip_call,
		  uint sip_call_sz,
		  uint first, uint last,
		  enum dp_test_sip_loc uut_loc,
		  struct dp_test_pkt_desc_t *ins_pre,
		  struct dp_test_pkt_desc_t *ins_post,
		  struct dp_test_pkt_desc_t *outs_pre,
		  struct dp_test_pkt_desc_t *outs_post,
		  enum dp_test_trans_type ttype,
		  uint vrfid,
		  const char *file, int line);

#define dpt_npf_sip_call(a, b, c, d, e, f, g, h, i, j, k)	\
	_dpt_npf_sip_call(a, b, c, d, e, f, g, h, i, j, k,	\
			  __FILE__, __LINE__)

#endif /* __DP_TEST_NPF_ALG_SIP_CALL_H__ */
