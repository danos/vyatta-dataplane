/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 *
 * Whole dataplane SIP ALG test library
 */

#ifndef __DP_TEST_NPF_ALG_SIP_LIB_H__
#define __DP_TEST_NPF_ALG_SIP_LIB_H__

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_npf_alg_sip_parse.h"


/*
 * Example debug:
 *
 * START_TEST: sip3, dnat
 * Initial call
 *   [1] INVITE       Forw, tgt=100.101.102.2, trans=200.201.202.203
 *   [2] 180 RINGING  Back, tgt=100.101.102.2, trans=200.201.202.203
 *   [3] 200 OK       Back, tgt=100.101.102.2, trans=200.201.202.203
 *   [4] ACK          Forw, tgt=100.101.102.2, trans=200.201.202.203
 *   [5] BYE          Back, tgt=100.101.102.2, trans=200.201.202.203
 *   [-] RTP          Forw, sport=10000, dport=60000
 *   [-] RTP          Back, sport=60000, dport=10000
 *   [6] 200 OK       Forw, tgt=100.101.102.2, trans=200.201.202.203
 */
#define DP_TEST_SIP_DEBUG 0

/*
 * Example debug when DP_TEST_SIP_DEBUG_DETAIL is enabled
 *
 * [2] 180 RINGING    Back, tgt=100.101.102.2, trans=200.201.202.203
 *     SIP:
 *       "SIP/2.0 180 Ringing"
 *       "Via: SIP/2.0/UDP 100.101.102.103:5060;branch=z9hG4bKfw19b"
 *       "From: Nikola Tesla <sip:n.tesla@high-voltage.org>;tag=76341"
 *       "To: G. Marconi <sip:marconi@radio.org>;tag=a53e42"
 *       "Call-ID: j2qu348ek2328ws"
 *       "CSeq: 1 INVITE"
 *       "Contact: <sip:marconi@200.201.202.203>"
 *       "Content-Length: 0"
 *      ""
 */
#define DP_TEST_SIP_DEBUG_DETAIL 0


/*
 * Forward references
 */
struct sip_alg_request;

/*
 * Validate helper callback context for SIP packets
 */
struct dp_test_alg_sip_ctx {
	char			file[50];
	int			line;
	struct dp_test_nat_ctx	*nat;

	/* Parsed SIP and SDP message from packet before translation */
	struct sip_alg_request	*orig_sr;

	/* Original dp_test validate callback */
	validate_cb		saved_cb;
};


struct sip_alg_request *
dp_test_sip_alg_parse(struct rte_mbuf *nbuf, bool verify_sip, char *err,
		      int len);

void
dp_test_sip_alg_request_free(struct sip_alg_request *sr);

void
_dp_test_alg_sip_set_validation(struct dp_test_alg_sip_ctx *ctx,
				struct rte_mbuf *test_pak,
				struct rte_mbuf *trans_pak,
				struct dp_test_expected *test_exp,
				const char *file, int line);

#define dp_test_alg_sip_set_validation(ctx, test_pak, trans_pak, test_exp) \
	_dp_test_alg_sip_set_validation(ctx, test_pak, trans_pak, test_exp, \
					__FILE__, __LINE__)

/*
 * Creates a test packet from a packet descriptor and a SIP payload string.
 */
struct rte_mbuf *
dp_test_npf_alg_sip_pak(struct dp_test_pkt_desc_t *pkt, const char *payload);

void
dp_test_npf_sip_debug(const char *fmt, ...);

#endif /* __DP_TEST_NPF_ALG_SIP_LIB_H__ */
