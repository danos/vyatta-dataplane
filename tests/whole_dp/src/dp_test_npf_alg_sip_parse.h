/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 *
 * SIP packet parsing
 */

#ifndef __DP_TEST_NPF_ALG_SIP_PARSE_H__
#define __DP_TEST_NPF_ALG_SIP_PARSE_H__

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test/dp_test_macros.h"


/*
 * SIP Requests
 */
enum dp_test_sip_req {
	DP_TEST_SIP_REQ_INVITE = 1,
	DP_TEST_SIP_REQ_ACK,
	DP_TEST_SIP_REQ_BYE,
	DP_TEST_SIP_REQ_CANCEL,
	DP_TEST_SIP_REQ_OPTIONS,
	DP_TEST_SIP_REQ_REGISTER,
	DP_TEST_SIP_REQ_PRACK,
	DP_TEST_SIP_REQ_SUBSCRIBE,
	DP_TEST_SIP_REQ_NOTIFY,
	DP_TEST_SIP_REQ_PUBLISH,
	DP_TEST_SIP_REQ_INFO,
	DP_TEST_SIP_REQ_REFER,
	DP_TEST_SIP_REQ_MESSAGE,
	DP_TEST_SIP_REQ_UPDATE
};

#define DP_TEST_SIP_REQ_FIRST DP_TEST_SIP_REQ_INVITE
#define DP_TEST_SIP_REQ_LAST  DP_TEST_SIP_REQ_UPDATE
#define DP_TEST_SIP_REQ_SIZE  (DP_TEST_SIP_REQ_LAST + 1)


/*
 * SIP Responses
 *
 * 1xx - Provisional responses
 * 2xx - Successful responses
 * 3xx - Redirection responses
 * 4xx - Client failure responses
 * 5xx - Server failure responses
 * 6xx - Global failure responses
 */
enum dp_test_sip_resp {
	DP_TEST_SIP_RESP_PROV = 1,	/* Provisional */
	DP_TEST_SIP_RESP_SUCCESS,
	DP_TEST_SIP_RESP_REDIR,
	DP_TEST_SIP_RESP_CNT_FAIL,	/* Client failure */
	DP_TEST_SIP_RESP_SVR_FAIL,	/* Server failure */
	DP_TEST_SIP_RESP_GBL_FAIL,	/* Global failure */
};

#define DP_TEST_SIP_RESP_FIRST DP_TEST_SIP_RESP_PROV
#define DP_TEST_SIP_RESP_LAST  DP_TEST_SIP_RESP_GBL_FAIL


/*
 * Returns the SIP request enum value if this is a SIP request, else returns 0
 */
enum dp_test_sip_req
dp_test_npf_sip_msg_req(const char *msg);

/* Is this a SIP request? */
bool
dp_test_npf_sip_msg_is_req(const char *msg);

/*
 * Replace a string, free old string, assign new string to pointer
 */
void
dp_test_npf_sip_replace_ptr(char **strp, const char *needle,
			    const char *replacement);

void
dp_test_sip_replace_ins_fqdn(char **msgp, bool snat, bool forw,
			     const char *ins_fqdn, const char *ins_ip,
			     const char *tgt, const char *trans);

void
dp_test_sip_replace_outs_fqdn(char **msgp, bool snat, bool forw,
			      const char *outs_fqdn, const char *outs_ip,
			      const char *tgt, const char *trans);

/*
 * Replace a string within all Via parts of a SIP message.
 */
void
dp_test_sip_via_replace_str(char **msgp, const char *needle,
			    const char *replacement);

/*
 * Return a pointer to the start of the SDP part of a SIP message
 */
const char *
dp_test_npf_sip_get_sdp(const char *sip);

/*
 * Calculate the length of the SDP part of a SIP message
 */
uint
dp_test_npf_sip_calc_content_length(const char *sip);

/*
 * Get the content-length value from a SIP message string.  Sets the length in
 * the *clen parameter, and returns a pointer to the start of the number in
 * the message.
 */
char *
dp_test_npf_sip_get_content_length(const char *sip, uint *clen);

/*
 * Sets the content length value in a SIP message.  Returns a new string if
 * successful.
 */
char *
dp_test_npf_sip_set_content_length(const char *sip, uint clen);

/*
 * Calculate content-length, malloc new message, set content-length, and free
 * old message.  Assumes the message passed in is malloc's memory.
 */
char *
dp_test_npf_sip_reset_content_length(char *sip);

/*
 * Split a SIP message into its constituent parts.  Returns a pointer to an
 * array of strings, each string being a SIP message part with the '\r\n'
 * delimiter removed.
 */
char **
dp_test_npf_sip_split(const char *sip, int *countp);

/*
 * Free an array previously created by dp_test_npf_sip_split
 */
void
dp_test_npf_sip_split_free(char **arr, int count);

/*
 * Combine a strings array (e.g. created by dp_test_npf_sip_split) into a SIP
 * message
 */
char *
dp_test_npf_sip_combine(char **arr, int count);

#endif /* __DP_TEST_NPF_ALG_SIP_PARSE_H__ */
