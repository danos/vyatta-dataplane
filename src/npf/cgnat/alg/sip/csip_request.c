/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <values.h>
#include <rte_mbuf.h>
#include "util.h"

#include "npf/bstr.h"
#include "npf/cgnat/alg/alg.h"
#include "npf/cgnat/alg/alg_rc.h"
#include "npf/cgnat/alg/sip/csip_defs.h"
#include "npf/cgnat/alg/sip/csip_parse_utils.h"
#include "npf/cgnat/alg/sip/csip_request.h"

/* Min length of strings we expect to find in SIP headers */
#define SIP_REQ_STARTLINE_MIN	((long)sizeof("ACK sip:a.bc SIP2/0") - 1)

/*
 * SIP Request names.  This is the first thing in a SIP request msg start
 * line.
 */
static const struct bstr csip_req_methods[] = {
	[SIP_REQ_NONE]		= BSTR_K("-"),
	[SIP_REQ_INVITE]	= BSTR_K("INVITE"),
	[SIP_REQ_ACK]		= BSTR_K("ACK"),
	[SIP_REQ_BYE]		= BSTR_K("BYE"),
	[SIP_REQ_CANCEL]	= BSTR_K("CANCEL"),
	[SIP_REQ_REGISTER]	= BSTR_K("REGISTER"),
	[SIP_REQ_OPTIONS]	= BSTR_K("OPTIONS"),
	[SIP_REQ_PRACK]		= BSTR_K("PRACK"),
	[SIP_REQ_SUBSCRIBE]	= BSTR_K("SUBSCRIBE"),
	[SIP_REQ_NOTIFY]	= BSTR_K("NOTIFY"),
	[SIP_REQ_PUBLISH]	= BSTR_K("PUBLISH"),
	[SIP_REQ_INFO]		= BSTR_K("INFO"),
	[SIP_REQ_REFER]		= BSTR_K("REFER"),
	[SIP_REQ_MESSAGE]	= BSTR_K("MESSAGE"),
	[SIP_REQ_UPDATE]	= BSTR_K("UPDATE"),
	[SIP_REQ_OTHER]		= BSTR_K("Other"),
};

/*
 * Get request type from string.  E.g. "INVITE" -> SIP_REQ_INVITE
 */
static enum csip_req csip_req_str2type(struct bstr const *method)
{
	enum csip_req req;

	for (req = SIP_REQ_FIRST; req <= SIP_REQ_LAST; req++)
		if (bstr_eq(method, &csip_req_methods[req]))
			break;

	/* Unknown Request? */
	if (req > SIP_REQ_LAST)
		req = SIP_REQ_OTHER;

	return req;
}

/*
 * Parse SIP msg Request start line.  Validate and identify the Request type.
 *
 * The Request line is a series of tokens separated by single spaces:
 *
 * "Method SP Request-URI SP SIP-Version CRLF" e.g.
 *
 * "INVITE sip:I.Wilson@192.0.2.1 SIP/2.0\r\n"
 */
enum csip_req csip_parse_request_start_line(struct bstr const *line, int *rc)
{
	struct bstr tail;

	/* We expect a minimum length of line */
	if (line->len < SIP_REQ_STARTLINE_MIN) {
		*rc = -ALG_ERR_SIP_PARSE_REQ;
		return SIP_REQ_NONE;
	}

	/* Method is first token; eat SP */
	struct bstr method;
	if (!bstr_split_term_after(line, ' ', &method, &tail) || method.len < 2) {
		*rc = -ALG_ERR_SIP_PARSE_REQ;
		return SIP_REQ_NONE;
	}
	bstr_drop_right(&method, 1);

	/* Request-URI is second token */
	struct bstr uri;

	/* Ignore other non-sip schemes; eat SP */
	if (!bstr_split_term_after(&tail, ' ', &uri, &tail) ||
	    !bstr_prefix(&uri, BSTRL("sip:"))) {
		*rc = -ALG_ERR_SIP_UNSP;
		return SIP_REQ_NONE;
	}
	bstr_drop_right(&uri, 1);

	/* Version is third token */
	struct bstr version = tail;

	/* We only support SIP version 2.0 */
	if (!bstr_prefix(&version, BSTRL("SIP/2.0"))) {
		*rc = -ALG_ERR_SIP_UNSP;
		return SIP_REQ_NONE;
	}

	/* What type of Request is it?  INVITE, ACK, BYE etc.? */
	return csip_req_str2type(&method);
}
