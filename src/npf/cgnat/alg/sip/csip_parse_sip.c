/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <values.h>
#include <rte_mbuf.h>
#include "util.h"

#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_test.h"

#include "npf/cgnat/alg/alg.h"
#include "npf/cgnat/alg/alg_rc.h"
#include "npf/cgnat/alg/sip/csip_defs.h"
#include "npf/cgnat/alg/sip/csip_parse_sip.h"
#include "npf/cgnat/alg/sip/csip_parse_utils.h"
#include "npf/bstr.h"

/* Min length of strings we expect to find in SIP headers */
#define SIP_REQ_STARTLINE_MIN	((long)sizeof("ACK sip:a.bc SIP2/0") - 1)
#define SIP_RESP_STARTLINE_MIN	((long)sizeof("SIP2/0 200") - 1)

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
static enum csip_req csip_parse_request_start_line(struct bstr const *line, int *rc)
{
	struct bstr tail;

	/* We expect a minimum length of line */
	if (line->len < SIP_REQ_STARTLINE_MIN) {
		*rc = -ALG_ERR_SIP_PARSE_REQ;
		return SIP_REQ_NONE;
	}

	/* Method is first token; eat SP */
	struct bstr method;
	if (!bstr_split_term(line, ' ', &method, &tail) || method.len < 2) {
		*rc = -ALG_ERR_SIP_PARSE_REQ;
		return SIP_REQ_NONE;
	}
	bstr_drop_right(&method, 1);

	/* Request-URI is second token */
	struct bstr uri;

	/* Ignore other non-sip schemes; eat SP */
	if (!bstr_split_term(&tail, ' ', &uri, &tail) ||
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

/*
 * Convert a 3-digit ASCII decimal value in to a unsigned value.
 */
static bool csip_parse_response_code(struct bstr const *text, uint *code)
{
	if (text->len != 3)
		return false;

	uint8_t c0 = text->buf[0], c1 = text->buf[1], c2 = text->buf[2];
	if (!isdigit(c0) || !isdigit(c1) || !isdigit(c2))
		return false;

	*code = ((unsigned int)(c0 - '0') * 100)
	      + ((unsigned int)(c1 - '0') * 10)
	      + ((unsigned int)(c2 - '0'));

	return true;
}

/*
 * Parse a SIP msg Response start line. Validate and identify the Response type.
 *
 * "SIP-Version SP Status-Code SP Reason-Phrase CRLF"
 *
 * We always parse every Response line.  If there is something we do not
 * understand or support then we return an error.  ALG parsing stops, the
 * error is counted, and the packet is allowed to continue.
 */
static uint csip_parse_response_start_line(struct bstr const *line, int *rc)
{
	struct bstr head, tail;

	/* We expect a minimum length of line */
	if (line->len < SIP_RESP_STARTLINE_MIN) {
		*rc = -ALG_ERR_SIP_PARSE_RSP;
		return 0;
	}

	/* Version is first token */

	/* Check version is SIP/2.0 - allow for syntax change */
	if (!bstr_prefix(line, BSTRL("SIP/2.0"))) {
		*rc = -ALG_ERR_SIP_UNSP;
		return 0;
	}

	/* Move past version */
	if (!bstr_split_term(line, ' ', &head, &tail)) {
		*rc = -ALG_ERR_SIP_UNSP;
		return 0;
	}

	/* response code is second token; eat SP */
	struct bstr code;
	if (!bstr_split_term(&tail, ' ', &code, &tail) || code.len < 2) {
		*rc = -ALG_ERR_SIP_PARSE_RSP;
		return 0;
	}
	bstr_drop_right(&code, 1);

	/* Reason-phrase is third token */
	struct bstr reason = tail;
	if (reason.len < 1) {
		*rc = -ALG_ERR_SIP_PARSE_RSP;
		return 0;
	}

	/* Extract the response code */
	unsigned int response_code;
	if (!csip_parse_response_code(&code, &response_code)) {
		*rc = -ALG_ERR_SIP_PARSE_RSP;
		return 0;
	}

	return response_code;
}

/*
 * Parse a SIP message start-line
 *
 * We are looking to verify the SIP version, and to determine if it is a
 * Request or a Response message.
 */
int csip_parse_start_line(struct bstr const *line, enum csip_req *req,
			  unsigned int *resp_code)
{
	int rc = 0;

	/* First line of Response msgs always start with "SIP/" */
	if (bstr_prefix(line, BSTRL("SIP/")))
		*resp_code = csip_parse_response_start_line(line, &rc);
	else
		*req = csip_parse_request_start_line(line, &rc);

	return rc;
}

/*
 * Locate the SIP URI in the message line and translate address and/or port if
 * either match the original address and port.
 *
 * If no translation is required, then the line is simply copied to the new
 * buffer.
 *
 * If an error is encountered then we will try as far as possible and
 * continue, but using the original line.  Debugging SIP ALG problems requires
 * the before and after messages to be traced by application such as
 * Wireshark.
 */
bool csip_find_and_translate_uri(struct bstr const *line, struct bstr *new,
				 struct bstr const *oaddr, struct bstr const *oport,
				 struct bstr const *taddr, struct bstr const *tport)
{
	struct bstr pre = BSTR_INIT;	/* string before the host */
	struct bstr host = BSTR_INIT;	/* host string */
	struct bstr port = BSTR_INIT;	/* port string */
	struct bstr post = BSTR_INIT;	/* string after the host/port */
	bool ok;
	struct bstr tmp = *new;

	ok = csip_find_uri(line, &pre, &host, &port, &post);
	if (!ok)
		/* copy untranslated line to new message */
		return bstr_addbuf(new, line);

	if (pre.len > 0) {
		ok = bstr_addbuf(new, &pre);
		if (!ok)
			goto error;
	}

	if (host.len > 0) {
		if (bstr_eq(&host, oaddr))
			ok = bstr_addbuf(new, taddr);
		else
			ok = bstr_addbuf(new, &host);

		if (!ok)
			goto error;
	}

	if (port.len > 0) {
		if (!bstr_addch(new, ':'))
			goto error;

		if (bstr_eq(&port, oport))
			ok = bstr_addbuf(new, tport);
		else
			ok = bstr_addbuf(new, &port);

		if (!ok)
			goto error;
	}

	if (post.len > 0) {
		ok = bstr_addbuf(new, &post);
		if (!ok)
			goto error;
	}

	return true;

error:
	*new = tmp;
	return bstr_addbuf(new, line);
}
