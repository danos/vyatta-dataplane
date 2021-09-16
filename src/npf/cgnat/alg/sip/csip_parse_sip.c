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
#include "npf/cgnat/alg/sip/csip_request.h"
#include "npf/cgnat/alg/sip/csip_response.h"
#include "npf/bstr.h"

/*
 * SIP Header Name
 *
 * csip_hdr_name[] is used to identify each interesting SIP header line. The
 * character case shown here is the most common.  However the identification
 * routines ignore the case.
 */
static struct bstr csip_hdr_name[] = {
	[SIP_HDR_NONE]		= BSTR_K("none"),
	[SIP_HDR_OTHER]		= BSTR_K("other"),

	[SIP_HDR_VIA]		= BSTR_K("Via"),
	[SIP_HDR_ROUTE]		= BSTR_K("Route"),
	[SIP_HDR_RR]		= BSTR_K("Record-Route"),
	[SIP_HDR_FROM]		= BSTR_K("From"),
	[SIP_HDR_TO]		= BSTR_K("To"),
	[SIP_HDR_CALLID]	= BSTR_K("Call-ID"),
	[SIP_HDR_CONTACT]	= BSTR_K("Contact"),
	[SIP_HDR_UA]		= BSTR_K("User-Agent"),
	[SIP_HDR_CTYPE]		= BSTR_K("Content-Type"),
	[SIP_HDR_CLEN]		= BSTR_K("Content-Length"),
};

/*
 * Some SIP header lines allow a short-form to be used.  This is less common.
 */
static char csip_hdr_short[] = {
	[SIP_HDR_NONE]		= '\0',
	[SIP_HDR_OTHER]		= '\0',

	[SIP_HDR_VIA]		= 'v',
	[SIP_HDR_ROUTE]		= '\0',
	[SIP_HDR_RR]		= '\0',
	[SIP_HDR_FROM]		= 'f',
	[SIP_HDR_TO]		= 't',
	[SIP_HDR_CALLID]	= 'i',
	[SIP_HDR_CONTACT]	= 'm',
	[SIP_HDR_UA]		= '\0',
	[SIP_HDR_CTYPE]		= 'c',
	[SIP_HDR_CLEN]		= 'l',
};

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
 * Parse, verify, and classify the SIP message start-line
 */
bool csip_classify_sip_start(struct csip_lines *sip_lines)
{
	struct csip_line *line = &sip_lines->lines[0];
	enum csip_req req = SIP_REQ_NONE;
	uint resp_code = 0;
	bool rv = true;

	/* Verify SIP version and scheme. Determine Req/Resp type */
	if (csip_parse_start_line(&line->b, &req, &resp_code) < 0)
		return false;

	/* Set the line type */
	if (req != SIP_REQ_NONE) {
		line->type = SIP_LINE_REQ;
		line->req = req;
	} else if (resp_code > 0) {
		line->type = SIP_LINE_RESP;
		line->resp = resp_code;
	} else {
		line->type = SIP_LINE_NONE;
		rv = false;
	}
	return rv;
}

static inline bool csip_ascii_islower(char c)
{
	return c >= 'a' && c <= 'z';
}

/*
 * Some SIP header lines allow a short form to be used.  We look for a single
 * lowercase character followed by either a colon, space or horizontal-tab.
 *
 * 'c' SWS : LWS
 */
static bool csip_line_is_short_form(struct bstr const *b)
{
	uint8_t c1, c2;

	if (!bstr_get_byte(b, 0, &c1) || !bstr_get_byte(b, 1, &c2))
		return false;

	/*
	 * We look for a single lowercase character followed by either a
	 * colon, space or horizontal-tab
	 */
	return csip_ascii_islower(c1) && (c2 == ':' || c2 == ' ' || c2 == '\t');
}

/*
 * Identify a short-form SIP header line
 */
static void csip_classify_sip_short(struct csip_line *line)
{
	enum csip_hdr_type type;

	for (type = SIP_HDR_FIRST; type <= SIP_HDR_LAST; type++)
		if (bstr_first_eq(&line->b, csip_hdr_short[type])) {
			line->sip = type;
			return;
		}

	line->sip = SIP_HDR_OTHER;
}

/*
 * Identify a SIP header from its name
 *
 * header  =  "header-name" HCOLON header-value *(COMMA header-value)
 *
 * HCOLON  =  *( SP / HTAB ) ":" SWS
 */
static void csip_classify_sip_long(struct csip_line *line)
{
	enum csip_hdr_type type;

	for (type = SIP_HDR_FIRST; type <= SIP_HDR_LAST; type++)
		if (bstr_prefix_ascii_case(&line->b, &csip_hdr_name[type])) {
			line->sip = type;
			return;
		}

	line->sip = SIP_HDR_OTHER;
}

/*
 * SIP Header Classification
 *
 * A header field name MAY appear in both long and short forms within the same
 * message.  Implementations MUST accept both the long and short forms of each
 * header name.
 */
bool csip_classify_sip(struct csip_lines *sip_lines, uint32_t index)
{
	struct csip_line *line = &sip_lines->lines[index];

	/* Truncated line? */
	if (unlikely(line->b.len < SIP_LINE_MIN)) {
		line->sip = SIP_HDR_OTHER;
		return false;
	}

	/* The short-form of the method string seems to be less common */
	if (unlikely(csip_line_is_short_form(&line->b)))
		csip_classify_sip_short(line);
	else
		csip_classify_sip_long(line);

	/*
	 * Remember first or only occurrence of this SIP header type in the
	 * msg.  Some SIP header lines (e.g. Via and Record-Route) may have
	 * multiple instances.  Others may only have a single instance
	 * (e.g. Call-ID and Content-Length).
	 */
	if (sip_lines->m.sip_index[line->sip] == 0)
		sip_lines->m.sip_index[line->sip] = index;

	return true;
}
