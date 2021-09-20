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

/*
 * Parse SIP Call-ID
 *
 * The Call-ID is a globally unique identifier for the call.  This is
 * typically a large number, optionally appended with the senders IP address.
 *
 * We only save the generated number part of the Call-ID since we only ever
 * use it in the context of a CGNAT session, which is itself a function of the
 * senders IP address.
 *
 * A typical Call-ID number is a 128 bit (16 bytes) cryptographic key, however
 * there is no absolute minimum or maximum.  It is common for SIP clients to
 * set maximum lengths, or to provide an option to configure a maximum length.
 *
 * We use CSIP_CALLID_SZ to set a maximum length of 16 bytes.
 *
 * There may be multiple SIP calls per SIP CGNAT session, each with a
 * different Call-ID.  For example, one call might just convey the dailtone or
 * a recorded message before a separate call is established for the voice
 * conversation.  Simultaneous calls may occur if voice, video and data are
 * being shared, e.g. in a whiteboard session.
 *
 * We use the callid as a hash into the media hash-table.  This is where we
 * temporarily store media (rtp) addresses and ports while the call is being
 * negotiated.
 *
 * We set the input parameter 'callid' to point to the call-ID generated
 * number within the line.  If the caller needs to store this value for longer
 * than the duration of the packet then it MUST make a copy.
 *
 * Format:
 *
 * Call-ID  =  ( "Call-ID" / "i" ) HCOLON callid
 * callid   =  word [ "@" word ]
 *
 * i.e.  Call-ID: (generated number)[@(ip address)]
 * e.g. "Call-ID: j2qu348ek2328ws\r\n"
 *
 */
bool csip_parse_sip_callid(struct bstr const *line, struct bstr *callid)
{
	struct bstr head, tail;

	/* Split method string from call ID */
	if (!bstr_split_term_after(line, ':', &head, &tail))
		return false;

	/* There may be linear whitespace if there is a continuation line */
	bstr_lws_ltrim(&tail);

	/*
	 * We are only interested in the generated-number part of the Call ID.
	 * A SIP 'word' may contain many non-alphanumeric characters but may
	 * *not* contain '@' or '\r' so we use those to find the end of the
	 * generated-number
	 */
	head = tail;
	if (!bstr_split_terms_before(&head, BSTRL("@\r"), callid, &tail))
		return false;

	/* We are only interested in CSIP_CALLID_SZ bytes */
	if (callid->len > CSIP_CALLID_SZ)
		if (!bstr_split_length(callid, CSIP_CALLID_SZ, callid, &tail))
			return false;

	return true;
}

/*
 * Is the Content-Type media sdp?
 *
 * If this is *not* true for Invite Requests or 150 or 200 Responses, then we
 * ignore the message body.  Note that it is also possible for a message to
 * contain a Content-Type header but for the message body to be empty.
 *
 * Examples:
 *
 * Content-Type: application/sdp
 * c: text/html; charset=ISO-8859-4
 *
 * Note that is is possible to have an smime encrypted SDP body within a SIP
 * message.  We obviously cannot handle these.
 *
 * Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m
 * Content-Disposition: attachment; filename=smime.p7m; handling=required
 *
 * A counter will be added for Content-Types that we do not understand.  We
 * may also want to consider adding a configuration option to enable logging
 * these (though that would require more parsing to extract the type and
 * subtype.  See csip_parse_sip_content_type in the unit-tests).
 */
bool csip_sip_content_type_is_sdp(struct bstr const *line)
{
	return bstr_find_str(line, BSTRL("application/sdp")) > 0;
}
