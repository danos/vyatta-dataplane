/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <values.h>
#include <string.h>

#include "util.h"
#include "npf/cgnat/alg/alg_rc.h"
#include "npf/cgnat/alg/sip/csip_parse_utils.h"
#include "npf/bstr.h"

/*
 * This file contains a set of very specific functions designed to help parse
 * SIP message-header fields.
 *
 * A SIP message consists of a start line, one or more message-header fields
 * (lines), an empty line (indicating the end of the header fields), and an
 * optional message-body.
 *
 * The start-line, each message-header line, and the empty line MUST be
 * terminated by a carriage-return line-feed sequence (CRLF).  Note that the
 * empty line MUST be present even if the message-body is not.
 *
 * Example of a message-header field/line:
 *
 *   "From: A. Workman <sip:workman@198.51.100.1>;tag=76341\r\n"
 *
 * However to complicate matters, a single message-header field may be split
 * over two lines in the SIP message.  A single space or tab at the start
 * denotes a 'continuation line':
 *
 *   "Via: SIP/2.0/UDP\r\n"                         <--- Example of hdr field
 *   " 198.51.100.1:5060;branch=z9hG4bKfw19b\r\n"   <--- split over two lines
 *
 * And to further complicate matters, it seems that its possible that some SIP
 * implementations use a single carriage-return ('\n') or a double
 * carriage-return ('\n\n') as the line-end marker.
 *
 * Example of a SIP Invite Request message:
 *
 *   "INVITE sip:I.Wilson@192.0.2.1 SIP/2.0\r\n"              <-- Start line
 *   "From: Fred <sip:workman@198.51.100.1>;tag=76341\r\n"    <-- Msg header
 *   "To: Ian <sip:I.Wilson@danos.co.uk>\r\n"
 *   "Call-ID: j2qu348ek2328ws\r\n"
 *   "Via: SIP/2.0/UDP\r\n"                         <--- Example of hdr field
 *   " 198.51.100.1:5060;branch=z9hG4bKfw19b\r\n"   <--- split over two lines
 *   "CSeq: 1 INVITE\r\n"
 *   "Contact: <sip:workman@198.51.100.1>\r\n"
 *   "Content-Type: application/sdp\r\n"
 *   "Max-forwards: 70\r\n"
 *   "Content-Length: 139\r\n"
 *   "\r\n"
 *   "v=0\r\n"                                                  <-- Msg body
 *   "o=Workman 2890844526 2890844526 IN IP4 198.51.100.1\r\n"
 *   "s=Phone Call\r\n"
 *   "c=IN IP4 198.51.100.1\r\n"
 *   "t=0 0\r\n"
 *   "m=audio 10000 RTP/AVP 0\r\n"
 *   "a=rtpmap:0 PCMU/8000\r\n",
 */

/*
 * Get header line. Find the EOL sequence at the end of a SIP message header
 * field, taking continuation lines into account.
 *
 * The return value is true/false indicating if we found a header line.  The
 * output values are headp with that line, and tailp with everything else
 * after that line.
 *
 * The *only* EOL sequence that we recognize is '\r\n'.  rfc2543 (March 1999)
 * allowed SIP lines to be terminated with CR, LF, or CRLF.  rfc3261 (June
 * 2002) obseletes rfc2543 and specifies that *only* CRLF ('\r\n') is allowed.
 */
bool csip_get_hline(struct bstr const *parent, struct bstr *headp, struct bstr *tailp)
{
	struct bstr cursor, head, tail;

	cursor = *parent;
	goto start;

	/* Find the longest sequence of continued lines */
	do {
		cursor = tail;

start:
		if (!bstr_split_term(&cursor, '\n', &head, &tail))
			return false;

		/* Did we find '\r\n'? */
		if (!bstr_penultimate_eq(&head, '\r'))
			return false;

		/* Is there a continuation line? */
	} while (bstr_first_eq(&tail, ' ') || bstr_first_eq(&tail, '\t'));

	/* Now do the split */
	if (!bstr_split_length(parent, parent->len - tail.len, headp, tailp))
		return false;

	return true;
}
