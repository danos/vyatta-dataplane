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

#define SIP_FQDN_MIN		((long)sizeof("a.bc") - 1)

/* One of these chars indicates the end of the host or host:port in a SIP URI */
#define TERMS BSTRL(" ;?>\r\n")

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
		if (!bstr_split_term_after(&cursor, '\n', &head, &tail))
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

/*
 * Split off a line ending in CRLF.  This does not allow for continued lines.
 */
bool csip_get_line(struct bstr const *parent, struct bstr *headp, struct bstr *tailp)
{
	if (!bstr_split_term_after(parent, '\n', headp, tailp))
		return false;

	/* Did we find '\r\n'? */
	if (!bstr_penultimate_eq(headp, '\r'))
		return false;

	return true;
}

/*
 * Split a SIP message up into an array of lines.
 *
 * The number of lines found is written to 'sip_lines->m.used'.  In addition,
 * the array element after the last line is set to BSTR_INIT in order to
 * delimit the end of the array entries.
 *
 * The SIP message we are interested in are in one of two format:
 *
 * SIP start-line
 * SIP headers lines
 *
 * or
 *
 * SIP start-line
 * SIP header lines
 * blank line (CRLF only)
 * SDP header lines
 *
 * Only SIP header lines use continuation lines, so csip_get_hline is used for
 * these.
 */
bool csip_split_lines(struct bstr const *msg, struct csip_lines *sip_lines)
{
	struct csip_line *lines = sip_lines->lines;
	struct bstr head, tail;
	uint32_t max_capacity;
	uint32_t i;

	/* Allow for an empty line at end of array */
	max_capacity = sip_lines->m.capacity - 1;

	/* These can never be zero if a SIP or SDP part is present */
	sip_lines->m.sip_first = 0;
	sip_lines->m.sip_last = 0;
	sip_lines->m.sdp_first = 0;
	sip_lines->m.sdp_last = 0;

	memset(sip_lines->m.sip_index, 0, sizeof(sip_lines->m.sip_index));

	/* Request or Response Start line */
	if (!csip_get_line(msg, &lines[0].b, &tail)) {
		lines[0].b = BSTR_INIT;
		lines[0].type = SIP_LINE_NONE;
		return false;
	}

	/*
	 * Mark start-line as a SIP line until such time as we can determine
	 * if its a Request or Response start-line
	 */
	lines[0].type = SIP_LINE_SIP;

	/* SIP header lines */
	for (i = 1, head = tail; i < max_capacity; i++, head = tail) {
		if (!csip_get_hline(&head, &lines[i].b, &tail)) {
			/* End of input.  Return success. */
			lines[i].b = BSTR_INIT;
			lines[i].type = SIP_LINE_NONE;
			return true;
		}

		/* Separating line between SIP and SDP parts? */
		if (lines[i].b.len == SIP_SEPARATOR_SZ) {
			lines[i].type = SIP_LINE_SEPARATOR;
			break;
		}
		lines[i].type = SIP_LINE_SIP;

		if (sip_lines->m.sip_first == 0)
			sip_lines->m.sip_first = i;

		sip_lines->m.sip_last = i;
	}

	/* We always expect the SIP lines to start on line 1 */
	assert(sip_lines->m.sip_first == 1);

	/* SDP header lines */
	for (i++, head = tail; i < max_capacity; i++, head = tail) {
		if (!csip_get_line(&head, &lines[i].b, &tail)) {
			/* End of input.  Return success. */
			lines[i].b = BSTR_INIT;
			lines[i].type = SIP_LINE_NONE;
			return true;
		}
		lines[i].type = SIP_LINE_SDP;

		if (sip_lines->m.sdp_first == 0)
			sip_lines->m.sdp_first = i;

		sip_lines->m.sdp_last = i;
	}

	/* out of space */
	lines[0].b = BSTR_INIT;
	lines[0].type = SIP_LINE_NONE;
	return false;
}

/*
 * Find SIP URI
 *
 * The SIP ALG needs to parse URIs in the SIP messages in order to determine
 * if they contain an address and/or port that need translating.  It also
 * needs to be able to potentially replace the address and/or port strings
 * with other values which may be different lengths.
 *
 * SIP URIs are of the form (some parts are optional):
 *
 *   sip:user:password@host:port;uri-parameters?headers
 *
 * See rfc3261, 19.1.1 and 25.1:
 *
 * rfc3261, 19.1.1: The 'userinfo' part of the URI comprises the user field,
 * the password field, and the @ following them.  The userinfo part of a URI
 * is optional and MAY be absent. If the @ sign is present in a SIP or SIPS
 * URI, the user field MUST NOT be empty.
 *
 * The host part contains either a fully-qualified domain name or numeric IPv4
 * address.  Using the fully-qualified domain name form is RECOMMENDED
 * whenever possible.
 *
 * Examples (first two are the most minimal URIs allowed):
 *
 * sip:atlanta.com
 * sip:192.0.2.4
 * sip:192.0.2.4:5060
 * sip:alice@atlanta.com
 * sip:alice@192.0.2.4
 * sip:alice:secretword@atlanta.com;transport=tcp
 * sip:alice@atlanta.com?subject=project%20x&priority=urgent
 * sip:+1-212-555-1212:1234@gateway.com;user=phone
 * sip:1212@gateway.com
 * sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com
 * sip:alice;day=tuesday@atlanta.com
 * <sip:atlanta.com>;method=REGISTER?to=alice%40atlanta.com
 * <sip:192.0.2.4:5060>;method=REGISTER
 *
 * This function will take a SIP message line, and overlay four counted
 * strings that point to the substrings it identifies within it.  These are
 * 1. the host name or address, 2. the port number, 3. the bytes before the
 * host (pre) and 4. the bytes after the port or host (post).
 *
 * This allows the caller to create a new line with a translated host address
 * and port.  If a SIP URI is not found, then 'pre' is set to point to the
 * original line.
 *
 * Note that IPv6 addresses in SIP URIs are enclosed in square brackets, e.g.:
 *
 *   sip:6000@[2620:0:2ef0:7070:250:60ff:fe03:32b7]:5060;transport=tcp
 *
 * Inputs:
 *   line - Counted string containing the URI.
 *
 * Outputs:
 *   pre  - Counted string overlay of the bytes before the URI
 *   host - Counted string overlay of the bytes before the URI
 *   port - Counted string overlay of the bytes before the URI
 *   post - Counted string overlay of the bytes before the URI
 *   returns true if a SIP URI host, or host and port, were identified
 *
 * e.g. for:
 *
 *   "INVITE sip:alice@192.0.2.4:5060;tag=76341 SIP/2.0\r\n"
 *
 *  pre  - "INVITE sip:alice@"
 *  host - "192.0.2.4"
 *  port - "5060"
 *  post - ";tag=76341 SIP/2.0\r\n"
 *
 * Returns true if a host within a SIP URI has been found.  If false is
 * returned then then pre, host, port, and post are left in unknown states.
 */
bool csip_find_uri(struct bstr const *line, struct bstr *pre, struct bstr *host,
		   struct bstr *port, struct bstr *post)
{
	struct bstr sip = BSTR_K("sip:");
	int offs, tmp;

	/* Locate the 'sip:' that prefixes the SIP URI */
	offs = bstr_find_str(line, &sip);
	if (offs < 0)
		return false;

	/* Move past 'sip:' */
	offs += sip.len;

	/* An '@' may or may not be present */
	tmp = bstr_find_term_offs(line, '@', offs);
	if (tmp >= 0)
		offs = tmp + 1;

	/*
	 * 'offs' should now be the offset of the host.  We can now split off
	 * all the 'pre' text up to the host part.
	 */
	if (!bstr_split_length(line, offs, pre, host))
		return false;

	/* We ignore URIs with IPv6 addresses */
	if (bstr_first_eq(host, '['))
		return false;

	/* A colon indicates a port number is present  */
	if (bstr_split_term_after(host, ':', host, port)) {

		/* drop the colon */
		if (!bstr_drop_right(host, 1))
			return false;

		/* Look for the end of host:port */
		(void)bstr_split_terms_before(port, TERMS, port, post);

	} else
		(void)bstr_split_terms_before(host, TERMS, host, post);

	/* host part must be at least this many chars long */
	if (host->len < SIP_FQDN_MIN)
		return false;

	return true;
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

/*
 * Locate the host and port in a Via header line
 *
 * The Via header line is the only SIP line not to use a SIP URI, and hence we
 * have no easy way to locate the Via host.  Instead, we locate the whitespace
 * that follows the second '/' character.
 *
 * We set the 4 bstrs to point to the constituent parts of the line.  If any
 * part is not found then it is left empty (len=0).
 *
 * e.g. "Via: SIP/2.0/UDP 192.0.2.103:5060;branch=z9hG4bKfw19b\r\n"
 *       ^                ^           ^   ^
 *       pre              host      port  post
 */
bool csip_via_find_host_port(struct bstr const *line, struct bstr *pre, struct bstr *host,
			     struct bstr *port, struct bstr *post)
{
	int offs, tmp;

	/* Find first '/' */
	offs = bstr_find_term(line, '/');
	if (offs < 0)
		return false;

	/* Find second '/' */
	offs = bstr_find_term_offs(line, '/', offs + 1);
	if (offs < 0)
		return false;

	/* Move past any WSP before the transport string */
	tmp = bstr_find_next_non_wsp(line, offs + 1);
	if (tmp > 0)
		offs = tmp;

	/* Find WSP after the transport string */
	offs = bstr_find_next_wsp(line, offs + 1);
	if (offs < 0)
		return false;

	/* Split line after the whitespace */
	if (!bstr_split_length(line, offs + 1, pre, host))
		return false;

	/* Trim any LWS before host.  'host' should now start with an IP addr or FQDN. */
	if (!bstr_lws_ltrim(host))
		return false;

	/* Is a port number present? */
	if (!bstr_split_term_after(host, ':', host, post)) {

		/* No colon found. Split host from remainder of line.  */
		if (!bstr_split_terms_before(host, BSTRL(" ;\r"), host, post))
			return false;

		return true;
	}

	/* Drop the colon at the end of 'host' */
	bstr_drop_right(host, 1);

	/* Split port from remainder of line. */
	if (!bstr_split_terms_before(post, BSTRL(" ;\r"), port, post))
		return false;

	return true;
}
