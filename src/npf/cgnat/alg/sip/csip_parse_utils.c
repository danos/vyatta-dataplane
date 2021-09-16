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

/*
 * Split off a line ending in CRLF.  This does not allow for continued lines.
 */
bool csip_get_line(struct bstr const *parent, struct bstr *headp, struct bstr *tailp)
{
	if (!bstr_split_term(parent, '\n', headp, tailp))
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

	/* sdp_index >= m.capacity means there is no SDP part */
	sip_lines->m.sdp_index = sip_lines->m.capacity;

	/* Request or Response Start line */
	if (!csip_get_line(msg, &lines[0].b, &tail)) {
		lines[0].b = BSTR_INIT;
		return false;
	}

	/* SIP header lines */
	for (i = 1, head = tail; i < max_capacity; i++, head = tail) {
		if (!csip_get_hline(&head, &lines[i].b, &tail)) {
			/* End of input.  Return success. */
			sip_lines->m.used = i;
			lines[i].b = BSTR_INIT;
			return true;
		}

		/* Separating line between SIP and SDP parts? */
		if (lines[i].b.len == SIP_SEPARATOR_SZ) {
			sip_lines->m.sdp_index = i + 1;
			break;
		}
	}

	/* SDP header lines */
	for (i++, head = tail; i < max_capacity; i++, head = tail)
		if (!csip_get_line(&head, &lines[i].b, &tail)) {
			/* End of input.  Return success. */
			sip_lines->m.used = i;
			lines[i].b = BSTR_INIT;
			return true;
		}

	/* out of space */
	lines[0].b = BSTR_INIT;
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
 */
bool csip_find_uri(struct bstr const *line, struct bstr *pre, struct bstr *host,
		   struct bstr *port, struct bstr *post)
{
	struct bstr head = BSTR_INIT;
	struct bstr tail = BSTR_INIT;
	struct bstr parent;

	parent = *line;

	/*
	 * Split line on '@' char or "sip: sub-string.  head will contain
	 * everything up to and including the '@' char or "sip: sub-string.
	 * tail will contain everything after.
	 */
	if (bstr_split_term(&parent, '@', &head, &tail)) {
		if (bstr_find_str(&head, BSTRL("sip:")) < 0) {
			/* line has '@' but does not have 'sip:' */
			*pre = *line;
			return false;
		}
	} else if (!bstr_split_after_substr(&parent, BSTRL("sip:"), &head, &tail)) {
		/* SIP URI not present */
		*pre = *line;
		return false;
	}
	/* else line has 'sip:' but does not have '@' */

	*pre = head;
	parent = tail;

	/* We ignore URIs with IPv6 addresses */
	if (bstr_find_term(&parent, '[') >= 0) {
		*pre = *line;
		return false;
	}

	/* A colon indicates a port number is present  */
	if (bstr_split_term(&parent, ':', &head, &tail)) {

		/* drop the colon */
		if (!bstr_drop_right(&head, 1)) {
			*pre = *line;
			return false;
		}

		*host = head;
		parent = tail;

		/* Look for the end of host:port */
		if (bstr_split_terms(&parent, TERMS, &head, &tail)) {
			/* There are some bytes after the port number */
			*port = head;
			*post = tail;
		} else
			/* The port number the last thing in 'parent' */
			*port = parent;

	} else if (bstr_split_terms(&parent, TERMS, &head, &tail)) {
		/* No port number.  We just have a host, plus whatever is left */
		*host = head;
		*post = tail;
	} else
		/* host is the last thing in 'parent' */
		*host = parent;

	/* host part must be at least this many chars long */
	if (host->len < SIP_FQDN_MIN) {
		*pre = *line;
		return -1;
	}

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
