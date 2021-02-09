/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/* Functions for operating on SIP data sets */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "dp_test_npf_alg_sip_data.h"

/*
 * Create a description string from the first line of a SIP packet payload
 * payload.  This is useful in identifying packets where the same function is
 * being used in a loop to send packets.
 */
char *sipd_descr(uint index, bool forw, const char *pload)
{
	static char str[100];
	uint i;
	uint len;

	len = snprintf(str, sizeof(str), "[%u:%s] ",
		       index, forw ? "FORW":"BACK");

	for (i = 0; i + len < sizeof(str) - 1; i++) {
		if (pload[i] == '\r' || pload[i] == '\0')
			break;
		str[i + len] = pload[i];
	}

	str[i + len] = '\0';
	return str;
}

/*
 * Extract content-length value from SIP message header, and measure actual
 * content-length.  Return false if both can be determined but are *not*
 * equal.
 */
bool sipd_check_content_length(const char *pload, uint *hdr_clen,
			       uint *body_clen)
{
	char str[30];
	char *p;
	uint i, hdr_cl, body_cl;
	int rc;

	if (hdr_clen)
		*hdr_clen = 0;
	if (body_clen)
		*body_clen = 0;

	/*
	 * Copy the "Content-Length" line from the payloaf into a local buffer
	 */
	p = strcasestr(pload, "Content-Length");
	if (!p)
		return true;

	/* End of the line is denoted by "\r\n" */
	for (i = 0; p[i] && p[i] != '\r' && i < sizeof(str) - 1; i++)
		str[i] = p[i];
	str[i] = '\0';

	/* Look for end of SIP msg headers */
	p = strstr(p, "\r\n\r\n");
	if (!p)
		return true;

	/*
	 * Move 'p' to start of SIP msg body (or end of string if there is no
	 * body)
	 */
	p += strlen("\r\n\r\n");
	if (p[0] == '\0')
		return true;

	/* Determine length of SIP msg body (i.e. the 'content-length') */
	body_cl = strlen(p);

	/* Get Content-length value in the header line */
	rc = 0;
	for (p = str; p[0]; p++) {
		if (isdigit(p[0])) {
			rc = sscanf(p, "%u", &hdr_cl);
			break;
		}
	}
	if (rc != 1)
		hdr_cl = 0;

	if (hdr_clen)
		*hdr_clen = hdr_cl;
	if (body_clen)
		*body_clen = body_cl;

	return hdr_cl == body_cl;
}
