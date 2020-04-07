/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Parsing and manipulating SIP messages
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "netinet6/ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf.h"

#include "dp_test_lib_internal.h"
#include "dp_test_str.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_alg_lib.h"
#include "dp_test_npf_alg_sip_parse.h"


/*
 * SIP Requests
 */

static const char * const sip_requests[DP_TEST_SIP_REQ_SIZE] = {
	[DP_TEST_SIP_REQ_INVITE]	= "INVITE",
	[DP_TEST_SIP_REQ_ACK]		= "ACK",
	[DP_TEST_SIP_REQ_BYE]		= "BYE",
	[DP_TEST_SIP_REQ_CANCEL]	= "CANCEL",
	[DP_TEST_SIP_REQ_OPTIONS]	= "OPTIONS",
	[DP_TEST_SIP_REQ_REGISTER]	= "REGISTER",
	[DP_TEST_SIP_REQ_PRACK]		= "PRACK",
	[DP_TEST_SIP_REQ_SUBSCRIBE]	= "SUBSCRIBE",
	[DP_TEST_SIP_REQ_NOTIFY]	= "NOTIFY",
	[DP_TEST_SIP_REQ_PUBLISH]	= "PUBLISH",
	[DP_TEST_SIP_REQ_INFO]		= "INFO",
	[DP_TEST_SIP_REQ_REFER]		= "REFER",
	[DP_TEST_SIP_REQ_MESSAGE]	= "MESSAGE",
	[DP_TEST_SIP_REQ_UPDATE]	= "UPDATE"
};

enum dp_test_sip_req
dp_test_npf_sip_msg_req(const char *msg)
{
	char *p, *first_line;
	uint i;

	/*
	 * Request or response info is always in first line
	 */
	p = strstr(msg, "\r\n");
	first_line = strndup(msg, p - msg);

	for (i = DP_TEST_SIP_REQ_FIRST; i <= DP_TEST_SIP_REQ_LAST; i++)
		if (strstr(first_line, sip_requests[i])) {
			free(first_line);
			return i;
		}

	free(first_line);
	return 0;
}

/*
 * SIP response first-lines are of the form:
 *
 * "SIP/2.0 180 Ringing\r\n"
 */
enum dp_test_sip_resp
dp_test_npf_sip_msg_resp(const char *msg, uint *code, char **strp)
{
	char *p, *first_line;

	/*
	 * Request or response info is always in first line
	 */
	p = strstr(msg, "\r\n");
	first_line = strndup(msg, p - msg);

	int rc;
	char str1[21], str2[21];
	uint u  = 0;

	str1[0] = '\0';
	str2[0] = '\0';

	rc = sscanf(first_line, "%20s %3u %20s", str1, &u, str2);
	free(first_line);
	if (rc != 3 || u < 100 || u > 606)
		return 0;

	if (!strstr(str1, "SIP"))
		return 0;

	if (strp)
		*strp = strdup(str2);

	if (code)
		*code = u;

	return u/100;
}

/*
 * Is this a SIP request?
 */
bool
dp_test_npf_sip_msg_is_req(const char *msg)
{
	return dp_test_npf_sip_msg_req(msg) != 0;
}

bool
dp_test_npf_sip_msg_is_req_bye(const char *msg)
{
	enum dp_test_sip_req req;

	req = dp_test_npf_sip_msg_req(msg);

	return req == DP_TEST_SIP_REQ_BYE;
}

/*
 * Replace a string, free old string, assign new string to pointer
 */
void
dp_test_npf_sip_replace_ptr(char **strp, const char *needle,
			    const char *replacement)
{
	char *new;

	new = dp_test_str_replace(*strp, needle, replacement);
	if (!new)
		return;

	free(*strp);
	*strp = new;
}

/*
 * Change the FQDNs to IP addresses
 */
void
dp_test_sip_replace_fqdn(char **msgp, bool snat, bool forw,
			 const char *ins_fqdn, const char *ins_ip,
			 const char *outs_fqdn, const char *outs_ip,
			 const char *tgt, const char *trans)
{
	char *msg = *msgp;
	bool req = dp_test_npf_sip_msg_is_req(msg);

	if (forw) {
		dp_test_npf_sip_replace_ptr(msgp, ins_fqdn, ins_ip);

		if (snat)
			dp_test_npf_sip_replace_ptr(msgp, outs_fqdn, outs_ip);

		if (!snat && req)
			dp_test_npf_sip_replace_ptr(msgp, outs_fqdn, tgt);

		if (!snat && !req)
			dp_test_npf_sip_replace_ptr(msgp, outs_fqdn, outs_ip);
	}

	if (!forw) {
		dp_test_npf_sip_replace_ptr(msgp, outs_fqdn, outs_ip);

		if (snat)
			dp_test_npf_sip_replace_ptr(msgp, ins_fqdn, trans);
		else
			dp_test_npf_sip_replace_ptr(msgp, ins_fqdn, ins_ip);
	}
}

void
dp_test_sip_replace_ins_fqdn(char **msgp, bool snat, bool forw,
			     const char *ins_fqdn, const char *ins_ip,
			     const char *tgt, const char *trans)
{
	if (forw)
		dp_test_npf_sip_replace_ptr(msgp, ins_fqdn, ins_ip);

	if (!forw) {
		if (snat)
			dp_test_npf_sip_replace_ptr(msgp, ins_fqdn, trans);
		else
			dp_test_npf_sip_replace_ptr(msgp, ins_fqdn, ins_ip);
	}
}

void
dp_test_sip_replace_outs_fqdn(char **msgp, bool snat, bool forw,
			      const char *outs_fqdn, const char *outs_ip,
			      const char *tgt, const char *trans)
{
	char *msg = *msgp;
	bool req = dp_test_npf_sip_msg_is_req(msg);

	if (forw) {
		if (snat)
			dp_test_npf_sip_replace_ptr(msgp, outs_fqdn, outs_ip);

		if (!snat && req)
			dp_test_npf_sip_replace_ptr(msgp, outs_fqdn, tgt);

		if (!snat && !req)
			dp_test_npf_sip_replace_ptr(msgp, outs_fqdn, outs_ip);
	}

	if (!forw)
		dp_test_npf_sip_replace_ptr(msgp, outs_fqdn, outs_ip);
}

/*
 * Replace a string within all Via parts of a SIP message.
 */
void
dp_test_sip_via_replace_str(char **msgp, const char *needle,
			    const char *replacement)
{
	char *msg = *msgp;
	char **split, *tmp;
	int i, count, changed = 0;

	split = dp_test_npf_sip_split(msg, &count);

	for (i = 0; i < count; i++) {
		if (strlen(split[i]) == 0 ||
		    strstr(split[i], "Via") != split[i])
			continue;

		tmp = dp_test_str_replace(split[i], needle, replacement);
		if (!tmp)
			continue;

		free(split[i]);
		split[i] = tmp;
		changed++;
	}
	if (!changed) {
		dp_test_npf_sip_split_free(split, count);
		return;
	}

	tmp = dp_test_npf_sip_combine(split, count);
	if (!tmp) {
		dp_test_fail("SIP combine failed");
		return;
	}

	/*
	 * This frees the param passed in, so we can safely assign to
	 * 'tmp'
	 */
	tmp = dp_test_npf_sip_reset_content_length(tmp);

	free(msg);
	*msgp = tmp;

	dp_test_npf_sip_split_free(split, count);
}


static const char *sip_delim = "\r\n";
static const char *sdp_delim = "\r\n\r\n";

/*
 * Return a pointer to the start of the SDP part of a SIP message
 */
const char *
dp_test_npf_sip_get_sdp(const char *sip)
{
	const char *sdp;

	sdp = strstr(sip, sdp_delim);
	if (!sdp)
		return NULL;

	sdp += strlen(sdp_delim);

	/* Is there anything after the SDP delimiter? */
	if (strlen(sdp) == 0)
		return NULL;

	return sdp;
}

/*
 * Calculate the content length of a SIP message body
 */
uint
dp_test_npf_sip_calc_content_length(const char *sip)
{
	const char *sdp;
	const char *end;

	/*
	 * Look for the separator between the message header and message body
	 */
	sdp = dp_test_npf_sip_get_sdp(sip);
	if (!sdp)
		return 0;

	end = sip + strlen(sip);

	return end - sdp;
}

/*
 * Get the content-length value from a SIP message string.  Sets the length in
 * the *clen parameter, and returns a pointer to the start of the number in
 * the message.
 */
char *
dp_test_npf_sip_get_content_length(const char *sip, uint *clen)
{
	char *cl, *start, *end;
	const char *clstr = "Content-Length:";

	cl = strcasestr(sip, clstr);
	if (!cl)
		return NULL;

	/*
	 * Find the first digit of the content-length number.  There will be
	 * at least one space between the colon and the first digit, possibly
	 * 3.
	 */
	start = cl + strlen(clstr);
	if (!isdigit(*start))
		while (*start && !isdigit(*++start))
			;
	if (!start)
		return NULL;

	/*
	 * Find the last digit of the content-length number. 'end' is set to
	 * point to the character just after the last digit.
	 */
	end = start;
	if (isdigit(*end))
		while (*end && isdigit(*++end))
			;
	if (!end)
		return NULL;

	if (clen) {
		ulong ul;

		ul = strtoul(start, NULL, 0);
		if (!ul || ul > UINT_MAX)
			return NULL;
		*clen = (uint)ul;
	}

	return start;
}

/*
 * Sets the content length value in a SIP message.  Returns a new string if
 * successful.
 */
char *
dp_test_npf_sip_set_content_length(const char *sip, uint clen)
{
	char *s, *new;
	char len_str[5];

	snprintf(len_str, sizeof(len_str), "%u", clen);

	/* Get pointer to start of the number */
	s = dp_test_npf_sip_get_content_length(sip, NULL);
	if (!s)
		return NULL;

	/* This mallocs more than we need, but who cares */
	new = malloc(strlen(sip) + strlen(len_str) + 1);
	new[0] = '\0';

	/* Pointer to offset */
	size_t insert_pos = s - sip;

	/* Copy the SIP message before the number */
	strncpy(new, sip, insert_pos);
	new[insert_pos] = '\0';

	/* Insert new number */
	strcat(new, len_str);

	/* Copy remainder of SIP message after the old number */
	strcat(new, s + strlen(len_str));

	return new;
}

/*
 * Calculate a SIP message content-length, malloc new message, set
 * content-length, and free old message.  Assumes the message passed in is
 * from malloc'd memory.
 */
char *
dp_test_npf_sip_reset_content_length(char *sip)
{
	uint cur, actual;
	char *tmp;

	if (dp_test_npf_sip_get_content_length(sip, &cur)) {

		actual = dp_test_npf_sip_calc_content_length(sip);

		if (cur != actual) {
			tmp = dp_test_npf_sip_set_content_length(sip, actual);

			dp_test_fail_unless(tmp, "setting content-length");
			free(sip);
			sip = tmp;
		}
	}
	return sip;
}

/*
 * Insert an SDP attribute to the SDP portion of a SIP message string, and
 * update the content-length field. e.g. an RTCP attribute:
 *
 * "a=rtcp:10003 IN IP4 192.168.1.2\r\n"
 *
 * might be inserted after "m=audio 60000 RTP/AVP 0\r\n" in an INVITE
 */
void
_dp_test_npf_sip_insert_attr(char **sipp, const char *after,
			     const char *attr, const char *file, int line)
{
	if (!sipp || !*sipp || !after || !attr)
		_dp_test_fail(file, line, "EINVAL");

	char *sip = *sipp, *tmp, *new;

	tmp = dp_test_str_insert_after(sip, after, attr);
	if (!tmp)
		_dp_test_fail(file, line,
			      "Failed to insert attribute \"%s\"", attr);

	/* This call takes care of freeing 'tmp' */
	new = dp_test_npf_sip_reset_content_length(tmp);

	_dp_test_fail_unless(
		new, file, line,
		"Failed to set content-length after inserting attribute");

	free(sip);
	*sipp = new;
}

/*
 * Split a SIP message into its constituent parts.  Returns a pointer to an
 * array of strings, each string being a SIP message part with the '\r\n'
 * delimiter removed.
 */
char **
dp_test_npf_sip_split(const char *sip, int *countp)
{
	char **arr;
	int i;

	/*
	 * Split the SIP message into its parts.
	 */
	arr = dp_test_str_split(sip, countp);
	if (!arr)
		return NULL;

	/*
	 * Remove the \r at the end of each string
	 */
	for (i = 0; i < *countp; ++i) {
		char *str = arr[i];
		size_t len = strlen(str);

		if (len > 0 && str[len - 1] == '\r')
			str[len - 1] = '\0';
	}

	return arr;
}

/*
 * Free an array previously created by dp_test_npf_sip_split
 */
void
dp_test_npf_sip_split_free(char **arr, int count)
{
	dp_test_str_split_free(arr, count);
}

/*
 * Combine a strings array (e.g. created by dp_test_npf_sip_split) into a SIP
 * message
 */
char *
dp_test_npf_sip_combine(char **arr, int count)
{
	size_t new_len = 1;
	char *new;
	int i;

	for (i = 0; i < count; i++) {
		if (strlen(arr[i]) > 0)
			new_len += strlen(arr[i]) + strlen(sip_delim);
		else
			new_len += strlen(sip_delim);
	}
	new = malloc(new_len);
	if (!new)
		return NULL;
	new[0] = '\0';

	for (i = 0; i < count; i++) {
		if (strlen(arr[i]) > 0) {
			strcat(new, arr[i]);
			strcat(new, sip_delim);
		} else {
			strcat(new, sip_delim);
		}
	}
	return new;
}
