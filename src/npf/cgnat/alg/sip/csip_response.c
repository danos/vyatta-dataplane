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
#include "npf/cgnat/alg/sip/csip_response.h"

/* Min length of strings we expect to find in SIP headers */
#define SIP_RESP_STARTLINE_MIN	((long)sizeof("SIP2/0 200") - 1)

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
uint csip_parse_response_start_line(struct bstr const *line, int *rc)
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
	if (!bstr_split_term_after(line, ' ', &head, &tail)) {
		*rc = -ALG_ERR_SIP_UNSP;
		return 0;
	}

	/* response code is second token; eat SP */
	struct bstr code;
	if (!bstr_split_term_after(&tail, ' ', &code, &tail) || code.len < 2) {
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
