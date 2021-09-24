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
