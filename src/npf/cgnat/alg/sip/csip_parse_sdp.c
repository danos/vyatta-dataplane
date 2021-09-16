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

#include "npf/bstr.h"
#include "npf/cgnat/alg/alg.h"
#include "npf/cgnat/alg/alg_rc.h"
#include "npf/cgnat/alg/sip/csip_defs.h"
#include "npf/cgnat/alg/sip/csip_parse_sdp.h"
#include "npf/cgnat/alg/sip/csip_parse_utils.h"

/*
 * Classify an SDP message line
 */
bool csip_classify_sdp(struct csip_lines *sip_lines, uint32_t index)
{
	struct csip_line *line = &sip_lines->lines[index];
	uint8_t c;

	if (!bstr_get_byte(&line->b, 0, &c)) {
		line->sdp = SDP_HDR_OTHER;
		return false;
	}

	switch (c) {
	case 'c':
		line->sdp = SDP_HDR_CONN;
		break;
	case 'o':
		line->sdp = SDP_HDR_ORIGIN;
		break;
	case 'm':
		line->sdp = SDP_HDR_MEDIA;
		break;
	case 'a':
		/* We are only interested in two specific attribute headers */
		if (bstr_prefix(&line->b, BSTRL("a=rtcp:")))
			line->sdp = SDP_HDR_ATTR_RTCP;
		else if (bstr_prefix(&line->b, BSTRL("a=rtcp-mux")))
			line->sdp = SDP_HDR_ATTR_RTCP_MUX;
		else
			line->sdp = SDP_HDR_OTHER;
		break;
	default:
		line->sdp = SDP_HDR_OTHER;
		break;
	};
	return true;
}
