/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef CSIP_PARSE_UTILS_H
#define CSIP_PARSE_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include "npf/bstr.h"
#include "npf/cgnat/cgn_dir.h"
#include "npf/cgnat/alg/sip/csip_defs.h"

/*
 * struct csip_line references one line of a SIP (or SIP+SDP) message.
 *
 * It references a line in a SIP message in a packet buffer, or in a new
 * message buffer on the stack.
 */
struct csip_line {
	struct bstr b;
	enum csip_line_type type;
	union {
		enum csip_req	req;	/* type SIP_LINE_REQ */
		uint		resp;	/* type SIP_LINE_RESP */
		enum csip_hdr_type sip;	/* type SIP_LINE_SIP */
		enum csdp_hdr_type sdp;	/* type SIP_LINE_SDP */
	};
};

/*
 * Meta data for SIP message line overlay
 */
struct csip_lines_meta {
	uint32_t capacity;

	/* Index of first and last SIP lines */
	uint32_t sip_first;
	uint32_t sip_last;

	/* Index of first and last SDP lines */
	uint32_t sdp_first;
	uint32_t sdp_last;

	/* index to first occurrence of each SIP line type */
	uint32_t sip_index[SIP_HDR_MAX];
};

/*
 * Array of lines.  Each line is a bstr string containing a SIP or SDP message
 * header line.
 */
struct csip_lines {
	struct csip_lines_meta m;
	struct csip_line lines[];
};

/* Size of separating line between SIP and SDP msg header blocks */
#define SIP_SEPARATOR_SZ	((long)sizeof("\r\n") - 1)

/* Approx minimum length of line (excluding SIP/SDP separator line) */
#define SIP_LINE_MIN		((long)sizeof("x=y\r\n") - 1)

bool csip_get_hline(struct bstr const *parent, struct bstr *headp, struct bstr *tailp);
bool csip_get_line(struct bstr const *parent, struct bstr *headp, struct bstr *tailp);
bool csip_split_lines(struct bstr const *msg, struct csip_lines *sip_lines);

bool csip_find_uri(struct bstr const *line, struct bstr *pre, struct bstr *host,
		   struct bstr *port, struct bstr *post);

bool csip_find_and_translate_uri(struct bstr const *line, struct bstr *new,
				 struct bstr const *oaddr, struct bstr const *oport,
				 struct bstr const *taddr, struct bstr const *tport);

#endif /* CSIP_PARSE_UTILS_H */
