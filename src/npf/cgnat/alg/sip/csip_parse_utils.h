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

struct csip_lines_meta {
	uint32_t capacity;
	uint32_t used;
};

struct csip_lines {
	struct csip_lines_meta m;
	struct bstr lines[];
};

/* Size of separating line between SIP and SDP msg header blocks */
#define SIP_SEPARATOR_SZ	((long)sizeof("\r\n") - 1)

bool csip_get_hline(struct bstr const *parent, struct bstr *headp, struct bstr *tailp);
bool csip_get_line(struct bstr const *parent, struct bstr *headp, struct bstr *tailp);
bool csip_split_lines(struct bstr const *msg, struct csip_lines *sip_lines);

bool csip_find_uri(struct bstr const *line, struct bstr *pre, struct bstr *host,
		   struct bstr *port, struct bstr *post);

#endif /* CSIP_PARSE_UTILS_H */
