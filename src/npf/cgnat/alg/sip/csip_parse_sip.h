/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */


#ifndef CSIP_PARSE_SIP_H
#define CSIP_PARSE_SIP_H

#include <stdint.h>
#include "npf/cgnat/alg/sip/csip_parse_utils.h"

struct bstr;

int csip_parse_start_line(struct bstr const *msg, enum csip_req *req,
			  unsigned int *resp_code);

bool csip_find_uri(struct bstr const *line, struct bstr *pre, struct bstr *host,
		   struct bstr *port, struct bstr *post);

#endif /* CSIP_PARSE_SIP_H */
