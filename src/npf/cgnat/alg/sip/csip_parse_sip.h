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

int csip_parse_start_line(struct bstr const *line, enum csip_req *req,
			  unsigned int *resp_code);

#endif /* CSIP_PARSE_SIP_H */
