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

bool csip_classify_sip_start(struct csip_lines *sip_lines);
bool csip_classify_sip(struct csip_lines *sip_lines, uint32_t index);

bool csip_parse_sip_callid(struct bstr const *line, struct bstr *callid);
bool csip_sip_content_type_is_sdp(struct bstr const *line);
bool csip_parse_sip_user_agent(struct bstr const *line, struct bstr *user_agent);

#endif /* CSIP_PARSE_SIP_H */
