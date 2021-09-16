/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */


#ifndef CSIP_PARSE_SDP_H
#define CSIP_PARSE_SDP_H

#include <stdint.h>

struct csip_lines;

bool csip_classify_sdp(struct csip_lines *sip_lines, uint32_t index);

#endif /* CSIP_PARSE_SDP_H */
