/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */


#ifndef CSIP_RESPONSE_H
#define CSIP_RESPONSE_H

#include "npf/cgnat/alg/sip/csip_defs.h"

struct bstr;

uint csip_parse_response_start_line(struct bstr const *line, int *rc);

#endif /* CSIP_RESPONSE_H */
