/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */


#ifndef CSIP_REQUEST_H
#define CSIP_REQUEST_H

#include "npf/cgnat/alg/sip/csip_defs.h"

struct bstr;

enum csip_req csip_parse_request_start_line(struct bstr const *line, int *rc);

#endif /* CSIP_REQUEST_H */
