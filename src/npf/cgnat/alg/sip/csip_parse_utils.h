/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */


#ifndef CSIP_PARSE_UTILS_H
#define CSIP_PARSE_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include "npf/cgnat/cgn_dir.h"

struct bstr;

bool csip_get_hline(struct bstr const *parent, struct bstr *headp, struct bstr *tailp);

#endif /* CSIP_PARSE_UTILS_H */
