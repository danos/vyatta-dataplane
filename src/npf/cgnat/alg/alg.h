/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef ALG_H
#define ALG_H

#include "npf/cgnat/alg/alg_defs.h"

/**
 * ALG ID to name
 *
 * @param id ALG ID
 * @return ALG name if found, else "-"
 */
const char *cgn_alg_id_name(enum cgn_alg_id id);

#endif /* ALG_H */
