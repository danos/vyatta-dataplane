/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * alg_pinhole.h - ALG Pinhole table
 */

#ifndef ALG_PINHOLE_H
#define ALG_PINHOLE_H

#include <stdint.h>

#include "npf/cgnat/cgn_dir.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/alg/alg_defs.h"

/**
 * Create pinhole table
 */
int alg_pinhole_init(void);

/**
 * Destroy pinhole table
 */
void alg_pinhole_uninit(void);

#endif /* ALG_PINHOLE_H */
