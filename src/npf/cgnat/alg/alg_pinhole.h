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

struct alg_pinhole;
struct cgn_session;

/**
 * Accessor to pinhole ALG ID
 */
enum cgn_alg_id alg_pinhole_alg_id(struct alg_pinhole *ap);

/**
 * Accessor to pinhole session pointer
 */
struct cgn_session *alg_pinhole_cse(struct alg_pinhole *ap);

/**
 * Create pinhole table
 */
int alg_pinhole_init(void);

/**
 * Destroy pinhole table
 */
void alg_pinhole_uninit(void);

#endif /* ALG_PINHOLE_H */
