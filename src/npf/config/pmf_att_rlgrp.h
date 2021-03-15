/*
 * Copyright (c) 2019,2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef PMF_ATT_RLGRP_H
#define PMF_ATT_RLGRP_H

#include <stdint.h>

void pmf_arlg_init(void);
void pmf_arlg_commit(void);

void *pmf_arlg_earg_get_attr_rule(void *earg);
uint32_t pmf_arlg_earg_get_rule_count(void *earg);

#endif /* PMF_ATT_RLGRP_H */
