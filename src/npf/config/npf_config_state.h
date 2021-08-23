/*
 * Copyright (c) 2018-2019,2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _NPF_CONFIG_STATE_H_
#define _NPF_CONFIG_STATE_H_

#include <stdbool.h>
#include <stdio.h>
#include "npf/npf_ruleset.h"

/*
 * This returns json for ruleset state, i.e. basic info of per-rule byte and
 * packet counts
 */
int npf_show_ruleset_state(FILE *fp, struct ruleset_select *sel);

#endif /* NPF_CONFIG_STATE_H */
