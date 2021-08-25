/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _PMF_DUMP_H_
#define _PMF_DUMP_H_

#include "json_writer.h"

struct pmf_rule;
void pmf_dump_rule_json(struct pmf_rule *rule, json_writer_t *json);

#endif /* PMF_DUMP_H */
