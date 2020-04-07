/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GROUPER2_H
#define GROUPER2_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "npf/npf.h"
#include "npf/npf_ruleset.h"

typedef struct g2_config g2_config_t;
typedef void *g2_handle_t;
typedef	bool (*process_callback)(void *, void *);

g2_config_t *g2_init(uint num_tables);
bool g2_create_rule(g2_config_t *conf, rule_no_t rule_no, void *match_data);
bool g2_add(g2_config_t *conf, uint table, uint ntables,
	    const uint8_t *match, const uint8_t *mask);
void g2_optimize(g2_config_t **confp);
void *g2_eval4(const g2_config_t *conf, const uint8_t *packet,
	       const void *data);
void *g2_eval6(const g2_config_t *conf, const uint8_t *packet,
	       const void *data);
void g2_destroy(g2_config_t **confp);

#endif /* GROUPER2_H */
