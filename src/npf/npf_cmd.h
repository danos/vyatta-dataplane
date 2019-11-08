/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NPF_CMD
#define NPF_CMD

#include <czmq.h>
#include <stdio.h>

#include "npf/config/npf_attach_point.h"

typedef int (*npf_cmd_handler)(FILE *, int, char **);

struct npf_command {
	npf_cmd_handler handler;
	const char *tokens;
};

extern const char npf_cmd_str_unknown[];
extern const char npf_cmd_str_missing[];
extern const char npf_cmd_str_missing_arg[];
extern const char npf_cmd_str_too_many_chars[];

zhash_t *npf_cmd_hash_init(struct npf_command const cmd_table[], unsigned int);
npf_cmd_handler npf_cmd_find(zhash_t *cmds, char **c, int *depth,
			     npf_cmd_handler h);
void npf_cmd_dump(zhash_t *cmds, int depth);
void npf_cmd_err(FILE *f, const char *format, ...);
int npf_cmd_handle(FILE *f, int argc, char **argv, zhash_t *cmds);

int npf_str2ap_type_and_point(char *word, enum npf_attach_type *attach_type,
			      const char **attach_point);
int npf_extract_class_and_group(char *word, enum npf_rule_class *group_class,
				char **group);

int cmd_show_rulesets(FILE *f, int argc, char **argv);

#endif
