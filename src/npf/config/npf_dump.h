/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NPF_DUMP
#define NPF_DUMP

/**
 * Dumps all the rule-group information into a file
 *
 * @param fp file to write the information into.
 *
 * Note: the information is in json format.
 */
#include <stdio.h>

void npf_dump_rule_groups(FILE *fp);

/**
 * Dumps all the attach point information into a file
 *
 * @param fp file to write the information into.
 *
 * Note: the information is in json format.
 */
void npf_dump_attach_points(FILE *fp);

#endif
