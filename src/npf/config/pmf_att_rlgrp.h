/*
 * Copyright (c) 2019,2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef PMF_ATT_RLGRP_H
#define PMF_ATT_RLGRP_H

#include <stdio.h>

void pmf_arlg_init(void);
void pmf_arlg_commit(void);
void pmf_arlg_dump(FILE *fp);
int pmf_arlg_cmd_show_counters(FILE *fp, char const *ifname, int dir,
				char const *rgname);
int pmf_arlg_cmd_clear_counters(char const *ifname, int dir,
				char const *rgname);

#endif /* PMF_ATT_RLGRP_H */
