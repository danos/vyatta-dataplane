/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * storm control command handling
 */
#ifndef STORM_CTL_H
#define STORM_CTL_H

#include "urcu.h"

int cmd_storm_ctl_cfg(FILE *f, int argc, char **argv);
int cmd_storm_ctl_op(FILE *f, int argc, char **argv);
const char *storm_ctl_traffic_type_to_str(enum fal_traffic_type tr_type);

#endif
