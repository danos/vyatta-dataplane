/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * main loop api
 */
#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "control.h"
#include "compat.h"

void main_loop(void);
void reset_dataplane(enum cont_src_en cont_src, bool delay);
int setup_interface_portid(portid_t portid);
int teardown_interface_portid(portid_t portid);

int cmd_main(FILE *f, int argc, char **argv);

bool dp_test_main_ready(enum cont_src_en cont_src);

/* For whole dp tests */
void enable_soft_clock_override(void);
void disable_soft_clock_override(void);

#endif /* CONTROLLER_H */
