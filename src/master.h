/*-
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * master loop api
 */
#ifndef MASTER_H
#define MASTER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "control.h"
#include "compat.h"

void master_loop(void);
void reset_dataplane(enum cont_src_en cont_src, bool delay);
int setup_interface_portid(portid_t portid);
int teardown_interface_portid(portid_t portid);

int cmd_master(FILE *f, int argc, char **argv);

bool dp_test_master_ready(enum cont_src_en cont_src);

int send_dp_event(zmsg_t *msg);

/* For whole dp tests */
void enable_soft_clock_override(void);
void disable_soft_clock_override(void);

#endif /* MASTER_H */
