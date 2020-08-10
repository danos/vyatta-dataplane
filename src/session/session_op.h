/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef SESSION_OP_H
#define SESSION_OP_H

#include <arpa/inet.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <urcu/list.h>

int cmd_op_list(FILE *f, int argc, char **argv);

#endif /* SESSION_OP_H */
