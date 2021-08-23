/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef BACKPLANE_H
#define BACKPLANE_H

#include "config_internal.h"

int backplane_init(struct pci_list *bp_list);
int cmd_backplane_cfg(FILE *f, int argc, char **argv);
int cmd_backplane_op(FILE *f, int argc, char **argv);
int backplane_port_get_index(uint16_t dpdk_port, int *index);
int backplane_port_get_name(uint16_t dpdk_port, char **name);

#endif /* BACKPLANE_H */
