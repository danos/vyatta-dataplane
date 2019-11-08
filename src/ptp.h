/*
 * Copyright (c) 2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PTP_H
#define PTP_H

#include "config.h"

int ptp_init(struct pci_list *bp_list);
int cmd_ptp_cfg(FILE *f, int argc, char **argv);
int cmd_ptp_op(FILE *f, int argc, char **argv);
int cmd_ptp_ut(FILE *f, int argc, char **argv);

#endif
