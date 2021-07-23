/*
 * Copyright (c) 2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef SFP_PERMIT_LIST_H
#define SFP_PERMIT_LIST_H

#define SFP_PERMIT_CONFIG_FILE "/var/run/vyatta/sfp_permit.conf"

int cmd_sfp_permit_op(FILE *f, int argc, char **argv);

void sfpd_process_presence_update(void);

#endif /* SFP_PERMIT_LIST_H */
