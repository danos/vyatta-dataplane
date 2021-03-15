/*
 * Copyright (c) 2020-2021 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GPC_ACL_CLI_H
#define GPC_ACL_CLI_H

#include <stdio.h>

void gpc_acl_dump(FILE *fp);
int gpc_acl_cmd_show_counters(FILE *fp, char const *ifname, int dir,
			      char const *rgname);
int gpc_acl_cmd_clear_counters(char const *ifname, int dir,
			       char const *rgname);

#endif /* GPC_ACL_CLI_H */
