/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_CMD_CFG_H_
#define _CGN_CMD_CFG_H_

#include "npf/npf_addr.h"

/* Extract int from string */
int cgn_arg_to_int(const char *arg);

/* npf_rule_gen.c */
int npf_parse_ip_addr(char *value, sa_family_t *fam, npf_addr_t *addr,
		      npf_netmask_t *masklen, bool *negate);

#endif /* CGN_CMD_CFG_H */
