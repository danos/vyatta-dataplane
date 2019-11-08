/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _NAT_CMD_CFG_H_
#define _NAT_CMD_CFG_H_

#include "npf/npf_addr.h"

/* npf_rule_gen.c */
int npf_parse_ip_addr(char *value, sa_family_t *fam, npf_addr_t *addr,
		      npf_netmask_t *masklen, bool *negate);

#endif
