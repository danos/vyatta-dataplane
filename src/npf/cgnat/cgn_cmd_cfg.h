/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_CMD_CFG_H_
#define _CGN_CMD_CFG_H_

#include "npf/npf_addr.h"

void cgn_cfg_replay(struct ifnet *ifp);
void cgn_cfg_replay_clear(struct ifnet *ifp);

/* npf_rule_gen.c */
int npf_parse_ip_addr(char *value, sa_family_t *fam, npf_addr_t *addr,
		      npf_netmask_t *masklen, bool *negate);

#endif
