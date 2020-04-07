/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * IP address/routing glue routines
 *
 */
#ifndef ADDRESS_H
#define ADDRESS_H

#include <linux/rtnetlink.h>

#include "util.h"

/*
 * Bit list to pass info to netlink handler for address family
 * Lowest 2 octets reserved for netlink msg flags
 */
#define NL_FLAG_ANY_ADDR	0x10000

void inet_netlink_init(void);
void local_addr_init(void);
void add_local_addr(vrfid_t vrf_id, int family, const void *addr);
void remove_local_addr(vrfid_t vrf_id, int family, const void *addr);
void nat_ifaddr_change(int family, int ifindex, struct in_addr *addr);

#endif
