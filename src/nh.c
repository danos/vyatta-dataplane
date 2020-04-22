/*
 * Copyright (c) 2017,2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "nh.h"


ALWAYS_INLINE const struct in_addr *
dp_nh4_get_addr(const struct next_hop *next_hop)
{
	return (struct in_addr *)&next_hop->gateway4;
}

ALWAYS_INLINE const struct in6_addr *
dp_nh6_get_addr(const struct next_hop *next_hop)
{
	return &next_hop->gateway6;
}
