/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_debug.h>

#include "nh_common.h"

/*
 * use entry 0 for AF_INET
 * use entry 1 for AF_INET6
 */
struct nh_common nh_common_af[2];

void nh_common_register(int family, struct nh_common *nh_common)
{
	if (family == AF_INET) {
		nh_common_af[0] = *nh_common;
		return;
	}

	if (family == AF_INET6) {
		nh_common_af[1] = *nh_common;
		return;
	}

	rte_panic("Invalid family %d for nh registration\n", family);
}
