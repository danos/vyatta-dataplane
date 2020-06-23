/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * if_name_types.h
 *
 * This file exists purely to capture the semantics of interface names
 * until proper netlink message extensions (or other mechanisms)
 * can be used to convey interface attributes.
 */
#ifndef IF_NAME_TYPES_H
#define IF_NAME_TYPES_H

#include <string.h>
#include <ctype.h>

/*
 * Is the interface a dataplane/backplane port
 */
static inline bool is_dp_intf(const char *ifname)
{
	return (ifname[0] == 'd' || ifname[0] == 'b') && ifname[1] == 'p';
}

static inline bool is_l2tpeth(const char *ifname)
{
	return strncmp(ifname, "lttp", 4) == 0;
}

#endif
