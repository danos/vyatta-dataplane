/*
 * Public functions defined in ip_options.c
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef IP_OPTIONS_H
#define IP_OPTIONS_H

#include <stdbool.h>

struct rte_mbuf;

int ip_dooptions(struct rte_mbuf *m, bool *ra_present);

#endif /* IP_OPTIONS_H */
