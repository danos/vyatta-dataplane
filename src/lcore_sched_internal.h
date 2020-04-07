/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef LCORE_SCHED_INTERNAL_H
#define LCORE_SCHED_INTERNAL_H

#include <stdint.h>

/*
 * Run all the registered per lcore init functions.
 */
void dp_lcore_events_init(unsigned int lcore_id);

/*
 * Run all the registered per lcore teardown functions.
 */
void dp_lcore_events_teardown(unsigned int lcore_id);

#endif /* LCORE_SCHED_INTERNAL_H */
