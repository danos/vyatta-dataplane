/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_TIME_H_
#define _CGN_TIME_H_

/* Dataplane uptime in seconds. Accurate to 10 millisecs. */
uint32_t cgn_uptime_secs(void);

/* Unix epoch time in microseconds. */
uint64_t cgn_time_usecs(void);

/* Convert a soft_ticks value in milliseconds to an Epoch time in microsecs */
uint64_t cgn_ticks2timestamp(uint64_t ticks);

/* Convert start time in soft_ticks into duration in microseconds */
uint64_t cgn_start2duration(uint64_t start_time);

void cgn_init_time(void);

#endif
