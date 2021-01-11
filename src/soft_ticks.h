/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef _SOFT_TICKS_H_
#define _SOFT_TICKS_H_

/*
 * Export of soft_ticks etc. from controller.c
 *
 * get_dp_uptime() may also be used to return the dataplane uptime in seconds.
 * (This is also derived from soft_ticks)
 */

/* Milliseconds since dataplane started. Updated every 10ms */
extern volatile uint64_t soft_ticks;

/* Microsecs since dataplane started. Updated every 10ms */
extern uint64_t soft_ticks_us;

/* Unix epoch in microsecs. Updated every 10ms. */
extern uint64_t unix_epoch_us;

#endif /* _SOFT_TICKS_H_ */
