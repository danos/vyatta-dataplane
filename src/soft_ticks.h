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

/*
 * Return soft_ticks value, with option to refresh it.  If refreshed then
 * it will be accurate to 1ms, else it may be up to 10ms slow.
 */
uint64_t get_soft_ticks(bool refresh);

/*
 * Get unix epoch in microsecs. Updated every 10ms by default.  If 'refresh'
 * is true then it is updated when this is called, and should be accurate to
 * 1ms.
 */
uint64_t unix_epoch_us(bool refresh);

#endif /* _SOFT_TICKS_H_ */
