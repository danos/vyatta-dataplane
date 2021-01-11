/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef _SOFT_TICKS_H_
#define _SOFT_TICKS_H_

/*
 * Export of soft_ticks from controller.c
 */

/* Milliseconds.  Updated every 10 milliseconds. */
extern volatile uint64_t soft_ticks;

#endif /* _SOFT_TICKS_H_ */
