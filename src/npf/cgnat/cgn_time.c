/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <time.h>

#include "compiler.h"
#include "util.h"
#include "soft_ticks.h"

#include "npf/cgnat/cgn_time.h"

/*
 * Time in millisecs since Epoch, relative to soft_ticks==0.  This is
 * calculated once when the dataplane starts.  Its value may then be added to
 * soft_ticks in order to get a 'unix epoch' millisec time.
 */
static uint64_t cgn_epoch_ms;

/*
 * Dataplane uptime in seconds. Accurate to 10 millisecs.  Used to expire
 * session table entries.
 */
uint32_t cgn_uptime_secs(void)
{
	return (uint32_t)(soft_ticks / 1000);
}

/*
 * Unix epoch time in microseconds.  Used to set 2-tuple sub-session start
 * time (s2_start_time), which is subsequently used for TCP 5-tuple sessions
 * RTT calculations, session logging, and show output.
 */
uint64_t cgn_time_usecs(void)
{
	struct timeval tod;

	gettimeofday(&tod, NULL);
	return (tod.tv_sec * 1000000) + tod.tv_usec;
}

/*
 * Convert start time in soft_ticks into duration in microseconds.  3-tuple
 * main sessions () and 'source' objects will record their start time using this
 * function.
 */
uint64_t cgn_start2duration(uint64_t start_time)
{
	return (soft_ticks - start_time) * 1000;
}

/*
 * Convert soft_ticks in millisecs to Epoch timestamp in microseconds.  Used
 * for logging and show commands.
 */
uint64_t cgn_ticks2timestamp(uint64_t ticks)
{
	return (cgn_epoch_ms + ticks) * 1000;
}

/* Initialize cgn_epoch_ms */
void cgn_init_time(void)
{
	cgn_epoch_ms = (cgn_time_usecs()) / 1000 - soft_ticks;
}
