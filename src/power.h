/*-
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef POWER_H
#define POWER_H


#include <rte_memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* Parameters relating to performance versus power trade off */
struct power_profile {
	const char *name;
	unsigned int idle_thresh;   /* number of misses before sleeping */
	unsigned int min_sleep;	  /* min us of sleep */
	unsigned int max_sleep;	  /* max us of sleep */
} __rte_cache_aligned;

/* Power management and poll loop parameters */
#define USLEEP_MAX		10000u	/* 10ms i.e. all links down */

/* Time to sleep for when all links down */
#define LCORE_IDLE_SLEEP_SECS		1

struct pm_governor {
	bool	  overrun;	/* got more than one packet */
	uint32_t  idle;		/* # of times poll ret no packets */
	uint32_t  nap;		/* sleep interval (us) */
};

/*
 * Update governor based on number of packets found by poll.
 * This provides hints about whether next interval should
 * be faster or slower.
 */
static inline void pm_update(struct pm_governor *g, unsigned int n)
{
	if (n == 0)
		++g->idle;
	else {
		g->idle = 0;
		if (n > 1)
			g->overrun = true;
	}
}

/*
 * Compute optimum sleep interval based on poll results
 *
 * if not keeping up, then sleep less (cut by half)
 * if no packets for long interval, sleep more
 */
static inline uint32_t pm_interval(const struct power_profile *pm,
				   struct pm_governor *g)
{
	if (g->overrun) {
		g->overrun = false;
		g->nap /= 2;
		g->idle = 0;
	} else if (g->idle > pm->idle_thresh) {
		if (g->nap < pm->max_sleep) {
			g->idle = 0;
			++g->nap;
		}
	}

	return g->nap;
}

const struct power_profile *get_current_pm(void);
int cmd_power_show(FILE *f, int argc, char **argv);
int cmd_power_cfg(FILE *f, int argc, char **argv);

#endif /* POWER_H */
