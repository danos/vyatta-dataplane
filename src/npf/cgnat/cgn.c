/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn.c - CGNAT module init and uninit and other global functions.
 */

#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "compiler.h"
#include "if_var.h"
#include "util.h"
#include "soft_ticks.h"
#include "dp_event.h"

#include "npf/cgnat/cgn.h"
#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_errno.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/nat/nat_pool_event.h"
#include "npf/nat/nat_pool_public.h"


/*
 * cgnat globals
 */

/* Hairpinning config enable/disable */
bool cgn_hairpinning_gbl = true;

/* Time in millisecs since Epoch relative to soft_ticks==0 */
static uint64_t cgn_epoch_ms;

static void cgn_init_time(void)
{
	struct timeval tod;
	uint64_t ms;

	gettimeofday(&tod, NULL);

	ms = (tod.tv_sec * 1000) + (tod.tv_usec / 1000);
	cgn_epoch_ms = ms - soft_ticks;
}

/*
 * Convert soft_ticks in millisecs to Epoch timestamp in microseconds.
 */
uint64_t cgn_ticks2timestamp(uint64_t ticks)
{
	return (cgn_epoch_ms + ticks) * 1000;
}

/*
 * Convert start time in soft_ticks into duration in microseconds.
 */
uint64_t cgn_start2duration(uint64_t start_time)
{
	return (soft_ticks - start_time) * 1000;
}

/*
 * Extract an integer from a string
 */
int cgn_arg_to_int(const char *arg)
{
	char *p;
	unsigned long val = strtoul(arg, &p, 10);

	if (p == arg || val > INT_MAX)
		return -1;

	return (uint32_t) val;
}

/*
 * Format an IPv4 host-byte ordered address
 */
char *cgn_addrstr(uint32_t addr, char *str, size_t slen)
{
	snprintf(str, slen, "%u.%u.%u.%u",
		 (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
		 (addr >>  8) & 0xFF, addr & 0xFF);
	return str;
}

/*
 * NAT pool has been de-activated.  Clear all sessions and mappings that
 * derive from this nat pool.
 */
static void cgn_np_inactive(struct nat_pool *np)
{
	if (nat_pool_type_is_cgnat(np))
		cgn_session_expire_pool(true, np, true);
}

/* NAT pool event handlers */
static const struct np_event_ops cgn_np_event_ops = {
	.np_inactive = cgn_np_inactive,
};

/* Register with NAT pool event handler */
static void cgn_nat_pool_event_init(void)
{
	if (!nat_pool_event_register(&cgn_np_event_ops))
		RTE_LOG(ERR, CGNAT, "Failed to register with NAT pool\n");
}

/*
 * DP_EVT_INIT event handler
 */
static void cgn_init(void)
{
	cgn_nat_pool_event_init();
	cgn_policy_init();
	cgn_session_init();
	cgn_source_init();
	apm_init();
	cgn_init_time();
}

/*
 * DP_EVT_UNINIT event handler
 */
static void cgn_uninit(void)
{
	cgn_session_uninit();
	apm_uninit();
	cgn_source_uninit();
	cgn_policy_uninit();
}

/*
 * CGNAT Event Handler
 */
static const struct dp_event_ops cgn_event_ops = {
	.init = cgn_init,
	.uninit = cgn_uninit,
	.if_index_set = cgn_event_if_index_set,
	.if_index_unset = cgn_event_if_index_unset,
};

/* Register event handler */
DP_STARTUP_EVENT_REGISTER(cgn_event_ops);


/* Called from unit-tests */
void dp_test_npf_clear_cgnat(void)
{
	cgn_session_cleanup();
	apm_cleanup();
	cgn_source_cleanup();
}
