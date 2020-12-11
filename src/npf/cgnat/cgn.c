/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
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
#include "npf/cgnat/cgn_errno.h"
#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_cmd_cfg.h"
#include "npf/cgnat/cgn_errno.h"
#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/nat/nat_pool_event.h"
#include "npf/nat/nat_pool_public.h"


/*
 * cgnat globals
 */

/* Hairpinning config enable/disable */
bool cgn_hairpinning_gbl = true;

/* snat-alg-bypass enable/disable */
bool cgn_snat_alg_bypass_gbl;

/*
 * Simple global counts for the number of dest addr (sess2) hash tables
 * created and destroyed.  These URCU hash tables are fairly resource
 * intensive, so we want to get some idea of how often they are required.
 */
rte_atomic64_t cgn_sess2_ht_created;
rte_atomic64_t cgn_sess2_ht_destroyed;

/*
 * Time in millisecs since Epoch, relative to soft_ticks==0.  This is
 * calculated once when the dataplane starts.  Its value may then be added to
 * soft_ticks in order to get a 'unix epoch' millisec time.
 */
static uint64_t cgn_epoch_ms;

/* Return code and error counters. */
struct cgn_rc_t *cgn_rc;

uint64_t cgn_rc_read(enum cgn_dir dir, enum cgn_rc_en rc)
{
	uint64_t sum;
	uint i;

	if (rc >= CGN_RC_SZ || dir >= CGN_DIR_SZ || !cgn_rc)
		return 0UL;

	sum = 0UL;
	FOREACH_DP_LCORE(i)
		sum += cgn_rc[i].dir[dir].count[rc];

	return sum;
}

void cgn_rc_clear(enum cgn_dir dir, enum cgn_rc_en rc)
{
	uint i;

	if (rc >= CGN_RC_SZ || dir >= CGN_DIR_SZ || !cgn_rc)
		return;

	FOREACH_DP_LCORE(i)
		cgn_rc[i].dir[dir].count[rc] = 0UL;
}

/*
 * Init cgnat global per-core return code counters
 */
static void cgn_rc_init(void)
{
	if (cgn_rc)
		return;

	cgn_rc = zmalloc_aligned((get_lcore_max() + 1) * sizeof(*cgn_rc));
}

static void cgn_rc_uninit(void)
{
	free(cgn_rc);
	cgn_rc = NULL;
}

/*
 * Dataplane uptime in seconds. Accurate to 10 millisecs.  Used to expire
 * table entries.
 */
uint32_t cgn_uptime_secs(void)
{
	return (uint32_t)(soft_ticks / 1000);
}

/*
 * Unix epoch time in microseconds.  Used for TCP 5-tuple sessions RTT
 * calculations.
 */
uint64_t cgn_time_usecs(void)
{
	struct timeval tod;

	gettimeofday(&tod, NULL);
	return (tod.tv_sec * 1000000) + tod.tv_usec;
}

/* Initialize cgn_epoch_ms */
static void cgn_init_time(void)
{
	cgn_epoch_ms = (cgn_time_usecs()) / 1000 - soft_ticks;
}

/*
 * Convert soft_ticks in millisecs to Epoch timestamp in microseconds
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
	cgn_rc_init();
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
	cgn_log_disable_all_handlers();
	cgn_rc_uninit();
}

/*
 * Callback for dataplane DP_EVT_IF_INDEX_UNSET event.
 */
static void
cgn_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused)
{
	/*
	 * For each policy on interface:
	 *  1. Clear sessions,
	 *  2. Remove policy from cgn_if list
	 *  3. Remove policy from hash table
	 *  4. Release reference on policy
	 * Free cgn_if
	 */
	cgn_if_disable(ifp);
}

/*
 * CGNAT Event Handler
 */
static const struct dp_event_ops cgn_event_ops = {
	.init = cgn_init,
	.uninit = cgn_uninit,
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
