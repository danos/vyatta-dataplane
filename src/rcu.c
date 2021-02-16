/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

#include <rte_malloc.h>
#include <rte_errno.h>

#include "debug.h"
#include "util.h"

#include "rcu.h"

struct rte_rcu_qsbr *dp_qsbr_rcu_v;

static __thread int rcu_qsbr_registered;

int dp_rcu_qsbr_setup(void)
{
	size_t sz;

	if (dp_qsbr_rcu_v)
		return 0;

	/* Allocate global DPDK QSBR RCU variable */
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	dp_qsbr_rcu_v = rte_zmalloc(NULL, sz, RTE_CACHE_LINE_SIZE);
	if (!dp_qsbr_rcu_v) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate DPDK QSBR RCU variable\n");
		return -ENOMEM;
	}

	if (rte_rcu_qsbr_init(dp_qsbr_rcu_v, RTE_MAX_LCORE)) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to initialize DPDK QSBR RCU variable\n");
		return -rte_errno;
	}

	return 0;
}

struct rte_rcu_qsbr *dp_rcu_qsbr_get(void)
{
	return dp_qsbr_rcu_v;
}

void dp_rcu_qsbr_register_thread(unsigned int lcore_id)
{
	if (rcu_qsbr_registered++ == 0) {
		/*
		 * Register to DPDK RCU QSBR variable
		 */

		rte_rcu_qsbr_thread_register(dp_qsbr_rcu_v, lcore_id);
		rte_rcu_qsbr_thread_online(dp_qsbr_rcu_v, lcore_id);
	}
}

void dp_rcu_qsbr_unregister_thread(unsigned int lcore_id)
{
	if (--rcu_qsbr_registered == 0) {
		/*
		 * Unregister from DPDK RCU QSBR variable
		 */

		rte_rcu_qsbr_thread_offline(dp_qsbr_rcu_v, lcore_id);
		rte_rcu_qsbr_thread_unregister(dp_qsbr_rcu_v, lcore_id);
	}
}

static __thread int rcu_registered;

void dp_rcu_register_thread(void)
{
	if (rcu_registered++ == 0)
		rcu_register_thread();
}

void dp_rcu_unregister_thread(void)
{
	if (--rcu_registered == 0)
		rcu_unregister_thread();
}
