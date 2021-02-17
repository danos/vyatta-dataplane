/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef VYATTA_DATAPLANE_RCU_H
#define VYATTA_DATAPLANE_RCU_H

#include <rte_rcu_qsbr.h>

#include "urcu.h"
#include "util.h"

/*
 * The dataplane uses the QSBR flavour of userspace rcu
 * and DPDk's RCU QSBR implementation.
 */

/* dataplane global DPDK RCU QSBR variable */
extern struct rte_rcu_qsbr *dp_qsbr_rcu_v;

/*
 * Setup RCU usage in the dataplane.
 *
 * This performs all prep work for all the used RCU
 * implementations.
 *
 * Should be called only once by the main function/thread.
 *
 * DPDK QSBR RCU:
 * Allocates global DPDK RCU QSBR variable.
 *
 * userspace RCU:
 * No special setup required.
 */
int dp_rcu_setup(void);

/*
 * Register a thread for rcu. This is used when it is not known if a thread
 * is already rcu registered. If the thread is already registered then this
 * call will make the thread rcu_online.  If it is not registered then it
 * will register it, and part of registration is to make the thread
 * rcu_online.
 */
void dp_rcu_register_thread(void);

/*
 * Unregister a thread from rcu and track that it is no longer registered
 * so that further calls to dp_rcu_register_thread() will then re-register
 * it.
 */
void dp_rcu_unregister_thread(void);

/*
 * Get the dataplane global DPDK RCU QSBR variable.
 *
 * Use this method to make use of DPDK of rte_rcu_qsbr
 * aware APIs.
 */
struct rte_rcu_qsbr *dp_rcu_qsbr_get(void);

/*
 * Mark long periods of the thread/lcore_id as inactive.
 *
 * Reader threads should call this  prior the call blocking
 * methods/APIs.
 */
static __rte_always_inline void
dp_rcu_thread_offline(void)
{
	rcu_thread_offline();
	rte_rcu_qsbr_thread_offline(dp_qsbr_rcu_v, dp_lcore_id());
}

/*
 * Mark long periods of the thread/lcore_id as active again.
 * This should be called as counter operation to dp_rcu_thread_offline.
 */
static __rte_always_inline void
dp_rcu_thread_online(void)
{
	rcu_thread_online();
	rte_rcu_qsbr_thread_online(dp_qsbr_rcu_v, dp_lcore_id());
}

/*
 * Update the quiescent state for the reader threads.
 * All reader threads must call this periodically.
 */
static __rte_always_inline void
dp_rcu_quiescent_state(unsigned int lcore_id)
{
	rcu_quiescent_state();
	rte_rcu_qsbr_quiescent(dp_qsbr_rcu_v, lcore_id);
}

#endif /* VYATTA_DATAPLANE_RCU_H */
