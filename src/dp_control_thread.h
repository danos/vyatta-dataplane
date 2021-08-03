/*
 * Copyright (c) 2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef DP_CONTROL_THREAD_H
#define DP_CONTROL_THREAD_H

#include <pthread.h>

/* Initialized the dp_control_thread API.
 * Needs to be called once during startup.
 */
void dp_control_thread_init(void);

/* Register a control thread.
 *
 * Must be called by the thread itself.
 *
 * Control threads receive following benefits:
 * - CPU affinity management
 *
 * If a control thread gets terminated, it needs to unregister
 * by calling dp_control_thread_unregister().
 */
int dp_control_thread_register(void);

/* Unregister a control thread.
 *
 * Must be called by the thread itself.
 */
void dp_control_thread_unregister(void);

/* Update affinity for all registered control threads. */
int dp_control_thread_set_affinity(cpu_set_t *cpuset);

#endif /* DP_CONTROL_THREAD_H */
