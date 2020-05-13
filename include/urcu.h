/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Dataplane uses Userspace RCU in accordance with Dynamic only linking
 * See userspace-rcu/LICENSE
 */
#ifndef VYATTA_DATAPLANE_URCU_H
#define VYATTA_DATAPLANE_URCU_H

/*
 * This file is used to make it easy to include the correct urcu headers.
 * The dataplane uses the QSBR flavour of userspace rcu.
 */

/* Allow URCU to inline small functions
 * performance vs shared library upgrade tradeoff
 */
#define URCU_INLINE_SMALL_FUNCTIONS 1

#include <urcu-qsbr.h>
#include <urcu-call-rcu.h>
#include <urcu/rculfhash.h>
#include <urcu/rculist.h>

/*
 * Register a thread for rcu. This is used when it is not known if a thread
 * is already rcu registered. If the thread is already registered then this
 * call will make the thread rcu_online.  If it is not registered then it
 * will register it, and part of registration is to make the thread
 * rcu_online.
 */
void dp_rcu_register_thread(void);

#endif /* VYATTA_DATAPLANE_URCU_H */
