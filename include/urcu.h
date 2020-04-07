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
#endif /* VYATTA_DATAPLANE_URCU_H */
