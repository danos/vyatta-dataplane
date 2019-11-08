/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Dataplane uses Userspace RCU in accordance with Dynamic only linking
 * See userspace-rcu/LICENSE
 */
#ifndef URCU_H
#define URCU_H

/* Allow URCU to inline small functions
 * performance vs shared library upgrade tradeoff
 */
#define URCU_INLINE_SMALL_FUNCTIONS 1

#include <urcu-qsbr.h>
#include <urcu-call-rcu.h>
#include <urcu/rculfhash.h>
#include <urcu/rculist.h>
#endif /* URCU_H */
