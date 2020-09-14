/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file nat_pool_event.c - NAT address pool events
 */

#include <stdint.h>
#include <stdio.h>
#include <rte_atomic.h>
#include "util.h"

#include "npf/nat/nat_pool.h"
#include "npf/nat/nat_pool_event.h"

/*
 * Fixed size array for holding event operations pointers.
 */
static struct np_event_ops *np_ops[NP_EVENT_MAX_OPS];

/* Process the event for all registered operations */
static void np_evt_notify(enum np_evt evt, struct np_event_ops *ops,
			  struct nat_pool *np)
{
	switch (evt) {
	case NP_EVT_CREATE:
		if (ops->np_create)
			ops->np_create(np);
		break;
	case NP_EVT_DELETE:
		if (ops->np_delete)
			ops->np_delete(np);
		break;
	case NP_EVT_ACTIVE:
		if (ops->np_active)
			ops->np_active(np);
		break;
	case NP_EVT_INACTIVE:
		if (ops->np_inactive)
			ops->np_inactive(np);
		break;
	}
}

/* Process a nat pool event */
void nat_pool_event(enum np_evt evt, struct nat_pool *np)
{
	struct np_event_ops *ops;
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(np_ops); i++) {
		ops = rcu_dereference(np_ops[i]);
		if (ops)
			np_evt_notify(evt, ops, np);
	}
}

/* Register event ops */
bool nat_pool_event_register(const struct np_event_ops *ops)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(np_ops); i++) {
		if (!rcu_cmpxchg_pointer(&np_ops[i], NULL,
					(struct np_event_ops *)ops))
			return true;
	}
	return false;
}
