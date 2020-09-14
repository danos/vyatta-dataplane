/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _NAT_POOL_EVENT_H_
#define _NAT_POOL_EVENT_H_

struct nat_pool;

/*
 * Maximum size of the event operations structs array.
 */
#define NP_EVENT_MAX_OPS	8

enum np_evt {
	/*
	 * NAT pool has been created and added to nat pool hash table (but is
	 * not yet active).  nat pool hash table exists only to allow config
	 * to lookup a nat pool with a name.
	 */
	NP_EVT_CREATE = 1,
	/*
	 * NAT pool has been unconfigured and removed from nat pool hash
	 * table.  (Should already be in-active)
	 */
	NP_EVT_DELETE,
	/*
	 * NAT pool has been activated.  May be used for mappings.
	 */
	NP_EVT_ACTIVE,
	/*
	 * NAT pool has been de-activated.  May no longer be used for
	 * mappings.  Clients must clear all existing mappings and sessions.
	 * This will occur for some config changes to the pool, e.g. port
	 * block size.
	 */
	NP_EVT_INACTIVE,
};

/* Event operations - 1:1 correspondence with above events */
struct np_event_ops {
	void (*np_create)(struct nat_pool *np);
	void (*np_delete)(struct nat_pool *np);
	void (*np_active)(struct nat_pool *np);
	void (*np_inactive)(struct nat_pool *np);
};

/* Process a nat pool event */
void nat_pool_event(enum np_evt evt, struct nat_pool *np);

/* Register event ops */
bool nat_pool_event_register(const struct np_event_ops *ops);

#endif /* _NAT_POOL_EVENT_H_ */
