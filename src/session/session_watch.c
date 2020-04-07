/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <urcu-qsbr.h>

#include "dp_session.h"
#include "npf/npf_state.h"
#include "session/session.h"
#include "session/session_watch.h"

/*
 * Hold session watch pointer.
 */
struct session_watch_info {
	struct session_watch *watch;
	bool watch_on;
};

static struct session_watch_info watch_ctx;

int dp_session_watch_register(struct session_watch *se_watch)
{
	if (!rcu_cmpxchg_pointer(&watch_ctx.watch, NULL, se_watch)) {
		watch_ctx.watch_on = true;
		return 0;
	}

	return -EBUSY;
}

int dp_session_watch_unregister(int watcher_id __unused)
{
	struct session_watch **p = &watch_ctx.watch;
	uint8_t old = watch_ctx.watch_on;

	watch_ctx.watch_on = false;
	if (rcu_xchg_pointer(p, NULL) != NULL)
		return 0;
	watch_ctx.watch_on = old;
	return -ENOENT;
}

bool is_watch_on(void)
{
	return watch_ctx.watch_on;
}

static struct session_watch *session_watch_get(void)
{
	struct session_watch *p = rcu_dereference(watch_ctx.watch);
	return p;
}

static bool check_session_type(struct session *session, unsigned int flags)
{
	if (dp_is_session_type(flags, FW) && !session_is_nat(session)
	    && !session_is_nat64(session) && !session_is_nat46(session)
	    && !session_is_alg(session))
		return true;
	if (dp_is_session_type(flags, NAT) && session_is_nat(session))
		return true;
	if (dp_is_session_type(flags, NAT64) && session_is_nat64(session))
		return true;
	if (dp_is_session_type(flags, NAT46) && session_is_nat46(session))
		return true;
	if (dp_is_session_type(flags, ALG) && session_is_alg(session))
		return true;

	return false;
}

/*
 * call notfication function for established sessions.
 * The call back function is called unconditionally.
 */
void session_do_watch(struct session *session, enum dp_session_hook hook)
{
	struct session_watch *wt = session_watch_get();

	if (wt == NULL)
		return;

	if (!check_session_type(session, wt->types))
		return;

	if (wt->fn)
		wt->fn(session, hook, wt->data);
}

struct dp_session_walk_data {
	unsigned int types;
	dp_session_walk_t *fn;
	void *data;
};

static int session_walk_cb(struct session *session, void *data)
{
	struct dp_session_walk_data *wd = (struct dp_session_walk_data *)data;

	if (!check_session_type(session, wd->types))
		return 0;
	return wd->fn(session, wd->data);
}

int dp_session_table_walk(dp_session_walk_t *fn, void *data, unsigned int types)
{
	struct dp_session_walk_data wd = { .types = types,
					   .fn = fn,
					   .data = data,
					  };
	return session_table_walk(session_walk_cb,  &wd);
}

