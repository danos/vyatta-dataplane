/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <sys/queue.h>

#include "main.h"
#include "lcore_sched.h"
#include "lcore_sched_internal.h"
#include "util.h"
#include "vplane_log.h"

int dp_foreach_lcore(int (*dp_per_lcore_fn)(unsigned int lcore, void *arg),
		     void *arg)
{
	unsigned int i;
	int rv;

	for (i = 0; i <= get_lcore_max(); i++) {
		rv = dp_per_lcore_fn(i, arg);
		if (rv)
			return rv;
	}
	return 0;
}

int dp_foreach_forwarding_lcore(int (*dp_per_lcore_fn)(unsigned int lcore,
						      void *arg),
				void *arg)
{
	int i, rv;

	/*
	 * Loop over all forwarding lcores. In the single cpu case return
	 * the master as that will also be doing forwarding.
	 */
	for (i = rte_get_next_lcore(-1, !single_cpu, 0);
	     i < RTE_MAX_LCORE;
	     i = rte_get_next_lcore((i), !single_cpu, 0)) {

		rv = dp_per_lcore_fn(i, arg);
		if (rv)
			return rv;
	}

	return 0;
}

static pthread_mutex_t dp_lcore_events_mutex = PTHREAD_MUTEX_INITIALIZER;

struct dp_lcore_events_internal {
	const struct dp_lcore_events *events;
	void *arg;
	LIST_ENTRY(dp_lcore_events_internal) list_entry;
};

LIST_HEAD(dp_lcore_events_list_head, dp_lcore_events_internal);

struct dp_lcore_events_list_head dp_lcore_events_list =
	LIST_HEAD_INITIALIZER(dp_lcore_events_list);

int dp_lcore_events_register(const struct dp_lcore_events *events,
			     void *arg)
{
	struct dp_lcore_events_internal *entry;

	ASSERT_MASTER();

	if (!events)
		return -EINVAL;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return -ENOMEM;

	entry->events = events;
	entry->arg = arg;

	pthread_mutex_lock(&dp_lcore_events_mutex);
	LIST_INSERT_HEAD(&dp_lcore_events_list, entry, list_entry);
	pthread_mutex_unlock(&dp_lcore_events_mutex);

	return 0;
}

int dp_lcore_events_unregister(const struct dp_lcore_events *events)
{
	struct dp_lcore_events_internal *entry;

	ASSERT_MASTER();

	if (!events)
		return -EINVAL;

	pthread_mutex_lock(&dp_lcore_events_mutex);

	LIST_FOREACH(entry, &dp_lcore_events_list, list_entry) {
		if (entry->events == events) {
			LIST_REMOVE(entry, list_entry);
			pthread_mutex_unlock(&dp_lcore_events_mutex);

			free(entry);
			return 0;
		}
	}

	pthread_mutex_unlock(&dp_lcore_events_mutex);
	return -ENOENT;
}

void dp_lcore_events_init(unsigned int lcore_id)
{
	struct dp_lcore_events_internal *entry;
	int rv;

	pthread_mutex_lock(&dp_lcore_events_mutex);

	LIST_FOREACH(entry, &dp_lcore_events_list, list_entry) {
		if (entry->events->dp_lcore_events_init_fn) {
			rv = entry->events->dp_lcore_events_init_fn(
				lcore_id,
				entry->arg);
			if (rv)
				RTE_LOG(INFO, DATAPLANE,
					"Failed to init per lcore on lcore %d (%d)\n",
					lcore_id, rv);
		}
	}

	pthread_mutex_unlock(&dp_lcore_events_mutex);
}

void dp_lcore_events_teardown(unsigned int lcore_id)
{
	struct dp_lcore_events_internal *entry;
	int rv;

	pthread_mutex_lock(&dp_lcore_events_mutex);

	LIST_FOREACH(entry, &dp_lcore_events_list, list_entry) {
		if (entry->events->dp_lcore_events_teardown_fn) {
			rv = entry->events->dp_lcore_events_teardown_fn(
				lcore_id,
				entry->arg);
			if (rv)
				RTE_LOG(INFO, DATAPLANE,
					"Failed to teardown per lcore on lcore %d (%d)\n",
					lcore_id, rv);
		}
	}

	pthread_mutex_unlock(&dp_lcore_events_mutex);
}
