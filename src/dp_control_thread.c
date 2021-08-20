/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <string.h>

#include <rte_log.h>
#include <urcu/list.h>

#include "rcu.h"

#include "vplane_debug.h"

#include "dp_control_thread.h"

/* List of registered control-thread contexts. */
static struct cds_list_head ctx_list;

struct dp_control_thread_ctx {
	struct rcu_head rcu;
	struct cds_list_head list_entry;
	pthread_t tid;
};

/* Currently set affinity, needs to be stored for on-demand control-threads.
 * On dataplane start the dataplane.conf control_cpumask= gets parsed and
 * prior starting the mainloop dp_control_thread_set_affinity() get called
 * which updates current_cpuset variable and all already registered control
 * threads.
 */
static cpu_set_t current_cpuset;

void dp_control_thread_init(void)
{
	CDS_INIT_LIST_HEAD(&ctx_list);
	CPU_ZERO(&current_cpuset);
}

static int dp_control_thread_ctx_create(struct dp_control_thread_ctx **ctx)
{
	if (!ctx)
		return -EINVAL;

	*ctx = calloc(1, sizeof(struct dp_control_thread_ctx));
	if (!*ctx) {
		RTE_LOG(ERR, DATAPLANE,
		       "Could not allocate control thread context: %s\n",
		       strerror(errno));
		return -errno;
	}

	return 0;
}

static void dp_control_thread_rcu_free(struct rcu_head *head)
{
	struct dp_control_thread_ctx *ctx;

	ctx = caa_container_of(head, struct dp_control_thread_ctx, rcu);

	free(ctx);
}

static void dp_control_thread_ctx_destroy(struct dp_control_thread_ctx *ctx)
{
	call_rcu(&ctx->rcu, dp_control_thread_rcu_free);
}

static int dp_control_thread_set_affinity_ctx(struct dp_control_thread_ctx *ctx,
					      cpu_set_t *cpuset)
{
	int rc;

	rc = pthread_setaffinity_np(ctx->tid, sizeof(*cpuset), cpuset);
	if (rc < 0) {
#define NAMELEN 16
		char name[NAMELEN];

		pthread_getname_np(ctx->tid, name, sizeof(name));
		RTE_LOG(ERR, DATAPLANE,
			"Failed to update CPU affinity for control thread: %s/%lx: %s\n",
			name, ctx->tid, strerror(-rc));
		return rc;
	}

	return 0;
}

int dp_control_thread_register(void)
{
	int rc;
	struct dp_control_thread_ctx *ctx;

	rc = dp_control_thread_ctx_create(&ctx);
	if (rc < 0)
		goto error;

	ctx->tid = pthread_self();

	cds_list_add_rcu(&ctx->list_entry, &ctx_list);

	/* set affinity, this could be a on-demand control-thread. */
	dp_control_thread_set_affinity_ctx(ctx, &current_cpuset);

error:
	return rc;
}

void dp_control_thread_unregister(void)
{
	struct dp_control_thread_ctx *ctx;
	struct cds_list_head *entry, *next;

	pthread_t self = pthread_self();

	cds_list_for_each_safe(entry, next, &ctx_list) {
		ctx = cds_list_entry(entry, struct dp_control_thread_ctx,
				     list_entry);

		if (ctx->tid != self)
			continue;

		cds_list_del_rcu(&ctx->list_entry);
		dp_control_thread_ctx_destroy(ctx);
		break;
	}
}

int dp_control_thread_set_affinity(cpu_set_t *cpuset)
{
	int err, rc = 0;
	struct dp_control_thread_ctx *ctx;

	if (!cpuset)
		return -1;

	/* Keep track of latest applied control-thread affinity
	 * for on-demand control-threads.
	 */
	current_cpuset = *cpuset;

	cds_list_for_each_entry_rcu(ctx, &ctx_list, list_entry) {
		err = dp_control_thread_set_affinity_ctx(ctx, cpuset);
		if (err < 0)
			rc = err;
	}

	return rc;
}
