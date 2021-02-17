/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "urcu.h"

#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_log.h"

static const struct cgn_log_type_info {
	const char *name;
} cgn_log_type_info[CGN_LOG_TYPE_COUNT] = {
	[CGN_LOG_TYPE_SESSION]		= {
		.name = "session",
	},
	[CGN_LOG_TYPE_PORT_BLOCK_ALLOCATION]	= {
		.name = "port-block-allocation",
	},
	[CGN_LOG_TYPE_SUBSCRIBER]	= {
		.name = "subscriber",
	},
	[CGN_LOG_TYPE_RES_CONSTRAINT]	= {
		.name = "resource-constraint",
	},
};

const char *cgn_get_log_type_name(enum cgn_log_type type)
{
	if (type >= CGN_LOG_TYPE_COUNT)
		return NULL;
	return cgn_log_type_info[type].name;
}

int cgn_get_log_type(const char *name, enum cgn_log_type *type)
{
	enum cgn_log_type t;

	for (t = 0; t < CGN_LOG_TYPE_COUNT; t++) {
		if (strcmp(name, cgn_log_type_info[t].name) == 0) {
			*type = t;
			return 0;
		}
	}

	return -ENOENT;
}

extern const struct cgn_log_fns cgn_rte_log_fns, cgn_protobuf_fns;

static const struct cgn_log_fns *cgn_log_fns[] = {
	&cgn_rte_log_fns,
	&cgn_protobuf_fns,
};

struct cgn_log_active_fns {
	const struct cgn_log_fns *cla_fns;
	enum cgn_log_type cla_ltype;
	struct cgn_log_active_fns *cla_next;
	struct rcu_head rcu;
};

static struct cgn_log_active_fns *cgn_log_active_fns[CGN_LOG_TYPE_COUNT];

#define CGN_LOG_FN_BODY(ltype, ltype_name, fn, ...) \
	{ \
		const struct cgn_log_active_fns *fns; \
\
		for (fns = rcu_dereference(cgn_log_active_fns[ltype]); \
		     fns != NULL; \
		     fns = rcu_dereference(fns->cla_next)) \
			if (fns->cla_fns->logfn[ltype].ltype_name->cl_ ## fn) \
				fns->cla_fns->logfn[ltype].ltype_name-> \
					cl_ ## fn(__VA_ARGS__); \
	}

void cgn_log_subscriber_start(uint32_t addr)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_SUBSCRIBER, subscriber,
			subscriber_start, addr)

void cgn_log_subscriber_end(uint32_t addr,
			    uint64_t start_time, uint64_t end_time,
			    uint64_t pkts_out, uint64_t bytes_out,
			    uint64_t pkts_in, uint64_t bytes_in,
			    uint64_t sessions)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_SUBSCRIBER, subscriber, subscriber_end,
			addr, start_time, end_time, pkts_out, bytes_out,
			pkts_in, bytes_in, sessions)

void cgn_log_resource_subscriber_mbpu(enum cgn_resource_type type,
				      uint32_t addr, uint8_t ipproto,
				      uint16_t count, uint16_t max_count)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_RES_CONSTRAINT, res_constraint,
			resource_subscriber_mbpu, type, addr, ipproto,
			count, max_count)

void cgn_log_resource_public_pb(enum cgn_resource_type type,
				uint32_t addr, uint16_t blocks_used,
				uint16_t nblocks)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_RES_CONSTRAINT, res_constraint,
			resource_public_pb, type, addr, blocks_used, nblocks)

void cgn_log_pb_alloc(uint32_t pvt_addr, uint32_t pub_addr,
		      uint16_t port_start, uint16_t port_end,
		      uint64_t start_time, const char *policy_name,
		      const char *pool_name)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_PORT_BLOCK_ALLOCATION, port_block_alloc,
			pb_alloc, pvt_addr, pub_addr, port_start, port_end,
			start_time, policy_name, pool_name)

void cgn_log_pb_release(uint32_t pvt_addr, uint32_t pub_addr,
			uint16_t port_start, uint16_t port_end,
			uint64_t start_time, uint64_t end_time,
			const char *policy_name, const char *pool_name)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_PORT_BLOCK_ALLOCATION, port_block_alloc,
			pb_release, pvt_addr, pub_addr, port_start, port_end,
			start_time, end_time, policy_name, pool_name)

void cgn_log_sess_start(struct cgn_sess2 *s2)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_SESSION, session, sess_start, s2)

void cgn_log_sess_active(struct cgn_sess2 *s2)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_SESSION, session, sess_active, s2)

void cgn_log_sess_end(struct cgn_sess2 *s2, uint64_t end_time)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_SESSION, session, sess_end, s2, end_time)

void cgn_log_sess_clear(const char *desc, uint count, uint64_t clear_time)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_RES_CONSTRAINT, res_constraint,
			sess_clear, desc, count, clear_time)

void cgn_log_resource_subscriber_table(enum cgn_resource_type type,
				       int32_t count, int32_t max_count)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_RES_CONSTRAINT, res_constraint,
			resource_subscriber_table, type, count, max_count)

void cgn_log_resource_session_table(enum cgn_resource_type type,
				    int32_t count, int32_t max_count)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_RES_CONSTRAINT, res_constraint,
			resource_session_table, type, count, max_count)

void cgn_log_resource_dest_session_table(enum cgn_resource_type type,
					 struct cgn_session *cse,
					 int16_t count, int16_t max_count)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_RES_CONSTRAINT, res_constraint,
			resource_dest_session_table, type, cse, count,
			max_count)

void cgn_log_resource_pool(enum cgn_resource_type type, struct nat_pool *np,
			   int32_t count, int32_t max_count)
	CGN_LOG_FN_BODY(CGN_LOG_TYPE_RES_CONSTRAINT, res_constraint,
			resource_pool, type, np, count, max_count)

int cgn_log_enable_handler(enum cgn_log_type ltype, const char *name)
{
	unsigned int i;
	struct cgn_log_active_fns *afns, *new;

	if (ltype >= CGN_LOG_TYPE_COUNT)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(cgn_log_fns); i++)
		if (strcmp(cgn_log_fns[i]->cl_name, name) == 0)
			break;

	if (i == ARRAY_SIZE(cgn_log_fns))
		return -ENOENT;

	for (afns = cgn_log_active_fns[ltype]; afns != NULL;
	     afns = afns->cla_next) {
		if (strcmp(afns->cla_fns->cl_name, name) == 0)
			return -EEXIST;
	}

	new = malloc(sizeof(*new));
	if (new == NULL)
		return -ENOMEM;

	if (cgn_log_fns[i]->cl_init) {
		int ret = cgn_log_fns[i]->cl_init(ltype, cgn_log_fns[i]);

		if (ret != 0) {
			free(new);
			return ret;
		}
	}

	new->cla_fns = cgn_log_fns[i];
	new->cla_ltype = ltype;
	new->cla_next = cgn_log_active_fns[ltype];

	rcu_assign_pointer(cgn_log_active_fns[ltype], new);

	return 0;
}

static void cgn_log_handler_reclaim(struct rcu_head *rp)
{
	struct cgn_log_active_fns *afns = container_of(
		rp, struct cgn_log_active_fns, rcu);

	free(afns);
}

int cgn_log_disable_handler(enum cgn_log_type ltype, const char *name)
{
	struct cgn_log_active_fns **afnsp;

	if (ltype >= CGN_LOG_TYPE_COUNT)
		return -EINVAL;

	for (afnsp = &cgn_log_active_fns[ltype]; *afnsp != NULL;
	     afnsp = &((*afnsp)->cla_next)) {
		if (strcmp((*afnsp)->cla_fns->cl_name, name) == 0) {
			struct cgn_log_active_fns *old = *afnsp;
			rcu_assign_pointer(*afnsp, (*afnsp)->cla_next);
			if (old->cla_fns->cl_fini)
				old->cla_fns->cl_fini(old->cla_ltype,
						      old->cla_fns);

			call_rcu(&old->rcu, cgn_log_handler_reclaim);
			return 0;
		}
	}

	return -ENOENT;
}

void cgn_log_disable_all_handlers(void)
{
	enum cgn_log_type ltype;
	struct cgn_log_active_fns **afnsp;

	for (ltype = 0; ltype < CGN_LOG_TYPE_COUNT; ltype++) {
		afnsp = &cgn_log_active_fns[ltype];
		while (*afnsp != NULL) {
			struct cgn_log_active_fns *old = *afnsp;
			rcu_assign_pointer(*afnsp, old->cla_next);
			call_rcu(&old->rcu, cgn_log_handler_reclaim);
		}
	}
}
