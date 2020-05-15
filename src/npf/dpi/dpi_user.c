/*
 * Copyright (c) 2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * APIs for user-defined applications.
 */

#include <rte_mbuf.h>
#include <time.h>
#include <ini.h>
#include <rte_jhash.h>

#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "pktmbuf.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_rule_gen.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_cache.h"
#include "npf/config/npf_config.h"
#include "npf_shim.h"
#include "npf/dpi/dpi_internal.h"
#include "npf/dpi/npf_appdb.h"
#include "npf/dpi/npf_typedb.h"
#include "npf/dpi/dpi_user.h"

/* Count of all uses. */
static uint32_t user_refcount;
static bool init;

/**
 * Initialise hash tables.
 * Returns false if either failed to create name or ID hash tables, true
 * otherwise.
 */
static bool
dpi_user_init(void)
{
	if (init)
		return true;

	if (!appdb_init())
		return false;

	if (!typedb_init()) {
		appdb_destroy();
		return false;
	}

	init = true;
	return true;
}

/**
 * Increment the refcount.
 */
static void
dpi_user_refcount_inc(void)
{
	if (++user_refcount == 0)
		/* Overflowed */
		--user_refcount;
}

/**
 * Decrement the refcount.
 */
static uint32_t
dpi_user_refcount_dec(void)
{
	if (user_refcount)
		user_refcount--;

	return user_refcount;
}

/**
 * Destroy the given flow.
 */
static void
dpi_user_flow_destroy(struct dpi_engine_flow *flow)
{
	if (flow)
		free(flow);
}

/**
 * Process the given packet.
 * Since the user engine always determines on the first packet, this is not
 * added to the engine_procs.
 * Returns false if there is no user-defined ruleset, true otherwise.
 */
static bool
dpi_user_process_pkt(struct npf_session *se, npf_cache_t *npc,
		struct rte_mbuf *mbuf, int dir)
{
	const npf_ruleset_t *npf_rs =
		npf_get_ruleset(npf_global_config, NPF_RS_APPLICATION);

	if (!npf_rs)
		return false;

	npf_rule_t *rl =
		npf_ruleset_inspect(npc, mbuf, npf_rs,
				    NULL, NULL, dir);
	if (rl) {
		/* Rule matched, so run the action. */
		npf_rproc_result_t rproc_result = {
			.decision = NPF_DECISION_UNKNOWN,
		};

		npf_rproc_action(NULL, NULL, dir, rl,
				se, &rproc_result);
	}

	return true;
}

/**
 * Initialise a new flow with the given packet.
 * Returns:
 *  - 0 on success
 *  - -EINVAL if the given packet is not an IP, TCP or UDP packet
 *  - -ENOMEM if cannot allocate memory for flows
 *  - -EEXIST if a flow already exists for the given session
 *  - -ENOTSUP if user-defined applications are not active in the global NPF
 *             config
 *  - -EINVAL if the packet could not be processed (no rulesets defined)
 */
static int
dpi_user_first_packet(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *mbuf, int dir, uint32_t data_len __unused,
		struct dpi_engine_flow **engine_flow)
{
	/* Only process if user-defined applications are enabled */
	if (!npf_active(npf_global_config, NPF_APPLICATION))
		return 0; // Keep going

	struct user_flow *flow = zmalloc_aligned(sizeof(struct user_flow));
	if (!flow)
		return -ENOMEM;

	flow->USER_FLOW_ENGINE_ID = IANA_USER;
	flow->application = DPI_APP_USER_UNDETERMINED;
	flow->protocol = DPI_APP_USER_UNDETERMINED;
	flow->type = DPI_APP_TYPE_NONE;
	*engine_flow = (struct dpi_engine_flow *)flow;

	return dpi_user_process_pkt(se, npc, mbuf, dir) ? 0 : -EINVAL;
}

/**
 * Returns if the given flow is offloaded.
 * Since the user engine only inspects headers, it only needs to check a
 * single packet, so is always "offloaded".
 */
static bool
dpi_user_is_offload(struct dpi_engine_flow *flow __unused)
{
	return true;
}

static bool
dpi_user_is_error(struct dpi_engine_flow *flow __unused)
{
	return false;
}

static uint32_t
dpi_user_get_proto(struct dpi_engine_flow *dpi_engine_flow)
{
	return ((struct user_flow *)dpi_engine_flow)->protocol;
}

static uint32_t
dpi_user_get_id(struct dpi_engine_flow *dpi_engine_flow)
{
	return ((struct user_flow *)dpi_engine_flow)->application;
}

static uint32_t
dpi_user_get_type(struct dpi_engine_flow *dpi_engine_flow)
{
	return ((struct user_flow *)dpi_engine_flow)->type;
}

static uint32_t
dpi_user_name_to_id(const char *name)
{
	return appdb_name_to_id(name);
}

static uint32_t
dpi_user_type_to_id(const char *type)
{
	return typedb_name_to_id(type);
}

static const char *
dpi_user_id_to_name(uint32_t id)
{
	return appdb_id_to_name(id);
}

static const char *
dpi_user_type_to_name(uint32_t type)
{
	return typedb_id_to_name(type);
}

static bool
dpi_user_flow_json(struct dpi_engine_flow *dpi_engine_flow, json_writer_t *json)
{
	if (!user_refcount)
		/* The user engine is not in use */
		return false;

	struct user_flow *flow = (struct user_flow *)dpi_engine_flow;
	if (!flow)
		return false;

	jsonw_start_object(json);

	const char *name = appdb_id_to_name(flow->application);
	const char *proto = appdb_id_to_name(flow->protocol);
	const char *type = typedb_id_to_name(flow->type);

	const struct dpi_flow_stats *stats =
		dpi_flow_get_stats(dpi_engine_flow, true);

	jsonw_uint_field(json, "forward-pkts", stats->pkts);
	jsonw_uint_field(json, "forward-bytes", stats->bytes);

	stats = dpi_flow_get_stats(dpi_engine_flow, false);
	jsonw_uint_field(json, "backward-pkts", stats->pkts);
	jsonw_uint_field(json, "backward-bytes", stats->bytes);

	jsonw_string_field(json, "engine", "user");

	if (name)
		jsonw_string_field(json, "app-name", name);

	if (proto)
		jsonw_string_field(json, "proto-name", proto);

	if (type)
		jsonw_string_field(json, "type", type);

	jsonw_bool_field(json, "offloaded", true);

	jsonw_end_object(json);

	return true;
}

static size_t
dpi_user_flow_log(struct dpi_engine_flow *flow, char *buf, size_t buf_len)
{
	if (!user_refcount)
		/* The user engine is not in use */
		return 0;

	if (!buf)
		return 0;

	if (!flow)
		return 0;

	size_t used_buf_len = 0;
	const uint32_t app_id = dpi_user_get_id(flow);
	const uint32_t app_proto = dpi_user_get_proto(flow);
	const uint32_t app_type = dpi_user_get_type(flow);

	/* Say nothing, if we've nothing useful to say. */
	if (no_app_id(app_id) && no_app_id(app_proto) && no_app_type(app_type))
		return 0;

	buf_app_printf(buf, &used_buf_len, buf_len, "engine=user ");

	buf_app_printf(buf, &used_buf_len, buf_len, "app-name=");
	dpi_app_id_to_buf(buf, &used_buf_len, buf_len, app_id,
			dpi_user_id_to_name);

	buf_app_printf(buf, &used_buf_len, buf_len, " proto-name=");
	dpi_app_id_to_buf(buf, &used_buf_len, buf_len, app_proto,
			dpi_user_id_to_name);

	buf_app_printf(buf, &used_buf_len, buf_len, " type=");
	dpi_app_type_to_buf(buf, &used_buf_len, buf_len, app_type,
			    dpi_user_type_to_name);

	return used_buf_len;
}


struct dpi_engine_procs user_engine_procs = {
	.id = IANA_USER,
	.init = dpi_user_init,
	.terminate = NULL,
	.refcount_inc = dpi_user_refcount_inc,
	.refcount_dec = dpi_user_refcount_dec,
	.destructor = dpi_user_flow_destroy,
	.first_packet = dpi_user_first_packet,
	.process_pkt = NULL,	// Engine always determines on the first packet
	.is_offloaded = dpi_user_is_offload,
	.is_error = dpi_user_is_error,
	.flow_get_proto = dpi_user_get_proto,
	.flow_get_id = dpi_user_get_id,
	.flow_get_type = dpi_user_get_type,
	.name_to_id = dpi_user_name_to_id,
	.type_to_id = dpi_user_type_to_id,
	.info_json = dpi_user_flow_json,
	.info_log = dpi_user_flow_log,
};
