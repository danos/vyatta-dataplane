/*
 * Copyright (c) 2021 AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2021 Centre for Development of Telematics. All rights reserved.
 *
 * Copyright (c) 2021 Centre for Development of Telematics. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * ndpi.c
 *
 * nDPI implementation.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <rte_config.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/npf_session.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_cache.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/config/npf_config.h"
#include "npf_shim.h"
#include "npf/dpi/app_cmds.h"
#include "npf/dpi/dpi_internal.h"
#include "ndpi_main.h"
#include "vplane_log.h"
#include "util.h"
#include "vplane_debug.h"

#define NDPI_PROTOCOLS_PATH	"/config/ndpi/protocols.cfg"
#define NDPI_CATEGORIES_PATH	"/config/ndpi/categories.cfg"

#define NDPI_FLOW_PKT_MAX 10

#define DPI_INTERNAL_UNKNOWN (DPI_ENGINE_NDPI | NDPI_PROTOCOL_UNKNOWN)

/* Count of all nDPI uses. */
static uint32_t ndpi_refcount;

/* Flag to enable/ disable nDPI protocol guessing.
 * 1 = enabled, 0 = disabled
 */
static uint8_t enable_protocol_guess = 1;

static const char *dpi_ndpi_app_id_to_name(uint32_t app_id);

struct ndpi_flow {
	struct dpi_engine_flow ef;	// Must be first.
	struct ndpi_flow_struct *key;
	bool error;
	bool offloaded;
	uint32_t application;
	uint32_t protocol;
	uint32_t type;
	struct ndpi_id_struct *src_id;
	struct ndpi_id_struct *dest_id;
	rte_spinlock_t fl_lock;
	struct rcu_head n_rcu_head;
};

#define NDPI_FLOW_ENGINE_ID	ef.engine_id
#define NDPI_FLOW_STATS		ef.stats
#define NDPI_FLOW_UPDATE_STATS	ef.update_stats

static struct ndpi_detection_module_struct *detection_modules[RTE_MAX_LCORE];

static inline uint16_t
dpi_to_ndpi_proto(uint32_t id)
{
	return (uint16_t) id & DPI_APP_MASK;
}

static inline uint32_t
dpi_from_ndpi_proto(uint16_t id)
{
	return DPI_ENGINE_NDPI | id;
}

/* Return true if the sum of the forward and backward packet counts
 * for the given ndpi_flow is greater than or equal to the specified maximum.
 */
static bool
dpi_ndpi_flow_pkt_count_maxed(const struct ndpi_flow *flow, uint32_t max)
{
	if (!flow)
		return false;

	const struct dpi_engine_flow *engine_flow =
		(const struct dpi_engine_flow *)flow;
	uint32_t cnt;
	const struct dpi_flow_stats *ds;

	ds = dpi_flow_get_stats(engine_flow, true);
	cnt = ds->pkts;

	ds = dpi_flow_get_stats(engine_flow, false);
	cnt += ds->pkts;

	if (cnt >= max)
		return true;

	return false;
}

/**
 * Process the given packet with nDPI.
 *
 * Finds and pass the start of the L3 header to nDPI, and set the flow to
 * offloaded if the protocol is successfully determined.
 *
 * @return false if the given detection module is NULL, true otherwise.
 */
static bool
dpi_ndpi_process(struct ndpi_detection_module_struct *detect,
		struct rte_mbuf *mbuf, struct ndpi_flow *flow)
{
	if (unlikely(!detect))
		return false;

	uint16_t offset = dp_pktmbuf_l2_len(mbuf);
	uint16_t data_len = rte_pktmbuf_data_len(mbuf) - offset;

	const unsigned char *data =
		rte_pktmbuf_mtod(mbuf, const unsigned char *) + offset;

	ndpi_protocol proto = ndpi_detection_process_packet(detect, flow->key,
			data, data_len, (uint64_t) get_time_uptime(),
			flow->src_id, flow->dest_id);

	/* Offload the given ndpi_flow if the protocol is known,
	 * or if the sum of its forward and backward packet counts
	 * is greater than or equal to NDPI_FLOW_PKT_MAX.
	 */
	flow->offloaded =
		proto.master_protocol != NDPI_PROTOCOL_UNKNOWN ||
		proto.app_protocol != NDPI_PROTOCOL_UNKNOWN ||
		dpi_ndpi_flow_pkt_count_maxed(flow, NDPI_FLOW_PKT_MAX);

	if (flow->offloaded) {
		/* Give up protocol detection by nDPI. Update detected
		 * protocols in ndpi_protocol structure using protocols
		 * guessed by nDPI if enable_protocol_guess is set to 1.
		 */
		uint8_t proto_guessed = 0;
		proto = ndpi_detection_giveup(detect, flow->key,
				enable_protocol_guess, &proto_guessed);
	}

	/* Sometimes nDPI sets "app_protocol" without setting "master_protocol",
	 * so we see app 'TLS' over protocol 'Unknown' which doesn't make sense.
	 * In this case we swap the app and protocol to get 'Unknown over TLS'.
	 */
	if ((proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) &&
	    (proto.app_protocol != NDPI_PROTOCOL_UNKNOWN)) {
		/* Swap */
		flow->protocol = dpi_from_ndpi_proto(proto.app_protocol);
		flow->application = dpi_from_ndpi_proto(NDPI_PROTOCOL_UNKNOWN);
	} else {
		/* Regular */
		flow->protocol = dpi_from_ndpi_proto(proto.master_protocol);
		flow->application = dpi_from_ndpi_proto(proto.app_protocol);
	}

	flow->type = ndpi_get_proto_category(detect, proto);

	if (unlikely(dp_debug & DP_DBG_DPI)) {
		RTE_LOG(DEBUG, DATAPLANE, "ndpi: P='%s' A='%s' C='%s'\n",
			ndpi_get_proto_name(detection_modules[dp_lcore_id()],
					    proto.master_protocol),
			ndpi_get_proto_name(detection_modules[dp_lcore_id()],
					    proto.app_protocol),
			ndpi_category_get_name(detection_modules[dp_lcore_id()],
					       proto.category));
	}

	return true;
}

/**
 * Process the given packet with nDPI
 *
 * The flow attached to the given session will be placed in an error state if
 * the DPI engine is invalid.
 *
 * @return false if the flow attached to the given session has an invalid key,
 * true otherwise.
 */
static bool
dpi_ndpi_process_pkt(struct dpi_engine_flow *engine_flow,
		struct rte_mbuf *mbuf, int dir __unused)
{
	struct ndpi_flow *flow = (struct ndpi_flow *) engine_flow;

	if (unlikely(!flow->key))
		return false;

	rte_spinlock_lock(&flow->fl_lock);
	if (!dpi_ndpi_process(detection_modules[dp_lcore_id()],
				mbuf, flow)) {
		flow->protocol = DPI_APP_ERROR;
		flow->offloaded = true;
		flow->error = true;
	}

	rte_spinlock_unlock(&flow->fl_lock);
	return true;
}

static bool initialised;

static bool dpi_ndpi_terminate(void);

/**
 * Initialise nDPI's detection modules.
 *
 * @return zero on success; errno if couldn't initialise detection module.
 */
static int
dpi_ndpi_init(void)
{
	unsigned int lcore;
	NDPI_PROTOCOL_BITMASK all;
	FILE *file;

	if (initialised)
		return 0;

	set_ndpi_malloc(zmalloc_aligned);
	NDPI_BITMASK_SET_ALL(all);

	FOREACH_DP_LCORE(lcore) {
		struct ndpi_detection_module_struct *detect
			= ndpi_init_detection_module(ndpi_no_prefs);
		if (!detect) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to initialise detection module: %d\n",
				lcore);
			dpi_ndpi_terminate();
			return -ENOMEM;
		}
		ndpi_set_protocol_detection_bitmask2(detect, &all);

		if ((file = fopen(NDPI_PROTOCOLS_PATH, "r")) != NULL) {
			ndpi_load_protocols_file(detect, NDPI_PROTOCOLS_PATH);
			fclose(file);
		}

		if ((file = fopen(NDPI_CATEGORIES_PATH, "r")) != NULL) {
			ndpi_load_categories_file(detect, NDPI_CATEGORIES_PATH);
			fclose(file);
		}

		ndpi_finalize_initalization(detect);

		detection_modules[lcore] = detect;
	}

	initialised = true;
	return 0;
}

/**
 * Terminate nDPI's detection modules.
 *
 * @return true on success, false if couldn't initialise detection module.
 */
static bool
dpi_ndpi_terminate(void)
{
	unsigned int lcore;
	RTE_LCORE_FOREACH(lcore) {
		if (detection_modules[lcore]) {
			ndpi_exit_detection_module(detection_modules[lcore]);
			detection_modules[lcore] = NULL;
		}
	}

	initialised = false;
	return true;
}

/**
 * Increment the refcount.
 */
static void
dpi_ndpi_refcount_inc(void)
{
	if (++ndpi_refcount == 0)
		/* Overflowed */
		--ndpi_refcount;
}

/**
 * Decrement the refcount.
 */
static uint32_t
dpi_ndpi_refcount_dec(void)
{
	if (ndpi_refcount)
		ndpi_refcount--;

	return ndpi_refcount;
}

/**
 * Free the dpi flow. Called from RCU callback.
 */
static void
dpi_ndpi_free(struct rcu_head *head)
{
	struct ndpi_flow *flow = caa_container_of(head, struct ndpi_flow,
						  n_rcu_head);

	ndpi_free_flow(flow->key);
	ndpi_free(flow->src_id);
	ndpi_free(flow->dest_id);
	free(flow);
}

/*
 * Destroy the given flow, which can be NULL.
 */
static void
dpi_ndpi_session_flow_destroy(struct dpi_engine_flow *dpi_flow)
{
	if (!dpi_flow)
		return;

	struct ndpi_flow *flow = (struct ndpi_flow *) dpi_flow;
	call_rcu(&flow->n_rcu_head, dpi_ndpi_free);
}

/*
 * Initialise the flow with the first packet of the given session, and attempt
 * to determine the protocol of the flow with the packet.
 */
static int
dpi_ndpi_session_first_packet(struct npf_session *se __unused,
		struct npf_cache *npc __unused, struct rte_mbuf *mbuf,
		int dir, uint32_t data_len, struct dpi_engine_flow **dpi_flow)
{
	struct ndpi_flow *flow = zmalloc_aligned(sizeof(struct ndpi_flow));
	if (!flow)
		return -ENOMEM;

	flow->NDPI_FLOW_ENGINE_ID = IANA_NDPI;
	flow->key = NULL;
	flow->application = DPI_APP_UNDETERMINED;
	flow->protocol = DPI_APP_UNDETERMINED;
	flow->type = DPI_APP_TYPE_NONE;
	flow->error = false;
	flow->offloaded = false;
	rte_spinlock_init(&flow->fl_lock);

	flow->key = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
	if (!flow->key)
		goto key_error;

	flow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT);
	if (!flow->src_id)
		goto src_id_error;

	flow->dest_id = ndpi_malloc(SIZEOF_ID_STRUCT);
	if (!flow->dest_id)
		goto dest_id_error;

	if (data_len != 0 && !dpi_ndpi_process_pkt(
				(struct dpi_engine_flow *)flow, mbuf, dir))
		return -EINVAL;

	*dpi_flow = (struct dpi_engine_flow *)flow;
	return 0;

dest_id_error:
	ndpi_free(flow->src_id);
	flow->src_id = NULL;

src_id_error:
	ndpi_free(flow->key);
	flow->key = NULL;
	flow->error = true;
	flow->offloaded = true;
	flow->protocol = DPI_APP_ERROR;

key_error:
	free(flow);
	return -ENOMEM;
}

static uint32_t
dpi_ndpi_flow_get_app_proto(struct dpi_engine_flow *dpi_flow)
{
	struct ndpi_flow *flow = (struct ndpi_flow *) dpi_flow;
	return flow->protocol;
}

static uint32_t
dpi_ndpi_flow_get_app_id(struct dpi_engine_flow *dpi_flow)
{
	struct ndpi_flow *flow = (struct ndpi_flow *) dpi_flow;
	return flow->application;
}

static uint32_t
dpi_ndpi_flow_get_app_type(struct dpi_engine_flow *dpi_flow)
{
	struct ndpi_flow *flow = (struct ndpi_flow *) dpi_flow;
	return flow->type;
}

static bool
dpi_ndpi_flow_get_offloaded(struct dpi_engine_flow *dpi_flow)
{
	struct ndpi_flow *flow = (struct ndpi_flow *) dpi_flow;
	return flow->offloaded;
}

static bool
dpi_ndpi_flow_get_error(struct dpi_engine_flow *dpi_flow)
{
	struct ndpi_flow *flow = (struct ndpi_flow *) dpi_flow;
	return flow->error;
}

static uint32_t
dpi_ndpi_app_name_to_id(const char *app_name)
{
	struct ndpi_detection_module_struct *ndpi_str =
		detection_modules[dp_lcore_id()];

	uint16_t id;
	if (!ndpi_str)
		id = NDPI_PROTOCOL_UNKNOWN;
	else {
		id = ndpi_get_protocol_id(ndpi_str, (char *)app_name);

		/* Work around that NDPI returns -1 for UNKNOWN. */
		if (id == (uint16_t) -1)
			id = NDPI_PROTOCOL_UNKNOWN;
	}

	return dpi_from_ndpi_proto(id);
}

static const char *
dpi_ndpi_app_id_to_name(uint32_t app_id)
{
	struct ndpi_detection_module_struct *ndpi_str =
		detection_modules[dp_lcore_id()];

	if (!ndpi_str)
		return "UNKNOWN";

	return ndpi_get_proto_name(ndpi_str, dpi_to_ndpi_proto(app_id));
}

static uint32_t
dpi_ndpi_app_type_name_to_id(const char *type_name)
{
	struct ndpi_detection_module_struct *ndpi_str =
		detection_modules[dp_lcore_id()];

	if (!ndpi_str)
		return NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;

	/* Work around that NDPI returns 30 for empty names. */
	int id = *type_name
		? ndpi_get_category_id(ndpi_str, (char *)type_name)
		: NDPI_PROTOCOL_CATEGORY_UNSPECIFIED;

	return (uint32_t) id;
}

static const char *
dpi_ndpi_app_type_to_name(uint32_t app_type)
{
	struct ndpi_detection_module_struct *ndpi_str =
		detection_modules[dp_lcore_id()];

	if (!ndpi_str)
		return "UNKNOWN";

	return ndpi_category_get_name(ndpi_str,
			(ndpi_protocol_category_t) app_type);
}

/*
 * This uses JSON to export the DPI information associated with the flow.
 */
static bool
dpi_ndpi_info_json(struct dpi_engine_flow *dpi_engine_flow, json_writer_t *json)
{
	if (!ndpi_refcount)
		/* The nDPI engine is not in use */
		return false;

	if (!dpi_engine_flow || !json)
		return false;

	struct ndpi_flow *flow = (struct ndpi_flow *) dpi_engine_flow;
	jsonw_start_object(json);

	const struct dpi_flow_stats *stats =
		dpi_flow_get_stats(dpi_engine_flow, true);

	jsonw_uint_field(json, "forward-pkts", stats->pkts);
	jsonw_uint_field(json, "forward-bytes", stats->bytes);

	stats = dpi_flow_get_stats(dpi_engine_flow, false);
	jsonw_uint_field(json, "backward-pkts", stats->pkts);
	jsonw_uint_field(json, "backward-bytes", stats->bytes);

	jsonw_string_field(json, "engine", "ndpi");

	jsonw_string_field(json, "app-name",
			dpi_ndpi_app_id_to_name(flow->application));
	jsonw_string_field(json, "proto-name",
			dpi_ndpi_app_id_to_name(flow->protocol));
	jsonw_string_field(json, "type",
			dpi_ndpi_app_type_to_name(flow->type));

	jsonw_bool_field(json, "offloaded", flow->offloaded);
	jsonw_bool_field(json, "error", flow->error);

	jsonw_end_object(json);

	return true;
}

static size_t
dpi_ndpi_info_log(struct dpi_engine_flow *dpi_flow, char *buf, size_t buf_len)
{
	if (!ndpi_refcount)
		/* The nDPI engine is not in use */
		return 0;

	if (!buf)
		return 0;

	if (!dpi_flow)
		return 0;

	size_t used_buf_len = 0;
	const uint32_t app_id = dpi_ndpi_flow_get_app_id(dpi_flow);
	const uint32_t app_proto = dpi_ndpi_flow_get_app_proto(dpi_flow);
	const uint32_t app_type = dpi_ndpi_flow_get_app_type(dpi_flow);

	/* Say nothing, if we've nothing useful to say. */
	if (no_app_id(app_id) && no_app_id(app_proto) && no_app_type(app_type))
		return 0;

	buf_app_printf(buf, &used_buf_len, buf_len, "engine=ndpi ");

	buf_app_printf(buf, &used_buf_len, buf_len, "app-name=");
	dpi_app_id_to_buf(buf, &used_buf_len, buf_len, app_id,
			  dpi_ndpi_app_id_to_name);

	buf_app_printf(buf, &used_buf_len, buf_len, " proto-name=");
	dpi_app_id_to_buf(buf, &used_buf_len, buf_len, app_proto,
			  dpi_ndpi_app_id_to_name);

	buf_app_printf(buf, &used_buf_len, buf_len, " type=");
	dpi_app_type_to_buf(buf, &used_buf_len, buf_len, app_type,
			    dpi_ndpi_app_type_to_name);

	return used_buf_len;
}

struct dpi_engine_procs ndpi_engine_procs = {
	.id = IANA_NDPI,
	.init = dpi_ndpi_init,
	.terminate = dpi_ndpi_terminate,
	.refcount_inc = dpi_ndpi_refcount_inc,
	.refcount_dec = dpi_ndpi_refcount_dec,
	.destructor = dpi_ndpi_session_flow_destroy,
	.first_packet = dpi_ndpi_session_first_packet,
	.process_pkt = dpi_ndpi_process_pkt,
	.is_offloaded = dpi_ndpi_flow_get_offloaded,
	.is_error = dpi_ndpi_flow_get_error,
	.flow_get_proto = dpi_ndpi_flow_get_app_proto,
	.flow_get_id = dpi_ndpi_flow_get_app_id,
	.flow_get_type = dpi_ndpi_flow_get_app_type,
	.name_to_id = dpi_ndpi_app_name_to_id,
	.type_to_id = dpi_ndpi_app_type_name_to_id,
	.info_json = dpi_ndpi_info_json,
	.info_log = dpi_ndpi_info_log,
};
