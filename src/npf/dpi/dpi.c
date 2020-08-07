/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "npf/npf_session.h"
#include "dpi.h"
#include "npf/dpi/dpi_internal.h"
#include "pktmbuf_internal.h"
#include "vplane_log.h"
#include "util.h"
#include "npf/npf_rule_gen.h"

struct flow_procs_tup {
	struct dpi_engine_flow *flow;
	struct dpi_engine_procs *procs;
};

struct dpi_flow {
	struct dpi_engine_flow ef;	// Must be first.
	struct flow_procs_tup *flows;
	size_t flows_len;
};

#define DPI_FLOW_ENGINE_ID	ef.engine_id
#define DPI_FLOW_STATS		ef.stats
#define DPI_FLOW_UPDATE_STATS	ef.update_stats

/**
 * Entry in the engine name to ID mapping.
 */
struct id_entry {
	const char *name;
	uint8_t id;
};

/* DPI engine dpi_engine_procs instances */
#ifdef USE_NDPI
extern struct dpi_engine_procs ndpi_engine_procs;
#endif /* USE_NDPI */
extern struct dpi_engine_procs user_engine_procs;

/* Array of known DPI engine dpi_engine_procs */
static struct dpi_engine_procs *engine_procs[] = {
	&user_engine_procs,
#ifdef USE_NDPI
	&ndpi_engine_procs,
#endif /* USE_NDPI */
};

struct id_entry engine_name_id_map[] = {
#ifdef USE_NDPI
	{ "ndpi", IANA_NDPI },
#endif /* USE_NDPI */
	{ "user", IANA_USER },
};

#define NULL_ENGINE (NULL)
#ifdef USE_NDPI
static uint8_t global_engine = IANA_NDPI;
#else
static uint8_t global_engine = IANA_USER;
#endif /* USER_NDPI */

static unsigned int engine_procs_len = ARRAY_SIZE(engine_procs);
static unsigned int engine_names_len = ARRAY_SIZE(engine_name_id_map);

/* Find the first dpi_engine_proc which is:
 * - not NULL
 * - has the same ID as the given id
 * - had the function func
 * If one is found, set engine to it.
 */
#define ENGINE_PROC_FIND(engine, ID, func) {\
	for (unsigned int i = 0; i < engine_procs_len; i++) {\
		if (engine_procs[i] && engine_procs[i]->id == ID &&\
				engine_procs[i]->func) {\
			engine = engine_procs[i];\
			break;\
		} \
	} \
}

#define CALL_IF_EXIST(_func, _procs, ...) \
	(_procs->_func ? _procs->_func(__VA_ARGS__) : false)

/* Run the specified function for all engines.
 */
#define ENGINE_PROC_EXEC_ALL(func) {\
	for (unsigned int i = 0; i < engine_procs_len; i++) {\
		if (engine_procs[i] && engine_procs[i]->func) {\
			engine_procs[i]->func();\
		} \
	} \
}

/**
 * Get the length of the given packet without the L3 and L4 headers.
 * Currently, the only supported L4 protocols are TCP and UDP.
 *
 * @return length of packet without headers
 */
static inline uint32_t
dpi_get_data_len(struct npf_cache *npc, struct rte_mbuf *mbuf)
{
	uint32_t offset = dp_pktmbuf_l2_len(mbuf) + dp_pktmbuf_l3_len(mbuf);
	uint32_t data_len = rte_pktmbuf_data_len(mbuf) - offset;

	/*
	 * Find the start of the transport payload.
	 *
	 * We can eventually pretend that other payloads (UDP-Lite, DCCP, SCTP)
	 * are actually UDP, and handle them here with the appropriate
	 * adjustment.
	 */
	switch (npf_cache_ipproto(npc)) {
	case IPPROTO_TCP: {
		uint16_t l4_offset = npc->npc_l4.tcp.doff << 2;
		data_len -= l4_offset;
		break;
	}
	case IPPROTO_UDP: {
		uint16_t l4_len = ntohs(npc->npc_l4.udp.uh_ulen);

		/* Ignore UDP with invalid (out of spec) length */
		if (l4_len > data_len || l4_len < sizeof(struct udphdr))
			return 0;

		/* Use the UDP header length */
		data_len = l4_len - sizeof(struct udphdr);
		break;
	}
	default:
		break;
	}

	return data_len;
}

/**
 * Update the stats for the given flow in the given direction with the given
 * data length.
 */
static inline void
dpi_update_stats(struct dpi_engine_flow *flow, uint32_t data_len, bool forw)
{
	unsigned int index = !forw;
	struct dpi_flow_stats *stats = &flow->stats[index];
	uint32_t new_val = stats->bytes + data_len;

	if (new_val <= UINT16_MAX) {
		stats->pkts++;
		stats->bytes = new_val;
	}

	if (stats->pkts == UINT16_MAX || stats->bytes == UINT16_MAX)
		flow->update_stats = false;
}

/**
 * Run DPI processing on the given packet.
 *
 * @return false if any DPI engine returns false, true otherwise.
 */
static bool
dpi_process_pkt(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *mbuf, int dir)
{
	if (pktmbuf_mdata_exists(mbuf, PKT_MDATA_DPI_SEEN))
		return true;

	uint32_t data_len = dpi_get_data_len(npc, mbuf);
	struct dpi_flow *dpi_flow = npf_session_get_dpi(se);
	bool forw = npf_session_forward_dir(se, dir);
	bool ret = true;
	bool offloaded = true;

	for (unsigned int i = 0; i < dpi_flow->flows_len; i++) {
		struct dpi_engine_procs *procs = dpi_flow->flows[i].procs;
		struct dpi_engine_flow *engine_flow = dpi_flow->flows[i].flow;

		if (!engine_flow ||
		    CALL_IF_EXIST(is_error, procs, engine_flow) ||
		    CALL_IF_EXIST(is_offloaded, procs, engine_flow) ||
		    !procs->process_pkt)
			continue;

		if (engine_flow->update_stats)
			dpi_update_stats(engine_flow, data_len, forw);

		if (!procs->process_pkt(engine_flow, mbuf, dir)) {
			ret = false;
			RTE_LOG(ERR, DATAPLANE,
					"engine [%d] failed to process packet\n",
					procs->id);
			break;
		}

		/* Offloaded if all flows offloaded */
		offloaded = CALL_IF_EXIST(is_offloaded, procs, engine_flow)
			&& offloaded;
	}

	if (offloaded)
		npf_session_set_pkt_hook(se, NULL);

	pktmbuf_mdata_set(mbuf, PKT_MDATA_DPI_SEEN);
	return ret;
}

uint8_t
dpi_global_engine(void)
{
	return global_engine;
}

uint8_t
dpi_engine_name_to_id(const char *name)
{
	if (!name)
		return IANA_RESERVED;

	for (unsigned int i = 0; i < engine_names_len; i++) {
		struct id_entry *entry = &engine_name_id_map[i];
		if (entry->name && strcmp(entry->name, name) == 0)
			return entry->id;
	}

	return IANA_RESERVED;
}

int32_t
dpi_engine_id_to_idx(uint8_t id)
{
	for (unsigned int i = 0; i < engine_names_len; i++) {
		struct id_entry *entry = &engine_name_id_map[i];
		if (entry->id == id)
			return i;
	}

	return -1;
}

int
dpi_init(uint8_t engine_id)
{
	if (engine_id == IANA_RESERVED) {
		/* Start all engines. */
		ENGINE_PROC_EXEC_ALL(init);
		return 0; /* success */
	}

	/* Try to start only the specified engine. */
	struct dpi_engine_procs *engine = NULL_ENGINE;
	ENGINE_PROC_FIND(engine, engine_id, init);
	return engine ? engine->init() : -ENOENT;
}

bool
dpi_terminate(uint8_t engine_id)
{
	if (engine_id == IANA_RESERVED) {
		/* Stop all engines. */
		ENGINE_PROC_EXEC_ALL(terminate);
		return true;
	}

	/* Try to stop only the specified engine. */
	struct dpi_engine_procs *engine = NULL_ENGINE;
	ENGINE_PROC_FIND(engine, engine_id, terminate);
	return engine ? engine->terminate() : false;
}

void
dpi_session_flow_destroy(struct dpi_flow *flow)
{
	if (flow) {
		if (flow->flows) {
			for (unsigned int i = 0; i < flow->flows_len; i++) {
				struct flow_procs_tup *tup = &flow->flows[i];
				if (tup->flow && tup->procs->destructor)
					tup->procs->destructor(tup->flow);
			}

			free(flow->flows);
		}

		free(flow);
	}
}

int
dpi_session_first_packet(struct npf_session *se, struct npf_cache *npc,
			 struct rte_mbuf *mbuf, int dir, size_t engines_len,
			 uint8_t *engines)
{
	unsigned int i;
	int ret = 0;

	/* Only create session for IP packets */
	if (unlikely(!npf_iscached(npc, NPC_IP46)))
		return -EINVAL; /* Impossible */

	/* Only create session for TCP/UDP packets */
	const uint8_t protocol = npf_cache_ipproto(npc);
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
		return -EINVAL;

	struct dpi_flow *flow = zmalloc_aligned(sizeof(struct dpi_flow));
	if (!flow)
		return -ENOMEM;

	flow->flows = zmalloc_aligned(engines_len
			* sizeof(struct flow_procs_tup));
	if (!flow->flows) {
		free(flow);
		return -ENOMEM;
	}

	flow->flows_len = engines_len;

	/* Add it or lose the race */
	if (!npf_session_set_dpi(se, flow)) {
		free(flow->flows);
		free(flow);
		return -EEXIST;
	}

	uint32_t data_len = dpi_get_data_len(npc, mbuf);

	for (i = 0; i < engines_len; i++) {
		struct dpi_engine_procs *engine = NULL_ENGINE;
		uint8_t engine_id = engines[i];
		struct flow_procs_tup *tup = &flow->flows[i];

		ENGINE_PROC_FIND(engine, engine_id, first_packet);
		tup->procs = engine;

		if (tup->procs == NULL_ENGINE) {
			RTE_LOG(ERR, DATAPLANE, "engine [%d] not found\n",
				engine_id);
			ret = -EINVAL;
			goto free_flows;
		}

		ret = tup->procs->first_packet(se, npc, mbuf, dir,
				data_len, &tup->flow);

		if (tup->flow) {
			tup->flow->update_stats = true;
			dpi_update_stats(tup->flow, data_len,
					 npf_session_forward_dir(se, dir));
		}

		if (ret != 0) {
			RTE_LOG(ERR, DATAPLANE,
					"engine [%d] failed first packet\n",
					engine_procs[i]->id);
			goto free_flows;
		}
	}

	npf_session_set_pkt_hook(se, dpi_process_pkt);

	return ret;

free_flows:
	for (unsigned int j = 0; j < i; j++) {
		struct flow_procs_tup *tup = &flow->flows[i];
		if (!tup)
			continue;
		if (!tup->procs)
			continue;
		if (!tup->procs->destructor)
			continue;
		if (!tup->flow)
			continue;
		if (tup->procs->destructor && tup->flow)
			tup->procs->destructor(tup->flow);
	}

	free(flow->flows);
	flow->flows = NULL;
	flow->flows_len = 0;

	return ret;
}

void
dpi_flow_for_each_engine(struct dpi_flow *flow,
		int (*call)(uint8_t engine, uint32_t app, uint32_t proto,
			uint32_t type, void *data),
		void *data)
{
	if (!flow)
		return;

	for (unsigned int i = 0; i < flow->flows_len; i++) {
		struct flow_procs_tup *tup = &flow->flows[i];
		if (tup && tup->procs->flow_get_id
			&& tup->procs->flow_get_proto
			&& tup->procs->flow_get_type) {
			uint32_t app;
			uint32_t proto;
			uint32_t type;
			app = tup->procs->flow_get_id(tup->flow);
			proto = tup->procs->flow_get_proto(tup->flow);
			type = tup->procs->flow_get_type(tup->flow);

			if (call(tup->flow->engine_id,
				 app, proto, type, data) != 0)
				break;
		}
	}
}

/**
 * Get the protocol ID the given flow is detected to be according to the given
 * flow's engine.
 * Returns DPI_APP_ERROR if there is no engine with the given ID, or the flow
 * is in an error state, otherwise returns the protocol ID, which can be
 * undetermined.
 */
uint32_t
dpi_flow_get_app_proto(uint8_t engine_id, struct dpi_flow *flow)
{
	if (!flow)
		return DPI_APP_ERROR;

	for (unsigned int i = 0; i < flow->flows_len; i++) {
		struct flow_procs_tup *tup = &flow->flows[i];
		if (tup->flow && tup->flow->engine_id == engine_id
				&& tup->procs->flow_get_proto)
			return tup->procs->flow_get_proto(tup->flow);
	}

	return DPI_APP_ERROR;
}

uint32_t
dpi_flow_get_app_id(uint8_t engine_id, struct dpi_flow *flow)
{
	if (!flow)
		return DPI_APP_ERROR;

	for (unsigned int i = 0; i < flow->flows_len; i++) {
		struct flow_procs_tup *tup = &flow->flows[i];
		if (tup->flow && tup->flow->engine_id == engine_id
				&& tup->procs->flow_get_id)
			return tup->procs->flow_get_id(tup->flow);
	}

	return DPI_APP_ERROR;
}

uint32_t
dpi_flow_get_app_type(uint8_t engine_id, struct dpi_flow *flow)
{
	if (!flow)
		return DPI_APP_ERROR;

	for (unsigned int i = 0; i < flow->flows_len; i++) {
		struct flow_procs_tup *tup = &flow->flows[i];
		if (tup->flow && tup->flow->engine_id == engine_id
				&& tup->procs->flow_get_type)
			return tup->procs->flow_get_type(tup->flow);
	}

	return DPI_APP_ERROR;
}

bool
dpi_flow_get_offloaded(struct dpi_flow *flow)
{
	if (!flow)
		/* Flow is invalid so offload to stop all further processing */
		return true;

	for (unsigned int i = 0; i < flow->flows_len; i++) {
		struct flow_procs_tup *tup = &flow->flows[i];
		if (tup->procs->is_offloaded &&
		   !tup->procs->is_offloaded(tup->flow))
			return false;
	}

	return true;
}

bool
dpi_flow_get_error(struct dpi_flow *flow)
{
	if (!flow || !flow->flows)
		return true;

	for (unsigned int i = 0; i < flow->flows_len; i++) {
		struct flow_procs_tup *tup = &flow->flows[i];
		if (tup->procs->is_error && tup->flow &&
		   !tup->procs->is_error(tup->flow))
			return false;
	}

	return true;
}

const struct dpi_flow_stats *dpi_flow_get_stats(struct dpi_engine_flow *flow,
						bool forw)
{
	unsigned int index = !forw;
	return &flow->stats[index];
}

uint32_t
dpi_app_name_to_id(uint8_t engine_id, const char *app_name)
{
	struct dpi_engine_procs *engine = NULL_ENGINE;
	ENGINE_PROC_FIND(engine, engine_id, name_to_id);
	return engine ? engine->name_to_id(app_name) : DPI_APP_ERROR;
}

uint32_t
dpi_app_type_name_to_id(uint8_t engine_id, const char *type_name)
{
	struct dpi_engine_procs *engine = NULL_ENGINE;
	ENGINE_PROC_FIND(engine, engine_id, type_to_id);
	return engine ? engine->type_to_id(type_name) : DPI_APP_ERROR;
}

void
dpi_info_json(struct dpi_flow *dpi_flow, json_writer_t *json)
{
	if (!dpi_flow)
		return;

	jsonw_name(json, "dpi");
	jsonw_start_object(json);

	jsonw_name(json, "engines");
	jsonw_start_array(json);

	uint32_t num_engines = 0;

	for (unsigned int i = 0; i < dpi_flow->flows_len; i++) {
		struct dpi_engine_procs *procs = dpi_flow->flows[i].procs;
		struct dpi_engine_flow *engine_flow = dpi_flow->flows[i].flow;

		if (!engine_flow || !procs->info_json)
			continue;

		if (procs->info_json(engine_flow, json))
			num_engines++;
	}

	jsonw_end_array(json);
	jsonw_uint_field(json, "num-engines", num_engines);
	jsonw_end_object(json);
}

void
dpi_info_log(struct dpi_flow *dpi_flow, char *buf, size_t buf_len)
{
	if (!dpi_flow || !buf)
		return;

	size_t used_buf_len = 0;

	for (unsigned int i = 0; i < dpi_flow->flows_len; i++) {
		struct dpi_engine_procs *engine = dpi_flow->flows[i].procs;
		struct dpi_engine_flow *engine_flow = dpi_flow->flows[i].flow;

		if (!engine->info_log)
			continue;

		used_buf_len += engine->info_log(engine_flow,
				buf + used_buf_len, buf_len - used_buf_len);

		if (used_buf_len)
			break;
	}

	if (!used_buf_len)
		buf_app_printf(buf, &used_buf_len, buf_len,
			       "engine=None app-name=None "
			       "proto-name=None type=None");
}

struct dpi_engine_flow *
dpi_get_engine_flow(struct dpi_flow *flow, uint8_t engine_id)
{
	if (!flow)
		return NULL;

	for (unsigned int i = 0; i < flow->flows_len; i++) {
		if (flow->flows[i].flow->engine_id == engine_id)
			return flow->flows[i].flow;
	}

	return NULL;
}

void
dpi_app_id_to_buf(char *buf, size_t *used_buf_len, const size_t total_buf_len,
		  uint32_t id, const char *(*id_to_name)(uint32_t))
{
	const char *str;

	switch (id & DPI_APP_MASK) {
	case DPI_APP_NA:
		buf_app_printf(buf, used_buf_len, total_buf_len,
				"(Unavailable)");
		break;

	case DPI_APP_ERROR:
		buf_app_printf(buf, used_buf_len, total_buf_len,
				"(Error)");
		break;

	case DPI_APP_UNDETERMINED:
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "(Undetermined)");
		break;

	default:
		str = id_to_name(id);
		if (str) {
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%s", str);
		} else {
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%u", id);
		}
	}
}

void
dpi_app_type_to_buf(char *buf, size_t *used_buf_len, const size_t total_buf_len,
		  uint32_t type, const char *(*id_to_type)(uint32_t))
{
	const char *str;

	switch (type) {
	case DPI_APP_TYPE_NONE:
		buf_app_printf(buf, used_buf_len, total_buf_len,
				"(None)");
		break;

	default:
		str = id_to_type(type);
		if (str) {
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%s", str);
		} else {
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%u", type);
		}
	}
}

bool no_app_id(uint32_t app_id)
{
	return ((app_id & DPI_APP_MASK) <= DPI_APP_UNDETERMINED);
}

bool no_app_type(uint32_t app_type)
{
	return (app_type == DPI_APP_TYPE_NONE);
}

void dpi_refcount_inc(uint8_t engine_id)
{
	struct dpi_engine_procs *engine = NULL_ENGINE;
	ENGINE_PROC_FIND(engine, engine_id, refcount_inc);
	if (engine)
		engine->refcount_inc();
}

uint32_t dpi_refcount_dec(uint8_t engine_id)
{
	struct dpi_engine_procs *engine = NULL_ENGINE;
	ENGINE_PROC_FIND(engine, engine_id, refcount_dec);
	if (engine)
		return engine->refcount_dec();

	return 0;
}
