/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <qmdpi.h>
#include <rte_branch_prediction.h>
#include <rte_config.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <dpi/protodef.h>       /* For Q_PROTO_BASE and Q_PROTO_MAX */

#include "npf/dpi/dpi_internal.h"
#include "npf/dpi/dpi_private.h"
#include "npf/npf.h" /* For get_time_uptime() */
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "npf/npf_rule_gen.h"
#include "npf_shim.h"
#include "npf/config/npf_config.h"
#include "npf/npf_ruleset.h"
#include "pktmbuf_internal.h"
#include "qmdpi_const.h"
#include "qmdpi_struct.h"
#include "util.h"
#include "vplane_log.h"
#include "json_writer.h"

/*
 * Application IDs begin with Q_PROTO_BASE which is 3 (see protodef.h).
 *
 * We use app ID 0 to indicate "no app"
 * We use app ID 1 to indicate an error, ie DPI processing failed.
 * We don't yet use app ID 2.
 */
_Static_assert(Q_PROTO_BASE >= DPI_APP_BASE, "Q_PROTO_BASE is too low");

/*
 * APP_ID_Q is the base for internally assigned application IDs.
 * Qosmos app IDs must not have APP_ID_Q set.
 */
_Static_assert(Q_PROTO_MAX < APP_ID_Q, "Q_PROTO_MAX is too high");

#define DPI_INI_STR_LEN 200

/* Index within the qosmos 'path',  e.g. base.ip.tcp.http */
#define DPI_L5_INDEX 3

static uint64_t dpi_app_id_to_type_bitfield(uint32_t app_id);

/* Local variables. */
static struct qmdpi_engine *dpi_engine;
static struct qmdpi_bundle *dpi_bundle;
static struct qmdpi_worker *dpi_worker[RTE_MAX_LCORE];
static rte_spinlock_t dpi_worker_lock[RTE_MAX_LCORE];


/* Get flow key tuple elements */
static void dpi_flow_get_params(npf_session_t *se, npf_cache_t *npc,
		npf_addr_t *saddr, uint16_t *sport,
		npf_addr_t *daddr, uint16_t *dport)
{
	npf_nat_t *nt = npf_session_get_nat(se);
	struct npf_ports *ports = &npc->npc_l4.ports;

	if (nt) {
		npf_nat_t *nt = npf_session_get_nat(se);
		npf_natpolicy_t *np = npf_nat_get_policy(nt);

		switch (npf_natpolicy_get_type(np)) {
		case NPF_NATOUT:
			npf_nat_get_orig(nt, saddr, sport);
			*daddr = *npf_cache_dstip(npc);
			*dport = ports->d_port;
			break;
		case NPF_NATIN:
			npf_nat_get_orig(nt, daddr, dport);
			*saddr = *npf_cache_srcip(npc);
			*sport = ports->s_port;
			break;
		default: /* Hush up gcc */
			memset(saddr, 0, sizeof(npf_addr_t));
			memset(daddr, 0, sizeof(npf_addr_t));
			*dport = 0;
			*sport = 0;
		}
	} else {
		*saddr = *npf_cache_srcip(npc);
		*sport = ports->s_port;
		*daddr = *npf_cache_dstip(npc);
		*dport = ports->d_port;
	}
}

/*
 * DPI engine initialisation.
 *
 * Create the DPI engine and bundle instances,
 * then activate the bundle and all the signatures.
 */
bool
dpi_init(void)
{
	char sys_ini_str[DPI_INI_STR_LEN];
	int ret;
	unsigned int lcore;
	static bool initialised;
	static bool run_already;

	/* Run only once, thereafter repeat the same status */
	if (run_already)
		return initialised;
	run_already = true;

	/*
	 * Appened the user init string (if any) to the system init string.
	 * The last value is taken for each parameter.
	 */
	snprintf(sys_ini_str, DPI_INI_STR_LEN,
		 "injection_mode=stream;nb_workers=%d;nb_flows=1",
		 rte_lcore_count());

	/* Create DPI engine instance. */
	dpi_engine = qmdpi_engine_create(sys_ini_str);

	if (dpi_engine == NULL) {
		RTE_LOG(ERR, DATAPLANE, "Failed to instantiate DPI engine\n");
		goto error;
	}

	/* Create DPI bundle instance. */
	dpi_bundle = qmdpi_bundle_create_from_file(dpi_engine, NULL);

	if (dpi_bundle == NULL) {
		RTE_LOG(ERR, DATAPLANE, "Failed to instantiate DPI bundle\n");
		goto error_engine;
	}

	/* Activate DPI bundle. */
	ret = qmdpi_bundle_activate(dpi_bundle);

	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE, "Failed to activate DPI bundle\n");
		goto error_bundle;
	}

	/* Enable all signatures in DPI bundle. */
	ret = qmdpi_bundle_signature_enable_all(dpi_bundle);

	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE, "Failed to enable DPI signatures\n");
		goto error_bundle;
	}

	/* Start a DPI worker for each core. */
	RTE_LCORE_FOREACH(lcore) {
		struct qmdpi_worker *worker = qmdpi_worker_create(dpi_engine);
		if (!worker) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to instantiate DPI worker %d\n", lcore);
			goto error_bundle;
		}
		dpi_worker[lcore] = worker;
		rte_spinlock_init(&dpi_worker_lock[lcore]);
	}

	RTE_LOG(INFO, DATAPLANE, "Initialised DPI (%d workers)\n",
		rte_lcore_count());

	initialised = true;

	return initialised;

error_bundle:
	qmdpi_bundle_destroy(dpi_bundle);
error_engine:
	qmdpi_engine_destroy(dpi_engine);
error:
	return false;
}

/*
 * Do all the DPI processing.
 */
static bool
dpi_process(struct qmdpi_worker *worker, npf_cache_t *npc,
	    struct rte_mbuf *mbuf, bool forw,
	    uint32_t ifindex, struct dpi_flow *dpi_flow)
{
	/* This should be impossible */
	if (unlikely(!worker))
		return false;

	/*
	 * Find the start of the transport payload.
	 *
	 * We can eventually pretend that other payloads (UDP-Lite, DCCP, SCTP)
	 * are actually UDP, and handle them here with the appropriate
	 * adjustment.
	 */
	uint16_t data_offset = dp_pktmbuf_l2_len(mbuf) +
		dp_pktmbuf_l3_len(mbuf);
	uint16_t data_len = rte_pktmbuf_data_len(mbuf) - data_offset;
	switch (npf_cache_ipproto(npc)) {
	case IPPROTO_TCP: {
		uint16_t l4_offset = npc->npc_l4.tcp.doff << 2;
		data_offset += l4_offset;
		data_len -= l4_offset;
		break;
	}
	case IPPROTO_UDP: {
		uint16_t l4_len = ntohs(npc->npc_l4.udp.uh_ulen);

		/* Ignore UDP with invalid (out of spec) length */
		if (l4_len > data_len || l4_len < sizeof(struct udphdr))
			return true;
		/* Use the UDP header length */
		data_offset += sizeof(struct udphdr);
		data_len = l4_len - sizeof(struct udphdr);
		break;
	}
	default:
		break;
	}

	char *data_ptr = rte_pktmbuf_mtod(mbuf, char *) + data_offset;

	/* We need some payload to process */
	if (data_len == 0)
		return true;

	/* Update stats and possibly offload */
	if (dpi_flow->update_stats) {
		unsigned int index = !forw;
		struct dpi_flow_stats *fsp = &dpi_flow->stats[index];
		uint32_t new_val = fsp->bytes + data_len;

		if (new_val <= UINT16_MAX) {
			fsp->pkts++;
			fsp->bytes = new_val;
		}
		if (fsp->pkts == UINT16_MAX || fsp->bytes == UINT16_MAX)
			dpi_flow->update_stats = false;
	}

	/* NB: Don't use gettimeofday() in the forwarding path */
	struct timeval tv;
	tv.tv_usec = 0;
	tv.tv_sec = get_time_uptime();

	dpi_status sts;

	/* Set PDU information to be processed by the worker. */
	const int dir = forw ? QMDPI_DIR_CTS : QMDPI_DIR_STC;
	sts = qmdpi_worker_pdu_set(worker, data_ptr, data_len, &tv, 0,
				   dir, ifindex);
	if (unlikely(sts != DPI_SUCCESS))
		return false;

	/* Process packet with worker */
	struct qmdpi_result *result;
	sts = qmdpi_worker_process(worker, dpi_flow->key, &result);

	if (unlikely(sts < 0)) {
		/* An error occurred while processing the packet. */
		if (net_ratelimit())
			RTE_LOG(ERR, DATAPLANE, "DPI worker: %s (%d)\n",
				qmdpi_error_get_string(dpi_bundle, sts), sts);
		return false;
	}

	/* Extract the L5 and L7 identifiers */
	struct qmdpi_path *path = qmdpi_result_path_get(result);
	if (path && path->qp_len >= (DPI_L5_INDEX + 1)) {
		dpi_flow->app_proto =
			DPI_ENGINE_QOSMOS | path->qp_value[DPI_L5_INDEX];
		dpi_flow->app_name =
			DPI_ENGINE_QOSMOS | path->qp_value[path->qp_len-1];
		dpi_flow->app_type =
			dpi_app_id_to_type_bitfield(dpi_flow->app_name);
	}

	/* Does the engine suggest that we should offload now? */
	if (qmdpi_flow_is_offloaded(dpi_flow->key))
		dpi_flow->offloaded = true;

	return true;
}

/*
 * Clean up any per session flow information.
 */
static void
dpi_flow_key_destroy(struct qmdpi_flow *flow_key, uint8_t wrkr_id)
{
	rte_spinlock_t *worker_lock = &dpi_worker_lock[wrkr_id];
	struct qmdpi_worker *worker = dpi_worker[wrkr_id];
	struct qmdpi_result *result;
	int err;

	rte_spinlock_lock(worker_lock);
	err = qmdpi_flow_offload(worker, flow_key, &result);
	if (!err)
		err = qmdpi_flow_destroy(worker, flow_key, &result);
	rte_spinlock_unlock(worker_lock);

	if (err && net_ratelimit())
		RTE_LOG(ERR, DATAPLANE, "DPI: flow destruction failed (%d)\n",
			err);
}

void
dpi_session_flow_destroy(struct dpi_flow *dpi_flow)
{
	if (!dpi_flow)
		return;

	struct qmdpi_flow *flow_key = dpi_flow->key;
	if (flow_key)
		dpi_flow_key_destroy(flow_key, dpi_flow->wrkr_id);

	free(dpi_flow);
}

/*
 * This processes each packet within a session, updating the
 * information cached upon the session.
 *
 * This hook is only enabled for a session if there is a
 * fully initialised flow structure attached.
 *
 * Returns true to continue procssing, or false to drop.
 */
static bool
dpi_session_pkt(npf_session_t *se, npf_cache_t *npc,
		struct rte_mbuf *mbuf, int dir)
{
	if (pktmbuf_mdata_exists(mbuf, PKT_MDATA_DPI_SEEN))
		return true;

	struct dpi_flow *dpi_flow = npf_session_get_dpi(se);

	/* Optimise for subsequent packets */
	if (likely(dpi_flow->offloaded))
		return true;
	/* This should be impossible */
	if (unlikely(!dpi_flow->key))
		return false;

	bool forw = npf_session_forward_dir(se, dir);
	uint32_t ifindex = npf_session_get_if_index(se);

	/* Access the correct worker, with exclusion */
	unsigned int wrkr_id = dpi_flow->wrkr_id;
	rte_spinlock_t *worker_lock = &dpi_worker_lock[wrkr_id];
	struct qmdpi_worker *worker = dpi_worker[wrkr_id];

	/*
	 * Process the packet. In the event of an engine error we stop
	 * processing this flow, leaving it in an error state.
	 */
	rte_spinlock_lock(worker_lock);
	if (!dpi_process(worker, npc, mbuf, forw, ifindex, dpi_flow)) {
		dpi_flow->app_name = DPI_APP_ERROR;
		dpi_flow->app_proto = DPI_APP_ERROR;
		dpi_flow->app_type = DPI_APP_TYPE_NONE;
		dpi_flow->offloaded = true;
		dpi_flow->error = true;
		dpi_flow->update_stats = false;
	}
	rte_spinlock_unlock(worker_lock);

	/* Unhook the handler when flow is offloaded */
	if (dpi_flow->offloaded)
		npf_session_set_pkt_hook(se, NULL);

	pktmbuf_mdata_set(mbuf, PKT_MDATA_DPI_SEEN);

	return true;
}

/*
 * Associate a session with our flow state, and feed the first
 * packet of the flow to the DPI engine.  Ensure that subsequent
 * packets will be fed to the engine by looking the above handler
 * on to the session.
 */
int
dpi_session_first_packet(npf_session_t *se, npf_cache_t *npc,
			 struct rte_mbuf *mbuf, int dir)
{
	/* Sanity - We only create sessions for IP packets */
	if (!npf_iscached(npc, NPC_IP46))
		return -EINVAL; /* Impossible */

	/* We currently only support TCP or UDP */
	const uint8_t ip_proto = npf_cache_ipproto(npc);
	if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP)
		return -EINVAL;

	/* Create our DPI structure */
	struct dpi_flow *dpi_flow = zmalloc_aligned(sizeof(*dpi_flow));
	if (!dpi_flow)
		return -ENOMEM;

	dpi_flow->key = NULL;
	dpi_flow->app_proto = DPI_APP_UNDETERMINED;
	dpi_flow->app_name = DPI_APP_UNDETERMINED;
	dpi_flow->app_type = DPI_APP_TYPE_NONE;
	dpi_flow->wrkr_id = dp_lcore_id();
	dpi_flow->offloaded = false;
	dpi_flow->error = false;
	dpi_flow->update_stats = true;

	/* Add it or lose the race */
	if (!npf_session_set_dpi(se, dpi_flow)) {
		free(dpi_flow);
		return -EEXIST;
	}

	/* If user-defined applications exist, then evaluate them first. */
	if (npf_active(npf_global_config, NPF_APPLICATION)) {
		const npf_ruleset_t *npf_rs =
			npf_get_ruleset(npf_global_config, NPF_RS_APPLICATION);
		if (npf_rs) {
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
				return 0;
			}
		}
	}

	/* Fall back to Qosmos DPI. */

	/* Extract the L3 + L4 protocol */
	int l3proto = npf_iscached(npc, NPC_IP4) ? Q_PROTO_IP : Q_PROTO_IP6;
	int l4proto = (ip_proto == IPPROTO_TCP) ? Q_PROTO_TCP : Q_PROTO_UDP;

	/* Create the flow key */
	npf_addr_t srcip;
	npf_addr_t dstip;
	uint16_t sport, dport;

	dpi_flow_get_params(se, npc, &srcip, &sport, &dstip, &dport);

	struct qmdpi_flow *flow_key =
		qmdpi_flow_create(dpi_worker[dpi_flow->wrkr_id], l3proto,
				l4proto, &srcip, &sport, &dstip, &dport);
	if (!flow_key) {
		dpi_flow->app_proto = DPI_APP_ERROR;
		dpi_flow->app_name = DPI_APP_ERROR;
		dpi_flow->app_type = DPI_APP_TYPE_NONE;
		dpi_flow->offloaded = true;
		dpi_flow->error = true;
		dpi_flow->update_stats = false;

		if (net_ratelimit())
			RTE_LOG(ERR, DATAPLANE, "DPI: flow creation failed\n");
		return -ENOMEM;
	}
	dpi_flow->key = flow_key;

	npf_session_set_pkt_hook(se, dpi_session_pkt);
	bool good = dpi_session_pkt(se, npc, mbuf, dir);
	if (!good)
		return -EINVAL;

	return 0;
}

/* Extract the APP 'protocol', i.e. L5 information */
uint32_t
dpi_flow_get_app_proto(struct dpi_flow *flow)
{
	return flow->app_proto;
}

/* Extract the APP 'name', i.e. L7 information */
uint32_t
dpi_flow_get_app_name(struct dpi_flow *flow)
{
	return flow->app_name;
}

/* Extract the APP 'type' for the 'name', i.e L7 information */
uint64_t
dpi_flow_get_app_type(struct dpi_flow *flow)
{
	return flow->app_type;
}

/* Has the DPI engine ceased to process this stream? */
bool
dpi_flow_get_offloaded(struct dpi_flow *flow)
{
	return flow->offloaded;
}

/* Is this flow in an error state? */
bool
dpi_flow_get_error(struct dpi_flow *flow)
{
	return flow->error;
}

/*
 * Return a pointer to the per direction packet stats.
 * NB: These are clamped.
 */
const struct dpi_flow_stats *
dpi_flow_get_stats(struct dpi_flow *flow, bool forw)
{
	unsigned int index = !forw;
	struct dpi_flow_stats *fsp = &flow->stats[index];

	return fsp;
}

/* Return the application ID for the given Qosmos application name. */
uint32_t
dpi_app_name_to_id_qosmos(const char *app_name)
{
	struct qmdpi_signature *signature =
		qmdpi_worker_signature_get_byname(dpi_worker[dp_lcore_id()],
						  dpi_bundle, app_name);

	if (signature)
		return DPI_ENGINE_QOSMOS | qmdpi_signature_id_get(signature);

	/* No such name. */
	return DPI_APP_NA;
}

/* Return the application ID for the given application name. */
uint32_t
dpi_app_name_to_id(const char *app_name)
{
	/* No name? Then no ID. */
	if ((!app_name) || (!*app_name))
		return DPI_APP_NA;

	/*
	 * Assuming that Qosmos names will be used more often,
	 * We first lookup the name in Qosmos.
	 * The order isn't important.
	 */
	uint32_t app_id = dpi_app_name_to_id_qosmos(app_name);

	if (app_id == DPI_APP_NA)
		/* Name not found in Qosmos, so lookup in the app DB. */
		app_id = appdb_name_to_id(app_name);

	return app_id;
}

/* Return the name associated with the given application ID. */
const char *
dpi_app_id_to_name(uint32_t app_id)
{
	if (APP_ID_QOSMOS(app_id)) {
		struct qmdpi_signature *signature =
			qmdpi_worker_signature_get_byid(
					dpi_worker[dp_lcore_id()],
					dpi_bundle,
					app_id & DPI_APP_MASK);

		return qmdpi_signature_name_get(signature);
	} else
		return appdb_id_to_name(app_id);
}

/*
 * Return the type ID for the given application type name.
 * Currently only Qosmos types are supported.
 */
uint32_t
dpi_app_type_name_to_id(const char *type_name)
{
	int type_id = qmdpi_tag_id_get_byname(dpi_bundle, type_name);

	return type_id > 0 ? type_id : 0;
}

/*
 * Return the type bitfield for all the app types
 * associated with the given application ID.
 *
 * We can only convert Qosmos app IDs to types, since each Qosmos app ID
 * has a unique set of types - whereas user-defined app IDs can be associated
 * with different types in different rules.
 */
static uint64_t
dpi_app_id_to_type_bitfield(uint32_t app_id)
{
	assert(APP_ID_QOSMOS(app_id));

	struct qmdpi_signature *signature =
		qmdpi_worker_signature_get_byid(dpi_worker[dp_lcore_id()],
						dpi_bundle,
						app_id & DPI_APP_MASK);

	return qmdpi_signature_tags_get(signature);
}

/* Return the type name associated with the given application type. */
const char *
dpi_app_type_to_name(uint32_t app_type)
{
	return qmdpi_tag_name_get_byid(dpi_bundle, app_type);
}

/*
 * Converts an application ID into a string, writing it to the buffer at
 * "used_buf_len", ensuring it does not go off the end of the buffer.
 *
 * This also handles ids DPI_APP_NA, ERROR and UNDETERMINED.
 */
static void
dpi_app_name_to_str(char *buf, size_t *used_buf_len, const size_t total_buf_len,
		 uint32_t id)
{
	const char *str = dpi_app_id_to_name(id);

	switch (id & DPI_APP_MASK) {
	case DPI_APP_NA:
		buf_app_printf(buf, used_buf_len, total_buf_len, "<N/A>");
		break;

	case DPI_APP_ERROR:
		buf_app_printf(buf, used_buf_len, total_buf_len, "<ERROR>");
		break;

	case DPI_APP_UNDETERMINED:
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "<UNDETERMINED>");
		break;

	default:
		if (str) {
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%s", str);
		} else {
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%u", id);
		}
	}
}

#define MAX_JSON_DPI_NAME_SIZE 128

/*
 * Outputs as a JSON string field called "field_name" which contains
 * the application ID converted into a name.
 */
static void
dpi_app_name_json(json_writer_t *json, const char *field_name, uint32_t id)
{
	char str[MAX_JSON_DPI_NAME_SIZE];
	size_t used_buf_len = 0;

	dpi_app_name_to_str(str, &used_buf_len, MAX_JSON_DPI_NAME_SIZE, id);
	jsonw_string_field(json, field_name, str);
}

/*
 * go through the type bits and create an array of types by name.
 */
static void
dpi_types_json(json_writer_t *json, const char *field_name, uint64_t type_bits)
{
	jsonw_name(json, field_name);
	jsonw_start_array(json);

	while (type_bits) {
		uint32_t next_psn = __builtin_ffsl(type_bits);
		const char *str = dpi_app_type_to_name(next_psn);
		if (str) {
			jsonw_string(json, str);
		} else {
			char buf[40];
			snprintf(buf, sizeof(buf), "%u", next_psn);
			jsonw_string(json, buf);
		}
		/* unset the bit just processed */
		type_bits &= (type_bits - 1);
	}
	jsonw_end_array(json);
}

/*
 * This exports using JSON the DPI information associated with the flow
 */
void
dpi_info_json(struct dpi_flow *dpi_flow, json_writer_t *json)
{
	jsonw_name(json, "dpi");
	jsonw_start_object(json);

	dpi_app_name_json(json, "app-name", dpi_flow_get_app_name(dpi_flow));
	dpi_app_name_json(json, "proto-name", dpi_flow_get_app_proto(dpi_flow));

	jsonw_uint_field(json, "type-bits", dpi_flow_get_app_type(dpi_flow));
	dpi_types_json(json, "types", dpi_flow_get_app_type(dpi_flow));

	jsonw_bool_field(json, "offloaded", dpi_flow_get_offloaded(dpi_flow));
	jsonw_bool_field(json, "error", dpi_flow_get_error(dpi_flow));

	const struct dpi_flow_stats *stats = dpi_flow_get_stats(dpi_flow, true);
	jsonw_uint_field(json, "forward-pkts", stats->pkts);
	jsonw_uint_field(json, "forward-bytes", stats->bytes);

	stats = dpi_flow_get_stats(dpi_flow, false);
	jsonw_uint_field(json, "backward-pkts", stats->pkts);
	jsonw_uint_field(json, "backward-bytes", stats->bytes);

	jsonw_end_object(json);
}

/*
 * This logs into a string the DPI information associated with the flow.
 */
void
dpi_info_log(struct dpi_flow *dpi_flow, char *buf, size_t buf_len)
{
	size_t used_buf_len = 0;
	const uint32_t app_name = dpi_flow_get_app_name(dpi_flow);
	const uint32_t app_proto = dpi_flow_get_app_proto(dpi_flow);

	buf_app_printf(buf, &used_buf_len, buf_len, "app-name=");
	dpi_app_name_to_str(buf, &used_buf_len, buf_len, app_name);
	if (app_proto != app_name) {
		buf_app_printf(buf, &used_buf_len, buf_len,
			       " proto-name=");
		dpi_app_name_to_str(buf, &used_buf_len, buf_len,
				 app_proto);
	}
}
