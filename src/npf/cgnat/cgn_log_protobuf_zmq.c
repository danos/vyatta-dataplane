/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_log_protobuf_zmq.c - cgnat logging sending protobufs over zmq
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "compiler.h"
#include "if_var.h"
#include "util.h"
#include "soft_ticks.h"
#include "czmq.h"
#include "zmq_dp.h"

#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn_sess_state.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_time.h"
#include "npf/nat/nat_pool.h"
#include "npf/cgnat/cgn_log_protobuf_zmq.h"

#include "protobuf/CgnatLogging.pb-c.h"

struct cgn_zmq {
	zsock_t *sock;
	void *ul_sock;
	struct rcu_head rcu;
};

struct cgnat_zmq_ctx {
	const char *endpoint;
	rte_spinlock_t lock;
	rte_atomic32_t hwm;
	struct cgn_zmq *sender;
	rte_atomic64_t msgs_sent;
	rte_atomic64_t init_fails;
	rte_atomic64_t send_fails;
	rte_atomic64_t no_channel;
};

struct cgnat_zmq_ctx cgnat_zmq_ctx[CGN_LOG_TYPE_COUNT] = {
	[CGN_LOG_TYPE_SESSION] = {
		.endpoint = "ipc:///var/run/vyatta/cgnat-event-session",
		.lock = RTE_SPINLOCK_INITIALIZER,
	},
	[CGN_LOG_TYPE_PORT_BLOCK_ALLOCATION] = {
		.endpoint =
		     "ipc:///var/run/vyatta/cgnat-event-port-block-allocation",
		.lock = RTE_SPINLOCK_INITIALIZER,
	},
	[CGN_LOG_TYPE_SUBSCRIBER] = {
		.endpoint = "ipc:///var/run/vyatta/cgnat-event-subscriber",
		.lock = RTE_SPINLOCK_INITIALIZER,
	},
	[CGN_LOG_TYPE_RES_CONSTRAINT] = {
		.endpoint =
			"ipc:///var/run/vyatta/cgnat-event-resource-constraint",
		.lock = RTE_SPINLOCK_INITIALIZER,
	},
};

void cgn_show_zmq(FILE *f)
{
	enum cgn_log_type ltype;
	uint64_t count;
	uint32_t count32;
	const char *ltype_name;
	struct cgn_zmq *sender;
	struct cgnat_zmq_ctx *zmqctx;

	json_writer_t *json;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "zmq");
	jsonw_start_object(json);

	jsonw_name(json, "statistics");
	jsonw_start_array(json);

	for (ltype = 0; ltype < CGN_LOG_TYPE_COUNT; ltype++) {

		jsonw_start_object(json);

		ltype_name = cgn_get_log_type_name(ltype);
		jsonw_string_field(json, "logtype",
				   ltype_name ? ltype_name : "unknown");

		count = rte_atomic64_read(&cgnat_zmq_ctx[ltype].msgs_sent);
		jsonw_uint_field(json, "msgs_sent", count);

		count = rte_atomic64_read(&cgnat_zmq_ctx[ltype].init_fails);
		jsonw_uint_field(json, "init_fails", count);

		count = rte_atomic64_read(&cgnat_zmq_ctx[ltype].send_fails);
		jsonw_uint_field(json, "send_fails", count);

		count = rte_atomic64_read(&cgnat_zmq_ctx[ltype].no_channel);
		jsonw_uint_field(json, "no_channel", count);

		jsonw_end_object(json);
	}

	jsonw_end_array(json);

	jsonw_name(json, "config");
	jsonw_start_array(json);

	for (ltype = 0; ltype < CGN_LOG_TYPE_COUNT; ltype++) {

		jsonw_start_object(json);

		ltype_name = cgn_get_log_type_name(ltype);
		jsonw_string_field(json, "logtype",
				   ltype_name ? ltype_name : "unknown");

		zmqctx = &cgnat_zmq_ctx[ltype];

		count32 = rte_atomic32_read(&zmqctx->hwm);
		jsonw_uint_field(json, "configured_hwm", count32);

		sender = rcu_dereference(zmqctx->sender);
		if (sender != NULL && sender->sock != NULL) {
			int act_snd_hwm = zsock_sndhwm(sender->sock);
			int act_rcv_hwm = zsock_rcvhwm(sender->sock);

			jsonw_uint_field(json, "actual_snd_hwm", act_snd_hwm);
			jsonw_uint_field(json, "actual_rcv_hwm", act_rcv_hwm);
		}

		jsonw_end_object(json);
	}

	jsonw_end_array(json);

	jsonw_end_object(json);
	jsonw_destroy(&json);
}

static void cl_reclaim_zmqctx(struct rcu_head *rp)
{
	struct cgn_zmq *cgn_zmq = container_of(rp, struct cgn_zmq, rcu);

	free(cgn_zmq);
}

/*
 * Function called when zmq protobuf logging is enabled for a log type
 */
static int cl_zmq_init(enum cgn_log_type ltype,
		       const struct cgn_log_fns *fns __unused)
{
	struct cgnat_zmq_ctx *zmqctx;
	struct cgn_zmq *sender;
	int ret;

	if (ltype >= CGN_LOG_TYPE_COUNT)
		return -EINVAL;

	zmqctx = &cgnat_zmq_ctx[ltype];

	sender = rcu_dereference(zmqctx->sender);
	if (sender != NULL)
		return -EEXIST;

	sender = calloc(sizeof(*sender), 1);

	if (sender == NULL)
		return -ENOMEM;

	rte_spinlock_lock(&zmqctx->lock);

	sender->sock = zsock_new(ZMQ_PUSH);
	if (sender->sock == NULL) {
		RTE_LOG(ERR, CGNAT, "%s: zsock_new failed (%s)\n",
			__func__, strerror(errno));
		free(sender);
		rte_spinlock_unlock(&zmqctx->lock);
		return -ECONNREFUSED;
	}

	/* NB: HWMs need set before zsock_bind() */
	zsock_set_sndhwm(sender->sock, rte_atomic32_read(&zmqctx->hwm));
	zsock_set_rcvhwm(sender->sock, rte_atomic32_read(&zmqctx->hwm));

	ret = zsock_bind(sender->sock, "%s", zmqctx->endpoint);

	if (ret < 0) {
		RTE_LOG(ERR, CGNAT, "%s: zsock_bind(%s) failed (%s)\n",
			__func__, zmqctx->endpoint, strerror(errno));
		zsock_destroy(&(sender->sock));
		free(sender);
		rte_spinlock_unlock(&zmqctx->lock);
		return -ECONNREFUSED;
	}

	sender->ul_sock = zsock_resolve(sender->sock);

	if (sender->ul_sock == NULL) {
		RTE_LOG(ERR, CGNAT, "%s: zsock_resolve failed for %s (%s)\n",
			__func__, zmqctx->endpoint, strerror(errno));
		zsock_destroy(&(sender->sock));
		free(sender);
		rte_spinlock_unlock(&zmqctx->lock);
		return -ENOTSOCK;
	}

	rcu_assign_pointer(zmqctx->sender, sender);

	rte_spinlock_unlock(&zmqctx->lock);
	return 0;
}

/*
 * Function called when zmw protobuf logging is disabled for a log type
 */
static void cl_zmq_fini(enum cgn_log_type ltype,
			const struct cgn_log_fns *fns __unused)
{
	struct cgnat_zmq_ctx *zmqctx;
	struct cgn_zmq *old_sender;

	if (ltype >= CGN_LOG_TYPE_COUNT)
		return;

	zmqctx = &cgnat_zmq_ctx[ltype];

	rte_spinlock_lock(&zmqctx->lock);

	old_sender = zmqctx->sender;
	rcu_assign_pointer(zmqctx->sender, NULL);

	if (old_sender != NULL) {
		zsock_destroy(&(old_sender->sock));
		call_rcu(&old_sender->rcu, cl_reclaim_zmqctx);
	}

	rte_spinlock_unlock(&zmqctx->lock);
}

int cl_zmq_set_hwm(enum cgn_log_type ltype, int32_t hwm)
{
	struct cgnat_zmq_ctx *zmqctx;

	if (ltype >= CGN_LOG_TYPE_COUNT)
		return -EINVAL;

	zmqctx = &cgnat_zmq_ctx[ltype];

	rte_atomic32_set(&(zmqctx->hwm), hwm);

	return 0;
}

/*
 * Function back-called by czmq library to free the allocated buffer
 * that has just been sent out.
 */
static void cl_protobuf_msg_free(void *data, void *hint __unused)
{
	free(data);
}

/*
 * Send a serialised protobuf message down the ZMQ channel associated with
 * the log type.
 *
 * Note: on return the buffer passed in will be freed, even if there is
 * an error.
 */
static int cl_protobuf_zmq_send(enum cgn_log_type ltype, void *buf,
				unsigned int buflen)
{
	int rv;
	zmq_msg_t zpb;
	struct cgnat_zmq_ctx *zmqctx = &cgnat_zmq_ctx[ltype];
	struct cgn_zmq *sender = rcu_dereference(zmqctx->sender);

	if (sender == NULL) {	/* using protobufs not currently enabled */
		rte_atomic64_inc(&zmqctx->no_channel);
		cl_protobuf_msg_free(buf, NULL);
		if (net_ratelimit())
			RTE_LOG(DEBUG, CGNAT, "%s: channel no set-up",
				 __func__);
		return 0;
	}

	rte_spinlock_lock(&zmqctx->lock);

	/* send the protobuf (without copying) */

	rv = zmq_msg_init_data(&zpb, buf, buflen, cl_protobuf_msg_free, NULL);
	if (unlikely(rv < 0)) {
		rte_atomic64_inc(&zmqctx->init_fails);
		cl_protobuf_msg_free(buf, NULL);
		if (net_ratelimit())
			RTE_LOG(DEBUG, CGNAT, "%s: zmq_msg_init_data failure "
				"(%s)\n", __func__, strerror(errno));
		rte_spinlock_unlock(&zmqctx->lock);
		return -errno;
	}

	rv = zmq_msg_send(&zpb, sender->ul_sock, ZMQ_DONTWAIT);
	if (unlikely(rv < 0)) {
		rte_atomic64_inc(&zmqctx->send_fails);
		zmq_msg_close(&zpb);
		if (net_ratelimit())
			RTE_LOG(DEBUG, CGNAT, "%s: zmq_send failure (%s)\n",
				__func__, strerror(errno));
		rte_spinlock_unlock(&zmqctx->lock);
		return -errno;
	}

	rte_atomic64_inc(&zmqctx->msgs_sent);
	zmq_msg_close(&zpb);

	rte_spinlock_unlock(&zmqctx->lock);
	return 0;
}

static inline void microsecs_to_timestamp(uint64_t micro_secs, Timestamp *ts)
{
	ts->has_seconds = 1;
	ts->seconds = micro_secs / 1000000;

	ts->has_nanos = 1;
	ts->nanos = (micro_secs - (ts->seconds * 1000000)) * 1000;
}

/*
 * Send a protobuf structure down the subscriber ZMQ channel
 */
static int cl_protobuf_log_send_subscriber(SubscriberLog *msg)
{
	unsigned int buflen = subscriber_log__get_packed_size(msg);
	void *buf = malloc(buflen);

	if (unlikely(buf == NULL)) {
		if (net_ratelimit())
			RTE_LOG(ERR, CGNAT, "%s: buffer allocation\n",
				__func__);
		return -ENOMEM;
	}

	subscriber_log__pack(msg, buf);

	return cl_protobuf_zmq_send(CGN_LOG_TYPE_SUBSCRIBER, buf, buflen);
}

/*
 * Log subscriber session start - SUBSCRIBER_EVENT_START
 */
static void cl_protobuf_subscriber_start(uint32_t addr)
{
	SubscriberLog msg = SUBSCRIBER_LOG__INIT;
	Timestamp start_ts = TIMESTAMP__INIT;

	msg.has_eventtype = 1;
	msg.eventtype = SUBSCRIBER_EVENT_TYPE__SUBSCRIBER_EVENT_START;

	msg.has_subscriberaddress = 1;
	msg.subscriberaddress = addr;

	microsecs_to_timestamp(cgn_ticks2timestamp(soft_ticks), &start_ts);
	msg.starttimestamp = &start_ts;

	cl_protobuf_log_send_subscriber(&msg);
}

/*
 * Log subscriber session end - SUBSCRIBER_EVENT_END
 */
static void cl_protobuf_subscriber_end(uint32_t addr, uint64_t start_time,
				       uint64_t end_time, uint64_t pkts_out,
				       uint64_t bytes_out, uint64_t pkts_in,
				       uint64_t bytes_in, uint64_t sessions)
{
	SubscriberLog msg = SUBSCRIBER_LOG__INIT;
	Timestamp start_ts = TIMESTAMP__INIT;
	Timestamp end_ts = TIMESTAMP__INIT;

	msg.has_eventtype = 1;
	msg.eventtype = SUBSCRIBER_EVENT_TYPE__SUBSCRIBER_EVENT_END;

	msg.has_subscriberaddress = 1;
	msg.subscriberaddress = addr;

	msg.has_sessioncount = 1;
	msg.sessioncount = sessions;

	msg.has_inbytes = 1;
	msg.inbytes = bytes_in;
	msg.has_outbytes = 1;
	msg.outbytes = bytes_out;
	msg.has_inpackets = 1;
	msg.inpackets = pkts_in;
	msg.has_outpackets = 1;
	msg.outpackets = pkts_out;

	microsecs_to_timestamp(cgn_ticks2timestamp(start_time), &start_ts);
	msg.starttimestamp = &start_ts;
	microsecs_to_timestamp(cgn_ticks2timestamp(end_time), &end_ts);
	msg.endtimestamp = &end_ts;

	cl_protobuf_log_send_subscriber(&msg);
}

/*
 * Send a protobuf structure down the port-block-allocation ZMQ channel
 */
static int cl_protobuf_log_send_pba(PortAllocationLog *msg)
{
	unsigned int buflen = port_allocation_log__get_packed_size(msg);
	void *buf = malloc(buflen);

	if (unlikely(buf == NULL)) {
		if (net_ratelimit())
			RTE_LOG(ERR, CGNAT, "%s: buffer allocation\n",
				__func__);
		return -ENOMEM;
	}

	port_allocation_log__pack(msg, buf);

	return cl_protobuf_zmq_send(CGN_LOG_TYPE_PORT_BLOCK_ALLOCATION, buf,
				    buflen);
}

/*
 * Log port block allocation - PB_EVENT_ALLOCATED
 */
static void cl_protobuf_pb_alloc(uint32_t pvt_addr, uint32_t pub_addr,
				 uint16_t port_start, uint16_t port_end,
				 uint64_t start_time, const char *policy_name,
				 const char *pool_name)
{
	PortAllocationLog msg = PORT_ALLOCATION_LOG__INIT;
	Timestamp start_ts = TIMESTAMP__INIT;

	msg.has_eventtype = 1;
	msg.eventtype = PORT_ALLOCATION_EVENT_TYPE__PB_EVENT_ALLOCATED;

	msg.has_subscriberaddress = 1;
	msg.subscriberaddress = pvt_addr;

	if (policy_name)
		msg.policyname = (char *)policy_name;

	msg.has_natallocatedaddress = 1;
	msg.natallocatedaddress = pub_addr;

	if (pool_name)
		msg.poolname = (char *)pool_name;

	msg.has_startportnumber = 1;
	msg.startportnumber = port_start;

	msg.has_endportnumber = 1;
	msg.endportnumber = port_end;

	microsecs_to_timestamp(cgn_ticks2timestamp(start_time), &start_ts);
	msg.starttimestamp = &start_ts;

	cl_protobuf_log_send_pba(&msg);
}

/*
 * Log port block release - PB_EVENT_RELEASED
 */
static void cl_protobuf_pb_release(uint32_t pvt_addr, uint32_t pub_addr,
				   uint16_t port_start, uint16_t port_end,
				   uint64_t start_time, uint64_t end_time,
				   const char *policy_name,
				   const char *pool_name)
{
	PortAllocationLog msg = PORT_ALLOCATION_LOG__INIT;
	Timestamp start_ts = TIMESTAMP__INIT;
	Timestamp end_ts = TIMESTAMP__INIT;

	msg.has_eventtype = 1;
	msg.eventtype = PORT_ALLOCATION_EVENT_TYPE__PB_EVENT_RELEASED;

	msg.has_subscriberaddress = 1;
	msg.subscriberaddress = pvt_addr;

	if (policy_name)
		msg.policyname = (char *)policy_name;

	msg.has_natallocatedaddress = 1;
	msg.natallocatedaddress = pub_addr;

	if (pool_name)
		msg.poolname = (char *)pool_name;

	msg.has_startportnumber = 1;
	msg.startportnumber = port_start;

	msg.has_endportnumber = 1;
	msg.endportnumber = port_end;

	microsecs_to_timestamp(cgn_ticks2timestamp(start_time), &start_ts);
	msg.starttimestamp = &start_ts;
	microsecs_to_timestamp(cgn_ticks2timestamp(end_time), &end_ts);
	msg.endtimestamp = &end_ts;

	cl_protobuf_log_send_pba(&msg);
}

static SessionState sess_state_to_pb(uint8_t state)
{
	switch (state) {
	case CGN_TCP_STATE_NONE:
		return SESSION_STATE__SESSION_NONE;
	case CGN_TCP_STATE_CLOSED:
		return SESSION_STATE__SESSION_CLOSED;
	case CGN_TCP_STATE_INIT:
		return SESSION_STATE__SESSION_OPENING;
	case CGN_TCP_STATE_ESTABLISHED:
		return SESSION_STATE__SESSION_ESTABLISHED;
	case CGN_TCP_STATE_TRANS:
		return SESSION_STATE__SESSION_TRANSITORY;
	case CGN_TCP_STATE_C_FIN_RCV:
		return SESSION_STATE__SESSION_C_FIN_RCV;
	case CGN_TCP_STATE_S_FIN_RCV:
		return SESSION_STATE__SESSION_S_FIN_RCV;
	case CGN_TCP_STATE_CS_FIN_RCV:
		return SESSION_STATE__SESSION_CS_FIN_RCV;
	};

	return SESSION_STATE__SESSION_OTHER;
}

static void cl_protobuf_sess_common(struct cgn_sess2 *s2, SessionLog *msg)
{
	struct cgn_session *cse = cgn_sess2_session(s2);
	struct ifnet *ifp = dp_ifnet_byifindex(cgn_session_ifindex(cse));
	struct cgn_state *state = cgn_sess2_state(s2);
	uint16_t port;

	msg->has_sessionid = 1;
	msg->sessionid = cgn_session_id(cse);

	msg->has_subsessionid = 1;
	msg->subsessionid = cgn_sess2_id(s2);

	if (ifp)
		msg->ifname = ifp->if_name;

	msg->has_protocol = 1;
	msg->protocol = cgn_sess2_ipproto(s2);

	msg->has_direction = 1;
	if (cgn_sess2_dir(s2) == CGN_DIR_IN)
		msg->direction = DIRECTION__DIRECTION_IN;
	else
		msg->direction = DIRECTION__DIRECTION_OUT;

	msg->has_subscriberaddress = 1;
	msg->subscriberaddress = ntohl(cgn_session_forw_addr(cse));

	msg->has_subscriberport = 1;
	port = cgn_session_forw_id(cse);
	msg->subscriberport = ntohs(port);

	msg->has_natallocatedaddress = 1;
	msg->natallocatedaddress = ntohl(cgn_session_back_addr(cse));

	msg->has_natallocatedport = 1;
	port = cgn_session_back_id(cse);
	msg->natallocatedport = ntohs(port);

	msg->has_destinationaddress = 1;
	msg->destinationaddress = ntohl(cgn_sess2_addr(s2));

	msg->has_destinationport = 1;
	port = cgn_sess2_port(s2);
	msg->destinationport = ntohs(port);

	msg->has_state = 1;
	msg->state = sess_state_to_pb(state->st_state);

	if (state->st_proto == NAT_PROTO_TCP) {
		msg->has_statehistory = 1;
		msg->statehistory = state->st_hist;
	}

	/*
	 * Note that the session start time is stored in microseconds,
	 * rather than milliseconds, as used in rtt calculations.
	 */
	microsecs_to_timestamp(cgn_sess2_start_time(s2), msg->starttimestamp);
}

/*
 * Send a protobuf structure down the session ZMQ channel
 */
static int cl_protobuf_log_send_session(SessionLog *msg)
{
	unsigned int buflen = session_log__get_packed_size(msg);
	void *buf = malloc(buflen);

	if (unlikely(buf == NULL)) {
		if (net_ratelimit())
			RTE_LOG(ERR, CGNAT, "%s: buffer allocation\n",
				__func__);
		return -ENOMEM;
	}

	session_log__pack(msg, buf);

	return cl_protobuf_zmq_send(CGN_LOG_TYPE_SESSION, buf, buflen);
}

/*
 * Log session creation - SESSION_EVENT_CREATE
 */
static void cl_protobuf_sess_start(struct cgn_sess2 *s2)
{
	SessionLog msg = SESSION_LOG__INIT;
	Timestamp start_ts = TIMESTAMP__INIT;

	msg.starttimestamp = &start_ts;

	cl_protobuf_sess_common(s2, &msg);

	msg.has_eventtype = 1;
	msg.eventtype = SESSION_EVENT_TYPE__SESSION_EVENT_CREATE;

	cl_protobuf_log_send_session(&msg);
}

static void cl_protobuf_sess_active_and_end(struct cgn_sess2 *s2,
					    SessionEventType eventtype,
					    uint64_t time2)
{
	SessionLog msg = SESSION_LOG__INIT;
	Timestamp start_ts = TIMESTAMP__INIT;
	Timestamp cur_ts = TIMESTAMP__INIT;
	struct cgn_state *state = cgn_sess2_state(s2);

	msg.starttimestamp = &start_ts;

	cl_protobuf_sess_common(s2, &msg);

	msg.has_eventtype = 1;
	msg.eventtype = eventtype;

	msg.has_inbytes = 1;
	msg.inbytes = cgn_sess2_bytes_in_tot(s2);
	msg.has_outbytes = 1;
	msg.outbytes = cgn_sess2_bytes_out_tot(s2);
	msg.has_inpackets = 1;
	msg.inpackets = cgn_sess2_pkts_in_tot(s2);
	msg.has_outpackets = 1;
	msg.outpackets = cgn_sess2_pkts_out_tot(s2);

	if (state->st_proto == NAT_PROTO_TCP) {
		msg.has_networkroundtriptime = 1;
		msg.networkroundtriptime = state->st_int_rtt;
		msg.has_internetroundtriptime = 1;
		msg.internetroundtriptime = state->st_ext_rtt;
	}

	microsecs_to_timestamp(time2, &cur_ts);
	msg.currenttimestamp = &cur_ts;

	cl_protobuf_log_send_session(&msg);
}

/*
 * Periodic logging - SESSION_EVENT_ACTIVE
 */
static void cl_protobuf_sess_active(struct cgn_sess2 *s2)
{
	cl_protobuf_sess_active_and_end(s2,
		SESSION_EVENT_TYPE__SESSION_EVENT_ACTIVE, cgn_time_usecs());
}

/*
 * Log 5-tuple session end - SESSION_EVENT_END
 */
static void cl_protobuf_sess_end(struct cgn_sess2 *s2, uint64_t end_time)
{
	cl_protobuf_sess_active_and_end(s2,
		SESSION_EVENT_TYPE__SESSION_EVENT_END, end_time);
}

static ConstraintLimit constraint_limit_to_pb(enum cgn_resource_type type)
{
	switch (type) {
	case CGN_RESOURCE_FULL:
		return CONSTRAINT_LIMIT__CONSTRAINT_LIMIT_FULL;
	case CGN_RESOURCE_AVAILABLE:
		return CONSTRAINT_LIMIT__CONSTRAINT_LIMIT_AVAILABLE;
	case CGN_RESOURCE_THRESHOLD:
		return CONSTRAINT_LIMIT__CONSTRAINT_LIMIT_THRESHOLD;
	};

	return CONSTRAINT_LIMIT__CONSTRAINT_LIMIT_UNKNOWN;
}

static void cl_protobuf_resource_common(enum cgn_resource_type type,
					ConstraintEventType eventtype,
					ConstraintLog *msg)
{
	msg->has_eventtype = 1;
	msg->eventtype = eventtype;

	msg->has_constraintlimit = 1;
	msg->constraintlimit = constraint_limit_to_pb(type);

	microsecs_to_timestamp(cgn_ticks2timestamp(soft_ticks), msg->timestamp);
}

/*
 * Send a protobuf structure down the resource constraint ZMQ channel
 */
static int cl_protobuf_log_send_res_constraint(ConstraintLog *msg)
{
	unsigned int buflen = constraint_log__get_packed_size(msg);
	void *buf = malloc(buflen);

	if (unlikely(buf == NULL)) {
		if (net_ratelimit())
			RTE_LOG(ERR, CGNAT, "%s: buffer allocation\n",
				__func__);
		return -ENOMEM;
	}

	constraint_log__pack(msg, buf);

	return cl_protobuf_zmq_send(CGN_LOG_TYPE_RES_CONSTRAINT, buf, buflen);
}

static void cl_protobuf_resource_common_count_and_max(
	enum cgn_resource_type resource_type, ConstraintEventType eventtype,
	int32_t count, int32_t max_count)
{
	ConstraintLog msg = CONSTRAINT_LOG__INIT;
	Timestamp cur_ts = TIMESTAMP__INIT;

	msg.timestamp = &cur_ts;

	cl_protobuf_resource_common(resource_type, eventtype, &msg);

	msg.has_count = 1;
	msg.count = count;

	msg.has_maxcount = 1;
	msg.maxcount = max_count;

	cl_protobuf_log_send_res_constraint(&msg);
}

/*
 * Log CONSTRAINT_EVENT_SUBSCRIBER_TABLE
 */
static void cl_protobuf_resource_subscriber_table(enum cgn_resource_type type,
						  int32_t count,
						  int32_t max_count)
{
	cl_protobuf_resource_common_count_and_max(type,
		CONSTRAINT_EVENT_TYPE__CONSTRAINT_EVENT_SUBSCRIBER_TABLE,
		count, max_count);
}

/*
 * Log CONSTRAINT_EVENT_SESSION_TABLE
 */
static void cl_protobuf_resource_session_table(enum cgn_resource_type type,
					       int32_t count, int32_t max_count)
{
	cl_protobuf_resource_common_count_and_max(type,
		CONSTRAINT_EVENT_TYPE__CONSTRAINT_EVENT_SESSION_TABLE,
		count, max_count);
}

/*
 * Logs CONSTRAINT_EVENT_MAPPING_TABLE
 */
static void cl_protobuf_resource_apm_table(enum cgn_resource_type type,
					   int32_t count, int32_t limit_count)
{
	cl_protobuf_resource_common_count_and_max(type,
		CONSTRAINT_EVENT_TYPE__CONSTRAINT_EVENT_MAPPING_TABLE,
		count, limit_count);
}

/*
 * Log CONSTRAINT_EVENT_DEST_SESSIONS
 */
static void cl_protobuf_resource_dest_session_table(enum cgn_resource_type type,
						    struct cgn_session *cse,
						    int16_t count,
						    int16_t max_count)
{
	ConstraintLog msg = CONSTRAINT_LOG__INIT;
	Timestamp cur_ts = TIMESTAMP__INIT;
	struct ifnet *ifp = dp_ifnet_byifindex(cgn_session_ifindex(cse));
	uint16_t port;

	msg.timestamp = &cur_ts;

	cl_protobuf_resource_common(type,
		CONSTRAINT_EVENT_TYPE__CONSTRAINT_EVENT_DEST_SESSIONS, &msg);

	msg.has_count = 1;
	msg.count = count;

	msg.has_maxcount = 1;
	msg.maxcount = max_count;

	msg.has_sessionid = 1;
	msg.sessionid = cgn_session_id(cse);

	if (ifp)
		msg.ifname = ifp->if_name;

	msg.has_protocol = 1;
	msg.protocol = cgn_session_ipproto(cse);

	msg.has_subscriberaddress = 1;
	msg.subscriberaddress = ntohl(cgn_session_forw_addr(cse));

	msg.has_subscriberport = 1;
	port = cgn_session_forw_id(cse);
	msg.subscriberport = ntohs(port);

	msg.has_natallocatedaddress = 1;
	msg.natallocatedaddress = ntohl(cgn_session_back_addr(cse));

	msg.has_natallocatedport = 1;
	port = cgn_session_back_id(cse);
	msg.natallocatedport = ntohs(port);

	cl_protobuf_log_send_res_constraint(&msg);
}

/*
 * Logs for subscriber resource limits - CONSTRAINT_EVENT_BLOCKS_PER_SUBSCRIBER
 */
static void
cl_protobuf_resource_subscriber_mbpu(enum cgn_resource_type type, uint32_t addr,
				     uint8_t ipproto, uint16_t count,
				     uint16_t max_count)
{
	ConstraintLog msg = CONSTRAINT_LOG__INIT;
	Timestamp cur_ts = TIMESTAMP__INIT;

	msg.timestamp = &cur_ts;

	cl_protobuf_resource_common(type,
		CONSTRAINT_EVENT_TYPE__CONSTRAINT_EVENT_BLOCKS_PER_SUBSCRIBER,
		&msg);

	msg.has_count = 1;
	msg.count = count;

	msg.has_maxcount = 1;
	msg.maxcount = max_count;

	msg.has_subscriberaddress = 1;
	msg.subscriberaddress = addr;

	/* ipproto will be 0 for 'other' (i.e. non-TCP and non-UDP) */
	msg.has_protocol = 1;
	msg.protocol = ipproto;

	cl_protobuf_log_send_res_constraint(&msg);
}

/*
 * Logs for public address blocks resource limits -
 * CONSTRAINT_EVENT_BLOCKS_FOR_NAT_ALLOC_ADDR
 */
static void cl_protobuf_resource_public_pb(enum cgn_resource_type type,
					   uint32_t addr, uint16_t blocks_used,
					   uint16_t nblocks)
{
	ConstraintLog msg = CONSTRAINT_LOG__INIT;
	Timestamp cur_ts = TIMESTAMP__INIT;

	msg.timestamp = &cur_ts;

	cl_protobuf_resource_common(type,
	      CONSTRAINT_EVENT_TYPE__CONSTRAINT_EVENT_BLOCKS_FOR_NAT_ALLOC_ADDR,
	      &msg);

	msg.has_count = 1;
	msg.count = blocks_used;

	msg.has_maxcount = 1;
	msg.maxcount = nblocks;

	msg.has_natallocatedaddress = 1;
	msg.natallocatedaddress = addr;

	cl_protobuf_log_send_res_constraint(&msg);
}

/*
 * Logs CONSTRAINT_EVENT_NAT_POOL
 */
static void cl_protobuf_resource_pool(enum cgn_resource_type type,
				      struct nat_pool *np, int32_t count,
				      int32_t max_count)
{
	ConstraintLog msg = CONSTRAINT_LOG__INIT;
	Timestamp cur_ts = TIMESTAMP__INIT;

	msg.timestamp = &cur_ts;

	cl_protobuf_resource_common(type,
		CONSTRAINT_EVENT_TYPE__CONSTRAINT_EVENT_NAT_POOL, &msg);

	msg.has_count = 1;
	msg.count = count;

	msg.has_maxcount = 1;
	msg.maxcount = max_count;

	msg.poolname = np->np_name;

	cl_protobuf_log_send_res_constraint(&msg);
}

/*
 * Log a session clear event (CONSTRAINT_EVENT_SESSION_CLEAR).  This is done
 * when one or more 2-tuple sessions are cleared manually, either from a clear
 * command or a change in config (e.g. nat pool block size changes).  This
 * log message replaces the multiple SESSION_EVENT_END log messages in order
 * to avoid scale issues.
 */
static void
cl_protobuf_sess_clear(const char *desc, uint count, uint64_t clear_time)
{
	ConstraintLog msg = CONSTRAINT_LOG__INIT;
	Timestamp cur_ts = TIMESTAMP__INIT;

	msg.has_eventtype = 1;
	msg.eventtype = CONSTRAINT_EVENT_TYPE__CONSTRAINT_EVENT_SESSION_CLEAR;

	msg.timestamp = &cur_ts;
	microsecs_to_timestamp(cgn_ticks2timestamp(clear_time), msg.timestamp);

	msg.has_count = 1;
	msg.count = count;

	msg.desc = (char *)desc;

	cl_protobuf_log_send_res_constraint(&msg);
}

const struct cgn_session_log_fns cgn_session_protobuf_fns = {
	.cl_sess_start = cl_protobuf_sess_start,
	.cl_sess_active = cl_protobuf_sess_active,
	.cl_sess_end = cl_protobuf_sess_end,
};

const struct cgn_port_block_alloc_log_fns cgn_port_block_alloc_protobuf_fns = {
	.cl_pb_alloc = cl_protobuf_pb_alloc,
	.cl_pb_release = cl_protobuf_pb_release,
};

const struct cgn_subscriber_log_fns cgn_subscriber_protobuf_fns = {
	.cl_subscriber_start = cl_protobuf_subscriber_start,
	.cl_subscriber_end = cl_protobuf_subscriber_end,
};

const struct cgn_res_constraint_log_fns cgn_res_constraint_protobuf_fns = {
	.cl_resource_subscriber_mbpu = cl_protobuf_resource_subscriber_mbpu,
	.cl_resource_public_pb = cl_protobuf_resource_public_pb,
	.cl_sess_clear = cl_protobuf_sess_clear,
	.cl_resource_subscriber_table = cl_protobuf_resource_subscriber_table,
	.cl_resource_session_table = cl_protobuf_resource_session_table,
	.cl_resource_dest_session_table =
		cl_protobuf_resource_dest_session_table,
	.cl_resource_apm_table = cl_protobuf_resource_apm_table,
	.cl_resource_pool = cl_protobuf_resource_pool,
};

const struct cgn_log_fns cgn_protobuf_fns = {
	.cl_name = "protobuf",
	.cl_init = cl_zmq_init,
	.cl_fini = cl_zmq_fini,
	.logfn[CGN_LOG_TYPE_SESSION].session =
		&cgn_session_protobuf_fns,
	.logfn[CGN_LOG_TYPE_PORT_BLOCK_ALLOCATION].port_block_alloc =
		&cgn_port_block_alloc_protobuf_fns,
	.logfn[CGN_LOG_TYPE_SUBSCRIBER].subscriber =
		&cgn_subscriber_protobuf_fns,
	.logfn[CGN_LOG_TYPE_RES_CONSTRAINT].res_constraint =
		&cgn_res_constraint_protobuf_fns,
};
