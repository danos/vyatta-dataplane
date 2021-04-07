/*
 * Flow stat pipeline feature node
 *
 * Copyright (c) 2021, SafePoint.  All rights reserved.
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * To generate the protobuf message source:
 * "protoc-c -I=. --c_out=. ./FlowStatFeatConfig.proto"
 *
 * To compile flow_stat as a standalone:
 * "gcc -shared -fPIC flowstat.c -I/usr/include/vyatta-dataplane
 *  $(pkg-config --cflags libdpdk) -o libflowstat.so"
 *
 */
#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>
#include <urcu.h>	    /* RCU flavor */
#include <urcu/rculfhash.h> /* RCU Lock-free hash table */
#include <urcu/compiler.h>
#include <urcu/uatomic.h>
#include <urcu/wfcqueue.h>
#include <rte_jhash.h>
#include <rte_cycles.h>

#include "compiler.h"
#include "debug.h"
#include "dp_session.h"
#include "feature_commands.h"
#include "feature_plugin.h"
#include "json_writer.h"
#include "pipeline.h"

#include "flowstat.h"
#include "FlowStatFeatConfig.pb-c.h"
#include "FlowStatFeatOp.pb-c.h"

#define RTE_LOGTYPE_FLOWSTAT RTE_LOGTYPE_USER4

enum fstat_dispositions { FLOW_STAT_ACCEPT, FLOW_STAT_NUM };

enum log_level {
	NOT_SET_LEVEL = 0,
	CRIT_LEVEL = 10,
	WARN_LEVEL = 20,
	INFO_LEVEL = 30,
	DEBUG_LEVEL = 40,
};

struct session_private {
	bool locked;
	bool is_long_lived; /* stat calculated by delta */
	time_t last_seen;
	time_t last_seen_tw;
	uint64_t last_pkts_in;
	uint64_t last_bytes_in;
	uint64_t last_pkts_out;
	uint64_t last_bytes_out;

	/* cached DPI */
	const char *app;
	const char *app_proto;
	const char *app_type;
};

/* Extra info for session */
#define SESSION_PRIVATE_ID 10001000
#define LOG_BUFFER_LIMIT 10000
#define LOG_MSG_SIZE 512
#define EXPORTER_FILE_BUFSIZ (LOG_MSG_SIZE * 1000)
#define EXPORTER_INTERVAL 5
#define LOG_TW_SESSION_INTERVAL 1
#define NPF_TCPS_TIME_WAIT 11

/* Buffer log */
static uint32_t log_buffer_count;

/* Config */
static bool is_enabled_global = true;
static int debug_level = INFO_LEVEL;

/*
 * Nodes populated into the queue.
 */
struct lognode {
	struct dp_session_info *info; /* Node content */
	struct cds_wfcq_node node;    /* Chaining in queue */
};

struct cds_wfcq_head logqueue_head; /* Queue head */
struct cds_wfcq_tail logqueue_tail; /* Queue tail */

/*
 * Enabled interfaces hash table.
 */
struct intf_node {
	char name[IFNAMSIZ];	   /* Interface name */
	struct cds_lfht_node node; /* Chaining in hash table */
};

struct cds_lfht *enabled_intf_ht;

#define ENABLED_INTF_HASH_MIN 4
#define ENABLED_INTF_HASH_MAX 0 /* Unlimited */

static inline uint32_t intf_hash_name(const char *ifname)
{
	char __ifname[IFNAMSIZ] __rte_aligned(sizeof(uint32_t));
	int len = MIN(strlen(ifname), sizeof(__ifname));

	memcpy(__ifname, ifname, len);
	return rte_jhash(__ifname, len, 0);
}

static inline int intf_match(struct cds_lfht_node *ht_node, const void *arg)
{
	const struct intf_node *node;
	const char *key = arg;

	node = caa_container_of(ht_node, struct intf_node, node);
	if ((strncmp(key, node->name, IFNAMSIZ) == 0))
		return 1;

	return 0;
}

static struct intf_node *intf_lookup(const char *ifname)
{
	struct intf_node *node = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ht_node;

	cds_lfht_lookup(enabled_intf_ht, intf_hash_name(ifname), intf_match,
			ifname, &iter);

	ht_node = cds_lfht_iter_get_node(&iter);
	if (ht_node)
		node = caa_container_of(ht_node, struct intf_node, node);

	return node;
}

static void format_session_log(char *buf, struct dp_session_info *info)
{
	time_t utc_now = mktime(gmtime(&info->timestamp));
	struct tm *ts = localtime(&info->timestamp);

	char srcip_str[INET6_ADDRSTRLEN];
	char dstip_str[INET6_ADDRSTRLEN];

	inet_ntop(info->se_af, &info->se_src_addr, srcip_str,
		  sizeof(srcip_str));
	inet_ntop(info->se_af, &info->se_dst_addr, dstip_str,
		  sizeof(dstip_str));

	sprintf(buf,
		"date=%04d-%02d-%02d "
		"time=%02d:%02d:%02d "
		"timestamp=%lu "
		"tz=\"%s\" "
		"session_id=%lu "
		"src_addr=%s src_port=%d "
		"dst_addr=%s dst_port=%d "
		"in_bytes=%lu in_pkts=%lu "
		"protocol=%d "
		"out_bytes=%lu out_pkts=%lu "
		"duration=%lu "
		"app_name=%s "
		"app_proto=%s "
		"app_type=%s "
		"if_name=\"%s\" ",
		ts->tm_year + 1900, ts->tm_mon + 1, ts->tm_mday, ts->tm_hour,
		ts->tm_min, ts->tm_sec, utc_now, ts->tm_zone, info->se_id,
		srcip_str, ntohs(info->se_src_port), dstip_str,
		ntohs(info->se_dst_port), info->se_bytes_in, info->se_pkts_in,
		info->se_protocol, info->se_bytes_out, info->se_pkts_out,
		info->duration, info->se_app_name ? info->se_app_name : "",
		info->se_app_proto ? info->se_app_proto : "",
		info->se_app_type ? info->se_app_type : "",
		info->se_ifname ? info->se_ifname : "");
}

static void export_log_to_file(struct lognode *nodes[], uint32_t size)
{
	FILE *f = fopen(FLOWSTAT_LOG, "a+");
	if (!f) {
		if (debug_level >= DEBUG_LEVEL)
			RTE_LOG(DEBUG, FLOWSTAT, "Failed to open log file\n");
		return;
	}

	char buf[EXPORTER_FILE_BUFSIZ];
	setbuf(f, buf);

	for (uint32_t i = 0; i < size; i++) {
		char msg[LOG_MSG_SIZE];
		format_session_log(msg, nodes[i]->info);
		fputs(msg, f);
		fputs("\n", f);
	}

	if (debug_level >= INFO_LEVEL)
		RTE_LOG(INFO, FLOWSTAT, "Flushed %d logs\n", size);

	fclose(f);
}

void export_log(void)
{
	struct lognode *buffer[LOG_BUFFER_LIMIT];
	uint32_t count = 0;

	/* get some limited items from queue */
	while (count < LOG_BUFFER_LIMIT) {
		struct cds_wfcq_node *qnode = __cds_wfcq_dequeue_nonblocking(
			&logqueue_head, &logqueue_tail);
		if (!qnode || qnode == CDS_WFCQ_WOULDBLOCK)
			break; /* empty queue or need block */

		uatomic_dec(&log_buffer_count);

		struct lognode *node =
			caa_container_of(qnode, struct lognode, node);
		buffer[count++] = node;
	}

	if (count > 0) {
		/* flush buffer to file */
		export_log_to_file(buffer, count);

		/* clean up */
		for (uint32_t i = 0; i < count; i++) {
			struct lognode *node = buffer[i];
			free(node->info);
			free(node);
		}
	}
}

static void *log_exporter_thread(void *args __unused)
{
	if (debug_level >= INFO_LEVEL) {
		unsigned long tid = syscall(SYS_gettid);
		RTE_LOG(INFO, FLOWSTAT, "Exporter started threadId=%lu\n", tid);
	}

	while (true) {
		export_log();
		sleep(EXPORTER_INTERVAL);
	}

	if (debug_level >= INFO_LEVEL)
		RTE_LOG(INFO, FLOWSTAT, "Exporter stopped\n");

	return NULL;
}

static void queue_log(struct dp_session_info *info)
{
	struct lognode *node = malloc(sizeof(struct lognode));
	if (!node)
		return;

	cds_wfcq_node_init(&node->node);
	node->info = info;
	cds_wfcq_enqueue(&logqueue_head, &logqueue_tail, &node->node);
	if (debug_level >= DEBUG_LEVEL) {
		char msg[LOG_MSG_SIZE];
		format_session_log(msg, info);
		RTE_LOG(DEBUG, FLOWSTAT, "Queued log %s\n", msg);
	}
}

static void add_session_log(struct session *s,
			    struct session_private *s_private,
			    enum dp_session_state state)
{
	uint32_t next = uatomic_add_return(&log_buffer_count, 1);
	if (next > LOG_BUFFER_LIMIT) {
		uatomic_dec(&log_buffer_count);
		return;
	}

	struct dp_session_info *info = malloc(sizeof(struct dp_session_info));
	dp_session_query(s, SESSION_ATTR_ALL, info);

	/* Load cached dpi for expired session */
	if (state == SESSION_STATE_CLOSED) {
		info->se_app_name = s_private->app;
		info->se_app_proto = s_private->app_proto;
		info->se_app_type = s_private->app_type;
	}

	time_t now = time(NULL);
	info->timestamp = now;

	/*
	 * duration
	 */
	int64_t duration = rte_get_timer_cycles() - info->se_create_time;
	duration = duration / rte_get_timer_hz();
	if (duration <= 0)
		duration = 1;
	info->duration = duration;

	if (s_private->is_long_lived) {
		uint64_t in_bytes, in_pkts, out_bytes, out_pkts;

		/* calc delta */
		in_bytes = info->se_bytes_in - s_private->last_bytes_in;
		in_pkts = info->se_pkts_in - s_private->last_pkts_in;
		out_bytes = info->se_bytes_out - s_private->last_bytes_out;
		out_pkts = info->se_pkts_out - s_private->last_pkts_out;

		/* no stats was updated, ignore it */
		if (!in_pkts && !out_pkts)
			return;

		/* update to latest stat */
		s_private->last_bytes_in = info->se_bytes_in;
		s_private->last_pkts_in = info->se_pkts_in;
		s_private->last_bytes_out = info->se_bytes_out;
		s_private->last_pkts_out = info->se_pkts_out;

		/* save delta for export */
		info->se_bytes_in = in_bytes;
		info->se_pkts_in = in_pkts;
		info->se_bytes_out = out_bytes;
		info->se_pkts_out = out_pkts;
	}

	queue_log(info);
}

static void add_es_session_log(struct session *s,
			       struct session_private *s_private,
			       enum dp_session_state state)
{
	/* try acquire lock */
	bool locked = uatomic_xchg(&s_private->locked, true);
	if (!locked) {
		s_private->is_long_lived = true;
		add_session_log(s, s_private, state);

		if (state == SESSION_STATE_ESTABLISHED)
			s_private->last_seen = time(NULL);
		else if (state == SESSION_STATE_TERMINATING)
			s_private->last_seen_tw = time(NULL);

		/* release lock */
		uatomic_set(&s_private->locked, false);
	} else if (debug_level >= DEBUG_LEVEL) {
		RTE_LOG(DEBUG, FLOWSTAT, "failed to acquire lock es\n");
	}
}

static void session_watch_cb(struct session *s, enum dp_session_hook hook,
			     void *data __unused)
{
	/* Check if feature is disabled global */
	if (!is_enabled_global)
		return;

	/* Check if feature is enabled for interface */
	struct dp_session_info info;
	dp_session_query(s, SESSION_ATTR_IF_NAME | SESSION_ATTR_PROTOCOL,
			 &info);

	rcu_read_lock();
	bool enabled = intf_lookup(info.se_ifname);
	rcu_read_unlock();

	if (!enabled)
		return;

	struct session_private *s_private = NULL;

	/* Set extra data for new session */
	if (hook == SESSION_ACTIVATE) {
		s_private = malloc(sizeof(*s_private));
		s_private->locked = false;
		s_private->is_long_lived = false;
		s_private->last_seen = time(NULL);
		s_private->last_seen_tw = 0;
		s_private->last_bytes_in = 0;
		s_private->last_pkts_in = 0;
		s_private->last_bytes_out = 0;
		s_private->last_pkts_out = 0;
		s_private->app = NULL;
		s_private->app_proto = NULL;
		s_private->app_type = NULL;

		dp_session_set_private(SESSION_PRIVATE_ID, s, s_private);
	} else {
		s_private = dp_session_get_private(SESSION_PRIVATE_ID, s);
	}

	if (!s_private)
		return;

	switch (hook) {
	case SESSION_STATS_UPDATE:
		if (dp_session_is_established(s)) {
			/* For long active connections, export log by interval
			 */
			double seconds =
				difftime(time(NULL), s_private->last_seen);
			if (seconds >= LOG_ES_SESSION_INTERVAL)
				add_es_session_log(s, s_private,
						   SESSION_STATE_ESTABLISHED);
		} else if (info.se_protocol == IPPROTO_TCP &&
			   info.se_protocol_state >= NPF_TCPS_TIME_WAIT) {
			double seconds =
				difftime(time(NULL), s_private->last_seen_tw);
			if (seconds >= LOG_TW_SESSION_INTERVAL)
				add_es_session_log(s, s_private,
						   SESSION_STATE_TERMINATING);
		}
		break;
	case SESSION_STATE_CHANGE:
		if (dp_session_get_state(s) == SESSION_STATE_TERMINATING) {
			/* Cache dpi info before session expired. Because
			 * expired session has no features, mean no dpi info.
			 */
			if (!s_private->app) {
				dp_session_query(s, SESSION_ATTR_DPI, &info);
				/* Make it dont try load again if not found any
				 * dpi
				 */
				s_private->app = info.se_app_name
							 ? info.se_app_name
							 : "";
				s_private->app_proto = info.se_app_proto;
				s_private->app_type = info.se_app_type;
			}
		}
		break;
	case SESSION_EXPIRE:
		/* Closed, add log */
		add_session_log(s, s_private, SESSION_STATE_CLOSED);

		/* Free private data, too */
		free(s_private);
		break;
	default:
		break;
	}

	if (debug_level >= DEBUG_LEVEL) {
		if (hook == SESSION_STATS_UPDATE) {
			char msg[LOG_MSG_SIZE];
			dp_session_query(s, SESSION_ATTR_ALL, &info);
			info.timestamp = time(NULL);
			info.duration = 0;
			format_session_log(msg, &info);
			RTE_LOG(DEBUG, FLOWSTAT,
				"session uuid=%lu state=%s hook=%d proto=%d "
				"proto_state=%d %s\n",
				dp_session_unique_id(s),
				dp_session_get_state_name(s, false), hook,
				info.se_protocol, info.se_protocol_state, msg);
		} else {
			RTE_LOG(DEBUG, FLOWSTAT,
				"session uuid=%lu state=%s hook=%d proto=%d "
				"proto_state=%d\n",
				dp_session_unique_id(s),
				dp_session_get_state_name(s, false), hook,
				info.se_protocol, info.se_protocol_state);
		}
	}
}

static void fstat_cleanup_cb(const char *instance __unused,
			     void *context __unused)
{
	cds_wfcq_destroy(&logqueue_head, &logqueue_tail);
	cds_lfht_destroy(enabled_intf_ht, NULL);
}

static unsigned int fstat_process(struct pl_packet *pkt __unused,
				  void *context __unused)
{
	return FLOW_STAT_ACCEPT;
}

static int fstat_feat_cmd(struct pb_msg *msg)
{
	int ret = 0;

	FlowStatFeatConfig *fstat_msg =
		flow_stat_feat_config__unpack(NULL, msg->msg_len, msg->msg);
	if (!fstat_msg) {
		dp_pb_cmd_err(msg, "failed to read fstat protobuf command\n");
		return -1;
	}

	if (!fstat_msg->has_is_active) {
		dp_pb_cmd_err(msg, "error in fstat protobuf command\n");
		return -1;
	}

	const char *if_name = fstat_msg->if_name;

	if (strlen(if_name) == 0) {
		/* Enable/disable on global */
		if (fstat_msg->is_active == false) {
			is_enabled_global = false;
			if (debug_level >= INFO_LEVEL)
				RTE_LOG(INFO, FLOWSTAT, "disabled global\n");
		} else {
			is_enabled_global = true;
			if (debug_level >= INFO_LEVEL)
				RTE_LOG(INFO, FLOWSTAT, "enabled global\n");
		}
	} else if (fstat_msg->is_active == false) {
		/*
		 * Disable interface.
		 */
		struct intf_node *node = intf_lookup(if_name);
		if (node) {
			cds_lfht_del(enabled_intf_ht, &node->node);
			free(node);
		}

		if (debug_level >= INFO_LEVEL)
			RTE_LOG(INFO, FLOWSTAT, "disabled on %s\n", if_name);
	} else {
		/*
		 * Enable interface.
		 */
		struct intf_node *node;
		struct cds_lfht_node *ret_node;

		node = malloc(sizeof(struct intf_node));
		if (!node) {
			dp_pb_cmd_err(msg, "Failed to allocate memory\n");
			return -1;
		}

		cds_lfht_node_init(&node->node);
		strncpy(node->name, if_name, IFNAMSIZ);

		ret_node = cds_lfht_add_unique(
			enabled_intf_ht, intf_hash_name(if_name), intf_match,
			if_name, &node->node);
		if (ret_node != &node->node)
			/* already added, free new node */
			free(node);

		if (debug_level >= INFO_LEVEL)
			RTE_LOG(INFO, FLOWSTAT, "enabled on %s\n", if_name);
	}

	flow_stat_feat_config__free_unpacked(fstat_msg, NULL);

	return ret;
}

static int cmd_fstat_feat_show(struct pb_msg *msg)
{
	/* request */
	FlowStatOpReq *fstat_op_req_msg =
		flow_stat_op_req__unpack(NULL, msg->msg_len, msg->msg);
	if (!fstat_op_req_msg) {
		dp_pb_cmd_err(msg,
			      "failed to read fstat protobuf op command\n");
		return -1;
	}
	flow_stat_op_req__free_unpacked(fstat_op_req_msg, NULL);

	/* response */
	FlowStatOpResp fstat_op_resp_msg = FLOW_STAT_OP_RESP__INIT;

	fstat_op_resp_msg.count = 0;
	fstat_op_resp_msg.has_count = false;

	/* now convert this to binary and add back */
	int len = flow_stat_op_resp__get_packed_size(&fstat_op_resp_msg);
	void *buf2 = malloc(len);
	flow_stat_op_resp__pack(&fstat_op_resp_msg, buf2);
	msg->ret_msg = buf2;
	msg->ret_msg_len = len;

	return 0;
}

const char *fstat_next_nodes[] = {
	"vyatta:term-noop",
};

static const char *plugin_name = "flow_stat";

struct dp_pipeline_feat_registration fstat_feat = {
	.plugin_name = "flow_stat",
	.name = "fstat:fstat",
	.node_name = "fstat:fstat",
	.feature_point = "vyatta:ipv4-validate",
	.visit_before = NULL,
	.visit_after = "vyatta:ipv4-pbr",
	.cleanup_cb = fstat_cleanup_cb,
};

static struct session_watch fstat_sew = {
	.fn = session_watch_cb,
	.types = SESSION_TYPE_FW,
	.data = NULL,
	.name = "fstat_session_watch",
};

int dp_feature_plugin_init(const char **name)
{
	int rv;

	rv = dp_pipeline_register_node("fstat:fstat", 1, fstat_next_nodes,
				       PL_PROC, fstat_process);
	if (rv)
		goto error;

	rv = dp_pipeline_register_list_feature(&fstat_feat);
	if (rv)
		goto error;

	rv = dp_feature_register_pb_cfg_handler("fstat:fstat-feat",
						fstat_feat_cmd);
	if (rv)
		goto error;

	rv = dp_feature_register_pb_op_handler("fstat:fstat-feat",
					       cmd_fstat_feat_show);
	if (rv)
		goto error;

	rv = dp_session_watch_register(&fstat_sew);
	if (rv)
		goto error;

	cds_wfcq_init(&logqueue_head, &logqueue_tail);

#ifndef UNIT_TEST
	pthread_t export_thread;
	rv = pthread_create(&export_thread, NULL, log_exporter_thread, NULL);
	if (rv < 0) {
		RTE_LOG(INFO, FLOWSTAT, "pthread create failed\n");
		goto error;
	}
#endif

	/*
	 * Allocate hash table.
	 */
	enabled_intf_ht =
		cds_lfht_new(ENABLED_INTF_HASH_MIN, ENABLED_INTF_HASH_MIN,
			     ENABLED_INTF_HASH_MAX,
			     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!enabled_intf_ht) {
		RTE_LOG(INFO, FLOWSTAT, "Error allocating hash table\n");
		goto error;
	}

	*name = plugin_name;
	RTE_LOG(INFO, FLOWSTAT, "flow_stat is loaded\n");
	return 0;
error:
	return rv;
}
