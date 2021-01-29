/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Communication with controller
 */

#include <arpa/inet.h>
#include <czmq.h>
#include <errno.h>
#include <inttypes.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <zmq.h>

#include "commands.h"
#include "compiler.h"
#include "config_internal.h"
#include "control.h"
#include "crypto/crypto_policy.h"
#include "dpmsg.h"
#include "event_internal.h"
#include "feature_commands.h"
#include "feature_plugin_internal.h"
#include "if/dpdk-eth/vhost.h"
#include "if_var.h"
#include "ip_addr.h"
#include "controller.h"
#include "mstp.h"
#include "netinet6/nd6_nbr.h"
#include "netlink.h"
#include "npf/config/npf_config.h"
#include "pl_commands.h"
#include "power.h"
#include "protobuf.h"
#include "rt_tracker.h"
#include "session/session_cmds.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "storm_ctl.h"
#include "backplane.h"
#include "ptp.h"

#define ZMQ_IPC_HWM (0)

/*
 * Definition of the member type for the table of message handlers.
 */
struct msg_handler {
	uint32_t version;
	const char *topic;
	int (*handler)(enum cont_src_en cont_src, void *data, size_t size,
		       const struct msg_handler *h);
	cmd_func_t cmd_handler;
};

struct cont_src_info_s {
	enum cont_src_en cont_src;
	zsock_t *csocket; /* Zmq socket to controller */
	zsock_t *subscriber; /* Receive messages from netlink publisher */
	uint64_t sub_last_seqno; /* Sequence number of last message seen */
	zsock_t *broker_ctrl_sock;
	zsock_t *broker_data_sock;
};

static struct cont_src_info_s cont_src_info[CONT_SRC_COUNT] = {
	{ .cont_src = CONT_SRC_MAIN, },
	{ .cont_src = CONT_SRC_UPLINK, },
};

static const char *cont_src_names[CONT_SRC_COUNT] = {
	[CONT_SRC_MAIN] = "vplaned",
	[CONT_SRC_UPLINK] = "vplaned-uplink",
};

zsock_t *cont_src_get_broker_ctrl(enum cont_src_en cont_src)
{
	return cont_src_info[cont_src].broker_ctrl_sock;
}

zsock_t *cont_src_get_broker_data(enum cont_src_en cont_src)
{
	return cont_src_info[cont_src].broker_data_sock;
}

void cont_src_set_broker_ctrl(enum cont_src_en cont_src, zsock_t *sock)
{
	cont_src_info[cont_src].broker_ctrl_sock = sock;
}

void cont_src_set_broker_data(enum cont_src_en cont_src, zsock_t *sock)
{
	cont_src_info[cont_src].broker_data_sock = sock;
}

const char *cont_src_name(enum cont_src_en cont_src)
{
	return cont_src_names[cont_src];
}

static inline uint64_t get_seqno(dpmsg_t *dpmsg)
{
	return *((uint64_t *)zmq_msg_data(&dpmsg->seqno_msg));
}

/* Uplink is programmed with ifindex's from 2 kernels.  The values may collide.
 * Linux uses a signed int for ifindex, the dataplane uses an unsigned int.
 * Set the top bit in the ifindex generated by the vplaned-local.
 */
unsigned int
cont_src_ifindex(enum cont_src_en cont_src, int ifindex)
{
	if (cont_src != CONT_SRC_UPLINK)
		return ifindex;

	set_bit_32((uint32_t *)&ifindex, 31);
	return (unsigned int)ifindex;
}

/*
 * Receive netlink message from controller:
 *  [0] topic string (for pub-sub)
 *  [1] sequence number (for resync)
 *  [2] netlink data (or command)
 *
 * dpmsg must be already allocated, and caller is responsible for destroying it.
 * Return 0 on success, -1 on error.
 */
int dpmsg_recv(zsock_t *sock, dpmsg_t *dpmsg)
{
	if (!sock || !dpmsg)
		return -1;

	/* zero-copy receive. No buffers malloc'ed, no data copied. */
	zmq_msg_init(&dpmsg->topic_msg);
	zmq_msg_init(&dpmsg->seqno_msg);
	zmq_msg_init(&dpmsg->data_msg);

	if (zmq_msg_recv(&dpmsg->topic_msg, zsock_resolve(sock), 0) <= 0)
		goto error;
	if (!zmq_msg_data(&dpmsg->topic_msg))
		goto error;
	if (zmq_msg_size(&dpmsg->topic_msg) <= 0)
		goto error;
	if (zmq_msg_get(&dpmsg->topic_msg, ZMQ_MORE) != 1)
		goto error;

	if (zmq_msg_recv(&dpmsg->seqno_msg, zsock_resolve(sock), 0) <= 0)
		goto error;
	if (!zmq_msg_data(&dpmsg->seqno_msg))
		goto error;
	if (zmq_msg_size(&dpmsg->seqno_msg) < sizeof(uint64_t))
		goto error;
	if (zmq_msg_get(&dpmsg->seqno_msg, ZMQ_MORE) != 1)
		goto error;

	if (zmq_msg_recv(&dpmsg->data_msg, zsock_resolve(sock), 0) <= 0)
		goto error;

	/* Among the many nice things CZMQ does for us is making sure all
	 * frames are read even if we just care about the first 3
	 */
	int more = zmq_msg_get(&dpmsg->data_msg, ZMQ_MORE);
	while (more) {
		zmq_msg_t sink;
		zmq_msg_init(&sink);
		zmq_msg_recv(&sink, zsock_resolve(sock), 0);
		more = zmq_msg_get(&sink, ZMQ_MORE);
		zmq_msg_close(&sink);
	}

	return 0;

error:
	zmq_msg_close(&dpmsg->topic_msg);
	zmq_msg_close(&dpmsg->seqno_msg);
	zmq_msg_close(&dpmsg->data_msg);
	return -1;
}

/*
 * Process already received netlink message from controller:
 *  [0] topic string (for pub-sub)
 *  [1] sequence number (for resync)
 *  [2] netlink data (or command)
 *
 * dpmsg must be already allocated.
 * Caller is responsible for destroying zmsg.
 * zmsg MUST NOT be destroyed before work on dpmsg is finished.
 * dpmsg_destroy does not necessarily have to be called, only stack data.
 * Return 0 on success, -1 on error.
 */
int dpmsg_convert_zmsg(zmsg_t *zmsg, dpmsg_t *dpmsg)
{
	if (!zmsg || !dpmsg)
		return -1;

	if (zmsg_size(zmsg) < 3) {
		RTE_LOG(ERR, DATAPLANE,
			"controller protocol error (%zu parts)\n",
			zmsg_size(zmsg));
		return -1;
	}

	/* To avoid malloc'ing memory and copying data, the existing buffers
	 * are pointed to by dpmsg.
	 */
	zframe_t *frame = zmsg_first(zmsg);
	if (!zframe_data(frame))
		return -1;
	if (!zframe_size(frame))
		return -1;
	if (zmq_msg_init_data(&dpmsg->topic_msg, zframe_data(frame),
			zframe_size(frame), NULL, NULL))
		return -1;

	frame = zmsg_next(zmsg);
	if (!zframe_data(frame))
		return -1;
	if (zframe_size(frame) < sizeof(uint64_t))
		return -1;
	if (zmq_msg_init_data(&dpmsg->seqno_msg, zframe_data(frame),
			zframe_size(frame), NULL, NULL))
		return -1;

	frame = zmsg_next(zmsg);
	if (zmq_msg_init_data(&dpmsg->data_msg, zframe_data(frame),
			zframe_size(frame), NULL, NULL))
		return -1;

	return 0;
}

void dpmsg_destroy(dpmsg_t *dpmsg)
{
	if (dpmsg) {
		zmq_msg_close(&dpmsg->topic_msg);
		zmq_msg_close(&dpmsg->seqno_msg);
		zmq_msg_close(&dpmsg->data_msg);
	}
}

static int report_config_error(const char *cmd, int code)
{
	int result;
	uint16_t dp_id = 0;
	zmsg_t *msg = zmsg_new();

	if (!msg)
		return -ENOMEM;

	result = zmsg_addstr(msg, "CONFERR");
	if (result < 0)
		goto err;

	result = zmsg_addmem(msg, &dp_id, sizeof(dp_id));
	if (result < 0)
		goto err;

	result = zmsg_addstr(msg, cmd);
	if (result < 0)
		goto err;

	result = zmsg_addmem(msg, &code, sizeof(code));
	if (result < 0)
		goto err;

	return dp_send_event_to_vplaned(msg);

err:
	zmsg_destroy(&msg);
	return result;
}

static int process_pb_cmd(enum cont_src_en cont_src,
			  void *data, size_t size,
			  const struct msg_handler *h __unused)
{
	size_t outsize;
	char *outbuf = NULL;

	FILE *f = open_memstream(&outbuf, &outsize);
	if (f == NULL)
		return -1;

	int rc = pb_cmd(data, size, f);
	fclose(f);
	if (rc < 0) {
		RTE_LOG(NOTICE, DATAPLANE,
			"(%s) protobuf : %s\n", cont_src_name(cont_src),
			outsize > 0 ? outbuf : "");
	}

	free(outbuf);
	return rc;
}

/* Generic config command, reroute to console. */
static int process_config_cmd(enum cont_src_en cont_src,
			      void *data, size_t size,
			      const struct msg_handler *h)
{
	char *cmd = malloc(size + 1);
	if (!cmd) {
		RTE_LOG(ERR, DATAPLANE, "malloc of %zu bytes failure\n", size);
		return -1;
	}
	memcpy(cmd, data, size);
	cmd[size] = '\0';

	/*
	 * Duplicate the command for logging an error, as handlers
	 * for the original command may have edited "cmd" string.
	 */
	char *cmd_log = strdup(cmd);
	if (!cmd_log) {
		RTE_LOG(ERR, DATAPLANE, "malloc of %zu bytes failure\n", size);
		free(cmd);
		return -1;
	}
	char *outbuf = NULL;
	size_t outsize = 0;
	int rc;

	rc = console_cmd(cmd, &outbuf, &outsize, h->cmd_handler, true);
	if (rc < 0) {
		int result;

		result = report_config_error(cmd_log, rc);
		if (result < 0)
			RTE_LOG(ERR, DATAPLANE,
				"Failed to send cmd report for cmd \"%s\": %s\n",
				cmd_log, strerror(-result));

		RTE_LOG(NOTICE, DATAPLANE,
			"(%s) cmd [ %s ] : %s\n", cont_src_name(cont_src),
			cmd_log, outsize > 0 ? outbuf : "");
	}
	free(cmd);
	free(cmd_log);
	free(outbuf);
	return rc;
}

/* Process netlink data from snapshot */
static int process_xfrm_policy_cmd(enum cont_src_en cont_src,
				   void *data, size_t size,
				   const struct msg_handler *h __unused)
{
	if (cont_src != CONT_SRC_MAIN) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) xfrm POLICY invalid controller\n",
			cont_src_name(cont_src));
		return -1;
	}

	vrfid_t vrf_id = VRF_DEFAULT_ID;
	int rc = mnl_cb_run(data, size, 0, 0, rtnl_process_xfrm,
			    &vrf_id);
	if (rc != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "netlink POLICY message parse error\n");
		return -1;
	}

	return 0;
}

static int process_xfrm_sa_cmd(enum cont_src_en cont_src,
			       void *data, size_t size,
			       const struct msg_handler *h __unused)
{
	if (cont_src != CONT_SRC_MAIN) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) xfrm SA invalid controller\n",
			cont_src_name(cont_src));
		return -1;
	}

	vrfid_t vrf_id = VRF_DEFAULT_ID;
	int rc = mnl_cb_run(data, size, 0, 0, rtnl_process_xfrm_sa,
			    &vrf_id);

	/* SA errors are recoverable */
	if (rc != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "netlink SA message parse error\n");
	}

	return 0;
}

static int process_l2tp_cmd(enum cont_src_en cont_src,
			    void *data, size_t size,
			    const struct msg_handler *h __unused)
{
	if (cont_src != CONT_SRC_MAIN) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) l21tp invalid controller\n",
			cont_src_name(cont_src));
		return -1;
	}

	int rc = mnl_cb_run(data, size, 0, 0, rtnl_process_l2tp,
			    (void *)cont_src);
	if (rc != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "l2tp message parse error\n");
		return -1;
	}

	return 0;
}

static int process_team_cmd(enum cont_src_en cont_src,
			    void *data, size_t size,
			    const struct msg_handler *h __unused)
{
	if (cont_src != CONT_SRC_MAIN) {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) team invalid controller\n",
			cont_src_name(cont_src));
		return -1;
	}

	int rc = mnl_cb_run(data, size, 0, 0, rtnl_process_team,
			    (void *)cont_src);
	if (rc != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "team message parse error\n");
		return -1;
	}

	return 0;
}

/* Process netlink data from snapshot */
static int process_netlink_data(enum cont_src_en cont_src,
				void *data, size_t size,
				const struct msg_handler *h __unused)
{
	int rc = mnl_cb_run(data, size, 0, 0, rtnl_process, (void *)cont_src);
	if (rc != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "netlink message parse error\n");
		return -1;
	}

	return 0;
}

/*
 * Map of controller topic to handler for that type.
 *
 * Topic must not be a substring of another topic, as a match
 * of a topic msg to a topic does not need to be on a word boundary for
 * performance reasons.
 *
 * Please do not add any further entries to this table. All new commands
 * should be in protobuf format.
 */
static const struct msg_handler message_handlers_main[] = {
	{ 0,	"address",	process_netlink_data,	 NULL },
	{ 0,	"affinity",	process_config_cmd,	 cmd_affinity_cfg },
	{ 1,	"affinity",	process_config_cmd,	 cmd_affinity_cfg },
	{ 0,    "backplane",    process_config_cmd,      cmd_backplane_cfg },
	{ 0,	"bridge_link",	process_netlink_data,	 NULL },
	{ 0,	"cgn-cfg",	process_config_cmd,	 cmd_cgn },
	{ 0,	"ecmp",		process_config_cmd,	 NULL },
	{ 0,	"ip4",		process_config_cmd,	 cmd_ip },
	{ 0,	"ipsec",	process_config_cmd,	 NULL },
	{ 0,	"l2tpeth",	process_config_cmd,	 NULL },
	{ 0,	"l2tp_",	process_l2tp_cmd,	 NULL },
	{ 0,	"link",		process_netlink_data,	 NULL },
	{ 0,	"mode",		process_config_cmd,	 cmd_power_cfg },
	{ 0,	"mpls",		process_config_cmd,	 NULL },
	{ 0,	"mstp",		process_config_cmd,	 cmd_mstp },
	{ 0,	"nat-cfg",	process_config_cmd,	 cmd_nat },
	{ 0,	"nd6",		process_config_cmd,	 cmd_nd6_set_cfg },
	{ 0,	"neigh",	process_netlink_data,	 NULL },
	{ 0,	"netconf",	process_netlink_data,	 NULL },
	{ 2,	"npf-cfg",	process_config_cmd,	 cmd_npf_cfg },
	{ 0,	"pathmonitor",	process_config_cmd,	 NULL },
	{ 0,	"poe",		process_config_cmd,	 cmd_poe },
	{ 0,	"portmonitor",	process_config_cmd,	 NULL },
	{ 1,	"portmonitor",	process_config_cmd,	 NULL },
	{ 0,	"protobuf",	process_pb_cmd,          NULL },
	{ 0,	"ptp",		process_config_cmd,      cmd_ptp_cfg },
	{ 14,	"qos",		process_config_cmd,	 cmd_qos_cfg },
	{ 15,	"qos",		process_config_cmd,	 cmd_qos_cfg },
	{ 0,	"route",	process_netlink_data,	 NULL },
	{ 3,    "storm-ctl",    process_config_cmd,      cmd_storm_ctl_cfg },
	{ 0,	"tablemap",	process_config_cmd,	 cmd_tablemap_cfg },
	{ 0,	"team",		process_team_cmd,	 NULL },
	{ 0,	"tracker-ut",	process_config_cmd,	 cmd_rt_tracker_cfg },
	{ 0,	"tunnel",	process_netlink_data,	 NULL },
	{ 0,	"session-cfg",	process_config_cmd,	 cmd_session_cfg },
	{ 0,    "switchport",   process_config_cmd,  cmd_switchport },
	{ 0,	"vhost-client",	process_config_cmd,	 cmd_vhost_client_cfg },
	{ 1,	"vhost-client",	process_config_cmd,	 cmd_vhost_client_cfg },
	{ 2,	"vhost-client",	process_config_cmd,	 cmd_vhost_client_cfg },
	{ 3,	"vhost-client",	process_config_cmd,	 cmd_vhost_client_cfg },
	{ 1,	"vhost",	process_config_cmd,	 cmd_vhost_cfg },
	{ 0,	"vxlan",	process_netlink_data,	 NULL },
	{ 0,	"xfrm",		process_xfrm_policy_cmd, NULL },
	{ 0,	"saxfrm",	process_xfrm_sa_cmd,	 NULL },
	{ 0,	"vfp",		process_config_cmd,	 cmd_set_vfp },
	{ 0,	"vplane",	process_config_cmd,	 NULL },
	{ 0,	"vrf",		process_netlink_data,	 NULL },
	{ 0,	"tc_qdisc",	process_netlink_data,	 NULL },
	{ 0,	"tc_chain",	process_netlink_data,	 NULL },
	{ 0,	"tc_filter",	process_netlink_data,	 NULL },
	{ 0,	NULL,		NULL }
};

void list_all_main_msg_versions(FILE *f)
{
	for (const struct msg_handler *handler = message_handlers_main;
	     handler->topic; ++handler) {
		fprintf(f, "%s %u\n", handler->topic, handler->version);
	}
	list_all_pipeline_msg_versions(f);
	list_all_protobuf_msg_versions(f);
}

static const struct msg_handler message_handlers_uplink[] = {
	/* If you add more handlers here you must use cont_src_ifindex
	 * to manage any received ifindex's
	 */
	{ 0,	"address",	process_netlink_data,	 NULL },
	{ 0,	"link",		process_netlink_data,	 NULL },
	{ 0,	"neigh",	process_netlink_data,	 NULL },
	{ 0,	"netconf",	process_netlink_data,	 NULL },
	{ 0,	"route",	process_netlink_data,	 NULL },
	{ 0,	NULL,		NULL }
};

static const struct msg_handler *message_handlers[CONT_SRC_COUNT] = {
	[CONT_SRC_MAIN]  = message_handlers_main,
	[CONT_SRC_UPLINK]   = message_handlers_uplink,
};

/*
 * Topics accepted in ready state
 */
static const struct msg_handler ready_handlers[] = {
	{ 0,    NULL,           NULL }
};

/*
 * Dynamically registered handlers
 */
struct dynamic_cfg_command_entry {
	struct msg_handler handler;
	struct cds_list_head list_entry;
};

static struct cds_list_head dynamic_cfg_command_list_head =
	CDS_LIST_HEAD_INIT(dynamic_cfg_command_list_head);

static const struct msg_handler *
find_msg_handler(const struct msg_handler *handlers,
		 const char *name, int len)
{
	const struct msg_handler *h;
	struct dynamic_cfg_command_entry *dynamic_cmd;

	for (h = handlers; h->topic; ++h) {
		if (memcmp(name, h->topic, MIN(len, strlen(h->topic))))
			continue;

		return h;
	}

	/* And check the dynamically registered commands too */
	cds_list_for_each_entry_rcu(dynamic_cmd, &dynamic_cfg_command_list_head,
				    list_entry) {
		if (memcmp(name, dynamic_cmd->handler.topic,
			   MIN(len, strlen(dynamic_cmd->handler.topic))))
			continue;
		return &dynamic_cmd->handler;
	}

	return NULL;
}

static int
process_topic_msg(enum cont_src_en cont_src,
		  const struct msg_handler *handlers, dpmsg_t *dpmsg)
{
	const struct msg_handler *h;
	int ret;

	h = find_msg_handler(handlers,
			     zmq_msg_data(&dpmsg->topic_msg),
			     zmq_msg_size(&dpmsg->topic_msg));
	if (h) {
		rcu_read_lock();
		ret = (*h->handler)(cont_src, zmq_msg_data(&dpmsg->data_msg),
				    zmq_msg_size(&dpmsg->data_msg), h);
		rcu_read_unlock();

		return ret;
	}

	/* This should never happen should only get stuff that
	 * was subscribed to.
	 */
	RTE_LOG(NOTICE, DATAPLANE, "(%s) unknown topic '%.*s'\n",
		cont_src_name(cont_src), (int)zmq_msg_size(&dpmsg->topic_msg),
		(char *)zmq_msg_data(&dpmsg->topic_msg));
	return -1;
}

int dp_feature_register_string_cfg_handler(const char *name,
					   feature_string_op_fn *fn)
{
	struct dynamic_cfg_command_entry *dynamic_cfg_cmd;
	const struct msg_handler *cmd;

	if (!name || !fn)
		return -EINVAL;

	cmd = find_msg_handler(message_handlers_main, name, strlen(name));
	if (cmd) {
		RTE_LOG(ERR, DATAPLANE,
			 "Can not register op cmd. Cmd %s already exists\n",
			 cmd->topic);
		return -EINVAL;
	}

	dynamic_cfg_cmd = calloc(1, sizeof(*dynamic_cfg_cmd));
	if (!dynamic_cfg_cmd) {
		RTE_LOG(ERR, DATAPLANE,
			 "Can not register op cmd. No memory\n");
		return -EINVAL;
	}

	dynamic_cfg_cmd->handler.version = 0;
	dynamic_cfg_cmd->handler.topic = strdup(name);
	if (!dynamic_cfg_cmd->handler.topic) {
		RTE_LOG(ERR, DATAPLANE,
			 "Can not register op cmd. No memory\n");
		free(dynamic_cfg_cmd);
		return -EINVAL;
	}
	dynamic_cfg_cmd->handler.handler = process_config_cmd;
	dynamic_cfg_cmd->handler.cmd_handler = fn;

	cds_list_add_rcu(&dynamic_cfg_cmd->list_entry,
			 &dynamic_cfg_command_list_head);
	return 0;
}

void feature_unregister_all_string_cfg_handlers(void)
{
	struct dynamic_cfg_command_entry *cmd = NULL;
	struct cds_list_head *this_entry, *next;

	cds_list_for_each_safe(this_entry, next,
			       &dynamic_cfg_command_list_head) {
		cmd = cds_list_entry(this_entry,
				     struct dynamic_cfg_command_entry,
				     list_entry);

		cds_list_del_rcu(&cmd->list_entry);
		free((char *)cmd->handler.topic);
		free(cmd);
	}
}

/* Process message either from pub-sub socket
 * or received during resynchronization.
 * Returns: 0 - OK
 *	    -1 - Error
 */
int process_dpmsg(enum cont_src_en cont_src, dpmsg_t *dpmsg)
{
	return process_topic_msg(cont_src, message_handlers[cont_src], dpmsg);
}

/*
 * Process message in ready state
 */
int process_ready_msg(enum cont_src_en cont_src, dpmsg_t *dpmsg)
{
	return process_topic_msg(cont_src, ready_handlers, dpmsg);
}

/*
 * If feature needs ending notification of
 * resync event add features call to this function.
 */
static void process_snapshot_end(void)
{
	npf_cfg_commit_all();
}

/* Request current snapshot from controller. */
int controller_snapshot(enum cont_src_en cont_src)
{
	DP_DEBUG(RESYNC, INFO, DATAPLANE,
		 "main(%s) controller resync started\n",
		 cont_src_name(cont_src));

	return zstr_send(cont_socket_get(cont_src), "WHATSUP?");
}

/* Process one message out of the snapshot.  Caller responsible for freeing
 * dpmsg
 */
int process_snapshot_one(enum cont_src_en cont_src, dpmsg_t *dpmsg, int *eof)
{
	int rc = 0;
	const char *done = "THATSALLFOLKS!";

	cont_src_info[cont_src].sub_last_seqno = get_seqno(dpmsg);
	*eof = 0;
	if (!memcmp(zmq_msg_data(&dpmsg->topic_msg), done,
			MIN(strlen(done), zmq_msg_size(&dpmsg->topic_msg)))) {
		DP_DEBUG(RESYNC, INFO, DATAPLANE,
			 "main(%s) resync [%"PRIu64"] completed\n",
			 cont_src_name(cont_src),
			 cont_src_info[cont_src].sub_last_seqno);
		process_snapshot_end();
		*eof = 1;
	} else {
		DP_DEBUG(RESYNC, INFO, DATAPLANE,
			 "main(%s) resync [%"PRIu64"] %.*s\n",
			 cont_src_name(cont_src),
			 get_seqno(dpmsg),
			 (int)zmq_msg_size(&dpmsg->topic_msg),
			 (char *)zmq_msg_data(&dpmsg->topic_msg));

		rc = process_dpmsg(cont_src, dpmsg);
		if (rc)
			DP_DEBUG(RESYNC, NOTICE, DATAPLANE,
				 "main(%s) %.*s: failed\n",
				 cont_src_name(cont_src),
				 (int)zmq_msg_size(&dpmsg->topic_msg),
				 (char *)zmq_msg_data(&dpmsg->topic_msg));
	}
	return rc;
}


/* Call back from main poll loop.
 * Only returns error if socket is dead.
 */
static int subscriber_recv(void *cont_src_info_arg)
{
	struct cont_src_info_s *cont_src_info = cont_src_info_arg;
	dpmsg_t dpmsg;
	zsock_t *zsocket = cont_src_info->subscriber;

	errno = 0;
	int rc = dpmsg_recv(zsocket, &dpmsg);
	if (rc != 0) {
		if (errno == 0)
			return 0;
		return -1;
	}

	if (get_seqno(&dpmsg) > cont_src_info->sub_last_seqno) {
		cont_src_info->sub_last_seqno = get_seqno(&dpmsg);

		DP_DEBUG(SUBSCRIBER, DEBUG, DATAPLANE,
			 "main(%s) sub [%"PRIu64"] %.*s\n",
			 cont_src_name(cont_src_info->cont_src),
			 get_seqno(&dpmsg),
			 (int)zmq_msg_size(&dpmsg.topic_msg),
			 (char *)zmq_msg_data(&dpmsg.topic_msg));

		if (process_dpmsg(cont_src_info->cont_src, &dpmsg) < 0)
			DP_DEBUG(SUBSCRIBER, NOTICE, DATAPLANE,
				 "subscription message error handling : %.*s\n",
				 (int)zmq_msg_size(&dpmsg.topic_msg),
				 (char *)zmq_msg_data(&dpmsg.topic_msg));
	} else {
		DP_DEBUG(SUBSCRIBER, DEBUG, DATAPLANE,
			 "main(%s) sub ignore [%"PRIu64" < %"PRIu64"] %.*s\n",
			 cont_src_name(cont_src_info->cont_src),
			 get_seqno(&dpmsg),
			 cont_src_info->sub_last_seqno,
			 (int)zmq_msg_size(&dpmsg.topic_msg),
			 (char *)zmq_msg_data(&dpmsg.topic_msg));
	}

	dpmsg_destroy(&dpmsg);

	return 0;
}

void controller_unsubscribe(enum cont_src_en cont_src)
{
	zsock_t *csocket = cont_src_info[cont_src].csocket;
	zsock_t *subscriber = cont_src_info[cont_src].subscriber;

	if (csocket) {
		dp_unregister_event_socket(zsock_resolve(csocket));
		zsock_destroy(&cont_src_info[cont_src].csocket);
	}

	if (subscriber) {
		dp_unregister_event_socket(zsock_resolve(subscriber));
		zsock_destroy(&cont_src_info[cont_src].subscriber);
	}
}

/* Subscribe to controller publish connection */
void controller_init(enum cont_src_en cont_src)
{
	const struct msg_handler *h;
	char *publish_url = NULL;
	zsock_t *subscriber;
	struct dynamic_cfg_command_entry *dynamic_cmd;

	switch (cont_src) {
	case CONT_SRC_MAIN:
		publish_url = config.publish_url;
		break;
	case CONT_SRC_UPLINK:
		publish_url = config.publish_url_uplink;
		break;
	}

	if (publish_url == NULL)
		rte_panic("publisher(%s) URL not found\n",
			  cont_src_name(cont_src));

	subscriber = zsock_new(ZMQ_SUB);
	if (!subscriber)
		rte_panic("publisher(%s) can't open zmq subscribe socket\n",
			  cont_src_name(cont_src));

	zsock_set_sndhwm(subscriber, ZMQ_IPC_HWM);
	zsock_set_rcvhwm(subscriber, ZMQ_IPC_HWM);

	if (zsock_connect(subscriber, "%s", publish_url) < 0)
		rte_panic("publisher(%s) zmq_connect %s failed\n",
			  cont_src_name(cont_src), publish_url);

	RTE_LOG(DEBUG, DATAPLANE,
		"Connect to publisher(%s) at %s\n",
		cont_src_name(cont_src), publish_url);

	for (h = message_handlers[cont_src]; h->topic; ++h)
		zsock_set_subscribe(subscriber, h->topic);

	/* And subscribe for the dynamically handled events */
	cds_list_for_each_entry_rcu(dynamic_cmd, &dynamic_cfg_command_list_head,
				    list_entry)
		zsock_set_subscribe(subscriber, dynamic_cmd->handler.topic);

	cont_src_info[cont_src].subscriber = subscriber;
}

/* Enable authentication on the specified socket */
void enable_authentication(zsock_t *socket)
{
	zcert_t *cert;
	zcert_t *controller_cert;
	const char *controller_key;
	char *time;
	char ip[INET6_ADDRSTRLEN];

	if ((config.certificate == NULL) ||
	    (config.remote_cert == NULL))
		rte_panic("Incomplete authentication configuration\n");

	cert = zcert_load(config.certificate);
	if (cert == NULL) {
		cert = zcert_new();
		if (cert == NULL)
			rte_panic("Authentication certificate failed\n");
		zcert_set_meta(cert, "auto-created-by", "%s",
				"Vyatta dataplane");
		time = zclock_timestr();
		if (time != NULL) {
			zcert_set_meta(cert, "creation-time", "%s", time);
			free(time);
		}
		zcert_set_meta(cert, "creator-ip", "%s",
			       inet_ntop(config.local_ip.type,
					 &config.local_ip.address,
					 ip, sizeof(ip)));
		if (config.uuid != NULL)
			zcert_set_meta(cert, "uuid", "%s", config.uuid);
		if (zcert_save(cert, config.certificate))
			rte_panic(
				  "Failed to create authentication certificate %s\n",
				  config.certificate);
	}

	controller_cert = zcert_load(config.remote_cert);
	if (controller_cert == NULL)
		rte_panic(
			  "Failed to load remote authentication certificate %s\n",
			  config.remote_cert);
	controller_key = zcert_public_txt(controller_cert);

	zcert_apply(cert, socket);
	zsock_set_curve_serverkey(socket, controller_key);
	zcert_destroy(&controller_cert);
	zcert_destroy(&cert);
	RTE_LOG(NOTICE, DATAPLANE, "Authentication enabled.\n");
}

/* Make the zmq request socket */
static zsock_t *open_controller(enum cont_src_en cont_src)
{
	char *request_url = NULL;
	zsock_t *zsock;

	switch (cont_src) {
	case CONT_SRC_MAIN:
		request_url = config.request_url;
		break;
	case CONT_SRC_UPLINK:
		request_url = config.request_url_uplink;
		break;
	}
	if (request_url == NULL)
		rte_panic("Open controller(%s) missing url\n",
			  cont_src_name(cont_src));

	zsock = zsock_new(ZMQ_DEALER);
	if (!zsock)
		rte_panic("Open controller(%s), cannot open ZMQ socket\n",
			  cont_src_name(cont_src));

	if (config.auth_enabled)
		enable_authentication(zsock);

	if (zsock_connect(zsock, "%s", request_url) < 0)
		rte_panic("Open controller(%s) connect to %s failed: %s\n",
			  cont_src_name(cont_src), request_url,
			  strerror(errno));
	RTE_LOG(DEBUG, DATAPLANE,
		"Connect to controller(%s) at %s\n", cont_src_name(cont_src),
		request_url);
	return zsock;
}

zsock_t *cont_socket_create(enum cont_src_en cont_src)
{
	if (cont_src_info[cont_src].csocket == NULL)
		cont_src_info[cont_src].csocket = open_controller(cont_src);
	return cont_src_info[cont_src].csocket;
}

zsock_t *cont_socket_get(enum cont_src_en cont_src)
{
	return cont_src_info[cont_src].csocket;
}

void controller_init_event_handler(enum cont_src_en cont_src)
{
	zsock_t *subscriber = cont_src_info[cont_src].subscriber;

	if (!subscriber)
		return;

	register_event_socket_src(zsock_resolve(subscriber), subscriber_recv,
				  &cont_src_info[cont_src], cont_src);
}

/*
 * Traverse a set of cached commands on a list, removing those
 * for a given interface, and if supplied, calling the handler for
 * those commands. If the list is empty after traversal, it's destroyed.
 *
 * Suitable to be called on an if_index set or unset event.
 */
int cfg_if_list_replay(struct cfg_if_list **cfg_list, const char *ifname,
		       cmd_func_t handler)
{
	struct cfg_if_list *if_list = *cfg_list;
	struct cfg_if_list_entry *entry, *temp_entry;
	int rv;

	if (!if_list)
		return 0;

	cds_list_for_each_entry_safe(entry, temp_entry, &if_list->if_list,
				     le_node) {
		if (strcmp(ifname, entry->le_ifname))
			continue;

		if (handler) {
			rv = handler(NULL, entry->le_argc, entry->le_argv);
			if (rv)
				return rv;
		}

		rv = cfg_if_list_del(if_list, ifname);
		if (rv)
			return rv;
	}

	if (!if_list->if_list_count)
		return cfg_if_list_destroy(cfg_list);

	return 0;
}

struct cfg_if_list_entry *
cfg_if_list_lookup(struct cfg_if_list *if_list, const char *ifname)
{
	struct cfg_if_list_entry *le;

	if (!if_list)
		return NULL;

	cds_list_for_each_entry(le, &if_list->if_list, le_node) {
		if (!strcmp(ifname, le->le_ifname))
			return le;
	}
	return NULL;
}

struct cfg_if_list *cfg_if_list_create(void)
{
	struct cfg_if_list *if_list;

	if_list = zmalloc_aligned(sizeof(*if_list));
	if (!if_list)
		return NULL;

	CDS_INIT_LIST_HEAD(&if_list->if_list);
	if_list->if_list_count = 0;
	return if_list;
}

static int
cfg_if_list_add_internal(struct cfg_if_list *if_list, const char *ifname,
			 int argc, char *argv[], bool multiple_per_if)
{
	struct cfg_if_list_entry *le = NULL;
	int i, size;

	if (strlen(ifname) + 1 > IFNAMSIZ)
		return -EINVAL;

	if (!multiple_per_if)
		le = cfg_if_list_lookup(if_list, ifname);
	if (!le) {
		le = zmalloc_aligned(sizeof(*le));
		if (!le)
			return -ENOMEM;

		memcpy(le->le_ifname, ifname, strlen(ifname) + 1);
		cds_list_add_tail(&le->le_node, &if_list->if_list);
		if_list->if_list_count++;
	} else {
		/* Config has changed. Free buffer and argv array. */
		free(le->le_buf);
		free(le->le_argv);
	}

	/* Determine space required for arg strings */
	for (size = 0, i = 0; i < argc; i++)
		size += (strlen(argv[i]) + 1);

	if (!size)
		return -EINVAL;

	le->le_buf = malloc(size);
	le->le_argv = malloc(argc * sizeof(void *));
	le->le_argc = argc;

	if (!le->le_buf || !le->le_argv) {
		cfg_if_list_del(if_list, ifname);
		return -ENOMEM;
	}

	char *ptr = le->le_buf;

	for (i = 0; i < argc; i++) {
		size = strlen(argv[i]) + 1;
		memcpy(ptr, argv[i], size);
		le->le_argv[i] = ptr;
		ptr += size;
	}

	return 0;
}

/*
 * Only 1 entry is allowed per interface and a subsequent add will
 * overwrite the entry.
 */
int cfg_if_list_add(struct cfg_if_list *if_list, const char *ifname,
		    int argc, char *argv[])
{
	return cfg_if_list_add_internal(if_list, ifname, argc, argv, false);
}

/*
 * Multiple entries are allowed per interface and a subsequent add will
 * be added at the tail of the list.
 */
int cfg_if_list_add_multi(struct cfg_if_list *if_list, const char *ifname,
			  int argc, char *argv[])
{
	return cfg_if_list_add_internal(if_list, ifname, argc, argv, true);
}

int cfg_if_list_bin_add(struct cfg_if_list *if_list, const char *ifname,
			char *msg, int len)
{
	struct cfg_if_list_entry *le;

	if (strlen(ifname) + 1 > IFNAMSIZ)
		return -EINVAL;

	le = cfg_if_list_lookup(if_list, ifname);
	if (!le) {
		le = zmalloc_aligned(sizeof(*le));
		if (!le)
			return -ENOMEM;

		memcpy(le->le_ifname, ifname, strlen(ifname) + 1);
		cds_list_add_tail(&le->le_node, &if_list->if_list);
		if_list->if_list_count++;
	} else {
		/* Config has changed. Free buffer and argv array. */
		free(le->le_buf);
		free(le->le_argv);
	}

	if (!len)
		return -EINVAL;

	le->le_buf = malloc(len);
	le->le_argc = len;
	le->le_argv = NULL;

	if (!le->le_buf) {
		cfg_if_list_del(if_list, ifname);
		return -ENOMEM;
	}

	memcpy(le->le_buf, msg, len);
	return 0;
}

int
cfg_if_list_del(struct cfg_if_list *if_list, const char *ifname)
{
	struct cfg_if_list_entry *le;

	if (!if_list || if_list->if_list_count == 0)
		return -ENOENT;

	le = cfg_if_list_lookup(if_list, ifname);
	if (!le)
		return -ENOENT;

	cds_list_del(&le->le_node);
	if_list->if_list_count--;

	if (le->le_buf)
		free(le->le_buf);
	if (le->le_argv)
		free(le->le_argv);
	free(le);

	return 0;
}

int cfg_if_list_destroy(struct cfg_if_list **if_list)
{
	if (!*if_list || (*if_list)->if_list_count)
		return -EINVAL;

	free(*if_list);
	*if_list = NULL;
	return 0;
}

int cfg_if_list_cache_command(struct cfg_if_list **if_list, const char *ifname,
			      int argc, char **argv)
{
	if (!*if_list) {
		*if_list = cfg_if_list_create();
		if (!*if_list)
			return -ENOMEM;
	}

	return cfg_if_list_add_multi(*if_list, ifname, argc, argv);
}
