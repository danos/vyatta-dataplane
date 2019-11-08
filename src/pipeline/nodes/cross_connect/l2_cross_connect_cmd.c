/*
 * l2_cross_connect_cmd.c
 *
 *
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "compiler.h"
#include "cross_connect.h"
#include "if_var.h"
#include "l2tp/l2tpeth.h"
#include "json_writer.h"
#include "pl_common.h"
#include "pl_fused.h"

#include "vplane_log.h"

#include "protobuf.h"
#include "protobuf/XConnectConfig.pb-c.h"

/* Show information xconnect session in JSON */
static void conn_show_session(void *s, void *arg)
{
	json_writer_t *wr = arg;
	const struct conn_session *session = s;
	struct ifnet *peer_ifp;
	struct ifnet *ifp;

	if (!session)
		return;

	jsonw_start_object(wr);

	jsonw_string_field(wr, "local_ifname",
			   session->local_if_name);
	jsonw_string_field(wr, "peer_ifname",
			   session->peer_if_name);
	ifp = ifnet_byifname(session->local_if_name);
	jsonw_uint_field(wr, "local_ifindex",
			 ifp ? ifp->if_index : 0);
	peer_ifp = ifp ? rcu_dereference(ifp->if_xconnect) : NULL;
	jsonw_uint_field(wr, "configured_peer_ifindex",
			 peer_ifp ? peer_ifp->if_index : 0);
	ifp = ifnet_byifname(session->peer_if_name);
	jsonw_uint_field(wr, "peer_ifindex",
			 ifp ? ifp->if_index : 0);

	jsonw_end_object(wr);
}

/* xconnect config commands
 */
static int cmd_xconnect_cfg(struct pb_msg *msg)
{
	void *payload = (void *)((char *)msg->msg);
	int len = msg->msg_len;

	XConnectConfig *xmsg =
		xconnect_config__unpack(NULL, len,
					payload);
	if (!xmsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read xconnect protobuf command\n");
		return -1;
	}

	int ret = cross_connect_set(xmsg->cmd,
				    xmsg->dp_ifname,
				    xmsg->new_ifname);

	xconnect_config__free_unpacked(xmsg, NULL);

	return ret;
}

/* xconnect op-mode commands
 */
static int cmd_xconnect(struct pl_command *cmd)
{
	/* One arg is required */
	if (cmd->argc < 1) {
		pl_cmd_err(cmd, "xconnect cmd: missing argument: %d",
			   cmd->argc);
		return -1;
	}

	if (strcmp(cmd->argv[0], "-s") == 0) {
		json_writer_t *wr = jsonw_new(cmd->fp);

		if (!wr)
			return -1;

		jsonw_pretty(wr, true);
		jsonw_name(wr, "xconn");
		jsonw_start_array(wr);

		if (cmd->argc == 1)
			conn_session_walk(conn_show_session, wr);
		else {
			struct ifnet *ifp = ifnet_byifname(cmd->argv[1]);
			if (ifp && ifp->if_softc) {
				struct l2tp_softc *sc = ifp->if_softc;
				conn_show_session(sc->sclp_session, wr);
			}
		}
		jsonw_end_array(wr);
		jsonw_destroy(&wr);

		return 0;
	} else if (strcmp(cmd->argv[0], "clear") == 0) {
		if (cmd->argc == 1)
			l2tp_init_stats(NULL);
		else
			l2tp_init_stats(l2tp_session_byid(atoi(cmd->argv[1])));
		return 0;
	}

	pl_cmd_err(cmd, "xconnect cmd: wrong command %s",
		   cmd->argv[0]);
	return -1;
}

PB_REGISTER_CMD(cross_connect_cmd) = {
	.cmd = "vyatta:xconnect",
	.handler = cmd_xconnect_cfg,
};

PL_REGISTER_OPCMD(cross_connect_opcmd) = {
	.cmd = "xconnect cmd",
	.handler = cmd_xconnect,
};
