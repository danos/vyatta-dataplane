/*
 * l2_pppoe_cmd.c
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2018-2019 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "compiler.h"
#include "ether.h"
#include "pppoe.h"
#include "util.h"
#include "vplane_log.h"

#include "protobuf.h"
#include "protobuf/PPPOEConfig.pb-c.h"

static int
pppoe_opcmd_handler(struct pl_command *cmd)
{
	json_writer_t *wr = jsonw_new(cmd->fp);
	struct pppoe_connection *conn;

	if (!wr)
		return 0;
	jsonw_pretty(wr, true);
	jsonw_name(wr, "pppoe");
	jsonw_start_array(wr);

	cds_list_for_each_entry_rcu(conn, pppoe_get_conn_list(), list_node) {
		char src[ETH_ADDR_STR_LEN], dst[ETH_ADDR_STR_LEN];

		ether_ntoa_r(&conn->my_eth, src);
		ether_ntoa_r(&conn->peer_eth, dst);

		jsonw_start_object(wr);
		jsonw_string_field(wr, "device", conn->ifp->if_name);
		jsonw_string_field(wr, "underlying",
				   conn->underlying_name);
		jsonw_uint_field(wr, "session", conn->session);
		jsonw_string_field(wr, "eth", src);
		jsonw_string_field(wr, "peer-eth", dst);
		jsonw_string_field(wr, "valid",
				   conn->valid ? "yes" : "no");
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);

	return 0;
}

static int
_pppoe_cmd_handler(PPPOEConfig *pppoe_msg, struct pb_msg *msg)
{
	char *pppname;
	struct ifnet *ppp_inter;
	char *under_name;
	struct ifnet *underlying;
	struct pppoe_connection *conn;
	struct ether_addr my_eth;
	struct ether_addr peer_eth;

	pppname = pppoe_msg->pppname;
	ppp_inter = dp_ifnet_byifname(pppname);
	if (!ppp_inter)
		return 0;

	under_name = pppoe_msg->undername;
	underlying = dp_ifnet_byifname(under_name);

	if (!ether_aton_r(pppoe_msg->ether, &my_eth)) {
		dp_pb_cmd_err(msg, "not a valid session id: %s\n",
			pppoe_msg->ether);
		return -1;
	}

	if (!ether_aton_r(pppoe_msg->peer_ether, &peer_eth)) {
		dp_pb_cmd_err(msg, "not a valid ethernet net address: %s\n",
			   pppoe_msg->peer_ether);
		return -1;
	}

	if (ppp_inter->if_softc) {
		dp_pb_cmd_err(msg, "Can not modify PPP connection.");
		return -1;
	}
	ppp_inter->if_softc = zmalloc_aligned(sizeof(struct pppoe_connection));
	if (!ppp_inter->if_softc) {
		RTE_LOG(ERR, PPPOE,
			"Out of memory allocating connection struct.");
		dp_pb_cmd_err(msg,
			"Out of memory allocating connection struct.");
		return -1;
	}

	conn = ppp_inter->if_softc;

	conn->session = pppoe_msg->session;
	conn->my_eth = my_eth;
	conn->peer_eth = peer_eth;
	snprintf(conn->underlying_name, IFNAMSIZ, "%s", under_name);
	conn->ifp = ppp_inter;

	conn->underlying_interface = underlying;
	if (underlying) {
		conn->underlying_ifindex = underlying->if_index;

		if (!pppoe_init_session(ppp_inter, conn->session)) {
			dp_pb_cmd_err(msg,
				"could not initialize pppoe session\n");
			free(ppp_inter->if_softc);
			ppp_inter->if_softc = NULL;
			return -1;
		}
		conn->valid = 1;
	}

	pppoe_track_underlying_interfaces();
	cds_list_add_rcu(&conn->list_node, pppoe_get_conn_list());
	return 0;
}

static int
pppoe_cmd_handler(struct pb_msg *msg)
{
	PPPOEConfig *pppoe_msg;
	int rc;

	pppoe_msg = pppoeconfig__unpack(NULL, msg->msg_len, msg->msg);
	if (!pppoe_msg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read pppoe protobuf command\n");
		return -1;
	}

	rc = _pppoe_cmd_handler(pppoe_msg, msg);

	pppoeconfig__free_unpacked(pppoe_msg, NULL);
	return rc;
}

PB_REGISTER_CMD(pppoe_cmd) = {
	.cmd = "vyatta:pppoe",
	.handler = pppoe_cmd_handler,
};

PL_REGISTER_OPCMD(pppoe_show) = {
	.cmd = "pppoe show",
	.handler = pppoe_opcmd_handler,
};
