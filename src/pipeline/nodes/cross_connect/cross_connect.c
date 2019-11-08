/*
 * Cross-Connect
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "cross_connect.h"
#include "pl_common.h"
#include "dp_event.h"
#include "if_var.h"
#include "main.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pktmbuf.h"
#include "pl_node.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"
#include "vrf.h"

/*
 * conn_cfg_list are used to store
 * the xconnect configs before it could
 * actually set in the ifp.
 * If conn config comes before either ifp
 * is created, the config is stored
 * in the conn_cfg_list.
 */
static CDS_LIST_HEAD(conn_cfg_list);

static struct conn_session *
conn_session_byname(const char *ifname)
{
	struct conn_session *conn;

	cds_list_for_each_entry_rcu(conn, &conn_cfg_list, conn_list) {
		if (strncmp(conn->local_if_name, ifname, IFNAMSIZ) == 0)
			return conn;
	}

	return NULL;
}

void conn_session_walk(conn_iter_func_t func, void *arg)
{
	struct conn_session *session;

	cds_list_for_each_entry_rcu(session, &conn_cfg_list, conn_list) {
		(func)(session, arg);
	}
}

static void
conn_session_insert(struct conn_session *session)
{

	cds_list_add_tail_rcu(&session->conn_list, &conn_cfg_list);
}

static void
conn_session_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct conn_session, conn_rcu));
}

static void
conn_session_delete(struct conn_session *session)
{
	if (likely(session != NULL)) {
		cds_list_del_rcu(&session->conn_list);
		call_rcu(&session->conn_rcu, conn_session_free);
	}
}

void
cross_connect_link(struct ifnet *src_ifp, struct ifnet *dst_ifp, bool config)
{
	if (dst_ifp)
		src_ifp->if_xconnect = dst_ifp;

	if (config) {
		ifpromisc(src_ifp, 1);
		pl_node_add_feature_by_inst(&cross_connect_ether_feat, src_ifp);
	}
}

void
cross_connect_unlink(struct ifnet *src_ifp, bool config)
{
	if (config) {
		pl_node_remove_feature_by_inst(&cross_connect_ether_feat,
					       src_ifp);
		ifpromisc(src_ifp, 0);
	}

	src_ifp->if_xconnect = NULL;
}

static void
conn_update(const char *ifname1, const char *ifname2)
{
	struct ifnet *src_ifp = ifnet_byifname(ifname1);
	bool insert = false;
	struct conn_session *session;

	if (src_ifp)
		cross_connect_link(src_ifp, ifnet_byifname(ifname2),
				   true);

	session = conn_session_byname(ifname1);
	if (!session) {
		session =
			zmalloc_aligned(sizeof(struct conn_session));

		if (unlikely(session == NULL)) {
			RTE_LOG(ERR, DATAPLANE,
				"can't allocate xconnect session\n");
			return;
		}
		insert = true;
	}
	if (strlen(ifname1) >= IFNAMSIZ)
		RTE_LOG(NOTICE, DATAPLANE, "Cross-connnect: truncating too "
			"long interface name: %s\n", ifname1);
	snprintf(session->local_if_name, IFNAMSIZ, "%s", ifname1);

	if (strlen(ifname2) >= IFNAMSIZ)
		RTE_LOG(NOTICE, DATAPLANE, "Cross-connnect: truncating too "
			"long interface name: %s\n", ifname2);
	snprintf(session->peer_if_name, IFNAMSIZ, "%s", ifname2);

	RTE_LOG(ERR, DATAPLANE, "insert %d, %s, %s\n", insert,
		session->local_if_name, session->peer_if_name);

	if (insert)
		conn_session_insert(session);
}

int cross_connect_set(const XConnectConfig__CommandType cmd,
		      const char *ifname1, const char *ifname2)
{
	if (cmd == XCONNECT_CONFIG__COMMAND_TYPE__REMOVE) {
		struct ifnet *src_ifp = ifnet_byifname(ifname1);

		if (src_ifp)
			cross_connect_unlink(src_ifp, true);

		struct conn_session *session = conn_session_byname(ifname1);
		if (session)
			conn_session_delete(session);
	} else
		conn_update(ifname1, ifname2);

	return 0;
}


/* When interface changes name, the old connection needs to be broken,
 * and new association made.
 */
void cross_connect_rename(struct ifnet *ifp, const char *ifname)
{
	struct conn_session *conn;

	if (ifp->if_type != IFT_ETHER)
		return;

	cds_list_for_each_entry_rcu(conn, &conn_cfg_list, conn_list) {
		if (strncmp(conn->local_if_name, ifname, IFNAMSIZ) == 0 ||
		    strncmp(conn->peer_if_name, ifname, IFNAMSIZ) == 0) {
			struct ifnet *src_ifp = ifnet_byifname(
				conn->local_if_name);
			if (!src_ifp)
				continue;

			cross_connect_unlink(src_ifp, false);
			cross_connect_link(src_ifp,
					   ifnet_byifname(conn->peer_if_name),
					   false);
		}
	}
}

static void notify_cross_connect_new_link(struct ifnet *intf,
					  uint32_t idx __unused)
{
	struct conn_session *conn;

	cds_list_for_each_entry_rcu(conn, &conn_cfg_list, conn_list) {
		if (strncmp(conn->local_if_name, intf->if_name, IFNAMSIZ)
		    == 0)
			cross_connect_link(intf,
					   ifnet_byifname(conn->peer_if_name),
					   true);

		if (strncmp(conn->peer_if_name, intf->if_name, IFNAMSIZ) == 0) {
			struct ifnet *src_ifp = ifnet_byifname(
				conn->local_if_name);
			if (src_ifp)
				cross_connect_link(src_ifp, intf, false);
		}
	}
}

static void conn_del_if(struct ifnet *ifp, void *arg)
{
	struct ifnet *del_ifp = arg;

	if (ifp->if_xconnect == del_ifp)
		cross_connect_unlink(ifp, false);
}

static void notify_cross_connect_del_link(struct ifnet *intf,
					  uint32_t idx __unused)
{
	ifnet_walk(conn_del_if, intf);
}

static const struct dp_event_ops cross_connect_events = {
	.if_index_set = notify_cross_connect_new_link,
	.if_index_unset = notify_cross_connect_del_link,
};

DP_STARTUP_EVENT_REGISTER(cross_connect_events);
