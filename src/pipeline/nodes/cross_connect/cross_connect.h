/*-
 * Copyright (c) 2018-2019,2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CROSS_CONNECT_H
#define CROSS_CONNECT_H

#include <netinet/in.h>
#include <stdbool.h>
#include <linux/if.h>
#include <urcu/list.h>

#include "urcu.h"

#include "protobuf/XConnectConfig.pb-c.h"

struct ifnet;
struct rte_mbuf;
struct pl_packet;

struct conn_session {
	char local_if_name[IFNAMSIZ];
	char peer_if_name[IFNAMSIZ];

	struct rcu_head conn_rcu;
	struct cds_list_head conn_list;
};

typedef void conn_iter_func_t(void *, void *arg);

void conn_session_walk(conn_iter_func_t func, void *arg);
int cross_connect_set(const XConnectConfig__CommandType cmd, XConnectConfig__XConnectType type,
		      const char *ifname1, const char *ifname2, uint8_t ttl);
void cross_connect_rename(struct ifnet *ifp, const char *ifname);

void cross_connect_link(struct ifnet *src_ifp, struct ifnet *dst_ifp,
			bool config);
void cross_connect_unlink(struct ifnet *src_ifp, bool config);

#endif /* CROSS_CONNECT_H */
