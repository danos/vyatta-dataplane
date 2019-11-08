/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef LAG_H
#define LAG_H

#include <linux/rtnetlink.h>
#include <rte_config.h>
#include <stdio.h>

#include "if_var.h"

struct rte_mbuf;

#define BOND_DEV_NAME "net_bonding"
#define LAG_MAX_SLAVES RTE_MAX_ETHPORTS

struct ifnet *ifnet_byteam(int ifindex);
int lag_etype_slow_tx(struct ifnet *master, struct ifnet *ifp,
		struct rte_mbuf *lacp_pkt);
struct ifnet *lag_create(const struct ifinfomsg *ifi, struct nlattr *tb[]);
int lag_slave_add(struct ifnet *master, struct ifnet *ifp);
int lag_slave_delete(struct ifnet *master, struct ifnet *ifp);
int lag_lsupdate(struct ifnet *ifp);
void lag_nl_master_delete(const struct ifinfomsg *ifi, struct ifnet *ifp);
int lag_nl_slave_update(const struct ifinfomsg *ifi, struct ifnet *ifp,
			struct ifnet *master);
int lag_mode_set_balance(struct ifnet *ifp);
int lag_mode_set_activebackup(struct ifnet *ifp);
int lag_select(struct ifnet *ifp, int sel);
int lag_activeport(struct ifnet *ifp, struct ifnet *ifp_slave);
void lag_refresh_actor_state(struct ifnet *master);
int lag_summary(FILE *fp);
void lag_slave_sync_mac_address(struct ifnet *ifp);
void lag_set_phy_qinq_mtu_slave(struct ifnet *sl, void *unused);
int lag_walk_bond_slaves(struct ifnet *ifp, ifnet_iter_func_t func, void *arg);
int slave_count(const struct ifnet *ifp);
bool lag_port_is_slave(struct ifnet *master, struct ifnet *ifp);

#endif
