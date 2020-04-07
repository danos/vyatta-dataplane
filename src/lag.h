/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
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

#define LAG_MAX_SLAVES RTE_MAX_ETHPORTS

struct lag_ops {
	int (*lagop_etype_slow_tx)(struct ifnet *master, struct ifnet *ifp,
				   struct rte_mbuf *lacp_pkt);
	struct ifnet *(*lagop_create)(const struct ifinfomsg *ifi,
				      struct nlattr *tb[]);
	int (*lagop_slave_add)(struct ifnet *master, struct ifnet *ifp);
	int (*lagop_slave_delete)(struct ifnet *master, struct ifnet *ifp);
	void (*lagop_delete)(struct ifnet *ifp);
	int (*lagop_nl_slave_update)(const struct ifinfomsg *ifi,
				     struct ifnet *ifp,
				     struct ifnet *master);
	int (*lagop_mode_set_balance)(struct ifnet *ifp);
	int (*lagop_mode_set_activebackup)(struct ifnet *ifp);
	int (*lagop_select)(struct ifnet *ifp, bool sel);
	int (*lagop_set_activeport)(struct ifnet *ifp, struct ifnet *ifp_slave);
	void (*lagop_refresh_actor_state)(struct ifnet *master);
	void (*lagop_show_detail)(struct ifnet *ifp, json_writer_t *wr);
	void (*lagop_slave_sync_mac_address)(struct ifnet *ifp);
	int (*lagop_walk_bond_slaves)(struct ifnet *ifp,
				      dp_ifnet_iter_func_t func, void *arg);
	bool (*lagop_can_start)(const struct ifnet *ifp);
	bool (*lagop_port_is_slave)(struct ifnet *master, struct ifnet *ifp);
	bool (*lagop_is_team)(struct ifnet *ifp);
	bool (*lagop_can_startstop_member)(struct ifnet *ifp);
	int (*lagop_set_l2_address)(struct ifnet *ifp,
				    struct ether_addr *macaddr);
};

extern const struct lag_ops dpdk_lag_ops;
extern const struct lag_ops fal_lag_ops;

struct ifnet *ifnet_byteam(int ifindex);
int lag_etype_slow_tx(struct ifnet *master, struct ifnet *ifp,
		struct rte_mbuf *lacp_pkt);
struct ifnet *lag_create(const struct ifinfomsg *ifi, struct nlattr *tb[]);
int lag_slave_add(struct ifnet *master, struct ifnet *ifp);
int lag_slave_delete(struct ifnet *master, struct ifnet *ifp);
void lag_nl_master_delete(const struct ifinfomsg *ifi, struct ifnet *ifp);
int lag_nl_slave_update(const struct ifinfomsg *ifi, struct ifnet *ifp,
			struct ifnet *master);
int lag_mode_set_balance(struct ifnet *ifp);
int lag_mode_set_activebackup(struct ifnet *ifp);
int lag_select(struct ifnet *ifp, bool sel);
int lag_set_activeport(struct ifnet *ifp, struct ifnet *ifp_slave);
void lag_refresh_actor_state(struct ifnet *master);
int lag_summary(FILE *fp);
void lag_slave_sync_mac_address(struct ifnet *ifp);
int lag_walk_bond_slaves(struct ifnet *ifp, dp_ifnet_iter_func_t func,
			 void *arg);
bool lag_can_start(const struct ifnet *ifp);
bool lag_is_team(struct ifnet *ifp);
int lag_can_startstop_member(struct ifnet *ifp);
int lag_set_l2_address(struct ifnet *ifp, struct ether_addr *macaddr);

#endif
