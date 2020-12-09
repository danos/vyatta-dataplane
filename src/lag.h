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

#define LAG_MAX_MEMBERS RTE_MAX_ETHPORTS

struct lag_ops {
	int (*lagop_etype_slow_tx)(struct ifnet *team, struct ifnet *ifp,
				   struct rte_mbuf *lacp_pkt);
	struct ifnet *(*lagop_create)(const struct ifinfomsg *ifi,
				      struct nlattr *tb[]);
	int (*lagop_member_add)(struct ifnet *team, struct ifnet *ifp);
	int (*lagop_member_delete)(struct ifnet *team, struct ifnet *ifp);
	void (*lagop_delete)(struct ifnet *ifp);
	int (*lagop_nl_member_update)(const struct ifinfomsg *ifi,
				     struct ifnet *ifp,
				     struct ifnet *team);
	int (*lagop_mode_set_balance)(struct ifnet *ifp);
	int (*lagop_mode_set_activebackup)(struct ifnet *ifp);
	int (*lagop_select)(struct ifnet *ifp, bool sel);
	int (*lagop_set_activeport)(struct ifnet *ifp,
				    struct ifnet *ifp_member);
	void (*lagop_refresh_actor_state)(struct ifnet *team);
	void (*lagop_show_detail)(struct ifnet *ifp, json_writer_t *wr);
	void (*lagop_member_sync_mac_address)(struct ifnet *ifp);
	int (*lagop_walk_team_members)(struct ifnet *ifp,
				      dp_ifnet_iter_func_t func, void *arg);
	bool (*lagop_can_start)(const struct ifnet *ifp);
	bool (*lagop_port_is_member)(struct ifnet *team, struct ifnet *ifp);
	bool (*lagop_is_team)(struct ifnet *ifp);
	bool (*lagop_can_startstop_member)(struct ifnet *ifp);
	int (*lagop_set_l2_address)(struct ifnet *ifp,
				    struct rte_ether_addr *macaddr);
	int (*lagop_min_links)(struct ifnet *ifp, uint16_t *min_links);
	int (*lagop_set_min_links)(struct ifnet *ifp, uint16_t min_links);
};

extern const struct lag_ops dpdk_lag_ops;
extern const struct lag_ops fal_lag_ops;

struct ifnet *ifnet_byteam(int ifindex);
int lag_etype_slow_tx(struct ifnet *team, struct ifnet *ifp,
		struct rte_mbuf *lacp_pkt);
struct ifnet *lag_create(const struct ifinfomsg *ifi, struct nlattr *tb[]);
int lag_member_add(struct ifnet *team, struct ifnet *ifp);
int lag_member_delete(struct ifnet *team, struct ifnet *ifp);
void lag_nl_team_delete(const struct ifinfomsg *ifi, struct ifnet *ifp);
int lag_nl_member_update(const struct ifinfomsg *ifi, struct ifnet *ifp,
			struct ifnet *team);
int lag_mode_set_balance(struct ifnet *ifp);
int lag_mode_set_activebackup(struct ifnet *ifp);
int lag_select(struct ifnet *ifp, bool enable);
int lag_set_activeport(struct ifnet *ifp, struct ifnet *ifp_member);
void lag_refresh_actor_state(struct ifnet *team);
int lag_summary(FILE *fp);
void lag_member_sync_mac_address(struct ifnet *ifp);
int lag_walk_team_members(struct ifnet *ifp, dp_ifnet_iter_func_t func,
			 void *arg);
bool lag_can_start(const struct ifnet *ifp);
bool lag_is_team(struct ifnet *ifp);
int lag_can_startstop_member(struct ifnet *ifp);
int lag_set_l2_address(struct ifnet *ifp, struct rte_ether_addr *macaddr);
int lag_min_links(struct ifnet *ifp, uint16_t *min_links);
int lag_set_min_links(struct ifnet *ifp, uint16_t min_links);

#endif
