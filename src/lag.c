/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "dp_event.h"
#include "if_var.h"
#include "lag.h"

static const struct lag_ops *current_lag_ops;

struct ifnet *ifnet_byteam(int ifindex)
{
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);

	if (ifp && ifp->if_team)
		return ifp;
	return NULL;
}

int lag_etype_slow_tx(struct ifnet *master, struct ifnet *ifp,
		      struct rte_mbuf *lacp_pkt)
{
	return current_lag_ops->lagop_etype_slow_tx(master, ifp, lacp_pkt);
}

void lag_slave_sync_mac_address(struct ifnet *ifp)
{
	current_lag_ops->lagop_slave_sync_mac_address(ifp);
}

struct ifnet *lag_create(const struct ifinfomsg *ifi, struct nlattr *tb[])
{
	return current_lag_ops->lagop_create(ifi, tb);
}

int lag_mode_set_balance(struct ifnet *ifp)
{
	return current_lag_ops->lagop_mode_set_balance(ifp);
}

int lag_mode_set_activebackup(struct ifnet *ifp)
{
	return current_lag_ops->lagop_mode_set_activebackup(ifp);
}

int lag_select(struct ifnet *ifp, bool enable)
{
	return current_lag_ops->lagop_select(ifp, enable);
}

int lag_set_activeport(struct ifnet *ifp, struct ifnet *ifp_slave)
{
	return current_lag_ops->lagop_set_activeport(ifp, ifp_slave);
}

void lag_nl_master_delete(const struct ifinfomsg *ifi __unused,
			  struct ifnet *master_ifp)
{
	return current_lag_ops->lagop_delete(master_ifp);
}

bool lag_can_start(const struct ifnet *ifp)
{
	if (!ifp->if_team)
		return true;

	return current_lag_ops->lagop_can_start(ifp);
}

int lag_slave_add(struct ifnet *master, struct ifnet *ifp)
{
	return current_lag_ops->lagop_slave_add(master, ifp);
}

int lag_slave_delete(struct ifnet *master, struct ifnet *ifp)
{
	return current_lag_ops->lagop_slave_delete(master, ifp);
}

/* Add interface to an aggregation or update an already enslaved interface */
int lag_nl_slave_update(const struct ifinfomsg *ifi,
			struct ifnet *ifp, struct ifnet *master)
{
	return current_lag_ops->lagop_nl_slave_update(ifi, ifp, master);
}

void lag_refresh_actor_state(struct ifnet *master)
{
	return current_lag_ops->lagop_refresh_actor_state(master);
}

static void show_lag(struct ifnet *ifp, void *arg)
{
	if (is_team(ifp))
		current_lag_ops->lagop_show_detail(ifp, arg);
}

int lag_summary(FILE *fp)
{
	json_writer_t *wr = jsonw_new(fp);

	if (!wr)
		return -1;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "lag");
	jsonw_start_array(wr);

	dp_ifnet_walk(show_lag, wr);

	jsonw_end_array(wr);
	jsonw_destroy(&wr);

	return 0;
}

int
lag_walk_bond_slaves(struct ifnet *ifp, dp_ifnet_iter_func_t iter_func,
		     void *arg)
{
	return current_lag_ops->lagop_walk_bond_slaves(ifp, iter_func, arg);
}

bool
lag_is_team(struct ifnet *ifp)
{
	if (ifp->if_type != IFT_ETHER)
		return false;

	return current_lag_ops->lagop_is_team(ifp);
}

int lag_can_startstop_member(struct ifnet *ifp)
{
	return current_lag_ops->lagop_can_startstop_member(ifp);
}

int lag_set_l2_address(struct ifnet *ifp, struct rte_ether_addr *macaddr)
{
	return current_lag_ops->lagop_set_l2_address(ifp, macaddr);
}

static void lag_init(void)
{
	if (platform_cfg.hardware_lag)
		current_lag_ops = &fal_lag_ops;
	else
		current_lag_ops = &dpdk_lag_ops;
}

static const struct dp_event_ops lag_events = {
	.init = lag_init,
};

DP_STARTUP_EVENT_REGISTER(lag_events);
