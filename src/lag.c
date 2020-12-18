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
#include "if/dpdk-eth/dpdk_eth_if.h"
#include "if_var.h"
#include "lag.h"
#include "protobuf.h"
#include "protobuf/LAGConfig.pb-c.h"
#include "vplane_debug.h"

static const struct lag_ops *current_lag_ops;

struct ifnet *ifnet_byteam(int ifindex)
{
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);

	if (ifp && ifp->if_team)
		return ifp;
	return NULL;
}

int lag_etype_slow_tx(struct ifnet *team, struct ifnet *ifp,
		      struct rte_mbuf *lacp_pkt)
{
	return current_lag_ops->lagop_etype_slow_tx(team, ifp, lacp_pkt);
}

void lag_member_sync_mac_address(struct ifnet *ifp)
{
	current_lag_ops->lagop_member_sync_mac_address(ifp);
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

int lag_set_member_usable(struct ifnet *ifp, bool usable)
{
	if (current_lag_ops->lagop_set_member_usable)
		return current_lag_ops->lagop_set_member_usable(ifp, usable);

	return 0;
}

int lag_set_activeport(struct ifnet *ifp, struct ifnet *ifp_member)
{
	return current_lag_ops->lagop_set_activeport(ifp, ifp_member);
}

void lag_nl_team_delete(const struct ifinfomsg *ifi __unused,
			  struct ifnet *team_ifp)
{
	return current_lag_ops->lagop_delete(team_ifp);
}

bool lag_can_start(const struct ifnet *ifp)
{
	if (!ifp->if_team)
		return true;

	return current_lag_ops->lagop_can_start(ifp);
}

int lag_member_add(struct ifnet *team, struct ifnet *ifp)
{
	int rc;

	rc = current_lag_ops->lagop_member_add(team, ifp);
	if (!rc)
		dp_event(DP_EVT_IF_LAG_ADD_MEMBER, 0, team, 0, 0, ifp);

	return rc;
}

int lag_member_delete(struct ifnet *team, struct ifnet *ifp)
{
	dp_event(DP_EVT_IF_LAG_DELETE_MEMBER, 0, team, 0, 0, ifp);
	return current_lag_ops->lagop_member_delete(team, ifp);
}

/* Add interface to an aggregation or update an existing member interface */
int lag_nl_member_update(const struct ifinfomsg *ifi,
			struct ifnet *ifp, struct ifnet *team)
{
	return current_lag_ops->lagop_nl_member_update(ifi, ifp, team);
}

void lag_refresh_actor_state(struct ifnet *team)
{
	return current_lag_ops->lagop_refresh_actor_state(team);
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
lag_walk_team_members(struct ifnet *ifp, dp_ifnet_iter_func_t iter_func,
		     void *arg)
{
	return current_lag_ops->lagop_walk_team_members(ifp, iter_func, arg);
}

bool
lag_is_team(struct ifnet *ifp)
{
	if (ifp->if_type != IFT_ETHER)
		return false;

	return current_lag_ops->lagop_is_team(ifp);
}

bool
lag_port_is_member(struct ifnet *ifp)
{
	if (current_lag_ops->lagop_port_is_member)
		return current_lag_ops->lagop_port_is_member(ifp);

	return false;
}

int lag_can_startstop_member(struct ifnet *ifp)
{
	return current_lag_ops->lagop_can_startstop_member(ifp);
}

int lag_set_l2_address(struct ifnet *ifp, struct rte_ether_addr *macaddr)
{
	return current_lag_ops->lagop_set_l2_address(ifp, macaddr);
}

int lag_min_links(struct ifnet *ifp, uint16_t *min_links)
{
	if (current_lag_ops->lagop_min_links)
		return current_lag_ops->lagop_min_links(ifp, min_links);
	return -ENOTSUP;
}

int lag_set_min_links(struct ifnet *ifp, uint16_t min_links)
{
	if (current_lag_ops->lagop_set_min_links)
		return current_lag_ops->lagop_set_min_links(ifp, min_links);
	return -ENOTSUP;
}

fal_object_t dp_ifnet_fal_lag_member(const struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *member_sc;

	if (ifp->if_type != IFT_ETHER)
		return FAL_NULL_OBJECT_ID;

	if (!ifp->aggregator)
		return FAL_NULL_OBJECT_ID;

	member_sc = ifp->if_softc;
	if (!member_sc->scd_fal_lag_member_created)
		return FAL_NULL_OBJECT_ID;

	return member_sc->scd_fal_lag_member_obj;
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

static int
lag_pb_create_handler(LAGConfig__LagCreate *lag_create)
{
	struct ifnet *ifp;

	if (!lag_create->ifname)
		return -EINVAL;

	ifp = dp_ifnet_byifname(lag_create->ifname);
	if (!ifp) {
		/* We will get another update when
		 * the interface eventually appears.
		 */
		return 0;
	}

	if (lag_create->has_minimum_links) {
		uint16_t minimum_links;
		int ret;

		if (lag_create->minimum_links > UINT16_MAX)
			return -EINVAL;

		ret = lag_min_links(ifp, &minimum_links);
		if (ret == -ENOTSUP)
			return 0;

		/* If min links was never set, lag_min_links will fail,
		 * but this isn't a problem.
		 */
		if (ret == -EINVAL) {
			minimum_links = 0;
			ret = 0;
		}

		if (ret < 0) {
			RTE_LOG(ERR, DATAPLANE, "%s: lag_min_links failed: %d\n",
				__func__, ret);
			return ret;
		}

		if (lag_create->minimum_links != minimum_links) {
			lag_set_min_links(ifp, lag_create->minimum_links);
			dp_event(DP_EVT_IF_LAG_CHANGE, 0, ifp,
				 DP_IF_LAG_EVENT_MIN_LINKS_CHANGE, 0, NULL);
		}
	}

	return 0;
}

static int
lag_pb_delete_handler(LAGConfig__LagDelete *lag_delete)
{
	if (!lag_delete->ifname)
		return -EINVAL;

	return 0;
}

static int
lag_pb_handler(struct pb_msg *msg)
{
	LAGConfig *lag = lagconfig__unpack(NULL, msg->msg_len, msg->msg);
	int ret;

	switch (lag->mtype_case) {
	case LAGCONFIG__MTYPE_LAG_CREATE:
		ret = lag_pb_create_handler(lag->lag_create);
		break;
	case LAGCONFIG__MTYPE_LAG_DELETE:
		ret = lag_pb_delete_handler(lag->lag_delete);
		break;
	default:
		RTE_LOG(ERR, DATAPLANE, "unhandled LAG message type %d\n",
			lag->mtype_case);
		ret = 0;
	}

	lagconfig__free_unpacked(lag, NULL);
	return ret;
}

PB_REGISTER_CMD(lag_create_cmd) = {
	.cmd = "vyatta:lag",
	.handler = lag_pb_handler,
};

