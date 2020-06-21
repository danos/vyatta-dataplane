/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <vyatta-dataplane/vyatta_swport.h>

#include "dpdk_eth_if.h"
#include "dp_event.h"
#include "ether.h"
#include "fal.h"
#include "if_var.h"
#include "lag.h"
#include "controller.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

static bool fal_lag_member_enabled[LAG_MAX_MEMBERS];

static int fal_lag_member_delete(struct ifnet *team_ifp, struct ifnet *ifp);

static bool
fal_lag_can_create_in_fal(struct ifnet *ifp)
{
	/*
	 * LAG supersedes bridging, and the latter is expected to
	 * remove itself just prior to the FAL notifications to add the
	 * LAG member.  So if there are no other embellished features,
	 * then the LAG can be created.
	 */
	return !if_check_any_except_emb_feat(ifp, IF_EMB_FEAT_LAG_MEMBER |
					     IF_EMB_FEAT_BRIDGE_MEMBER);
}

static int
fal_lag_etype_slow_tx(struct ifnet *bond __unused, struct ifnet *ifp,
		      struct rte_mbuf *lacp_pkt)
{
	if_output(ifp, lacp_pkt, NULL, ntohs(ethhdr(lacp_pkt)->ether_type));

	return 0;
}

static void
fal_lag_member_sync_mac_address(struct ifnet *ifp __unused)
{
	/* not required */
}

static struct ifnet *
fal_lag_create(const struct ifinfomsg *ifi, struct nlattr *tb[])
{
	struct swport_dev_info swport_dev_info;
	struct rte_eth_dev_info dev_info;
	struct rte_ether_addr *macaddr = NULL;
	struct dpdk_eth_if_softc *sc;
	fal_object_t fal_lag_obj;
	portid_t dpdk_port;
	const char *ifname;
	struct ifnet *ifp;
	int ret;

	if (tb[IFLA_IFNAME])
		ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);
	else {
		RTE_LOG(ERR, DATAPLANE,
			"FAL-LAG: missing name for %u\n",
			ifi->ifi_index);
		return NULL;
	}

	if (tb[IFLA_ADDRESS]) {
		size_t addrlen = mnl_attr_get_payload_len(tb[IFLA_ADDRESS]);

		if (addrlen == RTE_ETHER_ADDR_LEN)
			macaddr = mnl_attr_get_payload(tb[IFLA_ADDRESS]);
	}
	if (!macaddr) {
		RTE_LOG(ERR, DATAPLANE,
			"FAL-LAG: missing MAC address for %s\n",
			ifname);
		return NULL;
	}

	ret = fal_create_lag(0, NULL, &fal_lag_obj);
	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"unable to create FAL LAG interface for %s: %s\n",
			ifname, strerror(-ret));
		return NULL;
	}

	/*
	 * Find the DPDK port ID for the LAG interface just created in
	 * the FAL. We do it this way (rather than the port ID being
	 * returned from the FAL call) to lessen the need for the FAL
	 * API needing to be aware of there being a DPDK PMD backing
	 * for certain interfaces.
	 */
	for (dpdk_port = 0; dpdk_port < DATAPLANE_MAX_PORTS; dpdk_port++) {
		if (!rte_eth_dev_is_valid_port(dpdk_port))
			continue;
		rte_eth_dev_info_get(dpdk_port, &dev_info);
		if (strcmp(dev_info.driver_name, "net_sw_port"))
			continue;
		if (sw_port_get_dev_info(dpdk_port, &swport_dev_info) < 0)
			continue;

		if (swport_dev_info.fal_obj == fal_lag_obj)
			break;
	}
	if (dpdk_port == DATAPLANE_MAX_PORTS) {
		RTE_LOG(ERR, DATAPLANE,
			"unable to find sw_port PMD instance for FAL LAG interface %s with object 0x%lx\n",
			ifname, fal_lag_obj);
		goto del_fal_lag;
	}

	/*
	 * Set the MAC address so when the ifp is created it will be
	 * filled in with the correct MAC address
	 */
	rte_eth_dev_default_mac_addr_set(dpdk_port, macaddr);

	/* create ifp and set it up */
	if (insert_port(dpdk_port) != 0) {
		RTE_LOG(ERR, DATAPLANE,
			"insert port for FAL LAG interface %s failed\n",
			ifname);
		goto del_fal_lag;
	}

	ifp = if_hwport_alloc_w_port(ifname, ifi->ifi_index, dpdk_port);
	if (!ifp)
		goto del_rem_port;
	sc = ifp->if_softc;
	sc->scd_fal_port_lag_obj = fal_lag_obj;
	CDS_INIT_LIST_HEAD(&sc->scd_fal_lag_members_head);

	ifp->hw_forwarding = true;

	return ifp;

del_rem_port:
	remove_port(dpdk_port);

del_fal_lag:
	ret = fal_delete_lag(fal_lag_obj);
	if (ret < 0)
		RTE_LOG(ERR, DATAPLANE,
			"unable to delete FAL LAG interface for %s during failed create cleanup: %s\n",
			ifname, strerror(-ret));
	return NULL;
}

static int
fal_lag_mode_set_balance(struct ifnet *ifp __unused)
{
	/* ignored - there is no difference in our treatment of these modes */
	return 0;
}

static int
fal_lag_mode_set_activebackup(struct ifnet *ifp __unused)
{
	/* ignored - there is no difference in our treatment of these modes */
	return 0;
}

static int
fal_lag_select(struct ifnet *ifp, bool enable)
{
	struct dpdk_eth_if_softc *member_sc;
	struct fal_attribute_t attr_list[] = {
		{
			.id = FAL_LAG_MEMBER_ATTR_EGRESS_DISABLE,
			.value.booldata = !enable,
		},
		{
			.id = FAL_LAG_MEMBER_ATTR_INGRESS_DISABLE,
			.value.booldata = !enable,
		},
	};
	unsigned int i;
	int ret;

	if (ifp->if_type != IFT_ETHER || !ifp->aggregator)
		return -1;

	DP_DEBUG(LAG, DEBUG, DATAPLANE,
		"teamd runner %sselected ifindex %d:%s (port %u)\n",
		enable ? "" : "de", ifp->if_index, ifp->if_name, ifp->if_port);

	if (fal_lag_member_enabled[ifp->if_port] == enable)
		return 0;

	fal_lag_member_enabled[ifp->if_port] = enable;

	member_sc = ifp->if_softc;

	/* not yet created so nothing to do */
	if (!member_sc->scd_fal_lag_member_created)
		return 0;

	for (i = 0; i < ARRAY_SIZE(attr_list); i++) {
		ret = fal_set_lag_member_attr(
			member_sc->scd_fal_lag_member_obj, &attr_list[i]);
		if (ret < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"failed to set FAL member interface %s to %s: %s\n",
				ifp->if_name, enable ? "enabled" : "disabled",
				strerror(-ret));
			return -1;
		}
	}

	return 0;
}

static int
fal_lag_set_activeport(struct ifnet *ifp __unused,
		       struct ifnet *ifp_member __unused)
{
	/*
	 * ignored - we use the selected indication instead for all of
	 * active/backup, balanced and LACP config modes.
	 */
	return 0;
}

static void
fal_lag_delete(struct ifnet *team_ifp)
{
	struct dpdk_eth_if_softc *member_sc, *tmp;
	struct dpdk_eth_if_softc *sc;
	fal_object_t fal_lag_obj;
	char ifname[IFNAMSIZ];
	portid_t dpdk_port;
	int ret;

	dpdk_port = team_ifp->if_port;
	sc = team_ifp->if_softc;

	/* Delete all the members first */
	cds_list_for_each_entry_safe(member_sc, tmp,
				     &sc->scd_fal_lag_members_head,
				     scd_fal_lag_member_link) {
		RTE_LOG(INFO, DATAPLANE,
			"Removing member %s from LAG %s as part of LAG delete\n",
			member_sc->scd_ifp->if_name, team_ifp->if_name);
		ret = fal_lag_member_delete(team_ifp,
					   member_sc->scd_ifp);
		if (ret < 0)
			return;
	}

	/* cache fields before delete */
	fal_lag_obj = sc->scd_fal_port_lag_obj;
	snprintf(ifname, sizeof(ifname), "%s", team_ifp->if_name);

	remove_port(dpdk_port);
	if_free(team_ifp);

	ret = fal_delete_lag(fal_lag_obj);
	if (ret < 0)
		RTE_LOG(ERR, DATAPLANE,
			"unable to delete FAL LAG interface for %s: %s\n",
			ifname, strerror(-ret));
}

static bool
fal_lag_can_start(const struct ifnet *ifp __unused)
{
	return true;
}

static int
fal_lag_member_apply(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *member_sc;
	struct dpdk_eth_if_softc *sc;
	struct fal_attribute_t attr_list[] = {
		{
			.id = FAL_LAG_MEMBER_ATTR_IFINDEX,
			.value.u32 = ifp->if_index,
		},
		{
			.id = FAL_LAG_MEMBER_ATTR_LAG_ID,
			.value.objid = 0,
		},
		{
			.id = FAL_LAG_MEMBER_ATTR_EGRESS_DISABLE,
			.value.booldata = fal_lag_member_enabled[ifp->if_port],
		},
		{
			.id = FAL_LAG_MEMBER_ATTR_INGRESS_DISABLE,
			.value.booldata = fal_lag_member_enabled[ifp->if_port],
		},
	};
	int ret;

	sc = ifp->aggregator->if_softc;
	member_sc = ifp->if_softc;

	if (member_sc->scd_fal_lag_member_created)
		return 0;

	attr_list[1].value.objid = sc->scd_fal_port_lag_obj;

	ret = fal_create_lag_member(ARRAY_SIZE(attr_list), attr_list,
				    &member_sc->scd_fal_lag_member_obj);
	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to add FAL member interface %s to FAL LAG interface %s: %s\n",
			ifp->if_name, ifp->aggregator->if_name,
			strerror(-ret));
		return ret;
	}
	member_sc->scd_fal_lag_member_created = true;
	cds_list_add_tail_rcu(&member_sc->scd_fal_lag_member_link,
			      &sc->scd_fal_lag_members_head);

	return 0;
}

static int
fal_lag_member_add(struct ifnet *team_ifp, struct ifnet *ifp)
{
	int ret;

	if (ifp->if_type != IFT_ETHER)
		return -EINVAL;

	if (ifp->aggregator) {
		/* teamd can give us redundant updates, so this is expected */
		DP_DEBUG(LAG, DEBUG, DATAPLANE,
			"%s already a member of %s\n", ifp->if_name,
			ifp->aggregator->if_name);
		return -EEXIST;
	}

	rcu_assign_pointer(ifp->aggregator, team_ifp);
	if_notify_emb_feat_change(ifp);

	if (fal_lag_can_create_in_fal(ifp)) {
		ret = fal_lag_member_apply(ifp);
		if (ret < 0) {
			rcu_assign_pointer(ifp->aggregator, NULL);
			if_notify_emb_feat_change(ifp);

			return ret;
		}
	}

	return 0;
}

static int
fal_lag_member_unapply(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *member_sc;
	int ret;

	member_sc = ifp->if_softc;

	if (!member_sc->scd_fal_lag_member_created)
		return 0;

	ret = fal_delete_lag_member(member_sc->scd_fal_lag_member_obj);
	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to delete FAL member interface %s to FAL LAG interface %s: %s\n",
			ifp->if_name, ifp->aggregator->if_name,
			strerror(-ret));
		return ret;
	}

	member_sc->scd_fal_lag_member_created = false;
	cds_list_del_rcu(&member_sc->scd_fal_lag_member_link);

	return 0;
}

static int
fal_lag_member_delete(struct ifnet *team_ifp __unused, struct ifnet *ifp)
{
	int ret;

	if (ifp->if_type != IFT_ETHER)
		return -EINVAL;

	if (!ifp->aggregator)
		return -ENOENT;

	ret = fal_lag_member_unapply(ifp);
	if (ret < 0)
		return ret;

	rcu_assign_pointer(ifp->aggregator, NULL);
	if_notify_emb_feat_change(ifp);

	return ret;
}

/* Add interface to an aggregation or update an existing member interface */
static int
fal_lag_nl_member_update(const struct ifinfomsg *ifi __unused,
			struct ifnet *ifp __unused,
			struct ifnet *bond __unused)
{
	/*
	 * Not required, since MAC address syncing from bonding
	 * interface to member interfaces not done and link flap
	 * doesn't impact member enabled/disabled state.
	 */
	return 0;
}

static void
fal_lag_refresh_actor_state(struct ifnet *bond __unused)
{
	/*
	 * Not required, since starting/stopping member doesn't impact
	 * member enabled/disabled state.
	 */
}

static void fal_lag_show_detail(struct ifnet *node, json_writer_t *wr)
{
	struct dpdk_eth_if_softc *sc;

	if (node->if_type != IFT_ETHER)
		return;

	sc = node->if_softc;

	jsonw_start_object(wr);
	jsonw_string_field(wr, "ifname", node->if_name);
	jsonw_uint_field(wr, "teamdev", node->if_index);

	jsonw_name(wr, "platform_state");
	jsonw_start_object(wr);
	fal_dump_lag(sc->scd_fal_port_lag_obj, wr);
	jsonw_end_object(wr);

	jsonw_end_object(wr);
}

static int
fal_lag_walk_team_members(struct ifnet *ifp __unused,
			 dp_ifnet_iter_func_t iter_func __unused,
			 void *arg __unused)
{
	/* not required */
	return 0;
}

static bool
fal_lag_is_team(struct ifnet *ifp)
{
	struct swport_dev_info swport_dev_info;
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(ifp->if_port, &dev_info);

	if (strcmp(dev_info.driver_name, "net_sw_port"))
		return false;

	if (sw_port_get_dev_info(ifp->if_port, &swport_dev_info) < 0)
		return false;

	return swport_dev_info.is_lag;
}

static bool
fal_lag_can_startstop_member(struct ifnet *ifp __unused)
{
	/*
	 * members can be started/stopped independently of bonding
	 * interface.
	 */
	return true;
}

static int
fal_lag_set_l2_address(struct ifnet *ifp, struct rte_ether_addr *macaddr)
{
	return rte_eth_dev_default_mac_addr_set(
		ifp->if_port, macaddr);
}

const struct lag_ops fal_lag_ops = {
	.lagop_etype_slow_tx = fal_lag_etype_slow_tx,
	.lagop_member_sync_mac_address = fal_lag_member_sync_mac_address,
	.lagop_create = fal_lag_create,
	.lagop_mode_set_balance = fal_lag_mode_set_balance,
	.lagop_mode_set_activebackup = fal_lag_mode_set_activebackup,
	.lagop_select = fal_lag_select,
	.lagop_set_activeport = fal_lag_set_activeport,
	.lagop_delete = fal_lag_delete,
	.lagop_can_start = fal_lag_can_start,
	.lagop_member_add = fal_lag_member_add,
	.lagop_member_delete = fal_lag_member_delete,
	.lagop_nl_member_update = fal_lag_nl_member_update,
	.lagop_refresh_actor_state = fal_lag_refresh_actor_state,
	.lagop_show_detail = fal_lag_show_detail,
	.lagop_walk_team_members = fal_lag_walk_team_members,
	.lagop_is_team = fal_lag_is_team,
	.lagop_can_startstop_member = fal_lag_can_startstop_member,
	.lagop_set_l2_address = fal_lag_set_l2_address,
};

static void
fal_lag_if_feat_mode_change(struct ifnet *ifp,
			    enum if_feat_mode_event event)
{
	if (!ifp->aggregator || !fal_lag_is_team(ifp->aggregator))
		/* nothing to do */
		return;

	switch (event) {
	case IF_FEAT_MODE_EVENT_L2_FAL_ENABLED:
		if (fal_lag_can_create_in_fal(ifp))
			fal_lag_member_apply(ifp);
		break;
	case IF_FEAT_MODE_EVENT_L2_FAL_DISABLED:
		fal_lag_member_unapply(ifp);
		break;
	case IF_FEAT_MODE_EVENT_EMB_FEAT_CHANGED:
		if (fal_lag_can_create_in_fal(ifp))
			fal_lag_member_apply(ifp);
		else
			fal_lag_member_unapply(ifp);
		break;
	default:
		break;
	}
}

static const struct dp_event_ops fal_lag_events = {
	.if_feat_mode_change = fal_lag_if_feat_mode_change,
};

DP_STARTUP_EVENT_REGISTER(fal_lag_events);
