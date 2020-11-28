/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <rte_branch_prediction.h>
#include <rte_eth_bond.h>
#include <rte_eth_bond_8023ad.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <urcu/uatomic.h>
#include <rte_eth_bond_8023ad.h>

#include "compiler.h"
#include "capture.h"
#include "compat.h"
#include "dpdk_eth_if.h"
#include "ether.h"
#include "if_var.h"
#include "json_writer.h"
#include "lag.h"
#include "main.h"
#include "controller.h"
#include "netlink.h"
#include "pktmbuf_internal.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

#define BOND_DEV_NAME "net_bonding"

struct nlattr;

/* remember which members are collecting/distributing */
static uint8_t enabled[LAG_MAX_MEMBERS];

static int dpdk_lag_member_delete(struct ifnet *team, struct ifnet *ifp);

static void lacp_recv_cb(portid_t member_id, struct rte_mbuf *lacp_pkt)
{
	struct ifnet *ifp = ifnet_byport(member_id);

	if (unlikely(ifp == NULL)) {
		rte_pktmbuf_free(lacp_pkt);
		return;
	}

	pktmbuf_mdata_clear_all(lacp_pkt);

	/* local packet capture */
	if (ifp->capturing)
		capture_burst(ifp, &lacp_pkt, 1);

	local_packet(ifp, lacp_pkt);
}

/*
 * outgoing ether type slow traffic has special handling:
 * - capture via dataplane member
 * - send via rte_pmd_bond team interface
 */
static int
dpdk_lag_etype_slow_tx(struct ifnet *team, struct ifnet *ifp,
		       struct rte_mbuf *lacp_pkt)
{
	if (ifp->capturing)
		capture_burst(ifp, &lacp_pkt, 1);

	return rte_eth_bond_8023ad_ext_slowtx(team->if_port, ifp->if_port,
					lacp_pkt);
}

/*
 * The rte_pmd_bond might change MAC address of a member port on certain events.
 * This helper tries to update the MAC address of the DPDK device from the
 * dataplane ifnet structure.
 */
static void
dpdk_lag_member_sync_mac_address(struct ifnet *ifp)
{
	struct rte_ether_addr hwaddr;
	char buf1[32], buf2[32];

	rte_eth_macaddr_get(ifp->if_port, &hwaddr);
	if (rte_ether_addr_equal(&ifp->eth_addr, &hwaddr))
		return;

	DP_DEBUG(LAG, DEBUG, DATAPLANE, "%s updating MAC from %s to %s\n",
		ifp->if_name, ether_ntoa_r(&hwaddr, buf2),
		ether_ntoa_r(&ifp->eth_addr, buf1));

	int rc = rte_eth_dev_default_mac_addr_set(ifp->if_port, &ifp->eth_addr);
	if (rc) {
		/*
		 * If updating the member's address fails lets update the
		 * dataplane's address to be in sync!
		 */
		DP_DEBUG(LAG, ERR, DATAPLANE, "%s can't set address %s: %s\n",
			ifp->if_name, ether_ntoa_r(&ifp->eth_addr, buf1),
			strerror(-rc));
		ifp->eth_addr = hwaddr;
	}
}

static struct ifnet *
dpdk_lag_create(const struct ifinfomsg *ifi, struct nlattr *tb[])
{
	int port_id;
	const char *ifname;
	struct rte_ether_addr *macaddr = NULL;
	struct ifnet *ifp;
	char bond_name[RTE_ETH_NAME_MAX_LEN];
	int len;

	if (tb[IFLA_ADDRESS]) {
		size_t addrlen = mnl_attr_get_payload_len(tb[IFLA_ADDRESS]);

		if (addrlen != RTE_ETHER_ADDR_LEN)
			return NULL;
		macaddr = mnl_attr_get_payload(tb[IFLA_ADDRESS]);
	}
	if (macaddr == NULL)
		return NULL;

	if (tb[IFLA_IFNAME])
		ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);
	else
		return NULL;

	/* bond device name must start with "net_bonding" */
	len = snprintf(bond_name, sizeof(bond_name), "%s%s",
		       BOND_DEV_NAME, ifname);
	if (len < 0 || len >= (int)sizeof(bond_name))
		return NULL;

	port_id = rte_eth_bond_create(bond_name,
				      BONDING_MODE_ACTIVE_BACKUP,
				      rte_socket_id());
	if (port_id < 0)
		return NULL;

	rte_eth_bond_mac_address_set(port_id, macaddr);

	if (insert_port(port_id) != 0)
		return NULL;

	ifp = dpdk_eth_if_alloc_w_port(ifname, ifi->ifi_index, port_id);
	if (!ifp) {
		remove_port(port_id);
		return NULL;
	}

	ifp->eth_addr = *macaddr;

	return ifp;
}

static int member_add(struct ifnet *team, struct ifnet *ifp)
{
	int rv;
	struct rte_eth_dev_info member_info, team_info;
	struct rte_eth_dev *bond_dev;
	int bond_dev_started;

	if (ifp->aggregator) {
		/* teamd can give us redundant updates, so this is expected */
		DP_DEBUG(LAG, DEBUG, DATAPLANE,
			"%s already member of %s\n", ifp->if_name,
			ifp->aggregator->if_name);
		return -EEXIST;
	}

	rte_eth_dev_info_get(team->if_port, &team_info);
	rte_eth_dev_info_get(ifp->if_port, &member_info);

	bond_dev = &rte_eth_devices[team->if_port];
	bond_dev_started = bond_dev->data->dev_started;

	/* Ignore VMDQ information since we know that the BOND pmd
	 * will never have support for VMDQ and thus provides a
	 * reasonable upper bound.
	 */

	if (member_info.max_rx_queues < team_info.nb_rx_queues ||
	    member_info.max_tx_queues < team_info.nb_tx_queues) {
		int nb_rx_queues =
			MIN(member_info.max_rx_queues, team_info.nb_rx_queues);
		int nb_tx_queues =
			MIN(member_info.max_tx_queues, team_info.nb_tx_queues);

		if (bond_dev_started)
			dpdk_eth_if_stop_port(team);
		rv = reconfigure_queues(team->if_port,
					nb_rx_queues, nb_tx_queues);
		if (rv)
			return rv;
		if (bond_dev_started)
			dpdk_eth_if_start_port(team);
	}

	/*
	 * Queues are assigned again by start_port() call in
	 * member_remove()
	 */
	if_disable_poll_rcu(ifp->if_port);
	if (ifp->if_flags & IFF_UP)
		unassign_queues(ifp->if_port);

	/*
	 * Start the bonding device if not already started
	 * when adding a member. The member is configured only
	 * when the bonding device is started.
	 */
	if (!bond_dev_started)
		dpdk_eth_if_start_port(team);
	rv = rte_eth_bond_slave_add(team->if_port, ifp->if_port);
	if (rv < 0) {
		if (!bond_dev_started)
			dpdk_eth_if_stop_port(team);
		if (ifp->if_flags & IFF_UP)
			assign_queues(ifp->if_port);
		if_enable_poll(ifp->if_port);
		return rv;
	}
	if (!bond_dev_started)
		dpdk_eth_if_stop_port(team);
	/*
	 * internals is accessed in the forwarding threads. We stop them
	 * while we update this, but since there isn't a lock, there isn't a
	 * barrier to ensure that these updates are visible on the other
	 * lcores before we resume them.
	 */
	rte_smp_mb();

	rcu_assign_pointer(ifp->aggregator, team);

	return 0;
}

/*
 * Assumes that polling is turned off on the team interface, so that
 * there's no race with an in-progress rx.
 */
static int member_remove(struct ifnet *team, struct ifnet *ifp)
{
	int rv;

	if (!ifp->aggregator)
		return -ENOENT;

	rv = rte_eth_bond_slave_remove(team->if_port, ifp->if_port);
	if (rv < 0)
		return rv;
	/*
	 * internals is accessed in the forwarding threads. We stop them
	 * while we update this, but since there isn't a lock, there isn't a
	 * barrier to ensure that these updates are visible on the other
	 * lcores before we resume them.
	 */
	rte_smp_mb();

	/* clear RCU protected aggregator pointer */
	ifp->aggregator = NULL;

	/*
	 * Force the port to be stopped since it will have been
	 * started by bond if not already and there's no guarantee
	 * that our state is consistent with the DPDK state now.
	 */
	dpdk_eth_if_force_stop_port(ifp);

	/* enable any queues released by the bonding driver */
	rv = eth_port_config(ifp->if_port);
	if (rv < 0)
		return rv;

	if (ifp->if_flags & IFF_UP)
		dpdk_eth_if_start_port(ifp);
	if_enable_poll(ifp->if_port);

	return rv;
}

static int dpdk_lag_mode_set_balance(struct ifnet *ifp)
{
	struct rte_eth_bond_8023ad_conf conf;
	int rv;
	int mode = rte_eth_bond_mode_get(ifp->if_port);

	if (mode == BONDING_MODE_8023AD)
		return 0;

	/* get default configuration */
	rv = rte_eth_bond_8023ad_setup(ifp->if_port, NULL);
	if (rv < 0)
		return rv;

	rv = rte_eth_bond_8023ad_conf_get(ifp->if_port, &conf);
	if (rv < 0)
		return rv;

	conf.slowrx_cb = lacp_recv_cb;

	rv = rte_eth_bond_8023ad_setup(ifp->if_port, &conf);
	if (rv < 0)
		return rv;

	struct rte_eth_dev *dev = &rte_eth_devices[ifp->if_port];
	uint8_t dev_started = dev->data->dev_started;

	if (dev_started)
		rte_eth_dev_stop(ifp->if_port);

	rv = rte_eth_bond_mode_set(ifp->if_port, BONDING_MODE_8023AD);
	if (rv < 0)
		return rv;

	if (dev_started)
		rte_eth_dev_start(ifp->if_port);


	rte_eth_bond_xmit_policy_set(ifp->if_port, BALANCE_XMIT_POLICY_LAYER34);

	return 0;
}

static int dpdk_lag_mode_set_activebackup(struct ifnet *ifp)
{
	struct rte_eth_dev *dev = &rte_eth_devices[ifp->if_port];
	uint8_t dev_started = dev->data->dev_started;
	int rv;

	if (dev_started)
		rte_eth_dev_stop(ifp->if_port);

	rv = rte_eth_bond_mode_set(ifp->if_port, BONDING_MODE_ACTIVE_BACKUP);
	if (rv < 0)
		return rv;

	if (dev_started)
		rte_eth_dev_start(ifp->if_port);

	return rv;
}

static int dpdk_lag_select(struct ifnet *ifp, bool sel)
{
	if (ifp->aggregator == NULL)
		return -1;

	DP_DEBUG(LAG, DEBUG, DATAPLANE,
		"teamd runner %sselected ifindex %d:%s (port %u)\n",
		sel ? "" : "de", ifp->if_index, ifp->if_name, ifp->if_port);

	int mode = rte_eth_bond_mode_get(ifp->aggregator->if_port);

	enabled[ifp->if_port] = sel;

	if (mode == BONDING_MODE_ACTIVE_BACKUP)
		return 0;

	if (rte_eth_bond_8023ad_ext_collect(ifp->aggregator->if_port,
					    ifp->if_port,
					    enabled[ifp->if_port])) {
		DP_DEBUG(LAG, ERR, DATAPLANE, "cannot set collecting flag\n");
		return -1;
	}

	if (rte_eth_bond_8023ad_ext_distrib(ifp->aggregator->if_port,
					    ifp->if_port,
					    enabled[ifp->if_port])) {
		DP_DEBUG(LAG, ERR, DATAPLANE, "cannot set distributing flag\n");
		return -1;
	}

	return 0;
}

static int
dpdk_lag_set_activeport(struct ifnet *ifp, struct ifnet *ifp_member)
{
	DP_DEBUG(LAG, DEBUG, DATAPLANE,
		 "teamd runner %s activeport ifindex %d:%s (port %u)\n",
		 ifp->if_name, ifp_member->if_index, ifp_member->if_name,
		 ifp_member->if_port);

	int mode = rte_eth_bond_mode_get(ifp->if_port);

	if (mode == BONDING_MODE_ACTIVE_BACKUP)
		rte_eth_bond_primary_set(ifp->if_port, ifp_member->if_port);

	return 0;
}

/* Remove an aggregation.  team%d interface went away. */
static void dpdk_lag_delete(struct ifnet *team_ifp)
{
	portid_t port_id = team_ifp->if_port;
	struct rte_eth_dev_info dev_info;
	portid_t members[LAG_MAX_MEMBERS];
	int num_members;
	int i;

	num_members = rte_eth_bond_slaves_get(port_id,
					      members,
					      LAG_MAX_MEMBERS);
	if (num_members < 0)
		RTE_LOG(ERR, DATAPLANE,
			"Unable to get member count for %s\n",
			team_ifp->if_name);

	if (num_members > 0) {
		for (i = 0; i < num_members; i++) {
			int ret;
			struct ifnet *sl = ifnet_byport(members[i]);

			RTE_LOG(INFO, DATAPLANE,
				"LAG %s still has %d members, removing them\n",
				team_ifp->if_name, num_members);

			ret = dpdk_lag_member_delete(team_ifp, sl);
			if (ret < 0) {
				RTE_LOG(ERR, DATAPLANE,
					"Failed to remove %s from LAG %s\n",
					sl->if_name, team_ifp->if_name);
				return;
			}
		}
	}
	if_free(team_ifp);
	remove_port(port_id);

	rte_eth_dev_info_get(port_id, &dev_info);
	rte_eth_dev_close(port_id);
	if (rte_dev_remove(dev_info.device) != 0)
		RTE_LOG(ERR, DATAPLANE,
			"dpdk_lag_delete(%u): remove failed\n", port_id);
}

/*
 * Returns the number of members associated with this bonding interface.
 *
 * If not a bonding interface, return -1.
 */
static int member_count(const struct ifnet *ifp)
{
	portid_t members[LAG_MAX_MEMBERS];

	return rte_eth_bond_slaves_get(ifp->if_port, members,
				       LAG_MAX_MEMBERS);
}

static bool dpdk_lag_can_start(const struct ifnet *ifp)
{
	return member_count(ifp) != 0;
}

static int dpdk_lag_member_add(struct ifnet *team, struct ifnet *ifp)
{
	int count, rv;

	count = member_count(team);
	if (count < 0)
		return -EINVAL;

	/* access to bonding "internals" structure is not thread-safe */
	if_disable_poll_rcu(team->if_port);

	rv = member_add(team, ifp);
	if (rv < 0)
		goto out;

	/* We just added the first port, so we might need to finally
	 * start_port() if this interface is currently IFF_UP.
	 */
	if (count == 0 && team->if_flags & IFF_UP)
		dpdk_eth_if_start_port(team);

out:
	if_enable_poll(team->if_port);
	return rv;
}

static int dpdk_lag_member_delete(struct ifnet *team, struct ifnet *ifp)
{
	portid_t members[LAG_MAX_MEMBERS];
	int count, rv;

	count = rte_eth_bond_slaves_get(team->if_port, members,
					LAG_MAX_MEMBERS);
	if (count < 0)
		return -EINVAL;

	/* access to bonding "internals" structure is not thread-safe */
	if_disable_poll_rcu(team->if_port);

	rv = member_remove(team, ifp);
	if (rv < 0)
		goto out;

	/* we just remove the last port, so lets stop polling */
	if (count == 1) {
		dpdk_eth_if_stop_port(team);
		return rv;
	}

out:
	if_enable_poll(team->if_port);
	return rv;
}

/* Add interface to an aggregation or update an existing member interface */
static int
dpdk_lag_nl_member_update(const struct ifinfomsg *ifi, struct ifnet *ifp,
			 struct ifnet *team)
{
	if (ifp == NULL)
		return -1;

	if ((!ifp->aggregator && team) || (ifp->aggregator && !team)) {
		/* team was either set or cleared */
		dpdk_lag_member_sync_mac_address(ifp);
	} else {
		/* if link up, restore collect/dist flags */
		if (ifi->ifi_flags & IFF_RUNNING) {
			dpdk_lag_select(ifp, enabled[ifp->if_port]);
			dpdk_lag_member_sync_mac_address(ifp);
		}
	}

	return 0;
}

static void dpdk_lag_refresh_actor_state(struct ifnet *team)
{
	portid_t members[LAG_MAX_MEMBERS];
	int count, i;

	count = rte_eth_bond_slaves_get(team->if_port, members,
					LAG_MAX_MEMBERS);

	for (i = 0; i < count; i++)
		dpdk_lag_select(ifport_table[members[i]], enabled[members[i]]);
}

static const char * const bonding_modes[] = {
	[BONDING_MODE_ROUND_ROBIN]	= "Round Robin",
	[BONDING_MODE_ACTIVE_BACKUP]	= "Active-Backup",
	[BONDING_MODE_BALANCE]		= "Balanced",
	[BONDING_MODE_BROADCAST]	= "Broadcast",
	[BONDING_MODE_8023AD]		= "802.3AD",
	[BONDING_MODE_TLB]		= "Adaptive Transmit",
	[BONDING_MODE_ALB]		= "Adaptive Load Balance",
};

static const char * const policy_names[] = {
	[BALANCE_XMIT_POLICY_LAYER2]	= "BALANCE_XMIT_POLICY_LAYER2",
	[BALANCE_XMIT_POLICY_LAYER23]	= "BALANCE_XMIT_POLICY_LAYER23",
	[BALANCE_XMIT_POLICY_LAYER34]	= "BALANCE_XMIT_POLICY_LAYER34"
};


static bool lag_member_is_active(portid_t active[], int len, uint16_t portid)
{
	int i;

	for (i = 0; i < len; i++)
		if (active[i] == portid)
			return true;
	return false;
}

static void dpdk_lag_show_detail(struct ifnet *node, json_writer_t *wr)
{
	int num_members;
	int num_active;
	int i;
	int primary = rte_eth_bond_primary_get(node->if_port);
	int mode = rte_eth_bond_mode_get(node->if_port);
	int policy = rte_eth_bond_xmit_policy_get(node->if_port);
	const char *policy_str = "n/a";
	portid_t members[LAG_MAX_MEMBERS];
	portid_t active[LAG_MAX_MEMBERS];

	jsonw_start_object(wr);
	jsonw_string_field(wr, "ifname", node->if_name);
	jsonw_uint_field(wr, "teamdev",
			 node->if_team ? node->if_index : 0);
	jsonw_bool_field(wr, "lacp", !!(mode == BONDING_MODE_8023AD));
	jsonw_string_field(wr, "mode",
			mode >= 0 ? bonding_modes[mode] : "Unknown");

	if (mode == BONDING_MODE_8023AD && policy >= 0 &&
		policy < (int)ARRAY_SIZE(policy_names))
		policy_str = policy_names[policy];
	jsonw_string_field(wr, "hash", policy_str);

	num_active = rte_eth_bond_active_slaves_get(node->if_port,
						active,
						LAG_MAX_MEMBERS);
	num_members = rte_eth_bond_slaves_get(node->if_port, members,
					LAG_MAX_MEMBERS);
	jsonw_name(wr, "members");
	jsonw_start_array(wr);
	for (i = 0; i < num_members; i++) {
		struct ifnet *sl = ifnet_byport(members[i]);
		struct rte_eth_bond_8023ad_slave_info info;
		int rc;

		if (!sl)
			continue;

		bool is_primary = primary == sl->if_port;
		bool is_active = lag_member_is_active(active, num_active,
						sl->if_port);
		jsonw_start_object(wr);
		jsonw_string_field(wr, "ifname", sl->if_name);
		jsonw_bool_field(wr, "primary", is_primary);
		jsonw_bool_field(wr, "active", is_active);
		if (mode == BONDING_MODE_8023AD) {
			rc = rte_eth_bond_8023ad_slave_info(node->if_port,
							    sl->if_port, &info);
			if (rc == 0) {
				jsonw_name(wr, "802-3ad");
				jsonw_start_array(wr);
				jsonw_start_object(wr);
				jsonw_int_field(wr, "selected",
						    info.selected);
				jsonw_int_field(wr, "actor-state",
						    info.actor_state);
				jsonw_int_field(wr, "partner-state",
						    info.partner_state);
				jsonw_int_field(wr, "agg-port-id",
						    info.agg_port_id);
				jsonw_end_object(wr);
				jsonw_end_array(wr);
			}
		}

		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
}

static int
dpdk_lag_walk_team_members(struct ifnet *ifp, dp_ifnet_iter_func_t iter_func,
			  void *arg)
{
	int num_members;
	portid_t members[LAG_MAX_MEMBERS];
	int i;

	if (!ifp->if_team || !iter_func)
		return -EINVAL;

	num_members = rte_eth_bond_slaves_get(ifp->if_port, members,
					     LAG_MAX_MEMBERS);
	if (num_members < 0)
		return -EINVAL;

	for (i = 0; i < num_members; i++) {
		struct ifnet *sl = ifnet_byport(members[i]);

		if (sl)
			(iter_func)(sl, arg);
	}

	return 0;
}

static bool
dpdk_lag_is_team(struct ifnet *ifp)
{
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(ifp->if_port, &dev_info);

	DP_DEBUG(INIT, DEBUG, DATAPLANE,
		"%d:%s dev_info.driver_name %s\n",
		ifp->if_index, ifp->if_name, dev_info.driver_name);

	return strstr(dev_info.driver_name, BOND_DEV_NAME) != NULL;
}

static bool
dpdk_lag_can_startstop_member(struct ifnet *ifp)
{
	return !ifp->aggregator;
}

static int
dpdk_lag_set_l2_address(struct ifnet *ifp, struct rte_ether_addr *macaddr)
{
	return rte_eth_bond_mac_address_set(
		ifp->if_port, macaddr);
}

const struct lag_ops dpdk_lag_ops = {
	.lagop_etype_slow_tx = dpdk_lag_etype_slow_tx,
	.lagop_member_sync_mac_address = dpdk_lag_member_sync_mac_address,
	.lagop_create = dpdk_lag_create,
	.lagop_mode_set_balance = dpdk_lag_mode_set_balance,
	.lagop_mode_set_activebackup = dpdk_lag_mode_set_activebackup,
	.lagop_select = dpdk_lag_select,
	.lagop_set_activeport = dpdk_lag_set_activeport,
	.lagop_delete = dpdk_lag_delete,
	.lagop_can_start = dpdk_lag_can_start,
	.lagop_member_add = dpdk_lag_member_add,
	.lagop_member_delete = dpdk_lag_member_delete,
	.lagop_nl_member_update = dpdk_lag_nl_member_update,
	.lagop_refresh_actor_state = dpdk_lag_refresh_actor_state,
	.lagop_show_detail = dpdk_lag_show_detail,
	.lagop_walk_team_members = dpdk_lag_walk_team_members,
	.lagop_is_team = dpdk_lag_is_team,
	.lagop_can_startstop_member = dpdk_lag_can_startstop_member,
	.lagop_set_l2_address = dpdk_lag_set_l2_address,
};
