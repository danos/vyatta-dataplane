/*-
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
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
#include "ether.h"
#include "if_var.h"
#include "json_writer.h"
#include "lag.h"
#include "main.h"
#include "master.h"
#include "netlink.h"
#include "pktmbuf.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

struct nlattr;

/* remember which slaves are collecting/distributing */
static uint8_t enabled[LAG_MAX_SLAVES];

struct ifnet *ifnet_byteam(int ifindex)
{
	struct ifnet *ifp = ifnet_byifindex(ifindex);

	if (ifp && ifp->if_team)
		return ifp;
	return NULL;
}

static void lacp_recv_cb(portid_t slave_id, struct rte_mbuf *lacp_pkt)
{
	struct ifnet *ifp = ifnet_byport(slave_id);

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
 * - capture via dataplane slave
 * - send via rte_pmd_bond master
 */
int lag_etype_slow_tx(struct ifnet *master, struct ifnet *ifp,
		struct rte_mbuf *lacp_pkt)
{
	if (ifp->capturing)
		capture_burst(ifp, &lacp_pkt, 1);

	return rte_eth_bond_8023ad_ext_slowtx(master->if_port, ifp->if_port,
					lacp_pkt);
}

/*
 * The rte_pmd_bond might change MAC address of a slave port on certain events.
 * This helper tries to update the MAC address of the DPDK device from the
 * dataplane ifnet structure.
 */
void lag_slave_sync_mac_address(struct ifnet *ifp)
{
	struct ether_addr hwaddr;
	char buf1[32], buf2[32];

	rte_eth_macaddr_get(ifp->if_port, &hwaddr);
	if (ether_addr_equal(&ifp->eth_addr, &hwaddr))
		return;

	DP_DEBUG(LAG, DEBUG, DATAPLANE, "%s updating MAC from %s to %s\n",
		ifp->if_name, ether_ntoa_r(&hwaddr, buf2),
		ether_ntoa_r(&ifp->eth_addr, buf1));

	int rc = rte_eth_dev_default_mac_addr_set(ifp->if_port, &ifp->eth_addr);
	if (rc) {
		/*
		 * If updating the slave's address fails lets update the
		 * dataplane's address to be in sync!
		 */
		DP_DEBUG(LAG, ERR, DATAPLANE, "%s can't set address %s: %s\n",
			ifp->if_name, ether_ntoa_r(&ifp->eth_addr, buf1),
			strerror(-rc));
		ifp->eth_addr = hwaddr;
	}
}

struct ifnet *lag_create(const struct ifinfomsg *ifi, struct nlattr *tb[])
{
	int port_id;
	const char *ifname;
	struct ether_addr *macaddr = NULL;
	uint8_t i;
	struct ifnet *ifp;
	char bond_name[RTE_ETH_NAME_MAX_LEN];
	int len;

	if (tb[IFLA_ADDRESS]) {
		size_t addrlen = mnl_attr_get_payload_len(tb[IFLA_ADDRESS]);

		if (addrlen != ETHER_ADDR_LEN)
			return NULL;
		macaddr = mnl_attr_get_payload(tb[IFLA_ADDRESS]);
	}
	if (macaddr == NULL)
		return NULL;

	if (tb[IFLA_IFNAME])
		ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);
	else
		return NULL;

	struct rte_eth_dev *eth_dev = NULL;

	/* bond device name must start with "net_bonding" */
	len = snprintf(bond_name, sizeof(bond_name), "%s%s",
		       BOND_DEV_NAME, ifname);
	if (len < 0 || len >= (int)sizeof(bond_name))
		return NULL;

	for (i = 0; i < DATAPLANE_MAX_PORTS; i++) {
		if (!rte_eth_dev_is_valid_port(i))
			continue;
		if (strcmp(rte_eth_devices[i].data->name, bond_name) == 0) {
			eth_dev = &rte_eth_devices[i];
			break;
		}
	}

	if (eth_dev) {
		/* teamd was restarted.  Tell controller about new ifindex */
		port_id = eth_dev->data->port_id;
		setup_interface_portid(port_id);
	} else {
		port_id = rte_eth_bond_create(bond_name,
					      BONDING_MODE_ACTIVE_BACKUP,
					      rte_socket_id());
	}
	if (port_id < 0)
		return NULL;

	rte_eth_bond_mac_address_set(port_id, macaddr);

	if (!eth_dev) {
		if (insert_port(port_id) != 0)
			return NULL;
	}

	ifp = ifport_table[port_id];
	if (!ifp)
		return NULL;

	ifp->if_flags = ifi->ifi_flags;
	ifp->eth_addr = *macaddr;

	if_set_ifindex(ifp, ifi->ifi_index);
	ifp->if_team = 1;
	return ifp;
}

static int slave_add(struct ifnet *master, struct ifnet *ifp)
{
	int rv;
	struct rte_eth_dev_info slave_info, master_info;

	if (ifp->aggregator) {
		DP_DEBUG(LAG, ERR, DATAPLANE,
			"%s already slave of %s\n", ifp->if_name,
			ifp->aggregator->if_name);
		return -EEXIST;
	}

	rte_eth_dev_info_get(master->if_port, &master_info);
	rte_eth_dev_info_get(ifp->if_port, &slave_info);

	/* Ignore VMDQ information since we know that the BOND pmd
	 * will never have support for VMDQ and thus provides a
	 * reasonable upper bound.
	 */

	if (slave_info.max_rx_queues < master_info.nb_rx_queues ||
	    slave_info.max_tx_queues < master_info.nb_tx_queues) {
		struct rte_eth_dev *master_dev =
					&rte_eth_devices[master->if_port];
		int master_dev_started = master_dev->data->dev_started;
		int nb_rx_queues =
			MIN(slave_info.max_rx_queues, master_info.nb_rx_queues);
		int nb_tx_queues =
			MIN(slave_info.max_tx_queues, master_info.nb_tx_queues);

		if (master_dev_started)
			stop_port(master->if_port);
		rv = reconfigure_queues(master->if_port,
					nb_rx_queues, nb_tx_queues);
		if (rv)
			return rv;
		if (master_dev_started)
			start_port(master->if_port, master->if_flags);
	}

	/*
	 * Queues are assigned again by start_port() call in
	 * slave_remove()
	 */
	if_disable_poll_rcu(ifp->if_port);
	if (ifp->if_flags & IFF_UP)
		unassign_queues(ifp->if_port);

	rv = rte_eth_bond_slave_add(master->if_port, ifp->if_port);
	if (rv < 0) {
		if (ifp->if_flags & IFF_UP)
			assign_queues(ifp->if_port);
		if_enable_poll(ifp->if_port);
		return rv;
	}
	/*
	 * internals is accessed in the forwarding threads. We stop them
	 * while we update this, but since there isn't a lock, there isn't a
	 * barrier to ensure that these updates are visible on the other
	 * lcores before we resume them.
	 */
	rte_smp_mb();

	rcu_assign_pointer(ifp->aggregator, master);

	return 0;
}

/*
 * Assumes that polling is turned off on master interface, so that
 * there's no race with an in-progress rx.
 */
static int slave_remove(struct ifnet *master, struct ifnet *ifp)
{
	int rv;

	if (!ifp->aggregator)
		return -ENOENT;

	rv = rte_eth_bond_slave_remove(master->if_port, ifp->if_port);
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
	force_stop_port(ifp->if_port);

	/* enable any queues released by the bonding driver */
	rv = eth_port_config(ifp->if_port);
	if (rv < 0)
		return rv;

	/*
	 * There's no guarantee what order the slave removal team
	 * message and link update rtnl messages will arrive in, so
	 * attempt to start the port here. If it still has the
	 * IFF_SLAVE flag set then it won't be started here and
	 * instead it'll be started when the link update rtnl message
	 * removing that flag subsequently arrives.
	 */
	if (ifp->if_flags & IFF_UP)
		start_port(ifp->if_port, ifp->if_flags);
	if_enable_poll(ifp->if_port);

	return rv;
}

int lag_mode_set_balance(struct ifnet *ifp)
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

int lag_mode_set_activebackup(struct ifnet *ifp)
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

int lag_select(struct ifnet *ifp, int sel)
{
	if (ifp->aggregator == NULL)
		return -1;

	DP_DEBUG(LAG, DEBUG, DATAPLANE,
		"teamd runner %sselected ifindex %d:%s (port %u)\n",
		sel ? "" : "de", ifp->if_index, ifp->if_name, ifp->if_port);

	int mode = rte_eth_bond_mode_get(ifp->aggregator->if_port);

	enabled[ifp->if_port] = !!sel;

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

int lag_activeport(struct ifnet *ifp, struct ifnet *ifp_slave)
{
	DP_DEBUG(LAG, DEBUG, DATAPLANE,
		 "teamd runner %s activeport ifindex %d:%s (port %u)\n",
		 ifp->if_name, ifp_slave->if_index, ifp_slave->if_name,
		 ifp_slave->if_port);

	int mode = rte_eth_bond_mode_get(ifp->if_port);

	if (mode == BONDING_MODE_ACTIVE_BACKUP)
		rte_eth_bond_primary_set(ifp->if_port, ifp_slave->if_port);

	return 0;
}

/* Remove an aggregation.  team%d interface went away. */
void lag_nl_master_delete(const struct ifinfomsg *ifi __unused,
			  struct ifnet *master_ifp)
{
	/* librte_pmd_bond doesn't allow removal of interfaces,
	 * so just delete evidence of team interface.
	 */
	teardown_interface_portid(master_ifp->if_port);
	if_unset_ifindex(master_ifp);
}

/*
 * Returns the number of slaves associated with this bonding interface.
 *
 * If not a bonding interface, return -1.
 */
int slave_count(const struct ifnet *ifp)
{
	portid_t slaves[LAG_MAX_SLAVES];

	if (!ifp->if_team)
		return -1;

	return rte_eth_bond_slaves_get(ifp->if_port, slaves,
				       LAG_MAX_SLAVES);
}

int lag_slave_add(struct ifnet *master, struct ifnet *ifp)
{
	int count, rv;

	count = slave_count(master);
	if (count < 0)
		return -EINVAL;

	/* access to bonding "internals" structure is not thread-safe */
	if_disable_poll_rcu(master->if_port);

	rv = slave_add(master, ifp);
	if (rv < 0)
		goto out;

	/* We just added the first port, so we might need to finally
	 * start_port() if this interface is currently IFF_UP.
	 */
	if (count == 0 && master->if_flags & IFF_UP)
		start_port(master->if_port, master->if_flags);

out:
	if_enable_poll(master->if_port);
	return rv;
}

int lag_slave_delete(struct ifnet *master, struct ifnet *ifp)
{
	portid_t slaves[LAG_MAX_SLAVES];
	int count, rv;

	count = rte_eth_bond_slaves_get(master->if_port, slaves,
					LAG_MAX_SLAVES);
	if (count < 0)
		return -EINVAL;

	/* access to bonding "internals" structure is not thread-safe */
	if_disable_poll_rcu(master->if_port);

	rv = slave_remove(master, ifp);
	if (rv < 0)
		goto out;

	/* we just remove the last port, so lets stop polling */
	if (count == 1) {
		stop_port(master->if_port);
		return rv;
	}

out:
	if_enable_poll(master->if_port);
	return rv;
}

bool lag_port_is_slave(struct ifnet *master, struct ifnet *ifp)
{
	portid_t slaves[LAG_MAX_SLAVES];
	int count, i;

	count = rte_eth_bond_slaves_get(master->if_port, slaves,
					LAG_MAX_SLAVES);

	for (i = 0; i < count; i++)
		if (slaves[i] == ifp->if_port)
			return true;
	return false;
}

/* Add interface to an aggregation or update an already enslaved interface */
int lag_nl_slave_update(const struct ifinfomsg *ifi, struct ifnet *ifp,
			struct ifnet *master)
{
	if (ifi == NULL || ifp == NULL)
		return -1;

	if ((!ifp->aggregator && master) || (ifp->aggregator && !master)) {
		/* master was either set or cleared */
		lag_slave_sync_mac_address(ifp);
	} else {
		/* if link up, restore collect/dist flags */
		if (ifi->ifi_flags & IFF_RUNNING) {
			lag_select(ifp, enabled[ifp->if_port]);
			lag_slave_sync_mac_address(ifp);
		}
	}

	return 0;
}

void lag_refresh_actor_state(struct ifnet *master)
{
	portid_t slaves[LAG_MAX_SLAVES];
	int count, i;

	count = rte_eth_bond_slaves_get(master->if_port, slaves,
					LAG_MAX_SLAVES);

	for (i = 0; i < count; i++)
		lag_select(ifport_table[slaves[i]], enabled[slaves[i]]);
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


static bool lag_slave_is_active(portid_t active[], int len, uint16_t portid)
{
	int i;

	for (i = 0; i < len; i++)
		if (active[i] == portid)
			return true;
	return false;
}

static void show_lag_detail(struct ifnet *node, void *arg)
{
	json_writer_t *wr = arg;
	int num_slaves;
	int num_active;
	int i;
	int primary = rte_eth_bond_primary_get(node->if_port);
	int mode = rte_eth_bond_mode_get(node->if_port);
	int policy = rte_eth_bond_xmit_policy_get(node->if_port);
	const char *policy_str = "n/a";
	portid_t slaves[LAG_MAX_SLAVES];
	portid_t active[LAG_MAX_SLAVES];

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
						LAG_MAX_SLAVES);
	num_slaves = rte_eth_bond_slaves_get(node->if_port, slaves,
					LAG_MAX_SLAVES);
	jsonw_name(wr, "slaves");
	jsonw_start_array(wr);
	for (i = 0; i < num_slaves; i++) {
		struct ifnet *sl = ifnet_byport(slaves[i]);
		struct rte_eth_bond_8023ad_slave_info info;
		int rc;

		if (!sl)
			continue;

		bool is_primary = primary == sl->if_port;
		bool is_active = lag_slave_is_active(active, num_active,
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

static void show_lag(struct ifnet *ifp, void *arg)
{
	if (is_team(ifp))
		show_lag_detail(ifp, arg);
}

int lag_summary(FILE *fp)
{
	json_writer_t *wr = jsonw_new(fp);

	if (!wr)
		return -1;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "lag");
	jsonw_start_array(wr);

	ifnet_walk(show_lag, wr);

	jsonw_end_array(wr);
	jsonw_destroy(&wr);

	return 0;
}

void
lag_set_phy_qinq_mtu_slave(struct ifnet *sl, void *arg)
{
	if (!sl || arg)
		return;

	if_set_mtu(sl, sl->if_mtu, true);
}

int
lag_walk_bond_slaves(struct ifnet *ifp, ifnet_iter_func_t iter_func, void *arg)
{
	int num_slaves;
	portid_t slaves[LAG_MAX_SLAVES];
	int i;

	if (!ifp->if_team || !iter_func)
		return -EINVAL;

	num_slaves = rte_eth_bond_slaves_get(ifp->if_port, slaves,
					     LAG_MAX_SLAVES);
	if (num_slaves < 0)
		return -EINVAL;

	for (i = 0; i < num_slaves; i++) {
		struct ifnet *sl = ifnet_byport(slaves[i]);

		if (sl)
			(iter_func)(sl, arg);
	}

	return 0;
}
