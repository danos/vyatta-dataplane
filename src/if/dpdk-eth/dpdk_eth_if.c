/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * DPDK port-backed interface implementation
 */

#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_ethdev_driver.h>

#include "dpdk_eth_if.h"
#include "dpdk_eth_linkwatch.h"
#include "dp_event.h"
#include "ether.h"
#include "hotplug.h"
#include "if_var.h"
#include "l2_rx_fltr.h"
#include "lag.h"
#include "qos.h"
#include "vhost.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "transceiver.h"

#define MODULE_SFF_8436_AX_LEN 640

typedef int (*reconfigure_port_cb_fn)(struct ifnet *ifp,
				      struct rte_eth_conf *dev_conf);

static int reconfigure_port(struct ifnet *ifp,
			    struct rte_eth_conf *dev_conf,
			    reconfigure_port_cb_fn reconfigure_port_cb);

static bitmask_t started_port_mask;	/* port has been started */

static zhash_t *dpdk_name_to_eth_port_map;

static void dpdk_name_to_eth_port_map_cleanup(void)
{
	zhash_destroy(&dpdk_name_to_eth_port_map);
}

static void dpdk_name_to_eth_port_map_init(void)
{
	dpdk_name_to_eth_port_map = zhash_new();
	if (!dpdk_name_to_eth_port_map)
		rte_panic(
			"Cannot allocate zhash for name to port map for eth interfaces\n"
			);
}

int dpdk_name_to_eth_port_map_add(const char *ifname, portid_t port)
{
	uint16_t *portid_obj = malloc(sizeof(*portid_obj));

	if (!portid_obj)
		return -ENOMEM;
	*portid_obj = port;
	if (zhash_insert(dpdk_name_to_eth_port_map, ifname,
			 portid_obj) < 0) {
		free(portid_obj);
		return -ENOMEM;
	}
	zhash_freefn(dpdk_name_to_eth_port_map, ifname, free);

	return 0;
}

void dpdk_eth_port_map_del_port(portid_t port)
{
	uint16_t *portid_obj;
	const char *ifname;

	for (portid_obj = zhash_first(dpdk_name_to_eth_port_map);
	     portid_obj;
	     portid_obj = zhash_next(dpdk_name_to_eth_port_map)) {
		if (*portid_obj == port) {
			ifname = zhash_cursor(dpdk_name_to_eth_port_map);

			zhash_delete(dpdk_name_to_eth_port_map, ifname);
			return;
		}
	}
}

static portid_t
dpdk_name_to_eth_port_map_get(const char *ifname)
{
	uint16_t *portid_obj = zhash_lookup(dpdk_name_to_eth_port_map, ifname);

	if (!portid_obj)
		return IF_PORT_ID_INVALID;

	return *portid_obj;
}

/*
 * determine if device is Mellanox ConnectX-5
 * This will be used for some short-term customization of dataplane
 * behaviour until we are able to up-rev DPDK to 1908
 */
static bool is_device_mlx5(portid_t portid)
{
	struct rte_eth_dev_info dev_info;

	if (!rte_eth_dev_is_valid_port(portid))
		return false;

	rte_eth_dev_info_get(portid, &dev_info);
	if (strstr(dev_info.driver_name, "net_mlx5") == dev_info.driver_name)
		return true;

	return false;
}

bool dpdk_eth_if_port_started(portid_t port)
{
	return bitmask_isset(&started_port_mask, port);
}

static void soft_stop_port(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	portid_t port = ifp->if_port;

	if (!bitmask_isset(&started_port_mask, port))
		return;	 /* already inactive */

	bitmask_clear(&started_port_mask, port);
	rte_eth_led_off(port);

	linkwatch_update_port_status(port, LINKWATCH_FLAG_FORCE_LINK_DOWN);

	/* Stop monitoring port */
	rte_timer_stop(&sc->scd_link_timer);

	qos_sched_stop(ifp);

	/* make sure cores have drained */
	dp_rcu_synchronize();

	/* free any leftovers */
	pkt_ring_empty(port);
}

static void soft_start_port(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	portid_t port = ifp->if_port;

	if (bitmask_isset(&started_port_mask, port))
		return;	 /* already active */

	rte_eth_led_on(port);

	bitmask_set(&started_port_mask, port);
	linkwatch_update_port_status(port, LINKWATCH_FLAG_FORCE_NOTIFY);

	/* Start timer to send keepalive messages */
	if (rte_timer_reset(&sc->scd_link_timer,
			    config.port_update * rte_get_timer_hz(),
			    PERIODICAL, rte_get_master_lcore(),
			    linkwatch_timer, ifp) < 0)
		RTE_LOG(ERR, DATAPLANE,
			"rte_timer_reset failed for linkwatch timer port:%u\n",
			port);
}

/* Start device (admin up) */
void dpdk_eth_if_start_port(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	portid_t port = ifp->if_port;
	int ret;

	if (!lag_can_start(ifp)) {
		/* A bonding interface might not have any members yet. Don't
		 * try to start it since this will result in an error from
		 * rte_eth_dev_start().  Instead, lag_member_add() will start
		 * the interface (if necessary) when the first member is added.
		 */
		RTE_LOG(DEBUG, DATAPLANE,
			"no members on bonding device %s\n", ifp->if_name);
		return;
	}

	if (bitmask_isset(&started_port_mask, port))
		return;	 /* already active */

	/* bonding driver will start member device when ready */
	if (lag_can_startstop_member(ifp)) {
		if (assign_queues(port))
			return; /* failure */

		if (sc->scd_need_reset)
			dpdk_eth_if_reset_port(NULL, ifp);

		ret = rte_eth_dev_start(port);
		if (ret < 0 && !sc->scd_need_reset) {
			RTE_LOG(ERR, DATAPLANE,
				"rte_eth_dev_start: port=%u err=%d\n",
				port, ret);
			unassign_queues(port);
			return;
		}

		sc->scd_need_reset = false;
	}

	soft_start_port(ifp);
	if (lag_can_startstop_member(ifp))
		rte_eth_dev_set_link_up(port);
}

/* Stop device (admin down) */
void dpdk_eth_if_stop_port(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	portid_t port = ifp->if_port;

	if (!bitmask_isset(&started_port_mask, port) &&
	    !rte_timer_pending(&sc->scd_reset_timer))
		return;	 /* already inactive */

	/* if the PF is down when the port is stopped, then it will not work
	 * once it restarts unless rte_eth_dev_reset is called.
	 * But if the timer is simply left running then port will be set to UP
	 * when the PF goes back online, even if it should still be stopped
	 */
	if (rte_timer_pending(&sc->scd_reset_timer)) {
		rte_timer_stop_sync(&sc->scd_reset_timer);
		sc->scd_need_reset = true;
	}

	if (lag_can_startstop_member(ifp))
		rte_eth_dev_set_link_down(port);
	soft_stop_port(ifp);

	/*
	 * If we're a member of a bonding interface that doesn't
	 * support starting/stopping members independently then don't
	 * alter the state of the member - it will shortly be removed
	 * and it will then be coerced into the right state.
	 */
	if (!lag_can_startstop_member(ifp))
		return;

	rte_eth_dev_stop(port);

	unassign_queues(port);

	/*
	 * Some drivers require the HW multicast filter to be reprogrammed when
	 * the interface is next brought up after being taken down, regardless
	 * of whether this filter is already active
	 */
	l2_rx_fltr_set_reprogram(ifp);
}

/*
 * Stop a port when the dataplane port state may not be in sync with
 * the dpdk port state, ensuring that either way the dpdk port is
 * stopped on return.
 */
void dpdk_eth_if_force_stop_port(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	portid_t port = ifp->if_port;

	if (!bitmask_isset(&started_port_mask, port) &&
	    !rte_timer_pending(&sc->scd_reset_timer))
		rte_eth_dev_stop(port);
	else
		dpdk_eth_if_stop_port(ifp);
}

/* Stop data transfer */
void stop_all_ports(void)
{
	struct ifnet *ifp;
	unsigned int port;

	for (port = 0; port < DATAPLANE_MAX_PORTS; port++) {
		ifp = ifport_table[port];
		if (bitmask_isset(&started_port_mask, port))
			dpdk_eth_if_stop_port(ifp);
	}
}

/* Timer for periodic check of link reset
 *
 * Note: dp_rcu_read_lock not held here!
 * This can be run both via directly in response to a link reset interrupt
 * (tim will be NULL) or from an rte_timer callback (tim will be the actual
 * timer). In both cases it will be ran from the main thread.
 */
void dpdk_eth_if_reset_port(struct rte_timer *tim, void *arg)
{
	struct ifnet *ifp = arg;
	portid_t port = ifp->if_port;
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	int ret;
	struct rte_eth_conf dev_conf;
	struct rte_eth_dev *eth_dev;

	dpdk_eth_if_stop_port(ifp);

	ret = rte_eth_dev_reset(port);
	/* Only VF receives interrupt, bonding int will NOT reset. Also if the
	 * port is bonded, the bond interface must be restarted AFTER the
	 * reset call, otherwise bonding will be broken once PF is back up.
	 */
	if (ifp->aggregator) {
		soft_start_port(ifp->aggregator);
		if (is_team(ifp->aggregator))
			lag_refresh_actor_state(ifp->aggregator);
	}
	if (ret == -ENODEV || ret == -EINVAL) {
		RTE_LOG(ERR, DATAPLANE,
			"rte_eth_dev_reset: invalid port=%u err=%d\n",
			port, ret);
	} else if (ret == -ENOTSUP) {
		RTE_LOG(NOTICE, DATAPLANE,
			"rte_eth_dev_reset: no reset on HW port=%u err=%d\n",
			port, ret);
	} else if (ret == -EAGAIN || ret == -15) {
		RTE_LOG(DEBUG, DATAPLANE,
			"rte_eth_dev_reset: PF still down port=%u err=%d\n",
			port, ret);

		/* reset failed, start timer to check again. If tim is not
		 * NULL then the call is from the timer, so it's already
		 * running, no need to start it again
		 * -15 is a weird IXGBE specific error code
		 */
		if (!tim && rte_timer_reset(&sc->scd_reset_timer,
				    config.port_update * rte_get_timer_hz(),
				    PERIODICAL, rte_get_master_lcore(),
				    dpdk_eth_if_reset_port, ifp) < 0)
			RTE_LOG(ERR, DATAPLANE, "rte_timer_reset failed for "
					"reset timer port:%u\n", port);
		return;
	} else if (ret < 0) {
		/* drivers can return weird errors, catch it and log it */
		RTE_LOG(ERR, DATAPLANE,
			"rte_eth_dev_reset: reset failed on HW port=%u err=%d\n",
			port, ret);
	}

	/* Port is inactive, no races are possible. If tim is NULL then this
	 * is the first call on interrupt and the timer is not running.
	 */
	if (tim)
		rte_timer_stop_sync(tim);

	/* stop_port has to set need_reset if the timer is running, but
	 * setting it from here would cause a loop
	 */
	eth_dev = &rte_eth_devices[ifp->if_port];
	memcpy(&dev_conf, &eth_dev->data->dev_conf, sizeof(dev_conf));

	sc->scd_need_reset = false;
	reconfigure_port(ifp, &dev_conf, NULL);
}

void dpdk_eth_if_update_port_queue_state(portid_t port)
{
	unassign_queues(port);

	set_port_queue_state(port);

	if (bitmask_isset(&started_port_mask, port))
		assign_queues(port);
}

static void reconfigure_member(struct ifnet *ifp, void *arg)
{
	struct rte_eth_conf *conf = arg;
	struct rte_eth_conf *member_conf;
	struct rte_eth_dev *member_dev;
	bool dev_started;

	member_dev = &rte_eth_devices[ifp->if_port];
	member_conf = &member_dev->data->dev_conf;
	dev_started = member_dev->data->dev_started;

	/* Ensure member is stopped as stopping the bond port doesn't do this */
	if (dev_started)
		rte_eth_dev_stop(ifp->if_port);

	/*
	 * Update member config to match the aggregate jumbo config
	 * so that it will accept a jumbo mtu change.
	 * Leave everything else alone.
	 * When the bond is restarted, it will configure the member,
	 * set up its queues, and start it, so don't call
	 * rte_eth_dev_configure() directly here.
	 */
	if (conf->rxmode.offloads & DEV_RX_OFFLOAD_SCATTER)
		member_conf->rxmode.offloads |= DEV_RX_OFFLOAD_SCATTER;
	else
		member_conf->rxmode.offloads &= ~(DEV_RX_OFFLOAD_SCATTER);
	if (conf->rxmode.offloads & DEV_RX_OFFLOAD_JUMBO_FRAME)
		member_conf->rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		member_conf->rxmode.offloads &= ~(DEV_RX_OFFLOAD_JUMBO_FRAME);

	if (dev_started)
		rte_eth_dev_start(ifp->if_port);
}

/*
 * Reconfigure a port, stopping the port if necessary and
 * performing any necessary work after restarting the port.
 *
 * reconfigure_port_cb can be used to perform any additional
 * operations before the port is restarted.
 */
static int reconfigure_port(struct ifnet *ifp,
			    struct rte_eth_conf *dev_conf,
			    reconfigure_port_cb_fn reconfigure_port_cb)
{
	portid_t portid = ifp->if_port;
	int err;
	struct rte_eth_dev *dev = &rte_eth_devices[portid];
	int dev_started = dev->data->dev_started;

	if (dev_started)
		dpdk_eth_if_stop_port(ifp);

	err = eth_port_configure(portid, dev_conf);

	if (!err && reconfigure_port_cb)
		err = reconfigure_port_cb(ifp, dev_conf);

	/*
	 * If we brought the port down then bring it back up, even if there
	 * was an error.
	 */
	if (dev_started) {
		dpdk_eth_if_start_port(ifp);
		if (is_team(ifp))
			lag_refresh_actor_state(ifp);
		/* Reprogram HW multicast filter after restarting port */
		l2_rx_fltr_state_change(ifp);
	}

	if (err && reconfigure_port_cb)
		/*
		 * Try again if it failed when the port was down. Some
		 * drivers such as igb require the port to be brought
		 * back up after the jumbo cfg is set before the mtu
		 * can be set into the jumbo range.
		 */
		err = reconfigure_port_cb(ifp, dev_conf);

	return err;
}

static int reconfigure_pkt_len_cb(struct ifnet *ifp,
				  struct rte_eth_conf *dev_conf)
{
	int err;

	/* Reconfigure members to match aggregate jumbo config */
	if (is_team(ifp))
		lag_walk_team_members(ifp, reconfigure_member, dev_conf);

	err = rte_eth_dev_set_mtu(ifp->if_port, ifp->if_mtu_adjusted);
	if (err == -ENOTSUP)
		err = 0;

	return err;
}

/* Change hardware MTU, can only be called if stopped. */
static int reconfigure_pkt_len(struct ifnet *ifp, uint32_t mtu)
{
	struct rte_eth_conf dev_conf;
	struct rte_eth_dev *eth_dev = &rte_eth_devices[ifp->if_port];

	memcpy(&dev_conf, &eth_dev->data->dev_conf, sizeof(dev_conf));

	if (mtu > RTE_ETHER_MTU) {
		struct rte_eth_dev_info dev_info;
		rte_eth_dev_info_get(ifp->if_port, &dev_info);
		if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_JUMBO_FRAME)
			dev_conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
		if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_SCATTER)
			dev_conf.rxmode.offloads |= DEV_RX_OFFLOAD_SCATTER;
	} else {
		dev_conf.rxmode.offloads &= ~(DEV_RX_OFFLOAD_JUMBO_FRAME |
			DEV_RX_OFFLOAD_SCATTER);
	}
	dev_conf.rxmode.max_rx_pkt_len = mtu +
					 RTE_ETHER_HDR_LEN +
					 RTE_ETHER_CRC_LEN;

	return reconfigure_port(ifp, &dev_conf, reconfigure_pkt_len_cb);
}

static inline bool
is_jumbo_size(uint32_t size)
{
	return size > RTE_ETHER_MTU;
}

static bool is_device_swport(portid_t portid)
{
	struct rte_eth_dev_info dev_info;

	if (!rte_eth_dev_is_valid_port(portid))
		return false;

	rte_eth_dev_info_get(portid, &dev_info);
	if (strstr(dev_info.driver_name, "net_sw_port") == dev_info.driver_name)
		return true;

	return false;
}

static inline bool is_reconfigure_port_required(struct ifnet *ifp)
{
	return !is_device_swport(ifp->if_port);
}

static int dpdk_eth_if_set_mtu(struct ifnet *ifp, uint32_t mtu)
{
	int err = 0;
	int adjusted_mtu = mtu;

	if (ifp->aggregator) {
		/*
		 * This interface is already under control of the
		 * bonding interface. dev_start() in the bonding
		 * driver does a rte_eth_dev_configure() for
		 * each of the members and will update the member
		 * adapters at that point. But we need to keep
		 * ifp->if_mtu up to date.
		 */
		goto out;
	}

	if (ifp->qinq_vif_cnt)
		adjusted_mtu = adjusted_mtu + 4;

	/*
	 * MTU changes can affect the burst size used for QoS shaper.
	 * Thefeore, QoS needs to be notified of the MTU changes so it can
	 * make the necessary dynamic changes where possible or alternatively
	 * stop and then restart QoS to allow it to re-calculate any resultant
	 * changes in the bucket/burst sizes where dynamic changes aren't
	 * possible.  This is done using dp_event_notify
	 *
	 * Some drivers always need the port to be stopped (i40)
	 * for the mtu to be changed. Some drivers need the port to be
	 * stopped to transition into/outof jumbo range (ixgbe).
	 * Unfortunately we can't tell this ahead of time, so try to
	 * set the mtu, and if we get an error then stop the ports and
	 * try again.
	 *
	 * If we are transitioning into/outof jumbo range then we have to
	 * reconfigure the port to get the correct jumbo settings.
	 */
	bool changed = false;
	bool mtu_jumbo_change =
		(is_jumbo_size(ifp->if_mtu_adjusted) &&
			!is_jumbo_size(mtu)) ||
		(is_jumbo_size(mtu) &&
			!is_jumbo_size(ifp->if_mtu_adjusted));

	/*
	 * Certain drivers require the port to be reconfigured when changing
	 * the MTU to/from jumbo size.  Check if this is the case, if not then
	 * there is no reason to bounce the port.  Also if we get an error
	 * try again with port stopped.
	 */
	if (!mtu_jumbo_change || !is_reconfigure_port_required(ifp)) {
		err = rte_eth_dev_set_mtu(ifp->if_port, adjusted_mtu);
		changed = true;
	}

	/*
	 * We must update the interface's adjusted MTU before
	 * starting the port so that QoS can recalculate its
	 * token bucket size based upon the new MTU.
	 *
	 * Also used in the reconfigure_port callback.
	 */
	ifp->if_mtu_adjusted = adjusted_mtu;

	/* Try again, but this time after changing the port config */
	if (!changed || err ) {
		RTE_LOG(INFO, DATAPLANE,
			"reconfiguring %s due to %s\n",
			ifp->if_name,
			mtu_jumbo_change ?
				"jumbo length packet change" :
				"online MTU setting not supported for this interface");
		err = reconfigure_pkt_len(ifp, adjusted_mtu);
	}
out:
	if (!err)
		ifp->if_mtu = mtu;

	return err;
}

static int dpdk_eth_if_set_l2_address(struct ifnet *ifp, uint32_t l2_addr_len,
				      void *l2_addr)
{
	struct rte_ether_addr *macaddr = l2_addr;
	char b1[32], b2[32];

	if (l2_addr_len != RTE_ETHER_ADDR_LEN) {
		RTE_LOG(NOTICE, DATAPLANE,
			"link address is not ethernet (len=%u)!\n",
			l2_addr_len);
		return -EINVAL;
	}

	if (rte_ether_addr_equal(&ifp->eth_addr, macaddr))
		return 1;

	RTE_LOG(INFO, DATAPLANE, "%s change MAC from %s to %s\n",
		ifp->if_name,
		ether_ntoa_r(&ifp->eth_addr, b1),
		ether_ntoa_r(macaddr, b2));

	int rc;

	if (ifp->if_team)
		rc = lag_set_l2_address(ifp, macaddr);
	else
		rc = rte_eth_dev_default_mac_addr_set(
			ifp->if_port, macaddr);
	if (rc != 0)
		return rc;

	ifp->eth_addr = *macaddr;

	return 0;
}

static int dpdk_eth_if_start(struct ifnet *ifp)
{
	dpdk_eth_if_start_port(ifp);
	if (if_port_is_bkplane(ifp->if_port))
		ifpromisc(ifp, true);

	return 0;
}

static int dpdk_eth_if_stop(struct ifnet *ifp)
{
	/*
	 * If this is a bonding member then it's managed by the
	 * bonding PMD until the team genetlink removes it from the
	 * bond.
	 */
	if (!lag_can_startstop_member(ifp))
		return 0;

	dpdk_eth_if_stop_port(ifp);
	if (if_port_is_bkplane(ifp->if_port))
		ifpromisc(ifp, false);

	return 0;
}

static int
dpdk_eth_if_add_l2_addr(struct ifnet *ifp, void *l2_addr)
{
	return rte_eth_dev_mac_addr_add(ifp->if_port, l2_addr, 0);
}

static int
dpdk_eth_if_del_l2_addr(struct ifnet *ifp, void *l2_addr)
{
	return rte_eth_dev_mac_addr_remove(ifp->if_port, l2_addr);
}

static int dpdk_eth_if_init(struct ifnet *ifp, void *ctx)
{
	struct dpdk_eth_if_softc *sc;
	portid_t port = *(portid_t *)ctx;

	sc = rte_zmalloc_socket("dpdk softc", sizeof(*sc), 0, ifp->if_socket);
	if (!sc)
		return -ENOMEM;

	rte_timer_init(&sc->scd_link_timer);
	rte_timer_init(&sc->scd_blink_timer);
	rte_timer_init(&sc->scd_reset_timer);

	sc->scd_ifp = ifp;
	ifp->if_softc = sc;
	ifp->if_port = port;

	rte_ether_addr_copy(&ifp->eth_addr, &ifp->perm_addr);

	return 0;
}

static void dpdk_eth_if_softc_free_rcu(struct rcu_head *head)
{
	struct dpdk_eth_if_softc *sc =
		caa_container_of(head, struct dpdk_eth_if_softc, scd_rcu);

	if (sc->scd_vhost_info)
		vhost_info_free(sc->scd_vhost_info);

	rte_free(sc);
}

static void dpdk_eth_if_uninit(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;

	/* if unplugged, then this has already been done */
	if (!ifp->unplugged)
		shadow_uninit_port(ifp->if_port);

	/* to cope with freeing after errors during initialisation of ifp */
	if (!sc)
		return;

	rte_timer_stop(&sc->scd_link_timer);
	rte_timer_stop(&sc->scd_blink_timer);
	rte_timer_stop(&sc->scd_reset_timer);

	rcu_assign_pointer(ifp->if_softc, NULL);

	ifport_table[ifp->if_port] = NULL;

	call_rcu(&sc->scd_rcu, dpdk_eth_if_softc_free_rcu);
}

static int
dpdk_eth_if_set_vlan_filter(struct ifnet *ifp, uint16_t vlan, bool enable)
{
	struct rte_eth_dev_info dev_info;
	int ret = -ENOTSUP;

	rte_eth_dev_info_get(ifp->if_port, &dev_info);
	if ((dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_FILTER) != 0)
		ret = rte_eth_dev_vlan_filter(ifp->if_port, vlan, enable);

	return ret;
}

static int
dpdk_eth_if_set_vlan_proto(struct ifnet *ifp,
			   enum if_vlan_header_type type,
			   uint16_t proto)
{
	enum rte_vlan_type rte_type = ETH_VLAN_TYPE_UNKNOWN;
	int ret;

	if (!ifp->if_local_port)
		return -ENOTSUP;

	/*
	 * The Mellanox ConnectX-5 driver uses a very inefficient
	 * transmit function if VLAN insertion is offloaded.
	 * Temporarily handle this in the dataplane.
	 * This should be removed when we up-rev DPDK to 1908
	 */
	if (is_device_mlx5(ifp->if_port))
		return -ENOTSUP;

	switch (type) {
	case IF_VLAN_HEADER_OUTER:
		rte_type = ETH_VLAN_TYPE_OUTER;
		break;
	case IF_VLAN_HEADER_INNER:
		rte_type = ETH_VLAN_TYPE_INNER;
		break;
	}

	/*
	 * The vlan protocol is set in the PMD even if setting
	 * back to 802.1q and offload wasn't supported to
	 * avoid making assumptions about what the drivers may
	 * or may not supported. I.e. the driver may support
	 * certain protocols, rather than being an
	 * all-or-nothing deal.
	 */
	ret = rte_eth_dev_set_vlan_ether_type(ifp->if_port, rte_type,
					      proto);

	if (ret == -ENOTSUP && proto == ETH_P_8021Q) {
		/*
		 * Offload for the 802.1q protocol
		 * type is guaranteed by DPDK to
		 * always be supported in a PMD, but
		 * rte_eth_dev_set_vlan_ether_type
		 * returns -ENOTSUP if the PMD doesn't
		 * fill in the function pointer.
		 */
		return 0;
	}

	return ret;
}

static int
dpdk_eth_if_set_broadcast(struct ifnet *ifp, bool enable)
{
	/*
	 * This interface is under the control of bonding PMD, so
	 * don't make any changes to it.
	 */
	if (ifp->aggregator)
		return 0;

	return ether_if_set_broadcast(ifp, enable);
}

static int
dpdk_eth_if_set_promisc(struct ifnet *ifp, bool enable)
{
	struct rte_eth_dev_info dev_info;
	uint32_t offload_mask;
	int ret;

	/*
	 * This interface is under the control of bonding PMD
	 * so don't make any changes to it.
	 */
	if (ifp->aggregator)
		return 0;

	if (enable)
		ret = rte_eth_promiscuous_enable(ifp->if_port);
	else
		ret = rte_eth_promiscuous_disable(ifp->if_port);

	rte_eth_dev_info_get(ifp->if_port, &dev_info);
	if (!ret && dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_FILTER) {
		offload_mask =
			rte_eth_dev_get_vlan_offload(ifp->if_port);
		if (enable)
			offload_mask &= ~ETH_VLAN_FILTER_OFFLOAD;
		else
			offload_mask |= ETH_VLAN_FILTER_OFFLOAD;
		ret = rte_eth_dev_set_vlan_offload(ifp->if_port,
						   offload_mask);
	}

	return ret;
}

static void
dpdk_eth_if_show_dev_capabilities(json_writer_t *wr,
				  const struct rte_eth_dev_info *info)
{
	struct speed_capas {
		uint32_t speed_capa;
		uint32_t mbps;	/* megabits */
	} speed_capas[] = {
		{ ETH_LINK_SPEED_10M,      10 },
		{ ETH_LINK_SPEED_100M,    100 },
		{ ETH_LINK_SPEED_1G,     1000 },
		{ ETH_LINK_SPEED_2_5G,   2500 },
		{ ETH_LINK_SPEED_5G,     5000 },
		{ ETH_LINK_SPEED_10G,   10000 },
		{ ETH_LINK_SPEED_20G,   20000 },
		{ ETH_LINK_SPEED_25G,   25000 },
		{ ETH_LINK_SPEED_40G,   40000 },
		{ ETH_LINK_SPEED_50G,   50000 },
		{ ETH_LINK_SPEED_56G,   56000 },
		{ ETH_LINK_SPEED_100G, 100000 },
	};
	struct speed_capas hd_speed_capas[] = {
		{ ETH_LINK_SPEED_10M_HD,   10 },
		{ ETH_LINK_SPEED_100M_HD, 100 },
	};
	unsigned int i;

	jsonw_name(wr, "capabilities");
	jsonw_start_object(wr);

	/* If speed_capa is 0, it's likely it hasn't been set up and we
	 * have no idea what the hardware/driver actually supports. We
	 * could add some overrides to dataplane-drivers-default.conf
	 * to massage what we return here.
	 */
	jsonw_name(wr, "full-duplex");
	jsonw_start_array(wr);
	for (i = 0; i < ARRAY_SIZE(speed_capas); i++) {
		if (info->speed_capa & speed_capas[i].speed_capa)
			jsonw_uint(wr, speed_capas[i].mbps);
	}
	jsonw_end_array(wr);

	jsonw_name(wr, "half-duplex");
	jsonw_start_array(wr);
	for (i = 0; i < ARRAY_SIZE(hd_speed_capas); i++) {
		if (info->speed_capa & hd_speed_capas[i].speed_capa)
			jsonw_uint(wr, hd_speed_capas[i].mbps);
	}
	jsonw_end_array(wr);

	jsonw_end_object(wr);
}

static bool
dpdk_eth_is_mgmt_port(const struct rte_pci_addr *pci_addr)
{
	struct config_pci_entry *pci_entry;

	LIST_FOREACH(pci_entry, &platform_cfg.mgmt_list, link)
		if (!rte_pci_addr_cmp(&pci_entry->pci_addr, pci_addr))
			return true;

	return false;
}

static void
dpdk_eth_if_show_dev_info(struct ifnet *ifp, json_writer_t *wr)
{
	struct rte_eth_dev_info info;
	portid_t port = ifp->if_port;
	int hw_switch;

	rte_eth_dev_info_get(port, &info);

	jsonw_name(wr, "dev");
	jsonw_start_object(wr);
	if (info.driver_name)
		jsonw_string_field(wr, "driver", info.driver_name);
	jsonw_uint_field(wr, "node", rte_eth_dev_socket_id(port));

	if (port < RTE_MAX_ETHPORTS) { /* possibly NO_OWNER */
		struct rte_eth_dev *dev = &rte_eth_devices[port];
		bool settable;

		if (ifp->if_team)
			settable = true;
		else
			settable = dev && dev->dev_ops &&
				   dev->dev_ops->mac_addr_set ? true : false;

		jsonw_bool_field(wr, "mac_addr_settable", settable);
		jsonw_string_field(wr, "eth_dev_data_name", dev->data->name);
		jsonw_bool_field(wr, "dev_started", dev->data->dev_started);
		jsonw_bool_field(wr, "scattered_rx", dev->data->scattered_rx);
		jsonw_uint_field(wr, "lsc", dev->data->dev_conf.intr_conf.lsc);
		/*
		 * workaround to determine switch id until we have
		 * a mechanism for retrieving opaque data
		 */
		if (info.driver_name &&
		    get_switch_dev_info(info.driver_name, dev->data->name,
					&hw_switch, NULL))
			jsonw_uint_field(wr, "hw_switch_id", hw_switch);
	}

	const struct rte_bus *bus = rte_bus_find_by_device(info.device);
	struct rte_pci_device *pci = NULL;
	if (bus && streq(bus->name, "pci"))
		pci = RTE_DEV_TO_PCI(info.device);
	if (pci) {
		jsonw_name(wr, "pci");
		jsonw_start_object(wr);

		jsonw_name(wr, "address");
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "domain", pci->addr.domain);
		jsonw_uint_field(wr, "bus", pci->addr.bus);
		jsonw_uint_field(wr, "devid", pci->addr.devid);
		jsonw_uint_field(wr, "function", pci->addr.function);
		jsonw_end_object(wr);

		jsonw_name(wr, "id");
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "vendor", pci->id.vendor_id);
		jsonw_uint_field(wr, "device", pci->id.device_id);
		jsonw_uint_field(wr, "subsystem_vendor",
				 pci->id.subsystem_vendor_id);
		jsonw_uint_field(wr, "subsystem_device",
				 pci->id.subsystem_device_id);
		jsonw_end_object(wr);

		jsonw_end_object(wr);
	}

	dpdk_eth_if_show_dev_capabilities(wr, &info);

	jsonw_uint_field(wr, "min_rx_bufsize", info.min_rx_bufsize);
	jsonw_uint_field(wr, "max_rx_pktlen", info.max_rx_pktlen);
	jsonw_uint_field(wr, "max_rx_queues", info.max_rx_queues);
	jsonw_uint_field(wr, "max_tx_queues", info.max_tx_queues);
	jsonw_uint_field(wr, "max_mac_addrs", info.max_mac_addrs);
	jsonw_uint_field(wr, "vmdq_queue_base", info.vmdq_queue_base);
	jsonw_uint_field(wr, "vmdq_queue_num", info.vmdq_queue_num);

	if (info.driver_name && strcasestr(info.driver_name, "net_vhost"))
		vhost_devinfo(wr, ifp);

	if (pci && dpdk_eth_is_mgmt_port(&pci->addr))
		jsonw_bool_field(wr, "management", true);

	jsonw_end_object(wr);
}

/* Device with statistics in hardware */
static void
dpdk_eth_if_show_stats(struct ifnet *ifp, json_writer_t *wr)
{
	struct rte_eth_stats hwstats;
	unsigned int i;
	int ret;

	ret = rte_eth_stats_get(ifp->if_port, &hwstats);
	if (ret)
		return;

	jsonw_uint_field(wr, "rx_missed", hwstats.imissed);
	jsonw_uint_field(wr, "rx_nobuffer", hwstats.rx_nombuf);

	jsonw_name(wr, "qstats");
	jsonw_start_array(wr);
	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "ipackets", hwstats.q_ipackets[i]);
		jsonw_uint_field(wr, "ibytes", hwstats.q_ibytes[i]);
		jsonw_uint_field(wr, "opackets", hwstats.q_opackets[i]);
		jsonw_uint_field(wr, "obytes", hwstats.q_obytes[i]);
		jsonw_uint_field(wr, "errors", hwstats.q_errors[i]);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
}

/* Device with extended statistics in hardware (physical port) */
static void
dpdk_eth_if_show_xstats(struct ifnet *ifp, json_writer_t *wr)
{
	int i, len, ret;

	len = rte_eth_xstats_get_names(ifp->if_port, NULL, 0);
	if (len < 1)
		return;

	struct rte_eth_xstat_name xstat_names[len];
	struct rte_eth_xstat xstats[len];
	memset(xstat_names, 0, sizeof(xstat_names));
	memset(xstats, 0, sizeof(xstats));

	ret = rte_eth_xstats_get_names(ifp->if_port, xstat_names, len);
	if (ret < 0 || ret > len)
		return;
	ret = rte_eth_xstats_get(ifp->if_port, xstats, len);
	if (ret < 0 || ret > len)
		return;

	for (i = 0; i < len; i++)
		jsonw_uint_field(wr, xstat_names[xstats[i].id].name,
				 xstats[i].value);
}

static void
dpdk_eth_if_show_state(struct ifnet *ifp, json_writer_t *wr)
{
	if (ifp->if_local_port)
		jsonw_uint_field(wr, "port", ifp->if_port);
}

static void dpdk_eth_if_show_xcvr_info(struct ifnet *ifp, json_writer_t *wr)
{
	struct rte_eth_dev_module_info module_info;
	struct rte_dev_eeprom_info eeprom_info;
	char *buf;
	int rv;

	memset(&module_info, 0, sizeof(module_info));

	rv = rte_eth_dev_get_module_info(ifp->if_port, &module_info);
	if (rv)
		return;

	eeprom_info.length =
	module_info.eeprom_len < MODULE_SFF_8436_AX_LEN ?
		module_info.eeprom_len : MODULE_SFF_8436_AX_LEN;

	buf = malloc(eeprom_info.length);
	if (!buf) {
		DP_DEBUG(LINK, ERR, DATAPLANE,
			"Failed to allocate xcvr eeprom info buffer\n");
		return;
	}
	eeprom_info.data = buf;
	eeprom_info.offset = 0;

	rv = rte_eth_dev_get_module_eeprom(ifp->if_port, &eeprom_info);
	if (rv) {
		free(buf);
		return;
	}

	if (!module_info.eeprom_len) {
		free(buf);
		return;
	}

	jsonw_name(wr, "xcvr_info");
	jsonw_start_object(wr);
	sfp_status((ifp->if_flags & IFF_UP ? true : false),
		   &module_info, &eeprom_info, wr);
	jsonw_end_object(wr);
	free(buf);
}

static int
dpdk_eth_if_dump(struct ifnet *ifp, json_writer_t *wr,
		 enum if_dump_state_type type)
{
	if (!ifp->if_local_port || ifp->unplugged)
		return 0;

	switch (type) {
	case IF_DS_STATS:
		dpdk_eth_if_show_stats(ifp, wr);
		break;
	case IF_DS_XSTATS:
		dpdk_eth_if_show_xstats(ifp, wr);
		break;
	case IF_DS_DEV_INFO:
		dpdk_eth_if_show_dev_info(ifp, wr);
		break;
	case IF_DS_STATE:
		dpdk_eth_if_show_state(ifp, wr);
		break;
	case IF_DS_STATE_VERBOSE:
		dpdk_eth_if_show_xcvr_info(ifp, wr);
		break;
	default:
		break;
	}

	return 0;
}

static void
dpdk_eth_if_get_xstats(struct ifnet *ifp,
		       struct if_data *stats)
{
#define NUM_XSTATS 2
	int i, rv, nstats;
	const char *xstat_names[NUM_XSTATS] = {
		"rx_multicast_packets",
		"rx_broadcast_packets"
	};
	uint64_t xstat_ids[NUM_XSTATS] = { ~0ull, ~0ull };
	uint64_t rx_mcast_pkts = 0;

	/* retrieve all xstats */
	nstats = rte_eth_xstats_get(ifp->if_port, NULL, 0);
	if (nstats < 0)
		return;

	struct rte_eth_xstat xstat_values[nstats];

	rv = rte_eth_xstats_get(ifp->if_port, xstat_values, nstats);
	if (rv < 0)
		return;

	/* get stat ids for the ones we are interested in */
	for (i = 0; i < NUM_XSTATS; i++) {
		rv = rte_eth_xstats_get_id_by_name(ifp->if_port,
						   xstat_names[i],
						   &xstat_ids[i]);
		if (rv)
			continue;
	}

	for (nstats = 0, i = 0; i < NUM_XSTATS; i++) {
		if (xstat_ids[i] == ~0ull)
			continue;

		nstats++;
		rx_mcast_pkts += xstat_values[xstat_ids[i]].value;
	}

	if (nstats)
		stats->ifi_imulticast = rx_mcast_pkts;
}

static int
dpdk_eth_if_get_stats(struct ifnet *ifp, struct if_data *stats)
{
	struct rte_eth_stats hwstats;
	int ret;

	ret = rte_eth_stats_get(ifp->if_port, &hwstats);
	if (ret)
		return ret;

	stats->ifi_ipackets = hwstats.ipackets;
	stats->ifi_opackets = hwstats.opackets;
	stats->ifi_ibytes = hwstats.ibytes;
	stats->ifi_obytes = hwstats.obytes;
	stats->ifi_ierrors += hwstats.ierrors;
	stats->ifi_oerrors += hwstats.oerrors;

	dpdk_eth_if_get_xstats(ifp, stats);
	return 0;
}

/* Timer called (from main) to toggle state of LED. */
static void dpdk_eth_if_blink_timer(struct rte_timer *tim, void *arg)
{
	struct ifnet *ifp = arg;
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	int rc;

	if (sc->scd_blink_on)
		rc = rte_eth_led_on(ifp->if_port);
	else
		rc = rte_eth_led_off(ifp->if_port);

	if (rc < 0) {
		DP_DEBUG(LINK, NOTICE, DATAPLANE,
			 "%s: led %s failed: %s\n",
			 ifp->if_name, sc->scd_blink_on ? "on" : "off",
			 strerror(-rc));
		rte_timer_stop(tim);
	} else
		sc->scd_blink_on = !sc->scd_blink_on;
}

/* Start/stop LED blink timer */
static int dpdk_eth_if_blink(struct ifnet *ifp, bool on)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	int rc = 0;

	if (!ifp->if_local_port)
		return -ENOTSUP;

	if (on) {
		rc = rte_eth_led_on(ifp->if_port);
		if (rc < 0)
			return rc;

		sc->scd_blink_on = 0;
		rte_timer_reset(&sc->scd_blink_timer,
				rte_get_timer_hz() / 2,
				PERIODICAL, rte_get_master_lcore(),
				dpdk_eth_if_blink_timer, ifp);
	} else {
		rte_timer_stop_sync(&sc->scd_blink_timer);

		/* restore proper link state of LED */
		if (if_port_isup(ifp->if_port))
			rte_eth_led_on(ifp->if_port);
		else
			rte_eth_led_off(ifp->if_port);
	}

	return rc;
}

static int dpdk_eth_if_set_backplane(struct ifnet *ifp,
				     unsigned int bp_ifindex)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;

	sc->bp_ifindex = bp_ifindex;

	return 0;
}

static int dpdk_eth_if_get_backplane(struct ifnet *ifp,
				     unsigned int *bp_ifindex)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;

	*bp_ifindex = sc->bp_ifindex;

	return 0;
}

static int
dpdk_eth_if_l3_enable(struct ifnet *ifp)
{
	int ret = 0;

	if (!if_port_is_bkplane(ifp->if_port))
		ret = if_fal_create_l3_intf(ifp);

	return ret;
}

static int
dpdk_eth_if_l3_disable(struct ifnet *ifp)
{
	/*
	 * No check for backplane here (unlike in
	 * dpdk_eth_if_l3_enable) because the port may not be
	 * valid and if_delete_l3_intf checks whether the L3 interface
	 * has been created anyway.
	 */
	return if_fal_delete_l3_intf(ifp);
}

static bool
dpdk_eth_if_is_hw_switching_enabled(struct ifnet *ifp)
{
	return ifp->hw_forwarding;
}

static int
dpdk_eth_if_set_speed(struct ifnet *ifp, bool autoneg,
		      uint32_t speed, int duplex)
{
	struct rte_eth_conf dev_conf;
	struct rte_eth_dev *eth_dev;
	uint32_t link_speeds;

	if (autoneg)
		link_speeds = ETH_LINK_SPEED_AUTONEG;
	else {
		if (duplex == -1)
			/*
			 * Most speeds don't have a separate half-
			 * and full-duplex so or'ing their bitflags
			 * together is harmless.
			 */
			link_speeds = rte_eth_speed_bitflag(speed, 0) |
				rte_eth_speed_bitflag(speed, 1);
		else
			link_speeds =
				rte_eth_speed_bitflag(speed, duplex);
		link_speeds |= ETH_LINK_SPEED_FIXED;
	}

	eth_dev = &rte_eth_devices[ifp->if_port];
	memcpy(&dev_conf, &eth_dev->data->dev_conf, sizeof(dev_conf));

	/* Some drivers set bits for advertised speeds if autoneg enabled */
	if (dev_conf.link_speeds == link_speeds ||
	    (autoneg && !(dev_conf.link_speeds & ETH_LINK_SPEED_FIXED)))
		return 0;

	dev_conf.link_speeds = link_speeds;
	return reconfigure_port(ifp, &dev_conf, NULL);
}

/*
 * While speed/duplex for virtio in DPDK has changed from 10g/full to
 * unknown/half, retain the former for reasons of backwards compatibility.
 */
int
dpdk_eth_link_get_nowait(uint16_t port_id, struct rte_eth_link *eth_link)
{
	struct ifnet *ifp = ifport_table[port_id];
	struct rte_eth_dev_info dev_info;
	int rc;

	if (ifp->sfp_holddown) {
		eth_link->link_status = ETH_LINK_DOWN;
		return 0;
	}

	rc = rte_eth_link_get_nowait(port_id, eth_link);

	if (eth_link->link_speed == ETH_SPEED_NUM_UNKNOWN) {
		rte_eth_dev_info_get(port_id, &dev_info);

		if (strcmp(dev_info.driver_name, "net_virtio") == 0) {
			eth_link->link_duplex = ETH_LINK_FULL_DUPLEX;
			eth_link->link_speed = ETH_SPEED_NUM_10G;
		}
	}

	return rc;
}

static int
dpdk_eth_if_get_link_status(struct ifnet *ifp,
			    struct dp_ifnet_link_status *if_link)
{
	struct rte_eth_link link;

	memset(&link, 0, sizeof(link));

	/* consider unplugged as down, but don't ask DPDK */
	if (!ifp->unplugged && !ifp->sfp_holddown)
		dpdk_eth_link_get_nowait(ifp->if_port, &link);

	if_link->link_status = link.link_status;
	if_link->link_duplex =
		link.link_duplex ? DP_IFNET_LINK_DUPLEX_FULL :
		DP_IFNET_LINK_DUPLEX_HALF;
	if_link->link_speed = link.link_speed;

	return 0;
}

static enum dp_ifnet_iana_type
dpdk_eth_iana_type(struct ifnet *ifp)
{
	if (lag_is_team(ifp))
		return DP_IFTYPE_IANA_IEEE8023ADLAG;

	return DP_IFTYPE_IANA_ETHERNETCSMACD;
}

static int dpdk_eth_if_set_usability(struct ifnet *ifp, bool usable)
{
	if (!lag_port_is_member(ifp))
		return 0;

	return lag_set_member_usable(ifp, usable);
}

static const struct ift_ops dpdk_eth_if_ops = {
	.ifop_set_mtu = dpdk_eth_if_set_mtu,
	.ifop_set_l2_address = dpdk_eth_if_set_l2_address,
	.ifop_start = dpdk_eth_if_start,
	.ifop_stop = dpdk_eth_if_stop,
	.ifop_add_l2_addr = dpdk_eth_if_add_l2_addr,
	.ifop_del_l2_addr = dpdk_eth_if_del_l2_addr,
	.ifop_init = dpdk_eth_if_init,
	.ifop_uninit = dpdk_eth_if_uninit,
	.ifop_set_vlan_filter = dpdk_eth_if_set_vlan_filter,
	.ifop_set_vlan_proto = dpdk_eth_if_set_vlan_proto,
	.ifop_set_broadcast = dpdk_eth_if_set_broadcast,
	.ifop_set_promisc = dpdk_eth_if_set_promisc,
	.ifop_dump = dpdk_eth_if_dump,
	.ifop_get_stats = dpdk_eth_if_get_stats,
	.ifop_blink = dpdk_eth_if_blink,
	.ifop_set_backplane = dpdk_eth_if_set_backplane,
	.ifop_get_backplane = dpdk_eth_if_get_backplane,
	.ifop_l3_enable = dpdk_eth_if_l3_enable,
	.ifop_l3_disable = dpdk_eth_if_l3_disable,
	.ifop_is_hw_switching_enabled = dpdk_eth_if_is_hw_switching_enabled,
	.ifop_set_speed = dpdk_eth_if_set_speed,
	.ifop_get_link_status = dpdk_eth_if_get_link_status,
	.ifop_iana_type = dpdk_eth_iana_type,
	.ifop_set_usability = dpdk_eth_if_set_usability,
};

static void dpdk_eth_init(void)
{
	int ret = if_register_type(IFT_ETHER, &dpdk_eth_if_ops);
	if (ret < 0)
		rte_panic("Failed to register DPDK ethernet interface type: %s",
			  strerror(-ret));

	dpdk_name_to_eth_port_map_init();
}

static void dpdk_eth_uninit(void)
{
	dpdk_name_to_eth_port_map_cleanup();
}

static const struct dp_event_ops dpdk_eth_if_events = {
	.init = dpdk_eth_init,
	.uninit = dpdk_eth_uninit,
};

DP_STARTUP_EVENT_REGISTER(dpdk_eth_if_events);

static struct ifnet *
if_hwport_init(const char *if_name, unsigned int portid,
	       const struct rte_ether_addr *eth, int socketid)
{
	struct ifnet *ifp;

	/* device driver couldn't find MAC address */
	if (rte_is_zero_ether_addr(eth)) {
		RTE_LOG(NOTICE, DATAPLANE,
			"%s port %u: address not set!\n", if_name, portid);
		return NULL;
	}

	ifp = if_alloc(if_name, IFT_ETHER, RTE_ETHER_MTU, eth, socketid,
		       &portid);
	if (!ifp)
		return NULL;

	/*
	 * Temporarily turn off VLAN insertion offload for Mellanox
	 * ConnectX5 devices. This should be removed when DPDK is
	 * up-reved to 1908
	 */
	if (is_device_mlx5(portid))
		ifp->tpid_offloaded = 0;

	if (!if_setup_vlan_storage(ifp)) {
		if_free(ifp);
		return NULL;
	}

	return ifp;
}

/*
 * Allocate and initialize a DPDK ethernet interface
 */
struct ifnet *dpdk_eth_if_alloc_w_port(const char *if_name,
				       unsigned int ifindex, portid_t portid)
{
	struct rte_ether_addr mac_addr;
	struct ifnet *ifp;
	int socketid;

	socketid = rte_eth_dev_socket_id(portid);
	rte_eth_macaddr_get(portid, &mac_addr);

	ifp = if_hwport_init(if_name, portid, &mac_addr, socketid);
	if (!ifp)
		return NULL;

	/* Can't set ifp->if_dp_id, we have not been told our dp_id yet */

	/* port is on this dataplane, so if_port is valid */
	ifp->if_local_port = 1;

	/*
	 * Set mac-address driver filtering as initially
	 * supported. This will be reset later if any subsequent
	 * attempt to program filtering in the driver should fail.
	 */
	ifp->if_mac_filtr_supported = 1;
	ifp->if_mac_filtr_reprogram = 0;

	ifp->if_team = lag_is_team(ifp);

	rcu_assign_pointer(ifport_table[portid], ifp);

	if_set_ifindex(ifp, ifindex);

	/* No shadow interfaces for LAG interfaces */
	if (!is_team(ifp)) {
		int rc = shadow_init_port(ifp->if_port, ifp->if_name,
					  &ifp->eth_addr);

		if (rc < 0) {
			char port_name[RTE_ETH_NAME_MAX_LEN];
			RTE_LOG(ERR, DATAPLANE,
				"cannot init shadow interface for %s, port %u\n",
				ifp->if_name, ifp->if_port);
			if (rte_eth_dev_get_name_by_port(ifp->if_port,
							 port_name) < 0)
				RTE_LOG(ERR, DATAPLANE,
					"port(%u) to name  failed\n",
					ifp->if_port);
			else if (detach_device(port_name))
				RTE_LOG(ERR, DATAPLANE,
					"detach device %s failed\n",
					port_name);
		}
	}

	return ifp;
}

struct ifnet *dpdk_eth_if_alloc(const char *if_name, unsigned int ifindex)
{
	portid_t portid;

	portid = dpdk_name_to_eth_port_map_get(if_name);
	if (portid >= DATAPLANE_MAX_PORTS) {
		RTE_LOG(WARNING, DATAPLANE,
			"DPDK port not known for interface %s, not creating\n",
			if_name);
		return NULL;
	}

	return dpdk_eth_if_alloc_w_port(if_name, ifindex, portid);
}
