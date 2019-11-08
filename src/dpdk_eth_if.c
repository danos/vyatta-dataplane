/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * DPDK port-backed interface implementation
 */

#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_pci.h>
#ifdef HAVE_RTE_BUS_PCI_H
#include <rte_bus_pci.h>
#endif

#include "dpdk_eth_if.h"
#include "dp_event.h"
#include "ether.h"
#include "if_var.h"
#include "lag.h"
#include "vhost.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "transceiver.h"

#define MODULE_SFF_8436_AX_LEN 640

static inline bool
is_jumbo_size(uint32_t size)
{
	return size > ETHER_MTU;
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
		 * each of the slaves and will update the slave
		 * adapters at that point. But we need to keep
		 * ifp->if_mtu up to date.
		 */
		goto out;
	}

	if (ifp->qinq_vif_cnt)
		adjusted_mtu = adjusted_mtu + 4;

	/*
	 * If the interface has qos on it then we need to stop it
	 * and restart it to get QoS to recalculate its token bucket
	 * size based upon the new MTU.
	 *
	 * If it does not have QoS on it then we may have to stop it
	 * anyway as some drivers always need the port to be stopped (i40)
	 * for the mtu to be changed. Some drivers need the port to be
	 * stopped to transition into/outof jumbo range (ixgbe).
	 * Unfortunately we can't tell this ahead of time, so try to
	 * set the mtu, and if we get an error then stop the ports and
	 * try again.
	 *
	 * If we are transitioning into/outof jumbo range then we have to
	 * reconfigure the port to get the correct jumbo settings.
	 */
	bool mtu_jumbo_change =
		(is_jumbo_size(ifp->if_mtu_adjusted) &&
			!is_jumbo_size(mtu)) ||
		(is_jumbo_size(mtu) &&
			!is_jumbo_size(ifp->if_mtu_adjusted));

	/* Try and set it. If we get an error try again with port stopped */
	if (!mtu_jumbo_change && !ifp->if_qos)
		err = rte_eth_dev_set_mtu(ifp->if_port, adjusted_mtu);

	/*
	 * We must update the interface's adjusted MTU before
	 * starting the port so that QoS can recalculate its
	 * token bucket size based upon the new MTU.
	 *
	 * Also used in the reconfigure_port callback.
	 */
	ifp->if_mtu_adjusted = adjusted_mtu;

	/* Try again, but this time after changing the port config */
	if (mtu_jumbo_change || err || ifp->if_qos) {
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
	struct ether_addr *macaddr = l2_addr;
	char b1[32], b2[32];

	if (l2_addr_len != ETHER_ADDR_LEN) {
		RTE_LOG(NOTICE, DATAPLANE,
			"link address is not ethernet (len=%u)!\n",
			l2_addr_len);
		return -EINVAL;
	}

	if (ether_addr_equal(&ifp->eth_addr, macaddr))
		return 1;

	RTE_LOG(INFO, DATAPLANE, "%s change MAC from %s to %s\n",
		ifp->if_name,
		ether_ntoa_r(&ifp->eth_addr, b1),
		ether_ntoa_r(macaddr, b2));

	int rc;

	if (ifp->if_team)
		rc = rte_eth_bond_mac_address_set(
			ifp->if_port, macaddr);
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
	start_port(ifp->if_port, ifp->if_flags);
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
	if (ifp->aggregator && lag_port_is_slave(ifp->aggregator, ifp))
		return 0;

	stop_port(ifp->if_port);
	if (if_port_is_bkplane(ifp->if_port))
		ifpromisc(ifp, false);

	return 0;
}

static int
dpdk_eth_if_add_l2_addr(struct ifnet *ifp, void *l2_addr)
{
	/*
	 * The bonding PMD doesn't support normal MAC address
	 * operations, and neither does it return ENOTSUP from the
	 * functions, so return it explicitly here.
	 */
	if (ifp->if_team)
		return -ENOTSUP;

	return rte_eth_dev_mac_addr_add(ifp->if_port, l2_addr, 0);
}

static int
dpdk_eth_if_del_l2_addr(struct ifnet *ifp, void *l2_addr)
{
	/*
	 * The bonding PMD doesn't support normal MAC address
	 * operations, and neither does it return ENOTSUP from the
	 * functions, so return it explicitly here.
	 */
	if (ifp->if_team)
		return -ENOTSUP;

	return rte_eth_dev_mac_addr_remove(ifp->if_port, l2_addr);
}

static int dpdk_eth_if_init(struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc;

	sc = rte_zmalloc_socket("dpdk softc", sizeof(*sc), 0, ifp->if_socket);
	if (!sc)
		return -ENOMEM;

	rte_timer_init(&sc->scd_link_timer);
	rte_timer_init(&sc->scd_blink_timer);
	rte_timer_init(&sc->scd_reset_timer);

	ifp->if_softc = sc;

	ether_addr_copy(&ifp->eth_addr, &ifp->perm_addr);

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

	/* to cope with freeing after errors during initialisation of ifp */
	if (!sc)
		return;

	rte_timer_stop(&sc->scd_link_timer);
	rte_timer_stop(&sc->scd_blink_timer);
	rte_timer_stop(&sc->scd_reset_timer);

	rcu_assign_pointer(ifp->if_softc, NULL);

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
	/*
	 * This interface is under the control of bonding PMD
	 * so don't make any changes to it.
	 */
	if (ifp->aggregator)
		return 0;

	if (enable)
		rte_eth_promiscuous_enable(ifp->if_port);
	else
		rte_eth_promiscuous_disable(ifp->if_port);

	return 0;
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
		/*
		 * workaround to determine switch id until we have
		 * a mechanism for retrieving opaque data
		 */
		if (get_switch_dev_info(info.driver_name, dev->data->name,
					&hw_switch, NULL))
			jsonw_uint_field(wr, "hw_switch_id", hw_switch);
	}

#ifdef HAVE_RTE_ETH_DEV_INFO_DEVICE
	const struct rte_bus *bus = rte_bus_find_by_device(info.device);
	struct rte_pci_device *pci = NULL;
	if (bus && streq(bus->name, "pci"))
		pci = RTE_DEV_TO_PCI(info.device);
#else
	const struct rte_pci_device *pci = info.pci_dev;
#endif
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
	sfp_status(&module_info, &eeprom_info, wr);
	jsonw_end_object(wr);
	free(buf);
}

static int
dpdk_eth_if_dump(struct ifnet *ifp, json_writer_t *wr,
		 enum if_dump_state_type type)
{
	if (!ifp->if_local_port)
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
	uint64_t xstat_ids[NUM_XSTATS] = { -1 };
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
		if (xstat_ids[i] == (uint64_t) -1)
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

/* Timer called (from master) to toggle state of LED. */
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
};

static void dpdk_eth_init(void)
{
	int ret = if_register_type(IFT_ETHER, &dpdk_eth_if_ops);
	if (ret < 0)
		rte_panic("Failed to register DPDK ethernet interface type: %s",
			  strerror(-ret));
}

static const struct dp_event_ops dpdk_eth_if_events = {
	.init = dpdk_eth_init,
};

DP_STARTUP_EVENT_REGISTER(dpdk_eth_if_events);

bool is_device_mlx5(portid_t portid)
{
	struct rte_eth_dev_info dev_info;

	if (!rte_eth_dev_is_valid_port(portid))
		return false;

	rte_eth_dev_info_get(portid, &dev_info);
	if (strstr(dev_info.driver_name, "net_mlx5") == dev_info.driver_name)
		return true;

	return false;
}
