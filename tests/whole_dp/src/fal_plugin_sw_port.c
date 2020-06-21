/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdio.h>
#include "dp_test_lib_internal.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_netlink_state_internal.h"
#include "fal_plugin_test.h"
#include <vyatta_swport.h>
#include  "fal_plugin.h"
#include "fal_plugin_sw_port.h"
#include "fal_plugin_framer.h"
#include "dp_test_sfp.h"

struct fal_sw_port {
	int unit;
	int port;
	uint16_t port_id;
	uint16_t bp;
	char *name;
	struct rte_eth_link link;
	void *sw_port;
} fal_sw_port_0, fal_sw_port_7;

#define EDSA_PROTO 0xdada

static int
eth_dev_configure(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static int
eth_dev_set_link(struct rte_eth_dev *dev, int state)
{
	struct fal_sw_port *port = sw_port_fal_priv_from_dev(dev);

	port->link.link_speed = ETH_SPEED_NUM_10G;
	port->link.link_duplex = ETH_LINK_FULL_DUPLEX;
	port->link.link_status = state;

	return 0;
}

static int
eth_dev_set_link_up(struct rte_eth_dev *dev)
{
	return eth_dev_set_link(dev, ETH_LINK_UP);
}

static int
eth_dev_set_link_down(struct rte_eth_dev *dev)
{
	return eth_dev_set_link(dev, ETH_LINK_DOWN);
}

static int
eth_link_update(struct rte_eth_dev *dev, int wait_to_complete __rte_unused)
{
	struct fal_sw_port *bport = sw_port_fal_priv_from_dev(dev);

	sw_port_fal_report_link(bport->sw_port, &bport->link);

	return 0;
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	eth_dev_set_link_up(dev);
	return 0;
}

static void
eth_dev_stop(struct rte_eth_dev *dev)
{
	eth_dev_set_link_down(dev);
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev __rte_unused,
		   uint16_t rx_queue_id __rte_unused,
		   uint16_t nb_rx_desc __rte_unused,
		   unsigned int socket_id __rte_unused,
		   const struct rte_eth_rxconf *rx_conf __rte_unused,
		   struct rte_mempool *mb_pool __rte_unused)
{
	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev __rte_unused,
		   uint16_t queue_id __rte_unused,
		   uint16_t nb_tx_desc __rte_unused,
		   unsigned int socket_id __rte_unused,
		   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	return 0;
}

static int
eth_dev_info(struct rte_eth_dev *dev __rte_unused,
	struct rte_eth_dev_info *dev_info __rte_unused)
{
	return 0;
}

static int
eth_stats_get(struct rte_eth_dev *dev __rte_unused,
	      struct rte_eth_stats *stats __rte_unused)
{
	return 0;
}

static int
eth_stats_reset(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}

static void
eth_mac_addr_remove(struct rte_eth_dev *dev __rte_unused,
	uint32_t index __rte_unused)
{
}

static int
eth_mac_addr_add(struct rte_eth_dev *dev __rte_unused,
	struct rte_ether_addr *mac_addr __rte_unused,
	uint32_t index __rte_unused,
	uint32_t vmdq __rte_unused)
{
	return 0;
}

static void
eth_queue_release(void *q __rte_unused)
{
}


static const struct eth_dev_ops eth_ops = {
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_set_link_up = eth_dev_set_link_up,
	.dev_set_link_down = eth_dev_set_link_down,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_release = eth_queue_release,
	.tx_queue_release = eth_queue_release,
	.link_update = eth_link_update,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
	.mac_addr_remove = eth_mac_addr_remove,
	.mac_addr_add = eth_mac_addr_add,
	.get_module_info = dp_test_get_module_info,
	.get_module_eeprom = dp_test_get_module_eeprom,
};

#define SW_PORT_0_0 "dp1sw_port_0_0"
#define SW_PORT_0_7 "dp1sw_port_0_7"

static uint16_t
fal_plugin_tx_backplane_cb(void *fal_info, uint16_t backplane, uint16_t port,
			   struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	return fal_tx_pkt_burst(backplane, bufs, nb_bufs);
}

void fal_plugin_sw_ports_create(void)
{
	struct sw_port_create_args args;
	uint16_t backplane;

	memset(&args, 0, sizeof(args));

	fal_sw_port_0.unit = 0;
	fal_sw_port_0.port = 0;
	args.hw_unit = fal_sw_port_0.unit;
	args.hw_port = fal_sw_port_0.port;

	args.plugin_private = &fal_sw_port_0;
	args.plugin_dev_ops = &eth_ops;
	args.plugin_tx = fal_plugin_tx_backplane_cb;
	args.plugin_tx_framer = plugin_framer_tx;

	rte_eth_dev_get_port_by_name("net_ring_eth_ring10", &backplane);
	args.bp_interconnect_port = backplane;
	fal_sw_port_0.bp = backplane;

	args.mac = dp_test_intf_name2mac(SW_PORT_0_0);
	args.rx_queues = 1;
	args.tx_queues = 1;

	sw_port_create(&args);
	/* save sw_port ctx for use calling APIs */
	fal_sw_port_0.sw_port = args.fal_switch_port;
	fal_sw_port_0.port_id = args.dpdk_port_id;

	/*
	 * Create a second port that does not use a backplane interconnect
	 * and passes in part of the port name
	 */
	fal_sw_port_7.unit = 0;
	fal_sw_port_7.port = 7;
	fal_sw_port_0.bp = 0;
	args.hw_unit = fal_sw_port_7.unit;
	args.hw_port = fal_sw_port_7.port;
	args.bp_interconnect_port = 0;
	args.port_name = "port7";
	args.plugin_private = &fal_sw_port_7;
	args.plugin_tx = NULL;
	args.flags = SWITCH_PORT_FLAG_RX_RING_CREATE |
		SWITCH_PORT_FLAG_TX_RING_CREATE;
	args.mac = dp_test_intf_name2mac(SW_PORT_0_7);
	args.rx_queues = 1;
	args.tx_queues = 1;

	sw_port_create(&args);

	/* save sw_port ctx for use calling APIs */
	fal_sw_port_7.sw_port = args.fal_switch_port;
	fal_sw_port_0.port_id = args.dpdk_port_id;
}

__externally_visible
bool fal_plugin_ut_enable_rx_framer(bool enabled)
{
	uint16_t backplane;

	rte_eth_dev_get_port_by_name("net_ring_eth_ring10", &backplane);
	return fal_rx_bp_framer_enable(enabled, backplane, true, EDSA_PROTO,
				   plugin_framer_rcv);
}

int __externally_visible
fal_plugin_add_ut_framer_hdr(const char *name, struct rte_mbuf *mbuf)
{
	struct fal_sw_port *fal_sw_port;

	if (!strcmp(name, SW_PORT_0_0))
		fal_sw_port = &fal_sw_port_0;
	else
		if (!strcmp(name, SW_PORT_0_7))
			fal_sw_port = &fal_sw_port_7;
		else
			return -1;

	return plugin_framer_tx(fal_sw_port->sw_port, fal_sw_port, &mbuf);
}

int __externally_visible
fal_plugin_get_sw_port_info(struct fal_sw_port *fal_sw_port, uint16_t *proto,
			    uint8_t *dev, uint8_t *port)
{
	if (!fal_sw_port)
		return -1;

	*proto = EDSA_PROTO;
	*dev = fal_sw_port->unit;
	*port = fal_sw_port->port;
	return 0;
}

int __externally_visible
fal_plugin_queue_rx_direct(const char *name, struct rte_mbuf *mbuf)
{
	struct fal_sw_port *fal_sw_port;

	if (!strcmp(name, SW_PORT_0_0))
		fal_sw_port = &fal_sw_port_0;
	else
		if (!strcmp(name, SW_PORT_0_7))
			fal_sw_port = &fal_sw_port_7;
		else
			return -1;

	return sw_port_enqueue_rx_mbuf(fal_sw_port->sw_port, 0, &mbuf, 1);
}

int __externally_visible
fal_plugin_backplane_from_sw_port(const char *name, uint16_t *dpdk_port)
{
	struct fal_sw_port *fal_sw_port;

	if (!strcmp(name, SW_PORT_0_0))
		fal_sw_port = &fal_sw_port_0;
	else
		if (!strcmp(name, SW_PORT_0_7))
			fal_sw_port = &fal_sw_port_7;
		else
			return -1;

	*dpdk_port = fal_sw_port->bp;

	return 0;
}
