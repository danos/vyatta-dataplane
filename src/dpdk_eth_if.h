/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * DPDK Ethernet interfaces
 */

#ifndef	DPDK_ETH_IF_H
#define	DPDK_ETH_IF_H

#include <rte_timer.h>
#include <stdint.h>

#include "urcu.h"
#include "compat.h"

struct vhost_info;

struct dpdk_eth_if_softc {
	struct rcu_head    scd_rcu;
	struct rte_timer   scd_link_timer; /* update controller */
	struct rte_timer   scd_blink_timer; /* blink LED */
	struct rte_timer   scd_reset_timer; /* reset interface */
	struct vhost_info *scd_vhost_info;
	bool               scd_need_reset; /* VF down when PF is down */
	uint8_t		   scd_blink_on;
	unsigned int       bp_ifindex;     /* backplane interface */
};

/*
 * determine if device is Mellanox ConnectX-5
 * This will be used for some short-term customization of dataplane
 * behaviour until we are able to up-rev DPDK to 1908
 */
bool is_device_mlx5(portid_t portid);

#endif /* DPDK_ETH_IF_H */
