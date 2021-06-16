/*-
 * Copyright (c) 2019-2021, AT&T Intellectual Property.
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
#include "fal_plugin.h"

struct vhost_info;
struct ifnet;

struct dpdk_eth_if_softc {
	struct rcu_head      scd_rcu;
	struct rte_timer     scd_link_timer; /* update controller */
	struct rte_timer     scd_blink_timer; /* blink LED */
	struct rte_timer     scd_reset_timer; /* reset interface */
	struct vhost_info   *scd_vhost_info;
	bool                 scd_need_reset; /* VF down when PF is down */
	uint8_t		     scd_blink_on;
	bool                 scd_fal_lag_member_created;
	unsigned int         bp_ifindex;     /* backplane interface */
	struct ifnet        *scd_ifp; /* back pointer to the ifp */
	/* Keep track of LAG members */
	struct cds_list_head scd_fal_lag_members_head;
	struct cds_list_head scd_fal_lag_member_link;
	fal_object_t         scd_fal_port_lag_obj; /* Port or LAG FAL object */
	fal_object_t         scd_fal_lag_member_obj; /* LAG member FAL object */
	/* LAG configuration */
	bool		     has_min_links;
	uint16_t	     min_links;
};

void dpdk_eth_if_start_port(struct ifnet *ifp);
void dpdk_eth_if_stop_port(struct ifnet *ifp);
void dpdk_eth_if_force_stop_port(struct ifnet *ifp);
void stop_all_ports(void);
void dpdk_eth_if_update_port_queue_state(portid_t port);
bool dpdk_eth_if_port_started(portid_t port);
void dpdk_eth_if_reset_port(struct rte_timer *tim, void *arg);

char *dpdk_eth_vplaned_devinfo(portid_t port_id);

int dpdk_name_to_eth_port_map_add(const char *ifname, portid_t port);
void dpdk_eth_port_map_del_port(portid_t port);
int dpdk_eth_link_get_nowait(uint16_t port_id, struct rte_eth_link *eth_link);

struct ifnet *dpdk_eth_if_alloc(const char *if_name, unsigned int ifindex);
struct ifnet *dpdk_eth_if_alloc_w_port(const char *if_name,
				       unsigned int ifindex, portid_t portid);

typedef bool (*dpdk_eth_if_walker_t)(struct ifnet *ifp, void *arg);

void dpdk_eth_if_walk(dpdk_eth_if_walker_t walker, void *arg);

#endif /* DPDK_ETH_IF_H */
