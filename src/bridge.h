/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef BRIDGE_H
#define BRIDGE_H

/*
 * Bridge routines
 */

#include <netinet/in.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <urcu/list.h>

#include "fal_plugin.h"
#include "bridge_port.h"
#include "pktmbuf.h"
#include "urcu.h"
#include "util.h"

struct ifnet;
struct rte_mbuf;
struct nlattr;

#define	BRIDGE_CONSUMED	1
#define	BRIDGE_PASS	0


/*
 * Per vlan stats
 */
struct bridge_vlan_stats {
	uint64_t rx_octets;
	uint64_t rx_pkts;
	uint64_t rx_ucast_pkts;
	uint64_t rx_nucast_pkts;
	uint64_t tx_octets;
	uint64_t tx_pkts;
	uint64_t tx_ucast_pkts;
	uint64_t tx_nucast_pkts;
	/* end of first cache line */
	uint64_t rx_drops;
	uint64_t rx_errors;
	uint64_t tx_drops;
	uint64_t tx_errors;
} __rte_cache_aligned;

struct bridge_vlan_stat_block {
	struct rcu_head vlan_stats_rcu;
	struct bridge_vlan_stats stats[];
};

/*
 * Bridge keys consist of an ethernet address and the VLAN
 */
struct bridge_key {
	struct ether_addr addr;
	uint16_t          vlan;
};

/*
 * Bridge route node.
 */
struct bridge_rtnode {
	struct rcu_head		brt_rcu;	/* for deletion via rcu */
	struct cds_lfht_node	brt_node;	/* hash table node  */
	struct ifnet		*brt_difp;	/* destination if */
	struct bridge_key brt_key;
	uint8_t			brt_flags;	/* address flags */
	uint8_t			brt_expire;
	rte_atomic32_t          brt_unused;     /* 0 = used */
	uint32_t		brt_dip;
};

struct mstp_bridge;

struct bridge_softc {
	struct rte_timer	scbr_timer;
	struct cds_lfht         *scbr_rthash;	/* hash table linkage */
	struct cds_list_head	scbr_porthead;	/* tailq of ports */
	struct rcu_head		scbr_rcu;
	/* ageing time divided by seconds per tick.  0 == don't age */
	uint32_t		scbr_ageing_ticks;

	/* fields for VLAN aware mode */
	bool			scbr_vlan_filter;
	uint16_t		scbr_vlan_default_pvid;

	/* FAL spanning-tree object */
	fal_object_t            stp;

	/* MSTP additions */
	struct mstp_vlan2mstiindex *scbr_vlan2mstiindex;
	struct mstp_bridge      *scbr_mstp;

	/* Stats per vlan for switches */
	struct bridge_vlan_stat_block *vlan_stats[VLAN_N_VID];
};

/*
 * Netlink update bridge info. Only contains the fields we actually need.
 */
struct nl_bridge_info {
	uint32_t br_ageing_time;
	uint8_t  br_vlan_filter;
	uint16_t br_vlan_default_pvid;
};

/*
 * Netlink bridge port vlan information
 */
struct nl_bridge_vlan_info {
	uint16_t flags;
	uint16_t vid;
};

#define bridge_for_each_brport(brport, entry, sc)	\
	for (entry = rcu_dereference((sc)->scbr_porthead.next),		\
		     brport = bridge_port_from_list_entry(entry);	\
	     entry != (&(sc)->scbr_porthead);				\
	     entry = rcu_dereference(entry->next),			\
		     brport = bridge_port_from_list_entry(entry))


const char *bridge_get_ifstate_string(uint8_t brstate);

void bridge_input(struct bridge_port *port, struct rte_mbuf *m);

int
bridge_newneigh_tunnel(struct bridge_port *brport, const struct ether_addr *dst,
		       in_addr_t dst_ip, uint16_t vlan);

void bridge_output(struct ifnet *ifp, struct rte_mbuf *m, struct ifnet *in_ifp);

fal_object_t bridge_fal_stp_object(const struct ifnet *ifp);
void bridge_upd_hw_forwarding(const struct ifnet *port);

struct ifnet *bridge_create(int ifindex, const char *ifname,
			    unsigned int mtu,
			    const struct ether_addr *eth_addr);
void bridge_update(const char *ifname,
		   struct nl_bridge_info *br_info);
void bridge_nl_modify(struct ifnet *ifp, struct nlattr *kdata);
struct ifnet *bridge_nl_create(int ifindex, const char *ifname,
			       unsigned int mtu,
			       const struct ether_addr *eth_addr,
			       struct nlattr *kdata);

void bridge_fdb_dynamic_flush_vlan(struct ifnet *bridge, struct ifnet *port,
				   uint16_t vlanid);

/*
 * forward or flood a packet to local ports
 * TBD: input interface to be passed in metadata to help learning
 *      output interface to be passed in metadata to avoid second lookup
 */
void bridge_forward_flood_local(struct ifnet *br_ifp, struct ifnet *in_ifp,
				struct rte_mbuf *m, struct ifnet *out_ifp);
int cmd_bridge(FILE *f, int argc, char **argv);

struct ifnet *bridge_cmd_get_port(FILE *f, struct ifnet *bridge,
				  const char *port_name);
int bridge_vlan_clear_software_stat(struct bridge_softc *sc,
				    uint16_t vlan);
#endif
