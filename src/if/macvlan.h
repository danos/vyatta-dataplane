/*-
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef MACVLAN_H
#define MACVLAN_H


#include <netinet/in.h>

struct rte_ether_addr;
struct ifnet;
struct mvl_tbl;
struct rte_mbuf;

struct ifnet *
macvlan_create(struct ifnet *ifp, const char *mvl_name,
	       const struct rte_ether_addr *eth_addr, int ifindex);

void
macvlan_table_flush(struct mvl_tbl *mvlt);

void
macvlan_flood(struct ifnet *ifp, struct rte_mbuf *m);

struct ifnet *
macvlan_get_vrrp_ip_if(struct ifnet *ifp, struct sockaddr *target);

struct ifnet *
macvlan_input(struct ifnet *ifp, struct rte_mbuf *m);

struct ifnet *
macvlan_check_vrrp_if(struct ifnet *ifp);

struct ifnet *
macvlan_get_vrrp_if(const struct ifnet *ifp,
		    const struct rte_ether_addr *dst_mac);

void macvlan_output(struct ifnet *ifp, struct rte_mbuf *mbuf,
		    struct ifnet *input_ifp, uint16_t proto);

#endif
