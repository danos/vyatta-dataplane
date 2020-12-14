/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef NETLINK_H
#define NETLINK_H

#include <stdbool.h>
#include <stdint.h>

/* Netlink interface */
#include "compat.h"
#include "control.h"
#include "util.h"

struct ifaddrmsg;
struct ifinfomsg;
struct ndmsg;
struct netconfmsg;
struct nlattr;
struct nlmsghdr;
struct rtmsg;

struct netlink_handler {
	int (*link)(const struct nlmsghdr *nh,
		    const struct ifinfomsg *ifi, struct nlattr *tb[],
		    enum cont_src_en cont_src);

	int (*addr)(const struct nlmsghdr *nh,
		    const struct ifaddrmsg *ifa, struct nlattr *tb[],
		    enum cont_src_en cont_src);

	int (*route)(const struct nlmsghdr *nh,
		     const struct rtmsg *rt, struct nlattr *tb[],
		     enum cont_src_en cont_src);

	int (*neigh)(const struct nlmsghdr *nh,
		     const struct ndmsg *nd, struct nlattr *tb[],
		     enum cont_src_en cont_src);

	int (*netconf)(const struct nlmsghdr *nh,
		       const struct netconfmsg *nd, struct nlattr *tb[],
		       enum cont_src_en cont_src);
};

void register_netlink_handler(uint8_t, const struct netlink_handler *);
int rtnl_process(const struct nlmsghdr *nlh, void *data);
int rtnl_process_xfrm(const struct nlmsghdr *nlh, void *data);
int rtnl_process_l2tp(const struct nlmsghdr *nlh, void *data);
int rtnl_process_team(const struct nlmsghdr *nlh, void *data);
int rtnl_process_xfrm_sa(const struct nlmsghdr *nlh, void *data);

int notify_route(const struct nlmsghdr *nlh, enum cont_src_en cont_src);
/* Temporary code to adjust to hardwired uplink VRF */
struct ifnet;

bool netlink_uplink_vrf(enum cont_src_en cont_src,
			vrfid_t *vrf_id);
struct ifnet *lo_or_dummy_create(enum cont_src_en cont_src,
				 unsigned int ifindex,
				 unsigned int flags,
				 const char *ifname,
				 unsigned int mtu,
				 const struct rte_ether_addr *eth_addr);

#endif /* NETLINK_H */
