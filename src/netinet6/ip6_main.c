/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * IPv6 initialization into the dataplane
 */
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <linux/netconf.h>
#include <rte_config.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <stdint.h>

#include "if_var.h"
#include "ip6_funcs.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pl_node.h"
#include "route_v6.h"
#include "snmp_mib.h"
#include "vplane_debug.h"
#include "vplane_log.h"

struct nlattr;

struct ipstats_mib ip6stats[RTE_MAX_LCORE] __rte_cache_aligned;
uint64_t icmp6stats[ICMP6_MIB_MAX];

/* Attribute changed */
void ipv6_netconf_change(struct ifnet *ifp, struct nlattr *tb[])
{
	bool forwarding = false;

	if (tb[NETCONFA_FORWARDING]) {
		forwarding = mnl_attr_get_u32(tb[NETCONFA_FORWARDING]);
		if (forwarding)
			pl_node_remove_feature_by_inst(
				&ipv6_in_no_forwarding_feat, ifp);
		else
			pl_node_add_feature_by_inst(
				&ipv6_in_no_forwarding_feat, ifp);

		fal_if_update_forwarding(ifp, AF_INET6, false);
	}

	if (tb[NETCONFA_MC_FORWARDING]) {
		ifp->ip6_mc_forwarding = mnl_attr_get_u32(tb[NETCONFA_MC_FORWARDING]);
		fal_if_update_forwarding(ifp, AF_INET6, true);
	}

	DP_DEBUG(NETLINK_NETCONF, DEBUG, DATAPLANE,
		 "%s ipv6 forwarding %d mc_forwarding %d\n",
		 ifp->if_name,
		 forwarding, ifp->ip6_mc_forwarding);
}

void ip6_init(void)
{
	nexthop_v6_tbl_init();
}
