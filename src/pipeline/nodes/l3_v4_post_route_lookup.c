/*
 * l3_v4_post_route_lookup.c
 *
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if.h>
#include <linux/snmp.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "if/macvlan.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "ip_ttl.h"
#include "mpls/mpls.h"
#include "mpls/mpls_forward.h"
#include "nh_common.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "route.h"
#include "route_flags.h"
#include "snmp_mib.h"
#include "urcu.h"

ALWAYS_INLINE unsigned int
ipv4_post_route_lookup_process(struct pl_packet *pkt, void *context __unused)
{
	struct next_hop *nxt = pkt->nxt.v4;
	struct ifnet *ifp = pkt->in_ifp;

	/* no nexthop found, send icmp error */
	if (unlikely(!nxt)) {
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INNOROUTES);
		icmp_error(ifp, pkt->mbuf, ICMP_DEST_UNREACH,
			   ICMP_NET_UNREACH, 0);
		return IPV4_POST_ROUTE_LOOKUP_DROP;
	}
	if (unlikely(nxt->flags & (RTF_SLOWPATH | RTF_LOCAL)))
		return IPV4_POST_ROUTE_LOOKUP_LOCAL;

	struct iphdr *ip = pkt->l3_hdr;
	decrement_ttl(ip);

	/*
	 * Immediately drop blackholed traffic, and directed broadcasts
	 * for either the all-ones or all-zero subnet addresses on
	 * locally attached networks.
	 */
	if (unlikely(nxt->flags & (RTF_BLACKHOLE|RTF_BROADCAST|RTF_REJECT))) {
		if (nxt->flags & RTF_REJECT)
			icmp_error(ifp, pkt->mbuf, ICMP_DEST_UNREACH,
				   ICMP_HOST_UNREACH, 0);
		if (unlikely(IN_LOOPBACK(ntohl(ip->daddr))))
			IPSTAT_INC(if_vrfid(ifp), IPSTATS_MIB_INADDRERRORS);

		return IPV4_POST_ROUTE_LOOKUP_DROP;
	}

	/* MPLS imposition required because nh has given us a label */
	if (unlikely(nh_outlabels_present(&nxt->outlabels))) {
		mpls_unlabeled_input(ifp, pkt->mbuf,
				     NH_TYPE_V4GW, nxt, ip->ttl);
		return IPV4_POST_ROUTE_LOOKUP_CONSUME;
	}

	/* nxt->ifp may be changed by netlink messages. */
	struct ifnet *nxt_ifp = dp_nh_get_ifp(nxt);

	/* Destination device is not up? */
	if (unlikely(!nxt_ifp || !(nxt_ifp->if_flags & IFF_UP))) {
		icmp_error(ifp, pkt->mbuf, ICMP_DEST_UNREACH,
			   ICMP_HOST_UNREACH, 0);
		return IPV4_POST_ROUTE_LOOKUP_DROP;
	}

	pktmbuf_clear_rx_vlan(pkt->mbuf);

	/*
	 * If forwarding packet using same interface that it came in on,
	 * perhaps should send a redirect to sender to shortcut a hop.
	 * Only send redirect if source is sending directly to us,
	 * Also, don't send redirect if forwarding using a default route
	 * or a route modified by a redirect.
	 */
	if (unlikely(nxt_ifp == ifp)) {
		in_addr_t addr;
		/* Store next hop address  */
		if (nxt->flags & RTF_GATEWAY)
			addr = nxt->gateway.address.ip_v4.s_addr;
		else
			addr = ip->daddr;
		if (ip_same_network(ifp, addr, ip->saddr) &&
		    ip_redirects_get())
			icmp_error(ifp, pkt->mbuf, ICMP_REDIRECT,
				   ICMP_REDIR_HOST, addr);
	}

	/* macvlan mac passthrough check & replace ifp */
	pkt->out_ifp = macvlan_check_vrrp_if(nxt_ifp);

	return IPV4_POST_ROUTE_LOOKUP_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_post_route_lookup_node) = {
	.name = "vyatta:ipv4-post-route-lookup",
	.type = PL_PROC,
	.handler = ipv4_post_route_lookup_process,
	.num_next = IPV4_POST_ROUTE_LOOKUP_NUM,
	.next = {
		[IPV4_POST_ROUTE_LOOKUP_ACCEPT]  = "ipv4-out",
		[IPV4_POST_ROUTE_LOOKUP_DROP]    = "term-drop",
		[IPV4_POST_ROUTE_LOOKUP_LOCAL]   = "ipv4-local",
		[IPV4_POST_ROUTE_LOOKUP_CONSUME] = "term-finish",
	}
};
