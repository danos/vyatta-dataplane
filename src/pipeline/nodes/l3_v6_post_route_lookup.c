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
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <linux/if.h>
#include <rte_branch_prediction.h>
#include <rte_per_lcore.h>
#include <stdint.h>

#include "compiler.h"
#include "if/macvlan.h"
#include "if_var.h"
#include "mpls/mpls.h"
#include "mpls/mpls_forward.h"
#include "netinet6/ip6_funcs.h"
#include "nh.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "route_flags.h"
#include "route_v6.h"
#include "urcu.h"

static RTE_DEFINE_PER_LCORE(struct next_hop, ll_nexthop);

ALWAYS_INLINE unsigned int
ipv6_post_route_lookup_process(struct pl_packet *pkt, void *context __unused)
{
	struct next_hop *nxt = pkt->nxt.v6;
	struct ifnet *ifp = pkt->in_ifp;
	struct ip6_hdr *ip6 = pkt->l3_hdr;

	if (unlikely(IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst))) {
		/* Can only forward LL out arrival interface */
		RTE_PER_LCORE(ll_nexthop.flags) = 0;
		nxt = &RTE_PER_LCORE(ll_nexthop);
		nh_set_ifp(nxt, ifp);
		pkt->nxt.v6 = nxt;
	}

	/* no nexthop found, send icmp error */
	if (unlikely(!nxt)) {
		ip6_unreach(ifp, pkt->mbuf);
		return IPV6_POST_ROUTE_LOOKUP_FINISH;
	} else if (unlikely(nxt->flags & (RTF_SLOWPATH | RTF_LOCAL)))
		return IPV6_POST_ROUTE_LOOKUP_LOCAL;

	ip6->ip6_hlim -= IPV6_HLIMDEC;
	/* Immediately drop blackholed traffic. */
	if (unlikely(nxt->flags & RTF_BLACKHOLE)) {
		/*
		 * These are address errors, but we use the LPM to check for
		 * them.
		 */
		if (unlikely(IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_dst)) ||
		    unlikely(IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst)) ||
		    unlikely(IN6_IS_ADDR_V4MAPPED(&ip6->ip6_dst))) {
			if (pkt->in_ifp)
				IP6STAT_INC_IFP(pkt->in_ifp,
						IPSTATS_MIB_INADDRERRORS);
			rte_pktmbuf_free(pkt->mbuf);
			pkt->mbuf = NULL;
			return IPV6_POST_ROUTE_LOOKUP_FINISH;
		}

		return IPV6_POST_ROUTE_LOOKUP_DROP;
	}

	if (unlikely(nxt->flags & RTF_REJECT)) {
		icmp6_error(ifp, pkt->mbuf, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_ADDR, htonl(0));
		return IPV6_POST_ROUTE_LOOKUP_FINISH;
	}

	/* MPLS imposition required because nh has given us a label */
	if (unlikely(nh_outlabels_present(&nxt->outlabels))) {
		mpls_unlabeled_input(ifp, pkt->mbuf,
				     NH_TYPE_V6GW, nxt, ip6->ip6_hops);
		return IPV6_POST_ROUTE_LOOKUP_FINISH;
	}

	/* nxt->ifp may be changed by netlink messages. */
	struct ifnet *nxt_ifp = dp_nh_get_ifp(nxt);

	/* Destination device is not up? */
	if (unlikely(!nxt_ifp || !(nxt_ifp->if_flags & IFF_UP))) {
		icmp6_error(ifp, pkt->mbuf, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_ADDR, htonl(0));
		return IPV6_POST_ROUTE_LOOKUP_FINISH;
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
		/*
		 * If the incoming interface is equal to the
		 * outgoing one, and the link attached to the
		 * interface is point-to-point, then it will be
		 * highly probable that a routing loop occurs.
		 * Thus, we immediately drop the packet and
		 * send an ICMPv6 error message.
		 *
		 * type/code is based on suggestion by Rich
		 * Draves. not sure if it is the best pick.
		 */
		if ((ifp->if_flags & IFF_POINTOPOINT) != 0 ||
		    is_tunnel(ifp)) {
			icmp6_error(ifp, pkt->mbuf, ICMP6_DST_UNREACH,
				    ICMP6_DST_UNREACH_ADDR,
				    htonl(0));
			return IPV6_POST_ROUTE_LOOKUP_FINISH;
		}
		icmp6_redirect(ifp, pkt->mbuf, nxt);
	}

	/* macvlan mac passthrough check & replace ifp */
	pkt->out_ifp = macvlan_check_vrrp_if(nxt_ifp);

	return IPV6_POST_ROUTE_LOOKUP_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(ipv6_post_route_lookup_node) = {
	.name = "vyatta:ipv6-post-route-lookup",
	.type = PL_PROC,
	.handler = ipv6_post_route_lookup_process,
	.num_next = IPV6_POST_ROUTE_LOOKUP_NUM,
	.next = {
		[IPV6_POST_ROUTE_LOOKUP_ACCEPT] = "ipv6-out",
		[IPV6_POST_ROUTE_LOOKUP_DROP]   = "ipv6-drop",
		[IPV6_POST_ROUTE_LOOKUP_LOCAL]  = "ipv6-local",
		[IPV6_POST_ROUTE_LOOKUP_FINISH] = "term-finish"
	}
};
