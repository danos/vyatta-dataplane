/*-
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_ether.c	8.1 (Berkeley) 6/10/93
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <net/if_arp.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <urcu/list.h>

#include "arp.h"
#include "compat.h"
#include "config_internal.h"
#include "ether.h"
#include "if/gre.h"
#include "if/macvlan.h"
#include "if_ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "ip_addr.h"
#include "main.h"
#include "nh_common.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pktmbuf_internal.h"
#include "route.h"
#include "route_flags.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"

/*
 * Since Dataplane only supports Ethernet, use a simplified form of ARP
 * data structuctures (from old BSD)
 */

/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	u_int8_t arp_sha[RTE_ETHER_ADDR_LEN];/* sender hardware address */
	u_int8_t arp_spa[4];		/* sender protocol address */
	u_int8_t arp_tha[RTE_ETHER_ADDR_LEN];/* target hardware address */
	u_int8_t arp_tpa[4];		/* target protocol address */
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op

/* Debugging messages */
#define ARP_DEBUG(format, args...)	\
	DP_DEBUG(ARP, DEBUG, ARP, format, ##args)

/* Turn a request into a reply and send it */
static int arp_reply(struct ifnet *ifp, struct rte_mbuf *m,
		     const struct rte_ether_addr *ea, in_addr_t taddr)
{
	struct rte_ether_hdr *eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct ether_arp *ah = (struct ether_arp *) (eh + 1);
	in_addr_t dst_ip;

	ah->arp_op = htons(ARPOP_REPLY);

	memcpy(ah->arp_tha, ah->arp_sha, RTE_ETHER_ADDR_LEN);
	memcpy(ah->arp_sha, ea, RTE_ETHER_ADDR_LEN);

	memcpy(ah->arp_tpa, ah->arp_spa, sizeof(struct in_addr));
	memcpy(ah->arp_spa, &taddr, sizeof(struct in_addr));

	memcpy(&eh->d_addr, ah->arp_tha, RTE_ETHER_ADDR_LEN);
	memcpy(&eh->s_addr, ah->arp_sha, RTE_ETHER_ADDR_LEN);

	char b1[INET_ADDRSTRLEN], b2[ETH_ADDR_STR_LEN];
	ARP_DEBUG("send reply for %s (%s) on %s\n",
		  inet_ntop(AF_INET, &taddr, b1, sizeof(b1)),
		  ether_ntoa_r((const struct rte_ether_addr *)(ah->arp_sha),
			       b2),
		  ifp->if_name);

	ARPSTAT_INC(if_vrfid(ifp), txreplies);

	if (is_gre(ifp) && !(ifp->if_flags & IFF_NOARP)) {
		memcpy(&dst_ip, ah->arp_tpa, sizeof(ah->arp_tpa));
		if (!gre_tunnel_encap(ifp, ifp, &dst_ip, m, RTE_ETHER_TYPE_ARP))
			return ARP_IN_NOTHOT_FINISH;
	}
	return ARP_IN_NOTHOT_L2_OUT;
}

/* Answer arp responses for other host?
 * Two kinds of proxy:
 *  1. Entry can be marked as proxy (neighbour in Linux)
 *  2. Interface is configured to do proxy arp
 */
static bool arp_proxy(struct ifnet *ifp, in_addr_t addr, struct rte_mbuf *m,
		      int *resp)
{
	struct llentry *la;

	la = in_lltable_lookup(ifp, 0, addr);
	/* Per-entry flag used by controller in multi-dataplane */
	if (la && (la->la_flags & LLE_PROXY)) {
		*resp = arp_reply(ifp, m, &la->ll_addr, addr);
		return true;
	}

	if (!ifp->ip_proxy_arp)
		return false;

	/* Is there a route to this address */
	pktmbuf_set_vrf(m, if_vrfid(ifp));
	struct next_hop *nxt = dp_rt_lookup(addr, RT_TABLE_MAIN, m);
	if (nxt == NULL ||
	    (nxt->flags & (RTF_REJECT|RTF_BLACKHOLE|RTF_BROADCAST)))
		return false;

	/* Don't send proxy if on same interface */
	if (dp_nh_get_ifp(nxt) == ifp)
		return false;

	/* Respond with own address */
	*resp = arp_reply(ifp, m, &ifp->eth_addr, addr);
	return true;
}

/* VYATTA: unlike Linux (and BSD) only respond to ARP requests
 * only if the target IP address is configured on the incoming interface.
 * (Equivalent to arp_ignore=1 in Linux)
 */
static int arp_ignore(struct ifnet *ifp, const struct rte_ether_addr *enaddr,
		      in_addr_t src, in_addr_t target)
{
	struct if_addr *ifa;
	char b1[20];

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;

		if (sa->sa_family != AF_INET)
			continue;

		const struct sockaddr_in *sin = satosin(sa);
		if (unlikely(sin->sin_addr.s_addr == src)) {
			if (net_ratelimit())
				RTE_LOG(NOTICE, ARP,
					"%s is using my IP address %s on %s!\n",
					ether_ntoa_r(enaddr, b1),
					inet_ntoa(sin->sin_addr),
					ifp->if_name);

			ARPSTAT_INC(if_vrfid(ifp), dupips);
			return -EADDRINUSE;
		}

		if (sin->sin_addr.s_addr == target)
			return 0;
	}

	/* Target not matching i/f address is expected for GARP */
	return (src != target) ? -ENOENT : 0;
}

ALWAYS_INLINE unsigned int
arp_in_nothot_process(struct pl_packet *pkt, void *context __unused)
{
	struct ifnet *ifp = pkt->in_ifp;
	struct rte_mbuf *m = pkt->mbuf;
	struct rte_ether_hdr *eh;
	struct ether_arp *ah;
	struct llentry *la;
	in_addr_t itaddr, isaddr;
	uint16_t op;
	char addrb[INET_ADDRSTRLEN];
	int rc;
	bool garp;
	struct ifnet *vrrp_ifp;
	int resp;
	bool reachable = false;

	eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	vrrp_ifp = macvlan_get_vrrp_if(ifp,
				       (struct rte_ether_addr *)&eh->d_addr);
	if (vrrp_ifp)
		pkt->in_ifp = ifp = vrrp_ifp;

	ARPSTAT_INC(if_vrfid(ifp), received);

	if (!arp_input_validate(ifp, m))
		return ARP_IN_NOTHOT_DROP;

	ah = (struct ether_arp *) (eh + 1);
	op = ntohs(ah->arp_op);
	memcpy(&isaddr, ah->arp_spa, sizeof(isaddr));
	memcpy(&itaddr, ah->arp_tpa, sizeof(itaddr));

	if (unlikely(rte_is_multicast_ether_addr(&eh->d_addr))) {
		struct sockaddr sock_storage;
		struct sockaddr_in *ip_storage =
			(struct sockaddr_in *) &sock_storage;

		ip_storage->sin_family = AF_INET;
		ip_storage->sin_addr.s_addr = itaddr;
		/* Lookup based on the target IP address
		 *
		 * Note that this causes GARPs to only be processed in
		 * the context of the parent interface, but that's
		 * fine because we don't expect to use the lladdr
		 * table on the macvlan interfaces - L3 traffic is
		 * resolved using the physical interface.
		 *
		 * Also note this only works for ARP requests, not ARP
		 * replies, but ARP replies should never be
		 * multicasted anyway.
		 */
		vrrp_ifp = macvlan_get_vrrp_ip_if(ifp, &sock_storage);
		/* overriding the interface at this point does bypass
		 * the own-MAC check in arp_input_validate, but that's
		 * fine as we know at this point the destination
		 * address is a multicast one and our own MAC will
		 * always be unicast.
		 */
		if (vrrp_ifp)
			pkt->in_ifp = ifp = vrrp_ifp;
	}

	if (op == ARPOP_REPLY)
		ARPSTAT_INC(if_vrfid(ifp), rxreplies);

	rc = arp_ignore(ifp, (struct rte_ether_addr *) ah->arp_sha,
			isaddr, itaddr);
	if (rc != 0) {
		if (rc == -ENOENT && op == ARPOP_REQUEST &&
		    arp_proxy(ifp, itaddr, m, &resp)) {
			ARP_DEBUG("sent proxy response for %s on %s\n",
				  inet_ntop(AF_INET, &itaddr,
					    addrb, sizeof(addrb)),
				  ifp->if_name);
			ARPSTAT_INC(if_vrfid(ifp), proxy);
			pkt->in_ifp = NULL;
			pkt->l2_proto = RTE_ETHER_TYPE_ARP;
			pkt->out_ifp = ifp;
			return resp;
		}

		ARP_DEBUG("ignore request for %s on %s\n",
			  inet_ntop(AF_INET, &itaddr,
				    addrb, sizeof(addrb)), ifp->if_name);

		ARPSTAT_INC(if_vrfid(ifp), rxignored);
		return ARP_IN_NOTHOT_DROP;
	}

	/* RFC 2131 - IPv4 duplicate address detection */
	if (isaddr == 0 && op == ARPOP_REQUEST)
		goto reply;

	if (ifp->if_flags & IFF_NOARP)
		return ARP_IN_NOTHOT_DROP;

	garp = (isaddr == itaddr);

	if (garp) {
		if (op == ARPOP_REQUEST &&
		    ifp->ip_garp_op.garp_req_action == GARP_PKT_DROP) {
			ARPSTAT_INC(if_vrfid(ifp), garp_reqs_dropped);
			return ARP_IN_NOTHOT_DROP;
		}

		if (op == ARPOP_REPLY &&
		    ifp->ip_garp_op.garp_rep_action == GARP_PKT_DROP) {
			ARPSTAT_INC(if_vrfid(ifp), garp_reps_dropped);
			return ARP_IN_NOTHOT_DROP;
		}
	}

	/*
	 * Create or update ARP entry.
	 *
	 * Note: this behaves like Linux (arp_accept = 0).
	 * If the ARP table already contains the target IP address of a
	 * gratuitous arp frame, the arp table will be updated.
	 * If the ARP table does not contain that IP address we will
	 * drop it without creating an entry.
	 */

	if (op == ARPOP_REPLY && in_lltable_find(ifp, isaddr))
		reachable = true;

	la = in_lltable_lookup(ifp, garp ? 0 : LLE_CREATE, isaddr);
	if (la) {
		if (reachable) {
			lladdr_update(ifp, la, LLINFO_REACHABLE,
				      (struct rte_ether_addr *) ah->arp_sha,
				      arp_cfg.arp_reachable_time, 0);
		} else if (!rte_ether_addr_equal((struct rte_ether_addr *) ah->arp_sha,
						 &la->ll_addr))
			lladdr_update(ifp, la, LLINFO_STALE,
				      (struct rte_ether_addr *) ah->arp_sha,
				      arp_cfg.arp_scavenge_time, 0);

		/* Allow packet to bleed back to keep local tables in sync. */
		if ((op == ARPOP_REPLY) || garp) {
			if (is_local_controller() || if_is_uplink(ifp))
				return ARP_IN_NOTHOT_LOCAL;
			/* Remote controller does not maintain an arp cache */
			return ARP_IN_NOTHOT_DROP;
		}
	} else if (garp) {
		if (op == ARPOP_REQUEST)
			ARPSTAT_INC(if_vrfid(ifp), garp_reqs_dropped);
		else
			ARPSTAT_INC(if_vrfid(ifp), garp_reps_dropped);
		return ARP_IN_NOTHOT_DROP;
	}

reply:
	if (op != ARPOP_REQUEST)
		return ARP_IN_NOTHOT_DROP;

	ARPSTAT_INC(if_vrfid(ifp), rxrequests);

	/* Because of receiving interface is always the target.
	 * Shortcut.. the receiving interface is the target.
	 */
	pkt->in_ifp = NULL;
	pkt->l2_proto = RTE_ETHER_TYPE_ARP;
	pkt->out_ifp = ifp;
	return arp_reply(ifp, m, &ifp->eth_addr, itaddr);
}

/*
 * Handler for incoming ARP frames. mbuf is always consumed.
 *
 * Not to be inlined to avoid adding additional code to the main hot
 * forwarding function that could result in additional icache
 * footprint if the compiler heuristics work adversely.
 */
__noinline static void
arp_input(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct pl_packet pkt = {
		.in_ifp = ifp,
		.mbuf = m,
	};

	pipeline_fused_arp_in_nothot(&pkt);
}

/* Register Node */
PL_REGISTER_NODE(arp_in_nothot_node) = {
	.name = "vyatta:arp-in-nothot",
	.type = PL_PROC,
	.handler = arp_in_nothot_process,
	.num_next = ARP_IN_NOTHOT_NUM,
	.next = {
		[ARP_IN_NOTHOT_FINISH] = "term-finish",
		[ARP_IN_NOTHOT_LOCAL]  = "l2-local",
		[ARP_IN_NOTHOT_L2_OUT] = "l2-out",
		[ARP_IN_NOTHOT_DROP] = "term-drop",
	}
};

ALWAYS_INLINE unsigned int
arp_in_process(struct pl_packet *pkt, void *context __unused)
{
	arp_input(pkt->in_ifp, pkt->mbuf);
	return ARP_IN_FINISH;
}

PL_REGISTER_NODE(arp_in_node) = {
	.name = "vyatta:arp-in",
	.type = PL_PROC,
	.handler = arp_in_process,
	.num_next = ARP_IN_NUM,
	.next = {
		[ARP_IN_FINISH] = "term-finish",
	}
};
