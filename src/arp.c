/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
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
#include "if_ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "ip_addr.h"
#include "ip_funcs.h"
#include "main.h"
#include "nh_common.h"
#include "pktmbuf_internal.h"
#include "protobuf.h"
#include "protobuf/NbrResConfig.pb-c.h"
#include "route.h"
#include "route_flags.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "arp_cfg.h"

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

struct arp_nbr_cfg arp_cfg = {
	.arp_retries		= ARP_RETRIES,
	.arp_reachable_time	= ARP_REACHABLE_TIME,
	.arp_scavenge_time	= ARP_SCAVENGE_TIME,
	.arp_delay_time		= ARP_DELAY_TIME,
	.arp_max_entry		= ARP_MAX_ENTRY,
	.arp_max_hold		= ARP_MAXHOLD,
};

static struct garp_cfg garp_cfg = {
	.garp_req_default = 1,
	.garp_rep_default = 1,
	.garp_req_action  = GARP_PKT_UPDATE,
	.garp_rep_action  = GARP_PKT_UPDATE,
};

void get_garp_cfg(struct garp_cfg *cfg_copy)
{
	*cfg_copy = garp_cfg;
}

void set_garp_cfg(int op, enum garp_pkt_action action)
{
	if (op == ARPOP_REQUEST)
		garp_cfg.garp_req_action = action;
	else if (op == ARPOP_REPLY)
		garp_cfg.garp_rep_action = action;
	else
		RTE_LOG(ERR, ARP, "Invalid ARP op %d\n", op);
}

/* Look for an interface IP address that is in the same subnet as the target
 * IP address, if we can't find a matching IP address use the primary IP
 * address.  We need to do this because some Linux systems and network routers
 * will ignore ARP requests that appear to come from a different subnet.
 */
static in_addr_t arp_source(struct ifnet *ifp, in_addr_t tip)
{
	struct if_addr *ifa;
	in_addr_t sip = 0;
	in_addr_t primary = 0;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;
		uint32_t mask = prefixlen_to_mask(ifa->ifa_prefixlen);

		if (sa->sa_family == AF_INET) {
			sip = satosin(sa)->sin_addr.s_addr;
			if (!primary)
				primary = sip;
			if ((sip & mask) == (tip & mask))
				return sip;
		}
	}
	return primary;
}

/*
 * Broadcast an ARP request. Caller specifies:
 *	- interface to use
 *	- arp header target ip address
 */
struct rte_mbuf *
arprequest(struct ifnet *ifp, struct sockaddr *sa)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *eh;
	struct ether_arp *ah;
	in_addr_t sip;
	const unsigned len
		= sizeof(struct rte_ether_hdr) + sizeof(struct ether_arp);
	char b1[INET_ADDRSTRLEN];
	char b2[INET_ADDRSTRLEN];

	if (sa->sa_family != AF_INET)
		rte_panic("request for family %d\n", sa->sa_family);

	in_addr_t tip = satosin(sa)->sin_addr.s_addr;

	sip = arp_source(ifp, tip);
	if (!sip) {
		/* packet was destined without any IP address */
		ARP_DEBUG("request for %s but can't find source IP for %s?\n",
			  inet_ntop(AF_INET, &tip, b1, sizeof(b1)),
			  ifp->if_name);
		return NULL;
	}
	/* ARP is L2 so does not belong to a VRF.
	 * Virtual interfaces have no valid portid, so use the default pool.
	 */
	m = dp_pktmbuf_alloc_from_default(VRF_INVALID_ID);
	if (!m)	{
		ARPSTAT_INC(if_vrfid(ifp), mpoolfail);
		return NULL;
	}

	dp_pktmbuf_l2_len(m) = RTE_ETHER_HDR_LEN;
	eh = (struct rte_ether_hdr *) rte_pktmbuf_append(m, len);
	if (!eh) {
		ARP_DEBUG("no space in packet for arp request\n");
		dp_pktmbuf_notify_and_free(m);
		return NULL;
	}
	memset(&eh->d_addr, 0xff, RTE_ETHER_ADDR_LEN);
	rte_ether_addr_copy(&ifp->eth_addr, &eh->s_addr);
	eh->ether_type = htons(RTE_ETHER_TYPE_ARP);

	ah = (struct ether_arp *) (eh+1);
	ah->arp_hrd = htons(ARPHRD_ETHER);
	ah->arp_pro = htons(RTE_ETHER_TYPE_IPV4);
	ah->arp_hln = RTE_ETHER_ADDR_LEN;	/* hardware address length */
	ah->arp_pln = sizeof(in_addr_t);	/* protocol address length */
	ah->arp_op = htons(ARPOP_REQUEST);

	rte_ether_addr_copy(&ifp->eth_addr,
			    (struct rte_ether_addr *) ah->arp_sha);
	memcpy(ah->arp_spa, &sip, sizeof(sip));
	memset(ah->arp_tha, 0, RTE_ETHER_ADDR_LEN);
	memcpy(ah->arp_tpa, &tip, sizeof(tip));

	ARPSTAT_INC(if_vrfid(ifp), txrequests);

	ARP_DEBUG("send request for %s, tell %s on %s\n",
		  inet_ntop(AF_INET, &tip, b1, sizeof(b1)),
		  inet_ntop(AF_INET, &sip, b2, sizeof(b2)),
		  ifp->if_name);

	return m;
}

/*
 * Start resolution of IP address into an ethernet address.
 * Returns 0 if resolved, otherwise an error and mbuf is consumed or held.
 *
 * VYATTA: Unlike BSD, there is no socket or context for
 * this request so error code doesn't really matter.
 */
int arpresolve(struct ifnet *ifp, struct rte_mbuf *m,
	       in_addr_t addr, struct rte_ether_addr *desten)
{
	struct llentry *la;

lookup:
	la = in_lltable_find(ifp, addr);

	/* resolved now */
	if (likely(la && (la->la_flags & LLE_VALID))) {
resolved:
		rte_atomic16_clear(&la->ll_idle);
		rte_ether_addr_copy(&la->ll_addr, desten);
		return 0;
	}

	/* Create if necessary */
	if (la == NULL) {
		la = in_lltable_lookup(ifp, LLE_CREATE|LLE_LOCAL, addr);

		/* out of memory or cache limit hit */
		if (unlikely(la == NULL)) {
			dp_pktmbuf_notify_and_free(m);
			return -ENOMEM;
		}

		char b1[INET_ADDRSTRLEN];
		ARP_DEBUG("new entry created for %s\n",
			  inet_ntop(AF_INET, &addr, b1, sizeof(b1)));
	}

	/* Lock entry to hold off update and timer */
	rte_spinlock_lock(&la->ll_lock);

	/*
	 * Whilst waiting for the spin lock, has the main thread
	 * snuck in and deleted the entry?
	 */
	if (unlikely(la->la_flags & LLE_DELETED)) {
		rte_spinlock_unlock(&la->ll_lock);
		goto lookup;
	}

	/* create lost race with lladdr_update */
	if (unlikely(la->la_flags & LLE_VALID)) {
		rte_spinlock_unlock(&la->ll_lock);
		goto resolved;
	}

	/*
	 * There is an arptab entry, but no ethernet address
	 * response yet.  Add the mbuf to the list, dropping
	 * the oldest packet if we have exceeded the system
	 * setting.
	 */
	if (la->la_numheld >= arp_cfg.arp_max_hold) {
		ARPSTAT_INC(if_vrfid(ifp), dropped);
		dp_pktmbuf_notify_and_free(la->la_held[0]);
		memmove(&la->la_held[0], &la->la_held[1],
			(arp_cfg.arp_max_hold-1) * sizeof(la->la_held[0]));
		la->la_held[arp_cfg.arp_max_hold-1] = m;
	} else
		la->la_held[la->la_numheld++] = m;

	/*
	 * Only send first request here, others handled by timer.
	 */
	bool send_request = (++la->la_asked == 1);
	rte_spinlock_unlock(&la->ll_lock);
	if (send_request) {
		struct sockaddr_in taddr = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = addr,
		};

		m = arprequest(ifp, (struct sockaddr *) &taddr);
		if (m)
			if_output(ifp, m, NULL, RTE_ETHER_TYPE_ARP);
	}

	return -EWOULDBLOCK;
}

void arpresolve_hw_ecmp(struct rte_mbuf *m, const struct next_hop *nh_prime)
{
	struct next_hop_list *nhl = nh_prime->nhl;
	struct next_hop *nhlist;
	struct next_hop *nh;
	struct llentry *la;
	struct ifnet *ifp;
	struct iphdr *ip;
	in_addr_t daddr;
	in_addr_t addr;
	char b1[INET_ADDRSTRLEN];

	if (nhl == NULL)
		return;

	ip = iphdr(m);
	daddr = ip->daddr;
	nhlist = nhl->siblings;
	for (int path = 0; path < nhl->nsiblings; path++) {
		nh = &nhlist[path];

		nh->flags &= ~RTF_NH_NEEDS_HW_RES;

		/*
		 * Ignore the currently selected output path
		 */
		if (nh == nh_prime)
			continue;

		ifp = dp_nh_get_ifp(nh);
		if ((ifp == NULL) ||
		    ((ifp->if_flags & IFF_NOARP) != 0) ||
		    ((nh->flags & (RTF_SLOWPATH | RTF_LOCAL)) != 0))
			continue;

		if (nh->flags & RTF_GATEWAY)
			addr = nh->gateway.address.ip_v4.s_addr;
		else
			addr = daddr;

		la = in_lltable_find(ifp, addr);

		/*
		 * If an entry is present, assume resolution is in
		 * progress
		 */
		if (la != NULL)
			continue;

		/*
		 * Create new entry and issue the ARP request
		 */
		la = in_lltable_lookup(ifp, LLE_CREATE|LLE_LOCAL, addr);
		if (la == NULL) {
			nh->flags |= RTF_NH_NEEDS_HW_RES;
			continue;
		}

		ARP_DEBUG("%s/%s new entry (ECMP)\n", ifp->if_name,
			  inet_ntop(AF_INET, &addr, b1, sizeof(b1)));

		struct sockaddr_in taddr = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = addr,
		};

		m = arprequest(ifp, (struct sockaddr *) &taddr);
		if (m != NULL)
			if_output(ifp, m, NULL, RTE_ETHER_TYPE_ARP);
	}
}

/* Optimized inline version of arpresolve. */
ALWAYS_INLINE int
arpresolve_fast(struct ifnet *ifp, struct rte_mbuf *m,
		in_addr_t addr, struct rte_ether_addr *desten)
{
	struct llentry *la = in_lltable_find(ifp, addr);

	if (llentry_copy_mac(la, desten))
		return 0;

	return arpresolve(ifp, m, addr, desten);
}

bool arp_input_validate(const struct ifnet *ifp, struct rte_mbuf *m)
{
	struct rte_ether_hdr *eh;
	struct ether_arp *ah;
	in_addr_t itaddr, isaddr;
	uint16_t op;
	char addrb[INET_ADDRSTRLEN];

	eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if (rte_pktmbuf_data_len(m) < sizeof(*eh) + sizeof(*ah)) {
		ARP_DEBUG("runt packet len %u\n", rte_pktmbuf_data_len(m));
		goto drop;
	}

	ah = (struct ether_arp *) (eh + 1);
	if (ah->arp_hrd != htons(ARPHRD_ETHER) ||
	    ah->arp_pro != htons(RTE_ETHER_TYPE_IPV4)) {
		ARP_DEBUG("ignore arp for hrd %#x protocol %#x\n",
			ntohs(ah->arp_hrd), ntohs(ah->arp_pro));
		goto drop;
	}

	if (ah->arp_pln != sizeof(struct in_addr)) {
		ARP_DEBUG("requested protocol length %u != %zu\n",
			  ah->arp_pln, sizeof(struct in_addr));
		goto drop;
	}

	if (rte_is_multicast_ether_addr(
				(struct rte_ether_addr *) ah->arp_sha)) {
		ARP_DEBUG("source hardware addresss is multicast.\n");
		goto drop;
	}

	if (rte_is_zero_ether_addr((struct rte_ether_addr *) ah->arp_sha)) {
		ARP_DEBUG("source hardware address is invalid.\n");
		goto drop;
	}

	op = ntohs(ah->arp_op);
	memcpy(&isaddr, ah->arp_spa, sizeof(isaddr));
	memcpy(&itaddr, ah->arp_tpa, sizeof(itaddr));

	char b1[INET_ADDRSTRLEN], b2[INET_ADDRSTRLEN];
	ARP_DEBUG("op %s from %s about %s\n",
		  (op == ARPOP_REQUEST ? "REQUEST" : (op == ARPOP_REPLY ? "REPLY" : "???")),
		  inet_ntop(AF_INET, &isaddr, b1, sizeof(b1)),
		  inet_ntop(AF_INET, &itaddr, b2, sizeof(b2)));

	/* Check for bad requests */
	if ((ntohl(itaddr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
	    IN_MULTICAST(ntohl(itaddr))) {
		ARP_DEBUG("invalid target IP address %s on %s\n",
			  inet_ntop(AF_INET, ah->arp_tpa, addrb, sizeof(addrb)),
			  ifp->if_name);
		goto drop;
	}

	if (rte_ether_addr_equal((struct rte_ether_addr *) ah->arp_sha,
				 &ifp->eth_addr)) {
		ARP_DEBUG("saw own arp?");
		goto drop;	/* it's from me, ignore it. */
	}

	if (rte_is_broadcast_ether_addr((struct rte_ether_addr *)ah->arp_sha)) {
		ARP_DEBUG("link address is broadcast for IP address %s!\n",
			  inet_ntop(AF_INET, ah->arp_spa,
				    addrb, sizeof(addrb)));
		goto drop;
	}

	return true;

drop:
	return false;
}

/* Walk the ARP table.
 * Only called by console (main thread);
 * Can not be called safely from forwarding loop.
 */
void
arp_walk(const struct ifnet *ifp, ll_walkhash_f_t *f, void *arg)
{
	const struct lltable *llt = ifp->if_lltable;
	struct llentry	*lle;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(llt->llt_hash, &iter, lle, ll_node) {
		(*f)(ifp, lle, arg);
	}
}

/* Must be called with lle->ll_lock held */
void
arp_entry_destroy(struct lltable *llt, struct llentry *lle)
{
	unsigned int pkts_dropped;

	pkts_dropped = llentry_destroy(llt, lle);
	ARPSTAT_ADD(if_vrfid(llt->llt_ifp), dropped, pkts_dropped);
}

/*
 * arp-cfg ARP {SET|DELETE} <param enum> <param value>
 */
static int cmd_arp_cfg_handler(struct pb_msg *pbmsg)
{
	NbrResConfig *msg = nbr_res_config__unpack(NULL, pbmsg->msg_len,
							 pbmsg->msg);
	uint32_t val;
	char *ifname;
	int ret = -1;
	bool set;

	if (!msg) {
		RTE_LOG(ERR, ARP,
			"Cfg failed to read NbrResConfig protobuf cmd\n");
		return ret;
	}
	if (msg->prot != NBR_RES_CONFIG__PROT__ARP) {
		RTE_LOG(ERR, ARP,
			"Cfg incorrect protocol (%d)\n", msg->prot);
		goto end;
	}
	ifname = msg->ifname;
	if (ifname && (*ifname != '\0' && strncmp("all", ifname, 4) != 0)) {
		RTE_LOG(ERR, ARP,
			"Cfg per-interface config not yet supported\n");
		goto end;
	}
	set = msg->action == NBR_RES_CONFIG__ACTION__SET;
	val = msg->value;

	switch (msg->param) {
	case NBR_RES_CONFIG__PARAM__AGING_TIME:
		/*
		 * While ARP does not have a reachable time (30s) before entries
		 * can go stale due to it not yet having a state machine, ensure
		 * that entries cannot be aged out in less than this time.
		 */
		if (set && val < ARP_REACHABLE_TIME) {
			RTE_LOG(ERR, ARP,
				"Cfg res token value %d out of range\n", val);
			goto end;
		}
		arp_cfg.arp_reachable_time = set ? val : ARP_REACHABLE_TIME;
		ARP_DEBUG("Cfg param arp_aging_time (arp reachable timeout) set to: %d\n",
			  arp_cfg.arp_reachable_time);
		break;
	case NBR_RES_CONFIG__PARAM__MAX_ENTRY:
		/*
		 * Changes to cache size only impact subsequent resolutions.
		 * So if cache size is reduced to less than the number of
		 * entries for an interface, then the latter number decreases
		 * only as entries fail to re-resolve.
		 */
		if (set && (int)val <= 0) {
			RTE_LOG(ERR, ARP,
				"Cfg max entry value %d out of range\n", val);
			goto end;
		}
		arp_cfg.arp_max_entry = set ? val : ARP_MAX_ENTRY;
		ARP_DEBUG("Cfg param arp_max_entry (cache size) set to: %d\n",
			  arp_cfg.arp_max_entry);
		break;
	default:
		RTE_LOG(ERR, ARP,
			"Cfg parameter not supported (%d)\n", msg->param);
		goto end;
	}

	ret = 0;
end:
	nbr_res_config__free_unpacked(msg, NULL);
	return ret;
}

PB_REGISTER_CMD(arp_cfg_cmd) = {
	.cmd = "vyatta:arp",
	.handler = cmd_arp_cfg_handler,
};

int cmd_arp_get_cfg(FILE *f)
{
	json_writer_t *wr = jsonw_new(f);

	if (!wr) {
		RTE_LOG(NOTICE, DATAPLANE,
			"arp: Error creating JSON object for cfg params\n");
		return -1;
	}

	jsonw_pretty(wr, true);

	jsonw_uint_field(wr, "Aging time",	   arp_cfg.arp_reachable_time);
	jsonw_int_field(wr, "Max entries",	   arp_cfg.arp_max_entry);

	jsonw_destroy(&wr);

	return 0;
}
