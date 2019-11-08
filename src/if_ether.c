/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
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
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/neighbour.h>

#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>

#include "arp.h"
#include "compat.h"
#include "control.h"
#include "ether.h"
#include "fal.h"
#include "fal_plugin.h"
#include "if_ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "main.h"
#include "netinet6/nd6_nbr.h"
#include "pktmbuf.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"


/* Debugging messages */
#define LLADDR_DEBUG(format, args...)	\
	DP_DEBUG(ARP, DEBUG, LLADDR, format, ##args)

static const char *lladdr_ntop(struct llentry *la)
{
	const struct sockaddr *sa = ll_sockaddr(la);
	static char buf[INET6_ADDRSTRLEN];

	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin
			= (const struct sockaddr_in *) sa;

		return inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6
			= (const struct sockaddr_in6 *) sa;
		return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
	}
	default:
		snprintf(buf, sizeof(buf), "[family: %u]\n", sa->sa_family);
		return buf;
	}
}

/* This is all necessary so that when address is changed
 * in ARP entry the update is done as one atomic opearation.
 * There is no atomic 6 byte copy, but 64 bit operations are atomic
 * on 64 bit CPU's.
 */
void ll_addr_set(struct llentry *lle, const struct ether_addr *eth)
{
	union llentry_addr tmp;

	tmp.lu_addr = *eth;
	tmp.lu_flags = lle->la_flags;
	barrier();	/* keep compiler from optimizing aliased */
	lle->ll_u.lu_addr_flags = tmp.lu_addr_flags;
}

/* Update existing link-layer addr table entry. */
void lladdr_update(struct ifnet *ifp, struct llentry *la,
		   const struct ether_addr *enaddr, uint16_t flags)
{
	char b1[20], b2[20];

	if (!enaddr) {
		RTE_LOG(ERR, LLADDR, "update with no mac addr\n");
		return;
	}

	rte_spinlock_lock(&la->ll_lock);
	if (la->la_flags & LLE_VALID) {
		if (ether_addr_equal(enaddr, &la->ll_addr)) {
			rte_spinlock_unlock(&la->ll_lock);
			return;
		}

		/* static update can update an existing static entry */

		if (la->la_flags & LLE_STATIC && !(flags & LLE_STATIC)) {
			rte_spinlock_unlock(&la->ll_lock);
			RTE_LOG(NOTICE, LLADDR,
				"%s attempt to modify static entry %s on %s\n",
				ether_ntoa_r(enaddr, b1),
				lladdr_ntop(la),
				ifp->if_name);

			return;
		}

		ll_addr_set(la, enaddr);
		la->la_flags |= flags;
		/*
		 * We have had an address change so it needs to be signalled
		 * to the hardware, mark it as incomplete in the hardware so
		 * that the master thread can pick this up and send an update
		 */
		la->la_flags |= LLE_HW_UPD_PENDING;
		rte_timer_reset(&ifp->if_lltable->lle_timer, 0,
				SINGLE, rte_get_master_lcore(),
				lladdr_timer, ifp->if_lltable);

		rte_spinlock_unlock(&la->ll_lock);

		LLADDR_DEBUG("%s moved from %s to %s on %s\n",
			     lladdr_ntop(la),
			     ether_ntoa_r(&la->ll_addr, b1),
			     ether_ntoa_r(enaddr, b2),
			     ifp->if_name);

	} else {
		ll_addr_set(la, enaddr);
		rte_wmb();
		la->la_flags |= (LLE_VALID | flags);
		/*
		 * Fire the timer for this table immediately on master. It
		 * doesn't matter if it fails as it will get picked up on
		 * the next firing in that case.
		 */
		rte_timer_reset(&ifp->if_lltable->lle_timer, 0,
				SINGLE, rte_get_master_lcore(),
				lladdr_timer, ifp->if_lltable);

		int la_numheld = la->la_numheld;
		struct rte_mbuf *la_held[ARP_MAXHOLD];

		for (int i = 0; i < la_numheld; ++i) {
			la_held[i] = la->la_held[i];
			la->la_held[i] = NULL;
		}
		la->la_numheld = 0;
		rte_spinlock_unlock(&la->ll_lock);

		/* now valid: release any pending packets */
		for (int i = 0; i < la_numheld; i++) {
			struct rte_mbuf *m = la_held[i];
			struct ether_hdr *eh;

			/* fill in destination in held packet and send it */
			eh = rte_pktmbuf_mtod(m, struct ether_hdr *);

			ether_addr_copy(enaddr, &eh->d_addr);
			/*
			 * Note: even though this may be a forwarded
			 * packet, NULL is passed in for the input
			 * interface since this is only used for
			 * tunnel interfaces in certain corner cases
			 * and it's not worth the effort of keeping
			 * track of the input interface context.
			 */
			if_output(ifp, m, NULL, htons(eh->ether_type));
		}

		LLADDR_DEBUG("entry for %s resolved to %s\n",
			     lladdr_ntop(la),
			     ether_ntoa_r(enaddr, b1));
	}

	/* entry updated */
	rte_atomic16_clear(&la->ll_idle);
	la->ll_expire = rte_get_timer_cycles() + rte_get_timer_hz() * ARPT_KEEP;

	/* Extend the timeout for locally created proxy entries */
	if (la->la_flags & (LLE_LOCAL | LLE_PROXY))
		la->ll_expire += rte_get_timer_hz() * ARPT_KEEP;
}

static int
lladdr_add(struct ifnet *ifp, struct sockaddr *sock,
	   const struct ether_addr *mac,
	   uint16_t state, uint8_t ntf_flags)
{
	struct llentry *lle;
	uint16_t flags = LLE_CREATE;

	if (state & NUD_PERMANENT)
		flags |= LLE_STATIC;

	switch (sock->sa_family) {
	case AF_INET:
		lle = in_lltable_lookup(ifp, flags,
					satosin(sock)->sin_addr.s_addr);
		break;

	case AF_INET6:
		return nd6_lladdr_add(ifp, &satosin6(sock)->sin6_addr,
				      mac, state, ntf_flags);

	default:
		return -1;
	}

	if (lle == NULL) {
		RTE_LOG(NOTICE, LLADDR, "lladdr_add create failed\n");
		return -1;
	}

	if (state & (NUD_STALE|NUD_REACHABLE|NUD_NOARP|NUD_PERMANENT)) {
		uint16_t new_flags = 0;

		if (state & NUD_PERMANENT)
			new_flags |= LLE_STATIC;
		if (ntf_flags & NTF_PROXY)
			new_flags |= LLE_PROXY;

		lladdr_update(ifp, lle, mac, new_flags);
	} else {
		rte_spinlock_lock(&lle->ll_lock);
		lle->la_flags &= ~(LLE_VALID | LLE_STATIC);

		pktmbuf_free_bulk(lle->la_held, lle->la_numheld);
		lle->la_numheld = 0;
		rte_spinlock_unlock(&lle->ll_lock);
	}

	return 0;
}

static int
lladdr_delete(struct ifnet *ifp, struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return in_lltable_lookup(ifp, LLE_DELETE,
					 satosin(addr)->sin_addr.s_addr)
			? 0 : -1;
	case AF_INET6:
		return in6_lltable_lookup(ifp, LLE_DELETE,
					  &satosin6(addr)->sin6_addr)
			? 0 : -1;
	default:
		return -1;
	}
}

/*
 * Netlink event handling
 *
 * Called when receiving netlink neighbor event
 */
void lladdr_nl_event(int family, struct ifnet *ifp, uint16_t type,
		     const struct ndmsg *ndm,
		     const void *dst, const struct ether_addr *lladdr)
{
	struct sockaddr_storage saddr;

	memset(&saddr, 0, sizeof(saddr));

	switch (family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)&saddr;

		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, dst, sizeof(struct in_addr));
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&saddr;

		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, dst, sizeof(struct in6_addr));
		break;
	}
	default:
		RTE_LOG(NOTICE, LLADDR,
			"Unexpected netlink neighbor: invalid family: %d\n",
			family);
		return;
	}

	char b1[INET6_ADDRSTRLEN], b2[64];
	const char *eaddr_str = lladdr ? ether_ntoa_r(lladdr, b2) : "";
	const char *addr_str = inet_ntop(family, dst, b1, sizeof(b1));

	DP_DEBUG(NETLINK_NEIGH, INFO, LLADDR,
		 "%s %s dev %s [%s] flags %#x state %#x (%s)\n",
		 nlmsg_type(type), addr_str, ifp->if_name, eaddr_str,
		 ndm->ndm_flags,  ndm->ndm_state,
		 ndm_state(ndm->ndm_state));

	switch (type) {
	case RTM_NEWNEIGH:
		if (lladdr)
			lladdr_add(ifp, (struct sockaddr *) &saddr, lladdr,
				   ndm->ndm_state, ndm->ndm_flags);
		else
			RTE_LOG(NOTICE, LLADDR,
				"NEWNEIGH without link layer address?\n");
		break;

	case RTM_DELNEIGH:
		lladdr_delete(ifp, (struct sockaddr *) &saddr);
		break;

	default:
		RTE_LOG(NOTICE, LLADDR,
			"Unexpected netlink neighbor message type %d\n", type);
		return;
	}
}

/* Send a new ll request probe for entry that has not responded.
 * Since this runs in master lcore, and that can't send directly,
 * it intrudes into shadow output ring to send the packet.
 */
static void ll_probe(struct lltable *llt, struct llentry *la)
{
	struct ifnet *ifp = llt->llt_ifp;

	rte_spinlock_lock(&la->ll_lock);
	if (++la->la_asked < ARP_MAXPROBES) {
		struct sockaddr *sa = ll_sockaddr(la);
		struct rte_mbuf *m;

		rte_spinlock_unlock(&la->ll_lock);
		switch (sa->sa_family) {
		case AF_INET:
			m = arprequest(ifp, sa);
			break;
		default:
			m = NULL;
			break;
		}
		/*
		 * Note: even though this may be a forwarded packet,
		 * NULL is passed in for the input interface since
		 * this is only used for tunnel interfaces in certain
		 * corner cases and it's not worth the effort of
		 * keeping track of the input interface context.
		 */
		if (m)
			if_output(ifp, m, NULL, htons(ethhdr(m)->ether_type));
	} else {
		unsigned int pkts_dropped;

		pkts_dropped = llentry_destroy(llt, la);
		rte_spinlock_unlock(&la->ll_lock);

		ARPSTAT_INC(if_vrfid(ifp), timeouts);
		ARPSTAT_ADD(if_vrfid(ifp), dropped, pkts_dropped);

		LLADDR_DEBUG("retries exhausted for %s\n", lladdr_ntop(la));
	}
}

static void ll_age(struct lltable *llt, struct llentry *lle, uint64_t cur_time)
{
	if (llentry_has_been_used_and_clear(lle)) {
		lle->ll_expire = cur_time + rte_get_timer_hz() * ARPT_KEEP;

		/* Extend the timeout for locally created proxy entries */
		if (lle->la_flags & (LLE_LOCAL | LLE_PROXY))
			lle->ll_expire += rte_get_timer_hz() * ARPT_KEEP;

	} else if ((int64_t)(cur_time - lle->ll_expire) >= 0) {
		LLADDR_DEBUG("expire entry for %s, flags %#x\n",
			     lladdr_ntop(lle), lle->la_flags);
		rte_spinlock_lock(&lle->ll_lock);
		llentry_destroy(llt, lle);
		rte_spinlock_unlock(&lle->ll_lock);
	}
}

/*
 * Called when an lle entry transitions to VALID.
 */
void
llentry_routing_install(struct llentry *lle)
{
	rte_spinlock_lock(&lle->ll_lock);
	lle->la_flags |= LLE_FWDING;
	switch (lle->ll_sock.ss_family) {
	case AF_INET:
		routing_insert_arp_safe(lle, true);
		break;
	case AF_INET6:
		routing6_insert_neigh_safe(lle, true);
		break;
	}
	rte_spinlock_unlock(&lle->ll_lock);
}

/* walk the ll addr table and look for entries that have been used  */
void lladdr_timer(struct rte_timer *tim __rte_unused, void *arg)
{
	int ret = 0;
	bool new = false;
	bool upd = false;
	uint32_t attr_count = 0;
	struct lltable *llt = arg;
	struct llentry *lle;
	char b[INET_ADDRSTRLEN];
	struct sockaddr_in *sin;
	struct cds_lfht_iter iter;
	struct fal_attribute_t attr_list[2];
	uint64_t cur_time = rte_get_timer_cycles();

	rcu_read_lock();
	cds_lfht_for_each_entry(llt->llt_hash, &iter, lle, ll_node) {
		/*
		 * If the delete flag is set (which can be done on any
		 * core) do the actual delete here on master
		 */
		sin = (struct sockaddr_in *) ll_sockaddr(lle);
		if (lle->la_flags & LLE_DELETED) {
			rte_spinlock_lock(&lle->ll_lock);
			__llentry_destroy(llt, lle);
			rte_spinlock_unlock(&lle->ll_lock);
			continue;
		}
		rte_spinlock_lock(&lle->ll_lock);
		if (lle->la_flags & LLE_HW_UPD_PENDING) {
			if (lle->la_flags & LLE_VALID) {
				lle->la_flags &= ~LLE_HW_UPD_PENDING;
				upd = true;
				attr_list[0].id =
					FAL_NEIGH_ENTRY_ATTR_DST_MAC_ADDRESS;
				attr_list[0].value.mac = lle->ll_addr;
				attr_count++;
			}
			if (!(lle->la_flags & LLE_CREATED_IN_HW)) {
				new = true;
				lle->la_flags |= LLE_CREATED_IN_HW;
			}
		}
		rte_spinlock_unlock(&lle->ll_lock);

		if (new) {
			ret = fal_ip4_new_neigh(lle->ifp->if_index,
						sin, attr_count, attr_list);
			if (ret < 0 && ret != -EOPNOTSUPP) {
				RTE_LOG(NOTICE, DATAPLANE,
					"FAL new neighbour %s, %s failed: %s\n",
					inet_ntop(AF_INET, &sin, b, sizeof(b)),
					lle->ifp->if_name, strerror(-ret));
			}
		} else if (upd) {
			ret = fal_ip4_upd_neigh(lle->ifp->if_index, sin,
						attr_list);
			if (ret < 0) {
				RTE_LOG(NOTICE, DATAPLANE,
					"FAL neighbour mac update for %s, %s failed: %s\n",
					inet_ntop(AF_INET, &sin, b, sizeof(b)),
					lle->ifp->if_name, strerror(-ret));
			}
		}
		if ((lle->la_flags & (LLE_VALID | LLE_FWDING)) == LLE_VALID)
			llentry_routing_install(lle);

		if (lle->la_flags & LLE_STATIC)
			continue;

		/* retry incomplete entry */
		if ((lle->la_flags & (LLE_LOCAL | LLE_VALID)) == LLE_LOCAL) {
			if (lltable_probe_timer_is_enabled())
				ll_probe(llt, lle);
		} else if (lle->ll_expire == 0) {
			continue;
		} else if (lle->la_flags & LLE_VALID || lle->la_flags == 0) {
			ll_age(llt, lle, cur_time);
		}
	}

	rte_timer_reset(&llt->lle_timer, rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(),
			lladdr_timer, llt);

	rcu_read_unlock();
}

static void lladdr_flush(struct ifnet *ifp, void *cont_src_p)
{
	enum cont_src_en cont_src = *(enum cont_src_en *)cont_src_p;

	if (ifp->if_cont_src == cont_src) {
		lltable_flush(ifp->if_lltable);
		lltable_flush(ifp->if_lltable6);
	}
}

void lladdr_flush_all(enum cont_src_en cont_src)
{
	ifnet_walk(lladdr_flush, &cont_src);
}
