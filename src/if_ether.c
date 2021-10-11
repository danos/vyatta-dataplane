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
#include <netinet/in.h>
#include <in6.h>
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
#include <libmnl/libmnl.h>

#include "arp.h"
#include "compat.h"
#include "control.h"
#include "dp_event.h"
#include "ether.h"
#include "fal.h"
#include "fal_plugin.h"
#include "if_ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "main.h"
#include "netinet6/nd6_nbr.h"
#include "pktmbuf_internal.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

const char *nd_state[LLINFO_MAX] = {
	[LLINFO_INCOMPLETE] = "INCOMPLETE",
	[LLINFO_REACHABLE]  = "REACHABLE",
	[LLINFO_STALE]      = "STALE",
	[LLINFO_DELAY]      = "DELAY",
	[LLINFO_PROBE]      = "PROBE",
};

/*
 * Netlink socket to notify kernel about neighbor reachability
 */
static struct mnl_socket *kernel_nl;

const char *lladdr_ntop(struct llentry *la)
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
void ll_addr_set(struct llentry *lle, const struct rte_ether_addr *eth)
{
	union llentry_addr tmp;

	tmp.lu_addr = *eth;
	tmp.lu_flags = lle->la_flags;
	barrier();	/* keep compiler from optimizing aliased */
	lle->ll_u.lu_addr_flags = tmp.lu_addr_flags;
}

/* Update existing link-layer addr table entry. */
void lladdr_update(struct ifnet *ifp, struct llentry *la, uint8_t state,
		   const struct rte_ether_addr *enaddr, uint16_t secs, uint16_t flags)
{
	struct rte_mbuf *la_held[ARP_MAXHOLD];
	struct rte_ether_addr old_enaddr;
	char b1[20], b2[20];
	int la_numheld = 0;
	bool was_valid;

	if (!enaddr) {
		RTE_LOG(ERR, LLADDR, "update with no mac addr\n");
		return;
	}

	rte_spinlock_lock(&la->ll_lock);
	was_valid = la->la_flags & LLE_VALID;
	if (!was_valid) {
		flags |= LLE_VALID;
		ARPSTAT_INC(if_vrfid(ifp), total_added);
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

	old_enaddr = la->ll_addr;
	if (!was_valid || !rte_ether_addr_equal(enaddr, &la->ll_addr)) {
		ll_addr_set(la, enaddr);
		/*
		 * Ensure the write to the address is seen by readers
		 * before the write to the flags below.
		 */
		rte_wmb();
		/*
		 * We have had an address change so it needs
		 * to be signalled to the hardware, mark it as
		 * incomplete in the hardware so that the
		 * main thread can pick this up and send an
		 * update
		 */
		if (if_is_features_mode_active(
			    ifp, IF_FEAT_MODE_EVENT_L3_FAL_ENABLED))
			la->la_flags |= LLE_HW_UPD_PENDING;

		/* fire timer to update hardware and/or install routes */
		rte_timer_reset(&ifp->if_lltable->lle_timer, 0, SINGLE,
				rte_get_master_lcore(), lladdr_timer, ifp->if_lltable);
	}
	la->la_flags |= flags;
	LLADDR_DEBUG("%s/%s %s->%s\n", ifp->if_name, lladdr_ntop(la),
		     nd_state[la->la_state], nd_state[state]);
	la->la_state = state;

	if (!was_valid) {
		la_numheld = la->la_numheld;
		for (int i = 0; i < la_numheld; ++i) {
			la_held[i] = la->la_held[i];
			la->la_held[i] = NULL;
		}
		la->la_numheld = 0;
	}

	rte_spinlock_unlock(&la->ll_lock);

	if (was_valid) {
		if (!rte_ether_addr_equal(enaddr, &old_enaddr))
			LLADDR_DEBUG("%s moved from %s to %s on %s\n",
				     lladdr_ntop(la),
				     ether_ntoa_r(&old_enaddr, b1),
				     ether_ntoa_r(enaddr, b2),
				     ifp->if_name);
	} else {
		LLADDR_DEBUG("entry for %s resolved to %s\n",
			     lladdr_ntop(la),
			     ether_ntoa_r(enaddr, b1));
	}

	if (!was_valid) {
		/* now valid: release any pending packets */
		for (int i = 0; i < la_numheld; i++) {
			struct rte_mbuf *m = la_held[i];
			struct rte_ether_hdr *eh;

			/* fill in destination in held packet and send it */
			eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

			rte_ether_addr_copy(enaddr, &eh->d_addr);
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
	}

	/* entry updated */
	rte_atomic16_clear(&la->ll_idle);

	la->ll_expire = secs ? rte_get_timer_cycles() + rte_get_timer_hz() * secs : 0;

	/* Extend the timeout for locally created proxy entries in REACHABLE state*/
	if ((state == LLINFO_REACHABLE) && secs > 0 &&
	    (la->la_flags & LLE_LOCAL) && (la->la_flags & LLE_PROXY))
		la->ll_expire += rte_get_timer_hz() * secs;
}

void kernel_neigh_netlink_sock_close(void)
{
	int rv;

	rv = mnl_socket_close(kernel_nl);
	if (rv < 0)
		RTE_LOG(ERR, DATAPLANE, "Failed to close netlink socket - %s\n",
			strerror(errno));

	kernel_nl = NULL;
}

void kernel_neigh_netlink_sock_init(void)
{
	int rv;

	kernel_nl = mnl_socket_open(NETLINK_ROUTE);
	if (!kernel_nl) {
		RTE_LOG(ERR, DATAPLANE, "Failed to open netlink socket - %s\n",
			strerror(errno));
		return;
	}

	rv = mnl_socket_bind(kernel_nl, 0, MNL_SOCKET_AUTOPID);
	if (rv < 0) {
		RTE_LOG(ERR, DATAPLANE, "Failed to bind netlink socket - %s\n",
			strerror(errno));
		kernel_neigh_netlink_sock_close();
	}
}

/*
 * Notify kernel that addr is REACHABLE.
 */
void kernel_mark_neigh_reachable(const struct sockaddr *addr, uint32_t ifindex)
{
	int rv;
	static unsigned int myseq;
	char b[INET6_ADDRSTRLEN];
	const char *a;
	struct {
		struct nlmsghdr	n;
		struct ndmsg	ndm;
		char		buf[256];
	} req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE,
		.n.nlmsg_type = RTM_NEWNEIGH,
		.n.nlmsg_seq = ++myseq,
		.ndm.ndm_family = addr->sa_family,
		.ndm.ndm_state = NUD_REACHABLE,
		.ndm.ndm_ifindex = ifindex
	};

	switch (addr->sa_family) {
	case AF_INET:
		a = inet_ntop(AF_INET, &((struct sockaddr_in *)(addr))->sin_addr, b, sizeof(b));
		mnl_attr_put(&req.n, IFLA_ADDRESS, sizeof(struct in_addr),
			     &((struct sockaddr_in *)(addr))->sin_addr);
		break;

	case AF_INET6:
		a = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)(addr))->sin6_addr, b, sizeof(b));
		mnl_attr_put(&req.n, IFLA_ADDRESS, sizeof(struct in6_addr),
			     &((struct sockaddr_in6 *)(addr))->sin6_addr);
		break;

	default:
		RTE_LOG(ERR, DATAPLANE, "Cannot update reachability - Invalid AF %d\n",
			addr->sa_family);
		return;
	}

	if (!kernel_nl) {
		RTE_LOG(ERR, DATAPLANE, "Cannot update reachability for %s - no netlink sock\n", a);
		return;
	}

	rv = mnl_socket_sendto(kernel_nl, &req.n, req.n.nlmsg_len);
	if (rv < 0)
		RTE_LOG(ERR, DATAPLANE, "Failed to send neigh REACHABLE to kernel for %s - %s\n",
			a, strerror(errno));
	else
		DP_DEBUG(LINK, DEBUG, DATAPLANE,
			 "Synced neigh state REACHABLE to kernel for %s\n", a);
}

static int
lladdr_add(struct ifnet *ifp, struct sockaddr *sock,
	   const struct rte_ether_addr *mac,
	   uint16_t state, uint8_t ntf_flags)
{
	struct llentry *lle;
	uint16_t flags = LLE_CREATE;
	uint16_t secs = 0;

	switch (sock->sa_family) {
	case AF_INET:
		break;

	case AF_INET6:
		return nd6_lladdr_add(ifp, &satosin6(sock)->sin6_addr,
				      mac, state, ntf_flags);

	default:
		return -1;
	}

	if (!(state &
	      (NUD_PERMANENT | NUD_STALE | NUD_NOARP | NUD_REACHABLE | NUD_FAILED)))
		return 0;

	/* Do not create an entry as a result of a fail notification */
	if (state & NUD_FAILED)
		flags = 0;

	if (state & NUD_PERMANENT)
		flags |= LLE_STATIC;

	lle = in_lltable_lookup(ifp, flags, satosin(sock)->sin_addr.s_addr);

	if (state & NUD_STALE) {
		if (lle && llentry_has_been_used(lle))
			kernel_mark_neigh_reachable(sock, ifp->if_index);
	} else if (state & NUD_FAILED) {

		/* Ignore fail notification unless entry exists */
		if (!lle)
			return 0;

		if (llentry_has_been_used_and_clear(lle))
			return 0;

		rte_spinlock_lock(&lle->ll_lock);
		arp_entry_destroy(ifp->if_lltable, lle);
		rte_spinlock_unlock(&lle->ll_lock);
	} else {
		uint16_t new_flags = 0;

		if (!lle) {
			RTE_LOG(NOTICE, LLADDR, "lladdr add: create failed\n");
			return -1;
		}

		if (state & NUD_PERMANENT)
			new_flags |= LLE_STATIC;
		if (ntf_flags & NTF_PROXY)
			new_flags |= LLE_PROXY;
		if (state & NUD_REACHABLE)
			secs = arp_cfg.arp_reachable_time;

		lladdr_update(ifp, lle, LLINFO_REACHABLE,
			      mac, secs, new_flags);
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
		     const void *dst, const struct rte_ether_addr *lladdr)
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
		lladdr_add(ifp, (struct sockaddr *) &saddr, lladdr,
			   ndm->ndm_state, ndm->ndm_flags);
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

/*
 * Change cache entry state
 * Caller must have a spinlock on the entry if required
 */
static inline void
change_state(struct ifnet *ifp, struct llentry *lle, uint8_t state,
	     uint16_t expire)
{

	if (lle->la_flags & (LLE_STATIC | LLE_DELETED))
		return;

	LLADDR_DEBUG("%s/%s %s->%s\n", ifp->if_name, lladdr_ntop(lle),
		     nd_state[lle->la_state], nd_state[state]);

	lle->la_state = state;
	lle->ll_expire = rte_get_timer_cycles() + expire * rte_get_timer_hz();

	/* Extend the timeout for locally created proxy entries in REACHABLE state*/
	if ((state == LLINFO_REACHABLE) && (lle->la_flags & LLE_LOCAL) &&
	    (lle->la_flags & LLE_PROXY))
		lle->ll_expire += rte_get_timer_hz() * expire;
}

/* Send a new ll request probe for entry that has not responded.
 * Since this runs in main lcore, and that can't send directly,
 * it intrudes into shadow output ring to send the packet.
 */
void
ll_probe(struct lltable *llt, struct llentry *la)
{
	struct ifnet *ifp = llt->llt_ifp;
	struct sockaddr *sa = ll_sockaddr(la);
	struct rte_mbuf *m;

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
}

static void ll_age(struct lltable *llt, struct llentry *lle, uint64_t cur_time)
{
	struct ifnet *ifp = llt->llt_ifp;

	/*
	 * Check for traffic in Stale state
	 */
	if (llentry_has_been_used_and_clear(lle) &&
	    (lle->la_state == LLINFO_STALE)) {
		rte_spinlock_lock(&lle->ll_lock);
		change_state(ifp, lle, LLINFO_DELAY,
			     arp_cfg.arp_delay_time);
		rte_spinlock_unlock(&lle->ll_lock);
		return;
	}

	if ((int64_t)(cur_time - lle->ll_expire) >= 0) {
		rte_spinlock_lock(&lle->ll_lock);
		switch (lle->la_state) {
		case LLINFO_INCOMPLETE:
			break;

		case LLINFO_REACHABLE:
			break;

		case LLINFO_STALE:
			break;

		case LLINFO_DELAY:
			break;

		case LLINFO_PROBE:
			break;

		default:
			arp_entry_destroy(llt, lle);
			break;
		}
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
	struct lltable *llt = arg;
	struct llentry *lle;
	struct cds_lfht_iter iter;
	bool refresh_timer_expired = false;
	uint64_t cur_time = rte_get_timer_cycles();

	if (llt->lle_refresh_expire < cur_time) {
		refresh_timer_expired = true;

		/* one second later */
		llt->lle_refresh_expire = cur_time + rte_get_timer_hz();
	}

	dp_rcu_read_lock();
	cds_lfht_for_each_entry(llt->llt_hash, &iter, lle, ll_node) {
		/*
		 * If the delete flag is set (which can be done on any
		 * core) do the actual delete here on main
		 */
		if (lle->la_flags & LLE_DELETED) {
			rte_spinlock_lock(&lle->ll_lock);
			__llentry_destroy(llt, lle);
			rte_spinlock_unlock(&lle->ll_lock);
			continue;
		}

		llentry_issue_pending_fal_updates(lle);

		if ((lle->la_flags & (LLE_VALID | LLE_FWDING)) == LLE_VALID)
			llentry_routing_install(lle);

		if (lle->la_flags & LLE_STATIC)
			continue;

		/* retry incomplete entry */
		if ((lle->la_flags & (LLE_LOCAL | LLE_VALID)) == LLE_LOCAL) {
			if (lltable_probe_timer_is_enabled() &&
			    refresh_timer_expired)
				ll_age(llt, lle, cur_time);
		}

		if (lle->ll_expire == 0 || !refresh_timer_expired)
			continue;

		if (lle->la_flags & LLE_VALID || lle->la_flags == 0)
			ll_age(llt, lle, cur_time);
	}

	cur_time = rte_get_timer_cycles();
	rte_timer_reset(&llt->lle_timer,
			llt->lle_refresh_expire < cur_time ? 0 :
			llt->lle_refresh_expire - cur_time,
			SINGLE, rte_get_master_lcore(),
			lladdr_timer, llt);

	dp_rcu_read_unlock();
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
	dp_ifnet_walk(lladdr_flush, &cont_src);
}

static void
lladdr_if_feat_mode_change(struct ifnet *ifp,
			   enum if_feat_mode_event event)
{
	if (event != IF_FEAT_MODE_EVENT_L3_FAL_ENABLED &&
	    event != IF_FEAT_MODE_EVENT_L3_FAL_DISABLED)
		return;

	if (lltable_fal_l3_change(
		    ifp->if_lltable,
		    event == IF_FEAT_MODE_EVENT_L3_FAL_ENABLED))
		rte_timer_reset(&ifp->if_lltable->lle_timer, 0,
				SINGLE, rte_get_master_lcore(),
				lladdr_timer, ifp->if_lltable);
}

static const struct dp_event_ops lladdr_events = {
	.if_feat_mode_change = lladdr_if_feat_mode_change,
};

DP_STARTUP_EVENT_REGISTER(lladdr_events);
