/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
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
 *	@(#)in.c	8.4 (Berkeley) 1/9/95
 */
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <urcu/list.h>

#include "dp_event.h"
#include "fal.h"
#include "if_ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "in6_var.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pl_node.h"
#include "urcu.h"
#include "vplane_log.h"

/*
 * Return NULL if not found or marked for deletion.
 */
struct llentry *
in_lltable_lookup(struct ifnet *ifp, u_int flags, in_addr_t addr)
{
	struct lltable *llt = ifp->if_lltable;
	struct llentry *lle;
	unsigned long hash = lla_hash(llt, addr);
	char b[INET_ADDRSTRLEN];
	int ret;

	lle = lla_lookup(llt, hash, addr);
	if (unlikely(lle == NULL)) {
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = addr,
		};

		if (!(flags & LLE_CREATE))
			return NULL;

		lle = llentry_new(&sin, sizeof(sin), ifp);
		if (lle == NULL)
			return NULL;

		lle->la_flags = flags & ~LLE_CREATE;
		if (if_is_features_mode_active(
			    ifp, IF_FEAT_MODE_EVENT_L3_FAL_ENABLED))
			lle->la_flags |= LLE_HW_UPD_PENDING;

		struct cds_lfht_node *node;
		node = cds_lfht_add_unique(llt->llt_hash, hash,
					   lla_match, &addr, &lle->ll_node);

		/* If lost race on insert, use the winner. */
		if (unlikely(node != &lle->ll_node)) {
			llentry_free(lle);
			lle = caa_container_of(node, struct llentry, ll_node);
		} else {
			/* if on master thread */
			if (is_master_thread() && if_is_features_mode_active(
				    ifp, IF_FEAT_MODE_EVENT_L3_FAL_ENABLED)) {
				ret = fal_ip4_new_neigh(lle->ifp->if_index,
							&sin, 0, NULL);
				if (ret < 0 && ret != -EOPNOTSUPP) {
					RTE_LOG(NOTICE, DATAPLANE,
						"FAL new neighbour %s, %s failed: %s\n",
						inet_ntop(AF_INET, &addr, b,
							  sizeof(b)),
						lle->ifp->if_name,
						strerror(-ret));
				}
				if (ret >= 0) {
					rte_spinlock_lock(&lle->ll_lock);
					lle->la_flags |= LLE_CREATED_IN_HW;
					rte_spinlock_unlock(&lle->ll_lock);
				}
			}
			/*
			 * Fire the timer so it can be sourced in the
			 * hardware on the master thread and/or
			 * neighbour-sourced routes installed.
			 */
			rte_timer_reset(&llt->lle_timer, 0,
					SINGLE, rte_get_master_lcore(),
					lladdr_timer, llt);
		}
	} else if (unlikely(flags & LLE_DELETE)) {
		/*
		 * Only delete static or idle entries.
		 * Leave dynamic in-use entries to time out - kernel may
		 * think they are stale but they may be in active use
		 * by the dataplane.
		 */
		if ((lle->la_flags & LLE_STATIC) ||
		    !llentry_has_been_used(lle)) {
			rte_spinlock_lock(&lle->ll_lock);
			arp_entry_destroy(llt, lle);
			rte_spinlock_unlock(&lle->ll_lock);
			lle = NULL;
		}
	}

	return lle;
}

struct lltable *
in_domifattach(struct ifnet *ifp)
{
	struct lltable *llt;

	llt = lltable_new(ifp);

	llt->lle_refresh_expire = rte_get_timer_cycles() + rte_get_timer_hz();
	rte_timer_reset(&llt->lle_timer, rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(),
			lladdr_timer, llt);
	pl_node_add_feature_by_inst(
		&ipv4_in_no_address_feat, ifp);

	return llt;
}

/* Is the IPv4 address a broadcast address on this interface? */
bool ifa_broadcast(struct ifnet *ifp, uint32_t dst)
{
	struct if_addr *ifa;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *)&ifa->ifa_broadcast;

		if (sa->sa_family != AF_INET)
			continue;

		if (satosin(sa)->sin_addr.s_addr == dst)
			return true;
	}

	return false;
}

static struct if_addr *ifa_find(struct ifnet *ifp, int family,
				const void *addr, uint8_t prefixlen)
{
	struct if_addr *ifa;

	cds_list_for_each_entry(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;

		if (sa->sa_family != family)
			continue;
		if (ifa->ifa_prefixlen != prefixlen)
			continue;

		switch (family) {
		case AF_INET:
			sin = satosin(sa);
			if (sin->sin_addr.s_addr != *(const uint32_t *)addr)
				continue;
			break;

		case AF_INET6:
			sin6 = satosin6(sa);
			if (memcmp(&sin6->sin6_addr, addr,
				   sizeof(struct in6_addr)))
				continue;
			break;
		default:
			rte_panic("unknown family: %u\n", family);
		}

		return ifa;
	}

	return NULL;
}

static
void ifa_update(struct if_addr *ifa, int family,
		uint32_t scope, const void *broadcast)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (family) {
	case AF_INET:
		if (broadcast) {
			sin = satosin((struct sockaddr *) &ifa->ifa_broadcast);
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = *(const uint32_t *) broadcast;
		}
		break;

	case AF_INET6:
		sin6 = satosin6((struct sockaddr *)&ifa->ifa_addr);
		sin6->sin6_scope_id = scope;
		break;
	}
}

void ifa_add(int ifindex, int family, uint32_t scope,
	     const void *addr, uint8_t len, const void *broadcast)
{
	struct ifnet *ifp;
	struct if_addr *ifa;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp)
		return;

	ifa = ifa_find(ifp, family, addr, len);
	if (!ifa) {
		ifa = calloc(1, sizeof(*ifa));
		if (!ifa) {
			RTE_LOG(NOTICE, DATAPLANE,
				"out of space for if_addr\n");
			return;
		}

		switch (family) {
		case AF_INET:
			sin = satosin((struct sockaddr *)&ifa->ifa_addr);
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = *(const uint32_t *) addr;
			ifa->ifa_prefixlen = len;
			pl_node_remove_feature_by_inst(
				&ipv4_in_no_address_feat, ifp);
			break;

		case AF_INET6:
			sin6 = satosin6((struct sockaddr *)&ifa->ifa_addr);
			sin6->sin6_family = AF_INET6;
			ifa->ifa_prefixlen = len;
			memcpy(&sin6->sin6_addr, addr, sizeof(struct in6_addr));

			if (!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				pl_node_remove_feature_by_inst(
					&ipv6_in_no_address_feat, ifp);
			break;

		default:	/* unknown protocol */
			free(ifa);
			return;
		}

		ifa_update(ifa, family, scope, broadcast);

		cds_list_add_tail_rcu(&ifa->ifa_link, &ifp->if_addrhead);

		if (family == AF_INET)
			fal_ip4_new_addr(ifindex, ifa);
		else if (family == AF_INET6)
			fal_ip6_new_addr(ifindex, ifa);
	} else {
		ifa_update(ifa, family, scope, broadcast);

		if (family == AF_INET)
			fal_ip4_upd_addr(ifindex, ifa);
		else if (family == AF_INET6)
			fal_ip6_upd_addr(ifindex, ifa);
	}
}

static void ifa_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct if_addr, ifa_rcu));
}

uint32_t ifa_count_addr(struct ifnet *ifp, int family)
{
	struct if_addr *ifa;
	uint32_t count = 0;

	cds_list_for_each_entry(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *)&ifa->ifa_addr;

		if (sa->sa_family != family)
			continue;

		if (family == AF_INET6 &&
		    IN6_IS_ADDR_LINKLOCAL(IFA_IN6(ifa)))
			continue;

		count++;
	}
	return count;
}

bool ifa_has_addr(struct ifnet *ifp, int family)
{
	return ifa_count_addr(ifp, family) != 0;
}

void ifa_remove(int ifindex, int family, const void *addr, uint8_t prefixlen)
{
	struct ifnet *ifp;
	struct if_addr *ifa;

	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp)
		return;

	ifa = ifa_find(ifp, family, addr, prefixlen);
	if (ifa) {
		if (family == AF_INET)
			fal_ip4_del_addr(ifindex, ifa);
		else if (family == AF_INET6)
			fal_ip6_del_addr(ifindex, ifa);

		cds_list_del_rcu(&ifa->ifa_link);
		call_rcu(&ifa->ifa_rcu, ifa_free);

		/* Check if all addresses removed */
		if (!ifa_has_addr(ifp, AF_INET))
			pl_node_add_feature_by_inst(
				&ipv4_in_no_address_feat, ifp);
		if (!ifa_has_addr(ifp, AF_INET6))
			pl_node_add_feature_by_inst(
				&ipv6_in_no_address_feat, ifp);
	}
}

void ifa_flush(struct ifnet *ifp)
{
	struct if_addr *ifa, *tmp;

	cds_list_for_each_entry_safe(ifa, tmp, &ifp->if_addrhead, ifa_link) {
		cds_list_del_rcu(&ifa->ifa_link);
		call_rcu(&ifa->ifa_rcu, ifa_free);
	}
	pl_node_add_feature_by_inst(
		&ipv4_in_no_address_feat, ifp);
	pl_node_add_feature_by_inst(
		&ipv6_in_no_address_feat, ifp);
}
