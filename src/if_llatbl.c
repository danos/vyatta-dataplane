/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2004 Luigi Rizzo, Alessandro Cerri. All rights reserved.
 * Copyright (c) 2004-2008 Qing Li. All rights reserved.
 * Copyright (c) 2008 Kip Macy. All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "dp_event.h"
#include "fal.h"
#include "if_ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "lcore_sched.h"
#include "main.h"
#include "nd6_nbr.h"
#include "pktmbuf_internal.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

/* Bounds for auto resizing hash table */
#define	LL_HASHTBL_MIN  32
#define LL_HASHTBL_BITS 13
#define LL_HASHTBL_MAX	(1u << LL_HASHTBL_BITS)

static bool lltable_probe_timer_enabled = true;

bool lltable_probe_timer_is_enabled(void)
{
	return lltable_probe_timer_enabled;
}

void lltable_probe_timer_set_enabled(bool enable)
{
	lltable_probe_timer_enabled = enable;
}

/* Convert 4 byte IP address to a hash value. */
unsigned long lla_hash(const struct lltable *llt, in_addr_t key)
{
	return hash32(key ^ llt->lle_seed, LL_HASHTBL_BITS);
}

/* Compare the IP address of the entry with the desired value. */
int lla_match(struct cds_lfht_node *node, const void *key)
{
	struct llentry *lle = caa_container_of(node, struct llentry, ll_node);
	struct sockaddr_in *sa2 = (struct sockaddr_in *) ll_sockaddr(lle);
	const in_addr_t *addr = key;

	return sa2->sin_addr.s_addr == *addr;
}

static void llentry_free_rcu(struct rcu_head *head)
{
	struct llentry *lle = caa_container_of(head, struct llentry, ll_rcu);

	llentry_free(lle);
}

static void
llentry_routing_uninstall(struct llentry *lle)
{
	lle->la_flags &= ~LLE_FWDING;
	switch (lle->ll_sock.ss_family) {
	case AF_INET:
		routing_remove_arp_safe(lle);
		break;
	case AF_INET6:
		routing6_remove_neigh_safe(lle);
		break;
	}
}

static int
llentry_fal_destroy(struct lltable *llt, struct llentry *lle)
{
	struct ifnet *ifp = llt->llt_ifp;
	char b[INET6_ADDRSTRLEN];
	int ret = 0;

	llentry_routing_uninstall(lle);

	if (lle->la_flags & LLE_CREATED_IN_HW) {
		if (lle->ll_sock.ss_family == AF_INET) {
			ret = fal_ip4_del_neigh(ifp->if_index,
						ifp->fal_l3,
						satosin(ll_sockaddr(lle)));
			if (ret < 0) {
				RTE_LOG(NOTICE, DATAPLANE,
					"FAL neighbour del for %s, %s failed: %s\n",
					inet_ntop(lle->ll_sock.ss_family,
					   &satosin(ll_sockaddr(lle))->sin_addr,
						  b, sizeof(b)),
					ifp->if_name, strerror(-ret));
			}
		} else if (lle->ll_sock.ss_family == AF_INET6) {
			ret = fal_ip6_del_neigh(ifp->if_index,
						ifp->fal_l3,
						satosin6(ll_sockaddr(lle)));
			if (ret < 0) {
				RTE_LOG(NOTICE, DATAPLANE,
					"FAL neighbour del for %s, %s failed: %s\n",
					inet_ntop(lle->ll_sock.ss_family,
						  &satosin6(
						   ll_sockaddr(lle))->sin6_addr,
						  b, sizeof(b)),
					ifp->if_name, strerror(-ret));
			}
		}
	}

	return ret;
}

/* Drops entry, and frees the pending packets.
 * Final free done after RCU grace period.
 */
void
__llentry_destroy(struct lltable *llt, struct llentry *lle)
{
	llentry_routing_uninstall(lle);

	llentry_fal_destroy(llt, lle);

	cds_lfht_del(llt->llt_hash, &lle->ll_node);
	call_rcu(&lle->ll_rcu, llentry_free_rcu);
}

/* Marks entry as DELETED, so that the main thread can then pick it
 * up from the timer and complete the deletion.
 * Must be protected by spinlock.
 */
unsigned
llentry_destroy(struct lltable *llt, struct llentry *lle)
{
	unsigned int dropped = lle->la_numheld;

	if (lle->la_flags & LLE_VALID) {
		if (lle->ll_sock.ss_family == AF_INET)
			ARPSTAT_INC(if_vrfid(llt->llt_ifp), total_deleted);
	}

	lle->la_flags |= LLE_DELETED;

	pktmbuf_free_bulk(lle->la_held, dropped);
	lle->la_numheld = 0;

	if (is_main_thread())
		__llentry_destroy(llt, lle);
	else
		/* Fire the timer for this table immediately on main */
		rte_timer_reset(&llt->lle_timer, 0,
				SINGLE, rte_get_master_lcore(),
				lladdr_timer, llt);

	rte_atomic32_dec(&llt->lle_size);

	return dropped;
}

static unsigned
llentry_flush_cb(struct lltable *llt, struct llentry *lle, void *arg __unused)
{
	return llentry_destroy(llt, lle);
}

/*
 * Walk all entries in hash list.
 * Must be safe for function to delete current entry
 */
unsigned int
lltable_walk(struct lltable *llt, lltable_iter_func_t func, void *arg)
{
	struct llentry *lle;
	struct cds_lfht_iter iter;
	unsigned int count = 0;

	cds_lfht_for_each_entry(llt->llt_hash, &iter, lle, ll_node) {
		rte_spinlock_lock(&lle->ll_lock);
		count += (func)(llt, lle, arg);
		rte_spinlock_unlock(&lle->ll_lock);
	}

	return count;
}

void
lltable_flush(struct lltable *llt)
{
	lltable_walk(llt, llentry_flush_cb, NULL);
}

void
lltable_stop_timer(struct lltable *llt)
{
	rte_timer_stop(&llt->lle_timer);
}

/*
 * Free all entries from given table and free itself, called from RCU
 * context.
 */
void
lltable_free_rcu(struct lltable *llt)
{
	dp_ht_destroy_deferred(llt->llt_hash);
	free(llt);
}

/*
 * Create a new lltable.
 */
struct lltable *
lltable_new(struct ifnet *ifp)
{
	struct lltable *llt;

	llt = zmalloc_aligned(sizeof(*llt));
	if (!llt)
		rte_panic("Can't allocate lltable\n");

	llt->llt_ifp = ifp;
	llt->lle_seed = random();
	llt->llt_hash = cds_lfht_new(LL_HASHTBL_MIN, LL_HASHTBL_MIN,
				     LL_HASHTBL_MAX,
				     CDS_LFHT_AUTO_RESIZE, NULL);
	if (!llt->llt_hash)
		rte_panic("Can't allocate lltable hash\n");

	rte_timer_init(&llt->lle_timer);
	llt->lle_unrtoken = 0;
	rte_atomic16_set(&llt->lle_restoken, ND6_RES_TOKEN);
	rte_atomic32_clear(&llt->lle_size);

	return llt;
}

static unsigned
lltable_fal_l3_enable_cb(struct lltable *llt __unused, struct llentry *lle,
			 void *arg)
{
	bool *any_entries = arg;

	lle->la_flags |= LLE_HW_UPD_PENDING;
	*any_entries = true;

	return 0;
}

static unsigned
lltable_fal_l3_disable_cb(struct lltable *llt, struct llentry *lle,
			  void *arg __unused)
{
	int ret;

	lle->la_flags &= ~LLE_HW_UPD_PENDING;
	/*
	 * Do it straight away rather than deferring to timer callback
	 * because we are on the main thread and the FAL router
	 * interface object that these entries depend on is about to
	 * be deleted.
	 */
	ret = llentry_fal_destroy(llt, lle);
	if (!ret)
		lle->la_flags &= ~LLE_CREATED_IN_HW;

	return 0;
}

bool
lltable_fal_l3_change(struct lltable *llt, bool enable)
{
	bool any_entries = false;

	if (enable)
		lltable_walk(llt, lltable_fal_l3_enable_cb, &any_entries);
	else
		lltable_walk(llt, lltable_fal_l3_disable_cb, NULL);

	return any_entries;
}

void llentry_free(struct llentry *lle)
{
	if (lle->la_numheld != 0)
		RTE_LOG(ERR, DATAPLANE,
			"%s(%p) possible mbuf leak (%#x %d)\n",
			__func__, lle, lle->la_flags, lle->la_numheld);

	rte_free(lle);
}

struct llentry *llentry_new(const void *c, size_t len, struct ifnet *ifp)
{
	struct llentry *lle;

	lle = rte_zmalloc_socket("llentry", sizeof(*lle) + len,
				 RTE_CACHE_LINE_SIZE, ifp->if_socket);
	if (lle) {
		cds_lfht_node_init(&lle->ll_node);
		rte_atomic16_clear(&lle->ll_idle);
		rte_spinlock_init(&lle->ll_lock);

		memcpy(ll_sockaddr(lle), c, len);
		lle->ifp = ifp;
	}
	return lle;
}

struct in_addr *ll_ipv4_addr(struct llentry *lle)
{
	if (lle->ll_sock.ss_family == AF_INET)
		return &satosin(ll_sockaddr(lle))->sin_addr;

	return NULL;
}

struct in6_addr *ll_ipv6_addr(struct llentry *lle)
{
	if (lle->ll_sock.ss_family == AF_INET6)
		return &satosin6(ll_sockaddr(lle))->sin6_addr;

	return NULL;
}

static bool
_llentry_has_been_used(struct llentry *lle, bool clear)
{
	struct fal_attribute_t attr = {
		.id = FAL_NEIGH_ENTRY_ATTR_USED,
	};
	bool used_sw;
	char b[INET6_ADDRSTRLEN];
	bool used_hw = false;
	int ret;

	if (clear)
		/* test_and_set returns 0 if flag is already set. */
		used_sw = rte_atomic16_test_and_set(&lle->ll_idle);
	else
		used_sw = !rte_atomic16_read(&lle->ll_idle);

	ret = fal_ip_get_neigh_attrs(
		lle->ifp->if_index,
		lle->ifp->fal_l3,
		ll_sockaddr(lle),
		1, &attr);
	if (!ret && attr.value.booldata)
		used_hw = true;
	if (used_hw && clear) {
		attr.value.booldata = false;
		ret = fal_ip_upd_neigh(
			lle->ifp->if_index,
			lle->ifp->fal_l3,
			ll_sockaddr(lle),
			&attr);
		if (ret) {
			void *addr_ptr =
				lle->ll_sock.ss_family == AF_INET ?
				(void *)&satosin(ll_sockaddr(lle))->sin_addr :
				(void *)&satosin6(ll_sockaddr(lle))->sin6_addr;
			RTE_LOG(NOTICE, DATAPLANE,
				"FAL neighbour clear used bit for %s, %s failed: %s\n",
				inet_ntop(lle->ll_sock.ss_family,
					  addr_ptr, b, sizeof(b)),
				lle->ifp->if_name, strerror(-ret));
		}
	}

	return used_sw || used_hw;
}

bool
llentry_has_been_used_and_clear(struct llentry *lle)
{
	return _llentry_has_been_used(lle, true);
}

bool
llentry_has_been_used(struct llentry *lle)
{
	return _llentry_has_been_used(lle, false);
}

void
llentry_issue_pending_fal_updates(struct llentry *lle)
{
	struct fal_attribute_t attr_list[2];
	char b[INET6_ADDRSTRLEN];
	uint32_t attr_count = 0;
	bool new = false;
	bool upd = false;
	void *addr_ptr;
	int ret = 0;

	addr_ptr = lle->ll_sock.ss_family == AF_INET ?
		(void *)&satosin(ll_sockaddr(lle))->sin_addr :
		(void *)&satosin6(ll_sockaddr(lle))->sin6_addr;

	rte_spinlock_lock(&lle->ll_lock);
	if (lle->la_flags & LLE_HW_UPD_PENDING) {
		if (lle->la_flags & LLE_VALID) {
			if (lle->la_flags & LLE_CREATED_IN_HW)
				upd = true;
			attr_list[0].id =
				FAL_NEIGH_ENTRY_ATTR_DST_MAC_ADDRESS;
			attr_list[0].value.mac = lle->ll_addr;
			attr_count++;
		}
		if (!(lle->la_flags & LLE_CREATED_IN_HW) &&
		    if_is_features_mode_active(
			    lle->ifp,
			    IF_FEAT_MODE_EVENT_L3_FAL_ENABLED))
			new = true;
		lle->la_flags &= ~LLE_HW_UPD_PENDING;
	}
	rte_spinlock_unlock(&lle->ll_lock);

	if (new) {
		ret = fal_ip_new_neigh(lle->ifp->if_index,
				       lle->ifp->fal_l3,
				       ll_sockaddr(lle), attr_count,
				       attr_list);
		if (ret < 0 && ret != -EOPNOTSUPP) {
			RTE_LOG(NOTICE, DATAPLANE,
				"FAL new neighbour %s, %s failed: %s\n",
				inet_ntop(lle->ll_sock.ss_family,
					  addr_ptr,
					  b, sizeof(b)),
				lle->ifp->if_name, strerror(-ret));
		}
		if (ret >= 0) {
			rte_spinlock_lock(&lle->ll_lock);
			lle->la_flags |= LLE_CREATED_IN_HW;
			rte_spinlock_unlock(&lle->ll_lock);
		}
	} else if (upd) {
		ret = fal_ip_upd_neigh(lle->ifp->if_index,
				       lle->ifp->fal_l3,
				       ll_sockaddr(lle),
				       attr_list);
		if (ret < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"FAL neighbour mac update for %s, %s failed: %s\n",
				inet_ntop(lle->ll_sock.ss_family,
					  addr_ptr,
					  b, sizeof(b)),
				lle->ifp->if_name, strerror(-ret));
		}
	}
}
