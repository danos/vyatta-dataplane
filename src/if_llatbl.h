/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
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

#ifndef	IF_LLATBL_H
#define	IF_LLATBL_H

#include <netinet/in.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <rte_spinlock.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "compiler.h"
#include "if_var.h"
#include "urcu.h"

#define ARP_MAXHOLD	8	/* packets held until entry resolved */
#define ARP_MAXPROBES	5	/* send at most 5 requests  */

/* timer values */
#define ARPT_KEEP	(20*60)	/* once resolved, good for 20 * minutes */

/*
 * Generic neighbor ND/ARP entry
 *
 * This structure is hand tuned so that the lookup elements
 * are in the 1st cache line and the admin data is in later cache lines.
 *
 * The Ethernet address needs to be updated atomicly
 * which explains the 64 bit union.
 *
 * The used flag (idle) is zero based since doing an atomic
 * clear on x86 is does not have to be a locked operation.
 */
struct llentry {
	struct cds_lfht_node	ll_node;
	struct ifnet            *ifp;
	union llentry_addr {
		uint64_t	lu_addr_flags;
		struct {
			struct rte_ether_addr lu_addr;
			uint16_t	lu_flags;
		};
	} ll_u;
#define ll_addr ll_u.lu_addr
#define la_flags ll_u.lu_flags
	rte_atomic16_t		ll_idle;	/* 0 if used */
	uint8_t			la_numheld;
	uint8_t			la_asked;
	uint8_t			la_state;
	uint8_t			pad1[3];
	rte_spinlock_t		ll_lock;
	uint8_t			pad2[4];
	struct sockaddr_storage ll_sock;
	/* --- cacheline 2 boundary (128 bytes) was 48 bytes ago --- */
	uint64_t		ll_expire;
	struct rcu_head		ll_rcu;
	/* --- cacheline 3 boundary (192 bytes) was 8 bytes ago --- */
	struct rte_mbuf		*la_held[ARP_MAXHOLD];
};

static_assert(offsetof(struct llentry, ll_sock) < 64,
	      "first cache line exceeded");

LIST_HEAD(llentries, llentry);

static inline struct sockaddr *ll_sockaddr(struct llentry *lle)
{
	return (struct sockaddr *)&lle->ll_sock;
}

struct lltable {
	struct cds_lfht		*llt_hash;
	uint32_t		lle_seed;
	struct ifnet		*llt_ifp;
	struct rte_timer	lle_timer;
	uint16_t		lle_unrtoken;
	rte_atomic16_t		lle_restoken;
	rte_atomic32_t		lle_size;
	uint64_t		lle_refresh_expire;
};

/*
 * flags stored with entry
 */
#define LLE_DELETED		0x0001	/* entry must be deleted */
#define LLE_STATIC		0x0002	/* entry is static */
#define LLE_VALID		0x0004	/* ll_addr is valid */
#define LLE_PROXY		0x0008	/* should do proxy for this entry */
#define LLE_CTRL		0x0010  /* control plane interest */
#define LLE_FWDING		0x0020  /* forwarding is aware of this entry */
#define LLE_CREATED_IN_HW	0x0040  /* Sourced in the hardware */
#define LLE_HW_UPD_PENDING	0x0080  /* Incompleted in the hardware */

/*
 * flags indicating synchronization
 */
#define LLE_LOCAL	0x0100	/* entry created on dataplane */

/*
 * flags to be passed to arplookup.
 */
#define	LLE_DELETE	0x0400	/* delete on a lookup - match LLE_IFADDR */
#define	LLE_CREATE	0x0800	/* create on a lookup miss */

/*
 * mask of internal flags, i.e. that are set in the LLE, but shouldn't
 * be displayed to the user.
 */
#define LLE_INTERNAL_MASK (LLE_FWDING | LLE_CREATED_IN_HW |	\
			   LLE_HW_UPD_PENDING)

struct lltable *lltable_new(struct ifnet *ifp);
void lltable_stop_timer(struct lltable *);
void lltable_free_rcu(struct lltable *);

typedef unsigned int lltable_iter_func_t(struct lltable *, struct llentry *,
					void *arg);
unsigned int lltable_walk(struct lltable *llt, lltable_iter_func_t func,
			  void *arg);
void lltable_flush(struct lltable *);
bool lltable_fal_l3_change(struct lltable *llt, bool enable);

/* Final destroy on main thread */
void __llentry_destroy(struct lltable *llt, struct llentry *lle);
/* Destroy on any thread */
unsigned int llentry_destroy(struct lltable *, struct llentry *);
void llentry_free(struct llentry *);

struct llentry *in_lltable_lookup(struct ifnet *ifp, u_int flags,
					 in_addr_t addr);

struct llentry *llentry_new(const void *c, size_t len, struct ifnet *ifp);

unsigned long lla_hash(const struct lltable *llt, in_addr_t key);
int lla_match(struct cds_lfht_node *node, const void *key)
	__hot_func;

/*
 * Fast link layer address lookup function.
 * Assumes rcu_read_lock
 */
static inline struct llentry *
lla_lookup(struct lltable *llt, unsigned long hash, in_addr_t addr)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(llt->llt_hash, hash,
			lla_match, &addr, &iter);

	node = cds_lfht_iter_get_node(&iter);
	return node ? caa_container_of(node, struct llentry, ll_node) : NULL;
}

/* Minimized inline link address lookup */
static inline struct llentry *
in_lltable_find(struct ifnet *ifp, in_addr_t addr)
{
	struct lltable *llt = ifp->if_lltable;

	return lla_lookup(llt, lla_hash(llt, addr), addr);
}

bool lltable_probe_timer_is_enabled(void);
void lltable_probe_timer_set_enabled(bool enable);

/* If the entry is v4 return a ptr to the  v4 addr, otherwise null */
struct in_addr *ll_ipv4_addr(struct llentry *lle);
/* If the entry is v6 return a ptr to the  v4 addr, otherwise null */
struct in6_addr *ll_ipv6_addr(struct llentry *lle);

static ALWAYS_INLINE bool
llentry_copy_mac(struct llentry *la,  struct rte_ether_addr *desten)
{
	if (likely(la && (la->la_flags & LLE_VALID))) {
		if (rte_atomic16_read(&la->ll_idle))
			rte_atomic16_clear(&la->ll_idle);
		rte_ether_addr_copy((struct rte_ether_addr *)&la->ll_addr,
				    desten);
		return true;
	}
	return false;
}

/* Check if an lle has been used in HW or SW and reset the used bit */
bool
llentry_has_been_used_and_clear(struct llentry *lle);

/* Check if an lle has been used in HW or SW */
bool
llentry_has_been_used(struct llentry *lle);

/*
 * Issue updates that have been deferred from a non-main thread.
 *
 * Should be called without lle spinlock held.
 */
void
llentry_issue_pending_fal_updates(struct llentry *lle);

#endif	/* IF_LLATBL_H */
