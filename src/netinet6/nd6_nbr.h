/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <netinet/in.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "arp.h"
#include "if_llatbl.h"
#include "if_var.h"

struct in6_addr;
struct rte_mbuf;

#define ND6_NS_RETRIES 3
#define ND6_REACHABLE_TIME 30
#define ND6_SCAVENGE_TIME (20 * 60) /* Remove stale entries after 20 minutes */
#define ND6_DELAY_TIME 5
#define ND6_MAX_ENTRY 8192 /* Same as yang default for consistency */
#define ND6_RES_TOKEN 100
#define ND6_UNR_TOKEN 2
#define ND6_MAXHOLD ARP_MAXHOLD

struct rte_ether_addr;
struct ifnet;

struct nd6_nbr_cfg {
	uint8_t		nd6_ns_retries;
	uint16_t	nd6_reachable_time;
	uint16_t	nd6_scavenge_time;
	uint16_t	nd6_delay_time;
	int32_t		nd6_max_entry;
	int16_t		nd6_res_token;
	uint16_t	nd6_unr_token;
	uint8_t		nd6_maxhold;
};

struct nd6_nbr_stats {
	uint64_t received;	/* # of ND packets received by this host. */
	uint64_t rxignored;	/* # of requests ignored (wrong net) */
	uint64_t narx;		/* NA received */
	uint64_t natx;		/* NA transmitted */
	uint64_t nsrx;		/* NS received */
	uint64_t nstx;		/* NS transmitted */
	uint64_t ndpunt;	/* NA/NS punts to control plane */
	/* Abnormal event and error counting: */
	uint64_t dupips;	/* # of duplicate IPv6s detected. */
	uint64_t dropped;	/* # of packets dropped waiting for a reply. */
	uint64_t badpkt;	/* bad packet. */
	uint64_t timeouts;	/* Resolution fails */
	uint64_t nudfail;	/* NUD fails */
	uint64_t resthrot;	/* Resolution throttles */
	uint64_t tablimit;	/* Cache limit hit */
	uint64_t mpoolfail;	/* Memory pool limit hit */
};
extern struct nd6_nbr_stats nd6nbrstat;

int nd6_resolve(struct ifnet *in_ifp, struct ifnet *ifp,
		struct rte_mbuf *m, const struct in6_addr *addr,
		struct rte_ether_addr *desten);
int nd6_input(struct ifnet *ifp, struct rte_mbuf *m);

void nd6_nbr_walk(const struct ifnet *, ll_walkhash_f_t *, void *);
void nd6_entry_destroy(struct lltable *llt, struct llentry *lle);
struct llentry *nd6_lookup(const struct in6_addr *, const struct ifnet *);
struct llentry *in6_lltable_lookup(struct ifnet *ifp, u_int flags,
				   const struct in6_addr *);
struct llentry *
lla_lookup6(struct lltable *llt, const struct in6_addr *addr);
int nd6_lladdr_add(struct ifnet *ifp, struct in6_addr *addr,
		   const struct rte_ether_addr *mac, uint16_t state,
		   uint8_t ntf_flags);
int cmd_nd6_set_cfg(FILE *f, int argc, char **argv);
int cmd_nd6_get_cfg(FILE *f);

/* Minimized inline link address lookup */
static inline struct llentry *
in6_lltable_find(struct ifnet *ifp, const struct in6_addr *addr)
{
	struct lltable *llt = ifp->if_lltable6;

	return lla_lookup6(llt, addr);
}

/*
 * Inline optimized version of neighbor resolution
 */
static inline int
nd6_resolve_fast(struct ifnet *in_ifp, struct ifnet *ifp, struct rte_mbuf *m,
		 const struct in6_addr *addr, struct rte_ether_addr *desten)
{
	struct llentry *la;

	la = in6_lltable_find(ifp, addr);
	if (likely(la && (la->la_flags & LLE_VALID))) {
		rte_atomic16_clear(&la->ll_idle);
		rte_ether_addr_copy(&la->ll_addr, desten);
		return 0;
	}

	return nd6_resolve(in_ifp, ifp, m, addr, desten);
}
