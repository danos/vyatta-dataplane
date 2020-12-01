/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef ARP_H
#define ARP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct ifnet;
struct rte_mbuf;
struct rte_ether_addr;
struct sockaddr;
struct lltable;
struct llentry;

bool arp_input_validate(const struct ifnet *ifp, struct rte_mbuf *m);
int arpresolve(struct ifnet *ifp, struct rte_mbuf *m,
		      in_addr_t addr, struct rte_ether_addr *desten);
int arpresolve_fast(struct ifnet *ifp, struct rte_mbuf *m,
		in_addr_t addr, struct rte_ether_addr *desten);

struct arp_nbr_cfg {
	uint32_t arp_aging_time;
	int32_t  arp_max_entry;
};

extern struct arp_nbr_cfg arp_cfg;

#define ARP_CFG(param) (arp_cfg.param)

struct arp_stats {
	uint64_t txrequests;	/* # of ARP requests sent by this host. */
	uint64_t txreplies;	/* # of ARP replies sent by this host. */
	uint64_t rxrequests;	/* # of ARP requests received by this host. */
	uint64_t rxreplies;	/* # of ARP replies received by this host. */
	uint64_t received;	/* # of ARP packets received by this host. */

	/* Abnormal event and error counting: */
	uint64_t rxignored;	/* # of ARP requests ignored (wrong net) */
	uint64_t dupips;	/* # of duplicate IPs detected. */
	uint64_t dropped;	/* # of packets dropped waiting for a reply. */
	uint64_t timeouts;	/* # of times with entries removed */
				/* due to timeout. */
	uint64_t proxy;		/* # of proxy ARP responses */
	uint64_t garp_reqs_dropped; /* # of GARP requests dropped */
	uint64_t garp_reps_dropped; /* # of GARP replies dropped */
	uint64_t mpoolfail;	/* Memory pool limit hit */
	uint64_t memfail;	/* Out of memory hit */
	uint64_t tablimit;	/* Cache limit hit */
};

#define ARPSTAT_ADD(vrf_id, name, val)			\
	do {						\
		struct vrf *vrf = vrf_get_rcu(vrf_id);	\
		if (vrf)				\
			vrf->v_arpstat.name += (val);	\
	} while (0)

#define ARPSTAT_INC(vrf_id, name)		ARPSTAT_ADD(vrf_id, name, 1)

struct llentry;
typedef void ll_walkhash_f_t(const struct ifnet *, struct llentry *, void *);
void arp_walk(const struct ifnet *, ll_walkhash_f_t *, void *);
struct rte_mbuf *arprequest(struct ifnet *ifp, struct sockaddr *sa);

void arp_entry_destroy(struct lltable *llt, struct llentry *lle);

#endif /* ARP_H */
