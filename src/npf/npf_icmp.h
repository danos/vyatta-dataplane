/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_ICMP_H
#define NPF_ICMP_H

#include "npf/npf_cache.h"
#include "npf/npf_session.h"

struct ifnet;
struct npf_instance;
struct rte_mbuf;

/* Forward Declarations */
typedef struct npf_cache npf_cache_t;

npf_session_t *npf_icmp_err_session_find(int di, struct rte_mbuf *nbuf,
		npf_cache_t *npc, const struct ifnet *ifp);
int npf_icmp_err_nat(npf_cache_t *npc, struct rte_mbuf **nbuf,
		const struct ifnet *ifp, const int di);

#endif /* NPF_ICMP_H */
