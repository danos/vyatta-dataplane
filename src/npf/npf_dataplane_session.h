/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_DATAPLANE_SESSION_H
#define NPF_DATAPLANE_SESSION_H

#include <rte_mbuf.h>

#include "if_var.h"

#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "npf/npf_nat.h"

/* Protos */
int npf_dataplane_session_establish(npf_session_t *se, npf_cache_t *npc,
		struct rte_mbuf *nbuf, const struct ifnet *ifp);

#endif /* NPF_DATAPLANE_SESSION_H */
