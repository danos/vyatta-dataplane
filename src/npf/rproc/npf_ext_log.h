/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_EXT_LOG_H
#define NPF_EXT_LOG_H

struct rte_mbuf;
struct npf_cache;
struct npf_rule;
struct ifnet;

void npf_log_pkt(struct npf_cache *npc, struct rte_mbuf *mbuf,
		 struct npf_rule *rl, int dir);

#endif /* NPF_EXT_LOG_H */
