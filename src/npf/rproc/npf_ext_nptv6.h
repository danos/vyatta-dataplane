/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_EXT_NPTV6_H
#define NPF_EXT_NPTV6_H

/*
 * Returns either NPF_DECISION_PASS or NPF_DECISION_BLOCK
 */
npf_decision_t nptv6_translate(npf_cache_t *npc, struct rte_mbuf **nbuf,
			       void *arg, int *icmp_type, int *icmp_code);

#endif
