/*-
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_POLICY_CACHE_H
#define CRYPTO_POLICY_CACHE_H

#include <assert.h>
#include <stdint.h>

#include "urcu.h"
#include "util.h"

struct policy_rule;

#define POLICY_CACHE_SIZE 4096

#define POLICY_CACHE_HASH_SEED 0xDEAFCAFE

/*
 * Crypto Pkt Buffer (CPB) DB, containing pointers to all the
 * per CORE CPB.
 */
struct crypto_pkt_buffer *cpbdb[RTE_MAX_LCORE];

struct pr_cache_hash_key {
	uint32_t src;
	uint32_t dst;
	uint32_t proto;
	vrfid_t vrfid;
};

struct policy_cache_rule {
	struct cds_lfht_node pr_node;
	struct rcu_head policy_cache_rcu;
	struct policy_rule *pr;
	struct pr_cache_hash_key key;
	uint8_t in_rule_checked:1,
		in_rule_drop:1,
		PR_UNUSED:6;
	char SPARE[7];
	char *padding[0]  __rte_cache_aligned;
};

void pr_cache_timer_handler(struct rte_timer *, void *arg);

#endif /* CRYPTO_POLICY_CACHE_H */
