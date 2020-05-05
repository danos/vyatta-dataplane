/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
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
#include "ip.h"

struct policy_rule;

#define FLOW_CACHE_SIZE 4096

#define FLOW_CACHE_HASH_SEED 0xDEAFCAFE

/*
 * subset of AFs supported by flow cache
 * allows af to be used as index and enables common code
 */
enum FLOW_CACHE_AF {
	FLOW_CACHE_AF_INET,
	FLOW_CACHE_AF_INET6,
	FLOW_CACHE_AF_MAX
};

struct flow_cache_hash_key {
	enum FLOW_CACHE_AF af;
	union addr_u src;
	union addr_u dst;
	uint32_t proto;
	vrfid_t vrfid;
};

struct flow_cache_entry {
	struct cds_lfht_node fl_node;
	struct rcu_head flow_cache_rcu;
	struct policy_rule *pr;
	struct flow_cache_hash_key key;
	uint16_t context;
	uint32_t hit_count;
	uint32_t last_hit_count;
	char *padding[0]  __rte_cache_aligned;
};

void flow_cache_timer_handler(struct rte_timer *tmr, void *arg);

#endif /* CRYPTO_POLICY_CACHE_H */
