/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_MAP_H_
#define _CGN_MAP_H_

struct cgn_session;
struct cgn_packet;
struct cgn_policy;
struct cgn_source;
struct nat_pool;
struct apm;

/*
 * Addresses are in network byte-order.  proto is of type enum npf_proto_idx.
 */
int
cgn_map_get(struct cgn_policy *cp, vrfid_t vrfid, uint8_t proto,
	    uint32_t oaddr, uint32_t *taddr, uint16_t *tport,
	    struct cgn_source **srcp);

/*
 * Use the mapping given in taddr and tport.  Used by PCP.
 */
int
cgn_map_get2(struct cgn_policy *cp, vrfid_t vrfid, uint8_t proto,
	     uint32_t oaddr, uint32_t taddr, uint16_t tport,
	     struct cgn_source **srcp);

int cgn_map_put(struct nat_pool *np, vrfid_t vrfid, int dir, uint8_t proto,
		uint32_t oaddr, uint32_t taddr, uint16_t tport);

void cgn_alloc_pool_available(struct nat_pool *np, struct apm *apm);

#endif
