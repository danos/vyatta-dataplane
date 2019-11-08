/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_map.c - Allocation and release of cgnat addresses, port-blocks,
 * and ports.
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <dpdk/rte_jhash.h>

#include "compiler.h"
#include "if_var.h"
#include "urcu.h"
#include "util.h"

#include "npf/npf_addrgrp.h"

#include "npf/nat/nat_pool.h"

#include "npf/cgnat/cgn.h"
#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_errno.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"



/* CGN_BLK_ENOSPC */
static inline void cgn_alloc_log_pb_full(struct apm *apm)
{
	if (!apm->apm_pb_full)
		cgn_log_public_pb_full(apm->apm_addr,
				       apm->apm_blocks_used,
				       apm->apm_nblocks);

	apm->apm_pb_full = true;
}

/* CGN_POOL_ENOSPC */
static inline void cgn_alloc_pool_full(struct nat_pool *np)
{
	if (!np->np_full)
		RTE_LOG(NOTICE, CGNAT, "NP_FULL name=%s\n",
			np->np_name);

	np->np_full = true;
}

/*
 * Round-robin address allocation.
 *
 * Very simple. Each invocation uses the address after the one allocated by
 * the previous invocation.  After each allocation, we store the address
 * in the pools np_addr_hint object.
 *
 * Note that the apm is *not* locked anytime in this function.
 */
static struct apm *
cgn_alloc_addr_rrobin(struct nat_pool *np, uint8_t proto, uint32_t addr_hint,
		      vrfid_t vrfid, int *error)
{
	uint32_t addr, start_addr;
	struct apm *apm;

	addr = start_addr = addr_hint;

	/* Iterate over all addresses in all address ranges */
	do {
		/* Ignore blacklisted addresses */
		if (nat_pool_is_blacklist_addr(np, htonl(addr)))
			goto next_addr;

		apm = apm_lookup(addr, vrfid);

		if (!apm) {
			apm = apm_create_and_insert(addr, vrfid, np, error);

			/* Either out of memory, or apm table is full */
			if (unlikely(!apm))
				return NULL;
		}

		if (apm->apm_blocks_used < apm->apm_nblocks) {
			nat_pool_hint_set(np, addr, proto);
			return apm;
		}

next_addr:
		addr = nat_pool_next_addr(np, addr);
	} while (addr != start_addr);

	/* All pool addresses are in-use and with no free blocks */
	*error = -CGN_POOL_ENOSPC;
	cgn_alloc_pool_full(np);

	return NULL;
}

/*
 * Allocate a port block from the given public address ('apm').
 *
 * 'block_hint' is the block number to start with within the apm block array.
 * This will be 0 for the first allocaton from an apm.
 */
static struct apm_port_block *
cgn_alloc_block(struct nat_pool *np, struct apm *apm, uint16_t block_hint,
		int *error)
{
	struct apm_port_block *pb;
	uint16_t block, i;

	/*
	 * Lock the apm so we can allocate a port block
	 */
	rte_spinlock_lock(&apm->apm_lock);

	/* Was the apm destroyed while we waited for the lock? */
	if ((apm->apm_flags & APM_DEAD) != 0) {
		*error = -CGN_APM_ENOENT;
		goto error;
	}

	/* Were apm blocks used-up while waiting for the lock? */
	if (apm->apm_blocks_used >= apm->apm_nblocks) {
		*error = -CGN_BLK_ENOSPC;
		cgn_alloc_log_pb_full(apm);
		goto error;
	}

	/*
	 * Round-robin allocation of blocks.  Start with 'block_hint' block.
	 */
	for (i = 0, block = block_hint; i < apm->apm_nblocks; i++, block++) {
		if (block >= apm->apm_nblocks)
			block = 0;

		/* Is this block in-use? */
		if (apm->apm_blocks[block])
			continue;

		/* Create a port block */
		pb = apm_block_create(apm, block);

		if (!pb) {
			*error = -CGN_PB_ENOMEM;
			goto error;
		}

		/* Success */
		rte_spinlock_unlock(&apm->apm_lock);

		nat_pool_incr_block_allocs(np);
		nat_pool_incr_block_active(np);

		return pb;
	}

	/*
	 * We shouldn't get here since we checked apm_blocks_used before the
	 * above loop.
	 */
	*error = -CGN_BLK_ENOSPC;
	cgn_alloc_log_pb_full(apm);

error:
	rte_spinlock_unlock(&apm->apm_lock);

	nat_pool_incr_block_fails(np);
	return NULL;
}

/*
 * Find a free port in any of the port-blocks already in-use by a subscriber,
 * except the active block (since we will already have checked that).
 */
static uint16_t
cgn_source_find_port(struct apm_port_block **pbp, struct cgn_source *src,
		     uint8_t proto)
{
	return apm_block_list_first_free_port(&src->sr_block_list, proto,
					      src->sr_active_block[proto],
					      pbp);
}

/*
 * Allocate an address and port.
 *
 * Writes to *taddr and *tport (in network byte order), and to **srcp.
 * Returns 'enum cgn_errno'.
 */
int
cgn_map_get(struct cgn_policy *cp, vrfid_t vrfid, uint8_t proto,
	    uint32_t oaddr, uint32_t *taddr, uint16_t *tport,
	    struct cgn_source **srcp)
{
	struct apm_port_block *pb;
	struct cgn_source *src;
	struct nat_pool *np;
	struct apm *apm;
	uint16_t port;
	int error;

	assert(proto <= NAT_PROTO_LAST);

	np = cgn_policy_get_pool(cp);
	if (!np)
		/* No pool attached to policy, or pool is not active */
		return -CGN_POOL_ENOSPC;

	/* Count of mapping requests ever. Only ever increments */
	nat_pool_incr_map_reqs(np);

	/* Find (or create) and lock a src entry */
	src = cgn_source_find_and_lock(cp, ntohl(oaddr), vrfid, &error);

	if (unlikely(!src)) {
		nat_pool_incr_map_fails(np);
		return error;
	}
	/* Return the subscriber structure pointer to the caller */
	*srcp = src;

	/* src is locked from here on */

	src->sr_map_reqs++;

	/* Get active port-block for this proto */
	pb = src->sr_active_block[proto];

	/*
	 * If there is no active port-block for this protocol:
	 *  1. alloc a public address (apm),
	 *  2. alloc a port-block from that public address,
	 *  3. Add the port-block to the sources block list, and
	 *  4. Mark the port-block as the sources active block
	 */
	if (unlikely(!pb)) {
		/*
		 * Allocate a public address.  First check if there is a valid
		 * paired address for this subscriber.  Else get the next
		 * address in the nat pool after the last allocated address.
		 */
		uint32_t addr_hint;
		int rc;

		/* Does subscriber already have a paired address? */
		if (src->sr_paired_addr) {

			/* Check paired address is still valid */
			rc = nat_pool_addr_range(np, src->sr_paired_addr);
			if (rc < 0)
				src->sr_paired_addr = 0;
		}

		addr_hint = src->sr_paired_addr;
		if (addr_hint == 0) {
			/*
			 * No valid paired address, so get next addr to try
			 * from pool.
			 */
			addr_hint = nat_pool_hint(np, proto);
			addr_hint = nat_pool_next_addr(np, addr_hint);
		}

		/*
		 * Starting at addr_hint, iterate through addresses in the nat
		 * pool until we find one with a free port-block.
		 */
		apm = cgn_alloc_addr_rrobin(np, proto, addr_hint,
					    vrfid, &error);

		/*
		 * Either out of memory, apm table is full, or all addresses
		 * in the nat pool are in-use.
		 */
		if (!apm)
			goto error;

		pb = cgn_alloc_block(np, apm, 0, &error);
		if (!pb)
			goto error;

		cgn_source_add_block(src, proto, pb, np);
	} else {
		apm = apm_block_get_apm(pb);

		if (unlikely(!apm))
			/* Should never happen */
			goto error;
	}

	/*
	 * First we try and allocate a port from the active-block, pb.  This
	 * will be the most likely case.  Allocation within the port-block is
	 * either sequential, or random.
	 */
	if (nat_pool_is_pa_sequential(np))
		port = apm_block_alloc_first_free_port(pb, proto);
	else
		port = apm_block_alloc_random_port(pb, proto);

	if (likely(port > 0))
		goto port_found;

	/*
	 * No free ports in active block, so look for a free port in the
	 * other port-blocks already assigned to the subscriber.
	 */
	port = cgn_source_find_port(&pb, src, proto);
	if (port > 0) {
		/* Set new active port-block for this protocol */
		src->sr_active_block[proto] = pb;
		apm = apm_block_get_apm(pb);
		goto port_found;
	}

	/*
	 * No free ports in any of the port-blocks currently assigned
	 * to the subscriber.  Alloc a new port-block.
	 */

	/*
	 * Before allocating a new port-block, check max-blocks-per-user
	 * limit.
	 */
	if (src->sr_block_count >= nat_pool_get_mbpu(np)) {

		nat_pool_incr_block_limit(np);
		error = -CGN_MBU_ENOSPC;

		if (!src->sr_mbpu_full && net_ratelimit())
			cgn_log_subscriber_mbpu_full(src->sr_addr,
						     src->sr_block_count,
						     nat_pool_get_mbpu(np));

		src->sr_mbpu_full = true;
		goto error;
	}

	/*
	 * Are there any available port-blocks on this public address?
	 */
	if (apm->apm_blocks_used >= apm->apm_nblocks) {
		/*
		 * No free port-blocks.  Alloc a new public address if
		 * address-pool pairing is not enabled.
		 */
		if (nat_pool_is_ap_paired(np)) {
			error = -CGN_BLK_ENOSPC;
			cgn_alloc_log_pb_full(apm);
			goto error;
		} else {
			/* alloc a new public address */
			uint32_t addr_hint;

			addr_hint = nat_pool_hint(np, proto);
			addr_hint = nat_pool_next_addr(np, addr_hint);

			apm = cgn_alloc_addr_rrobin(np, proto, addr_hint,
						    vrfid, &error);
			if (!apm)
				goto error;
		}
	}

	pb = cgn_alloc_block(np, apm, apm_block_get_block(pb) + 1, &error);
	if (!pb)
		goto error;

	/* Add block to source's block list, and set as active block */
	cgn_source_add_block(src, proto, pb, np);

	/* Alloc port from new block */
	if (nat_pool_is_pa_sequential(np))
		port = apm_block_alloc_first_free_port(pb, proto);
	else
		port = apm_block_alloc_random_port(pb, proto);

port_found:
	*taddr = htonl(apm->apm_addr);
	*tport = htons(port);
	rte_atomic32_inc(&src->sr_map_active);

	rte_spinlock_unlock(&src->sr_lock);

	/*
	 * Increment count of current active mappings, and take reference on
	 * pool
	 */
	nat_pool_incr_map_active(np);

	return 0;

error:
	src->sr_map_fails++;
	rte_spinlock_unlock(&src->sr_lock);

	nat_pool_incr_map_fails(np);

	return error;
}

/*
 * Return a mapped address and port.
 */
int cgn_map_put(struct nat_pool *np, vrfid_t vrfid, int dir __unused,
		uint8_t proto, uint32_t oaddr,	uint32_t taddr, uint16_t tport)
{
	struct cgn_source *src;
	struct apm *apm;
	int rc;

	assert(proto <= NAT_PROTO_LAST);
	assert(np);

	apm = apm_lookup(ntohl(taddr), vrfid);
	if (unlikely(!apm))
		return 0;

	src = cgn_source_lookup(ntohl(oaddr), vrfid);
	if (unlikely(!src))
		return 0;

	rte_spinlock_lock(&apm->apm_lock);

	/*
	 * Was apm destroyed while we waited for lock?  This should never
	 * happen in normal operation as only the master thread destroys
	 * sessions, and hence calls cgn_map_put.
	 */
	if (unlikely((apm->apm_flags & APM_DEAD) != 0)) {
		rte_spinlock_unlock(&apm->apm_lock);
		return 0;
	}

	uint16_t port, block;
	struct apm_port_block *pb;

	port = ntohs(tport);
	block = apm_block(port, apm->apm_port_start, apm->apm_port_block_sz);
	pb = apm->apm_blocks[block];
	assert(pb);

	/* Should never happen */
	if (unlikely(!pb)) {
		rte_spinlock_unlock(&apm->apm_lock);
		return 0;
	}

	/* Clear bit in port-block bitmap */
	apm_block_release_port(pb, proto, port);

	/*
	 * Can we free the port block?
	 */
	if (apm_block_get_ports_used(pb) == 0) {
		/*
		 * Delete block from source list.  This spinlocks source
		 * structure and releases reference on source, which may cause
		 * the source to be destroyed.
		 */
		rc = cgn_source_del_block(src, pb, np);
		if (rc < 0)
			src = NULL;

		/* Remove block from apm's block list and rcu-free */
		apm_block_destroy(pb);

		nat_pool_incr_block_freed(np);
		nat_pool_decr_block_active(np);
	}

	if (src)
		rte_atomic32_dec(&src->sr_map_active);

	rte_spinlock_unlock(&apm->apm_lock);

	/*
	 * Decrement count of current active mappings, and release reference
	 * on pool.
	 */
	nat_pool_decr_map_active(np);

	return 0;
}
