/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
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
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"


/*
 * Called from cgn_alloc_addr_rrobin when cgnat mapping fails to find an
 * available public  address (CGN_POOL_ENOSPC).
 */
static inline void cgn_alloc_pool_full(struct nat_pool *np)
{
	if (!np->np_full)
		cgn_log_resource_pool(CGN_RESOURCE_FULL, np,
				rte_atomic32_read(&np->np_ranges->nr_used),
				np->np_ranges->nr_naddrs);

	np->np_full = true;
}

/*
 * Called from apm_block_destroy when a port-block on an apm is freed.
 *
 * Refer to cgn_alloc_addr_rrobin to see how we decide if an address is
 * available or not.
 */
void cgn_alloc_pool_available(struct nat_pool *np, struct apm *apm)
{
	if (!np || !np->np_full)
		return;

	/* The apm should be locked */
	assert(rte_spinlock_is_locked(&apm->apm_lock));

	struct nat_pool_range *pr = NULL;
	int range;

	range = nat_pool_addr_range(np, apm->apm_addr);
	if (range >= 0)
		pr = &np->np_ranges->nr_range[range];

	if (apm->apm_blocks_used == 0 || (pr && pr->pr_shared)) {
		cgn_log_resource_pool(
			CGN_RESOURCE_AVAILABLE, np,
			rte_atomic32_read(&np->np_ranges->nr_used),
			np->np_ranges->nr_naddrs);
		np->np_full = false;
	}
}

/*
 * Round-robin address allocation.
 *
 * Each invocation uses the address after the one allocated by the previous
 * invocation.  After each allocation, we store the address in the pools
 * np_addr_hint object.
 *
 * Before we consider an address to use, we check if it has unallocated port
 * blocks.  Addresses with no port blocks in-use are preferred over an address
 * with some port blocks already in-use.
 *
 * On first iteration of the pool addresses we try and identify the "least
 * used" address.  This may be used if an totally unused address is not found.
 *
 * We also make a "last gasp" second iteration of the pool addresses if the
 * above yields no result.  This simply grabs the first address with any free
 * port-blocks.
 *
 * If addr_hint is set then pr may also be set.  If so, then this a pointer to
 * the address range that addr_hint is in.
 *
 * If successful, the returned apm will be LOCKED.
 */
static struct apm *
cgn_alloc_addr_rrobin(struct nat_pool *np, enum nat_proto proto,
		      uint32_t addr_hint, struct nat_pool_range *pr,
		      vrfid_t vrfid, int *error)
{
	uint32_t addr, start_addr;
	struct apm *apm, *lu_apm = NULL;
	bool pass2 = false;

	/* Do not iterate over pool addresses if we know none are available */
repeat:
	if (np->np_full) {
		*error = -CGN_POOL_ENOSPC;
		return NULL;
	}

	addr = start_addr = addr_hint;

	if (!pr) {
		int range = nat_pool_addr_range(np, addr);

		if (range >= 0)
			pr = &np->np_ranges->nr_range[range];
	}

	/* Iterate over all addresses in all address ranges */
	do {
		int lock_result;

		/*
		 * This should almost never happen.  It might only occur if an
		 * address pool has been reconfigured before the stored
		 * address hint has been updated or cleared.
		 */
		if (unlikely(!pr))
			goto next_addr;

		/* Ignore blocked addresses */
		if (nat_pool_is_blocked_addr(np, htonl(addr)))
			goto next_addr;

		apm = apm_lookup(addr, vrfid);

		if (!apm) {
			apm = apm_create_and_insert(addr, vrfid, np, error);

			/* Either out of memory, or apm table is full */
			if (unlikely(!apm))
				return NULL;
		}

		/* LOCK apm before checking if there are free blocks */
		lock_result = rte_spinlock_trylock(&apm->apm_lock);

		/* Lock was unsuccessful, try next address */
		if (lock_result == 0)
			goto next_addr;

		/* Was the apm destroyed between table lookup and lock? */
		if (unlikely((apm->apm_flags & APM_DEAD) != 0)) {
			rte_spinlock_unlock(&apm->apm_lock);
			goto next_addr;
		}

		/* Always pick an unused public address first */
		if (apm->apm_blocks_used == 0)
			goto addr_found;

		/*
		 * Is the address shareable, and does it have some free
		 * port-blocks?
		 */
		if (pr->pr_shared &&
		    (apm->apm_blocks_used < apm->apm_nblocks)) {
			/*
			 * On second iteration through the NAT pool addresses,
			 * we simply use the first shareable address with any
			 * free port-blocks.
			 */
			if (unlikely(pass2))
				goto addr_found;

			/*
			 * On first iteration through the NAT pool addresses,
			 * we try and identify a "least used" address.
			 */
			if (!lu_apm ||
			    (apm->apm_blocks_used < lu_apm->apm_blocks_used))
				lu_apm = apm;
		}

		rte_spinlock_unlock(&apm->apm_lock);

		/* Try the next address in the pool */
next_addr:
		addr = nat_pool_next_addr(np, addr, &pr);
	} while (addr != start_addr);

	/*
	 * No unused addresses were found in first iteration of the pool.  Did
	 * we find a "least used" address?
	 */
	if (lu_apm) {
		int lock_result;

		/*
		 * If we cannot lock the candidate apm, or it is no longer
		 * suitable, then simple fall through to do the second
		 * iteration.
		 */
		apm = lu_apm;
		lock_result = rte_spinlock_trylock(&apm->apm_lock);

		if (lock_result != 0) {
			/* Lock successful.  Can we still use this addr? */
			if ((apm->apm_flags & APM_DEAD) == 0 &&
			    apm->apm_blocks_used < apm->apm_nblocks) {
				/* Use this address */
				addr = apm->apm_addr;
				goto addr_found;
			}

			/*
			 * No longer suitable.  Unlock and do second
			 * iteration.
			 */
			rte_spinlock_unlock(&apm->apm_lock);
		}
	}

	/*
	 * No unused addresses found, and either we failed to find a "least
	 * used" address or we lost the race to use the "least used" address.
	 * Make a last gasp attempt to just grab the first address with any
	 * free port-blocks.
	 */
	if (!pass2) {
		pass2 = true;
		pr = NULL;
		lu_apm = NULL;
		goto repeat;
	}

	/*
	 * We only get here if both: 1. no unshareble addresses are unused,
	 * and 2. no shareable addresses have any free port-blocks.
	 */
	*error = -CGN_POOL_ENOSPC;
	cgn_alloc_pool_full(np);

	return NULL;

addr_found:
	/*
	 * If a suitable address is found then leave the apm LOCKED, set the
	 * address hint in the pool, and return.
	 */
	nat_pool_hint_set(np, addr, proto);
	return apm;
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

	assert(rte_spinlock_is_locked(&apm->apm_lock));

	/* This should have already been checked, but check again */
	if (unlikely(apm->apm_blocks_used >= apm->apm_nblocks)) {
		*error = -CGN_BLK_ENOSPC;
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
		nat_pool_incr_block_allocs(np);
		nat_pool_incr_block_active(np);

		return pb;
	}

	/*
	 * We shouldn't get here since we checked apm_blocks_used before the
	 * above loop.
	 */
	*error = -CGN_BLK_ENOSPC;

error:
	nat_pool_incr_block_fails(np);
	return NULL;
}

/*
 * Find a free port in any of the port-blocks already in-use by a subscriber,
 * except the active block (since we will already have checked that).
 */
static uint16_t
cgn_source_find_port(struct apm_port_block **pbp, struct cgn_source *src,
		     enum nat_proto proto)
{
	return apm_block_list_first_free_port(&src->sr_block_list, proto,
					      src->sr_active_block[proto],
					      pbp);
}

/*
 * Allocate an address and port from the apm module.
 *
 * Inputs:
 *    vrfid
 *    cp			- cgnat policy
 *    cmi->cmi_proto		- 'Condensed' nat proto
 *    cmi->cmi_oaddr		- Subscribers source addr
 *
 * Outputs (if successful):
 *    cmi->cmi_src		- subscriber struct)
 *    cmi->cmi_taddr		- Allocated public addr
 *    cmi->cmi_tid		- Allocated public port
 *    cmi->cmi_reserved = true
 *    return 'enum cgn_errno'
 *
 * There are two locks that may be used here - one in the source address
 * structure (struct cgn_source) and one is in the public address structure
 * (struct apm).
 *
 * If we allocate from a port-block already assigned to the source, then only
 * the source structure needs to be locked.  (So if the port-block size is
 * 512, then for 511 new sessions we only need to lock the source structure.)
 *
 * If we need to get a new port block then we need to lock *both* the source
 * and apm structures while we assign the port block to the source.  After
 * that the apm lock can be released (and source lock kept), while we allocate
 * the port from the port-block.
 */
int
cgn_map_get(struct cgn_map *cmi, struct cgn_policy *cp, vrfid_t vrfid)
{
	struct apm_port_block *pb;
	enum nat_proto proto = cmi->cmi_proto;
	struct cgn_source *src;
	struct nat_pool *np;
	struct apm *apm = NULL;
	uint16_t port;
	int error;

	assert(proto <= NAT_PROTO_LAST);
	assert(cmi->cmi_oaddr);
	assert(cp);

	if (unlikely(!cp || cmi->cmi_oaddr == 0))
		return -CGN_RC_UNKWN;

	/* Get public address pool from the policy */
	np = cgn_policy_get_pool(cp);
	if (!np)
		/* No pool attached to policy, or pool is not active */
		return -CGN_POOL_ENOSPC;

	/* Count of mapping requests ever. Only ever increments */
	nat_pool_incr_map_reqs(np);

	/*
	 * Find (or create) and LOCK a subscriber address structure.  The
	 * source struct remains locked until the end of cgn_map_get.
	 */
	src = cgn_source_find_and_lock(cp, ntohl(cmi->cmi_oaddr), vrfid,
				       &error);

	if (unlikely(!src)) {
		nat_pool_incr_map_fails(np);
		return error;
	}

	/* src is LOCKED from here on */

	src->sr_map_reqs++;

	/* Get active port-block for this source and protocol */
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
		struct nat_pool_range *pr = NULL;
		uint32_t addr_hint;

		/* Does subscriber already have a paired address? */
		if (src->sr_paired_addr) {

			/* Check paired address is still valid */
			if (!nat_pool_is_pool_addr(np,
						   htonl(src->sr_paired_addr)))
				src->sr_paired_addr = 0;
		}

		addr_hint = src->sr_paired_addr;
		if (addr_hint == 0) {
			/*
			 * No valid paired address, so get next addr to try
			 * from pool.
			 */
			addr_hint = nat_pool_hint(np, proto);
			addr_hint = nat_pool_next_addr(np, addr_hint, &pr);
		}

		/*
		 * Starting at addr_hint, iterate through addresses in the nat
		 * pool until we find one with a free port-block.
		 *
		 * If successful, the returned apm will be LOCKED.
		 */
		apm = cgn_alloc_addr_rrobin(np, proto, addr_hint, pr,
					    vrfid, &error);

		/*
		 * Either out of memory, apm table is full, or all addresses
		 * in the nat pool are in-use.
		 */
		if (!apm)
			goto error;

		assert(rte_spinlock_is_locked(&apm->apm_lock));

		pb = cgn_alloc_block(np, apm, 0, &error);
		if (!pb) {
			rte_spinlock_unlock(&apm->apm_lock);
			goto error;
		}

		/*
		 * Add port-block to source list.  port-block is now under
		 * control of source lock so we can release the apm lock.
		 */
		cgn_source_add_block(src, proto, pb, np);
		rte_spinlock_unlock(&apm->apm_lock);

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

		if (!src->sr_mbpu_full[proto]) {
			cgn_log_resource_subscriber_mbpu(
				CGN_RESOURCE_FULL,
				src->sr_addr, nat_ipproto_from_proto(proto),
				src->sr_block_count,
				nat_pool_get_mbpu(np));

			src->sr_mbpu_full[proto] = true;
		}

		goto error;
	}

	/* LOCK apm */
	assert(!rte_spinlock_is_locked(&apm->apm_lock));
	rte_spinlock_lock(&apm->apm_lock);

	/*
	 * Are there any available port-blocks on this public address?
	 */
	if (apm->apm_blocks_used >= apm->apm_nblocks) {
		/*
		 * No free port-blocks.  Alloc a new public address if
		 * address-pool pairing is not enabled.
		 */
		rte_spinlock_unlock(&apm->apm_lock);

		if (nat_pool_is_ap_paired(np)) {
			error = -CGN_BLK_ENOSPC;
			goto error;
		} else {
			/* alloc a new public address */
			struct nat_pool_range *pr = NULL;
			uint32_t addr_hint;

			addr_hint = nat_pool_hint(np, proto);
			addr_hint = nat_pool_next_addr(np, addr_hint, &pr);

			/* If successful, apm will be LOCKED */
			apm = cgn_alloc_addr_rrobin(np, proto, addr_hint, pr,
						    vrfid, &error);
			if (!apm)
				goto error;
		}
	}

	assert(rte_spinlock_is_locked(&apm->apm_lock));

	pb = cgn_alloc_block(np, apm, apm_block_get_block(pb) + 1, &error);
	if (!pb) {
		rte_spinlock_unlock(&apm->apm_lock);
		goto error;
	}

	/*
	 * Add port-block to source's block list, and set as active block.
	 * port-block is now under control of source lock so we can release
	 * the apm lock.
	 */
	cgn_source_add_block(src, proto, pb, np);
	rte_spinlock_unlock(&apm->apm_lock);

	/* Alloc port from new block */
	if (nat_pool_is_pa_sequential(np))
		port = apm_block_alloc_first_free_port(pb, proto);
	else
		port = apm_block_alloc_random_port(pb, proto);

port_found:
	/* Successful! */
	cmi->cmi_src = src;
	cmi->cmi_taddr = htonl(apm->apm_addr);
	cmi->cmi_tid = htons(port);
	cmi->cmi_reserved = true;

	rte_atomic32_inc(&src->sr_map_active);

	assert(!rte_spinlock_is_locked(&apm->apm_lock));
	assert(rte_spinlock_is_locked(&src->sr_lock));

	rte_spinlock_unlock(&src->sr_lock);

	/*
	 * Increment count of current active mappings, and take reference on
	 * pool
	 */
	nat_pool_incr_map_active(np);

	return 0;

error:
	assert(!apm || !rte_spinlock_is_locked(&apm->apm_lock));
	assert(rte_spinlock_is_locked(&src->sr_lock));

	src->sr_map_fails++;
	rte_spinlock_unlock(&src->sr_lock);

	nat_pool_incr_map_fails(np);

	return error;
}

/*
 * cgn_map_get2
 *
 * Obtain mapping specified by taddr *and* tport.  taddr and tport are in
 * network byte order. Used by PCP.
 */
int cgn_map_get2(struct cgn_map *cmi, struct cgn_policy *cp, vrfid_t vrfid)
{
	struct apm_port_block *pb;
	enum nat_proto proto  = cmi->cmi_proto;
	struct cgn_source *src;
	struct nat_pool *np;
	struct apm *apm = NULL;
	uint16_t port, block;
	int error = 0;

	assert(proto <= NAT_PROTO_LAST);
	assert(cmi->cmi_oaddr);
	assert(cp);

	if (cmi->cmi_taddr == 0 || cmi->cmi_tid == 0)
		return -CGN_PCP_EINVAL;

	/* Get public address pool */
	np = cgn_policy_get_pool(cp);
	if (!np)
		/* No pool attached to policy, or pool is not active */
		return -CGN_POOL_ENOSPC;

	/* Count of mapping requests ever. Only ever increments */
	nat_pool_incr_map_reqs(np);

	/* Find (or create) and LOCK a source address structure */
	src = cgn_source_find_and_lock(cp, ntohl(cmi->cmi_oaddr),
				       vrfid, &error);

	if (unlikely(!src)) {
		nat_pool_incr_map_fails(np);
		return error;
	}

	/* src is LOCKED from here on */

	src->sr_map_reqs++;

	/*
	 * Is the requested public address in the NAT pool for the policy that
	 * is being used by this subscriber?
	 */
	if (!nat_pool_is_pool_addr(np, cmi->cmi_taddr)) {
		error = -CGN_POOL_ENOSPC;
		goto error;
	}

	/*
	 * Is the requested public address blocked?
	 */
	if (nat_pool_is_blocked_addr(np, cmi->cmi_taddr)) {
		error = -CGN_POOL_ENOSPC;
		goto error;
	}

	/* Lookup public address in apm table */
	apm = apm_lookup(cmi->cmi_taddr, vrfid);
	if (!apm) {
		apm = apm_create_and_insert(ntohl(cmi->cmi_taddr), vrfid,
					    np, &error);

		/* Either out of memory, or apm table is full */
		if (unlikely(!apm))
			goto error;
	}

	/* Lock apm */
	rte_spinlock_lock(&apm->apm_lock);

	/* Was the apm destroyed while we waited for the lock? */
	if (unlikely((apm->apm_flags & APM_DEAD) != 0)) {
		error = -CGN_POOL_ENOSPC;
		goto error;
	}

	/* Find the port-block for the given port */
	port = ntohs(cmi->cmi_tid);
	block = apm_block(port, apm->apm_port_start, apm->apm_port_block_sz);
	pb = apm->apm_blocks[block];

	if (!pb) {
		/*
		 * Before allocating a new port-block, check
		 * max-blocks-per-user limit.
		 */
		if (src->sr_block_count >= nat_pool_get_mbpu(np)) {

			nat_pool_incr_block_limit(np);
			error = -CGN_MBU_ENOSPC;

			if (!src->sr_mbpu_full[proto]) {
				cgn_log_resource_subscriber_mbpu(
					CGN_RESOURCE_FULL,
					src->sr_addr,
					nat_ipproto_from_proto(proto),
					src->sr_block_count,
					nat_pool_get_mbpu(np));

				src->sr_mbpu_full[proto] = true;
			}

			goto error;
		}

		/* Allocate new port-block */
		pb = cgn_alloc_block(np, apm, block, &error);
		if (!pb)
			goto error;

		/*
		 * Check the block number is the one we requested.
		 *
		 * This should never fail since we checked
		 * apm->apm_blocks[block] above, but check anyway in case
		 * cgn_alloc_block changes in the future.
		 */
		if (unlikely(apm_block_get_block(pb) != block)) {
			error = -CGN_BLK_ENOSPC;
			goto error;
		}

		/* Add port-block to source list */
		cgn_source_add_block(src, proto, pb, np);

	} else {
		/*
		 * Port-block already exists.  Ensure it is being used by the
		 * same subscriber.  (we cannot use the port-block if a
		 * different subscriber is already using it).
		 */
		if (apm_block_get_source(pb) != src) {
			error = -CGN_BLK_ENOSPC;
			goto error;
		}
	}

	/*
	 * At this point we have a port-block (either new or existing) that
	 * has been assigned to the given subscriber.  Since the port-block is
	 * now under control of the subscriber, and the subscriber is locked,
	 * can release the apm lock.
	 */
	rte_spinlock_unlock(&apm->apm_lock);
	apm = NULL;

	/*
	 * Try and allocate the specified port.
	 */
	port = apm_block_alloc_specific_port(pb, proto, port);
	if (port == 0) {
		error = -CGN_PCP_ENOSPC;
		goto error;
	}

	/* Success.  Increments stats and unlock the subscriber. */
	cmi->cmi_src = src;
	cmi->cmi_reserved = true;

	rte_atomic32_inc(&src->sr_map_active);

	assert(rte_spinlock_is_locked(&src->sr_lock));
	rte_spinlock_unlock(&src->sr_lock);

	/*
	 * Increment count of current active mappings, and take reference on
	 * pool
	 */
	nat_pool_incr_map_active(np);

	return 0;

error:
	assert(!apm || !rte_spinlock_is_locked(&apm->apm_lock));
	assert(rte_spinlock_is_locked(&src->sr_lock));

	if (apm)
		rte_spinlock_unlock(&apm->apm_lock);

	src->sr_map_fails++;
	rte_spinlock_unlock(&src->sr_lock);

	nat_pool_incr_map_fails(np);

	return error;
}

/*
 * Return a mapped address and port.
 *
 * This is called:
 *
 *   1. If a new flow obtained a mapping but failed to create a session, or
 *   2. When a session is destroyed
 *
 * A session may be destroyed:
 *   1. We fail to activate a new session
 *   2. We fail to translate a packet for which a new session was created
 *   3. session is reaped by garbage collector
 *   4. session clear command
 *
 * Inputs:
 *    vrfid
 *    cmi->cmi_reserved
 *    cmi->cmi_proto
 *    cmi->cmi_src
 *    cmi->cmi_taddr
 *    cmi->cmi_tid
 */
int cgn_map_put(struct cgn_map *cmi, vrfid_t vrfid)
{
	struct cgn_source *src;
	struct nat_pool *np;
	struct apm *apm;

	if (!cmi->cmi_reserved)
		return 0;

	assert(cmi->cmi_src);
	assert(cmi->cmi_taddr);
	assert(cmi->cmi_tid);

	if (unlikely(!cmi->cmi_src || cmi->cmi_taddr == 0 ||
		     cmi->cmi_tid == 0))
		return -CGN_RC_UNKWN;

	src = cmi->cmi_src;

	/* Lock the source */
	rte_spinlock_lock(&src->sr_lock);

	/* Get pool from subscriber (not policy) */
	np = cgn_source_get_pool(src);
	if (unlikely(!np)) {
		rte_spinlock_unlock(&src->sr_lock);
		return 0;
	}

	/* Lookup public address in apm table */
	apm = apm_lookup(ntohl(cmi->cmi_taddr), vrfid);
	if (unlikely(!apm)) {
		rte_spinlock_unlock(&src->sr_lock);
		return 0;
	}

	uint16_t port, block;
	struct apm_port_block *pb;

	/* Find the port-block for the given port */
	port = ntohs(cmi->cmi_tid);
	block = apm_block(port, apm->apm_port_start, apm->apm_port_block_sz);
	pb = apm->apm_blocks[block];

	/* Should never happen */
	if (unlikely(!pb)) {
		rte_spinlock_unlock(&src->sr_lock);
		return 0;
	}

	assert(apm_block_get_source(pb) && apm_block_get_source(pb) == src);

	/* Clear bit in port-block bitmap */
	apm_block_release_port(pb, cmi->cmi_proto, port);

	/*
	 * Can we free the port block?
	 */
	if (apm_block_get_ports_used(pb) == 0) {
		/*
		 * Lock the apm before releasing the port-block
		 */
		rte_spinlock_lock(&apm->apm_lock);

		/*
		 * Delete block from source list.  This releases reference on
		 * source, which may cause the source to be later destroyed in
		 * GC.
		 */
		cgn_source_del_block(src, pb, np);

		/* Remove block from apm's block list, and rcu-free it */
		apm_block_destroy(pb);

		nat_pool_incr_block_freed(np);
		nat_pool_decr_block_active(np);

		/* Unlock apm */
		rte_spinlock_unlock(&apm->apm_lock);
	}

	rte_atomic32_dec(&src->sr_map_active);

	/*
	 * Decrement count of current active mappings, and release reference
	 * on pool.
	 */
	nat_pool_decr_map_active(np);

	/* Reservation has been released */
	cmi->cmi_reserved = false;

	/* Unlock source */
	rte_spinlock_unlock(&src->sr_lock);

	return 0;
}
