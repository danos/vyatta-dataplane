/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file apm.h - address-port management for NATs
 *
 */

#ifndef _APM_H_
#define _APM_H_

#include <values.h>
#include <stdint.h>
#include <urcu/list.h>

#include "if_var.h"
#include "urcu.h"

#include "npf/nat/nat_proto.h"

struct apm;
struct nat_pool;
struct cgn_source;
struct apm_port_block;

#define PORTS_PER_BITMAP	64

/*
 * The APMS_LIMIT define and apms_limit variable are *not* enforced, and the apm
 * table is allowed to grow as big as required.  The limiting factor will be
 * the number of addresses in the relevant address pools.  apms_limit is only
 * used to provide some indication (via logs and show output) of how full the
 * apm table is.
 */
#define APMS_LIMIT 32768

/*
 * public address (apm) table entry.  Each entry is defined by: public source
 * address and vrfid.
 *
 * The apm structure does not have a ref count.  We use apm_blocks_used to
 * determine when an apm can be destroyed.
 *
 * apm_lock is used to lock the apm.  Any thread acquiring the lock must check
 * that the APM_DEAD flag is still clear.
 *
 * For each nat prototol (tcp, udp, and other), there is an array of pointers
 * to port blocks.  These arrays are only allocated when required.
 */
struct apm {
	struct cds_lfht_node	apm_node;
	uint32_t		apm_addr;     /* public addr, host order */
	vrfid_t			apm_vrfid;
	rte_spinlock_t		apm_lock;
	struct rcu_head		apm_rcu_head;

	uint8_t			apm_flags;
	uint8_t			apm_gc_pass;
	uint8_t			apm_pb_full;
	uint8_t			apm_pad1[3];

	/*
	 * apm_port_start, apm_port_stop and apm_port_block_sz are copied
	 * from the nat pool configuration.
	 */
	uint16_t		apm_port_start;
	uint16_t		apm_port_end;
	uint16_t		apm_nports;
	uint16_t		apm_port_block_sz; /* ports per block */

	/*
	 * Port bit-map blocks.
	 *
	 * apm_nblocks is the size of the apm_blocks array, and is set once at
	 * time of apm entry creation.  It is calculated from:
	 * "apm_nports / apm_port_block_sz".
	 */
	uint16_t		apm_nblocks;     /* max blocks per apm */

	/* --- cacheline 1 boundary (64 bytes) --- */
	struct nat_pool		*apm_np;         /* back pointer to nat pool */

	/* blocks in-use */
	uint16_t		apm_blocks_used;
	uint8_t			apm_pad2[6];

	/* Port block pointer array.  MUST be last. */
	struct apm_port_block	*apm_blocks[];
};

static_assert(offsetof(struct apm, apm_np) == 64,
	      "first cache line exceeded");

/* apm entry removal bits. */
#define APM_EXPIRED	0x01
#define APM_DEAD	0x02


/*
 * Determine which block a port belongs to.
 *
 * start_port - Start port for the range assigned to the public address.
 * ppblk      - Ports per block (derived from config).
 */
static ALWAYS_INLINE uint16_t
apm_block(uint16_t port, uint16_t start_port, uint16_t ppblk)
{
	return (port - start_port) / ppblk;
}

/*
 * Determine which bitmap within a block that a port belongs to.
 *
 * start_port - Start port for the range assigned to the public address.
 * ppblk      - Ports per block (derived from config).
 * block      - Block the port belongs to.
 */
static ALWAYS_INLINE uint16_t
apm_bm(uint16_t port, uint16_t start_port, uint16_t ppblk, uint16_t block)
{
	/*
	 * block_start_port = (block * ppblk) + start_port
	 * return (port - block_start_port) / PORTS_PER_BITMAP
	 */
	return (port - ((block * ppblk) + start_port)) / PORTS_PER_BITMAP;
}

/*
 * Determine which bit within a bitmap represents the given port.
 *
 * start_port - Start port for the range assigned to the public address.
 * ppblk      - Ports per block (derived from config).
 * block      - Block the port belongs to.
 * bm         - Bitmap that the port belongs to.
 */
static ALWAYS_INLINE uint16_t
apm_bit(uint16_t port, uint16_t start_port, uint16_t ppblk,
	uint16_t block, uint16_t bm)
{
	/*
	 * block_start_port = (block * ppblk) + start_port
	 * bm_start_port = (bm * PORTS_PER_BITMAP) + block_start_port;
	 * bit = (port - bm_start_port);
	 */
	return (port - ((bm * PORTS_PER_BITMAP) +
			((block * ppblk) + start_port)));
}

/* Accessors */

/* Get apm handle */
struct apm *apm_block_get_apm(struct apm_port_block *pb);

/* Get block number */
uint16_t apm_block_get_block(struct apm_port_block *pb);

/* Get ports used count for all protocols */
uint32_t apm_block_get_ports_used(struct apm_port_block *pb);

/* Get total number of ports */
uint16_t apm_block_get_nports(struct apm_port_block *pb);

/* Get pointer to list node */
struct cds_list_head *apm_block_get_list_node(struct apm_port_block *pb);

/* Set src ptr in port-block */
void apm_block_set_source(struct apm_port_block *pb, struct cgn_source *src);

/* Get the src ptr if this port-block is in a source list */
struct cgn_source *apm_block_get_source(struct apm_port_block *pb);

/* Get port and blocks used counts from a list of port blocks */
void apm_source_block_list_get_counts(struct cds_list_head *list,
				      uint *nports, uint *ports_used);

void apm_log_block_alloc(struct apm_port_block *pb, uint32_t src_addr,
			 const char *policy_name, const char *pool_name);
void apm_log_block_release(struct apm_port_block *pb, uint32_t src_addr,
			   const char *policy_name, const char *pool_name);

/* Threshold */
void apm_table_threshold_set(int32_t threshold, uint32_t interval);

/* jsonw port-blocks from a source list */
void apm_source_port_block_list_jsonw(json_writer_t *json,
				      struct cds_list_head *list);

/*
 * Allocate a port from a port block.  Returns 0 if it fails to find an
 * available port.
 */
uint16_t apm_block_alloc_first_free_port(struct apm_port_block *pb,
					 uint8_t proto);

/*
 * Pseudo random port allocation.  Randomly select initial port.  If thats not
 * free, then look for first clear bit in each bitmap.
 */
uint16_t apm_block_alloc_random_port(struct apm_port_block *pb,
				     uint8_t proto);

/*
 * Allocate a specified port.  Used by PCP.
 */
uint16_t
apm_block_alloc_specific_port(struct apm_port_block *pb, uint8_t proto,
			      uint16_t port);

/* Release a port in a port-block */
bool apm_block_release_port(struct apm_port_block *pb, uint8_t proto,
			    uint16_t port);

/* Allocate a port from any port block in the given list */
uint16_t apm_block_list_first_free_port(struct cds_list_head *list,
					uint8_t proto,
					struct apm_port_block *skip,
					struct apm_port_block **pbp);

/*
 * Addresses are in host byte-order
 */
struct apm *apm_lookup(uint32_t addr, vrfid_t vrfid);

struct apm *apm_create_and_insert(uint32_t addr, vrfid_t vrfid,
					  struct nat_pool *np, int *error);

struct apm_port_block *apm_block_create(struct apm *apm, uint16_t block);
void apm_block_destroy(struct apm_port_block *pb);

void apm_public_list(FILE *f, int argc, char **argv);

/* Get apm table used count */
int32_t apm_get_used(void);

void apm_show(FILE *f, int argc, char **argv);

void apm_cleanup(void);
void apm_gc_pass(void);

void apm_init(void);
void apm_uninit(void);

#endif
