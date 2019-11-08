/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_SOURCE_H_
#define _CGN_SOURCE_H_

#include <urcu/list.h>
#include "util.h"

#include "npf/nat/nat_proto.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn.h"

struct nat_pool;
struct cgn_source;
struct apm_port_block;

/*
 * Record sr_sess_created value for every interval of last 5 minutes.
 */
#define CGN_SESS_RATE_CNTRS	((60*5)/CGN_SRC_GC_INTERVAL)

/*
 * cgnat source/subscriber address table entry.  Hash of sr_addr and
 * sr_vrfid. Addresses are in host-byte order.
 *
 * sr_active_block[proto] is the block we are currently allocating ports from
 * for a given protocol.  When this is full, we try all other blocks in the
 * list before adding a new block.  A block is removed from the list when all
 * ports in that block have been released for all protocols.
 *
 * sr_mbpu_full is set true when a subscriber has reached max-blocks-per-user
 * limit.  It is used to gate log messages.  Note thats its possible (and
 * likely) that one protocol will cause max-blocks to be reached, and that
 * this should not prevent allocations for other protocols.
 */
struct cgn_source {
	struct cds_lfht_node	sr_node;        /* hash table node */
	uint32_t		sr_addr;        /* source (private) addr */
	uint8_t			sr_flags;
	uint8_t			sr_gc_pass;
	rte_atomic32_t		sr_refcnt;
	uint32_t		sr_paired_addr;

	struct apm_port_block	*sr_active_block[NAT_PROTO_COUNT];
	struct cds_list_head	sr_block_list;
	uint16_t		sr_block_count;   /* blocks in sr_block_list */
	uint8_t			sr_mbpu_full;     /* mbpu reached */

	vrfid_t			sr_vrfid;
	rte_spinlock_t		sr_lock;
	struct rcu_head		sr_rcu_head;
	uint64_t		sr_pkts_out;
	uint64_t		sr_bytes_out;
	uint64_t		sr_pkts_out_tot;
	uint64_t		sr_bytes_out_tot;
	uint64_t		sr_pkts_in;
	uint64_t		sr_bytes_in;
	uint64_t		sr_pkts_in_tot;
	uint64_t		sr_bytes_in_tot;
	struct cgn_policy	*sr_policy;     /* Back ptr to policy */
	uint64_t		sr_start_time;  /* millisecs */

	/* Sessions created and destroyed in current interval */
	rte_atomic32_t		sr_sess_created;
	rte_atomic32_t		sr_sess_destroyed;

	/* Total sessions created/destroyed since src start */
	uint64_t		sr_sess_created_tot;
	uint64_t		sr_sess_destroyed_tot;

	/*
	 * sr_sess_rate is a record of the number of sessions created during
	 * last 'n' complete gc intervals.
	 */
	uint8_t			sr_sess_rate_cur;
	uint32_t		sr_sess_rate[CGN_SESS_RATE_CNTRS];
	uint32_t		sr_sess_rate_max;
	uint64_t		sr_sess_rate_max_time;

	uint64_t		sr_map_reqs;
	uint64_t		sr_map_fails;
	rte_atomic32_t		sr_map_active;
};

/* source entry removal bits. */
#define SF_EXPIRED	0x01
#define SF_DEAD		0x02

int cgn_source_add_block(struct cgn_source *src, uint8_t proto,
			 struct apm_port_block *pb,
			 struct nat_pool *np);
int cgn_source_del_block(struct cgn_source *src, struct apm_port_block *pb,
			 struct nat_pool *np);

struct cgn_source *cgn_source_get(struct cgn_source *src);
void cgn_source_put(struct cgn_source *src);
void cgn_source_stats_sess_created(struct cgn_source *src);
void cgn_source_stats_sess_destroyed(struct cgn_source *src);
struct nat_pool *cgn_source_get_pool(struct cgn_source *src);

/*
 * Addresses are in host byte-order.  proto is of type enum npf_proto_idx.
 */

struct cgn_source *cgn_source_lookup(uint32_t addr, vrfid_t vrfid);

struct cgn_source *cgn_source_find_and_lock(struct cgn_policy *cp,
					    uint32_t addr, vrfid_t vrfid,
					    int *error);

void cgn_source_update_stats(struct cgn_source *src,
			     uint64_t pkts_out, uint64_t bytes_out,
			     uint64_t pkts_in, uint64_t bytes_in);

/* Get subscriber hash table used and max counts */
int32_t cgn_source_get_used(void);
int32_t cgn_source_get_max(void);

void cgn_source_show(FILE *f, int argc, char **argv);
void cgn_source_list(FILE *f, int argc, char **argv);

void cgn_source_cleanup(void);

void cgn_source_init(void);
void cgn_source_uninit(void);

#endif
