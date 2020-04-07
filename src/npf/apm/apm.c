/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file apm.c - address-port management for NATs
 *
 * Allocation and management of addresses and ports for address translation.
 *
 * Comprises a global hash table of addresses (in host byte-order).  Each
 * entry/address has an array of port blocks.  Each port block is an extended
 * bitmap (array of 64-bit words).
 *
 * Entries are protocol dependent to some extent. Protocols are summarized as
 * one of three values: TCP, UDP, and 'other' (enum nat_proto).  The same
 * address and port may be allocated separately for each of these three
 * protocol 'types'.
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <dpdk/rte_jhash.h>
#include <rte_malloc.h>
#include <rte_log.h>

#include "compiler.h"
#include "vplane_log.h"
#include "if_var.h"
#include "urcu.h"
#include "util.h"
#include "soft_ticks.h"

#include "npf/npf_addr.h"
#include "npf/nat/nat_pool.h"

#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_errno.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_map.h"


/* npf_rule_gen.c */
int npf_parse_ip_addr(char *value, sa_family_t *fam, npf_addr_t *addr,
		      npf_netmask_t *masklen, bool *negate);

/* Session garbage collection interval (seconds) */
#define APM_GC_INTERVAL	10

/* Number of gc passes before apm is deactivated */
#define APM_GC_COUNT	2

#define ONE_THOUSAND		(1<<10)

/*
 * Start with 128 buckets, and allow to grow to any size (size will be limited
 * by number of addresses in the CGNAT address pools).
 */
#define APM_HT_INIT		128
#define APM_HT_MIN		(4 * ONE_THOUSAND)
#define APM_HT_MAX		0

/*
 * port block
 */
struct apm_port_block {
	struct cds_list_head	pb_list_node;	/* source list node */
	struct apm		*pb_apm;	/* back ptr */
	struct cgn_source	*pb_src;	/* ptr to source */
	struct rcu_head		pb_rcu_head;
	uint64_t		pb_start_time;
	uint16_t		pb_port_start;  /* first port in block */
	uint16_t		pb_port_end;    /* last port in block */
	uint16_t		pb_nports;	/* end - start + 1 */
	uint16_t		pb_block;	/* index in apm_blocks[] */
	uint16_t		pb_nmaps;   /* Number of bitmaps per proto */

	/* Ports used per-protocol */
	uint16_t		pb_ports_used[NAT_PROTO_COUNT];

	/* Last place port found */
	uint16_t		pb_cur_bm[NAT_PROTO_COUNT];

	/*
	 * Per-protocol bitmap array, _pb_map. MUST be last. We setup pb_map[]
	 * pointers to point into _pb_map.  Used as follows:
	 *
	 *   pb_map[proto][bm]
	 */
	uint64_t		*pb_map[NAT_PROTO_COUNT];
	uint64_t		_pb_map[];
};

/* apm GC Timer */
static struct rte_timer apm_timer;

/* apm hash table */
static struct cds_lfht *apm_ht;

/* hash table match params */
struct apm_match {
	uint32_t addr;
	uint8_t  proto;  /* enum nat_proto */
	vrfid_t  vrfid;
};

/* APM table used count */
static rte_atomic32_t apms_used;

/*
 * Find first clear bit in a 64-bit word, starting at LSB, bit 1.  Returns 0
 * if no bits are clear, e.g.
 *
 *    msb          lsb		Returns
 *  0x0000000000000000		1
 *  0x0000000000000007		4
 *  0x000000000000000f		5
 *  0x7fffffffffffffff		64
 *  0xffffffffffffffff		0
 */
static ALWAYS_INLINE int ffcl(long word)
{
	return ffsl(~word);
}

/* Get apm handle */
struct apm *apm_block_get_apm(struct apm_port_block *pb)
{
	return pb->pb_apm;
}

/* Get block number */
uint16_t apm_block_get_block(struct apm_port_block *pb)
{
	return pb ? pb->pb_block : 0;
}

/* Get ports used count for all protocols */
uint32_t apm_block_get_ports_used(struct apm_port_block *pb)
{
	return pb->pb_ports_used[NAT_PROTO_TCP] +
		pb->pb_ports_used[NAT_PROTO_UDP] +
		pb->pb_ports_used[NAT_PROTO_OTHER];
}

/* Get total number of ports */
uint16_t apm_block_get_nports(struct apm_port_block *pb)
{
	return pb->pb_nports;
}

/* Get pointer to list node */
struct cds_list_head *apm_block_get_list_node(struct apm_port_block *pb)
{
	return &pb->pb_list_node;
}

/*
 * pb_src is non-NULL *only* while a port-block is in a sources port-block
 * list.  When pb_src is set then that sources lock must be held when changing
 * the port-block.
 */
void apm_block_set_source(struct apm_port_block *pb, struct cgn_source *src)
{
	pb->pb_src = src;
}

struct cgn_source *apm_block_get_source(struct apm_port_block *pb)
{
	return pb->pb_src;
}

/*
 * Allocate a port from a port block.  Returns 0 if it fails to find an
 * available port.
 */
uint16_t
apm_block_alloc_first_free_port(struct apm_port_block *pb, uint8_t proto)
{
	uint bit = 0;
	uint16_t port, i, bm;

	if (pb->pb_ports_used[proto] == pb->pb_nports)
		return 0;

	/*
	 * Start at the bitmap from which we last allocated a port for this
	 * protocol.
	 */
	for (i = 0, bm = pb->pb_cur_bm[proto]; i < pb->pb_nmaps; i++) {

		/* Find first clear bit in bitmap, starting with lsb */
		bit = ffcl(pb->pb_map[proto][bm]);

		if (bit != 0) {
			/* Subtract 1 since ffcl return 1 for bit 0 etc */
			bit -= 1;

			/* Remember where we found a free port */
			pb->pb_cur_bm[proto] = bm;

			pb->pb_ports_used[proto]++;

			/* convert bit to a port number */
			port = pb->pb_port_start +
				(bm * PORTS_PER_BITMAP) + bit;

			/* Set bit */
			pb->pb_map[proto][bm] |= (UINT64_C(1) << bit);

			return port;
		}

		if (++bm == pb->pb_nmaps)
			bm = 0;
	}

	return 0;
}

/*
 * Pseudo random port allocation.  Randomly select initial port.  If thats not
 * free, then look for first clear bit in each bitmap.  This is faster than
 * looping around ever port.
 */
uint16_t
apm_block_alloc_random_port(struct apm_port_block *pb, uint8_t proto)
{
	uint16_t bm, port;
	uint16_t bm_start, bit;
	uint64_t mask;

	if (pb->pb_ports_used[proto] == pb->pb_nports)
		return 0;

	/* Choose a random starting point */
	port = pb->pb_port_start + (random() % pb->pb_nports);

	assert(port >= pb->pb_port_start);
	assert(port <= pb->pb_port_end);

	/* Which bitmap in the block? */
	bm = (port - pb->pb_port_start) / PORTS_PER_BITMAP;

	/* Which bit in the bitmap? */
	bm_start = (bm * PORTS_PER_BITMAP) + pb->pb_port_start;
	bit = port - bm_start;

	mask = UINT64_C(1) << bit;

	if ((pb->pb_map[proto][bm] & mask) == UINT64_C(0)) {
		pb->pb_ports_used[proto]++;

		/* Set bit */
		pb->pb_map[proto][bm] |= (UINT64_C(1) << bit);
		return port;
	}

	/*
	 * Initial random port is not free.  Look for first free bit in each
	 * bitmap, starting with the current bitmap.
	 */
	pb->pb_cur_bm[proto] = bm;
	port = apm_block_alloc_first_free_port(pb, proto);

	return port;
}

/*
 * Allocate a specific port from a port-block.  Used by PCP.
 */
uint16_t
apm_block_alloc_specific_port(struct apm_port_block *pb, uint8_t proto,
			      uint16_t port)
{
	uint16_t bm;
	uint16_t bm_start, bit;
	uint64_t mask;

	if (pb->pb_ports_used[proto] == pb->pb_nports)
		return 0;

	assert(port >= pb->pb_port_start);
	assert(port <= pb->pb_port_end);

	/* Which bitmap in the block? */
	bm = (port - pb->pb_port_start) / PORTS_PER_BITMAP;

	/* Which bit in the bitmap? */
	bm_start = (bm * PORTS_PER_BITMAP) + pb->pb_port_start;
	bit = port - bm_start;

	mask = UINT64_C(1) << bit;

	if ((pb->pb_map[proto][bm] & mask) == UINT64_C(0)) {
		pb->pb_ports_used[proto]++;

		/* Set bit */
		pb->pb_map[proto][bm] |= (UINT64_C(1) << bit);
		return port;
	}

	/* Fail if port is not free */
	return 0;
}

/*
 * Release a port in a port-block
 */
bool
apm_block_release_port(struct apm_port_block *pb, uint8_t proto, uint16_t port)
{
	uint16_t bm, bm_start, bit;
	uint64_t mask;

	if (!pb)
		return false;

	/* Which bitmap in the block? */
	bm = (port - pb->pb_port_start) / PORTS_PER_BITMAP;

	/* Which bit in the bitmap? */
	bm_start = (bm * PORTS_PER_BITMAP) + pb->pb_port_start;
	bit = port - bm_start;

	mask = UINT64_C(1) << bit;

	assert(bm < pb->pb_nmaps);

	/* Is bit already cleared? */
	if ((pb->pb_map[proto][bm] & mask) != UINT64_C(0)) {
		pb->pb_map[proto][bm] &= ~mask;
		pb->pb_ports_used[proto]--;
		return true;
	}
	return false;
}

/*
 * Allocate first free port from a block in the given block list
 */
uint16_t apm_block_list_first_free_port(struct cds_list_head *list,
					uint8_t proto,
					struct apm_port_block *skip,
					struct apm_port_block **pbp)
{
	struct apm_port_block *pb;
	uint16_t port;

	cds_list_for_each_entry(pb, list, pb_list_node) {
		/*
		 * Skip active block (since we assume the caller has already
		 * have tried the active block)
		 */
		if (pb == skip)
			continue;

		/* Alloc port from port block */
		port = apm_block_alloc_first_free_port(pb, proto);

		if (port) {
			/*
			 * Success!  Port found in existing port-block.
			 * Remember which block it was.
			 */
			*pbp = pb;
			return port;
		}
	}

	/* Failure.  No port found */
	return 0;
}

/*
 * Called from apm_block_create when apm_blocks_used >= apm_nblocks
 */
static inline void apm_pb_full(struct apm *apm)
{
	if (!apm->apm_pb_full) {
		/* Mark this address as full */
		apm->apm_pb_full = true;

		/* Log address is full */
		cgn_log_resource_public_pb(CGN_RESOURCE_FULL, apm->apm_addr,
					   apm->apm_blocks_used,
					   apm->apm_nblocks);

		/* Increment and check address pool threshold */
		np_threshold_get(apm->apm_np);

	}
}

/*
 * Called from apm_block_destroy when a block is freed.
 */
static inline void apm_pb_available(struct apm *apm)
{
	if (apm->apm_pb_full) {
		/* Mark this address as available */
		apm->apm_pb_full = false;

		/* Log address is available */
		cgn_log_resource_public_pb(CGN_RESOURCE_AVAILABLE,
					   apm->apm_addr, apm->apm_blocks_used,
					   apm->apm_nblocks);

		/* Decrement and check address pool threshold */
		np_threshold_put(apm->apm_np);
	}
}

/*
 * Create a port-block and add it to apm block array.
 *
 * Each port block has a dynamic array of 64-bit bitmaps at its end.
 */
struct apm_port_block *
apm_block_create(struct apm *apm, uint16_t block)
{
	struct apm_port_block *pb;
	uint16_t nmaps;
	size_t sz;

	assert(rte_spinlock_is_locked(&apm->apm_lock));

	/* How many 64-bit bitmaps do we need? */
	nmaps = apm->apm_port_block_sz / PORTS_PER_BITMAP;
	sz = sizeof(struct apm_port_block) +
		(sizeof(pb->_pb_map[0]) * nmaps * NAT_PROTO_COUNT);

	pb = zmalloc_aligned(sz);
	if (!pb)
		return NULL;

	/* Block number */
	pb->pb_block = block;

	/* Ports in this block */
	pb->pb_nports = apm->apm_port_block_sz;

	/* Number of port bitmaps in this block */
	pb->pb_nmaps = nmaps;

	/* Back pointer to apm */
	pb->pb_apm = apm;

	/* start time in millisecs */
	pb->pb_start_time = soft_ticks;

	/* Determine first and last ports in this block */
	pb->pb_port_start = (block * apm->apm_port_block_sz) +
		apm->apm_port_start;
	pb->pb_port_end = pb->pb_port_start + apm->apm_port_block_sz - 1;

	/* Setup per-protocol pointers into bitmap array */
	uint8_t p;
	for (p = NAT_PROTO_FIRST; p < NAT_PROTO_COUNT; p++)
		pb->pb_map[p] = &pb->_pb_map[p*nmaps];

	/*
	 * Add port block to apm structure and increment apm_blocks_used.
	 * This serves as the blocks reference on the apm.
	 */
	apm->apm_blocks[block] = pb;
	apm->apm_blocks_used++;

	if (apm->apm_blocks_used >= apm->apm_nblocks)
		apm_pb_full(apm);

	return pb;
}

/* rcu callback to free a port block */
static void apm_block_rcu_free(struct rcu_head *head)
{
	struct apm_port_block *pb;

	pb = caa_container_of(head, struct apm_port_block, pb_rcu_head);
	free(pb);
}

/*
 * Destroy port-block.  Remove from apm block array, and schedule free from
 * rcu callback.
 *
 * Called from cgn_map_put when a mapping is released, which in turn is called
 * then a session is destroyed.
 */
void apm_block_destroy(struct apm_port_block *pb)
{
	struct apm *apm = pb->pb_apm;

	uint8_t p;
	for (p = NAT_PROTO_FIRST; p < NAT_PROTO_COUNT; p++)
		assert(pb->pb_ports_used[p] == 0);

	assert(rte_spinlock_is_locked(&apm->apm_lock));
	assert(apm->apm_blocks[pb->pb_block] != NULL);

	apm->apm_blocks[pb->pb_block] = NULL;
	apm->apm_blocks_used--;

	apm_pb_available(apm);
	cgn_alloc_pool_available(apm->apm_np, apm);

	call_rcu(&pb->pb_rcu_head, apm_block_rcu_free);
}

void apm_log_block_alloc(struct apm_port_block *pb, uint32_t src_addr,
			 const char *policy_name, const char *pool_name)
{
	cgn_log_pb_alloc(src_addr,
			 pb->pb_apm->apm_addr,
			 pb->pb_port_start, pb->pb_port_end,
			 pb->pb_start_time,
			 policy_name, pool_name);
}

void apm_log_block_release(struct apm_port_block *pb, uint32_t src_addr,
			   const char *policy_name, const char *pool_name)
{
	cgn_log_pb_release(src_addr,
			   pb->pb_apm->apm_addr,
			   pb->pb_port_start, pb->pb_port_end,
			   pb->pb_start_time, soft_ticks,
			   policy_name, pool_name);
}

/* Deprecated */
void
apm_table_threshold_set(int32_t threshold __unused, uint32_t interval __unused)
{
}

/*
 * Note that there is no max value for the apm table.  We allow the hash table
 * to grow as much as it needs to.  The apms_used count is only used to
 * provide show state.
 */
static inline void apm_slot_get(void)
{
	rte_atomic32_inc(&apms_used);
}

static inline void apm_slot_put(void)
{
	rte_atomic32_dec(&apms_used);
}

/* Get apm table used count */
int32_t apm_get_used(void)
{
	return rte_atomic32_read(&apms_used);
}

/*
 * Create an apm entry.
 *
 * Each apm has a per-protocol array of pointers to port blocks.  The size of
 * the array is dependent on block size and port range.  It is unlikely to be
 * more than 1000 elements, meaning over 8k memory may be required per
 * protocol per apm.
 */
static struct apm *
apm_create(uint32_t addr, vrfid_t vrfid, struct nat_pool *np,
	       int *error)
{
	uint16_t nblocks = np->np_nports / np->np_block_sz;
	struct apm *apm;
	size_t sz;

	/* Increment apms_used count */
	apm_slot_get();

	sz = sizeof(*apm) + nblocks * sizeof(struct apm_port_block *);

	/* Allocate memory from hugepages area */
	apm = rte_zmalloc("apm", sz, RTE_CACHE_LINE_SIZE);
	if (!apm) {
		*error = -CGN_APM_ENOMEM;
		apm_slot_put();
		return NULL;
	}

	/* Copy from nat pool configured items */
	apm->apm_port_start = np->np_port_start;
	apm->apm_port_end = np->np_port_end;
	apm->apm_port_block_sz = np->np_block_sz;

	apm->apm_nblocks = nblocks;
	apm->apm_nports = np->np_nports;

	apm->apm_addr = addr;
	apm->apm_vrfid = vrfid;

	/* Take reference on nat pool */
	apm->apm_np = nat_pool_get(np);

	apm->apm_blocks_used = 0;
	rte_spinlock_init(&apm->apm_lock);

	return apm;
}

static void apm_rcu_free(struct rcu_head *head)
{
	struct apm *apm = caa_container_of(head, struct apm,
					       apm_rcu_head);

	assert(apm->apm_blocks_used == 0);
	rte_free(apm);
}

static void apm_destroy(struct apm *apm)
{
	assert(rte_spinlock_is_locked(&apm->apm_lock));
	assert((apm->apm_flags & APM_DEAD) == 0);

	/* Mark as invalid for anyone doing a lookup or acquiring lock */
	apm->apm_flags |= APM_DEAD;

	/* Remove from hash table */
	cds_lfht_del(apm_ht, &apm->apm_node);

	/* Decrement apms_used count */
	apm_slot_put();

	/* Release nat pool */
	nat_pool_put(apm->apm_np);
	apm->apm_np = NULL;

	/* Schedule rcu-free */
	call_rcu(&apm->apm_rcu_head, apm_rcu_free);
}

static ulong apm_hash(uint32_t addr, vrfid_t vrfid)
{
	return rte_jhash_1word(addr, vrfid);
}

/*
 * apm hash table match function
 */
static int apm_match(struct cds_lfht_node *node, const void *key)
{
	const struct apm_match *m = key;
	struct apm *apm;

	apm = caa_container_of(node, struct apm, apm_node);

	/* Never return an expired or dead entry. */
	if (apm->apm_flags & (APM_DEAD | APM_EXPIRED))
		return 0;

	if (apm->apm_addr != m->addr)
		return 0; /* no match */

	if (apm->apm_vrfid != m->vrfid)
		return 0; /* no match */

	return 1; /* match */
}

/*
 * Lookup a public address
 */
struct apm *
apm_lookup(uint32_t addr, vrfid_t vrfid)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct apm_match m = { .addr = addr,
			       .vrfid = vrfid };
	ulong hash;

	assert(apm_ht != NULL);
	if (!apm_ht)
		return NULL;

	hash = apm_hash(addr, vrfid);
	cds_lfht_lookup(apm_ht, hash, apm_match, &m, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct apm, apm_node);

	return NULL;
}

/*
 * Insert an apm entry
 */
static int
apm_insert(struct apm **apmp)
{
	struct apm *apm = *apmp;
	struct cds_lfht_node *node;
	ulong hash;

	if (!apm)
		return 0;

	struct apm_match m = { .addr = apm->apm_addr,
			       .vrfid = apm->apm_vrfid };

	hash = apm_hash(apm->apm_addr, apm->apm_vrfid);
	node = cds_lfht_add_unique(apm_ht, hash, apm_match, &m,
				   &apm->apm_node);

	/* Did we loose race to add this address? */
	if (node != &apm->apm_node) {
		/* Yes.  Free apm and return entry that beat us. */
		rte_free(apm);
		*apmp = caa_container_of(node, struct apm, apm_node);
		apm_slot_put();
		return 0;
	}

	return 0;
}

struct apm *
apm_create_and_insert(uint32_t addr, vrfid_t vrfid, struct nat_pool *np,
			  int *error)
{
	struct apm *apm;

	apm = apm_create(addr, vrfid, np, error);
	if (apm)
		(void)apm_insert(&apm);

	return apm;
}

/*
 * Return json list of active public addresses in uint format, host-byte order
 */
void apm_public_list(FILE *f, int argc, char **argv)
{
	uint32_t fltr_addr = 0, mask = 0;
	int rc;

	argc -= 3;
	argv += 3;

	if (argc >= 2 && !strcmp(argv[0], "prefix")) {
		npf_addr_t npf_addr;
		npf_netmask_t pl;
		sa_family_t fam;
		bool negate;
		ulong tmp;

		rc = npf_parse_ip_addr(argv[1], &fam, &npf_addr, &pl, &negate);
		if (rc < 0)
			return;

		pl = MIN(32, pl);
		memcpy(&fltr_addr, &npf_addr, 4);
		fltr_addr = ntohl(fltr_addr);
		tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
		mask = tmp;
	}

	struct cds_lfht_iter iter;
	struct apm *apm;
	json_writer_t *json;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "public");
	jsonw_start_array(json);

	cds_lfht_for_each_entry(apm_ht, &iter, apm, apm_node) {
		if (mask != 0 && (apm->apm_addr & mask) != fltr_addr)
			continue;

		jsonw_uint(json, apm->apm_addr);
	}

	jsonw_end_array(json);
	jsonw_destroy(&json);

}

/*
 * jsonw port-block from a source pov
 */
static void
apm_source_port_block_jsonw(json_writer_t *json, struct apm_port_block *pb)
{
	static char addr_str[16];
	uint32_t addr;

	jsonw_start_object(json);

	addr = htonl(pb->pb_apm->apm_addr);
	inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));

	jsonw_uint_field(json, "block", pb->pb_block);
	jsonw_string_field(json, "pub_addr", addr_str);
	jsonw_uint_field(json, "port_start", pb->pb_port_start);
	jsonw_uint_field(json, "port_end", pb->pb_port_end);

	jsonw_uint_field(json, "tcp_ports_used",
			 pb->pb_ports_used[NAT_PROTO_TCP]);

	jsonw_uint_field(json, "udp_ports_used",
			 pb->pb_ports_used[NAT_PROTO_UDP]);

	jsonw_uint_field(json, "other_ports_used",
			 pb->pb_ports_used[NAT_PROTO_OTHER]);

	jsonw_end_object(json);
}

void apm_source_port_block_list_jsonw(json_writer_t *json,
				      struct cds_list_head *list)
{
	struct apm_port_block *pb;

	cds_list_for_each_entry(pb, list, pb_list_node)
		apm_source_port_block_jsonw(json, pb);
}

/* Get port and blocks used counts from a list of port blocks */
void apm_source_block_list_get_counts(struct cds_list_head *list,
				      uint *nports, uint *ports_used)
{
	struct apm_port_block *pb;
	uint proto;

	cds_list_for_each_entry(pb, list, pb_list_node) {
		*nports += apm_block_get_nports(pb);

		for (proto = NAT_PROTO_FIRST; proto < NAT_PROTO_COUNT; proto++)
			ports_used[proto] += pb->pb_ports_used[proto];
	}
}

struct apm_fltr {
	bool		af_all;
	uint32_t	af_addr;	/* host byte-order */
	uint32_t	af_mask;
	bool		af_detail;
	uint32_t	af_start;
	uint32_t	af_count;
};

/*
 * Write json for one port-block protocol
 */
static uint
apm_jsonw_pb_proto(struct apm_port_block *pb, json_writer_t *json,
		       uint8_t proto, bool detail)
{
	uint ports_used = pb->pb_ports_used[proto];

	jsonw_start_object(json);
	jsonw_string_field(json, "protocol", nat_proto_lc_str(proto));
	jsonw_uint_field(json, "ports_used", ports_used);

	if (detail) {
		uint16_t bm;

		jsonw_name(json, "bitmaps");
		jsonw_start_array(json);

		for (bm = 0; bm < pb->pb_nmaps; bm++)
			jsonw_uint(json, pb->pb_map[proto][bm]);

		jsonw_end_array(json);
	}

	jsonw_end_object(json);

	return ports_used;
}

/*
 * Write json for one apm entry
 */
static void
apm_jsonw_one(struct apm *apm, json_writer_t *json, bool detail)
{
	uint ports_used[NAT_PROTO_COUNT] = { 0 };
	char addr_str[16];
	uint32_t addr;
	uint16_t block;
	uint blocks_used = 0;

	addr = htonl(apm->apm_addr);
	inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));

	jsonw_start_object(json);

	jsonw_string_field(json, "address", addr_str);
	jsonw_uint_field(json, "flags", apm->apm_flags);
	jsonw_uint_field(json, "port_start", apm->apm_port_start);
	jsonw_uint_field(json, "port_end", apm->apm_port_end);
	jsonw_uint_field(json, "block_sz", apm->apm_port_block_sz);

	jsonw_name(json, "blocks");
	jsonw_start_array(json);

	for (block = 0; block < apm->apm_nblocks; block++) {
		if (apm->apm_blocks[block] == NULL)
			continue;

		struct apm_port_block *pb = apm->apm_blocks[block];
		uint8_t proto;

		blocks_used++;

		jsonw_start_object(json);
		jsonw_uint_field(json, "block", pb->pb_block);
		jsonw_uint_field(json, "port_start", pb->pb_port_start);
		jsonw_uint_field(json, "port_end", pb->pb_port_end);

		if (detail)
			jsonw_uint_field(json, "nmaps", pb->pb_nmaps);

		jsonw_name(json, "protocols");
		jsonw_start_array(json);

		for (proto = NAT_PROTO_FIRST; proto < NAT_PROTO_COUNT; proto++)
			ports_used[proto] +=
				apm_jsonw_pb_proto(pb, json, proto, detail);

		jsonw_end_array(json); /* protocols */
		jsonw_end_object(json);
	}

	jsonw_end_array(json); /* blocks */

	/* Total blocks possible */
	jsonw_uint_field(json, "nblocks", apm->apm_nblocks);

	/* Blocks in-use */
	jsonw_uint_field(json, "blocks_used", blocks_used);

	/* Totals for all blocks on the apm */
	jsonw_uint_field(json, "tcp_ports_used", ports_used[NAT_PROTO_TCP]);
	jsonw_uint_field(json, "udp_ports_used", ports_used[NAT_PROTO_UDP]);
	jsonw_uint_field(json, "other_ports_used", ports_used[NAT_PROTO_OTHER]);

	jsonw_end_object(json);
}

/*
 * apm_jsonw
 */
static void
apm_jsonw(FILE *f, struct apm_fltr *fltr)
{
	bool detail = fltr->af_detail;
	struct cds_lfht_iter iter;
	struct apm *apm;
	json_writer_t *json;
	uint i = 1, count = 0;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "apm");
	jsonw_start_array(json);

	/*
	 * If a host mask is specified in filter, then just lookup address.
	 */
	if (fltr->af_mask == 0xffffffff) {
		apm = apm_lookup(fltr->af_addr, VRF_DEFAULT_ID);
		if (apm)
			apm_jsonw_one(apm, json, detail);
		goto end;
	}

	cds_lfht_for_each_entry(apm_ht, &iter, apm, apm_node) {
		if (fltr->af_mask &&
		    (apm->apm_addr & fltr->af_mask) != fltr->af_addr)
			continue;

		if (fltr->af_count && i++ < fltr->af_start)
			continue;

		apm_jsonw_one(apm, json, detail);

		if (fltr->af_count && ++count >= fltr->af_count)
			break;
	}

end:
	jsonw_end_array(json);
	jsonw_destroy(&json);
}

static void __attribute__((format(printf, 2, 3))) cmd_err(FILE *f,
		const char *format, ...)
{
	char str[100];
	va_list ap;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	RTE_LOG(DEBUG, CGNAT, "%s\n", str);

	if (f) {
		json_writer_t *json = jsonw_new(f);
		if (json) {
			jsonw_string_field(json, "__error", str);
			jsonw_destroy(&json);
		}
	}
}

/*
 * Extract an integer from a string
 */
static int apm_arg_to_int(const char *arg)
{
	char *p;
	unsigned long val = strtoul(arg, &p, 10);

	if (p == arg || val > INT_MAX)
		return -1;

	return (uint32_t) val;
}

/*
 * cgn-op show apm [address <prefix/len>] [start <start> count <count>]
 */
void apm_show(FILE *f, int argc, char **argv)
{
	struct apm_fltr fltr = { 0 };

	fltr.af_all = true;

	/* Remove "cgn-op show apm" */
	argc -= 3;
	argv += 3;

	while (argc > 0) {
		if (!strcmp(argv[0], "address") && argc >= 2) {
			npf_addr_t npf_addr;
			npf_netmask_t pl;
			sa_family_t fam;
			uint32_t addr;
			bool negate;
			ulong tmp;
			int rc;

			rc = npf_parse_ip_addr(argv[1], &fam, &npf_addr,
					       &pl, &negate);
			if (rc < 0)
				return;

			pl = MIN(32, pl);
			memcpy(&addr, &npf_addr, 4);
			fltr.af_addr = ntohl(addr);

			tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
			fltr.af_mask = tmp;
			fltr.af_addr &= fltr.af_mask;
			fltr.af_all = false;

			argc -= 2;
			argv += 2;

		} else if (argc >= 1 && !strcmp(argv[0], "detail")) {
			fltr.af_detail = true;
			argc -= 1;
			argv += 1;

		} else if (!strcmp(argv[0], "start") && argc >= 2) {
			int tmp;

			tmp = apm_arg_to_int(argv[1]);
			if (tmp < 0)
				cmd_err(f, "invalid start: %s\n", argv[1]);

			fltr.af_start = tmp;
			/* count is optional, so set default here */
			fltr.af_count = UINT_MAX;
			fltr.af_all = false;

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "count") && argc >= 2) {
			int tmp;

			tmp = apm_arg_to_int(argv[1]);
			if (tmp < 0)
				cmd_err(f, "invalid count: %s\n", argv[1]);

			/* count of 0 means show all */
			if (tmp > 0)
				fltr.af_count = tmp;
			else
				fltr.af_count = UINT_MAX;

			argc -= 2;
			argv += 2;

		} else {
			/* Unknown option */
			argc -= 1;
			argv += 1;
		}
	}

	apm_jsonw(f, &fltr);
}

/*
 * Garbage collector per-entry inspection function
 */
static void apm_gc_inspect(struct apm *apm)
{
	assert(!rte_spinlock_is_locked(&apm->apm_lock));
	rte_spinlock_lock(&apm->apm_lock);

	/*
	 * Wait until all blocks on the entry have been removed.
	 */
	if (apm->apm_blocks_used > 0) {
		apm->apm_gc_pass = 0;
		apm->apm_flags &= ~(APM_EXPIRED | APM_DEAD);
		goto unlock;
	}

	/*
	 * Once all references are released:
	 *  1st pass: Nothing happens
	 *  2nd pass: Marked as APM_EXPIRED (no longer findable in ht)
	 *  3rd pass: Marked as APM_DEAD (apm destroyed and rcu-freed)
	 */

	if (apm->apm_gc_pass++ < APM_GC_COUNT) {
		/*
		 * Mark apm as expired 1 full gc pass before it is removed
		 * from the hash table destroyed.  Expired apms are no
		 * longer findable in the table.
		 */
		if (apm->apm_gc_pass == APM_GC_COUNT)
			apm->apm_flags |= APM_EXPIRED;
		goto unlock;
	}

	apm_destroy(apm);

unlock:
	rte_spinlock_unlock(&apm->apm_lock);
}

static void apm_gc(struct rte_timer *timer, void *arg __unused)
{
	struct cds_lfht_iter iter;
	struct apm *apm;

	if (!apm_ht)
		return;

	/* Walk the apm table */
	cds_lfht_for_each_entry(apm_ht, &iter, apm, apm_node)
		apm_gc_inspect(apm);

	/* Restart timer if dataplane still running */
	if (running && timer)
		rte_timer_reset(timer,
				APM_GC_INTERVAL * rte_get_timer_hz(),
				SINGLE, rte_get_master_lcore(), apm_gc,
				NULL);
}

/*
 * Called from unit-test and from apm_uninit.
 */
void apm_cleanup(void)
{
	uint i;

	rte_timer_stop(&apm_timer);

	for (i = 0; i <= APM_GC_COUNT; i++)
		/* Do not restart gc timer */
		apm_gc(NULL, NULL);
}

/*
 * Called via hidden vplsh command.  Used by unit-test and by dev testers.
 */
void apm_gc_pass(void)
{
	rte_timer_stop(&apm_timer);
	apm_gc(&apm_timer, NULL);
}

/*
 * Called from DP_EVT_INIT event handler
 */
void apm_init(void)
{
	if (apm_ht)
		return;

	apm_ht = cds_lfht_new(
		APM_HT_INIT, APM_HT_MIN, APM_HT_MAX,
		CDS_LFHT_AUTO_RESIZE,
		NULL);

	rte_timer_init(&apm_timer);
	rte_timer_reset(&apm_timer,
			(APM_GC_INTERVAL + 3) * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), apm_gc,
			NULL);
}

/*
 * Called from DP_EVT_UNINIT event handler
 */
void apm_uninit(void)
{
	if (!apm_ht)
		return;

	/* Do three passes of the garbage collector */
	apm_cleanup();

	assert(apm_get_used() == 0);

	dp_ht_destroy_deferred(apm_ht);
	apm_ht = NULL;
}
