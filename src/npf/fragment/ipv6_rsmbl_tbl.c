/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <stdlib.h>

#include "compiler.h"
#include "npf/fragment/ipv4_rsmbl.h"
#include "npf/npf.h"
#include "npf/fragment/ipv6_rsmbl_tbl.h"
#include "util.h"
#include "vplane_log.h"
#include "vrf.h"

struct cds_lfht;

/*
 * Globals
 */
static struct rte_timer ipv6_timer;
static uint32_t ipv6_hash_seed;

static inline void
ipv6_frag_key_copy(struct ipv6_frag_key *dst,
		   const struct ipv6_frag_key *src)
{
	unsigned int word;

	for (word = 0; word < IPV6_FRAG_KEY_WORDS; word++)
		dst->src_dst[word] = src->src_dst[word];

	dst->id = src->id;
}

/*
 * Compare two keys, and return -1, 0, or 1 if k1 < k2, k1 == k2, or
 * k1 > k2, respectively.
 */
static inline int
ipv6_frag_key_cmp(const struct ipv6_frag_key *k1,
		  const struct ipv6_frag_key *k2)
{
	unsigned int word;

	for (word = 0; word < IPV6_FRAG_KEY_WORDS; word++) {
		if (k1->src_dst[word] < k2->src_dst[word])
			return -1;
		if (k1->src_dst[word] > k2->src_dst[word])
			return 1;
	}
	if (k1->id < k2->id)
		return -1;
	if (k1->id > k2->id)
		return 1;
	return 0;
}

/*
 * update timeout stats
 */
static void
ipv6_frag_timeout_stats(struct ipv6_frag_pkt *fp __unused)
{
}

/*
 * free a fragmentation packet
 */
static void ipv6_frag_free_pkt(struct rcu_head *head)
{
	struct ipv6_frag_pkt *fp = caa_container_of(head,
				    struct ipv6_frag_pkt, pkt_rcu_head);
	struct rte_mbuf *m;
	uint32_t i;

	for (i = 0; i != fp->last_idx; i++) {
		m = fp->frags[i].mb;
		if (m != NULL) {
			rte_pktmbuf_free(m);
			fp->frags[i].mb = NULL;
		}
	}
	free(fp);
}

/*
 * Delete a frag packet struct from the hash table
 */
void
ipv6_frag_free(struct cds_lfht *frag_table, struct ipv6_frag_pkt *fp)
{
	if (!cds_lfht_del(frag_table, &fp->pkt_node))
		call_rcu(&fp->pkt_rcu_head, ipv6_frag_free_pkt);
}

/*
 * Clean out expired frag pkts
 *
 * NB ipv6_gc() is a callback function for rte_timer_reset(),
 *    so we use __rte_unused rather than __unused.
 */
static void
ipv6_gc(struct rte_timer *t __rte_unused, void *arg __rte_unused)
{
	struct cds_lfht_iter iter;
	struct ipv6_frag_pkt *fp;
	uint64_t current = get_time_uptime(); /* uptime in secs */
	vrfid_t vrfid;
	struct vrf *vrf;

	VRF_FOREACH(vrf, vrfid) {
		if (!vrf)
			continue;

		cds_lfht_for_each_entry(vrf->v_ipv6_frag_table, &iter, fp,
					pkt_node) {
			if (fp->pkt_expire < current) {
				ipv6_frag_timeout_stats(fp);
				ipv6_frag_free(vrf->v_ipv6_frag_table, fp);
			}
		}
	}
}

/*
 * Clear the rte_mbufs from a pkt
 */
void
ipv6_frag_clear(struct ipv6_frag_pkt *fp)
{
	uint32_t i;

	for (i = 0; i != fp->last_idx; i++)
		fp->frags[i].mb = NULL;
}

static unsigned long
ipv6_hash(const struct ipv6_frag_key *key)
{
	/* Plus one to include the 'id' field */
	return rte_jhash_32b(key->src_dst, IPV6_FRAG_KEY_WORDS + 1,
			     ipv6_hash_seed);
}

/*
 * hash table match function.	Return 1 for a match, 0 for no match
 */
static int
ipv6_match(struct cds_lfht_node *node, const void *data)
{
	const struct ipv6_frag_key *key = data;
	struct ipv6_frag_pkt *fp;

	fp = caa_container_of(node, struct ipv6_frag_pkt, pkt_node);

	return ipv6_frag_key_cmp(key, &fp->pkt_key) == 0 ? 1 : 0;
}

/* Count nodes */
static unsigned long
ipv6_frag_count(struct cds_lfht *frag_table)
{
	unsigned long count;
	long dummy;

	cds_lfht_count_nodes(frag_table, &dummy, &count, &dummy);
	return count;
}

/*
 * Add a new pkt if max not reached
 */
static struct ipv6_frag_pkt *
ipv6_frag_create(struct cds_lfht *frag_table, unsigned long hash,
		 const struct ipv6_frag_key *key)
{
	struct cds_lfht_node *node;
	struct ipv6_frag_pkt *fp;
	unsigned long count;

	/* Max packets reached? */
	count = ipv6_frag_count(frag_table);
	if (count >= IPV6_MAX_FRAG_SETS)
		return NULL;

	fp = calloc(1, sizeof(struct ipv6_frag_pkt));
	if (!fp)
		return NULL;

	rte_spinlock_init(&fp->pkt_lock);
	ipv6_frag_key_copy(&fp->pkt_key, key);
	fp->last_idx = FIRST_INTERMEDIATE_FRAG_IDX;
	cds_lfht_node_init(&fp->pkt_node);
	fp->pkt_expire = get_time_uptime() + IPV6_FRAG_SET_TTL;

	/*
	 * Now try to add the new pkt, if somebody beat us to it, use
	 * that one.
	 */
	node = cds_lfht_add_unique(frag_table, hash, ipv6_match,
				   key, &fp->pkt_node);
	if (node != &fp->pkt_node) {
		free(fp);
		fp = caa_container_of(node, struct ipv6_frag_pkt, pkt_node);
	}

	return fp;
}

/*
 * Lookup a 'pkt' in the hash table
 */
static struct ipv6_frag_pkt *
ipv6_frag_lookup(struct cds_lfht *frag_table, unsigned long hash,
		 const struct ipv6_frag_key *key)
{
	struct ipv6_frag_pkt *fp;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(frag_table, hash, ipv6_match, key, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node)
		fp = caa_container_of(node, struct ipv6_frag_pkt, pkt_node);
	else
		fp = NULL;

	return fp;
}

/*
 * Find an entry in the table for the corresponding fragment.
 * If such entry is not present, then allocate a new one.
 */
struct ipv6_frag_pkt *
ipv6_frag_find_or_create(struct vrf *vrf, const struct ipv6_frag_key *key)
{
	struct ipv6_frag_pkt *fp;
	unsigned long hash = ipv6_hash(key);
	struct cds_lfht *frag_table = vrf->v_ipv6_frag_table;

	fp = ipv6_frag_lookup(frag_table, hash, key);
	if (!fp)
		fp = ipv6_frag_create(frag_table, hash, key);

	return fp;
}

void
ipv6_fragment_table_uninit(struct vrf *vrf)
{
	struct cds_lfht_iter iter;
	struct ipv6_frag_pkt *pkt;

	if (!vrf->v_ipv6_frag_table)
		return;

	cds_lfht_for_each_entry(vrf->v_ipv6_frag_table, &iter, pkt,
				pkt_node) {
		ipv6_frag_free(vrf->v_ipv6_frag_table, pkt);
	}

	dp_ht_destroy_deferred(vrf->v_ipv6_frag_table);
	vrf->v_ipv6_frag_table = NULL;
}

/*
 * Create a new IPv6 Frag table.
 */
int
ipv6_fragment_table_init(struct vrf *vrf)
{
	/*
	 * Create a lock-free RCU hash table.  Since we only support a
	 * (relatively) small number of frag pkt's at any given time,
	 * allow to grow but not shrink.  We can save cycles by not
	 * doing accounting for splits.
	 */
	vrf->v_ipv6_frag_table = cds_lfht_new(IPV6_FRAG_HT_INIT,
					      IPV6_FRAG_HT_MIN,
					      IPV6_FRAG_HT_MAX,
					      CDS_LFHT_AUTO_RESIZE, NULL);
	if (!vrf->v_ipv6_frag_table) {
		DP_LOG_W_VRF(ERR, DATAPLANE, vrf->v_id,
			     "Unable to create ipv6 frag hash table\n");
		return -1;
	}

	/*
	 * Create a seed for hashing
	 */
	ipv6_hash_seed = random();
	return 0;
}

void ipv6_fragment_tables_timer_init(void)
{
	/*
	 * Create a timer for cleanup of stale entries.
	 */
	rte_timer_init(&ipv6_timer);
	rte_timer_reset(&ipv6_timer,
			IPV6_FRAG_INTERVAL * rte_get_timer_hz(),
			PERIODICAL, rte_get_master_lcore(), ipv6_gc, NULL);
}
