/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <linux/snmp.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include <stdint.h>
#include <stdlib.h>

#include "ipv4_frag_tbl.h"
#include "ipv4_rsmbl.h"
#include "snmp_mib.h"
#include "util.h"
#include "vplane_log.h"
#include "vrf_internal.h"

struct cds_lfht;

static struct rte_timer ipv4_timer;
static uint32_t hash_seed;

/* free a pkt */
static void ipv4_frag_free_pkt(struct rcu_head *head)
{
	struct ipv4_frag_pkt *pkt = caa_container_of(head,
					struct ipv4_frag_pkt, pkt_rcu_head);
	uint32_t i;

	for (i = 0; i != pkt->last_idx; i++) {
		if (pkt->frags[i].mb)
			dp_pktmbuf_notify_and_free(pkt->frags[i].mb);
	}
	free(pkt);
}

/* update timeout stats */
static void ipv4_frag_timeout_stats(struct ipv4_frag_pkt *pkt)
{
	uint32_t i;

	/* temp while frag vrf unaware */
	IPSTAT_INC(VRF_DEFAULT_ID, IPSTATS_MIB_REASMFAILS);
	for (i = 0; i != pkt->last_idx; i++) {
		if (pkt->frags[i].mb)
			/* temp while frag vrf unaware */
			IPSTAT_INC(VRF_DEFAULT_ID, IPSTATS_MIB_REASMTIMEOUT);
	}
}

/* Delete a frag packet struct from the hash table */
void ipv4_frag_free(struct cds_lfht *frag_table, struct ipv4_frag_pkt *pkt)
{
	if (!cds_lfht_del(frag_table, &pkt->pkt_node))
		call_rcu(&pkt->pkt_rcu_head, ipv4_frag_free_pkt);
}

/*
 * Clean out expired frag pkts
 *
 * NB ipv4_gc() is a callback function for rte_timer_reset(),
 *    so we use __rte_unused rather than __unused.
 */
static void ipv4_gc(struct rte_timer *t __rte_unused, void *arg __rte_unused)
{
	struct cds_lfht_iter iter;
	struct ipv4_frag_pkt *pkt;
	uint64_t current = rte_get_timer_cycles();
	vrfid_t vrfid;
	struct vrf *vrf;

	VRF_FOREACH(vrf, vrfid) {
		cds_lfht_for_each_entry(vrf->v_ipv4_frag_table, &iter, pkt,
					pkt_node) {
			if (pkt->pkt_expire < current) {
				ipv4_frag_timeout_stats(pkt);
				ipv4_frag_free(vrf->v_ipv4_frag_table, pkt);
			}
		}
	}
}

/* Clear the rte_mbufs from a pkt */
void ipv4_frag_clear(struct ipv4_frag_pkt *pkt)
{
	uint32_t i;

	for (i = 0; i != pkt->last_idx; i++)
		pkt->frags[i].mb = NULL;
}

/* Hash the key */
static unsigned long ipv4_hash(const struct ipv4_frag_key *key)
{
	uint32_t v;
	const uint32_t *p;

	p = (const uint32_t *)&key->src_dst;
	v = rte_jhash_3words(p[0], p[1], key->id, hash_seed);

	return v;
}

/* hash table match function */
static int ipv4_match(struct cds_lfht_node *node, const void *data)
{
	const struct ipv4_frag_key *key = data;
	struct ipv4_frag_pkt *pkt;
	int rc = 1;

	pkt = caa_container_of(node, struct ipv4_frag_pkt, pkt_node);

	if (key->src_dst != pkt->pkt_key.src_dst)
		rc = 0;
	if (key->id != pkt->pkt_key.id)
		rc = 0;
	return rc;
}

/* Count nodes */
static unsigned long ipv4_frag_count(struct cds_lfht *frag_table)
{
	unsigned long count;
	long dummy;

	cds_lfht_count_nodes(frag_table, &dummy, &count, &dummy);
	return count;
}

/* Add a new pkt if max not reached */
static struct ipv4_frag_pkt *
ipv4_frag_create(struct cds_lfht *frag_table, unsigned long hash,
		 const struct ipv4_frag_key *key)
{
	struct ipv4_frag_pkt *pkt;
	struct cds_lfht_node *node;
	unsigned long count;

	/* Max packets reached? */
	count = ipv4_frag_count(frag_table);
	if (count >= IPV4_MAX_FRAG_SETS)
		return NULL;

	pkt = calloc(1, sizeof(struct ipv4_frag_pkt));
	if (!pkt)
		return NULL;

	rte_spinlock_init(&pkt->pkt_lock);
	pkt->pkt_key.src_dst = key->src_dst;
	pkt->pkt_key.id = key->id;
	pkt->last_idx = FIRST_INTERMEDIATE_FRAG_IDX;
	cds_lfht_node_init(&pkt->pkt_node);
	pkt->pkt_expire = rte_get_timer_cycles() +
		(rte_get_timer_hz() * IPV4_FRAG_SET_TTL);

	/*
	 * Now try to add the new pkt, if somebody beat us to it,
	 * use that one.
	 */
	node = cds_lfht_add_unique(frag_table, hash, ipv4_match,
				key, &pkt->pkt_node);
	if (node != &pkt->pkt_node) {
		free(pkt);
		pkt = caa_container_of(node, struct ipv4_frag_pkt, pkt_node);
	}

	return pkt;
}

/* Lookup a 'pkt' in the hash table */
static struct ipv4_frag_pkt *
ipv4_frag_lookup(struct cds_lfht *frag_table, unsigned long hash,
		 const struct ipv4_frag_key *key)
{
	struct ipv4_frag_pkt *pkt;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(frag_table, hash, ipv4_match, key, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node)
		pkt = caa_container_of(node, struct ipv4_frag_pkt, pkt_node);
	else
		pkt = NULL;

	return pkt;
}

/*
 * Find an entry in the table for the corresponding fragment.
 * If such entry is not present, then allocate a new one.
 */
struct ipv4_frag_pkt *ipv4_frag_find(struct vrf *vrf,
				     const struct ipv4_frag_key *key)
{
	struct ipv4_frag_pkt *pkt;
	unsigned long hash = ipv4_hash(key);
	struct cds_lfht *frag_table = vrf->v_ipv4_frag_table;

	pkt = ipv4_frag_lookup(frag_table, hash, key);
	if (!pkt)
		pkt = ipv4_frag_create(frag_table, hash, key);
	return pkt;
}

static void
ipv4_fragment_table_uninit(struct vrf *vrf)
{
	struct cds_lfht_iter iter;
	struct ipv4_frag_pkt *pkt;

	if (!vrf->v_ipv4_frag_table)
		return;

	cds_lfht_for_each_entry(vrf->v_ipv4_frag_table, &iter, pkt,
				pkt_node) {
		ipv4_frag_free(vrf->v_ipv4_frag_table, pkt);
	}

	dp_ht_destroy_deferred(vrf->v_ipv4_frag_table);
	vrf->v_ipv4_frag_table = NULL;
}

/*
 * Create a new IPV4 Frag table.
 */
static int
ipv4_fragment_table_init(struct vrf *vrf)
{
	/*
	 * Create a RCU hash table.  Since we only support a
	 * (relatively) small number of frag pkt's at any given time,
	 * allow to grow but not shrink.  We can save cycles by not doing
	 * accounting for splits.
	 */
	vrf->v_ipv4_frag_table = cds_lfht_new(IPV4_FRAG_HT_INIT,
					      IPV4_FRAG_HT_MIN,
					      IPV4_FRAG_HT_MAX,
					      CDS_LFHT_AUTO_RESIZE, NULL);
	if (!vrf->v_ipv4_frag_table) {
		DP_LOG_W_VRF(ERR, DATAPLANE, vrf->v_id,
			     "Unable to create ipv4 frag hash table\n");
		return -1;
	}

	/*
	 * Create a seed for hashing
	 */
	hash_seed = random();
	return 0;
}

/*
 * Create a new IPV4 and IPv6 fragment reassembly tables.
 */
int fragment_tables_init(struct vrf *vrf)
{
	int ret = 0;

	ret = ipv4_fragment_table_init(vrf);
	if (ret < 0)
		return ret;

	return ipv6_fragment_table_init(vrf);
}

void fragment_tables_uninit(struct vrf *vrf)
{
	ipv4_fragment_table_uninit(vrf);
	ipv6_fragment_table_uninit(vrf);
}

static void
ipv4_fragment_tables_timer_init(void)
	{
	/*
	 * Creat a timer for cleanup of stale entries.
	 */
	rte_timer_init(&ipv4_timer);
	rte_timer_reset(&ipv4_timer, IPV4_FRAG_INTERVAL * rte_get_timer_hz(),
			PERIODICAL, rte_get_master_lcore(), ipv4_gc, NULL);
}

void fragment_tables_timer_init(void)
{
	ipv4_fragment_tables_timer_init();
	ipv6_fragment_tables_timer_init();
}
