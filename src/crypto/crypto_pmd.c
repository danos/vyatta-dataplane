/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <rte_bus_vdev.h>
#include <rte_config.h>
#include <rte_cryptodev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_ring.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "crypto.h"
#include "crypto_internal.h"
#include "crypto_main.h"
#include "json_writer.h"
#include "main.h"
#include "urcu.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "crypto_rte_pmd.h"

#define MAX_CRYPTO_PMD 128

/*
 * Dynamic number of pmds supported. Based upon the number of crypto
 * engines available which is reported from either a probe or a set.
 */
static unsigned int max_pmds;

/*
 * A per pmd structure that is referenced by dev_id in the forwarding
 * plane It can be attached to either a lcore forwarding thread for
 * processing, or to a free running pthread.
 */
struct crypto_pmd_q_pair {
	struct rte_ring *q[MAX_CRYPTO_XFRM];
};

struct pmd_counters {
	uint64_t packets;
	uint64_t bytes;
};

#define DEV_NAME_LEN 64

struct crypto_pmd {
	struct cds_list_head next;
	struct crypto_pmd_q_pair q_pair;
	unsigned int lcore;
	int dev_id;
	unsigned int sa_cnt;
	int rte_cdev_id;
	struct rcu_head pmd_rcu;
	/* --- cacheline 1 boundary (64 bytes) --- */
	/*
	 * The counters are forced into a new cache line to stop
	 * dcache sharing issues as they are updated by the engine and
	 * the other pmd fields are read by the fast path theads
	 */
	char *padding[0] __rte_cache_aligned;
	struct pmd_counters cnt[MAX_CRYPTO_XFRM];
	struct rate_stats rates[MAX_CRYPTO_XFRM];
	unsigned int sa_cnt_per_type[MAX_CRYPTO_XFRM];
	unsigned int pending_remove[MAX_CRYPTO_XFRM];
	char dev_name[DEV_NAME_LEN];
	enum cryptodev_type dev_type;
};

static_assert(offsetof(struct crypto_pmd, padding) == 64,
	      "first cache line exceeded");
static_assert(offsetof(struct crypto_pmd, cnt) == 64,
	      "first cache line exceeded");

static struct crypto_pmd *crypto_pmd_devs[MAX_CRYPTO_PMD];

/*
 * Counters to be exported for debug and status
 */
static unsigned int pmd_alloc, pmd_alloc_fail, pmd_sa_active,
	pmd_engine_assign_fail, pmd_invalid_id, pmd_not_found,
	pmd_create_failed, pmd_total_created;

static struct crypto_pmd *crypto_dev_id_to_pmd(int dev_id,
					       bool *err)
{
	if ((dev_id >= MAX_CRYPTO_PMD) ||
	    dev_id == CRYPTO_PMD_INVALID_ID) {
		CRYPTO_ERR("Invalid crypto pmd ID %d\n", dev_id);
		pmd_invalid_id++;
		*err = true;
		return NULL;
	}

	*err = false;
	return rcu_dereference(crypto_pmd_devs[dev_id]);
}

static bool crypto_pmd_rate_cb(int pmd_dev_id, enum crypto_xfrm xfrm,
			       struct rte_ring *pmd_queue __unused,
			       uint64_t *bytes __unused,
			       uint32_t *packets __unused)
{
	struct crypto_pmd *pmd;
	bool err;
	uint64_t pmd_packets, pmd_bytes;

	pmd = crypto_dev_id_to_pmd(pmd_dev_id, &err);
	if (!pmd)
		return true;

	pmd_packets = CMM_ACCESS_ONCE(pmd->cnt[xfrm].packets);
	pmd_bytes  = CMM_ACCESS_ONCE(pmd->cnt[xfrm].bytes);

	scale_rate_stats(&pmd->rates[xfrm], &pmd_packets, &pmd_bytes);
	return true;
}


static int crypto_pmd_pend_rm_cnt(struct crypto_pmd *pmd,
				   enum crypto_xfrm xfrm)
{
	int i, count = 0;

	if (xfrm == MAX_CRYPTO_XFRM) {
		for (i = 0; i < MAX_CRYPTO_XFRM; i++)
			count += pmd->pending_remove[i];
		return count;
	}

	return pmd->pending_remove[xfrm];
}

static struct crypto_pmd *
pmd_lb_tiebreak(struct crypto_pmd *best_pmd, struct crypto_pmd *pmd,
		enum crypto_xfrm xfrm)
{
	unsigned int best_sa_cnt, sa_cnt;

	if (!best_pmd)
		return pmd;

	best_sa_cnt = best_pmd->sa_cnt_per_type[xfrm] -
		crypto_pmd_pend_rm_cnt(best_pmd, xfrm);
	sa_cnt = pmd->sa_cnt_per_type[xfrm] -
		crypto_pmd_pend_rm_cnt(pmd, xfrm);

	return sa_cnt < best_sa_cnt ? pmd : best_pmd;
}

static int pmd_weighted_sa_cnt(struct crypto_pmd *pmd)
{
	return pmd->sa_cnt -
		crypto_pmd_pend_rm_cnt(pmd, MAX_CRYPTO_XFRM);
}

static struct crypto_pmd *
crypto_pmd_alloc_loadshare(enum crypto_xfrm xfrm)
{
	struct crypto_pmd *pmd, *best_pmd = NULL;
	unsigned int i, best_count = 0xffff, weight;

	for (i = 0; i < MAX_CRYPTO_PMD; i++) {
		pmd = crypto_pmd_devs[i];
		if (!pmd)
			continue;
		weight = pmd_weighted_sa_cnt(pmd);
		if (weight < best_count) {
			best_count = weight;
			best_pmd = pmd;
		} else if (weight == best_count) {
			best_pmd =
				pmd_lb_tiebreak(best_pmd, pmd, xfrm);
		}
	}
	return best_pmd;
}

/*
 * array of pmd dev ids per core per pmd type
 * Used to determine if we already have a specific type of PMD
 * running on the desired core
 */
static int8_t lcore_dev_ids[RTE_MAX_LCORE][CRYPTODEV_MAX];

static struct crypto_pmd *
crypto_pmd_find_or_create(enum crypto_xfrm xfrm,
			  enum cryptodev_type dev_type)
{
	unsigned int cpu_socket;
	uint8_t dev_id;
	struct crypto_pmd *pmd;
	enum crypto_xfrm q;
	int err;
	int lcore;

	if (pmd_alloc == 0)
		memset(lcore_dev_ids, -1, sizeof(lcore_dev_ids));

	if (xfrm == MAX_CRYPTO_XFRM)
		return NULL;

	if (pmd_alloc >= max_pmds)
		return crypto_pmd_alloc_loadshare(xfrm);

	/*
	 * check if we have an existing PMD of the desired type
	 * on the next available crypto core
	 */
	lcore = next_available_crypto_lcore();
	if (lcore < 0)
		return NULL;

	if (lcore_dev_ids[lcore][dev_type] >= 0) {
		dev_id = lcore_dev_ids[lcore][dev_type];
		return crypto_pmd_devs[dev_id];
	}

	/*
	 * allocate id for device
	 */
	for (dev_id = 0; dev_id < MAX_CRYPTO_PMD; dev_id++)
		if (!crypto_pmd_devs[dev_id])
			break;

	if (dev_id >= MAX_CRYPTO_PMD) {
		CRYPTO_ERR("PMD alloc failed\n");
		pmd_create_failed++;
		return NULL;
	}

	cpu_socket = rte_lcore_to_socket_id(rte_get_master_lcore());

	pmd = rte_zmalloc_socket("crypto pmd",
				 sizeof(*pmd),
				 RTE_CACHE_LINE_SIZE,
				 cpu_socket);
	if (!pmd) {
		CRYPTO_ERR("PMD alloc failed\n");
		pmd_create_failed++;
		return NULL;
	}

	pmd->dev_id = dev_id;

	err = crypto_rte_create_pmd(cpu_socket, dev_id,
				    dev_type, pmd->dev_name, DEV_NAME_LEN,
				    &pmd->rte_cdev_id);
	if (err != 0) {
		CRYPTO_ERR("Could not create DPDK PMD\n");
		rte_free(pmd);
		return NULL;
	}

	pmd->dev_type = dev_type;

	CDS_INIT_LIST_HEAD(&pmd->next);

	pmd->q_pair.q[CRYPTO_ENCRYPT] =
		crypto_create_ring("pmd-en-q", PMD_RING_SIZE,
				   cpu_socket, dev_id,
				   RING_F_SC_DEQ);
	pmd->q_pair.q[CRYPTO_DECRYPT] =
		crypto_create_ring("pmd-de-q", PMD_RING_SIZE,
				   cpu_socket, dev_id,
				   RING_F_SC_DEQ);

	/* Need to add the pmd to the table as the callback
	 * from crypto_assign_engine needs to locate pmd
	 */
	rcu_assign_pointer(crypto_pmd_devs[dev_id], pmd);

	if (crypto_assign_engine(pmd->dev_id, lcore) < 0) {
		pmd_engine_assign_fail++;
		rcu_assign_pointer(crypto_pmd_devs[dev_id], NULL);
		for (q = MIN_CRYPTO_XFRM; q < MAX_CRYPTO_XFRM; q++)
			crypto_delete_queue(pmd->q_pair.q[q]);
		rte_free(pmd);
		return NULL;
	}

	lcore_dev_ids[lcore][dev_type] = pmd->dev_id;
	pmd_alloc++;
	pmd_total_created++;

	return pmd;
}

void crypto_pmd_mod_pending_del(int pmd_dev_id, enum crypto_xfrm xfrm, bool inc)
{
	if (pmd_dev_id == CRYPTO_PMD_INVALID_ID)
		return;
	if (crypto_pmd_devs[pmd_dev_id]) {
		if (inc)
			crypto_pmd_devs[pmd_dev_id]->pending_remove[xfrm]++;
		else
			crypto_pmd_devs[pmd_dev_id]->pending_remove[xfrm]--;
	}
}

void crypto_pmd_dec_pending_del(int pmd_dev_id, enum crypto_xfrm xfrm)
{
	if (pmd_dev_id == CRYPTO_PMD_INVALID_ID)
		return;
	if (crypto_pmd_devs[pmd_dev_id])
		crypto_pmd_devs[pmd_dev_id]->pending_remove[xfrm]--;
}

static int crypto_cpu_describe(FILE *f, unsigned int count,
			       bool sticky)
{
	json_writer_t *wr = jsonw_new(f);

	if (!wr)
		return -1;

	jsonw_pretty(wr, true);
	jsonw_start_object(wr);
	jsonw_name(wr, "crypto_cores");
	jsonw_uint_field(wr, "count", count);
	jsonw_uint_field(wr, "crypto_sticky", sticky);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	return 0;
}

static void set_max_pmd(unsigned int new)
{
	max_pmds = new < MAX_CRYPTO_PMD ?
		new : MAX_CRYPTO_PMD;
}

int crypto_engine_probe(FILE *f)
{
	unsigned int num;
	bool sticky;

	num = probe_crypto_engines(&sticky);
	set_max_pmd(num);

	return  f ? crypto_cpu_describe(f, num, sticky) :
		 (int) num;
}

int crypto_engine_set(FILE *f, const char *str)
{
	bool tmp_sticky;
	int num  = set_crypto_engines(str, &tmp_sticky);

	if (!f)
		return -1;

	if (num < 0) {
		fprintf(f, "error invalid mask\n");
		return -1;
	}

	set_max_pmd(num);

	return crypto_cpu_describe(f, num, tmp_sticky);
}
/*
 * Return a PMD to be used by the caller, either reusing an
 * existing PMD or create a new one. If a new one is created
 * then link it to a crypto_engine
 */
int crypto_allocate_pmd(enum crypto_xfrm xfrm,
			enum rte_crypto_cipher_algorithm cipher_algo,
			enum rte_crypto_aead_algorithm aead_algo)
{
	struct crypto_pmd *pmd;
	enum cryptodev_type dev_type;
	bool setup_openssl;
	int err;

	/* If this is the first SA then lets go probe the number
	 * of crypto engines we have.
	 */
	if (!pmd_alloc)
		(void)crypto_engine_probe(NULL);

	err = crypto_rte_select_pmd_type(cipher_algo, aead_algo, &dev_type,
					 &setup_openssl);
	if (err)
		return CRYPTO_PMD_INVALID_ID;

	pmd = crypto_pmd_find_or_create(xfrm, dev_type);

	if (!pmd) {
		pmd_alloc_fail++;
		return CRYPTO_PMD_INVALID_ID;
	}

	pmd->sa_cnt++;
	pmd->sa_cnt_per_type[xfrm]++;
	pmd_sa_active++;

	return pmd->dev_id;
}

static void pmd_purge_and_release_queues(struct crypto_pmd *pmd)
{
	unsigned int q;

	for (q = MIN_CRYPTO_XFRM; q < MAX_CRYPTO_XFRM; q++) {
		crypto_purge_queue(pmd->q_pair.q[q]);
		crypto_delete_queue(pmd->q_pair.q[q]);
	}
}

static void pmd_rcu_free(struct rcu_head *head)
{
	struct crypto_pmd *pmd;
	int err;

	pmd  = caa_container_of(head, struct crypto_pmd, pmd_rcu);
	pmd_purge_and_release_queues(pmd);

	err = crypto_rte_destroy_pmd(pmd->dev_type, pmd->dev_name,
				     pmd->dev_id);
	if (err != 0)
		CRYPTO_ERR("Could not destroy pmd %s\n", pmd->dev_name);

	rte_free(pmd);
}

static void crypto_pmd_remove(int dev_id)
{
	bool err;
	struct crypto_pmd *pmd = crypto_dev_id_to_pmd(dev_id,
						      &err);

	if (!pmd)
		return;

	rcu_assign_pointer(crypto_pmd_devs[dev_id], NULL);
	pmd_alloc--;

	cds_list_del_rcu(&pmd->next);

	crypto_unassign_from_engine(pmd->lcore);

	call_rcu(&pmd->pmd_rcu, pmd_rcu_free);
}

void crypto_pmd_remove_all(void)
{
	int i;

	for (i = 0; i < MAX_CRYPTO_PMD; i++)
		if (crypto_pmd_devs[i])
			crypto_pmd_remove(i);
}

void crypto_remove_sa_from_pmd(int dev_id, enum crypto_xfrm xfrm,
			       struct crypto_session *ctx,
			       bool pending)
{
	bool err;
	struct crypto_pmd *pmd = crypto_dev_id_to_pmd(dev_id,
						      &err);

	if (!pmd) {
		CRYPTO_ERR("No PMD for ID %d\n", dev_id);
		pmd_not_found++;
		return;
	}

	crypto_rte_destroy_session(ctx, pmd->rte_cdev_id);

	pmd->sa_cnt_per_type[xfrm]--;
	pmd->sa_cnt--;
	pmd_sa_active--;
	if (pending)
		crypto_pmd_dec_pending_del(dev_id, xfrm);

	if (!pmd->sa_cnt)
		crypto_pmd_remove(dev_id);
}

/*
 * Insert a PMD into the list of PMDs being procssed by an engine,
 * i.e. an lcore or a pthread
 */
int crypto_attach_pmd(struct cds_list_head *pmd_list, int dev_id, int lcore)
{
	bool err;
	struct crypto_pmd *new_pmd = crypto_dev_id_to_pmd(dev_id,
							  &err);
	if (!new_pmd) {
		CRYPTO_ERR("Failed to attach crypto_dev %d to lcore %d\n",
			   dev_id, lcore);
		pmd_not_found++;
		return -1;
	}

	new_pmd->lcore = lcore;
	cds_list_add_rcu(&new_pmd->next, pmd_list);
	return 0;
}

/*
 * Used by the forwarding threads to retrieve the remote pmd queue
 * to send packet to.
 */
struct rte_ring *crypto_pmd_get_q(int dev_id, enum crypto_xfrm xfrm)
{
	struct crypto_pmd *pmd;
	bool err;

	pmd = crypto_dev_id_to_pmd(dev_id, &err);
	if (!pmd) {
		pmd_not_found++;
		return NULL;
	}

	return pmd->q_pair.q[xfrm];
}

/*
 * crypto pmd processing loop.
 */
void dp_crypto_periodic(struct cds_list_head *pmd_head)
{
	(void)crypto_pmd_walk_per_xfrm(pmd_head,
				       crypto_pmd_rate_cb);
}

/*
 * Walk the list of PMDs passed calling the passed callback for each
 * XFRM within a PMD.
 */
unsigned int crypto_pmd_walk_per_xfrm(struct cds_list_head *pmd_head,
				      crypto_pmd_walker_cb cb)
{
	struct crypto_pmd *pmd;
	enum crypto_xfrm q;
	uint64_t bytes;
	uint32_t pkts, total_pkts = 0;
	bool rc;

	cds_list_for_each_entry_rcu(pmd, pmd_head, next) {
		for (q = MIN_CRYPTO_XFRM; q < MAX_CRYPTO_XFRM; q++) {
			pkts = bytes = 0;
			rc = (cb)(pmd->dev_id, q, pmd->q_pair.q[q],
				  &bytes, &pkts);
			pmd->cnt[q].bytes += bytes;
			pmd->cnt[q].packets += pkts;
			total_pkts += pkts;
			if (!rc)
				break;
		}
	}
	return total_pkts;
}

static void
crypto_show_pmd_counters(json_writer_t *wr, struct crypto_pmd *pmd)
{
	enum crypto_xfrm q;

	if (!pmd)
		return;

	jsonw_start_object(wr);
	jsonw_uint_field(wr, "pmd_dev_id", pmd->dev_id);
	jsonw_uint_field(wr, "active_sa", pmd->sa_cnt);
	jsonw_uint_field(wr, "lcore", pmd->lcore);
	jsonw_start_array(wr);
	jsonw_name(wr, "per_pmd_counters");
	for (q = MIN_CRYPTO_XFRM; q < MAX_CRYPTO_XFRM; q++) {
		uint64_t packets, bytes;

		jsonw_start_object(wr);
		jsonw_name(wr, crypto_xfrm_name(q));
		bytes = pmd->cnt[q].bytes;
		packets = pmd->cnt[q].packets;
		jsonw_uint_field(wr, "bytes", bytes);
		jsonw_uint_field(wr, "packets", packets);
		bytes = pmd->rates[q].byte_rate;
		packets = pmd->rates[q].packet_rate;
		jsonw_uint_field(wr, "bytes_per_sec", bytes);
		jsonw_uint_field(wr, "packets_per_sec", packets);
		jsonw_uint_field(wr, "ring_count",
				 rte_ring_count(pmd->q_pair.q[q]));
		jsonw_uint_field(wr, "sa_count",
				 pmd->sa_cnt_per_type[q]);
		jsonw_uint_field(wr, "sa_del_pending",
				 pmd->pending_remove[q]);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
}

void crypto_show_pmd(FILE *f)
{
	int i;
	json_writer_t *wr = jsonw_new(f);
	bool err;

	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "pmd_info");
	jsonw_start_object(wr);
	jsonw_name(wr, "pmd_general counters");
	jsonw_uint_field(wr, "sas_bound", pmd_sa_active);
	jsonw_uint_field(wr, "total_created", pmd_total_created);
	jsonw_uint_field(wr, "alloc", pmd_alloc);
	jsonw_uint_field(wr, "alloc_fail", pmd_alloc_fail);
	jsonw_uint_field(wr, "engine_assign_fail",
			 pmd_engine_assign_fail);
	jsonw_uint_field(wr, "pmd_invalid_id", pmd_invalid_id);
	jsonw_uint_field(wr, "pmd_not_found", pmd_not_found);
	jsonw_uint_field(wr, "pmd_create_fail", pmd_create_failed);
	jsonw_end_object(wr);

	jsonw_start_object(wr);
	jsonw_name(wr, "allocated_crypto_pmd");
	jsonw_start_array(wr);
	for (i = 0; i < MAX_CRYPTO_PMD; i++)
		crypto_show_pmd_counters(wr, crypto_dev_id_to_pmd(i, &err));
	jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

int crypto_pmd_get_info(int pmd_dev_id, uint8_t *rte_dev_id,
			enum cryptodev_type *dev_type)
{
	struct crypto_pmd *pmd;
	bool err;

	pmd = crypto_dev_id_to_pmd(pmd_dev_id, &err);
	if (!pmd) {
		pmd_not_found++;
		return -ENOENT;
	}

	*rte_dev_id = pmd->rte_cdev_id;
	*dev_type = pmd->dev_type;
	return 0;
}
