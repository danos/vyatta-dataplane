/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_MAIN_H
#define CRYPTO_MAIN_H

#include <rte_per_lcore.h>
#include <rte_ring.h>
#include <rte_timer.h>
#include <stdint.h>

#include "crypto_defs.h"
#include "crypto_rte_pmd.h"
#include "urcu.h"

/*
 * Same as MAX_PKT_BURST in main.c
 */
#define MAX_CRYPTO_PKT_BURST 64

struct crypto_pkt_ctx;

/*
 * crypto_pkt_buffer
 *
 * Per lcore structure to track packets that are to be sent to the
 * crypto thread for processing and that have been returned by the
 * crypto thread and need to be post-processed in the original
 * forwarding thread.
 */

enum crypto_xfrm {
	MIN_CRYPTO_XFRM,
	CRYPTO_ENCRYPT = 0,
	CRYPTO_DECRYPT,
	MAX_CRYPTO_XFRM
};

/*
 * Per lcore structure that holds the queue of packets to crypto
 * pmds. There is a queue per XFRM type. Each queue holds packets for
 * only one PMD and the queue needs to be sent to the remote PMD
 * before traffic for a new PMD can be queued.
 */
struct crypto_pkt_buffer {
	int pmd_dev_id[MAX_CRYPTO_XFRM];
	uint32_t local_q_count[MAX_CRYPTO_XFRM];
	char SPARE[6];
	struct crypto_pkt_ctx *local_crypto_q[MAX_CRYPTO_XFRM]
	[MAX_CRYPTO_PKT_BURST];
	struct rte_crypto_op *cops[MAX_CRYPTO_PKT_BURST];
	unsigned char iv_cache[MAX_CRYPTO_PKT_BURST][CRYPTO_MAX_IV_LENGTH];
};

/*
 * crypto per-core post-processing queue
 * The processing that needs to occur after encryption/decryption is standard
 * IP forwarding that can occur in parallel on each forwarding core. The only
 * constraint is that all packets associated with a particular SA need to
 * be processed on the same forwarding core.
 */
struct crypto_fwd_info {
	struct rte_ring *fwd_q;
	uint64_t         fwd_cnt;
};

RTE_DECLARE_PER_LCORE(struct crypto_fwd_info *, crypto_fwd);

extern struct crypto_fwd_info crypto_fwd[RTE_MAX_LCORE];

RTE_DECLARE_PER_LCORE(struct crypto_pkt_buffer *, crypto_pkt_buffer);

/*
 * Crypto Pkt Buffer (CPB) DB, containing pointers to all the
 * per CORE CPB.
 */
extern struct crypto_pkt_buffer *cpbdb[RTE_MAX_LCORE];

int crypto_send_burst(struct crypto_pkt_buffer *cpb,
		      enum crypto_xfrm xfrm, bool drop);

static inline void crypto_send(struct crypto_pkt_buffer *cpb)
{
	uint32_t q;
	for (q = MIN_CRYPTO_XFRM;
	     q < MAX_CRYPTO_XFRM; q++)
		if (cpb->local_q_count[q])
			(void)crypto_send_burst(cpb, (enum crypto_xfrm)q,
						false);
}

void dp_crypto_init(void);
unsigned int dp_crypto_poll(struct cds_list_head *pmd_head);
void dp_crypto_shutdown(void);
int crypto_attach_pmd(struct cds_list_head *pmd_head,
		      int crypto_dev_id, int lcore);
void dp_crypto_periodic(struct cds_list_head *pmd_head);
void crypto_pmd_remove_all(void);
void crypto_flow_cache_timer_handler(struct rte_timer *tmr, void *arg);
int crypto_pmd_get_info(int pmd_dev_id, uint8_t *rte_dev_id,
			enum cryptodev_type *dev_type);

void crypto_create_fwd_queue(unsigned int lcore_id);
void crypto_destroy_fwd_queue(void);
void crypto_fwd_processed_packets(void);

#endif /* _CRYPTO_MAIN_H_ */
