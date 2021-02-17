/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */
/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
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
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <linux/if.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <urcu/arch.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <czmq.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_ring.h>
#include <rte_timer.h>
#include <rte_version.h>
#include <setjmp.h>

#include "address.h"
#include "bitmask.h"
#include "capture.h"
#include "commands.h"
#include "compat.h"
#include "compiler.h"
#include "config_internal.h"
#include "crypto/crypto_forward.h"
#include "crypto/crypto_main.h"
#include "dp_event.h"
#include "ether.h"
#include "event_internal.h"
#include "fal.h"
#include "feature_plugin_internal.h"
#include "if/dpdk-eth/dpdk_eth_if.h"
#include "if/dpdk-eth/dpdk_eth_linkwatch.h"
#include "if/dpdk-eth/vhost.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "ip_ttl.h"
#include "json_writer.h"
#include "l2_rx_fltr.h"
#include "main.h"
#include "controller.h"
#include "mpls/mpls_label_table.h"
#include "netinet6/ip6_funcs.h"
#include "npf/fragment/ipv4_rsmbl.h"
#include "npf_shim.h"
#include "pipeline/pl_internal.h"
#include "pktmbuf_internal.h"
#include "portmonitor/portmonitor.h"
#include "power.h"
#include "qos.h"
#include "rcu.h"
#include "route.h"
#include "session/session.h"
#include "lcore_sched.h"
#include "lcore_sched_internal.h"
#include "udp_handler.h"
#include "util.h"
#include "version.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "backplane.h"

packet_input_t packet_input_func __hot_data = ether_input_no_dyn_feats;

#define MBUF_OVERHEAD RTE_PKTMBUF_HEADROOM
#define MIN_MBUF_POOL	4096			/* Minimum number of mbufs */

/* per-core cache size for global pools */
#define NUMA_POOL_MBUF_CACHE_SIZE 256

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

/*
 * Number of RX/TX ring descriptors per queue
 * At 10G need more descriptors but it also has more
 * restrictions on IXGE:
 *  1. Rx_desc < IXGBE_MAX_RING_DESC(4096) - RTE_PMD_IXGE_RX_MAX_BURST(32)
 *  2. Rx_desc must be power of 2
 */

/* For bond interface, maximum number of member interfaces */
#define DATAPLANE_MEMBER_MULTIPLIER	2

static struct rxtx_param *driver_param;

#define DEFAULT_FCPAUSE	0xffff	/* see ixgbe.h */

#define RX_PKT_BURST  32
#define QOS_PKT_BURST 64
#define TX_PKT_BURST  32

/* Number of packets queued between top and bottom half.
 * It has to be big enough that an initial burst of packets
 * can be processed by Tx thread which may be sleeping.
 */
#define PKT_RING_SIZE	2048

/* Union to allow atomic fetch */
union atomic_stat {
	uint64_t qword;
	uint32_t dword[2];
};

/* Temporary buffer to aggregate before going into the packet ring */
struct pkt_burst {
	uint8_t			port;	/* intended port */
	uint16_t		queue;  /* queue to use for multi-queue tx */
	uint32_t		count;	/* packets in burst */
	struct rte_mbuf *m_tbl[TX_PKT_BURST];	/* pending packets */
};

RTE_DEFINE_PER_LCORE(unsigned int, _dp_lcore_id) = 0;
static RTE_DEFINE_PER_LCORE(struct pkt_burst *, pkt_burst);

enum lcore_state {
	LCORE_STATE_POLL,
	LCORE_STATE_POWERSAVE,
	LCORE_STATE_IDLE,
	LCORE_STATE_EXIT,
};

/*
 * Per CPU configuration
 */
struct lcore_conf {
	/* mask of receive ports this cpu should check */
	bitmask_t portmask;

	uint16_t num_rxq;     /* # rx queues currently assigned to this cpu */
	uint16_t high_rxq;    /* highest index assigned to rx_poll */
	uint8_t num_txq;      /* # tx queues currently assigned to this cpu */
	bool running;         /* whether the forwarding loop is running */
	uint16_t high_txq;    /* highest index assigned to tx_poll */
	uint8_t tx_qid;	      /* my tx queue for multi-queue devices */
	uint8_t do_crypto;    /* thread is tasked with doing crypto */
	uint8_t crypto_fwd;   /* post-crypto forwarding workload present */

	/* receive queues this cpu should check for input */
	struct lcore_rx_queue {
		portid_t portid;
		uint8_t queueid;
		struct pm_governor gov;
		uint64_t packets;
	} rx_poll[MAX_RX_QUEUE_PER_CORE];

	/* transmit queues this cpu should do output processing on */
	struct lcore_tx_queue {
		portid_t portid;
		uint8_t queueid;
		uint8_t ringid;
		uint8_t pending : 7;
		/*
		 * Call transmit function even if there are no packets
		 * to send, e.g. for bonding 802.3ad mode where
		 * control packets share a queue with data packets.
		 */
		uint8_t tx_no_pkts : 1;
		struct pm_governor gov;
		uint64_t packets;
		struct rte_mbuf *burst[TX_PKT_BURST];
	} tx_poll[MAX_TX_QUEUE_PER_CORE];

	struct lcore_crypt {
		struct pm_governor gov;
		uint64_t packets;
		struct cds_list_head pmd_list;
	} crypt;

	/* Not touched in forwarding path so at end to avoid false sharing */
	void *padding[0]   __rte_cache_aligned;
	struct rate_stats rx_poll_stats[MAX_RX_QUEUE_PER_CORE];
	struct rate_stats tx_poll_stats[MAX_TX_QUEUE_PER_CORE];
	struct rate_stats crypt_stats;
	struct rate_stats crypt_fwd_stats;
	bool ded_to_feature;

	/* State for when a feature has registered to use this core */
	uint8_t do_feature;
	struct dp_lcore_feat feat;
	struct rate_stats feat_rx_stats;
	struct rate_stats feat_tx_stats;
} __rte_cache_aligned;

static struct lcore_conf *lcore_conf[RTE_MAX_LCORE];

/* Is the rx/tx queue reusable.
 * Must be > maximum portid (RTE_MAX_ETHPORTS)
 */
static const uint8_t NO_OWNER = 255;

/* Port configuration */
static struct port_conf {
	struct rte_ring *pkt_ring[MAX_TX_QUEUE_PER_PORT];	/*  0 32 */
	uint8_t		nrings;					/* 32  1 */
	uint8_t		max_rings;				/* 33  1 */
	bool		percoreq;				/* 34  1 */

	/* XXX 5 bytes hole, try to pack. */

	bitmask_t	tx_enabled_queues;			/* 40 16 */
	bitmask_t	rx_enabled_queues;			/* 56 16 */

	/* size: 128, cachlines: 2, members: 6 */
	/* sum members: 57, holes: 1, sum holes: 5 */
	/* padding: 56 */
} __rte_cache_aligned port_config[DATAPLANE_MAX_PORTS] __hot_data;

/* Port allocations */
static struct port_alloc {
	uint64_t		 dev_flags;			/*   0  8 */
	uint32_t		 buf_size;			/*   8  4 */
	uint16_t		 rx_desc;			/*  12  2 */
	uint16_t		 tx_desc;			/*  14  2 */
	uint32_t		 buffers;			/*  16  4 */
	uint8_t			 rx_queues;			/*  20  1 */
	uint8_t			 tx_queues;			/*  20  1 */
	int8_t			 socketid;			/*  22  1 */
	bool			 uses_queue_state;		/*  23  1 */
	bitmask_t		 rx_cpu_affinity;		/*  24 16 */
	bitmask_t		 tx_cpu_affinity;		/*  40 16 */
	struct rte_eth_txconf    tx_conf;			/*  56 56 */
	/* --- cacheline 1 boundary (64 bytes) was 48 bytes ago --- */
	struct rte_eth_rxconf    rx_conf;			/* 112 48 */
	/* --- cacheline 2 boundary (128 bytes) was 32 bytes ago --- */
	enum rte_eth_rx_mq_mode  rx_mq_mode;			/* 160  4 */

	/* XXX 4 bytes hole, try to packet */

	struct rte_mempool	*rx_pool;			/* 168  8 */

	/* size: 176, cachelines: 3, members: 15 */
	/* sum members: 172, holes: 1, sum holes: 4 */
	/* last cacheline: 48 bytes */
} port_allocations[DATAPLANE_MAX_PORTS];

/* Per socket mbuf pool */
static struct rte_mempool *numa_pool[RTE_MAX_NUMA_NODES];

/* Single CPU forwarding thread */
static pthread_t single_forward_thread;

/* DPDK owner for ports */
struct rte_eth_dev_owner owner = { .id = RTE_ETH_DEV_NO_OWNER };

/* Program name for log and usage message */
char *progname;

/* Command line flags */

volatile bool running = true;
uid_t dataplane_uid;
gid_t dataplane_gid;

bitmask_t enabled_port_mask;		/* port is valid */
bitmask_t poll_port_mask;		/* should be polled */
/* port should be polled and is link up */
bitmask_t active_port_mask __hot_data;

uint16_t nb_ports_total;		/* highest DPDK portid + 1 */

static bool daemon_mode;		/* become daemon */
static unsigned int avail_cores;		/* number of forwarding cores */
bool single_cpu;			/* is dataplane running on uP */
static const char *pid_file;		/* record pid of main thread */
static const char *drv_cfg_file =
	VYATTA_DATA_DIR"/dataplane-drivers-default.conf";
static const char *drv_override_cfg_file =
	VYATTA_SYSCONF_DIR"/dataplane-drivers.conf";

static pthread_t main_pthread;

/* Modified version of DPDK routine which accounts for case of uP. */
#define FOREACH_FORWARD_LCORE(i) \
	for ((i) = rte_get_next_lcore(-1, !single_cpu, 0);	\
	     (i) < RTE_MAX_LCORE;				\
	     (i) = rte_get_next_lcore((i), !single_cpu, 0))

/*
 * Default Ethernet configuration
 * Modified as needed to support different MTU
 *
 * We may need to transmit a jumbo frame, or prepend to a
 * cloned packet and both of these require multiple segment
 * support for TX, so request it.
 */
static const struct rte_eth_conf eth_base_conf = {
	.rxmode = {
		.mq_mode	= ETH_MQ_RX_RSS,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.split_hdr_size = 0,
	},
	.txmode = {
		.offloads	= DEV_TX_OFFLOAD_MULTI_SEGS |
				  DEV_TX_OFFLOAD_VLAN_INSERT,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
		},
	},
};

/* Physical port information */
struct ifnet *ifport_table[DATAPLANE_MAX_PORTS] __hot_data;

void if_enable_poll(int port_id)
{
	bitmask_set(&poll_port_mask, port_id);
	bitmask_and(&active_port_mask, &poll_port_mask, &linkup_port_mask);
}

void if_disable_poll(portid_t port_id)
{
	bitmask_clear(&poll_port_mask, port_id);
	bitmask_and(&active_port_mask, &poll_port_mask, &linkup_port_mask);
}

/* Software vlan encapsulation for devices that require it */
static void pkt_transmit_vid(struct rte_mbuf **tx_pkts, unsigned int n,
			     uint16_t tpid)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (!(tx_pkts[i]->ol_flags & PKT_TX_VLAN_PKT))
			continue;

		vid_encap(pktmbuf_get_txvlanid(tx_pkts[i]),
			  &tx_pkts[i], tpid);
		tx_pkts[i]->ol_flags &= ~PKT_TX_VLAN_PKT;
	}
}

/*
 * Ethernet TX features to be run after QoS scheduling
 *
 * Called as part of emptying burst buffer, so these features must not
 * generate any dataplane packets in their processing.
 */
static inline void
eth_tx_run_post_qos_features(struct ifnet *ifp,
			     struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	if (unlikely(!ifp->tpid_offloaded))
		pkt_transmit_vid(tx_pkts, nb_pkts, if_tpid(ifp));

	if (unlikely(ifp->capturing))
		capture_burst(ifp, tx_pkts, nb_pkts);
}

/* Xmit burst with capture if required. */
static inline uint16_t
eth_tx_burst(struct ifnet *ifp, uint16_t queue_id,
	     struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	eth_tx_run_post_qos_features(ifp, tx_pkts, nb_pkts);
	return rte_eth_tx_burst(ifp->if_port, queue_id, tx_pkts, nb_pkts);
}

/* Used to send burst of packets when only one queue available.
 * Since multiple pthreads run on main core, need a mutex.
 */
static int
main_eth_tx(struct ifnet *ifp, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	int ret;
	static pthread_mutex_t main_tx_lock = PTHREAD_MUTEX_INITIALIZER;

	eth_tx_run_post_qos_features(ifp, tx_pkts, nb_pkts);

	pthread_mutex_lock(&main_tx_lock);
	ret = rte_eth_tx_burst(ifp->if_port, 0, tx_pkts, nb_pkts);
	pthread_mutex_unlock(&main_tx_lock);

	return ret;
}

/* Is it possible to go direct to device by using multiple queues
 * or do we need to use a transmit thread to process packets.
 */
static inline
bool __use_directpath(portid_t portid, bool qos_enabled)
{
	return CMM_ACCESS_ONCE(port_config[portid].percoreq) && !qos_enabled;
}

static inline
bool use_directpath(portid_t portid)
{
	return __use_directpath(portid, ifport_table[portid]->qos_software_fwd);
}

static inline bool forwarding_lcore(const struct lcore_conf *conf)
{
	return !bitmask_isempty(&conf->portmask);
}

static inline
bool forwarding_or_crypto_engine_lcore(const struct lcore_conf *conf)
{
	return conf->do_crypto || forwarding_lcore(conf);
}

/* Free any packets left in the rings or bursts */
void pkt_ring_empty(portid_t port)
{
	struct rte_ring *ring;
	struct rte_mbuf *m;
	unsigned int lcore;
	uint8_t r;

	for (r = 0; r < port_config[port].max_rings; r++) {
		ring = port_config[port].pkt_ring[r];

		while (rte_ring_sc_dequeue(ring, (void **)&m) == 0)
			rte_pktmbuf_free(m);
	}

	FOREACH_FORWARD_LCORE(lcore) {
		struct lcore_conf *conf = lcore_conf[lcore];
		unsigned int i;

		for (i = 0; i < MAX_TX_QUEUE_PER_CORE; i++) {
			struct lcore_tx_queue *txq = &conf->tx_poll[i];

			/* If port is down then flush pkts */
			if (txq->portid == NO_OWNER && txq->pending) {
				pktmbuf_free_bulk(txq->burst, txq->pending);
				txq->pending = 0;
			}
		}
	}
}

static void pkt_burst_init(unsigned int lcore_id, uint16_t qid)
{
	struct pkt_burst *pb;

	pb = rte_zmalloc_socket("pkt_burst", sizeof(struct pkt_burst),
				RTE_CACHE_LINE_SIZE,
				rte_lcore_to_socket_id(lcore_id));
	if (pb == NULL)
		rte_panic("no memory for lcore %u pkt_burst\n", lcore_id);

	pb->queue = qid;
	RTE_PER_LCORE(pkt_burst) = pb;
}


void dp_pkt_burst_free(void)
{
	unsigned int lcore_id = rte_lcore_id();

	if (!single_cpu &&
	    (lcore_id == rte_get_master_lcore() || lcore_id == LCORE_ID_ANY))
		return;

	rte_free(RTE_PER_LCORE(pkt_burst));
}

void dp_pkt_burst_setup(void)
{
	unsigned int lcore_id = rte_lcore_id();

	if (lcore_id == rte_get_master_lcore() || lcore_id == LCORE_ID_ANY)
		return;

	pkt_burst_init(lcore_id, lcore_conf[lcore_id]->tx_qid);
}

static ALWAYS_INLINE uint16_t
pkt_out_burst_cmn(struct ifnet *ifp, bool qos_enabled, uint16_t port,
		  uint16_t queue, struct rte_mbuf **mbufs, uint16_t nb_pkts)
{
	uint16_t n;

	if (__use_directpath(port, qos_enabled))
		n = eth_tx_burst(ifp, queue, mbufs, nb_pkts);
	else {
		uint8_t rid;

		if (qos_enabled)
			rid = 0;	/* always use ringid 0 for QoS */
		else
			rid = queue % CMM_ACCESS_ONCE(
				port_config[port].nrings);

		n = rte_ring_mp_enqueue_burst(
					port_config[port].pkt_ring[rid],
					(void **) mbufs, nb_pkts,
					NULL);
	}
	return n;
}

/* Move packets out of per-cpu burst buffer.
 * If devices is using percoreq mode then go direct to device
 * otherwise queue into packet ring for Tx thread.
 */
static __hot_func void
pkt_ring_burst(struct pkt_burst *pb, bool drain)
{
	struct ifnet *ifp = ifport_table[pb->port];
	bool qos_enabled = ifp->qos_software_fwd;
	uint32_t n;

	n = pkt_out_burst_cmn(ifp, qos_enabled, pb->port, pb->queue,
			      pb->m_tbl, pb->count);

	if (n < pb->count) {
		if (n == 0 || drain) {
			/* The transmit queue is full or some packets could
			 * not be sent (or placed in tx ring) and we are
			 * changing ports and need to drain the burst queue.
			 * Drop the packets (and update counter).
			 */
			unsigned int drop = pb->count - n;
			struct ifnet *ifp = ifnet_byport(pb->port);

			pktmbuf_free_bulk(&pb->m_tbl[n], drop);
			if (ifp) {
				if (__use_directpath(pb->port, qos_enabled))
					if_incr_full_hwq(ifp, drop);
				else
					if_incr_full_txring(ifp, drop);
			}
			goto out;
		}

		/* If some packets remain, shuffle to front of the queue */
		unsigned int unsent = pb->count - n;
		memmove(pb->m_tbl,
			pb->m_tbl + n,
			unsent * sizeof(struct rte_mbuf *));
		pb->count = unsent;
		return;
	}
out:
	pb->count = 0;
}

static __hot_func void pkt_ring_drain(void)
{
	struct crypto_pkt_buffer *cpb = RTE_PER_LCORE(crypto_pkt_buffer);
	struct pkt_burst *pb = RTE_PER_LCORE(pkt_burst);

	if (pb->count > 0)
		pkt_ring_burst(pb, true);
	crypto_send(cpb);
}

ALWAYS_INLINE __hot_func
void pkt_ring_output(struct ifnet *ifp, struct rte_mbuf *m)
{
	portid_t portid = ifp->if_port;
	struct pkt_burst *pb = RTE_PER_LCORE(pkt_burst);

	/*
	 * Check poll mask also for non-directpath case since although
	 * the mask just means not to use the DPDK port, it makes
	 * things simpler and at any reasonable packet rate the TX
	 * ring will just fill up and overflow anyway.
	 */
	if (unlikely(!bitmask_isset(&active_port_mask, portid))) {
		/*
		 * Account drop against appropriate queue as if the
		 * link down detection was not detected at this point
		 * then this could equally happen due to the hardware
		 * TX queue filling up (and resulting in backpressure
		 * for non-directpath case).
		 */
		if (__use_directpath(portid, ifp->qos_software_fwd))
			goto full_hwq;
		else
			goto full_txring;
	}

	if (likely(pb != NULL)) {
		if (unlikely(ifp->portmonitor) &&
		    __use_directpath(portid, ifp->qos_software_fwd))
			portmonitor_src_phy_tx_output(ifp, &m, 1);

		/* If changing flows to another port */
		if (unlikely(portid != pb->port)) {
			if (pb->count > 0)
				pkt_ring_burst(pb, true);
			pb->port = portid;
		}

		pb->m_tbl[pb->count++] = m;

		/* if burst is ready, send now */
		if (pb->count == TX_PKT_BURST)
			pkt_ring_burst(pb, false);
	} else {
		if (__use_directpath(portid, ifp->qos_software_fwd)) {
			if (unlikely(ifp->portmonitor))
				portmonitor_src_phy_tx_output(ifp, &m, 1);

			if (!main_eth_tx(ifp, &m, 1))
				goto full_hwq;
		} else {
			/* must be lcore 0 */
			struct rte_ring *ring = port_config[portid].pkt_ring[0];

			if (rte_ring_mp_enqueue(ring, m) != 0)
				goto full_txring;
		}
	}

	return;

full_txring: __cold_label;
	if_incr_full_txring(ifp, 1);
	rte_pktmbuf_free(m);
	return;

full_hwq: __cold_label;
	if_incr_full_hwq(ifp, 1);
	rte_pktmbuf_free(m);
}

void dp_pkt_burst_flush(void)
{
	unsigned int lcore_id = rte_lcore_id();

	if (lcore_id == rte_get_master_lcore() || lcore_id == LCORE_ID_ANY)
		return;

	struct pkt_burst *pb = RTE_PER_LCORE(pkt_burst);

	if (pb->count > 0)
		pkt_ring_burst(pb, true);
}

static __hot_func void
process_burst(portid_t portid, struct rte_mbuf *pkts[], uint16_t nb)
{
	struct ifnet *ifp = ifport_table[portid];
	packet_input_t input_func = packet_input_func;
	unsigned int i;

	/* Prefetch first packets */
	for (i = 0; i < PREFETCH_OFFSET && i < nb; i++) {
		rte_prefetch0(pkts[i]->cacheline1);
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
	}

	/* local packet capture */
	if (unlikely(ifp->capturing))
		capture_burst(ifp, pkts, nb);

	/* Mirror packets from physical interface */
	if (unlikely(ifp->portmonitor))
		portmonitor_src_phy_rx_output(ifp, pkts, nb);

	/* Process already prefetched packets */
	for (i = 0; i + PREFETCH_OFFSET < nb; i++) {
		rte_prefetch0(pkts[i + PREFETCH_OFFSET]->cacheline1);
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i + PREFETCH_OFFSET],
					       void *));
		pktmbuf_mdata_clear_all(pkts[i]);
		input_func(ifp, pkts[i]);
	}

	/* Process remaining packets */
	for (; i < nb; i++) {
		pktmbuf_mdata_clear_all(pkts[i]);
		input_func(ifp, pkts[i]);
	}
}

/*
 * Determine the next state for the lcore
 *
 * Possible next states:
 * 1. There is no work assigned to the core (no work to do and it
 *    isn't due to ports just being inactive) -> exit state
 * 2. This is no work to do and all the assigned ports are down ->
 *    idle state (lcore may sleep for long periods, but must wake up
 *    periodically)
 * 3. Work out the minimum sleep time based on heuristics of how much
 *    work was done for each work item recently. If less than power
 *    policy minimum sleep time -> poll
 * 4. Otherwise -> powernap for the specified time.
 */
static __hot_func enum lcore_state
lcore_next_state(struct lcore_conf *conf,
		 const struct power_profile *pm,
		 unsigned int *nap_us)
{
	unsigned int i;
	uint32_t us, min_us = USLEEP_MAX;
	bool inactive_port_linkup = false;
	bool inactive_port_exists = false;
	bool work_to_do = false;
	uint16_t high_txq;
	uint16_t high_rxq;

	if (CMM_LOAD_SHARED(conf->do_crypto)) {
		min_us = pm_interval(pm, &conf->crypt.gov);
		work_to_do = true;
	}

	high_txq = CMM_LOAD_SHARED(conf->high_txq);
	for (i = 0; i < high_txq; i++) {
		struct lcore_tx_queue *txq = &conf->tx_poll[i];
		portid_t portid = CMM_LOAD_SHARED(txq->portid);

		if (unlikely(portid == NO_OWNER))
			continue;

		if (unlikely(!bitmask_isset(&active_port_mask, portid))) {
			inactive_port_exists = true;
			if (bitmask_isset(&linkup_port_mask, portid))
				inactive_port_linkup = true;
			continue;
		}

		us = pm_interval(pm, &txq->gov);
		if (us < min_us)
			min_us = us;
		work_to_do = true;
	}

	high_rxq = CMM_LOAD_SHARED(conf->high_rxq);
	for (i = 0; i < high_rxq; i++) {
		struct lcore_rx_queue *rxq = &conf->rx_poll[i];
		portid_t portid = CMM_LOAD_SHARED(rxq->portid);

		if (unlikely(portid == NO_OWNER))
			continue;

		if (unlikely(!bitmask_isset(&active_port_mask, portid))) {
			inactive_port_exists = true;
			if (bitmask_isset(&linkup_port_mask, portid))
				inactive_port_linkup = true;
			continue;
		}

		us = pm_interval(pm, &rxq->gov);
		if (us < min_us)
			min_us = us;
		work_to_do = true;
	}

	if (unlikely(!work_to_do)) {
		/* no ports assigned */
		if (!inactive_port_exists)
			return LCORE_STATE_EXIT;
		/* all assigned ports are down */
		if (!inactive_port_linkup)
			return LCORE_STATE_IDLE;
	}
	if (min_us < pm->min_sleep)
		return LCORE_STATE_POLL;
	*nap_us = min_us;
	return LCORE_STATE_POWERSAVE;
}

/* Check for packets from network ports */
static void __hot_func
poll_receive_queues(struct lcore_conf *conf)
{
	struct crypto_pkt_buffer *cpb = RTE_PER_LCORE(crypto_pkt_buffer);
	uint16_t high_rxq;
	unsigned int i;

	high_rxq = CMM_LOAD_SHARED(conf->high_rxq);
	for (i = 0; i < high_rxq; i++) {
		struct lcore_rx_queue *rxq = &conf->rx_poll[i];
		struct rte_mbuf *rx_pkts[RX_PKT_BURST];
		portid_t portid;
		uint16_t nb;

		portid = CMM_LOAD_SHARED(rxq->portid);

		/* port unused or not up yet? */
		if (unlikely(portid == NO_OWNER) ||
		    unlikely(!bitmask_isset(&active_port_mask, portid)))
			continue;

		/* read queueid after reading portid */
		cmm_smp_rmb();

		/* Check for packets from network */
		nb = rte_eth_rx_burst(portid, rxq->queueid,
				      rx_pkts, RX_PKT_BURST);

		pm_update(&rxq->gov, nb);

		if (nb > 0) {
			rxq->packets += nb;
			process_burst(portid, rx_pkts, nb);
			crypto_send(cpb);
		}
	}
}

/* Move packets from txq->burst array to hardware.
 * Only used when doing QoS or device only supports a single Tx queue,
 * otherwise the transmit thread can be bypassed entirely.
 *
 * If device is multi-queue then use per-cpu tx queue
 * to avoid race when transitioning in/out of multi-queue mode.
 */
static void put_transmit(struct ifnet *ifp, uint16_t queue_id,
			 struct lcore_tx_queue *txq)
{
	unsigned int sent;

	sent = eth_tx_burst(ifp, queue_id, txq->burst, txq->pending);
	if (unlikely(sent == 0))
		return;		/* Device Tx queue full */

	/* if some packet remain, shuffle to front of the queue */
	if (unlikely(sent < txq->pending)) {
		unsigned int unsent = txq->pending - sent;
		memmove(txq->burst,
			txq->burst + sent,
			unsent * sizeof(struct rte_mbuf *));
	}

	txq->pending -= sent;
	txq->packets += sent;
}

/*
 * If QoS is enabled, then always pull full chunk of packets
 * off of transmit ring (64) and then look for smaller
 * burst of packets (up to 32) that are ready to send
 * and put them in transmit queue staging buffer.
 *
 * Per Intel developer should always dequeue in smaller chunks
 * than enqueued.
 */
static unsigned int pkt_transmit_qos(struct ifnet *ifp,
				 struct sched_info *qinfo,
				 struct lcore_tx_queue *txq,
				 portid_t portid,
				 unsigned int space)
{
	struct rte_ring *ring = port_config[portid].pkt_ring[txq->ringid];
	struct rte_mbuf *q_pkts[QOS_PKT_BURST];
	unsigned int n;

	n = rte_ring_sc_dequeue_burst(ring, (void **) q_pkts,
				      QOS_PKT_BURST, NULL);

	pm_update(&txq->gov, n);

	struct rte_mbuf **tx_pkts = txq->burst + txq->pending;
	return qos_sched(ifp, qinfo, q_pkts, n, tx_pkts, space);
}

/* Fast path, Qos not enabled.
 * Dequeue packets direct from packet ring into transmit staging buffer.
 */
static unsigned int pkt_transmit_direct(struct lcore_tx_queue *txq,
				    portid_t portid,
				    unsigned int space)
{
	struct rte_ring *ring = port_config[portid].pkt_ring[txq->ringid];

	if (unlikely(space == 0))
		return 0;

	struct rte_mbuf **pkts = txq->burst + txq->pending;
	return rte_ring_sc_dequeue_burst(ring, (void **) pkts,
					 space, NULL);
}

/* Get some packets from inter-thread packet ring
 * and put them in the per-queue burst buffer.
 */
static void __hot_func
poll_transmit_queues(struct lcore_conf *conf)
{
	unsigned int i, added;
	uint16_t high_txq;

	high_txq = CMM_LOAD_SHARED(conf->high_txq);
	for (i = 0; i < high_txq; i++) {
		struct lcore_tx_queue *txq = &conf->tx_poll[i];
		struct ifnet *ifp;
		portid_t portid;

		portid = CMM_LOAD_SHARED(txq->portid);
		ifp = ifnet_byport(portid);

		/* port unused or not up yet? */
		if (unlikely(ifp == NULL) ||
		    unlikely(!bitmask_isset(&active_port_mask, portid)))
			continue;

		/* read queueid and other txq fields after reading portid */
		cmm_smp_rmb();

		/* prefetch the Tx queue state */
		struct rte_eth_dev *dev = &rte_eth_devices[portid];
		rte_prefetch0(dev->data->tx_queues[txq->queueid]);

		unsigned int space = TX_PKT_BURST - txq->pending;

		struct sched_info *qinfo = qos_handle(ifp);
		if (qinfo && txq->ringid == 0) /* QoS only uses ringid 0 */
			added = pkt_transmit_qos(ifp, qinfo, txq, portid,
						 space);
		else
			added = pkt_transmit_direct(txq, portid, space);

		if (added > 0) {
			struct rte_mbuf **tx_pkts = txq->burst + txq->pending;

			if (unlikely(ifp->portmonitor))
				portmonitor_src_phy_tx_output(ifp,
							      tx_pkts, added);
		}

		pm_update(&txq->gov, added);
		txq->pending += added;

		if (txq->pending > 0 || txq->tx_no_pkts)
			put_transmit(ifp, txq->queueid, txq);
	}
}

static void process_crypto(struct lcore_conf *conf)
{
	struct lcore_crypt *cpq = &conf->crypt;
	unsigned int pkts = dp_crypto_poll(&conf->crypt.pmd_list);

	cpq->packets += pkts;
	pm_update(&cpq->gov, pkts);
}

/* main processing loop */
static int __hot_func
forwarding_loop(unsigned int lcore_id)
{
	unsigned int i, us;
	const struct power_profile *pm;
	struct lcore_conf *conf = lcore_conf[lcore_id];
	enum lcore_state state;

	RTE_PER_LCORE(_dp_lcore_id) = lcore_id;
	dp_lcore_events_init(lcore_id);

	crypto_create_fwd_queue(lcore_id);

	pkt_burst_init(lcore_id, conf->tx_qid);

	char name[16];
	snprintf(name, sizeof(name), "dataplane/%u", lcore_id);
	pthread_setname_np(pthread_self(), name);

	DP_DEBUG(INIT, DEBUG, DATAPLANE,
		 "forwarding %sstarted on core %u\n",
		 conf->do_crypto ? "and crypto " : "", lcore_id);

	/* Each thread containing read-side critical sections must be registered
	 * with rcu_register_thread() before calling rcu_read_lock().
	 */
	dp_rcu_register_thread();
	do {
		rcu_read_lock();

		pm = get_current_pm();
		for (i = 0; i < pm->idle_thresh ; i++) {
			if (CMM_LOAD_SHARED(conf->num_rxq) > 0)
				poll_receive_queues(conf);
			if (CMM_LOAD_SHARED(conf->do_crypto))
				process_crypto(conf);
			if (CMM_LOAD_SHARED(conf->num_txq) > 0)
				poll_transmit_queues(conf);
			if (CMM_LOAD_SHARED(conf->crypto_fwd))
				crypto_fwd_processed_packets();
		}

		/* Move leftover packets */
		pkt_ring_drain();

		state = lcore_next_state(conf, pm, &us);

		rcu_read_unlock();

		switch (state) {
		case LCORE_STATE_EXIT:
			RTE_LOG(DEBUG, DATAPLANE, "terminating core %d\n",
				lcore_id);
			break;
		case LCORE_STATE_POLL:
			dp_rcu_quiescent_state(lcore_id);
			break;
		case LCORE_STATE_POWERSAVE:
			dp_rcu_quiescent_state(lcore_id);
			usleep(us);
			break;
		case LCORE_STATE_IDLE:
			dp_rcu_thread_offline();
			sleep(LCORE_IDLE_SLEEP_SECS);
			dp_rcu_thread_online();
			break;
		}
	} while (likely(state != LCORE_STATE_EXIT));
	dp_rcu_unregister_thread();

	dp_lcore_events_teardown(lcore_id);
	dp_pkt_burst_free();

	RTE_LOG(DEBUG, DATAPLANE,
		"stopped core %d\n", lcore_id);
	return 0;
}

/* Callback from DPDK remote launch
 * used to start forwarding thread in SMP
 */
int
launch_one_lcore(void *arg __unused)
{
	unsigned int lcore = rte_lcore_id();

	RTE_LOG(DEBUG, DATAPLANE,
		"start core %d\n", lcore);

	renice(-20);

	if (CMM_LOAD_SHARED(lcore_conf[lcore]->do_feature)) {
		RTE_PER_LCORE(_dp_lcore_id) = lcore;
		dp_lcore_events_init(lcore);

		lcore_conf[lcore]->feat.dp_lcore_feat_fn(lcore, NULL);

		dp_lcore_events_teardown(lcore);
	} else {
		forwarding_loop(lcore);
	}

	return 0;
}

/* Callback from pthread_create
 * used to start forwarding thread in uP
 */
static void *
forwarding_pthread(void *arg)
{
	forwarding_loop(rte_get_master_lcore());
	return arg;
}

/* Change queue configuration.  Should only be called if stopped. */
int reconfigure_queues(portid_t portid,
		       uint16_t nb_rx_queues, uint16_t nb_tx_queues)
{
	struct port_conf *port_conf = &port_config[portid];
	struct port_alloc *port_alloc = &port_allocations[portid];
	struct rte_eth_dev *eth_dev = &rte_eth_devices[portid];
	struct rte_eth_conf dev_conf;
	int ret;
	uint16_t q;

	/* The device may have changed its configuration since
	 * we last configured. This is typical for bonding which
	 * must use a subset of the capabilities of the members.
	 */
	memcpy(&dev_conf, &eth_dev->data->dev_conf, sizeof(dev_conf));

	ret = rte_eth_dev_configure(portid,
				    nb_rx_queues, nb_tx_queues, &dev_conf);
	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"port %u: reconfigure failed: %d (%s)\n",
			portid, ret, strerror(-ret));
		goto out;
	}

	port_alloc->rx_queues = nb_rx_queues;
	port_alloc->tx_queues = nb_tx_queues;
	bitmask_zero(&port_conf->tx_enabled_queues);
	bitmask_zero(&port_conf->rx_enabled_queues);
	for (q = 0; q < port_alloc->tx_queues; q++)
		bitmask_set(&port_conf->tx_enabled_queues, q);
	for (q = 0; q < port_alloc->rx_queues; q++)
		bitmask_set(&port_conf->rx_enabled_queues, q);

out:
	return ret;
}

int
eth_port_configure(portid_t portid, struct rte_eth_conf *dev_conf)
{
	struct port_alloc *port_alloc = &port_allocations[portid];
	uint16_t queueid;
	int ret;
	int8_t socketid;

	if (port_alloc->socketid == SOCKET_ID_ANY)
		socketid = 0;
	else
		socketid = port_alloc->socketid;

	DP_DEBUG(INIT, DEBUG, DATAPLANE,
		"Configure port %u (rxq %u, txq %u, socket %d)\n",
		 portid, port_alloc->rx_queues,
		 port_alloc->tx_queues, socketid);

	ret = rte_eth_dev_configure(portid, port_alloc->rx_queues,
				    port_alloc->tx_queues, dev_conf);
	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			 "Cannot configure device: err=%d, port=%u\n",
			 ret, portid);
		return -1;
	}

	for (queueid = 0; queueid < port_alloc->rx_queues; ++queueid) {
		ret = rte_eth_rx_queue_setup(portid, queueid,
					     port_alloc->rx_desc,
					     socketid, &port_alloc->rx_conf,
					     port_alloc->rx_pool);
		if (ret < 0) {
			RTE_LOG(ERR, DATAPLANE,
				 "rte_eth_rx_queue_setup: err=%d, port=%u\n",
				 ret, portid);
			return -1;
		}
	}

	for (queueid = 0; queueid < port_alloc->tx_queues; ++queueid) {
		ret = rte_eth_tx_queue_setup(portid, queueid,
					     port_alloc->tx_desc,
					     socketid, &port_alloc->tx_conf);
		if (ret < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"rte_eth_tx_queue_setup: err=%d, port=%u\n",
				ret, portid);
			return -1;
		}
	}

	return 0;
}

uint64_t get_link_modes(struct ifnet *ifp)
{
	struct rte_eth_dev *eth_dev;
	uint32_t link_speeds;
	uint64_t link_modes = 0;

	if (ifp->if_type != IFT_ETHER) {
		RTE_LOG(ERR, DATAPLANE,
			"%s: %s not valid local port\n",
			__func__, ifp->if_name);
		goto out;
	}

	eth_dev = &rte_eth_devices[ifp->if_port];
	link_speeds = eth_dev->data->dev_conf.link_speeds;

	if (link_speeds == ETH_LINK_SPEED_AUTONEG)
		link_modes |= ADVERTISED_Autoneg;
	else {
		if (link_speeds & ETH_LINK_SPEED_10M_HD)
			link_modes |= ADVERTISED_10baseT_Half;
		if (link_speeds & ETH_LINK_SPEED_10M)
			link_modes |= ADVERTISED_10baseT_Full;
		if (link_speeds & ETH_LINK_SPEED_100M_HD)
			link_modes |= ADVERTISED_100baseT_Half;
		if (link_speeds & ETH_LINK_SPEED_100M)
			link_modes |= ADVERTISED_100baseT_Full;
		if (link_speeds & ETH_LINK_SPEED_1G)
			link_modes |= ADVERTISED_1000baseT_Full;
		if (link_speeds & ETH_LINK_SPEED_10G)
			link_modes |= ADVERTISED_10000baseT_Full;
	}

out:
	return link_modes;
}

/* Shutdown all regular (not including backplane) DPDK ports */
static void close_all_regular_ports(void)
{
	unsigned int portid;

	for (portid = 0; portid < DATAPLANE_MAX_PORTS; ++portid) {
		if (bitmask_isset(&enabled_port_mask, portid) &&
		    rte_eth_dev_is_valid_port(portid) &&
		    !if_port_is_bkplane(portid))
			rte_eth_dev_close(portid);
	}
}

/* Shutdown all DPDK backplane ports */
static void close_all_backplane_ports(void)
{
	unsigned int portid;

	for (portid = 0; portid < DATAPLANE_MAX_PORTS; ++portid) {
		if (bitmask_isset(&enabled_port_mask, portid) &&
		    rte_eth_dev_is_valid_port(portid) &&
		    if_port_is_bkplane(portid))
			rte_eth_dev_close(portid);
	}
}

/* display usage */
static void
usage(int status) __attribute__((noreturn));
static void
usage(int status)
{
	printf("%s OPTIONS -- [EAL options]\n"
	       " OPTIONS:\n"
	       " -d, --daemon              Run in daemon mode.\n"
	       " -f, --file FILE           Use configuration file\n"
	       " -F, --feat_plugin_dir     Extra directory to check for feat plugins\n"
	       " -h, --help                Display this help and exit\n"
	       " -i, --pid_file FILE       Set process id file name\n"
	       " -p, --port_mask PORTMASK  Bitmask of ports to configure\n"
	       " -q, --queue N             Number of receivers threads per port (default 2)\n"
	       " -g, --group GROUP         Change group to GROUP\n"
	       " -u, --user USER           Change user to USER\n"
	       " -v, --version             Print program version\n"
	       " -C, --console ZMQPATH	   Alternate console endpoint\n"
	       " -D, --debug MASK          Debug log mask\n"
	       "     --list_cmd_versions   List all ops command versions\n"
	       "     --list_msg_versions   List all cfg command versions\n"
	       " -c, --config              use config file for driver state\n",
	       progname);

	exit(status);
}

/* We don't have short opts for these */
#define ARGS_LIST_CMDS 1000
#define ARGS_LIST_MSGS 1001

/* Parse the argument given in the command line of the application
 * This happens before EAL library so don't use RTE_LOG here
 */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	int option_index;
	struct passwd *pw;
	struct group *gr;
	bitmask_t pm;

	static const struct option lgopts[] = {
		{ "help",     no_argument,       NULL, 'h' },
		{ "version",  no_argument,       NULL, 'v' },
		{ "pid_file", required_argument, NULL, 'i' },
		{ "port_mask", required_argument, NULL, 'p' },
		{ "daemon",   no_argument,	 NULL, 'd' },
		{ "file",     required_argument, NULL, 'f' },
		{ "feat_plugin_dir", required_argument, NULL, 'F' },
		{ "user",     required_argument, NULL, 'u' },
		{ "group",    required_argument, NULL, 'g' },
		{ "debug",    required_argument, NULL, 'D' },
		{ "console",  required_argument, NULL, 'C' },
		{ "config",   required_argument, NULL, 'c' },
		{ "platform_file ", required_argument, NULL, 'P' },
		{ "list_cmd_versions", no_argument, NULL, ARGS_LIST_CMDS },
		{ "list_msg_versions", no_argument, NULL, ARGS_LIST_MSGS },
		{ NULL, 0, NULL, 0}
	};

	while ((opt = getopt_long(argc, argv, "hvdi:p:u:g:o:f:c:N:D:C:sF:P:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		case 'd':
			daemon_mode = true;
			break;

		case 'p': /* portmask */
			ret = bitmask_parse(&pm, optarg);
			if (ret < 0) {
				fprintf(stderr, "invalid portmask '%s'\n",
					optarg);
				usage(1);
			}
			enabled_port_mask = pm;
			break;

		case 'P':
			set_platform_cfg_file(optarg);
			break;

		case 'f':
			set_config_file(optarg);
			break;

		case 'F':
			set_feat_plugin_dir(optarg);
			break;

		case 'c':
			drv_override_cfg_file = optarg;
			drv_cfg_file = optarg;
			break;

		case 'i':
			pid_file = optarg;
			break;

		case 'u':	/* set user to run as after initialization */
			pw = getpwnam(optarg);
			if (!pw) {
				fprintf(stderr, "unknown user '%s'\n", optarg);
				exit(1);
			}
			dataplane_uid = pw->pw_uid;
			break;

		case 'g':	/* set group to use */
			gr = getgrnam(optarg);
			if (!gr) {
				fprintf(stderr, "unknown group '%s'\n", optarg);
				exit(1);
			}
			dataplane_gid = gr->gr_gid;
			break;

		case 'v':
			printf("%s version %s\n",
			       DATAPLANE_PROGNAME, DATAPLANE_VERSION);
			exit(0);

		case 'h':
			usage(0);
			break;

		/* Debug options */
		case 'C':
			console_endpoint_set(optarg);
			break;

		case 'D':
			dp_debug = strtoul(optarg, NULL, 0);
			dp_debug_init = dp_debug;
			break;

		case ARGS_LIST_CMDS:
			list_all_cmd_versions(stdout);
			exit(0);
			break;

		case ARGS_LIST_MSGS:
			list_all_main_msg_versions(stdout);
			exit(0);
			break;

		default:
			fprintf(stderr, "Unknown option %c\n", opt);
			usage(1);
			break;
		}
	}

	ret = optind-1;
	optind = 0; /* reset getopt lib */

	return ret;
}

static void init_rate_stats(struct rate_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	gettimeofday(&stats->last_time, NULL);
}

void scale_rate_stats(struct rate_stats *stats, const uint64_t *packets,
		      const uint64_t *bytes)
{
	struct timeval now, diff;
	uint64_t scaled;
	uint64_t time_diff_usec;

	gettimeofday(&now, NULL);
	timersub(&now, &stats->last_time, &diff);
	stats->last_time = now;

	time_diff_usec = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
	if (time_diff_usec == 0)
		time_diff_usec = 1;

	/* scale the packts to reflect 1 second */
	scaled = *packets - stats->last_packets;
	scaled = (scaled  * USEC_PER_SEC) / time_diff_usec;
	stats->packet_rate = scaled;
	stats->last_packets = *packets;

	if (bytes) {
		scaled = *bytes - stats->last_bytes;
		scaled = (scaled  * USEC_PER_SEC) / time_diff_usec;
		stats->byte_rate = scaled;
		stats->last_bytes = *bytes;
	}
}

static void stop_one_cpu(unsigned int lcore)
{
	struct lcore_conf *conf = lcore_conf[lcore];

	if (!conf->running)
		return;

	if (lcore == rte_get_master_lcore()) {
		int ret;

		if (!single_cpu) {
			RTE_LOG(ERR, DATAPLANE,
				"attempt to stop forwarding thread for main core in non-single-cpu case\n");
			return;
		}

		ret = pthread_join(single_forward_thread, NULL);
		if (ret != 0) {
			RTE_LOG(ERR, DATAPLANE,
				"forwarding pthread join failed: %s\n",
				strerror(ret));
		}
	} else {
		if (rte_eal_wait_lcore(lcore) < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"core %d wait failed\n", lcore);
		}

		crypto_destroy_fwd_queue();
	}
	conf->running = false;
}

static void stop_cpus(void)
{
	unsigned int lcore;
	bool any_stopped = false;

	FOREACH_FORWARD_LCORE(lcore) {
		const struct lcore_conf *conf = lcore_conf[lcore];

		if (forwarding_or_crypto_engine_lcore(conf) ||
		    !conf->running || conf->ded_to_feature)
			continue;

		stop_one_cpu(lcore);
		any_stopped = true;
	}
	if (any_stopped)
		register_forwarding_cores();
}

static void unassign_port_transmit_queues(portid_t portid,
					  struct lcore_conf *conf)
{
	unsigned int i;
	bool have_rxq = false;

	for (i = 0; i < MAX_TX_QUEUE_PER_CORE; i++) {
		struct lcore_tx_queue *txq = &conf->tx_poll[i];

		if (portid != txq->portid)
			continue;

		_CMM_STORE_SHARED(txq->portid, NO_OWNER);
		CMM_STORE_SHARED(conf->num_txq, conf->num_txq - 1);
	}

	for (i = 0; i < MAX_RX_QUEUE_PER_CORE; i++) {
		const struct lcore_rx_queue *rxq = &conf->rx_poll[i];

		if (portid == rxq->portid) {
			have_rxq = true;
			break;
		}
	}

	if (!have_rxq)
		bitmask_clear(&conf->portmask, portid);
}

static void unassign_port_receive_queues(portid_t portid,
					 struct lcore_conf *conf)
{
	unsigned int i;
	bool have_txq = false;

	for (i = 0; i < MAX_RX_QUEUE_PER_CORE; i++) {
		struct lcore_rx_queue *rxq = &conf->rx_poll[i];

		if (portid != rxq->portid)
			continue;

		_CMM_STORE_SHARED(rxq->portid, NO_OWNER);
		CMM_STORE_SHARED(conf->num_rxq, conf->num_rxq - 1);
	}

	for (i = 0; i < MAX_TX_QUEUE_PER_CORE; i++) {
		const struct lcore_tx_queue *txq = &conf->tx_poll[i];

		if (portid == txq->portid) {
			have_txq = true;
			break;
		}
	}

	if (!have_txq)
		bitmask_clear(&conf->portmask, portid);
}

void unassign_queues(portid_t portid)
{
	unsigned int lcore;

	FOREACH_FORWARD_LCORE(lcore) {
		struct lcore_conf *conf = lcore_conf[lcore];

		unassign_port_transmit_queues(portid, conf);
		unassign_port_receive_queues(portid, conf);
	}

	synchronize_rcu();
	pkt_ring_empty(portid);
	stop_cpus();
}

void enable_crypto_fwd(unsigned int lcore)
{
	struct lcore_conf *conf = lcore_conf[lcore];

	CMM_STORE_SHARED(conf->crypto_fwd, 1);
}

void disable_crypto_fwd(unsigned int lcore)
{
	struct lcore_conf *conf = lcore_conf[lcore];

	CMM_STORE_SHARED(conf->crypto_fwd, 0);
}

/* Compute load based on how much work CPU core is doing
 * Try and put Rx queue on primary HT and Tx on secondary HT
 * Use same NUMA socket if possible.
 */
#define HT_PENALTY 1
#define NUMA_PENALTY 10
#define CRYPTO_PENALTY 1

static unsigned int lcore_score(unsigned int lcore, int socket_id, bool is_txq)
{
	const struct lcore_conf *conf = lcore_conf[lcore];
	unsigned int score;

	score = conf->num_rxq + conf->num_txq +
		(CRYPTO_PENALTY * conf->do_crypto);
	if (socket_id != SOCKET_ID_ANY) {
		if (is_txq) {
			if (!secondary_cpu(lcore))
				score += HT_PENALTY;
		} else {
			if (secondary_cpu(lcore))
				score += HT_PENALTY;
		}

		if ((unsigned int)socket_id != rte_lcore_to_socket_id(lcore))
			score += NUMA_PENALTY;
	}

	return score;
}

/* Compute least loaded lcore in round-robin fashion */
static int next_available_lcore(int socket_id,
				const bitmask_t *allowed, bool is_txq)
{
	static int current_lcore = -1;
	unsigned int start, i, best_score = 0;
	int best = -1;

	i = start = rte_get_next_lcore(current_lcore, !single_cpu, 1);

	do {
		if (!bitmask_isset(allowed, i))
			continue;

		unsigned int weight = lcore_score(i, socket_id, is_txq);
		if (best < 0 || weight < best_score) {
			best = i;
			best_score = weight;
		}

	} while ((i = rte_get_next_lcore(i, !single_cpu, 1)) != start);

	current_lcore = start;	/* round robin */
	return best;
}

static bitmask_t online_lcores_mask(void)
{
	unsigned int lcore;
	bitmask_t online;

	memset(&online, 0, sizeof(online));

	FOREACH_FORWARD_LCORE(lcore) {
		if (lcore_conf[lcore]->ded_to_feature)
			continue;

		bitmask_set(&online, lcore);
	}

	return online;
}

/*
 * Ensures only online forwarding cores are in the mask returned.
 * Note that if there are none in the set, then all online cores
 * are returned in the mask.
 */
static bitmask_t cpu_affinity_online(const bitmask_t *cpu_affinity_mask)
{
	bitmask_t mask = online_lcores_mask();

	bitmask_and(&mask, cpu_affinity_mask, &mask);

	if (bitmask_isempty(&mask))
		mask = online_lcores_mask();

	return mask;
}

/* Assign all receive queues for a port */
static int assign_port_receive_queues(portid_t portid)
{
	struct port_conf *port_conf = &port_config[portid];
	struct port_alloc *port_alloc = &port_allocations[portid];
	unsigned int q;
	bitmask_t allowed = cpu_affinity_online(&port_alloc->rx_cpu_affinity);

	for (q = 0; q < port_alloc->rx_queues; q++) {
		struct lcore_conf *conf;
		int i, lcore;

		if (!bitmask_isset(&port_conf->rx_enabled_queues, q))
			continue;

		lcore = next_available_lcore(port_alloc->socketid,
					     &allowed,
					     false);
		if (lcore < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"no available lcore for rx port %u\n", portid);
			return -ENOENT;
		}
		conf = lcore_conf[lcore];

		/* find empty slot to use */
		for (i = 0; i < conf->high_rxq; i++) {
			if (conf->rx_poll[i].portid == NO_OWNER)
				goto found;
		}

		if (conf->high_rxq < MAX_RX_QUEUE_PER_CORE)
			_CMM_STORE_SHARED(conf->high_rxq, conf->high_rxq + 1);
		else {
			RTE_LOG(ERR, DATAPLANE,
				"Socket %d has no unused rx queues\n",
				port_alloc->socketid);
			return -ENOMEM;
		}
found:
		bitmask_clear(&allowed, lcore);
		if (bitmask_isempty(&allowed))
			allowed = cpu_affinity_online(		/* start over */
				&port_alloc->rx_cpu_affinity);
		_CMM_STORE_SHARED(conf->num_rxq, conf->num_rxq + 1);

		DP_DEBUG(INIT, DEBUG, DATAPLANE,
			 "Assign RX port %u queue %u to core %u (node %u)\n",
			 portid, q, lcore, port_alloc->socketid);

		struct lcore_rx_queue *rxq = &conf->rx_poll[i];
		struct rate_stats *rxq_stats = &conf->rx_poll_stats[i];

		init_rate_stats(rxq_stats);

		memset(&rxq->gov, 0, sizeof(rxq->gov));
		rxq->packets = 0;
		CMM_STORE_SHARED(rxq->queueid, q);
		/* write queueid before writing portid */
		cmm_smp_wmb();
		_CMM_STORE_SHARED(rxq->portid, portid);

		bitmask_set(&conf->portmask, portid);
	}

	return 0;
}

/* Assign lcores that will handle transmit queues (bottom half) */
static int assign_port_transmit_queues(portid_t portid)
{
	struct port_conf *port_conf = &port_config[portid];
	struct port_alloc *port_alloc = &port_allocations[portid];
	bitmask_t allowed = cpu_affinity_online(&port_alloc->tx_cpu_affinity);
	struct ifnet *ifp = ifport_table[portid];
	uint16_t q;
	uint8_t r;

	/*
	 * Assign TX rings to cores and TX queues to rings, handling
	 * gaps for not-enabled rings.
	 */
	for (r = 0, q = 0;
	     r < port_conf->nrings && q < port_alloc->tx_queues;
	     q++) {
		struct lcore_conf *conf;
		int i, lcore;

		if (!bitmask_isset(&port_conf->tx_enabled_queues, q))
			continue;

		lcore = next_available_lcore(port_alloc->socketid,
					     &allowed,
					     true);
		if (lcore < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"no available lcore for tx port %u\n", portid);
			return -ENOENT;
		}
		conf = lcore_conf[lcore];

		/* find empty slot to use */
		for (i = 0; i < conf->high_txq; i++) {
			if (conf->tx_poll[i].portid == NO_OWNER)
				goto found;
		}

		if (conf->high_txq < MAX_TX_QUEUE_PER_CORE)
			_CMM_STORE_SHARED(conf->high_txq, conf->high_txq + 1);
		else {
			RTE_LOG(ERR, DATAPLANE,
				"Socket %d has no unused tx queues\n",
				port_alloc->socketid);
			return -ENOMEM;
		}

found:
		bitmask_clear(&allowed, lcore);
		if (bitmask_isempty(&allowed))
			allowed = cpu_affinity_online(		/* start over */
				&port_alloc->tx_cpu_affinity);
		_CMM_STORE_SHARED(conf->num_txq, conf->num_txq + 1);

		struct lcore_tx_queue *txq = &conf->tx_poll[i];
		struct rate_stats *txq_stats = &conf->tx_poll_stats[i];

		init_rate_stats(txq_stats);

		memset(&txq->gov, 0, sizeof(txq->gov));
		/*
		 * Need to attempt transmit every poll as in 802.3AD
		 * mode must call driver with interval period of <
		 * 100ms
		 */
		txq->tx_no_pkts = ifp->if_team;
		txq->packets = 0;
		txq->ringid = r;
		r++;
		CMM_STORE_SHARED(txq->queueid, q);
		/* write queueid and other fields before writing portid */
		cmm_smp_wmb();
		_CMM_STORE_SHARED(txq->portid, portid);

		DP_DEBUG(INIT, DEBUG, DATAPLANE,
			 "Assign TX port %u queue %u to core %u (node %u)\n",
			 portid, q, lcore, port_alloc->socketid);

		bitmask_set(&conf->portmask, portid);
	}

	return 0;
}

static bool start_one_cpu(unsigned int lcore)
{
	struct lcore_conf *conf = lcore_conf[lcore];

	if (conf->running) {
		RTE_LOG(DEBUG, DATAPLANE,
			"core %d already running\n", lcore);
		return true;
	}
	if (lcore == rte_get_master_lcore()) {
		if (!single_cpu) {
			RTE_LOG(ERR, DATAPLANE,
				"attempt to create forwarding thread for main core in non-single-cpu case\n");
			return false;
		}

		if (pthread_create(&single_forward_thread, NULL,
				   forwarding_pthread, NULL) != 0) {
			RTE_LOG(ERR, DATAPLANE,
				"forwarding pthread create failed: %s\n",
				strerror(errno));
			return false;
		}
	} else {
		rte_eal_remote_launch(launch_one_lcore, NULL, lcore);
	}
	conf->running = true;

	return true;
}

/* Kick Cpu's that were completely idle and now have something to do. */
static void start_cpus(void)
{
	unsigned int lcore;
	bool any_started = false;

	FOREACH_FORWARD_LCORE(lcore) {
		const struct lcore_conf *conf = lcore_conf[lcore];

		if ((!forwarding_or_crypto_engine_lcore(conf) &&
		     !conf->ded_to_feature) || conf->running)
			continue;

		(void)start_one_cpu(lcore);
		any_started = true;
	}
	if (any_started)
		register_forwarding_cores();
}

/* Is a forwarding thread already assigned to poll for Tx on this port? */
static bool transmit_thread_running(portid_t portid)
{
	unsigned int lcore;

	FOREACH_FORWARD_LCORE(lcore) {
		const struct lcore_conf *conf = lcore_conf[lcore];
		unsigned int i;

		for (i = 0; i < conf->high_txq; i++)
			if (conf->tx_poll[i].portid == portid)
				return true;
	}

	return false;
}

/* Start queues for new port. */
int assign_queues(portid_t portid)
{
	int rc;

	rc = assign_port_receive_queues(portid);
	if (rc != 0)
		goto exit;

	if (!use_directpath(portid)) {
		if (transmit_thread_running(portid))
			goto startcpus;

		rc = assign_port_transmit_queues(portid);
		if (rc != 0) {
			unsigned int lcore;

			FOREACH_FORWARD_LCORE(lcore) {
				struct lcore_conf *conf = lcore_conf[lcore];
				unassign_port_receive_queues(portid, conf);
				synchronize_rcu();
				pkt_ring_empty(portid);
				stop_cpus();
			}
			goto exit;
		}
	}

startcpus:
	start_cpus();
exit:
	return rc;
}

/* Called from QoS when transmit needs to be activated. */
int enable_transmit_thread(portid_t portid)
{
	int ret;

	if (!dpdk_eth_if_port_started(portid))
		return -1;

	if (transmit_thread_running(portid))
		return 0;

	ret = assign_port_transmit_queues(portid);
	if (ret == 0)
		start_cpus();

	return ret;
}

/* Called from QoS when transmit needs can be deactivated. */
void disable_transmit_thread(portid_t portid)
{
	unsigned int lcore;

	/* Still need tx thread on single queue devices */
	if (!port_config[portid].percoreq)
		return;

	FOREACH_FORWARD_LCORE(lcore) {
		struct lcore_conf *conf = lcore_conf[lcore];

		unassign_port_transmit_queues(portid, conf);
	}

	synchronize_rcu();
	pkt_ring_empty(portid);
	stop_cpus();
}

bool port_uses_queue_state(uint16_t portid)
{
	struct port_alloc *port_alloc = &port_allocations[portid];
	struct rte_eth_dev *dev = &rte_eth_devices[portid];

	/*
	 * Only multiqueue-capable vhost interfaces generate
	 * RTE_ETH_EVENT_QUEUE_STATE events.
	 */

	return !strncmp(dev->data->name, "eth_vhost", 9) &&
		port_alloc->tx_queues > 1 && port_alloc->rx_queues > 1;
}

void set_port_uses_queue_state(uint16_t portid, bool val)
{
	struct port_alloc *port_alloc = &port_allocations[portid];

	CMM_STORE_SHARED(port_alloc->uses_queue_state, val);
}

bool get_port_uses_queue_state(uint16_t portid)
{
	struct port_alloc *port_alloc = &port_allocations[portid];

	return CMM_ACCESS_ONCE(port_alloc->uses_queue_state);
}

void reset_port_all_queue_state(uint16_t portid)
{
	struct port_conf *port_conf = &port_config[portid];

	bitmask_zero(&port_conf->tx_enabled_queues);
	bitmask_zero(&port_conf->rx_enabled_queues);
	_CMM_STORE_SHARED(port_conf->percoreq, false);
	CMM_STORE_SHARED(port_conf->nrings, 1);
}

void reset_port_enabled_queue_state(uint16_t portid)
{
	struct port_conf *port_conf = &port_config[portid];

	bitmask_zero(&port_conf->tx_enabled_queues);
	bitmask_zero(&port_conf->rx_enabled_queues);
}

void track_port_queue_state(uint16_t portid, uint16_t queue_id, bool rx,
			    bool enable)
{
	struct port_conf *port_conf = &port_config[portid];

	DP_DEBUG(INIT, DEBUG, DATAPLANE,
		 "CB Set %s queue %u for port %u %s\n",
		rx ? "RX" : "TX", queue_id, portid,
		 enable ? "enabled" : "disabled");

	if (queue_id >= BITMASK_BITS) {
		RTE_LOG(ERR, DATAPLANE,
			"Unexpectedly large %s queue id %u %s for port %u whilst setting queue state: max %u\n",
			rx ? "RX" : "TX", queue_id,
			enable ? "enabled" : "disabled", portid, BITMASK_BITS);
		return;
	}

	if (rx) {
		if (enable)
			bitmask_set(&port_conf->rx_enabled_queues, queue_id);
		else
			bitmask_clear(&port_conf->rx_enabled_queues, queue_id);
	} else {
		if (enable)
			bitmask_set(&port_conf->tx_enabled_queues, queue_id);
		else
			bitmask_clear(&port_conf->tx_enabled_queues, queue_id);
	}
}

/*
 * The set of queues to be enabled was set in the lsc interrupt
 * thread. Bring the running state into line with that.
 */
void set_port_queue_state(uint16_t portid)
{
	struct port_conf *port_conf = &port_config[portid];
	struct port_alloc *port_alloc = &port_allocations[portid];
	unsigned int lcore;
	bool percoreq = true;
	unsigned int q = 0;
	uint8_t nrings;
	bitmask_t temp_mask;

	bitmask_copy(&temp_mask, &port_conf->tx_enabled_queues);

	RTE_LCORE_FOREACH(lcore) {
		if (q >= port_alloc->tx_queues ||
		    !bitmask_isset(&temp_mask, q)) {
			percoreq = false;
			break;
		}
		q++;
	}
	if (percoreq) {
		nrings = 1;
	} else {
		nrings = bitmask_numset(&temp_mask);
		/*
		 * Ensure there is always at least one ring to
		 * avoid having to check for this case in the
		 * forwarding path.
		 */
		if (nrings == 0)
			nrings = 1;
	}
	_CMM_STORE_SHARED(port_conf->percoreq, percoreq);
	CMM_STORE_SHARED(port_conf->nrings, nrings);
}

/* Steal mbuf pool on an existing port (for use creating control packets) */
struct rte_mempool *mbuf_pool(unsigned int portid)
{
	const struct port_alloc *port_alloc = &port_allocations[portid];

	return port_alloc->rx_pool;
}

/* Create a standard mbuf pool */
struct rte_mempool *mbuf_pool_create(const char *name,
				     unsigned int n,
				     unsigned int cache_size,
				     unsigned long roomsz,
				     int socket_id)
{
	struct rte_mempool *mp;

	RTE_BUILD_BUG_ON(sizeof(struct pktmbuf_mdata) % RTE_MBUF_PRIV_ALIGN);

	mp = rte_pktmbuf_pool_create(name, n, cache_size,
				     sizeof(struct pktmbuf_mdata), roomsz,
				     socket_id);

	/* Try and reuse existing mbuf pool on restart */
	if (mp == NULL && rte_errno == EEXIST)
		mp = rte_mempool_lookup(name);

	return mp;
}

/* Initialize per socket mbuf pool. */
static uint16_t mbuf_pool_init(void)
{
	unsigned int bufs_per_socket[RTE_MAX_NUMA_NODES];
	unsigned int buf_size[RTE_MAX_NUMA_NODES] = {
		RTE_MBUF_DEFAULT_BUF_SIZE };
	unsigned int lcore, portid;
	int socketid;
	uint16_t max_mbuf_sz = RTE_MBUF_DEFAULT_BUF_SIZE;
	uint16_t num_fwd_lcores = 0;

	memset(bufs_per_socket, 0, sizeof(bufs_per_socket));

	/* How many mbufs are need for per-CPU data structures? */
	FOREACH_FORWARD_LCORE(lcore) {
		socketid = rte_lcore_to_socket_id(lcore);

		bufs_per_socket[socketid] += TX_PKT_BURST;
		buf_size[socketid] = RTE_MBUF_DEFAULT_BUF_SIZE;
		num_fwd_lcores++;
	}

	/* How many mbufs are needed for each device? */
	for (portid = 0; portid < nb_ports_total; ++portid) {
		const struct port_alloc *port_alloc = &port_allocations[portid];

		if (!bitmask_isset(&enabled_port_mask, portid) ||
		    !rte_eth_dev_is_valid_port(portid))
			continue;

		socketid = port_alloc->socketid;

		bufs_per_socket[socketid] +=
			port_alloc->buffers + SHADOW_IO_RING_SIZE;

		/* device may need larger buffer size */
		if (port_alloc->buf_size > buf_size[socketid]) {
			buf_size[socketid] = port_alloc->buf_size;
			if (max_mbuf_sz < port_alloc->buf_size)
				max_mbuf_sz = port_alloc->buf_size;
		}
	}

	/* Allocate mbuf pool per NUMA socket */
	for (socketid = 0; socketid < RTE_MAX_NUMA_NODES; ++socketid) {
		unsigned int bufsz = buf_size[socketid];

		if (bufs_per_socket[socketid] == 0)
			continue;

		bufs_per_socket[socketid] +=
			(num_fwd_lcores + 1) * NUMA_POOL_MBUF_CACHE_SIZE;

		/* account for buffers in ring for spathintf */
		bufs_per_socket[socketid] += SHADOW_IO_RING_SIZE;

		/* Align to optimum size for mempool */
		unsigned int nbufs = rte_align32pow2(bufs_per_socket[socketid]) - 1;

		char name[RTE_MEMPOOL_NAMESIZE];
		snprintf(name, RTE_MEMPOOL_NAMESIZE, "mbuf_node_%d",
			 socketid);

		struct rte_mempool *pool;
retry:
		pool = mbuf_pool_create(name, nbufs, NUMA_POOL_MBUF_CACHE_SIZE,
					bufsz, socketid);
		if (pool == NULL) {
			RTE_LOG(NOTICE, DATAPLANE,
				"Failed to create pool %s of %u mbufs size %uM in socket %d\n",
				name, nbufs, (bufsz * nbufs) / (1024*1024u),
				socketid);

			if (rte_errno != ENOMEM)
				rte_panic("mbuf  %s create failed: %s\n",
					  name, rte_strerror(rte_errno));

			if (nbufs <= MIN_MBUF_POOL)
				rte_panic("mbuf %s no space for %u bufs\n",
					  name, nbufs);

			nbufs /= 2;
			goto retry;
		}

		RTE_LOG(INFO, DATAPLANE,
			"Created %s mbuf pool size %u %uM in socket %d\n", name,
			nbufs,  (bufsz * nbufs) / (1024*1024u), socketid);

		numa_pool[socketid] = pool;
	}

	/* Assign mbuf pool for each device */
	for (portid = 0; portid < nb_ports_total; ++portid) {
		struct port_alloc *port_alloc = &port_allocations[portid];

		if (!bitmask_isset(&enabled_port_mask, portid))
			continue;
		port_alloc->rx_pool = numa_pool[port_alloc->socketid];
	}

	return max_mbuf_sz;
}

/* Initialize interface specific mbuf pool. */
int mbuf_pool_init_portid(const portid_t portid)
{
	struct port_alloc *port_alloc = &port_allocations[portid];

	/*
	 * mbuf pool can't be destroyed so may exist
	 * from previous use of this port.
	 */
	if (port_alloc->rx_pool == NULL) {
		unsigned int buf_size = RTE_MBUF_DEFAULT_BUF_SIZE;
		int socketid = port_alloc->socketid;

		if (port_alloc->buf_size > buf_size)
			buf_size = port_alloc->buf_size;

		/* Align to optimum size for mempool */
		unsigned int nbufs = rte_align32pow2(port_alloc->buffers) - 1;

		char name[RTE_MEMPOOL_NAMESIZE];

		snprintf(name, RTE_MEMPOOL_NAMESIZE, "mbuf_%u", portid);

		port_alloc->rx_pool = mbuf_pool_create(name, nbufs,
						      MBUF_CACHE_SIZE_DEFAULT,
						      buf_size, socketid);
		if (port_alloc->rx_pool == NULL) {
			RTE_LOG(ERR, DATAPLANE,
				"could not create pool %s with %u bufs\n",
				name, nbufs);
			return -1;
		}
	}

	return 0;
}

static const struct rxtx_param *
__get_driver_param(const char *driver_name)
{
	const struct rxtx_param *p = driver_param;

	if (!driver_name)
		return NULL;

	while (p) {
		char *found;

		if (!p->match) /* end of list */
			return NULL;

		found = strstr(driver_name, p->match);
		if (found && (strcmp(found, p->match) == 0)) {
			RTE_LOG(INFO, DATAPLANE, "%s matched entry %s\n",
						driver_name, p->match);
			return p;
		}
		p++;
	}

	return NULL;
}

/* Find the Receive and Transmit parameter values like
 * number of receive queues and descriptors based on
 * device driver name (ie "rte_ixgbe") and the speed
 * capabilities of the device.
 */
static const struct rxtx_param *
get_driver_param(const char *driver_name, uint32_t speed_capa)
{
	const struct rxtx_param *param = NULL;
	struct speed_suffix {
		int speed;
		const char *suffix;
	} ss[] = {
		/* most capable to least */
		{ ETH_LINK_SPEED_100G, "100" },
		{ ETH_LINK_SPEED_40G,   "40" },
		{ ETH_LINK_SPEED_25G,   "25" },
		{ ETH_LINK_SPEED_10G,   "10" },
	};
	unsigned int i;

	/* Search for a potentially more specific match based
	 * on the speed capabilities
	 */
	for (i = 0; i < ARRAY_SIZE(ss); i++) {
		struct speed_suffix *ssp = &ss[i];
		char *suffixed_name;
		int ret;

		if (speed_capa & ssp->speed) {
			ret = asprintf(&suffixed_name, "%s_%s", driver_name,
								ssp->suffix);
			if (ret != -1) {
				param = __get_driver_param(suffixed_name);
				free(suffixed_name);
				if (param)
					break;
			}
		}
	}

	if (!param)
		param = __get_driver_param(driver_name);

	/* If no driver found, then use the default parameters */
	if (!param)
		param = __get_driver_param("default");
	if (!param)
		rte_panic("missing default entry in driver_param table\n");

	return param;
}

static bitmask_t all_lcores_mask(void)
{
	unsigned int lcore;
	bitmask_t all;

	memset(&all, 0, sizeof(all));

	FOREACH_FORWARD_LCORE(lcore)
		bitmask_set(&all, lcore);

	return all;
}

static bitmask_t fwding_core_mask(void)
{
	unsigned int lcore;
	bitmask_t fwding;
	const struct lcore_conf *conf;

	memset(&fwding, 0, sizeof(fwding));

	FOREACH_FORWARD_LCORE(lcore) {
		conf = lcore_conf[lcore];
		if (forwarding_lcore(conf) || conf->ded_to_feature)
			bitmask_set(&fwding, lcore);
	}

	return fwding;
}

static void cpuset_update(void)
{
	FILE *p;
	char tmp[BITMASK_STRSZ];
	char str[PATH_MAX];
	bitmask_t fwding_cores;

	if (running) {
		/*
		 * Only call if running because it will ask us the
		 * dataplane what the current set of running cores are
		 */
		fwding_cores = fwding_core_mask();
		bitmask_sprint(&fwding_cores, tmp, sizeof(tmp));

		snprintf(str, PATH_MAX, "/usr/bin/cpu_shield --update --dp %s",
			tmp);
		p = popen(str, "r");
		if (p)
			pclose(p);
	}
}

static int main_worker_event_handler(zloop_t *loop  __unused,
				     zmq_pollitem_t *item,
				     void *arg __unused)
{
	uint64_t seqno;

	if (item[0].revents & ZMQ_POLLIN) {
		/* Clear wakeup flag on event fd */
		if ((read(item[0].fd, &seqno, sizeof(seqno)) < 0)) {

			if (errno == EINTR || errno == EAGAIN)
				return 0;

			RTE_LOG(NOTICE, DATAPLANE,
				"cpu shield event fd read failed: %s\n",
				strerror(errno));
			return -1;
		}
		cpuset_update();
	}
	if (item[1].revents & ZMQ_POLLIN) {
		/* Clear wakeup flag on event fd */
		if ((read(item[1].fd, &seqno, sizeof(seqno)) < 0)) {
			if (errno == EINTR || errno == EAGAIN)
				return 0;

			RTE_LOG(NOTICE, DATAPLANE,
				"vhost update event fd read failed: %s\n",
				strerror(errno));
				return -1;
		}
		dp_rcu_thread_online();
		/* Call vhost event handler */
		vhost_event_handler();
		dp_rcu_thread_offline();
	}
	return 0;
}
static pthread_t main_worker_thread;
static struct main_worker_thread_info {
	int cpushield_fd;
	int vhost_fd;
} main_worker_info;

/* Handle thread cancellation */
static void main_worker_cleanup(void *arg __unused)
{
	dp_rcu_unregister_thread();
}

static void *main_worker_thread_fn(void *args)
{
	struct main_worker_thread_info *info =
				(struct main_worker_thread_info *)args;

	pthread_setname_np(pthread_self(), "dataplane/main_worker");
	pthread_cleanup_push(main_worker_cleanup, NULL);


	/* poll event fd to wakeup main_worker thread*/
	zmq_pollitem_t event_poll[] = {
		{.fd = info->cpushield_fd,
		 .events = ZMQ_POLLIN,
		 .socket = NULL,
		},
		{.fd = info->vhost_fd,
		 .events = ZMQ_POLLIN,
		 .socket = NULL,
		}
	};
	int ev_count = ARRAY_SIZE(event_poll);

	dp_rcu_register_thread();
	dp_rcu_thread_offline();
	while (!zsys_interrupted) {
		if (zmq_poll(event_poll, ev_count, -1) < 0) {
			if (errno == EINTR)
				continue;

			RTE_LOG(ERR, DATAPLANE,
				"main_worker poll failed: %s\n",
				strerror(errno));
			break;		/* error detected */
		}
		(void)main_worker_event_handler(NULL, event_poll, NULL);
	}
	pthread_cleanup_pop(1);
	return NULL;
}

/*
 * Create a new thread to handle CPU shield changes. We do this as we call out
 * to an external script, and we do not want that to block the main thread.
 */
static void main_worker_thread_init(void)
{
	main_worker_info.cpushield_fd = eventfd(0, EFD_NONBLOCK);
	if (main_worker_info.cpushield_fd < 0)
		rte_panic("Cannot open cpu_shield fd for main_worker\n");

	main_worker_info.vhost_fd = eventfd(0, EFD_NONBLOCK);
	if (main_worker_info.vhost_fd < 0)
		rte_panic("Cannot open vhost fd for main_worker\n");

	vhost_event_init();

	if (pthread_create(&main_worker_thread, NULL,
			   main_worker_thread_fn, &main_worker_info) < 0)
		rte_panic("cpu_shield thread creation failed\n");
}

static void main_worker_thread_cleanup(void)
{
	int join_rc;

	pthread_cancel(main_worker_thread);
	join_rc = pthread_join(main_worker_thread, NULL);
	if (join_rc != 0)
		RTE_LOG(ERR, DATAPLANE,
			"main_worker thread join failed, rc %i\n", join_rc);
	close(main_worker_info.cpushield_fd);
	close(main_worker_info.vhost_fd);
}

/*
 * As we set the pthread affinity we need to make sure that any cpuset
 * actions are done before that, as changes afterwards clear the thread
 * level affinity. Call this early and put dataplane into the correct cpuset.
 */
static void cpuset_init(void)
{
	FILE *p;

	p = popen("/usr/bin/cpu_shield --dataplane_init", "r");
	if (p)
		pclose(p);
}

void register_forwarding_cores(void)
{
	/* wake up main_worker thread for cpu_shield fd */
	static const uint64_t incr = 1;

	if (write(main_worker_info.cpushield_fd, &incr, sizeof(incr)) < 0)
		RTE_LOG(NOTICE, DATAPLANE,
			"main_worker cpu shield  event write failed: %s\n",
			strerror(errno));
}

int set_main_worker_vhost_event_fd(void)
{
	/* wake up main_worker thread for vhost fd */
	static const uint64_t incr = 1;

	if (write(main_worker_info.vhost_fd, &incr, sizeof(incr)) < 0) {
		RTE_LOG(NOTICE, DATAPLANE,
			"main_worker vhost event fd write failed: %s\n",
			strerror(errno));
		return -1;
	}
	return 0;
}

static int port_conf_final(portid_t portid, struct rte_eth_conf *dev_conf)
{
	struct rte_eth_dev_info dev_info;
	struct port_alloc *port_alloc = &port_allocations[portid];

	if (!dev_conf)
		return -1;

	memcpy(dev_conf, &eth_base_conf, sizeof(*dev_conf));

	rte_eth_dev_info_get(portid, &dev_info);

	dev_conf->intr_conf.lsc = (port_alloc->dev_flags &
				   RTE_ETH_DEV_INTR_LSC) ? 1 : 0;

	dev_conf->rxmode.offloads = port_alloc->rx_conf.offloads;
	dev_conf->rxmode.mq_mode = port_alloc->rx_mq_mode;

	/* DPDK 18.08 errors if offload flags don't match PMD caps */
	if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_FILTER)
		dev_conf->rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_FILTER;
	if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_VLAN_STRIP)
		dev_conf->rxmode.offloads |= DEV_RX_OFFLOAD_VLAN_STRIP;
	dev_conf->rx_adv_conf.rss_conf.rss_hf &=
					dev_info.flow_type_rss_offloads;

	/* If we want VLAN offload, but don't have it,
	 * continue but issue a warning.
	 */
	if (port_alloc->tx_conf.offloads & DEV_TX_OFFLOAD_VLAN_INSERT) {
		if (!(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_VLAN_INSERT)) {
			port_alloc->tx_conf.offloads &=
						~DEV_TX_OFFLOAD_VLAN_INSERT;
			RTE_LOG(WARNING, DATAPLANE,
				"Driver %s missing hardware VLAN insertion capability; performance may be reduced.\n",
				dev_info.driver_name);
		}
	}

	dev_conf->txmode.offloads = port_alloc->tx_conf.offloads;

	DP_DEBUG(INIT, INFO, DATAPLANE,
		 "Port %d, tx_offloads 0x%lx, rx_offloads 0x%lx\n",
		 portid, dev_conf->txmode.offloads, dev_conf->rxmode.offloads);

	return 0;
}

static int port_conf_init(portid_t portid)
{
	struct rte_eth_dev *dev = &rte_eth_devices[portid];
	struct port_conf *port_conf = &port_config[portid];
	struct port_alloc *port_alloc = &port_allocations[portid];
	int socketid = rte_eth_dev_socket_id(portid);
	struct rte_eth_dev_info dev_info;
	const struct rxtx_param *parm;
	char ring_name[RTE_RING_NAMESIZE];
	unsigned int tx_pkt_ring_size;
	uint16_t q;
	uint8_t r;
	uint16_t pf_max_rx_queues, pf_max_tx_queues;
	uint8_t tx_desc_vm_multiplier;

	if (socketid < 0) /* SOCKET_ID_ANY */
		socketid = 0;

	port_alloc->socketid = socketid;

	rte_eth_dev_info_get(portid, &dev_info);
	parm = get_driver_param(dev_info.driver_name, dev_info.speed_capa);

	port_alloc->rx_desc = parm->rx_desc;
	port_alloc->tx_desc = parm->tx_desc;
	if (hypervisor_id() &&
	    !(parm->drv_flags & DRV_PARAM_VIRTUAL)) {
		if (parm->tx_desc_vm_multiplier)
			tx_desc_vm_multiplier = parm->tx_desc_vm_multiplier;
		else
			tx_desc_vm_multiplier = MAX_TX_DESC_VM_MULTIPLIER;
		port_alloc->tx_desc = tx_desc_vm_multiplier *
				      port_alloc->tx_desc;
	}
	if (port_alloc->rx_desc > dev_info.rx_desc_lim.nb_max) {
		port_alloc->rx_desc = dev_info.rx_desc_lim.nb_max;
		DP_DEBUG(INIT, INFO, DATAPLANE,
			"Lowering rx buf to max supported %d for port %u\n",
			dev_info.tx_desc_lim.nb_max, portid);
	}
	if (port_alloc->tx_desc > dev_info.tx_desc_lim.nb_max) {
		port_alloc->tx_desc = dev_info.tx_desc_lim.nb_max;
		DP_DEBUG(INIT, INFO, DATAPLANE,
			"Lowering tx buf to max supported %d for port %u\n",
			dev_info.tx_desc_lim.nb_max, portid);
	}
	port_alloc->rx_queues = parm->max_rxq;
	port_alloc->tx_queues = rte_lcore_count();

	port_alloc->buf_size = dev_info.min_rx_bufsize + MBUF_OVERHEAD;
	port_alloc->rx_cpu_affinity = all_lcores_mask();
	port_alloc->tx_cpu_affinity = all_lcores_mask();
	bitmask_zero(&port_conf->tx_enabled_queues);
	bitmask_zero(&port_conf->rx_enabled_queues);

	/* reduce Rx queues if limited by device or system */
	if (port_alloc->rx_queues > avail_cores)
		port_alloc->rx_queues = avail_cores;

	/* If an adapter has VMDQ support, the start of the virtual
	 * machine queues may not overlap with the non-VMDQ queues.
	 * We can't use VMDQ queues with the PF so we must truncate.
	 * Note: On devices that overlap, we will need to choose
	 * some partitioning between PF and VMs.
	 */
	if (dev_info.vmdq_queue_base) {
		pf_max_rx_queues = dev_info.vmdq_queue_base;
		pf_max_tx_queues = dev_info.vmdq_queue_base;
	} else {
		pf_max_rx_queues = dev_info.max_rx_queues;
		pf_max_tx_queues = dev_info.max_tx_queues;
	}

	if (port_alloc->rx_queues > pf_max_rx_queues ||
	    parm->drv_flags & DRV_PARAM_USE_ALL_RXQ)
		port_alloc->rx_queues = pf_max_rx_queues;

	/* Account for worst case Rx buffers */
	port_alloc->buffers = port_alloc->rx_queues *
		(parm->rx_desc + parm->extra);

	if (parm->match && strstr(parm->match, "bond"))
		port_alloc->buffers *= DATAPLANE_MEMBER_MULTIPLIER;

	/* If device does not have enough TX queues for each lcore
	 * then disable percoreq mode.
	 *
	 * Further, some devices, flagged as DRV_PARAM_LIMITTXQ,
	 * cannot support more TX queues than RX queues.
	 */
	if (port_alloc->tx_queues > pf_max_tx_queues ||
	    parm->drv_flags & DRV_PARAM_NO_DIRECT ||
	    ((parm->drv_flags & DRV_PARAM_LIMITTXQ) &&
	     port_alloc->tx_queues > port_alloc->rx_queues)) {
		if (parm->drv_flags & DRV_PARAM_USE_ALL_TXQ) {
			port_conf->max_rings = pf_max_tx_queues;
		} else {
			int max_txq;

			if (parm->max_txq)
				max_txq = parm->max_txq;
			else
				/*
				 * As a rough estimate, the TX
				 * processing of a packet takes around
				 * half the effort of the RX processing,
				 * so reduce the number of queues to use
				 * accordingly.
				 */
				max_txq = port_alloc->rx_queues / 2;

			/*
			 * Make sure that we still have at least one
			 * TX queue to use.
			 */
			if (max_txq <= 0)
				max_txq = 1;
			/*
			 * Don't use more queues than either the
			 * driver or the dataplane can handle.
			 */
			if (max_txq > MAX_TX_QUEUE_PER_PORT)
				max_txq = MAX_TX_QUEUE_PER_PORT;
			if (max_txq > pf_max_tx_queues)
				max_txq = pf_max_tx_queues;

			if (parm->drv_flags & DRV_PARAM_LIMITTXQ)
				max_txq =
					RTE_MIN(max_txq,
						RTE_MIN(port_alloc->tx_queues,
							port_alloc->rx_queues));
			else
				/*
				 * Don't ask for more queues than there
				 * are cores, since they won't be used.
				 */
				max_txq = RTE_MIN(max_txq,
						  port_alloc->tx_queues);

			port_conf->max_rings = max_txq;
		}
		port_alloc->tx_queues = port_conf->max_rings;
		port_conf->percoreq = false;
	} else {
		port_conf->percoreq = true;
		port_conf->max_rings = 1;		/* needed for QoS */
	}
	port_conf->nrings = port_conf->max_rings;

	for (q = 0; q < port_alloc->tx_queues; q++)
		bitmask_set(&port_conf->tx_enabled_queues, q);
	for (q = 0; q < port_alloc->rx_queues; q++)
		bitmask_set(&port_conf->rx_enabled_queues, q);

	DP_DEBUG(INIT, DEBUG, DATAPLANE,
		 "Port %u %s rx_queues %d tx_queues %d percoreq %d\n",
		 portid, dev_info.driver_name,
		 port_alloc->rx_queues, port_alloc->tx_queues,
		 port_conf->percoreq ? 1 : 0);

	tx_pkt_ring_size = parm->tx_pkt_ring_size ? parm->tx_pkt_ring_size :
		PKT_RING_SIZE;
	for (r = 0; r < port_conf->max_rings; r++) {
		struct rte_ring **pkt_ring = &port_conf->pkt_ring[r];

		snprintf(ring_name,
			 sizeof(ring_name), "pkt-ring-%u-%u", portid, r);

		*pkt_ring = rte_ring_create(ring_name, tx_pkt_ring_size,
					    socketid, RING_F_SC_DEQ);

		if (*pkt_ring == NULL) {
			RTE_LOG(ERR,
				DATAPLANE, "Cannot create %s\n", ring_name);
			return -rte_errno;
		}
	}

	/* If not percoreq or QoS is enabled then there will
	 * need to be a pkt ring.
	 */
	port_alloc->buffers += tx_pkt_ring_size * port_conf->max_rings;

	/* Overhead of every Tx queue being full */
	port_alloc->buffers += port_alloc->tx_desc * port_alloc->tx_queues;

	/* Defaults from PMD and eth_base_conf */
	port_alloc->tx_conf = dev_info.default_txconf;
	port_alloc->tx_conf.offloads |= eth_base_conf.txmode.offloads;
	port_alloc->rx_conf = dev_info.default_rxconf;
	port_alloc->rx_conf.offloads |= eth_base_conf.rxmode.offloads;
	port_alloc->rx_mq_mode = eth_base_conf.rxmode.mq_mode;

	/* This avoids head of line blocking when one queue is overloaded. */
	port_alloc->rx_conf.rx_drop_en = 1;

	/* Set offloads from conf file */
	port_alloc->rx_conf.offloads |= parm->rx_offloads;
	port_alloc->rx_conf.offloads &= ~parm->neg_rx_offloads;
	port_alloc->tx_conf.offloads |= parm->tx_offloads;
	port_alloc->tx_conf.offloads &= ~parm->neg_tx_offloads;
	if (parm->rx_mq_mode_set)
		port_alloc->rx_mq_mode = parm->rx_mq_mode;

	/* Potentially restrict device capabilities */
	port_alloc->dev_flags = dev->data->dev_flags;
	port_alloc->dev_flags |= parm->dev_flags;
	port_alloc->dev_flags &= ~parm->neg_dev_flags;

	DP_DEBUG(INIT, INFO, DATAPLANE,
		 "Port %u %s on socket %d (mbufs %u) (rx %u) (tx %u)\n",
		 portid, dev_info.driver_name, port_alloc->socketid,
		 port_alloc->buffers, port_alloc->rx_desc, port_alloc->tx_desc);

	return 0;
}

/* setup data structures per-port */
static int eth_port_init(portid_t portid)
{
	int rc;

	rc = rte_eth_dev_owner_set(portid, &owner);
	if (rc < 0) {
		RTE_LOG(NOTICE, DATAPLANE, "Port%d failed to set owner!\n",
					   portid);
		goto fail;
	}

	rc = eth_port_config(portid);
	if (rc < 0) {
		RTE_LOG(NOTICE, DATAPLANE,
			"Port%d failed to configure!\n", portid);
		goto fail;
	}

	return 0;

fail:
	bitmask_clear(&enabled_port_mask, portid);
	return rc;
}

/* teardown data structures per-portid  */
static void eth_port_uninit(portid_t portid)
{
	uint8_t q;
	struct port_conf *port_conf = &port_config[portid];
	int rc;

	linkwatch_port_unconfig(portid);
	bitmask_clear(&enabled_port_mask, portid);

	for (q = 0; q < MAX_TX_QUEUE_PER_PORT; q++) {
		if (port_conf->pkt_ring[q]) {
			rte_ring_free(port_conf->pkt_ring[q]);
			port_conf->pkt_ring[q] = NULL;
		}
	}

	rc = rte_eth_dev_owner_unset(portid, owner.id);
	if (rc < 0)
		RTE_LOG(NOTICE, DATAPLANE, "Port%d failed to unset owner!\n",
					   portid);
}

int insert_port(portid_t port_id)
{
	struct rte_eth_dev_info dev_info;

	if (port_id >= DATAPLANE_MAX_PORTS) {
		RTE_LOG(ERR, DATAPLANE,
			"can't init port %u, port out of range\n",
			port_id);
		goto failed;
	}

	bitmask_set(&enabled_port_mask, port_id);
	bitmask_clear(&linkup_port_mask, port_id);
	if_enable_poll(port_id);

	if (port_conf_init(port_id) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"insert_port(%u): ring init failed\n", port_id);
		goto failed;
	}

	if (mbuf_pool_init_portid(port_id) != 0) {
		RTE_LOG(ERR, DATAPLANE,
			"insert_port(%u): mbuf pool init failed\n", port_id);
		goto failed;
	}

	if (eth_port_init(port_id) != 0) {
		RTE_LOG(ERR, DATAPLANE,
			"insert_port(%u): failed to init port\n", port_id);
		goto failed;
	}

	return 0;

failed:
	rte_eth_dev_info_get(port_id, &dev_info);
	rte_dev_remove(dev_info.device);
	return -1;
}

void remove_port(portid_t port_id)
{
	eth_port_uninit(port_id);
}

static bitmask_t generate_crypto_engine_set(void)
{
	bitmask_t cores, fwding_cores, crypto_cores;
	int i;

	memset(&crypto_cores, 0, sizeof(crypto_cores));

	cores = online_lcores_mask();
	fwding_cores = fwding_core_mask();

	RTE_LCORE_FOREACH(i) {
		if (bitmask_isset(&cores, i) &&
		    !bitmask_isset(&fwding_cores, i))
			bitmask_set(&crypto_cores, i);
	}

	return crypto_cores;
}

static bitmask_t crypto_cpus, crypto_active_cpus;
static bool crypto_sticky;
/*
 * Probe for cores that crypto engines could potentially be allocated to.
 * The call returns the number of potential engines,
 */
unsigned int probe_crypto_engines(bool *sticky)
{
	char tmp[BITMASK_STRSZ];

	if (crypto_sticky) {
		*sticky = true;
		return bitmask_numset(&crypto_cpus);
	}
	crypto_cpus = generate_crypto_engine_set();
	if (bitmask_isempty(&crypto_cpus))
		crypto_cpus = online_lcores_mask();

	bitmask_sprint(&crypto_cpus, tmp, sizeof(tmp));
	DP_DEBUG(INIT, INFO, DATAPLANE,
		 "Crypto probe: core(s) %s available\n", tmp);

	*sticky = false;
	return bitmask_numset(&crypto_cpus);
}

/*
 * Parse cpumask expressed as hex bitmask and set as the crypto cpu
 * set for future allocations.  If no mask or an empty mask is
 * passed, then auto probe the system, disabling stickyness.
 */
int set_crypto_engines(const uint8_t *bytes, uint8_t len, bool *sticky)
{
	bitmask_t cores;
	int rc;
	char tmp[BITMASK_STRSZ];
	bool tmp_sticky;

	rc = bitmask_parse_bytes(&cores, bytes, len);

	if (rc || bitmask_isempty(&cores)) {
		crypto_sticky = false;
		probe_crypto_engines(&tmp_sticky);
	} else {
		crypto_sticky = true;
		crypto_cpus = cores;
	}

	bitmask_sprint(&crypto_cpus, tmp, sizeof(tmp));
	DP_DEBUG(INIT, INFO, DATAPLANE,
		 "Crypto cores set: %s %s\n", tmp,
		 crypto_sticky ? "Sticky" : "");

	*sticky = crypto_sticky;
	return bitmask_numset(&crypto_cpus);
}

int next_available_crypto_lcore(void)
{
	int lcore;

	lcore = next_available_lcore(SOCKET_ID_ANY, &crypto_cpus, true);

	if (lcore < 0) {
		RTE_LOG(ERR, DATAPLANE, "no crypto thread found\n");
		return -1;
	}

	return lcore;
}

/*
 * Assign one forwarding thread to have crypto processing role
 */
int crypto_assign_engine(int crypto_dev_id, int lcore)
{
	/* we have a winner! */
	struct lcore_conf *conf = lcore_conf[lcore];
	if (crypto_attach_pmd(&conf->crypt.pmd_list, crypto_dev_id, lcore) < 0)
		return -1;

	init_rate_stats(&conf->crypt_stats);

	/* Need to set do_crypto here, to stop the thread starting, and
	 * immediately terminating as do_crypto is not set.
	 */
	CMM_STORE_SHARED(conf->do_crypto, conf->do_crypto + 1);
	bitmask_set(&crypto_active_cpus, lcore);

	if (!conf->running) {
		if (!start_one_cpu(lcore)) {
			RTE_LOG(ERR, DATAPLANE,
				"Failed to start crypto on core %d\n", lcore);
			CMM_STORE_SHARED(conf->do_crypto, 0);
			bitmask_clear(&crypto_active_cpus, lcore);
			return -1;
		}
		register_forwarding_cores();
	}

	return lcore;
}

void crypto_unassign_from_engine(int lcore)
{
	struct lcore_conf *conf = lcore_conf[lcore];

	if (conf) {
		CMM_STORE_SHARED(conf->do_crypto, conf->do_crypto - 1);
		if (!conf->do_crypto)
			bitmask_clear(&crypto_active_cpus, lcore);

		if (!forwarding_or_crypto_engine_lcore(conf)) {
			stop_one_cpu(lcore);
			register_forwarding_cores();
		}
	}
}

static void
reassign_queues_for_all_ports(void)
{
	portid_t portid;

	for (portid = 0; portid < DATAPLANE_MAX_PORTS; ++portid) {
		struct port_alloc *port_alloc = &port_allocations[portid];

		if (!bitmask_isset(&enabled_port_mask, portid))
			continue;
		set_port_affinity(portid, &port_alloc->rx_cpu_affinity,
				  &port_alloc->tx_cpu_affinity);
	}
}

/* Configure ethernet port */
int eth_port_config(portid_t portid)
{
	int ret;
	struct rte_eth_fc_conf fc_conf, fcoff = {
		.pause_time = DEFAULT_FCPAUSE,
		.send_xon = 1,
		.mode = RTE_FC_NONE,
	};
	struct rte_eth_conf dev_conf;

	ret = port_conf_final(portid, &dev_conf);
	if (ret < 0)
		return ret;

	ret = eth_port_configure(portid, &dev_conf);
	if (ret < 0)
		return ret;

	ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
	if (ret == 0) {
		/* Use the adapter's high/low water marks.
		 * Programming "bad" high/low water marks can
		 * result in spurious behavior even if flow
		 * control is disabled. */
		fcoff.high_water = fc_conf.high_water;
		fcoff.low_water = fc_conf.low_water;

		/* Disable 802 flow control since it can lead to head-of-line
		 * blocking. Ignore errors some chips can't do it now. */
		ret = rte_eth_dev_flow_ctrl_set(portid, &fcoff);
		if (ret < 0 && ret != -ENOTSUP)
			RTE_LOG(NOTICE, DATAPLANE,
				"rte_eth_dev_flow_ctrl_set: err=%d, port=%u\n",
				ret, portid);
	}

	linkwatch_port_config(portid);

	return 0;
}

/* Setup lcore_conf memory */
static void lcore_init(void)
{
	unsigned int i, j, q = 0;

	avail_cores = 0;
	single_cpu = false;
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		struct lcore_conf *conf;

		if (!rte_lcore_is_enabled(i))
			continue;

		if (i != rte_get_master_lcore())
			++avail_cores;

		conf = rte_zmalloc_socket("lcore_conf",
					 sizeof(struct lcore_conf),
					 RTE_CACHE_LINE_SIZE,
					 rte_lcore_to_socket_id(i));
		if (conf == NULL)
			rte_panic("no memory for lcore %u config\n", i);

		lcore_conf[i] = conf;

		for (j = 0; j < MAX_RX_QUEUE_PER_CORE; j++)
			conf->rx_poll[j].portid = NO_OWNER;

		for (j = 0; j < MAX_TX_QUEUE_PER_CORE; j++)
			conf->tx_poll[j].portid = NO_OWNER;

		conf->tx_qid = q++;

		/* Initialise the pmd list head */
		CDS_INIT_LIST_HEAD(&conf->crypt.pmd_list);
	}

	if (avail_cores == 0) {
		avail_cores = 1;
		single_cpu = true;
	}

	DP_DEBUG(INIT, INFO, DATAPLANE, "%u core(s) available\n", avail_cores);
}

static void lcore_cleanup(void)
{
	unsigned int i;

	for (i = 0; i < RTE_MAX_LCORE; i++)
		rte_free(lcore_conf[i]);
}

/* SIGHUP  used to force resync with controller. */
static void reset_sig(int signo __unused)
{
	if (is_local_controller())
		reset_dataplane(CONT_SRC_MAIN, false);
	else
		reset_dataplane(CONT_SRC_UPLINK, false);
}

static void sigbus_hotplug(int sig, siginfo_t *si, void *ctx __unused)
	__attribute__((noreturn));
static void sigbus_hotplug(int sig, siginfo_t *si, void *ctx __unused)
{
	if (sig == SIGBUS && si->si_code == BUS_ADRERR
		 && CMM_LOAD_SHARED(hotplug_inprogress)) {
		RTE_LOG(ERR, DATAPLANE, "SIGBUS during hotplug\n");
		siglongjmp(hotplug_jmpbuf, 1);
	}
	/* Anything else is the end! */
	abort();
}

static void record_pid(const char *pidfile)
{
	FILE *f = fopen(pidfile, "w");
	if (!f)
		perror(pidfile);
	else {
		fprintf(f, "%d\n", getpid());
		fclose(f);
	}
}

static void set_signal_handlers(void)
{
	unsigned int i;
	struct sigaction action;
	static const struct {
		int signo;
		void (*handler)(int);
	} sig_handlers[] = {
		{ SIGHUP,   reset_sig },
		{ SIGPIPE,  SIG_IGN },
	};

	memset(&action, 0, sizeof(action));
	sigemptyset(&action.sa_mask);

	for (i = 0; i < ARRAY_SIZE(sig_handlers); i++) {
		int signum = sig_handlers[i].signo;

		action.sa_handler = sig_handlers[i].handler;
		if (signum == SIGUSR1 || signum == SIGUSR2)
			action.sa_flags = SA_RESTART;

		if (sigaction(signum, &action, NULL) < 0)
			rte_panic("set_signal_handler: sig %d\n", signum);
	}

	static uint8_t altstack[SIGSTKSZ];
	stack_t ss = {
		.ss_sp = altstack,
		.ss_size = SIGSTKSZ,
	};

	if (sigaltstack(&ss, NULL) == -1)
		rte_panic("signal altstack\n");

	memset(&action, 0, sizeof(action));
	action.sa_sigaction = sigbus_hotplug;
	action.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&action.sa_mask);

	sigaction(SIGBUS, &action, NULL);
}

/*
 * Add process to supplementary groups, e.g. "wireshark" so that we can later
 * successfully change the ownership of the capture FIFOs.
 */
static void set_supplementary_groups(void)
{
	int ngroups;

	struct passwd *pw = getpwuid(dataplane_uid);
	if (!pw)
		rte_panic("could not getpwuid: %s\n", strerror(errno));

	/* inquire for number of groups first */
	ngroups = 0;
	getgrouplist(pw->pw_name, dataplane_gid, NULL, &ngroups);

	/* create list of groups on stack */
	gid_t groups[ngroups];

	if (getgrouplist(pw->pw_name, dataplane_gid, groups, &ngroups) <= 0)
		rte_panic("could not getgrouplist: %s\n", strerror(errno));

	if (setgroups(ngroups, groups) < 0)
		rte_panic("could not setgroups: %s\n", strerror(errno));
}

/*
 * Dataplane application doesn't need to run as root.
 * Once initialized, safely drop most privileges (except net_admin).
 */
static void set_privilege(void)
{
	cap_t caps;

	/* keep capabilities across uid change */
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
		rte_panic("%s: PR_SET_KEEPCAPS failed: %s\n",
			  __func__, strerror(errno));

	set_supplementary_groups();

	if (dataplane_uid && setreuid(0, dataplane_uid) < 0)
		rte_panic("%s: setreuid %u failed: %s\n",
			  __func__, dataplane_uid, strerror(errno));

	/* Generate core dumps on crash even when setuid */
	if (prctl(PR_SET_DUMPABLE, 1) < 0)
		rte_panic("%s: PR_SET_DUMPABLE failed: %s\n",
			  __func__, strerror(errno));

	/*
	 * SYS_ADMIN capability does a multitude of things.
	 * Keep it permitted so we can use it in future hotplug events,
	 * but not in the effective set.
	 */
	caps = cap_from_text(
		"cap_net_admin=pe cap_net_raw=pe cap_chown=pe "
		"cap_dac_override=pe cap_ipc_lock=pe "
		"cap_sys_admin=p cap_sys_nice=pe");
	if (!caps)
		rte_panic("%s: cap_from_text failed:%s\n",
			  __func__, strerror(errno));
	if (cap_set_proc(caps) == -1)
		rte_panic("%s: cap_set_proc failed: %s\n",
			  __func__, strerror(errno));
	cap_free(caps);
}

static void init_port_configurations(uint8_t start_id, uint8_t num_ports)
{
	portid_t portid;

	for (portid = start_id; portid < (start_id + num_ports); portid++) {
		/* skip ports that are not enabled */
		if (!bitmask_isset(&enabled_port_mask, portid))
			continue;

		if (port_conf_init(portid) < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"port_conf_init failed for port %u\n", portid);
			bitmask_clear(&enabled_port_mask, portid);
		}
	}
}

/* setup data structures per-port */
static void init_eth_ports(uint8_t start_id, uint8_t num_ports)
{
	portid_t portid;
	int rc;

	for (portid = start_id; portid < (start_id + num_ports); portid++) {
		/* skip ports that are not enabled */
		if (!bitmask_isset(&enabled_port_mask, portid)) {
			RTE_LOG(INFO, DATAPLANE,
				"Skipping port%d not enabled\n", portid);
			continue;
		}

		rc = eth_port_init(portid);
		if (rc < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"Port%d failed to configure!\n", portid);
			continue;
		}
	}
}

/* free packet rings */
static void pkt_ring_destroy(void)
{
	portid_t portid;
	uint8_t q;
	struct port_conf *port_conf;

	for (portid = 0; portid < DATAPLANE_MAX_PORTS; ++portid) {
		port_conf = &port_config[portid];
		for (q = 0; q < MAX_TX_QUEUE_PER_PORT; q++)
			if (port_conf->pkt_ring[q])
				rte_ring_free(port_conf->pkt_ring[q]);
	}
}

bool is_main_thread(void)
{
	pthread_t self;

	self = pthread_self();
	return pthread_equal(self, main_pthread);
}

__FOR_EXPORT
uint16_t
fal_tx_pkt_burst(uint16_t tx_port, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	uint16_t n;
	uint8_t queue;
	struct ifnet *ifp = ifport_table[tx_port];
	struct pkt_burst *pb = RTE_PER_LCORE(pkt_burst);

	if (unlikely(!bitmask_isset(&active_port_mask, tx_port))) {
		/*
		 * Account drop against appropriate queue as if the
		 * link down detection was not detected at this point
		 * then this could equally happen due to the hardware
		 * TX queue filling up (and resulting in backpressure
		 * for non-directpath case).
		 */
		if (__use_directpath(tx_port, ifp->qos_software_fwd))
			goto full_hwq;
		else
			goto full_txring;
	}

	if (likely(pb != NULL)) {
		queue = pb->queue;
	} else {
		/*
		 * If we have reached here then we must have come
		 * though main_eth_tx, and a mutex taken, and so if
		 * directpath is subsequently taken  there  will be no
		 * contention for queue 0 with other main core pthreads
		 */
		queue = 0;
	}

	n = pkt_out_burst_cmn(ifp, ifp->qos_software_fwd, tx_port, queue,
			      bufs, nb_bufs);
	return n;

full_txring: __cold_label;
	ifp = ifnet_byport(tx_port);
	if_incr_full_txring(ifp, nb_bufs);
	return 0;

full_hwq: __cold_label;
	ifp = ifnet_byport(tx_port);
	if_incr_full_hwq(ifp, nb_bufs);
	return 0;

}

__FOR_EXPORT
void
fal_pkt_mark_set_framed(struct rte_mbuf *m)
{
	pktmbuf_mdata_set(m, PKT_MDATA_FAL_FRAMED);
}

__FOR_EXPORT
bool
fal_pkt_mark_is_framed(struct rte_mbuf *m)
{
	return pktmbuf_mdata_exists(m, PKT_MDATA_FAL_FRAMED);
}

__FOR_EXPORT
int
fal_prepare_for_header_change(struct rte_mbuf **m, uint16_t header_len)
{
	return pktmbuf_prepare_for_header_change(m, header_len);
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t max_mbuf_sz = RTE_MBUF_DEFAULT_BUF_SIZE;
	zactor_t *vplane_auth = NULL;
	struct call_rcu_data *rcu_data;
	pthread_t rcu_thread;
	unsigned int i;
	char tmp[BITMASK_STRSZ];
	bitmask_t default_enabled_port_mask;
	uint16_t nb_ports = 0;

	/*
	 * Ensure this is not fully buffered,  such that do not get lines
	 * broken at odd positions.  This also ensures the console_log_write()
	 * mechanism inter-mixes properly.
	 *
	 * This has to be done before we write to stdout.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/* Preserve name of myself. */
	progname = strrchr(argv[0], '/');
	progname = strdup(progname ? progname + 1 : argv[0]);

	/* parse application arguments (before the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		return -1;

	argc -= ret;
	argv += ret;

	parse_config();

	parse_platform_config(get_platform_cfg_file());

	/* Must be before any threads are created, and before eal_init */
	cpuset_init();

	/* Go into daemon mode.
	   Must be before EAL init or ZMQ init. */
	if (daemon_mode) {
		if (daemon(1, 1) < 0)
			rte_panic("daemon failed\n");
	}

	if (pid_file)
		record_pid(pid_file);

	/* Setup signal handlers */
	set_signal_handlers();

	/* keep track of main thread for consistency checking */
	main_pthread = pthread_self();

	ret = backplane_init(&platform_cfg.bp_list);
	if (ret < 0)
		return -1;

	/* workaround fact that EAL expects progname as first argument */
	argv[0] = progname;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		return -1;

	ret = rte_eal_hpet_init(1);
	if (ret < 0)
		RTE_LOG(INFO, DATAPLANE,
			"HPET is not available, using TSC as default timer. Timestamps in captured packets may drift over time\n"
			);

	/* set the global CZMQ socket options, will apply to all sockets */
	zsys_set_ipv6(1);

	/* set up zauth actor, can be used from all sockets */
	if (config.auth_enabled) {
		vplane_auth = zactor_new(zauth, NULL);
		if (vplane_auth == NULL)
			rte_panic("Authentication initialization failed: %s\n",
				  strerror(errno));
		zstr_sendx(vplane_auth, "CURVE", CURVE_ALLOW_ANY, NULL);
		zsock_wait(vplane_auth);
	}

	open_log();
	debug_init();

	RTE_LOG(INFO, DATAPLANE,
		"%s version %s\n",
		DATAPLANE_PROGNAME, DATAPLANE_VERSION);

	interface_init();
	incomplete_interface_init();

	fal_init();
	fal_init_plugins();

	check_broken_firmware();

	if (dataplane_uid != 0)
		set_privilege();

	rte_timer_subsystem_init();

	snprintf(owner.name, RTE_ETH_MAX_OWNER_NAME_LEN, "%s", progname);
	ret = rte_eth_dev_owner_new(&owner.id);
	if (ret < 0)
		rte_panic("Can't get owner id\n");

	parse_driver_config(&driver_param, drv_cfg_file);
	parse_driver_config(&driver_param, drv_override_cfg_file);

	bitmask_zero(&default_enabled_port_mask);
	RTE_ETH_FOREACH_DEV(i) {
		nb_ports_total = MAX(nb_ports_total, i + 1);
		if (nb_ports_total > DATAPLANE_MAX_PORTS) {
			DP_DEBUG(INIT, NOTICE, DATAPLANE,
				 "Too many Ethernet ports %u, downgrade to %u\n",
				 nb_ports, DATAPLANE_MAX_PORTS);
			nb_ports_total = DATAPLANE_MAX_PORTS;
			break;
		}
		nb_ports++;
		bitmask_set(&default_enabled_port_mask, i);
	}

	/* default to enabling all ports */
	if (bitmask_numset(&enabled_port_mask) == 0 && nb_ports != 0)
		bitmask_copy(&enabled_port_mask, &default_enabled_port_mask);

	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		bitmask_set(&poll_port_mask, i);

	bitmask_sprint(&enabled_port_mask, tmp, sizeof(tmp));
	DP_DEBUG(INIT, INFO, DATAPLANE,
		 "%u ports (%u total) available (enabled mask %s)\n",
		 nb_ports, nb_ports_total, tmp);

	random_init();
	lcore_init();
	link_state_init();

	if (dp_rcu_setup())
		rte_panic("Setting up dataplane RCU environment failed\n");

	init_port_configurations(0, nb_ports_total);
	if (nb_ports)
		max_mbuf_sz = mbuf_pool_init();

	udp_handler_init();

	feature_load_plugins();
	pl_graph_validate();

	dp_event(DP_EVT_INIT, 0, NULL, 0, 0, NULL);

	npf_init();
	session_init();
	nexthop_tbl_init();
	ip6_init();
	init_eth_ports(0, nb_ports_total);
	fragment_tables_timer_init();
	mpls_init();

	ip_id_init();

	inet_netlink_init();

	capture_init(max_mbuf_sz);
	bitmask_zero(&crypto_active_cpus);
	bitmask_zero(&crypto_cpus);
	crypto_sticky = false;
	dp_crypto_init();
	vrf_init();
	qos_init();
	main_worker_thread_init();
	/* needs to be after features have had a chance to register */
	dp_lcore_events_init(rte_lcore_id());

	console_setup();
	device_server_init();

	dp_rcu_register_thread();
	if (rcu_defer_register_thread())
		rte_panic("rcu defer register thread failed\n");

	/*
	 * Create the call_rcu thread now so that it is not created inline
	 * from a forwarding thread
	 */
	rcu_data = get_default_call_rcu_data();
	rcu_thread = get_call_rcu_thread(rcu_data);
	if (pthread_setname_np(rcu_thread, "dataplane/rcu"))
		DP_DEBUG(INIT, INFO, DATAPLANE,
			"naming of rcu thread failed\n");

	main_loop();

	crypto_pmd_remove_all();
	stop_all_ports();

	dp_crypto_shutdown();

	capture_destroy();
	device_server_destroy();
	console_destroy();
	zactor_destroy(&vplane_auth);
	interface_cleanup();
	incomplete_interface_cleanup();
	pkt_ring_destroy();
	vrf_cleanup();
	npf_cleanup();

	dp_event(DP_EVT_UNINIT, 0, NULL, 0, 0, NULL);

	close_all_regular_ports();
	dp_lcore_events_teardown(rte_lcore_id());
	feature_unload_plugins();
	udp_handler_destroy();
	platform_config_cleanup();
	fal_cleanup();
	close_all_backplane_ports();
	main_worker_thread_cleanup();

	/* wait for all RCU handlers */
	rcu_barrier();
	rcu_defer_unregister_thread();
	dp_rcu_unregister_thread();

	lcore_cleanup();

	rte_eal_cleanup();

	RTE_LOG(NOTICE, DATAPLANE, "normal exit\n");

	return 0;
}

/* Update packets per second value */
void load_estimator(void)
{
	unsigned int id, i;

	FOREACH_FORWARD_LCORE(id) {
		struct lcore_conf *conf = lcore_conf[id];
		uint64_t packets;

		for (i = 0; i < conf->high_rxq; i++) {
			struct lcore_rx_queue *rxq = &conf->rx_poll[i];

			if (rxq->portid == NO_OWNER)
				continue;

			packets = CMM_ACCESS_ONCE(rxq->packets);
			scale_rate_stats(&conf->rx_poll_stats[i],
					 &packets, NULL);
		}

		for (i = 0; i < conf->high_txq; i++) {
			struct lcore_tx_queue *txq = &conf->tx_poll[i];

			if (txq->portid == NO_OWNER)
				continue;

			packets = CMM_ACCESS_ONCE(txq->packets);
			scale_rate_stats(&conf->tx_poll_stats[i],
					 &packets, NULL);
		}

		if (conf->do_crypto) {
			struct lcore_crypt *cpq = &conf->crypt;

			packets = CMM_ACCESS_ONCE(cpq->packets);
			scale_rate_stats(&conf->crypt_stats, &packets, NULL);
			dp_crypto_periodic(&conf->crypt.pmd_list);
		}

		if (conf->do_feature) {
			if (conf->feat.dp_lcore_feat_get_rx) {
				conf->feat.dp_lcore_feat_get_rx(id, &packets);
				scale_rate_stats(&conf->feat_rx_stats, &packets,
						 NULL);
			}
			if (conf->feat.dp_lcore_feat_get_tx) {
				conf->feat.dp_lcore_feat_get_tx(id, &packets);
				scale_rate_stats(&conf->feat_tx_stats, &packets,
						 NULL);
			}

		}

		packets = crypto_fwd[id].fwd_cnt;
		scale_rate_stats(&conf->crypt_fwd_stats, &packets, NULL);
	}
}

/* Display per-core info in JSON
 * This used to display interesting stuff about worker core's,
 * their configuration and packet load.
 */
void show_per_core(FILE *f)
{
	json_writer_t *wr = jsonw_new(f);
	unsigned int id, i;
	char tmp[BITMASK_STRSZ];
	bitmask_t fwding_cores;
	char feat_name[DP_LCORE_FEAT_MAX_NAME_SIZE + 2];

	if (!wr)
		return;

	jsonw_name(wr, "lcore");
	jsonw_start_array(wr);
	FOREACH_FORWARD_LCORE(id) {
		const struct lcore_conf *conf = lcore_conf[id];

		jsonw_start_object(wr);
		jsonw_uint_field(wr, "core", id);
		jsonw_uint_field(wr, "running",  conf->running);
		jsonw_int_field(wr, "socket", rte_lcore_to_socket_id(id));
		jsonw_name(wr, "rx");
		jsonw_start_array(wr);
		for (i = 0; i < conf->high_rxq; i++) {
			const struct lcore_rx_queue *rxq = &conf->rx_poll[i];
			const struct rate_stats *rxq_stats =
				&conf->rx_poll_stats[i];
			const struct ifnet *ifp = ifnet_byport(rxq->portid);
			unsigned int nap;

			if (!ifp)
				continue;

			jsonw_start_object(wr);
			jsonw_string_field(wr, "interface", ifp->if_name);
			jsonw_uint_field(wr, "queue", rxq->queueid);
			jsonw_uint_field(wr, "packets", rxq->packets);
			jsonw_uint_field(wr, "rate", rxq_stats->packet_rate);
			if (bitmask_isset(&linkup_port_mask, rxq->portid))
				nap = rxq->gov.nap;
			else
				nap = LCORE_IDLE_SLEEP_SECS * USEC_PER_SEC;
			jsonw_uint_field(wr, "idle", nap);
			jsonw_string_field(wr, "directpath",
					   use_directpath(ifp->if_port) ? "yes"
					   : "no");
			jsonw_end_object(wr);
		}

		if (conf->do_feature && conf->feat.dp_lcore_feat_get_rx) {
			jsonw_start_object(wr);
			snprintf(feat_name, sizeof(feat_name), "[%s]",
				 conf->feat.name);
			jsonw_string_field(wr, "interface", feat_name);
			jsonw_uint_field(wr, "queue", 0);
			jsonw_uint_field(wr, "packets",
					 conf->feat_rx_stats.last_packets);
			jsonw_uint_field(wr, "rate",
					 conf->feat_rx_stats.packet_rate);
			jsonw_uint_field(wr, "idle", 0);
			jsonw_string_field(wr, "directpath", "no");
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);

		jsonw_name(wr, "tx");
		jsonw_start_array(wr);
		for (i = 0; i < conf->high_txq; i++) {
			const struct lcore_tx_queue *txq = &conf->tx_poll[i];
			const struct rate_stats *txq_stats =
				&conf->tx_poll_stats[i];
			const struct ifnet *ifp = ifnet_byport(txq->portid);
			unsigned int nap;

			if (!ifp)
				continue;

			jsonw_start_object(wr);
			jsonw_string_field(wr, "interface", ifp->if_name);
			jsonw_uint_field(wr, "queue", txq->queueid);
			jsonw_uint_field(wr, "packets", txq->packets);
			jsonw_uint_field(wr, "rate", txq_stats->packet_rate);
			if (bitmask_isset(&linkup_port_mask, txq->portid))
				nap = txq->gov.nap;
			else
				nap = LCORE_IDLE_SLEEP_SECS * USEC_PER_SEC;
			jsonw_uint_field(wr, "idle", nap);
			jsonw_end_object(wr);
		}
		if (conf->do_crypto) {
			const struct lcore_crypt *cpq = &conf->crypt;
			const struct rate_stats *cpq_stats =
				&conf->crypt_stats;

			jsonw_start_object(wr);
			jsonw_string_field(wr, "interface", "[crypt]");
			jsonw_uint_field(wr, "active_pmds", conf->do_crypto);
			jsonw_uint_field(wr, "packets", cpq->packets);
			jsonw_uint_field(wr, "rate", cpq_stats->packet_rate);
			jsonw_uint_field(wr, "idle", cpq->gov.nap);
			jsonw_end_object(wr);
		}
		if (conf->do_feature && conf->feat.dp_lcore_feat_get_tx) {
			jsonw_start_object(wr);
			snprintf(feat_name, sizeof(feat_name), "[%s]",
				 conf->feat.name);
			jsonw_string_field(wr, "interface", feat_name);
			jsonw_uint_field(wr, "packets",
					 conf->feat_tx_stats.last_packets);
			jsonw_uint_field(wr, "rate",
					 conf->feat_tx_stats.packet_rate);
			jsonw_uint_field(wr, "idle", 0);
			jsonw_end_object(wr);
		}

		if (conf->crypt_fwd_stats.packet_rate) {
			jsonw_start_object(wr);
			jsonw_string_field(wr, "interface", "[crypt-fwd]");
			jsonw_uint_field(wr, "rate",
					 conf->crypt_fwd_stats.packet_rate);
			jsonw_uint_field(wr, "idle", 0);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);

	bitmask_sprint(&crypto_cpus, tmp, sizeof(tmp));
	jsonw_string_field(wr, "crypto_permitted_cores", tmp);
	jsonw_uint_field(wr, "crypto_sticky", crypto_sticky);
	bitmask_sprint(&crypto_active_cpus, tmp, sizeof(tmp));
	jsonw_string_field(wr, "crypto_active_cores", tmp);
	fwding_cores = fwding_core_mask();
	bitmask_sprint(&fwding_cores, tmp, sizeof(tmp));
	jsonw_string_field(wr, "forwarding_cores", tmp);
	jsonw_destroy(&wr);
}

static void show_ifp_affinity(struct ifnet *ifp, void *arg)
{
	const struct port_alloc *port_alloc = &port_allocations[ifp->if_port];
	char tmp[BITMASK_STRSZ];
	unsigned int lcore, q;
	json_writer_t *wr = arg;
	bitmask_t rx_mask, tx_mask;

	bitmask_zero(&rx_mask);
	bitmask_zero(&tx_mask);

	FOREACH_FORWARD_LCORE(lcore) {
		const struct lcore_conf *conf = lcore_conf[lcore];

		for (q = 0; q < conf->high_rxq; q++)
			if (conf->rx_poll[q].portid == ifp->if_port)
				bitmask_set(&rx_mask, lcore);

		for (q = 0; q < conf->high_txq; q++)
			if (conf->tx_poll[q].portid == ifp->if_port)
				bitmask_set(&tx_mask, lcore);
	}

	jsonw_name(wr, ifp->if_name);
	jsonw_start_object(wr);

	bitmask_t affinity_online;
	bitmask_t cpu_affinity;
	bitmask_or(&cpu_affinity, &port_alloc->rx_cpu_affinity,
		   &port_alloc->tx_cpu_affinity);
	affinity_online = cpu_affinity_online(&cpu_affinity);
	bitmask_sprint(&affinity_online, tmp, sizeof(tmp));
	jsonw_string_field(wr, "affinity", tmp);

	affinity_online = cpu_affinity_online(&port_alloc->rx_cpu_affinity);
	bitmask_sprint(&affinity_online, tmp, sizeof(tmp));
	jsonw_string_field(wr, "rx_affinity", tmp);

	affinity_online = cpu_affinity_online(&port_alloc->tx_cpu_affinity);
	bitmask_sprint(&affinity_online, tmp, sizeof(tmp));
	jsonw_string_field(wr, "tx_affinity", tmp);

	bitmask_sprint(&rx_mask, tmp, sizeof(tmp));
	jsonw_string_field(wr, "rx_cpu", tmp);

	bitmask_sprint(&tx_mask, tmp, sizeof(tmp));
	jsonw_string_field(wr, "tx_cpu", tmp);

	jsonw_end_object(wr);
}

/* Generate an JSON array of port cpu affinity */
int show_affinity(FILE *f, int argc, char **argv)
{
	json_writer_t *wr = jsonw_new(f);

	if (!wr)
		return -1;

	jsonw_pretty(wr, true);
	if (argc == 1)
		dp_ifnet_walk(show_ifp_affinity, wr);
	else {
		while (--argc > 0) {
			struct ifnet *ifp = dp_ifnet_byifname(*++argv);

			if (!ifp) {
				fprintf(f, "Unknown interface: %s\n", *argv);
				jsonw_destroy(&wr);
				return -1;
			}
			show_ifp_affinity(ifp, wr);
		}
	}
	jsonw_destroy(&wr);

	return 0;
}

void set_port_affinity(portid_t portid, const bitmask_t *rx_mask,
		       const bitmask_t *tx_mask)
{
	struct port_alloc *port_alloc = &port_allocations[portid];

	if (rx_mask)
		port_alloc->rx_cpu_affinity = *rx_mask;
	else
		port_alloc->rx_cpu_affinity = all_lcores_mask();

	if (tx_mask)
		port_alloc->tx_cpu_affinity = *tx_mask;
	else
		port_alloc->tx_cpu_affinity = all_lcores_mask();

	/* reassign queues to make the affinity take effect */
	if (dpdk_eth_if_port_started(portid)) {
		unassign_queues(portid);
		assign_queues(portid);
	}
}

void set_packet_input_func(packet_input_t input_fn)
{
	if (input_fn)
		packet_input_func = input_fn;
	else
		/* set to default */
		packet_input_func = ether_input_no_dyn_feats;
}

void
switch_port_process_burst(portid_t portid, struct rte_mbuf *pkts[], uint16_t nb)
{
	process_burst(portid, pkts, nb);
}

bool dp_lcore_is_active(unsigned int lcore)
{
	const struct lcore_conf *conf;

	if (lcore >= get_lcore_max())
		return false;

	conf = lcore_conf[lcore];
	if (CMM_LOAD_SHARED(conf->running))
		return true;

	return false;
}

enum dp_lcore_use dp_lcore_get_current_use(unsigned int lcore)
{
	struct lcore_conf *conf;

	if (lcore > get_lcore_max())
		return DP_LCORE_INVALID;

	if (lcore == rte_get_master_lcore())
		return DP_LCORE_MAIN;

	conf = lcore_conf[lcore];
	/*
	 * Crypto is not considered to be 'FEATURE' as it can run alongside
	 * forwarders, i.e crypto does not take dedicated control of the core
	 */
	if (conf->do_feature)
		return DP_LCORE_FEATURE;

	return DP_LCORE_FORWARDER;
}

int
dp_allocate_lcore_to_feature(unsigned int lcore,
			     struct dp_lcore_feat *feat)
{
	struct lcore_conf *conf;
	portid_t portid;
	unsigned int id;
	enum dp_lcore_use core_use;
	int core_count;
	const bitmask_t all_lcores = all_lcores_mask();

	if (!feat->dp_lcore_feat_fn)
		return -EINVAL;

	if (lcore > get_lcore_max()) {
		RTE_LOG(ERR, DATAPLANE,
			"Request to allocate invalid core %d to feature\n",
			lcore);
		return -EINVAL;
	}

	conf = lcore_conf[lcore];
	if (dp_lcore_get_current_use(lcore) == DP_LCORE_MAIN) {
		RTE_LOG(ERR, DATAPLANE,
			"Request to allocate main core %d to feature\n",
			lcore);
		return -EINVAL;
	}

	if (dp_lcore_get_current_use(lcore) == DP_LCORE_FEATURE) {
		RTE_LOG(ERR, DATAPLANE,
			"Request to allocate feature core %d to feature\n",
			lcore);
		return -EINVAL;
	}

	/*
	 * If crypto is on this core (either due to config or arbitrary
	 * allocation then reject). This may change with some of the crypto
	 * rework being planned.
	 */
	if (conf->do_crypto) {
		RTE_LOG(ERR, DATAPLANE,
			"Request to allocate crypto core %d to feature\n",
			lcore);
		return -EINVAL;
	}

	/* Check all ports to see if one is configured for this core */
	for (portid = 0; portid < DATAPLANE_MAX_PORTS; ++portid) {
		struct port_alloc *port_alloc = &port_allocations[portid];

		/*
		 * If the affinity is the same as the all_lcores_mask
		 * then not configured.
		 */
		if (bitmask_equal(&all_lcores, &port_alloc->rx_cpu_affinity) &&
		    bitmask_equal(&all_lcores, &port_alloc->tx_cpu_affinity))
			continue;

		if (bitmask_isset(&port_alloc->rx_cpu_affinity, lcore) ||
		    bitmask_isset(&port_alloc->tx_cpu_affinity, lcore)) {
			RTE_LOG(ERR, DATAPLANE,
				"Request to allocate cfged forwarding core %d to feature\n",
				lcore);
			return -EBUSY;
		}
	}

	/* Must have at least one forwarder left after this change. */
	core_count = 0;
	FOREACH_FORWARD_LCORE(id) {
		if (id == lcore)
			continue;
		core_use = dp_lcore_get_current_use(id);
		if (core_use == DP_LCORE_FORWARDER)
			core_count++;
	}
	if (core_count == 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Request to allocate feature core %d would leave no forwarders\n",
			lcore);
		return -EINVAL;
	}

	/*
	 * Indicate that the core is dedicated to a feature, and so should
	 * not be used for forwarding.
	 */
	conf->ded_to_feature = true;

	/*
	 * Cause the ports to be reassigned, so that the forwarding thread
	 * will no longer use this core
	 */
	reassign_queues_for_all_ports();

	conf->feat = *feat;
	CMM_STORE_SHARED(conf->do_feature, true);

	/* wait for the core to be available to start a thread on it again */
	stop_one_cpu(lcore);
	start_one_cpu(lcore);

	return 0;
}

int dp_unallocate_lcore_from_feature(unsigned int lcore)
{
	struct lcore_conf *conf;

	if (lcore > get_lcore_max()) {
		RTE_LOG(ERR, DATAPLANE,
			"Request to unallocate invalid core %d from feature\n",
			lcore);
		return -EINVAL;
	}

	conf = lcore_conf[lcore];
	if (dp_lcore_get_current_use(lcore) != DP_LCORE_FEATURE) {
		RTE_LOG(ERR, DATAPLANE,
			"Request to unallocate feature core %d, but not a feature core\n",
			lcore);
		return -EINVAL;
	}

	if (CMM_LOAD_SHARED(conf->do_feature)) {
		CMM_STORE_SHARED(conf->do_feature, false);
		memset(&conf->feat, 0, sizeof(conf->feat));
		conf->ded_to_feature = false;

		stop_one_cpu(lcore);

		reassign_queues_for_all_ports();
	} else {
		RTE_LOG(ERR, DATAPLANE,
			"Request to unallocate feature core %d, but not a feature core\n",
			lcore);
		return -EINVAL;
	}
	return 0;
}
