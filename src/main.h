/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef MAIN_H
#define MAIN_H

#include <czmq.h>
#include <rte_memory.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>

#include "bitmask.h"
#include "compat.h"
#include "compiler.h"
#include "control.h"

struct rte_mbuf;
struct rte_mempool;

extern char *progname;

extern uid_t dataplane_uid;
extern gid_t dataplane_gid;

/* Flag to indicate thread should keep running (or exit) */
extern volatile bool running;

extern bitmask_t linkup_port_mask;	/*  has carrier */
extern bitmask_t active_port_mask;
extern bitmask_t poll_port_mask;
extern bitmask_t enabled_port_mask;
extern unsigned int slowpath_mtu;

struct rte_mempool *mbuf_pool(unsigned int portid);
struct rte_mempool *mbuf_pool_create(const char *name,
				     unsigned int n,
				     unsigned int cache_sz,
				     unsigned long roomsz,
				     int socket_id);

/* Console interface */
void load_estimator(void);
void show_per_core(FILE *f);

extern const char *console_endpoint;
void console_setup(void);
void console_destroy(void);

int portid_to_ifindex(portid_t port);
int8_t ifindex_to_portid(int index);

/* Logging */
int open_log(void);

struct ifnet;
struct rte_eth_link;
/* Packet interface */
struct sched_info;

enum l2_packet_type {
	L2_PKT_UNICAST,
	L2_PKT_BROADCAST,
	L2_PKT_MULTICAST,
};

/* hotplug */
extern sigjmp_buf hotplug_jmpbuf;
extern bool hotplug_inprogress;

void local_packet(struct ifnet *ifp, struct rte_mbuf *m);
void local_packet_internal(struct ifnet *ifp, struct rte_mbuf *m);

const char *link_duplexstr(unsigned int duplex);
void link_state_init(void);
void send_port_status(uint32_t port_id, const struct rte_eth_link *link);
int show_affinity(FILE *f, int argc, char **argv);
void set_port_affinity(portid_t portid, const bitmask_t *rx_mask,
		       const bitmask_t *tx_mask);
uint64_t get_link_modes(struct ifnet *ifp);

int assign_queues(portid_t portid);
void unassign_queues(portid_t portid);
int enable_transmit_thread(portid_t portid);
void disable_transmit_thread(portid_t portid);
void set_port_queue_state(uint16_t port);
void reset_port_all_queue_state(uint16_t port);
bool port_uses_queue_state(uint16_t port);
int mbuf_pool_init_portid(const portid_t portid);
void pkt_ring_empty(portid_t portid);
void pkt_ring_output(struct ifnet *ifp, struct rte_mbuf *m);
int insert_port(portid_t port_id);
void remove_port(portid_t port_id);
int launch_one_lcore(void *arg);
int send_device_event(const char *name, bool is_add);
void device_server_init(void);
void device_server_destroy(void);
int eth_port_config(portid_t portid);
int eth_port_configure(portid_t portid, struct rte_eth_conf *dev_conf);
unsigned int probe_crypto_engines(bool *sticky);
int set_crypto_engines(const char *str, bool *sticky);
int crypto_assign_engine(int crypto_dev_id, int lcore);
void crypto_unassign_from_engine(int lcore);
void register_forwarding_cores(void);
int reconfigure_queues(portid_t portid, uint16_t nb_rx_qs, uint16_t nb_tx_qs);

/* Rate states */
struct rate_stats {
	uint32_t packet_rate;
	uint64_t last_packets;
	uint32_t byte_rate;
	uint64_t last_bytes;
	struct timeval last_time;
};
void scale_rate_stats(struct rate_stats *stats, uint64_t *packets,
		      uint64_t *bytes);

#define DRV_PARAM_LIMITTXQ	(1<<0)	/* size of rxq == size of txq */
#define DRV_PARAM_VIRTUAL	(1<<1)	/* is a "virtual" device */
#define DRV_PARAM_NO_DIRECT	(1<<2)	/* do not use direct TX */
#define DRV_PARAM_USE_ALL_RXQ	(1<<3)	/* use all available RX queues */
#define DRV_PARAM_USE_ALL_TXQ	(1<<4)	/* use all available TX queues */

struct rxtx_param {
	const char *match;
	uint8_t	 max_rxq;
	uint8_t	 max_txq;
	uint16_t rx_desc;
	uint16_t tx_desc;
	uint16_t extra;
	uint16_t drv_flags;
	uint16_t tx_pkt_ring_size;
	uint64_t rx_offloads;
	uint64_t neg_rx_offloads;
	uint8_t	 tx_desc_vm_multiplier;
	uint64_t tx_offloads;
	uint64_t neg_tx_offloads;
	uint64_t dev_flags;
	uint64_t neg_dev_flags;
	uint64_t rx_mq_mode;
	bool rx_mq_mode_set;
};

#define MAX_RX_QUEUE_PER_PORT	20
#define MAX_TX_QUEUE_PER_PORT	4

#define MAX_TX_QUEUE_PER_CORE	(MAX_TX_QUEUE_PER_PORT * DATAPLANE_MAX_PORTS)
#define MAX_RX_QUEUE_PER_CORE	(MAX_RX_QUEUE_PER_PORT * DATAPLANE_MAX_PORTS)

#define MAX_RX_DESC_PER_QUEUE 65536
#define MAX_TX_DESC_PER_QUEUE 65536

#define MAX_TX_DESC_VM_MULTIPLIER 8

#define MBUF_CACHE_SIZE_DEFAULT 32 /* per-core buffer cache size */

void set_port_uses_queue_state(uint16_t portid, bool val);
bool get_port_uses_queue_state(uint16_t portid);
void reset_port_enabled_queue_state(uint16_t portid);
void track_port_queue_state(uint16_t portid, uint16_t queue_id, bool rx,
			    bool enable);
void switch_port_process_burst(portid_t portid, struct rte_mbuf *pkts[],
			       uint16_t nb);
int set_main_worker_vhost_event_fd(void);

extern bool single_cpu;

extern uint16_t nb_ports_total;

int next_available_crypto_lcore(void);

#endif /* MAIN_H */
