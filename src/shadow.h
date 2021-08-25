/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef SHADOW_H
#define SHADOW_H

#include <czmq.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <zmq.h>

#include "control.h"
#include "pktmbuf_internal.h"
#include "urcu.h"
#include "util.h"

struct rte_ether_addr;
struct ifnet;
struct rte_mbuf;
struct tun_meta;
struct tun_pi;

/* Number of buffers queued from dataplane to slowpath thread  */
#define SHADOW_IO_RING_SIZE	1024

/* per interface data structure
 *   rx - packets received on NIC and going to kernel
 *   tx - packets from kernel going to NIC
 */
struct shadow_if_info {
	struct rte_ring *rx_slow_ring;	/* pkts going to tunnel */
	unsigned int	 port;
	int		 fd;
	bool		 wake_me;
	bool		 congested;

	uint64_t rs_packets;	/* pkts sent over tunnel */
	uint64_t rs_infull;	/* pkts dropped because ring was full */
	uint64_t rs_errors;	/* pkts dropped on write to tun dev */
	uint64_t rs_overrun;	/* pkts dropped because of socket queue full */
	uint64_t rs_congested;  /* pkts marked with congestion experienced */
	uint64_t ts_packets;	/* pkts from tunnel */
	uint64_t ts_errors;	/* pkts dropped on read */
	uint64_t ts_nobufs;	/* pkts dropped because no mbufs */

	struct rcu_head	 rcu;
};

/* Start monitoring port */
void shadow_start_port(portid_t portid);
void shadow_stop_port(portid_t portid);

/* Initialize a shadow interface port. */
int shadow_init_port(portid_t portid, const char *ifname,
		     const struct rte_ether_addr *eth_addr);
void shadow_uninit_port(portid_t port);

/* Display shadow interface statistics */
void shadow_show_summary(FILE *f, const char *name);

struct ifnet *get_lo_ifp(enum cont_src_en cont_src);
int shadow_add_event(zloop_t *loop, portid_t port, const char *ifname);
int tap_attach(const char *ifname);

void shadow_init_spath_ring(int tun_fd);
int slowpath_init(void);

void set_spath_rx_meta_data(struct rte_mbuf *m, const struct ifnet *ifp,
			    uint16_t proto, uint8_t meta_mask);
int tap_receive(zloop_t *loop, zmq_pollitem_t *item, struct shadow_if_info *sii,
		struct rte_mbuf **pkt);
int spath_receive(zmq_pollitem_t *item, struct tun_pi *pi,
		  struct tun_meta *meta, struct shadow_if_info *sii,
		  struct rte_mbuf **mbuf);
int tap_reader(zloop_t *loop, zmq_pollitem_t *item, void *arg);
int spath_reader(zloop_t *loop, zmq_pollitem_t *item, void *arg);
int tuntap_write(int fd, struct rte_mbuf *m, struct ifnet *ifp);
bool local_packet_filter(const struct ifnet *ifp, struct rte_mbuf *m);
struct shadow_if_info *get_port2shadowif(portid_t portid);
struct shadow_if_info *get_fd2shadowif(int fd);

#endif /* SHADOW_H */
