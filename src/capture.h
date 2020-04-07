/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef	CAPTURE_H
#define	CAPTURE_H

#include <czmq.h>
#include <pcap/bpf.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <time.h>

#include "if_var.h"

struct rte_mbuf;

/*
 * Info used by capture thread.
 */
TAILQ_HEAD(capture_filter_list, capture_filter);

struct capture_filter {
	TAILQ_ENTRY(capture_filter) next;
	struct bpf_program filter; /* BPF filter to apply */
	uint8_t mask; /* bitmask of capture slots applying this filter */
};

struct capture_info {
	int cap_wake;
	struct rte_ring *cap_ring;
	pthread_t cap_thread;
	zsock_t *cap_pub;
	int cap_pub_port;
	zsock_t *cap_pcapin;
	int cap_pcapin_port;
	int offload_mask;
	uint8_t capture_mask; /* bitmask of current captures */
	struct capture_filter_list filters;
	struct timespec last_beat;
	bool is_promisc;
	bool is_swonly;
	unsigned int snaplen;
	unsigned int bandwidth;
	fal_object_t falobj;
};

/* This should be expanded to all vplane interface types */
static inline bool capture_supported_if(const struct ifnet *ifp)
{
	return ifp->if_type == IFT_ETHER ||
		ifp->if_type == IFT_L2TPETH ||
		ifp->if_type == IFT_L2VLAN ||
		ifp->if_type == IFT_BRIDGE ||
		ifp->if_type == IFT_VXLAN ||
		is_gre(ifp) ||
		is_vti(ifp) ||
		is_s2s_feat_attach(ifp);
}

/*
 * Use common capture points unless capturing on ethernet port, where we
 * capture in bursts, or on bridge, where capture is done
 * on interface specific basis.
 */
static inline bool capture_if_use_common_cap_points(const struct ifnet *ifp)
{
	return !(ifp->if_type == IFT_ETHER ||
		 ifp->if_type == IFT_BRIDGE);
}

/* Capture interface */
void capture_destroy(void);
void capture_init(uint16_t);
void capture_cancel(struct ifnet *ifp);
void capture_hardware(const struct ifnet *ifp, struct rte_mbuf *mbuf)
	__attribute__((cold));
void capture_burst(const struct ifnet *ifp, struct rte_mbuf *pkts[], unsigned int n)
	__attribute__((cold));
int cmd_capture(FILE *f, int argc, char **argv);
#endif /* CAPTURE_H */
