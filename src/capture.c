/*
 * Simple data capture output.
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <arpa/inet.h>
#include <czmq.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <zmq.h>

#include "capture.h"
#include "config_internal.h"
#include "event.h"
#include "fal.h"
#include "if_var.h"
#include "ip_addr.h"
#include "main.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pktmbuf_internal.h"
#include "pl_node.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"
#include "zmq_dp.h"

/* Assume that only some ports are doing capture at once. */
#define CAPTURE_MAX_PORTS	8
#define CAP_PKT_BURST		4
#define CAPTURE_RING_SZ		256
#define CAP_MAX_PER_PORT        4 /* max simultaneous captures on a port */
#define CAPTURE_TIME_RESYNC_USECS (60 * USEC_PER_SEC)

static struct rte_mempool *capture_pool;

static rte_spinlock_t capture_time_lock;
static struct timeval capture_tod;
static uint64_t capture_base;
static uint64_t capture_hz;

static zsock_t *capture_sock_master;
static zsock_t *capture_sock_console;
static pthread_mutex_t capture_sock_lock = PTHREAD_MUTEX_INITIALIZER;

typedef int (*fal_func_t)(void *arg);

static int capture_master_send(fal_func_t func, void *arg);

static void capture_time_resync(struct timeval *tod, uint64_t *base,
				uint64_t *hz)
{
	uint64_t new_capture_base = rte_get_timer_cycles();
	uint64_t new_capture_hz = rte_get_timer_hz();
	struct timeval new_capture_tod;

	gettimeofday(&new_capture_tod, NULL);

	/* protect against resync happening in another thread */
	rte_spinlock_lock(&capture_time_lock);

	capture_base = new_capture_base;
	capture_hz = new_capture_hz;
	capture_tod = new_capture_tod;

	rte_spinlock_unlock(&capture_time_lock);

	if (tod)
		*tod = new_capture_tod;
	if (base)
		*base = new_capture_base;
	if (hz)
		*hz = new_capture_hz;
}

/*
 * Stop capturing on the given slot, if no more slots capturing
 * then we will exit the main capture loop and clean up.
 */
static bool capture_stop(struct ifnet *ifp,
			 uint8_t slot)
{
	struct capture_info *cap_info = ifp->cap_info;
	struct capture_filter *cap_filter;

	cap_info->capture_mask &= ~slot;

	if (cap_info->capture_mask == 0)
		return true;

	TAILQ_FOREACH(cap_filter, &cap_info->filters, next) {
		if (!(cap_filter->mask & slot))
			continue;

		cap_filter->mask &= ~slot;
		if (cap_filter->mask)
			continue;

		TAILQ_REMOVE(&cap_info->filters, cap_filter, next);
		rte_free(cap_filter->filter.bf_insns);
		rte_free(cap_filter);
		break;
	}

	return false;
}

/*
 * Install a new capture filter on the requested slot.
 * If we already have the same filter on an existing slot then
 * just add this slot to the slotmask.
 */
static int cap_filter_install(struct ifnet *ifp, uint8_t slotmask,
			      uint32_t len, struct bpf_insn *insn)
{
	struct capture_info *cap_info = ifp->cap_info;
	struct capture_filter *cap_filter;
	struct bpf_insn *bf_insns;

	TAILQ_FOREACH(cap_filter, &cap_info->filters, next) {
		if (cap_filter->filter.bf_len == len &&
		    !memcmp(cap_filter->filter.bf_insns, insn,
			    sizeof(struct bpf_insn) * len)) {
			cap_filter->mask |= slotmask;
			break;
		}
	}

	if (cap_filter == NULL) {
		cap_filter = rte_zmalloc_socket("filter", sizeof(*cap_filter),
						RTE_CACHE_LINE_SIZE,
						ifp->if_socket);
		if (cap_filter == NULL)
			return -1;

		bf_insns = rte_zmalloc_socket("insns",
					      sizeof(*bf_insns) * len,
					      RTE_CACHE_LINE_SIZE,
					      ifp->if_socket);
		if (bf_insns == NULL) {
			rte_free(cap_filter);
			return -1;
		}
		memcpy(bf_insns, insn, sizeof(*bf_insns) * len);

		cap_filter->filter.bf_insns = bf_insns;
		cap_filter->filter.bf_len = len;
		cap_filter->mask = slotmask;

		TAILQ_INSERT_TAIL(&cap_info->filters, cap_filter, next);
	}
	return 0;
}

/*
 * Send response to pcap request and free inbound message.
 */
#define MAX_RESPONSE 50
static void pcapin_response(zsock_t *sock, char *type, zmsg_t *recv_msg,
			    const char *response)
{
	zstr_sendf(sock, "%s %s", response, type ? : "");
	free(type);
	zmsg_destroy(&recv_msg);
}

/*
 * Handler for incoming requests from libpcap (filters, heartbeats and stop
 * command).
 */
static int pcapin_handler(zsock_t *sock, struct ifnet *ifp)
{
	struct capture_info *cap_info = ifp->cap_info;
	zmsg_t *msg;
	zframe_t *frame;
	uint8_t slotmask;
	uint32_t len;
	struct bpf_insn *insn;
	char *type;

	msg = zmsg_recv(sock);

	/*
	 * Message formats
	 *
	 * Filter install:
	 * Frame 1 - "FILTER"
	 * Frame 2 - <slotmask>
	 * Frame 3 - <filter len>
	 * Frame 4 - <filter instructions>
	 *
	 * Capture stop:
	 * Frame 1 - "STOP"
	 * Frame 2 - <slotmask>
	 *
	 * Heartbeat:
	 * Frame 1 - "BEAT"
	 */
	if (msg) {
		type = zmsg_popstr(msg);
		if (type == NULL) {
			pcapin_response(sock, type, msg, "ERR: no type");
			return -1;
		}

		if (!strcmp(type, "BEAT")) {
			clock_gettime(CLOCK_MONOTONIC_COARSE,
				      &cap_info->last_beat);
			pcapin_response(sock, type, msg, "OK");
			return 0;
		}

		frame = zmsg_pop(msg);
		if (frame == NULL) {
			pcapin_response(sock, type, msg, "ERR: no slotmask");
			return -1;
		}
		memcpy(&slotmask, zframe_data(frame), sizeof(uint8_t));
		zframe_destroy(&frame);

		if (!(cap_info->capture_mask & slotmask)) {
			pcapin_response(sock, type, msg, "ERR: invalid slot");
			return -1;
		}

		if (!strcmp(type, "STOP")) {
			int stop = capture_stop(ifp, slotmask);
			pcapin_response(sock, type, msg, "OK");
			return stop;
		} else if (!strcmp(type, "FILTER")) {

			frame = zmsg_pop(msg);
			if (frame == NULL) {
				pcapin_response(sock, type, msg,
						"ERR: no filt len");
				return -1;
			}
			memcpy(&len, zframe_data(frame),
			       sizeof(uint32_t));
			zframe_destroy(&frame);

			frame = zmsg_pop(msg);
			if (frame == NULL) {
				pcapin_response(sock, type, msg,
						"ERR: no filt insn");
				return -1;
			}
			insn = (struct bpf_insn *) zframe_data(frame);

			if (!bpf_validate(insn, len) ||
			    cap_filter_install(ifp, slotmask,
					       len, insn) < 0) {
				zframe_destroy(&frame);
				pcapin_response(sock, type, msg,
						"ERR: filt install");
				return -1;
			}
			zframe_destroy(&frame);
			pcapin_response(sock, type, msg, "OK");
		} else {
			pcapin_response(sock, type, msg,
					"ERR: unknown type");
			return -1;
		}
	}
	return 0;
}

static int64_t capture_usec_from_tod_base(uint64_t ts, uint64_t base,
					  uint64_t hz)
{
	return ((int64_t)(ts - base) * USEC_PER_SEC) / (int64_t)hz;
}

/* Read timestamp from packet and convert it to system time of day format */
static void capture_get_timestamp(struct rte_mbuf *m, struct timeval *tv)
{
	uint64_t ts = m->udata64;
	int64_t us;
	uint64_t base;
	uint64_t hz;

	m->udata64 = 0;

	/* protect against resync happening in another thread */
	rte_spinlock_lock(&capture_time_lock);

	us = capture_usec_from_tod_base(ts, capture_base, capture_hz);
	*tv = capture_tod;

	rte_spinlock_unlock(&capture_time_lock);

	/* Check if we should resync the time base */
	if (us >= CAPTURE_TIME_RESYNC_USECS ||
	    us + CAPTURE_TIME_RESYNC_USECS <= 0) {
		capture_time_resync(tv, &base, &hz);
		us = capture_usec_from_tod_base(ts, base, hz);
	}

	tv->tv_sec += us / USEC_PER_SEC;
	tv->tv_usec += us % USEC_PER_SEC;
	if (tv->tv_usec >= USEC_PER_SEC) {
		++tv->tv_sec;
		tv->tv_usec -= USEC_PER_SEC;
	} else if (tv->tv_usec < 0) {
		--tv->tv_sec;
		tv->tv_usec += USEC_PER_SEC;
	}
}

/* write to event fd to wakeup capture thread */
static void capture_wakeup(struct capture_info *cap_info)
{
	static const uint64_t incr = 1;

	if (write(cap_info->cap_wake, &incr, sizeof(incr)) < 0)
		RTE_LOG(NOTICE, DATAPLANE,
			"capture wakeup failed: %s\n",
			strerror(errno));
}

/* Make a copy of the packet mbufs */
static int capture_mbuf_copy(struct rte_mbuf *mbi[], struct rte_mbuf *mbo[],
			     unsigned int n)
{
	uint64_t ts = rte_get_timer_cycles();
	struct rte_mbuf *m;
	unsigned int i, j;

	for (i = 0; i < n; i++) {
		m = pktmbuf_copy(mbi[i], capture_pool);
		if (!m)
			goto nomem;

		m->udata64 = ts;
		mbo[i] = m;
	}
	return 0;

 nomem:
	for (j = 0; j < i; j++)
		rte_pktmbuf_free(mbo[j]);

	return -ENOBUFS;
}

/* Put clone of mbuf's into ring for capture thread */
static int capture_enqueue(struct capture_info *cap_info,
			   struct rte_mbuf *pkts[], unsigned int n)
{
	int ret;

	ret = rte_ring_mp_enqueue_bulk(cap_info->cap_ring,
				       (void **)pkts, n, NULL);
	if (likely(ret > 0))
		capture_wakeup(cap_info);

	return ret;
}

/*
 * Add a hardware snooped packet, received directly from the platform
 * backplane, to the capture ring.
 */
void capture_hardware(const struct ifnet *ifp, struct rte_mbuf *mbuf)
{
	mbuf->udata64 = rte_get_timer_cycles();

	if (unlikely(!ifp->hw_capturing) ||
	    (unlikely(capture_enqueue(ifp->cap_info, &mbuf, 1) == 0)))
		rte_pktmbuf_free(mbuf);
}

/* Put mbuf(s) in capture ring. */
void capture_burst(const struct ifnet *ifp,
		   struct rte_mbuf *pkts[], unsigned int n)
{
	struct rte_mbuf *snap[n];

	/* may be called with no packets on transmit with bonding interfaces */
	if (n == 0 || capture_mbuf_copy(pkts, snap, n) < 0)
		return;

	if (unlikely(capture_enqueue(ifp->cap_info, snap, n) == 0))
		pktmbuf_free_bulk(snap, n);
}

/* Add to zmq msg if within the snaplen and return the remaining space. */
static int addmsg_if_space(zmsg_t *msg, const void *ptr,
			   unsigned int len, unsigned int space)
{
	unsigned int addlen;

	addlen = len > space ? space : len;
	zmsg_addmem(msg, ptr, addlen);
	return space - addlen;
}

/* Filter packets and send to captures via zmq */
static int capture_write(struct rte_mbuf *m, struct ifnet *ifp)
{
	struct capture_info *cap_info = ifp->cap_info;
	struct capture_filter *cap_filter;
	struct pcap_pkthdr pcap;
	uint8_t filtered_mask = cap_info->capture_mask;
	zmsg_t *msg;
	unsigned int space = cap_info->snaplen;

	capture_get_timestamp(m, &pcap.ts);
	pcap.len = rte_pktmbuf_pkt_len(m);
	if (pcap.len < cap_info->snaplen)
		pcap.caplen = pcap.len;
	else
		pcap.caplen = cap_info->snaplen;

	TAILQ_FOREACH(cap_filter, &cap_info->filters, next) {
		if (!bpf_filter(cap_filter->filter.bf_insns,
			       (const u_char *) rte_pktmbuf_mtod(m, char *),
			       pcap.len, pcap.caplen))
			filtered_mask &= ~cap_filter->mask;
	}

	if (!filtered_mask)
		return 0;

	msg = zmsg_new();

	if (!msg)
		return -1;

	/*
	 * First send filtered mask, ie. the slots that survived filtering.
	 */
	zmsg_addmem(msg, &filtered_mask, sizeof(filtered_mask));

	/* ... then PCAP header */
	if (m->ol_flags & (PKT_TX_VLAN_PKT|PKT_RX_VLAN)) {
		pcap.caplen += sizeof(struct rte_vlan_hdr);
		if (pcap.caplen > cap_info->snaplen)
			pcap.caplen = cap_info->snaplen;
		pcap.len += sizeof(struct rte_vlan_hdr);
	}

	zmsg_addmem(msg, &pcap, sizeof(pcap));

	/* Special case for VLAN.
	 * copy Ethernet header from original packet
	 * and rebuild real ethernet and vlan header
	 * in a temporary buffer.
	 */
	if (m->ol_flags & (PKT_TX_VLAN_PKT|PKT_RX_VLAN)) {
		const struct rte_ether_hdr *eh
			= rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		struct {
			struct rte_ether_hdr eh;
			struct rte_vlan_hdr  vh;
		} vhdr;

		memcpy(&vhdr.eh, eh, 2 * ETHER_ADDR_LEN);
		vhdr.eh.ether_type = htons(if_tpid(ifp));
		vhdr.vh.vlan_tci = htons(m->vlan_tci);
		vhdr.vh.eth_proto = eh->ether_type;

		space = addmsg_if_space(msg, &vhdr, sizeof(vhdr), space);
		if (!space)
			goto msg_send;

		/* hide original ethernet header */
		space = addmsg_if_space(msg,
					rte_pktmbuf_mtod(m, char *) + ETHER_HDR_LEN,
					(unsigned int)rte_pktmbuf_data_len(m) - ETHER_HDR_LEN,
					space);
		if (!space)
			goto msg_send;

		m = m->next;
	}

	while (m) {
		space = addmsg_if_space(msg, rte_pktmbuf_mtod(m, char *),
					(unsigned int)rte_pktmbuf_data_len(m),
					space);
		if (!space)
			goto msg_send;

		m = m->next;
	}

msg_send:
	return zmsg_send_and_destroy(&msg, cap_info->cap_pub);
}

static void capture_flush(const struct capture_info *cap_info)
{
	struct rte_mbuf *m;

	while (rte_ring_sc_dequeue(cap_info->cap_ring, (void **)&m) == 0)
		rte_pktmbuf_free(m);
}

/*
 * Bind or unbind the FAL capture object to/from the interface. This
 * action function runs in the context of the master thread.
 */

struct capture_hw_bind_args {
	uint32_t ifindex;
	fal_object_t obj;
};

static int capture_hw_bind(void *arg)
{
	struct capture_hw_bind_args *bind_args = arg;
	struct fal_attribute_t portattr;

	portattr.id = FAL_PORT_ATTR_CAPTURE_BIND;
	portattr.value.objid = bind_args->obj;
	return fal_l2_upd_port(bind_args->ifindex, &portattr);
}

static void capture_hw_stop(const struct ifnet *ifp,
			    struct capture_info *cap_info)
{
	struct capture_hw_bind_args args;

	if (cap_info->falobj == 0)
		return;

	args.ifindex = ifp->if_index;
	args.obj = FAL_NULL_OBJECT_ID;

	/*
	 * Termination is triggered from normal capture cancellation
	 * and deletion of the interface (capture_cancel()). The
	 * former is in the context of the capture thread (loop
	 * termination), the latter is in the context of the master
	 * thread.
	 *
	 * In the interface deletion case, trying to schedule the
	 * unbind action on the master thread is never going to work
	 * (deadlock as we're already running on the master
	 * thread). Update the FAL directly.
	 */
	if (is_master_thread())
		capture_hw_bind(&args);
	else
		capture_master_send(capture_hw_bind, &args);

	fal_capture_delete(cap_info->falobj);
	cap_info->falobj = 0;
}

static void capture_cleanup(void *arg)
{
	struct ifnet *ifp = arg;
	struct capture_info *cap_info = ifp->cap_info;
	struct capture_filter *cap_filter, *next_filter;

	capture_flush(cap_info);
	close(cap_info->cap_wake);
	zsock_destroy(&cap_info->cap_pub);
	zsock_destroy(&cap_info->cap_pcapin);

	for (cap_filter = TAILQ_FIRST(&cap_info->filters);
	     cap_filter;
	     cap_filter = next_filter) {

		next_filter = TAILQ_NEXT(cap_filter, next);
		TAILQ_REMOVE(&cap_info->filters, cap_filter, next);
		rte_free(cap_filter->filter.bf_insns);
		rte_free(cap_filter);
	}

	if (ifp->if_type == IFT_ETHER) {
		if (cap_info->is_promisc)
			ifpromisc(ifp, 0);
		if (cap_info->offload_mask >= 0)
			rte_eth_dev_set_vlan_offload(ifp->if_port,
						     cap_info->offload_mask);
	}

	RTE_LOG(INFO, DATAPLANE, "Capture stopped on %s\n",
		ifp->if_name);
}

/* Max numer of loops processing packets without checking for events */
#define CAPTURE_MAX_LOOPS 100

/* Main capture loop */
static void capture_loop(struct ifnet *ifp)
{
	struct capture_info *cap_info = ifp->cap_info;
	struct rte_mbuf *m;
	struct timespec now;
	uint loops;
	zmq_pollitem_t items[] = {
		{ .fd = cap_info->cap_wake,
		  .events = ZMQ_POLLIN,
		  .socket = NULL,
		},
		{ .socket = zsock_resolve(cap_info->cap_pcapin),
		  .events = ZMQ_POLLIN,
		}
	};

	while (running) {
		/*
		 * If we haven't heard from anyone in 20s, give up
		 * and stop the capture on this port.
		 */
		clock_gettime(CLOCK_MONOTONIC_COARSE,
			      &now);
		if (now.tv_sec - cap_info->last_beat.tv_sec > 20)
			return;

		loops = 0;
		while (rte_ring_sc_dequeue(cap_info->cap_ring,
					   (void **) &m) == 0) {
			int ret;

			ret = capture_write(m, ifp);

			rte_pktmbuf_free(m);

			if (ret < 0)
				return;

			if (loops++ >= CAPTURE_MAX_LOOPS) {
				capture_wakeup(cap_info);
				break;
			}
		}

		/*
		 * Ring is empty or we looped MAX times, wait for new packets.
		 * Timeout at 10s to make sure we check for heartbeats.
		 */
		if (zmq_poll(items, 2, 10000 * ZMQ_POLL_MSEC) < 0) {
			RTE_LOG(ERR, DATAPLANE, "capture poll failed: %s\n",
				strerror(errno));
			return;
		}

		if (items[0].revents & ZMQ_POLLIN) {
			uint64_t seqno;

			if (read(cap_info->cap_wake,
				 &seqno, sizeof(seqno)) < 0) {
				RTE_LOG(ERR, DATAPLANE,
					"capture wakeup read failed: %s\n",
					strerror(errno));
				return;
			}
		}

		if (items[1].revents & ZMQ_POLLIN)
			if (pcapin_handler(cap_info->cap_pcapin, ifp))
				return;
	}
}

/* Worker thread for capture.
 * - enable capture flag
 * - read packets from ring buffer
 * - handle incoming requests from pcap
 */
static void *capture_thread(void *arg)
{
	struct ifnet *ifp = arg;
	struct capture_info *cap_info = ifp->cap_info;

	pthread_cleanup_push(capture_cleanup, arg);

	if (ifp->if_type == IFT_ETHER) {
		int offload_mask;
		/* Turn off vlan filtering */
		offload_mask =
			rte_eth_dev_get_vlan_offload(ifp->if_port);
		if (offload_mask > 0)
			rte_eth_dev_set_vlan_offload(ifp->if_port,
						     offload_mask &
						     ~ETH_VLAN_FILTER_OFFLOAD);
		cap_info->offload_mask = offload_mask;
		if (cap_info->is_promisc)
			ifpromisc(ifp, 1);
	}

	if (cap_info->falobj != 0)
		ifp->hw_capturing = 1;
	else
		ifp->capturing = 1;

	if (ifp->capturing && capture_if_use_common_cap_points(ifp)) {
		pl_node_add_feature_by_inst(&capture_ether_in_feat, ifp);
		pl_node_add_feature_by_inst(&capture_l2_output_feat, ifp);
	}

	RTE_LOG(INFO, DATAPLANE, "%sCapture started on %s\n",
		ifp->hw_capturing ? "Hardware " : "", ifp->if_name);

	capture_loop(ifp);

	if (ifp->capturing && capture_if_use_common_cap_points(ifp)) {
		pl_node_remove_feature_by_inst(&capture_ether_in_feat, ifp);
		pl_node_remove_feature_by_inst(&capture_l2_output_feat, ifp);
	}

	capture_hw_stop(ifp, cap_info);
	ifp->hw_capturing = 0;
	ifp->capturing = 0;

	synchronize_rcu();	/* all threads stop capturing */

	pthread_cleanup_pop(1);
	ifp->cap_info = NULL;
	rte_ring_free(cap_info->cap_ring);
	rte_free(cap_info);
	pthread_detach(pthread_self());

	return NULL;
}

/*
 * Cancel the capture thread and clean up.
 */
void capture_cancel(struct ifnet *ifp)
{
	struct capture_info *cap_info;
	void *join_res;

	if (!ifp || !ifp->cap_info)
		return;
	cap_info = ifp->cap_info;
	ifp->hw_capturing = 0;
	ifp->capturing = 0;
	capture_hw_stop(ifp, cap_info);
	pthread_cancel(cap_info->cap_thread);
	pthread_join(cap_info->cap_thread, &join_res);

	if (join_res != PTHREAD_CANCELED)
		RTE_LOG(ERR, DATAPLANE,
			"capture thread join, expected cancel\n");
	ifp->cap_info = NULL;
	rte_ring_free(cap_info->cap_ring);
	rte_free(cap_info);
}

static bool capture_hw_start(FILE *f, const struct ifnet *ifp,
			     struct capture_info *cap_info)
{
	struct fal_attribute_t capattr[] = {
		{ .id = FAL_CAPTURE_ATTR_COPY_LENGTH,
		  .value.u32 = cap_info->snaplen },
		{ .id = FAL_CAPTURE_ATTR_BANDWIDTH,
		  .value.u32 = cap_info->bandwidth }
	};
	struct capture_hw_bind_args args;
	fal_object_t obj;
	int rc;

	if (cap_info->is_swonly || !if_is_hwport((struct ifnet *)ifp))
		return true;

	rc = fal_capture_create(ARRAY_SIZE(capattr), capattr, &obj);
	if (rc == -EOPNOTSUPP)
		return true;

	if (rc < 0) {
		fprintf(f, "capture_start: hardware setup failed: %s\n",
			strerror(-rc));
		return false;
	}

	/*
	 * Bind the object to the interface (turn on packet capture)
	 */
	args.ifindex = ifp->if_index;
	args.obj = obj;
	rc = capture_master_send(capture_hw_bind, &args);
	if (rc < 0) {
		fal_capture_delete(obj);

		if (rc == -EOPNOTSUPP)
			return true;

		fprintf(f, "capture_start: hardware enable failed: %s\n",
			strerror(-rc));
		return false;
	}

	cap_info->falobj = obj;
	return true;
}

static struct capture_info *capture_new(FILE *f, const char *addrstr,
					struct ifnet *ifp,
					bool is_promisc, unsigned int snaplen,
					bool swonly, unsigned int bandwidth)
{
	struct capture_info *cap_info;
	int cap_pub_port, cap_pcapin_port;
	char rname[RTE_RING_NAMESIZE];

	cap_info = rte_zmalloc_socket("capture", sizeof(struct capture_info),
				      RTE_CACHE_LINE_SIZE, ifp->if_socket);
	if (cap_info == NULL) {
		fprintf(f, "capture_start: cap_info create failed");
		goto fail;
	}

	cap_info->is_promisc = is_promisc;
	cap_info->snaplen = snaplen;
	cap_info->is_swonly = swonly;
	cap_info->bandwidth = bandwidth;

	snprintf(rname, RTE_RING_NAMESIZE, "capture_%s", ifp->if_name);
	cap_info->cap_ring = rte_ring_create(rname, CAPTURE_RING_SZ,
					     ifp->if_socket,
					     RING_F_SC_DEQ);

	if (!cap_info->cap_ring) {
		fprintf(f, "capture_start: cap_ring create failed");
		goto cleanup_fail;
	}

	clock_gettime(CLOCK_MONOTONIC_COARSE, &cap_info->last_beat);
	TAILQ_INIT(&cap_info->filters);

	/* Publisher to send capture data */
	cap_info->cap_pub = zsock_new(ZMQ_PUB);
	if (cap_info->cap_pub == NULL) {
		fprintf(f, "capture_start: pub socket create failed");
		goto cleanup_ring_fail;
	}

	cap_pub_port = zsock_bind(cap_info->cap_pub,
				    "tcp://%s:*", addrstr);
	if (cap_pub_port < 0) {
		fprintf(f, "capture_start: pub socket bind failed, %s",
			strerror(errno));
		goto cleanup_pub_fail;
	}
	cap_info->cap_pub_port = cap_pub_port;

	/* Listener for filters, heartbeat and stop command */
	cap_info->cap_pcapin = zsock_new(ZMQ_REP);

	if (cap_info->cap_pcapin == NULL) {
		fprintf(f, "capture_start: filt socket create failed");
		goto cleanup_pub_fail;
	}

	cap_pcapin_port = zsock_bind(cap_info->cap_pcapin,
				       "tcp://%s:*",
				       addrstr);
	if (cap_pcapin_port < 0) {
		fprintf(f, "capture_start: filt socket bind failed, %s",
			strerror(errno));
		goto cleanup_pcapin_fail;
	}
	cap_info->cap_pcapin_port = cap_pcapin_port;

	cap_info->cap_wake = eventfd(0, 0);
	if (cap_info->cap_wake < 0) {
		fprintf(f, "capture_start: wakeup fd create failed");
		goto cleanup_pcapin_fail;
	}

	if (!capture_hw_start(f, ifp, cap_info))
		goto cleanup_pcapin_fail;

	return cap_info;

 cleanup_pcapin_fail:
	zsock_destroy(&cap_info->cap_pcapin);
 cleanup_pub_fail:
	zsock_destroy(&cap_info->cap_pub);
 cleanup_ring_fail:
	rte_ring_free(cap_info->cap_ring);
 cleanup_fail:
	rte_free(cap_info);
 fail:
	return NULL;
}
/*
 * Start a new capture on this port. If no capture slots
 * are currently in use then do the necessary setup.
 */
static int capture_start(FILE *f, struct ifnet *ifp,
			 bool is_promisc, unsigned int snaplen,
			 bool swonly, unsigned int bandwidth)
{
	struct capture_info *cap_info = ifp->cap_info;
	char addrstr[INET6_ADDRSTRLEN];
	uint8_t cap_slot = 0;
	int i;

	if (!inet_ntop(config.local_ip.type, &config.local_ip.address,
		       addrstr, sizeof(addrstr))) {
		fprintf(f, "capture_start: Failed to get addr string");
		return -1;
	}

	if (cap_info == NULL) {
		cap_info = capture_new(f, addrstr,
				       ifp, is_promisc, snaplen,
				       swonly, bandwidth);
		if (cap_info == NULL)
			return -1;

		ifp->cap_info = cap_info;
		/* start a collector thread */
		if (pthread_create(&cap_info->cap_thread, NULL,
				   capture_thread, ifp) < 0) {
			fprintf(f, "capture_start: pthread create failed");
			zsock_destroy(&cap_info->cap_pcapin);
			zsock_destroy(&cap_info->cap_pub);
			capture_hw_stop(ifp, cap_info);
			ifp->cap_info = NULL;
			rte_ring_free(cap_info->cap_ring);
			rte_free(cap_info);
			return -1;
		}
		pthread_setname_np(cap_info->cap_thread, "dataplane/cap");
	}

	/* Find a free slot */
	for (i = 0; i < CAP_MAX_PER_PORT; i++) {
		uint8_t slot = 1 << i;

		if (cap_info->capture_mask & slot)
			continue;
		cap_info->capture_mask |= slot;
		cap_slot = slot;
		break;
	}

	if (!cap_slot) {
		fprintf(f, "capture_start: out of slots");
		return -1;
	}

	fprintf(f, "%2x tcp://%s:%d tcp://%s:%d",
		cap_slot,
		addrstr, cap_info->cap_pub_port,
		addrstr, cap_info->cap_pcapin_port);
	return 0;
}

static int
capture_show(FILE *f, const struct ifnet *ifp)
{
	const struct capture_info *cap_info = ifp->cap_info;
	json_writer_t *wr = jsonw_new(f);
	struct fal_attribute_t portattr = {
		.id = FAL_PORT_ATTR_HW_CAPTURE,
	};

	if (wr == NULL)
		return -1;

	jsonw_name(wr, "capture");
	jsonw_start_object(wr);
	jsonw_string_field(wr, "interface", ifp->if_name);
	jsonw_bool_field(wr, "active", cap_info != 0);
	jsonw_bool_field(wr, "hardware-support",
			 fal_l2_get_attrs(ifp->if_index, 1, &portattr) == 0);
	if (cap_info != NULL) {
		jsonw_uint_field(wr, "snaplen", cap_info->snaplen);
		jsonw_bool_field(wr, "promiscuous", cap_info->is_promisc);
		jsonw_bool_field(wr, "hw-capture", ifp->hw_capturing);
		jsonw_bool_field(wr, "software-only", cap_info->is_swonly);
		jsonw_uint_field(wr, "bandwidth", cap_info->bandwidth);
	}
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}

/*
 * Handler for capture command.
 *
 * capture start <interface> <is_promisc> <snaplen> <swonly> <bandwidth>
 * capture show  <interface>
 */
int cmd_capture(FILE *f, int argc, char **argv)
{
	const char *intf;
	struct ifnet *ifp;
	bool is_promisc;
	unsigned int snaplen;
	bool swonly = false;
	unsigned int bandwidth = 0;

	if (argc < 3) {
		fprintf(f, "capture: invalid arguments (%d)", argc);
		return -1;
	}

	intf = argv[2];
	ifp = dp_ifnet_byifname(intf);
	if (ifp == NULL) {
		fprintf(f, "capture: interface %s not found", intf);
		return -1;
	}

	if (!capture_supported_if(ifp)) {
		fprintf(f, "capture: unsupported interface type");
		return -1;
	}

	if (streq(argv[1], "show"))
		return capture_show(f, ifp);

	if (argc < 5) {
		fprintf(f, "capture: invalid arguments (%d)", argc);
		return -1;
	}

	if (strcmp(argv[1], "start")) {
		fprintf(f, "capture: unknown command\n");
		return -1;
	}

	is_promisc = (*argv[3] == '1');
	snaplen = strtoul(argv[4], NULL, 10);
	if (argc > 5) {
		unsigned int value;

		if (get_unsigned(argv[5], &value) == 0)
			swonly = value > 0;

		/*
		 * Usable backplane bandwidth is in Kbit/sec, with a
		 * maximum value of 1 Gbit/sec.
		 */
		if ((get_unsigned(argv[6], &value) < 0) ||
		    (value > (1*1000*1000))) {
			fprintf(f, "capture: invalid bandwidth %s\n",
				argv[6]);
			return -1;
		}

		bandwidth = value;
	}

	return capture_start(f, ifp, is_promisc, snaplen, swonly, bandwidth);
}

/*
 * In order to maintain serialisation with other FAL updates, the FAL
 * updates to packet capture must be run within the context of the
 * master thread (as opposed to the console or capture threads).
 *
 * Use a simple synchronous RPC-like mechanism to schedule FAL action
 * routines on the master thread.
 */
static int capture_master_receive(void *arg)
{
	zsock_t *sock = (zsock_t *)arg;
	fal_func_t func;
	void *func_arg;
	int func_rc;

	if (zsock_recv(sock, "pp", &func, &func_arg) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"%s() failed to get action from console\n", __func__);
		return -EIO;
	}

	func_rc = (*func)(func_arg);

	if (zsock_send(sock, "i", func_rc) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"%s() failed to send response to console\n", __func__);
		return -EIO;
	}

	return 0;
}

static int capture_master_send_locked(fal_func_t func, void *arg)
{
	int func_rc;

	if (zsock_send(capture_sock_console, "pp", func, arg) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"%s() failed to send action to master\n",
			__func__);
		return -EIO;
	}

	if (zsock_recv(capture_sock_console, "i", &func_rc) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"%s() failed to get response from master\n",
			__func__);
		return -EIO;
	}

	return func_rc;
}

static int capture_master_send(fal_func_t func, void *arg)
{
	int rc;

	pthread_mutex_lock(&capture_sock_lock);
	rc = capture_master_send_locked(func, arg);
	pthread_mutex_unlock(&capture_sock_lock);
	return rc;
}

void capture_destroy(void)
{
	dp_unregister_event_socket(zsock_resolve(capture_sock_master));
	zsock_destroy(&capture_sock_master);
	zsock_destroy(&capture_sock_console);
}

/*
 * Setup mbuf pool for packet capture.
 */
void capture_init(uint16_t mbuf_sz)
{
	unsigned int nbufs;

	nbufs = CAPTURE_MAX_PORTS * CAPTURE_RING_SZ + CAP_PKT_BURST;
	nbufs = rte_align32pow2(nbufs) - 1;

	capture_pool = mbuf_pool_create("capture", nbufs,
					MBUF_CACHE_SIZE_DEFAULT, mbuf_sz,
					rte_socket_id());
	if (!capture_pool)
		rte_panic("can not initialize capture pool\n");

	rte_spinlock_init(&capture_time_lock);
	capture_time_resync(NULL, NULL, NULL);

	capture_sock_master = zsock_new_pair("@inproc://capture_master_event");
	if (capture_sock_master == NULL)
		rte_panic("capture master socket failed");

	capture_sock_console = zsock_new_pair(">inproc://capture_master_event");
	if (capture_sock_master == NULL)
		rte_panic("capture console socket failed");

	dp_register_event_socket(zsock_resolve(capture_sock_master),
				 capture_master_receive,
				 capture_sock_master);
}
