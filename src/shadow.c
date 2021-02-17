/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * shadow - manage the creation and data movement for the slow path devices.
 *
 * There are two kinds of shadow devices:
 * When controller and dataplane are on the same machine,
 * the tuntap device is used. The tun device is a hybrid
 * with a file descriptor (like a raw device) in the dataplane but
 * also has a network device available for the controller.
 *
 * If dataplane and controller are on separate machines (or VM's)
 * a GRE tunnel is used to transfer packets.
 */

#include <czmq.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <sched.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <urcu/uatomic.h>
#include <zmq.h>

#include "compat.h"
#include "compiler.h"
#include "config_internal.h"
#include "crypto/crypto_forward.h"
#include "crypto/vti.h"
#include "dp_event.h"
#include "ether.h"
#include "if/gre.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "json_writer.h"
#include "lag.h"
#include "main.h"
#include "nh_common.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "rcu.h"
#include "route.h"
#include "route_v6.h"
#include "shadow.h"
#include "vplane_log.h"

/* Get a port number for spathintf out of range of physical ports */
#define DATAPLANE_SPATH_PORT (DATAPLANE_MAX_PORTS)

#define SHADOW_IO_RING_HWM	32
#define SHADOW_IO_RING_BURST	8

/* to be fair with the tun/tap reader */
#define SHADOW_WRITE_POLLS 1

enum shadow_ev {
	SHADOW_ADD,
	SHADOW_REMOVE,
};

/* One for each physical port and also slow path interface */
struct shadow_if_info *shadow_if[DATAPLANE_MAX_PORTS + 1];

static int event_fd;		      /* wakeup writer thread */
static int lfd;
static int shadow_fd;
static zsock_t *shadow_server_sock;
static pthread_t shadow_thread;
static uint64_t shadow_next_ring_id;

/* inproc server address */
static const char shadow_inproc[] = "inproc://shadow";

/*
 * Determine the shadow interface where packet should
 * be queued.
 */
static struct shadow_if_info *
local_shadow_if(struct rte_mbuf *m, struct ifnet *inp_ifp)
{
	portid_t portid = m->port;
	struct shadow_if_info *sii;

	/*
	 * If this packet arrived on the spathintf interface, or has
	 * meta data due to being decapped here, then remove the
	 * prepended pseudo eth header before sending it to the kernel
	 * via spath TUN device unless the payload being carried is TEB.
	 */
	if (pktmbuf_mdata_invar_exists(m, PKT_MDATA_INVAR_SPATH)) {
		struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);

		if (mdata->md_spath.pi.proto != htons(RTE_ETHER_TYPE_TEB) &&
		    unlikely(!rte_pktmbuf_adj(m, sizeof(struct rte_ether_hdr))))
			return NULL;

		portid = DATAPLANE_SPATH_PORT;
	}

	sii =  rcu_dereference(shadow_if[portid]);
	if (sii)
		return sii;

	if (is_s2s_feat_attach(inp_ifp)) {
		/*
		 * Set mdata so that when the packet is sent on the spath the
		 * correct data is sent.
		 */
		set_spath_rx_meta_data(m, inp_ifp, ntohs(ethhdr(m)->ether_type),
				       TUN_META_FLAGS_DEFAULT);
		if (!rte_pktmbuf_adj(m, sizeof(struct rte_ether_hdr)))
			return NULL;

		portid = DATAPLANE_SPATH_PORT;
		return rcu_dereference(shadow_if[portid]);
	}
	return NULL;
}

/*
 * Pass received packets  into the Linux TCP/IP stack.
 * Use ring to pass packets to main thread.
 *
 * Always consumes (free) mbuf
 */
void local_packet_internal(struct ifnet *ifp, struct rte_mbuf *m)
{
	unsigned int free_space;

	if (!local_packet_filter(ifp, m))
		goto drop;

	struct shadow_if_info *sii = local_shadow_if(m, ifp);
	if (unlikely(!sii)) {
		RTE_LOG(ERR, DATAPLANE,
			"local_packet: port %u is missing its shadow if\n",
			m->port);
		goto drop;
	}

	/*
	 * We need the member interface in tuntap_write to be able to
	 * restore vlan headers correctly
	 */
	if (pktmbuf_mdata_invar_exists(m, PKT_MDATA_INVAR_BRIDGE)) {
		struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);
		struct ifnet *member_ifp;

		member_ifp = dp_ifnet_byifindex(
			mdata->md_bridge.member_ifindex);
		if (member_ifp)
			ifp = member_ifp;
	}
	pktmbuf_save_ifp(m, ifp);
	if (sii->congested)
		pktmbuf_ecn_set_ce(m);

	int ret = rte_ring_mp_enqueue_bulk(sii->rx_slow_ring,
					   (void **) &m, 1, &free_space);
	if (ret == 0)
		goto full;

	if (free_space < (SHADOW_IO_RING_SIZE - SHADOW_IO_RING_HWM - 1)) {
		++sii->rs_congested;
		sii->congested = true;
	} else
		sii->congested = false;

	if (CMM_LOAD_SHARED(sii->wake_me)) {
		/* wake up slowpath thread on the main. */
		static const uint64_t incr = 1;

		if (unlikely(write(event_fd, &incr, sizeof(incr)) < 0))
			RTE_LOG(NOTICE, DATAPLANE,
				"shadow event write failed: %s\n",
				strerror(errno));
	}
	return;

full:   __cold_label;
	++sii->rs_infull;

drop:	__cold_label;
	if_incr_dropped(ifp);
	{
		struct pl_packet pkt = {
			.mbuf = m,
			.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
			.in_ifp = ifp
		};
		pipeline_fused_term_drop(&pkt);
	}
}

/*
 * Pass received packets  into the Linux TCP/IP stack.
 * Use ring to pass packets to main thread.
 *
 * Always consumes (free) mbuf
 */
void local_packet(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct pl_packet pkt = {
		.mbuf = m,
		.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
		.in_ifp = ifp
	};

	pipeline_fused_l2_local(&pkt);
}

/*
 * Move packet from the input ring to the tunnel.
 * If kernel is full, drop packet.
 */
static void shadow_io_write(struct shadow_if_info *sii, struct rte_mbuf *m)
{
	int rc;

	rc = tuntap_write(sii->fd, m, pktmbuf_restore_ifp(m));

	if (rc < 0) {
		if (errno == ENOBUFS || errno == EWOULDBLOCK || errno == EAGAIN)
			++sii->rs_overrun;
		else
			++sii->rs_errors;
	} else
		++sii->rs_packets;

	rte_pktmbuf_free(m);
}

/* Get a burst of packets from ring and forward them to kernel */
static unsigned int shadow_io_burst(struct shadow_if_info *sii)
{
	struct rte_mbuf *s_pkts[SHADOW_IO_RING_BURST];
	unsigned int i, n;

	n = rte_ring_sc_dequeue_burst(sii->rx_slow_ring,
				      (void **)s_pkts,
				      SHADOW_IO_RING_BURST,
				      NULL);

	for (i = 0; i < n; i++)
		shadow_io_write(sii, s_pkts[i]);

	return n;
}

/* Callback from event_fd
 * Processes all packets for all receive rings.
 * Keeps going until all rings are empty.
 */
static int shadow_writer(zloop_t *loop __rte_unused,
			 zmq_pollitem_t *item,
			 void *arg __rte_unused)
{
	struct shadow_if_info *sii;
	unsigned int npkts = 0;
	unsigned int port;
	uint64_t seqno;
	int i;

	/* Clear wakeup flag on event fd */
	if (unlikely(read(item->fd, &seqno, sizeof(seqno)) < 0)) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

		RTE_LOG(NOTICE, DATAPLANE,
			"shadow event fd read failed: %s\n",
			strerror(errno));
		return -1;
	}

	dp_rcu_thread_online();

	for (i = 0; i < SHADOW_WRITE_POLLS; i++) {
		npkts = 0;

		/* Check for packets to send over tunnel */
		for (port = 0; port <= DATAPLANE_MAX_PORTS; port++) {

			/* Check for hotplug removal */
			if (port < DATAPLANE_MAX_PORTS &&
			    unlikely(!rte_eth_dev_is_valid_port(port)))
				continue;

			sii = rcu_dereference(shadow_if[port]);
			if (!sii)
				continue;

			/* Enable doorbell only if not busy */
			if (rte_ring_empty(sii->rx_slow_ring)) {
				sii->congested = false;
				CMM_STORE_SHARED(sii->wake_me, true);
			} else {
				CMM_STORE_SHARED(sii->wake_me, false);
			}

			npkts += shadow_io_burst(sii);
		}

		if (npkts == 0)
			break;	/* my work here is done */
	}

	if (npkts != 0) {
		static const uint64_t incr = 1;

		/*
		 * My work here is not quite done - give other events
		 * in this thread a chance to be serviced.
		 */
		if (write(item->fd, &incr, sizeof(incr)) < 0)
			RTE_LOG(NOTICE, DATAPLANE,
				"shadow event write failed: %s\n",
				strerror(errno));
	}

	dp_rcu_thread_offline();
	return 0;
}

/*
 * Create ring for packets from dataplane to kernel via spathintf
 */
void shadow_init_spath_ring(int tun_fd)
{
	char ring_name[RTE_RING_NAMESIZE];
	struct shadow_if_info *sii;


	sii = rte_zmalloc("shadow", sizeof(struct shadow_if_info),
			  RTE_CACHE_LINE_SIZE);
	if (!sii)
		rte_panic("can't allocate slowpath interface\n");

	snprintf(ring_name, RTE_RING_NAMESIZE, "spathintf");
	sii->rx_slow_ring = rte_ring_create(ring_name,
					    SHADOW_IO_RING_SIZE, 0,
					    RING_F_SC_DEQ);
	if (!sii->rx_slow_ring)
		rte_panic("spathintf ring %s create failed\n", ring_name);

	sii->port = IF_PORT_ID_INVALID;
	/* Enable doorbell by default */
	sii->wake_me = true;
	sii->fd = tun_fd;
	shadow_if[DATAPLANE_SPATH_PORT] = sii;
}

static uint8_t
shadow_feature_if_output(struct ifnet *ifp, struct rte_mbuf *m,
			 struct rte_ether_hdr *hdr)
{
	if (hdr->ether_type == htons(RTE_ETHER_TYPE_IPV4)) {
		if (ip_spath_output(ifp, m) < 0)
			/* pak freed, but not yet counted */
			return 1;
	} else if (hdr->ether_type == htons(RTE_ETHER_TYPE_IPV6)) {
		if (ip6_spath_output(ifp, m) < 0)
			/* pak freed, but not yet counted */
			return 1;
	} else {
		if_output(ifp, m, NULL, ntohs(hdr->ether_type));
	}
	return 0;
}

static int shadow_output(struct shadow_if_info *sii, struct rte_mbuf *m,
			 struct ifnet *ifp)
{
	struct rte_ether_hdr *hdr = ethhdr(m);
	struct ifnet *team;

	if (!(ifp->if_flags & IFF_UP))
		return -1;

	dp_pktmbuf_l2_len(m) = RTE_ETHER_HDR_LEN;

	team = rcu_dereference(ifp->aggregator);

	if (unlikely(hdr->ether_type == htons(RTE_ETHER_TYPE_SLOW))) {
		if (team) {
			int ret = lag_etype_slow_tx(team, ifp, m);

			return ret;
		}
	}

	if (team) {
		if (!(team->if_flags & IFF_UP))
			return -1;
		ifp = team;
	}

	uint16_t vif = vid_from_pkt(m, if_tpid(ifp));
	if (vif) {
		/* Account for slowpath packets on VLAN */
		struct ifnet *vifp = if_vlan_lookup(ifp, vif);

		if (vifp) {
			vid_decap(m, if_tpid(ifp));
			ifp = vifp; /* use the VIF interface for rules, etc */

			if (vifp->qinq_outer) {
				struct ifnet *cvlan;
				uint16_t vid = vid_decap(m,
							 RTE_ETHER_TYPE_VLAN);

				cvlan = if_vlan_lookup(vifp,
						       vid & VLAN_VID_MASK);
				if (cvlan)
					ifp = cvlan; /* use inner interface */
			}
			hdr = ethhdr(m); /* need header inside VLAN */
		}
	}

	pktmbuf_set_vrf(m, if_vrfid(ifp));
	pktmbuf_mdata_set(m, PKT_MDATA_FROM_US);

	/*
	 * Apply post-routing features to IPv4 and IPv6 packets, and
	 * output the packet.
	 */
	sii->ts_errors += shadow_feature_if_output(ifp, m, hdr);

	return 0;
}

/* Move packets from TAP device to port
 * In order to handle Jumbo packets, need to pre-stage packet
 * in buffer on stack;
 */
int tap_reader(zloop_t *loop, zmq_pollitem_t *item, void *arg)
{
	struct shadow_if_info *sii = arg;
	struct ifnet *ifp = ifport_table[sii->port];
	struct rte_mbuf *m = NULL;

	int ret = tap_receive(loop, item, sii, &m);

	if (ret <= 0)
		return ret;

	dp_rcu_thread_online();

	if (shadow_output(sii, m, ifp) < 0)
		goto drop;

	++sii->ts_packets;
	dp_rcu_thread_offline();
	return 0;
 drop:
	++sii->ts_errors;
	rte_pktmbuf_free(m);

	dp_rcu_thread_offline();
	return 0;
}

/* Read packet with meta data from .spathintf */
int spath_reader(zloop_t *loop __rte_unused, zmq_pollitem_t *item,
		 void *arg)
{
	struct tun_pi pi;
	struct tun_meta meta;
	struct rte_ether_hdr *ether;
	struct ifnet *ifp = NULL, *host_ifp, *s2s_ifp = NULL;
	struct rte_mbuf *m = NULL;
	enum cont_src_en cont_src = CONT_SRC_MAIN;
	struct shadow_if_info *sii = arg;
	struct next_hop *nh = NULL;

	int ret = spath_receive(item, &pi, &meta, sii, &m);

	if (ret <= 0)
		return ret;

	dp_rcu_thread_online();

	if (!(meta.flags & TUN_META_FLAG_IIF)) {
		RTE_LOG(ERR, DATAPLANE,	"spath missing iif\n");
		goto drop;
	}

	ifp = dp_ifnet_byifindex(meta.iif);

	if (ifp)
		cont_src = ifp->if_cont_src;

	m->port = DATAPLANE_SPATH_PORT;

	host_ifp = get_lo_ifp(cont_src);
	if (!host_ifp)
		goto drop;

	/*
	 * The packet that we get is L3 only, so add an L2 header if needed.
	 * pi.proto is in network byte order.
	 */
	if (!ifp || (!(is_gre(ifp) && gre_encap_l2_frame(ntohs(pi.proto))) &&
		     !(is_bridge(ifp) || is_l2vlan(ifp)))) {
		if (rte_pktmbuf_prepend(m,
					sizeof(struct rte_ether_hdr)) == NULL)
			goto drop;
		dp_pktmbuf_l2_len(m) = RTE_ETHER_HDR_LEN;
		ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		ether->ether_type = pi.proto;

		/*
		 * Save the ether_type in metadata in case this packet has
		 * to go back down .spathintf later. We MUST not set the
		 * TUN_META_FLAGS_IIF flag or the kernel would bounce it
		 * back to us as IIF is a tunnel.
		 */
		set_spath_rx_meta_data(m, NULL, ntohs(pi.proto),
				       TUN_META_FLAGS_NONE);
	}

	pktmbuf_mdata_set(m, PKT_MDATA_FROM_US);

	if (!ifp) {
		/*
		 * This is the s2s case. If there is a mark then it
		 * represents the ifindex that is part of the selector,
		 * or if no ifindex in the selector then the vrf.
		 */
		if (meta.flags & TUN_META_FLAG_MARK) {
			struct ifnet *temp_ifp = dp_ifnet_byifindex(meta.mark);

			if (temp_ifp) {
				pktmbuf_set_vrf(m, if_vrfid(temp_ifp));
				if (temp_ifp->if_type != IFT_VRF) {
					/* set s2s_ifp for later */
					s2s_ifp = temp_ifp;
				}
			}
		}
		/*
		 * Need to setup the L3 len in the mbuf if this is an
		 * IPv4 packet.  Site to site packets , are
		 * arriving with their proto in the reverse byte
		 * order.
		 */
		if (ntohs(pi.proto) == RTE_ETHER_TYPE_IPV4)
			dp_pktmbuf_l3_len(m) = iphdr(m)->ihl << 2;
	}

	if (!ifp) {
		/*
		 * If the packet matches an outbound IPsec
		 * policy, send it to the crypto. If it comes
		 * back with a next hop, then it has a virtual
		 * feature point configured which might have
		 * output features we need to run before encryption.
		 */

		if (likely((ntohs(pi.proto)) == RTE_ETHER_TYPE_IPV4) ||
		    likely((ntohs(pi.proto)) == RTE_ETHER_TYPE_IPV6)) {
			struct next_hop nh46 = {.u.ifp = s2s_ifp};

			if (s2s_ifp)
				nh = &nh46;

			if (unlikely
			    (crypto_policy_check_outbound(host_ifp, &m,
							  RT_TABLE_MAIN,
							  pi.proto,
							  &nh)))
				goto rcu_offline;
			else if (nh)
				ifp = dp_nh_get_ifp(nh);
			else
				goto drop;
		}
		/* Locally generated packets by kernel might not have iif set */
		if (!ifp)
			goto drop;
	}

	if ((ifp->if_flags & IFF_UP) && ((ifp->if_flags & IFF_POINTOPOINT) ||
					 is_tunnel(ifp) || is_bridge(ifp) ||
					 is_l2vlan(ifp) ||
					 is_s2s_feat_attach(ifp))) {
		if (is_bridge(ifp) || is_l2vlan(ifp)) {
			ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			dp_pktmbuf_l2_len(m) = RTE_ETHER_HDR_LEN;
			shadow_feature_if_output(ifp, m, ether);
		} else if (is_gre(ifp)) {
			const in_addr_t *dst;

			if (!(meta.flags & TUN_META_FLAG_MARK))
				dst = NULL;
			else
				dst = mgre_nbma_to_tun_addr(ifp, &meta.mark);

			bool consumed = false;
			if (likely(pi.proto == htons(RTE_ETHER_TYPE_IPV4)))
				consumed = ip_spath_filter(ifp, &m);
			else if (likely(pi.proto == htons(RTE_ETHER_TYPE_IPV6)))
				consumed = ip6_spath_filter(ifp, &m);
			if (!consumed)
				gre_tunnel_fragment_and_send(
					host_ifp, ifp, dst, m,
					ntohs(pi.proto));
		} else if (is_vti(ifp) || is_s2s_feat_attach(ifp)) {
			ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			struct iphdr *ip = iphdr(m);
			bool consumed = false;
			if (likely(ip->version == 4))
				consumed = ip_spath_filter(ifp, &m);
			else if (likely(ip->version == 6))
				consumed = ip6_spath_filter(ifp, &m);
			if (!consumed) {
				if_output(ifp, m, host_ifp,
					  ntohs(ether->ether_type));
			}
		} else {
			if (likely(pi.proto == htons(RTE_ETHER_TYPE_IPV4))) {
				struct pl_packet pl_pkt = {
					.mbuf = m,
					.l2_pkt_type = L2_PKT_UNICAST,
					.in_ifp = ifp,
				};
				pipeline_fused_ipv4_validate(&pl_pkt);
			} else if (likely(pi.proto ==
						htons(RTE_ETHER_TYPE_IPV6))) {
				struct pl_packet pl_pkt = {
					.mbuf = m,
					.in_ifp = ifp,
				};
				pipeline_fused_ipv6_validate(&pl_pkt);
			}
		}

		goto rcu_offline;
	}

 drop:
	if (ifp)
		if_incr_oerror(ifp);
	else
		++sii->ts_errors;

	rte_pktmbuf_free(m);

rcu_offline:
	if (sii)
		++sii->ts_packets;
	dp_rcu_thread_offline();
	return 0;
}

static void del_handler_tap_fd(zloop_t *loop, struct shadow_if_info *sii)
{
	if (!sii || (sii->fd <= 0))
		return;

	zmq_pollitem_t tap_poll = {
		.fd = sii->fd,
		.events = ZMQ_POLLIN,
		.socket = NULL,
	};
	zloop_poller_end(loop, &tap_poll);
}

static int
shadow_send_event(enum shadow_ev type, portid_t port,
		  const char *ifname, const struct rte_ether_addr *eth)
{
	zsock_t *sock = zsock_new_req(shadow_inproc);
	int rv;
	int call_rv;

	if (!sock)
		return -1;

	rv = zsock_bsend(sock, "12ppp", type, port, ifname, eth, &call_rv);
	if (rv < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"shadow: failed to send event %d for port %u\n",
			type, port);
		goto cleanup;
	}

	rv = zsock_wait(sock);
	if (rv < 0)
		goto cleanup;

	rv = call_rv;

cleanup:
	zsock_destroy(&sock);
	return rv;
}

static bool
shadow_port_needed(portid_t port)
{
	return (is_local_controller() || if_port_is_uplink(port));
}

/* Initialize a shadow interface. */
int shadow_init_port(portid_t port, const char *ifname,
		     const struct rte_ether_addr *eth)
{
	if (!shadow_port_needed(port))
		return 0;

	return shadow_send_event(SHADOW_ADD, port, ifname, eth);
}

/* Uninitialize a shadow interface. */
void shadow_uninit_port(portid_t port)
{
	if (!shadow_port_needed(port))
		return;

	/*
	 * if called during shutdown then ignore - the thread has
	 * already or is about to terminate
	 */
	if (zsys_interrupted)
		return;

	shadow_send_event(SHADOW_REMOVE, port, NULL, NULL);
}

/* Add a fd to the tap_reader event loop */
static int add_handler_tap_fd(zloop_t *loop, struct shadow_if_info *sii)
{
	zmq_pollitem_t tap_poll = {
		.fd = sii->fd,
		.events = ZMQ_POLLIN,
		.socket = NULL,
	};

	if (zloop_poller(loop, &tap_poll, tap_reader, sii) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"zloop_poller failed\n");
		return -1;
	}

	return 0;
}

/*
 * After receiving response from controller,
 * set the interface port parameters (name, index)
 * and for local device make the tap device.
 */
int shadow_add_event(zloop_t *loop, portid_t port, const char *ifname)
{
	int socket_id = rte_eth_dev_socket_id(port);
	struct shadow_if_info *sii;
	int ret;

	sii = rte_zmalloc_socket("shadow", sizeof(struct shadow_if_info),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (!sii) {
		RTE_LOG(ERR, DATAPLANE, "shadow: malloc failed\n");
		return -ENOMEM;
	}

	char ring_name[RTE_RING_NAMESIZE];
	snprintf(ring_name, RTE_RING_NAMESIZE, "shadow%u-%016"PRIx64,
		 port, shadow_next_ring_id++);

	sii->rx_slow_ring = rte_ring_create(ring_name,
					    SHADOW_IO_RING_SIZE,
					    socket_id,
					    RING_F_SC_DEQ);

	if (!sii->rx_slow_ring) {
		RTE_LOG(ERR, DATAPLANE,
			"shadow ring %s create failed\n", ring_name);
		ret = -ENOMEM;
		goto fail_free;
	}

	sii->port = port;
	sii->wake_me = true;

	sii->fd = tap_attach(ifname);
	if (sii->fd < 0) {
		ret = -errno;
		goto fail_ring_free;
	}
	if (add_handler_tap_fd(loop, sii) < 0) {
		ret = -ENOMEM;
		goto fail_close;
	}

	rcu_assign_pointer(shadow_if[port], sii);

	return 0;

fail_close:
	close(sii->fd);
fail_ring_free:
	rte_ring_free(sii->rx_slow_ring);
fail_free:
	rte_free(sii);
	return ret;
}

static void shadow_free_rcu(struct rcu_head *head)
{
	struct shadow_if_info *sii =
		caa_container_of(head, struct shadow_if_info, rcu);

	close(sii->fd);
	rte_ring_free(sii->rx_slow_ring);
	rte_free(sii);
}

static void shadow_remove_event(zloop_t *loop, portid_t port)
{
	struct shadow_if_info *sii;
	struct rte_mbuf *m;

	sii = shadow_if[port];

	if (sii == NULL)
		return;

	rcu_assign_pointer(shadow_if[port], NULL);

	del_handler_tap_fd(loop, sii);

	/*
	 * Drain ring
	 */
	while (rte_ring_sc_dequeue(sii->rx_slow_ring, (void **) &m) == 0)
		rte_pktmbuf_free(m);

	call_rcu(&sii->rcu, shadow_free_rcu);
}

/* Handle thread cancellation */
static void shadow_cleanup(void *arg)
{
	zloop_t **loop = arg;

	zloop_destroy(loop);
	dp_rcu_unregister_thread();
}

static int shadow_handle_event(zloop_t *loop, zsock_t *sock,
			       void *arg __rte_unused)
{
	const struct rte_ether_addr *addr;
	const char *ifname;
	portid_t port;
	uint8_t type;
	int rv;
	int *call_rv;

	rv = zsock_brecv(sock, "12ppp", &type, &port, &ifname, &addr,
			 &call_rv);
	if (rv >= 0) {
		*call_rv = 0;
		dp_rcu_thread_online();
		rcu_read_lock();
		switch (type) {
		case SHADOW_ADD:
			*call_rv = shadow_add_event(loop, port, ifname);
			break;
		case SHADOW_REMOVE:
			shadow_remove_event(loop, port);
			break;
		default:
			RTE_LOG(ERR, DATAPLANE,
				"shadow-event: unknown event type %d\n", type);
			*call_rv = -EINVAL;
			break;
		}
		rcu_read_unlock();
		dp_rcu_thread_offline();
	} else {
		RTE_LOG(ERR, DATAPLANE,
			"shadow-event: failed to receive event\n");
	}

	/*
	 * Note: zsock_signal takes a byte, so we signal the success
	 * or failure of the call separately through the call_rv
	 * parameter.
	 */
	if (zsock_signal(sock, 0) != 0)
		RTE_LOG(ERR, DATAPLANE,
				"shadow-event: failed to signal socket\n");

	return 0;
}

/* main thread loop for processing TUNTAP and GRE packets */
static void *shadow_handler(void *args)
{
	zloop_t *loop;

	lfd = *(int *) args;

	pthread_setname_np(pthread_self(), "dataplane/slow");

	loop = zloop_new();
	if (!loop)
		rte_panic("shadow handler zloop failed\n");
	pthread_cleanup_push(shadow_cleanup, &loop);

	struct sched_param sched = { 0 };
	int err = pthread_setschedparam(pthread_self(), SCHED_BATCH, &sched);
	if (err != 0)
		RTE_LOG(NOTICE, DATAPLANE,
			"shadow setschedparam failed: %s\n", strerror(err));

	zloop_reader(loop, shadow_server_sock, shadow_handle_event,
		     NULL);
	zloop_reader_set_tolerant(loop, shadow_server_sock);

	/* poll event fd to wakeup shadow writer */
	zmq_pollitem_t event_poll = {
		.fd = event_fd,
		.events = ZMQ_POLLIN,
	};
	zloop_poller(loop, &event_poll, shadow_writer, NULL);

	/* poll slowpath TUN file(local) */
	zmq_pollitem_t local_poll = {
		.fd = lfd,
		.events = ZMQ_POLLIN,
	};

	if (zloop_poller(loop, &local_poll, spath_reader,
			 shadow_if[DATAPLANE_SPATH_PORT]) < 0)
		rte_panic("spath poller setup failed\n");

	dp_rcu_register_thread();
	dp_rcu_thread_offline();

	while (!zsys_interrupted) {
		if (zloop_start(loop) != 0)
			break;		/* error detected */
	}

	pthread_cleanup_pop(1);

	return NULL;
}

/* Setup global data for shadow */
static void
shadow_init(void)
{
	event_fd = eventfd(0, EFD_NONBLOCK);
	if (event_fd < 0)
		rte_panic("Cannot open event fd\n");

	/* Open local device.
	 * Must be done in this thread
	 * therwise uid change may race with shadow thread
	 */
	shadow_fd = slowpath_init();

	shadow_server_sock = zsock_new_rep(shadow_inproc);
	if (!shadow_server_sock)
		rte_panic("cannot bind to shadow server socket\n");

	if (pthread_create(&shadow_thread, NULL,
			   shadow_handler, &shadow_fd) < 0)
		rte_panic("shadow thread creation failed\n");
}

static void
shadow_destroy(void)
{
	int join_rc;
	struct shadow_if_info *sii;

	pthread_cancel(shadow_thread);
	join_rc = pthread_join(shadow_thread, NULL);
	if (join_rc != 0)
		RTE_LOG(ERR, DATAPLANE,
			"shadow thread join failed, rc %i\n", join_rc);
	zsock_destroy(&shadow_server_sock);
	close(shadow_fd);
	sii = shadow_if[DATAPLANE_SPATH_PORT];
	rte_ring_free(sii->rx_slow_ring);
}

/* Display shadow interface statistics */
void shadow_show_summary(FILE *f, const char *name)
{
	json_writer_t *wr = jsonw_new(f);
	unsigned int port;
	bool is_spathintf;

	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "interfaces");
	jsonw_start_array(wr);
	for (port = 0; port <= DATAPLANE_MAX_PORTS; port++) {
		is_spathintf = (port == DATAPLANE_MAX_PORTS);

		const struct shadow_if_info *sii =
			rcu_dereference(shadow_if[port]);
		const struct ifnet *ifp = is_spathintf ? NULL :
			rcu_dereference(ifport_table[port]);

		if (!sii ||
		    (!is_spathintf &&
		     (!ifp || !rte_eth_dev_is_valid_port(port))))
			continue;

		if (name && ifp && strcmp(name, ifp->if_name) != 0)
			continue;

		jsonw_start_object(wr);
		jsonw_string_field(wr, "name",
				ifp ? ifp->if_name : ".spathintf");
		jsonw_uint_field(wr, "rx_packet", sii->rs_packets);
		jsonw_uint_field(wr, "rx_dropped", sii->rs_infull);
		jsonw_uint_field(wr, "rx_errors", sii->rs_errors);
		jsonw_uint_field(wr, "rx_overrun", sii->rs_overrun);
		jsonw_uint_field(wr, "rx_congested", sii->rs_congested);

		jsonw_uint_field(wr, "tx_packet", sii->ts_packets);
		jsonw_uint_field(wr, "tx_errors", sii->ts_errors);
		jsonw_uint_field(wr, "tx_nobufs", sii->ts_nobufs);

		jsonw_name(wr, "rx_ring");
		const struct rte_ring *r = sii->rx_slow_ring;
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "used", rte_ring_count(r));
		jsonw_uint_field(wr, "avail", rte_ring_free_count(r));
		jsonw_end_object(wr);

		jsonw_end_object(wr);
		if (name)
			break;
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

void
set_spath_rx_meta_data(struct rte_mbuf *m, const struct ifnet *ifp,
		       uint16_t proto, uint8_t meta_mask)
{
	struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);
	const struct iphdr *ip = iphdr(m);

	mdata->md_spath = (struct pkt_mdata_spath) {
		.pi = {
			.flags = TUN_PKT_STRIP,
			.proto = htons(proto),
		},
		.meta = {
			.flags = meta_mask,
			.iif = ((meta_mask & TUN_META_FLAG_IIF) && ifp) ?
					ifp->if_index : 0,
			.mark = (meta_mask & TUN_META_FLAG_MARK) ?
					ip->saddr : 0,
		},
	};
	pktmbuf_mdata_invar_set(m, PKT_MDATA_INVAR_SPATH);
}

struct shadow_if_info *get_port2shadowif(portid_t portid)
{
	int i;
	struct shadow_if_info *sii;

	for (i = 0; i <  DATAPLANE_MAX_PORTS+1; i++) {
		sii = rcu_dereference(shadow_if[i]);
		if (sii && sii->port == portid)
			return sii;
	}

	return NULL;
}

struct shadow_if_info *get_fd2shadowif(int fd)
{
	int i;
	struct shadow_if_info *sii;

	for (i = 0; i <  DATAPLANE_MAX_PORTS+1; i++) {
		sii = rcu_dereference(shadow_if[i]);
		if (sii && sii->fd == fd)
			return sii;
	}

	return NULL;
}

static const struct dp_event_ops shadow_events = {
	.init = shadow_init,
	.uninit = shadow_destroy,
};

DP_STARTUP_EVENT_REGISTER(shadow_events);
