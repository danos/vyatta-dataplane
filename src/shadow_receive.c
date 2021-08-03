/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2012-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <alloca.h>
#include <czmq.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#include <zmq.h>
#include <linux/if.h>

#define _LINUX_IP_H
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include <rte_eth_bond.h>
#include <rte_eth_bond_8023ad.h>

#include "compat.h"
#include "config_internal.h"
#include "ether.h"
#include "if/bridge/bridge_port.h"
#include "if_var.h"
#include "l2_rx_fltr.h"
#include "l2tp/l2tpeth.h"
#include "pktmbuf_internal.h"
#include "pipeline/nodes/pppoe/pppoe.h"
#include "shadow.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"
#include "vrf_internal.h"

struct rte_mempool;

#define GRE_OVERHEAD_IPV4 32  /* IP + GRE + VLAN */
#define GRE_OVERHEAD_IPV6 52  /* IPv6 + GRE + VLAN */
#define MIN_GRE_PKT  42  /* IP + GRE + Ether */

#define ESMC_ETH_SUBTYPE   0x0A

static struct rte_mbuf *pkt_to_mbuf(struct rte_mempool *mp, vrfid_t vrf_id,
				    const uint8_t *pkt, int len)
{
	struct rte_mbuf *m0, **top;
	int offset;

	offset = 0;
	m0 = NULL;
	top = &m0;
	do {
		struct rte_mbuf *m = pktmbuf_alloc(mp, vrf_id);

		if (unlikely(m == NULL)) {
			if (m0)
				dp_pktmbuf_notify_and_free(m0);
			return NULL;
		}

		uint16_t seg_len = RTE_MIN(len,
					   m->buf_len - RTE_PKTMBUF_HEADROOM);
		memcpy(rte_pktmbuf_mtod(m, char *), pkt + offset, seg_len);
		rte_pktmbuf_data_len(m) = seg_len;
		m->nb_segs = 1;

		*top = m;
		top = &m->next;
		if (m == m0)
			rte_pktmbuf_pkt_len(m) = len;
		else
			++m0->nb_segs;

		offset += seg_len;
		len -= seg_len;
	} while (len > 0);

	return m0;
}

static uint16_t rte_mbuf_buf_size(struct rte_mempool *pool)
{
	return rte_pktmbuf_data_room_size(pool) - RTE_PKTMBUF_HEADROOM;
}

int tap_receive(zloop_t *loop, zmq_pollitem_t *item,
		struct shadow_if_info *sii, struct rte_mbuf **pkt)
{
	struct ifnet *ifp = ifnet_byport(sii->port);
	/* 8 is added to allow space for 2 VLAN headers (i.e. QinQ) */
	const size_t max_pkt = ifp->if_mtu + RTE_ETHER_HDR_LEN + 8;
	void *base;
	ssize_t len;
	struct rte_mbuf *m = NULL;
	portid_t portid;

	/*
	 * Use the mbuf pool for portid 0 for virtual interfaces, as these have
	 * no valid portid. This is safe, as the mbuf pool stays in use even if
	 * the device for portid 0 is unplugged.
	 */
	portid = ifp->if_port == IF_PORT_ID_INVALID ? 0 : ifp->if_port;

	/* optimize for in-place receive if not doing jumbo packets */
	if (max_pkt <= rte_mbuf_buf_size(mbuf_pool(portid)))
		m = pktmbuf_alloc(mbuf_pool(portid), if_vrfid(ifp));

	if (m)
		base = rte_pktmbuf_mtod(m, char *);
	else
		base = alloca(max_pkt);

	len = read(item->fd, base, max_pkt);
	if (len < 0) {
		if (m)
			dp_pktmbuf_notify_and_free(m);

		if (errno == EINTR || errno == EAGAIN)
			return 0;

		if (errno == EBADFD || errno == EBADF) {
			RTE_LOG(INFO, DATAPLANE,
				"tap read stale fd. Cleaning up\n");
			zloop_poller_end(loop, item);
			return 0;
		}

		RTE_LOG(ERR, DATAPLANE,
			"tap read error on port %u: %s\n", sii->port,
			strerror(errno));
		return -1;
	}

	if (m)
		rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m) = len;
	else {
		m = pkt_to_mbuf(mbuf_pool(portid), if_vrfid(ifp), base, len);
		if (m == NULL) {
			++sii->ts_nobufs;
			return 0;
		}
	}

	*pkt = m;
	return 1;
}

int spath_receive(zmq_pollitem_t *item, struct tun_pi *pi,
		  struct tun_meta *meta, struct shadow_if_info *sii,
		  struct rte_mbuf **mbuf)
{
	ssize_t len;
	struct iovec io[3];
	uint8_t pkt[RTE_ETHER_MAX_JUMBO_FRAME_LEN];
	struct ifnet *ifp = NULL;
	vrfid_t vrf_id = VRF_DEFAULT_ID;
	portid_t portid;

	/*
	 * Use the mbuf pool for portid 0 when there is no associated ifp, or if
	 * there is no valid portid e.g. for virtual interfaces. This is safe,
	 * as it stays in use even if the device for portid 0 is unplugged.
	 */
	portid = 0;

	io[0].iov_base = pi;
	io[0].iov_len = sizeof(*pi);
	io[1].iov_base = meta;
	io[1].iov_len = sizeof(*meta);
	io[2].iov_base = pkt;
	io[2].iov_len = sizeof(pkt);

	len = readv(item->fd, io, 3);
	if (len < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

		RTE_LOG(ERR, DATAPLANE,
			"spath tap read error: %s\n", strerror(errno));
		return -1;
	}

	len -= sizeof(*pi);
	len -= sizeof(*meta);
	if (len <= 0) {
		RTE_LOG(ERR, DATAPLANE,	"spath short packet\n");
		return -1;
	}

	ifp = dp_ifnet_byifindex(meta->iif);
	if (ifp) {
		portid = ifp->if_port == IF_PORT_ID_INVALID ? 0 : ifp->if_port;
		vrf_id = if_vrfid(ifp);
	}

	struct rte_mbuf *m = pkt_to_mbuf(mbuf_pool(portid), vrf_id, pkt, len);

	if (m == NULL) {
		++sii->ts_nobufs;
		return 0;
	}

	*mbuf = m;
	return 1;
}

/* Create new TUN/TAP device for VPN slow path */
int slowpath_init(void)
{
	int fd;
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR|O_NDELAY);
	if (fd < 0)
		rte_panic("can not open /dev/net/tun device: %s\n",
			  strerror(errno));

	memset(&ifr, 0, sizeof(ifr));

	/* Special hidden interface only used for tunnels */
	snprintf(ifr.ifr_name, IFNAMSIZ, ".spathintf");
	ifr.ifr_flags = IFF_TUN | IFF_META_HDR | IFF_POINTOPOINT;

	/* Set the name and type of new endpoint */
	if (ioctl(fd, TUNSETIFF, &ifr) < 0)
		rte_panic("ioctl(TUNSETIFF) failed: %s\n",
			  strerror(errno));

	/* Tell IPv6 to ignore this interface */
	FILE *f = fopen("/proc/sys/net/ipv6/conf/.spathintf/disable_ipv6", "w");

	if (f) {
		fprintf(f, "1\n");
		fclose(f);
	}

	/* Bring device up */
	int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (udp_fd < 0)
		rte_panic("UDP socket?\n");

	if (ioctl(udp_fd, SIOCGIFFLAGS, &ifr) < 0)
		rte_panic("ioctl(SIOCGIFFLAGS)\n");

	ifr.ifr_flags |= IFF_UP;
	if (ioctl(udp_fd, SIOCSIFFLAGS, &ifr) < 0)
		rte_panic("ioctl(SIOCSIFFLAGS)\n");

	close(udp_fd);

	/* Create slowpath rx ring for packets going to kernel */
	shadow_init_spath_ring(fd);

	return fd;
}

/* Setup TUN/TAP device */
int tap_attach(const char *ifname)
{
	struct ifreq ifr;
	int fd;

	memset(&ifr, 0, sizeof(ifr));

	fd = open("/dev/net/tun", O_RDWR|O_NDELAY);
	if (fd < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"can not open /dev/net/tun device: %s\n",
			strerror(errno));
		return fd;
	}

	if (strlen(ifname) >= IFNAMSIZ)
		RTE_LOG(NOTICE, DATAPLANE,
			"Truncating too long interface name - tap: %s\n",
			ifname);
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	/* Set the name and type of new endpoint */
	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"ioctl(TUNSETIFF) failed: %s\n",
			strerror(errno));
		goto fail;
	}

	return fd;

fail:
	close(fd);
	return -1;
}

/* Collect fragmented mbuf and send to TAP device
 * Note: this function builds meta data to send to TAP device
 *  onto stack by using alloca() before sending.
 */
int tuntap_write(int fd, struct rte_mbuf *m, struct ifnet *ifp)
{
	unsigned int n = 0;
	struct iovec iov[m->nb_segs + 3];

	/* When sending packets of .spathintf more information
	 * needs to be passed.
	 */
	if (pktmbuf_mdata_invar_exists(m, PKT_MDATA_INVAR_SPATH)) {
		struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);

		if (mdata->md_spath.pi.proto) {
			iov[n].iov_base = &mdata->md_spath.pi;
			iov[n].iov_len  = sizeof(struct tun_pi)
				+ sizeof(struct tun_meta);
		} else {
			iov[n].iov_base = &mdata->md_spath.meta;
			iov[n].iov_len  = sizeof(struct tun_meta);
		}
		++n;
	}

	/* If received packet had VLAN tag,
	 * push 802.1q header in front of packet
	 */
	if (m->ol_flags & PKT_RX_VLAN) {
		bool sw_qinq_inner = false;
		uint16_t sw_outer_vlan;
		const struct rte_ether_hdr *oeh
			= rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);

		if (!ifp) {
			/*
			 * Interface has been deleted in between the
			 * packet being enqueued and it being dequeued
			 * and processed here.
			 */
			errno = ENODEV;
			return -1;
		}

		if (pktmbuf_mdata_invar_exists(m, PKT_MDATA_INVAR_BRIDGE)) {
			struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);

			sw_outer_vlan  = mdata->md_bridge.outer_vlan;
			if (sw_outer_vlan)
				sw_qinq_inner = true;
		}

		if (!ifp->qinq_inner && !sw_qinq_inner) {
			struct {
				struct rte_ether_hdr eh;
				struct rte_vlan_hdr vh;
			} *vhdr = alloca(sizeof(*vhdr));

			memcpy(&vhdr->eh, oeh, 2 * RTE_ETHER_ADDR_LEN);
			vhdr->eh.ether_type = htons(if_tpid(ifp));
			vhdr->vh.vlan_tci = htons(m->vlan_tci);
			vhdr->vh.eth_proto = oeh->ether_type;

			iov[n].iov_base = vhdr;
			iov[n].iov_len  = sizeof(*vhdr);
			++n;
		} else {
			struct {
				struct rte_ether_hdr eh;
				struct rte_vlan_hdr vh1;
				struct rte_vlan_hdr vh2;
			} *qinqhdr = alloca(sizeof(*qinqhdr));

			memcpy(&qinqhdr->eh, oeh, 2 * RTE_ETHER_ADDR_LEN);
			if (!sw_qinq_inner) {
				qinqhdr->eh.ether_type =
					htons(if_tpid(ifp->if_parent));
				qinqhdr->vh1.vlan_tci = htons(m->vlan_tci);
				qinqhdr->vh2.vlan_tci = htons(ifp->if_vlan);
			} else {
				qinqhdr->eh.ether_type = htons(if_tpid(ifp));
				qinqhdr->vh1.vlan_tci = htons(sw_outer_vlan);
				qinqhdr->vh2.vlan_tci = htons(m->vlan_tci);
			}
			qinqhdr->vh1.eth_proto = htons(RTE_ETHER_TYPE_VLAN);
			qinqhdr->vh2.eth_proto = oeh->ether_type;

			iov[n].iov_base = qinqhdr;
			iov[n].iov_len  = sizeof(*qinqhdr);

			++n;
		}

		/* Skip original Ethernet header in the data packet */
		iov[n].iov_base = dp_pktmbuf_mtol3(m, char *);
		iov[n].iov_len  = rte_pktmbuf_data_len(m) -
			dp_pktmbuf_l2_len(m);
		++n;

		m = m->next;
	}

	while (m) {
		iov[n].iov_base = rte_pktmbuf_mtod(m, void *);
		iov[n].iov_len = rte_pktmbuf_data_len(m);
		++n;
		m = m->next;
	}

	return writev(fd, iov, n);
}

/*
 * Filter and mangle local packets
 * returns false if packet is unwanted.
 */
bool local_packet_filter(const struct ifnet *ifp, struct rte_mbuf *m)
{
	const struct rte_ether_hdr *eh = ethhdr(m);
	struct slow_protocol_frame *slow_hdr;

	/* Filter out unwanted multicasts */
	if (rte_is_multicast_ether_addr(&eh->d_addr) &&
	    ifp->if_mac_filtr_active &&
	    l2_mcfltr_node_lookup(ifp, &eh->d_addr) == NULL)
		return false;

	if (ifp->if_type == IFT_BRIDGE) {
		struct ifnet *in_ifp = ifnet_byport(m->port);

		if (in_ifp) {
			struct bridge_port *brport;
			struct ifnet *aggregator;

			/*
			 * teams uses the ifp of the aggregator but keep the
			 * portid of the receiving port
			 */
			aggregator = rcu_dereference(in_ifp->aggregator);
			if (aggregator)
				in_ifp = aggregator;

			brport = rcu_dereference(in_ifp->if_brport);
			if (unlikely(brport &&
				     bridge_port_get_bridge(brport) != ifp)) {
				if (l2tp_undo_decap_br(ifp, m) < 0)
					return false;	/* decap failed */
			}
		} else {
			return false;
		}

	} else if ((ifp->if_type == IFT_L2TPETH) ||
		   (ifp->if_parent &&
		    (ifp->if_parent->if_type == IFT_L2TPETH))) {

		if (l2tp_undo_decap(ifp, m) < 0)
			return false;

	} else if (ifp->if_type == IFT_PPP) {
		/* Something went wrong, we have an IFT_PPP without
		 * accompanying session information
		 */
		void *conn = rcu_dereference(ifp->if_softc);
		if (!conn)
			return false;

		/* Packet coming from pipeline is in host byte order */
		ppp_do_encap(m, conn, htons(eh->ether_type), false);

	} else if (!pktmbuf_mdata_invar_exists(m, PKT_MDATA_INVAR_SPATH) &&
		   is_vti(ifp)) {
		set_spath_rx_meta_data(m, ifp, ntohs(eh->ether_type),
				       TUN_META_FLAGS_DEFAULT);
	} else if (!ifp->aggregator) {
		if (eh->ether_type == htons(RTE_ETHER_TYPE_SLOW)) {
			slow_hdr = rte_pktmbuf_mtod(m,
					struct slow_protocol_frame *);
			/* Allow ESMC frames on the interface */
			if (slow_hdr && (slow_hdr->slow_protocol.subtype !=
						ESMC_ETH_SUBTYPE))
				return false;
		}
	}

	return true;
}
