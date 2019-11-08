/*
 * Functions for handling l2tpeth data path operations.
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <urcu/list.h>

#include "bridge.h"
#include "bridge_port.h"
#include "ether.h"
#include "if_var.h"
#include "in_cksum.h"
#include "l2tpeth.h"
#include "pktmbuf.h"
#include "urcu.h"
#include "util.h"
#include "vrf.h"


#define chk_bit(x, m1, m2) (((x) & (m1)) == (m2))
#define chk_mask(x, m) chk_bit(x, m, m)
#define MASK_L2TPUDPV4 (L2TP_ENCAP_UDP|L2TP_ENCAP_IPV4)


static inline bool is_l2tp_udpv4(const struct l2tp_session *s)
{
	return chk_mask(s->flags, MASK_L2TPUDPV4);
}

static inline bool is_l2tp_udpv6(const struct l2tp_session *s)
{
	return chk_bit(s->flags, MASK_L2TPUDPV4, L2TP_ENCAP_UDP);
}

static inline bool is_l2tp_ipv4(const struct l2tp_session *s)
{
	return chk_bit(s->flags, MASK_L2TPUDPV4, L2TP_ENCAP_IPV4);
}

static inline bool is_l2tp_ipv6(const struct l2tp_session *s)
{
	return chk_bit(s->flags, MASK_L2TPUDPV4, 0);
}

/* Check for T bit and version in a packet */
static inline bool is_hdr_l2tp_udp(const void *phdr)
{
	return chk_bit(ntohs(*(const uint16_t *)phdr), 0x800f, 3);
}

static inline int l2tp_opt_hdrlen(const struct l2tp_session *s)
{
	return s->peer_cookie_len + ((s->flags & L2TP_ENCAP_SEQ) ? 4 : 0);
}

/* check new sequence after old sequence in modulo 0x1000000 */
static inline bool l2tp_seq_after(uint32_t ns, uint32_t olds)
{
	return (ns + 0x1000000U - olds) > 0x1000000U;
}

/*
 * adjust mbuf and if required change vlan tag
 */
static void l2tp_decap(struct rte_mbuf *m, uint32_t offset)
{
	struct ether_hdr *eth = NULL;

	rte_pktmbuf_adj(m, offset);

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	if (eth->ether_type != htons(ETHER_TYPE_VLAN)) {
		m->ol_flags &= ~PKT_RX_VLAN;
		return;
	}

	/* Adjust vlan information */
	struct vlan_hdr *vh = (struct vlan_hdr *) (eth + 1);

	m->vlan_tci = ntohs(vh->vlan_tci);
	m->ol_flags |= PKT_RX_VLAN;

	memmove((char *)eth + sizeof(struct vlan_hdr), eth, 2 * ETHER_ADDR_LEN);
	rte_pktmbuf_adj(m, sizeof(struct vlan_hdr));
}


/*
 * Receive encapsulated packets from a l2tpv3 peer
 *
 * -- RFC3931:
 *   The peer LCCE receiving the L2TP data packet identifies the session
 *   with which the packet is associated by the Session ID in the data
 *   packet's header.  The LCCE then checks the Cookie field in the data
 *   packet against the Cookie value received in the Assigned Cookie AVP
 *   during session establishment.  It is important for implementers to
 *   note that the Cookie field check occurs after looking up the session
 *   context by the Session ID, and as such, consists merely of a value
 *   match of the Cookie field and that stored in the retrieved context.
 *   There is no need to perform a lookup across the Session ID and Cookie
 *   as a single value.  Any received data packets that contain invalid
 *   Session IDs or associated Cookie values MUST be dropped.  Finally,
 *   the LCCE either forwards the network packet within the tunneled frame
 *   (e.g., as an LNS) or switches the frame to a circuit (e.g., as an
 *   LAC).
 *
 * For cross-connect - enqueue the packet to outgoing dataplane interface.
 * For forwarding - call ether_input with the new ethernet frames.
 * We do not try to do defrag here. The same function is called for handling
 * both ip and udp encapsulation.
 *
 */

static int l2tp_recv_encap(struct rte_mbuf *m,
		const unsigned char *l2tp, struct l2tp_session *s)
{
	struct ifnet *ifp;
	struct l2tp_stats *stats = &s->stats[dp_lcore_id()];
	unsigned int offset = (l2tp - rte_pktmbuf_mtod(m, unsigned char *))
				+ l2tp_opt_hdrlen(s);

	if (unlikely((rte_pktmbuf_data_len(m) <= offset)))
		return 1;

	if (s->peer_cookie_len != 0
		&& memcmp(l2tp, s->peer_cookie, s->peer_cookie_len)) {
		++stats->rx_cookie_discards;
		return -1; /* discard - bad cookie */
	}
	l2tp += s->peer_cookie_len;

	if (unlikely(s->flags  & L2TP_ENCAP_SEQ)) {
		uint32_t seq = ntohl(*((const uint32_t *)l2tp));

		if (seq & 0x40000000) {
			seq &= 0x00ffffff;
			if (!l2tp_seq_after(seq, s->peer_seq)) {
				++stats->rx_oos_discards;
				return -1; /* discard */
			}
			s->peer_seq = seq;
		}
	}

	ifp = rcu_dereference(s->ifp);
	if (unlikely(ifp == NULL))
		return -1;

	l2tp_decap(m, offset);
	if_incr_in(ifp, m);
	pktmbuf_prepare_decap_reswitch(m);

	if (rte_pktmbuf_data_len(m) < sizeof(struct ether_hdr)) {
		if_incr_error(ifp);
		rte_pktmbuf_free(m);
		return 0;
	}

	ether_input(ifp, m);
	return 0;
}

static inline int l2tp_verify_udpv4(const struct l2tp_session *s,
		const uint32_t saddr, const uint32_t daddr,
		const uint16_t sport, const uint16_t dport)
{
	return is_l2tp_udpv4(s)
		&& s->d_addr.ipv4.s_addr == daddr
		&& s->s_addr.ipv4.s_addr == saddr
		&& s->dport == ntohs(dport)
		&& s->sport == ntohs(sport);
}

static inline int l2tp_verify_udpv6(const struct l2tp_session *s,
		const struct in6_addr saddr, const struct in6_addr daddr,
		const uint16_t sport, const uint16_t dport)
{
	return is_l2tp_udpv6(s)
		&& !memcmp(&s->d_addr.ipv6, &daddr, sizeof(struct in6_addr))
		&& !memcmp(&s->s_addr.ipv6, &saddr, sizeof(struct in6_addr))
		&& s->dport == ntohs(dport)
		&& s->sport == ntohs(sport);
}

static inline int l2tp_verify_ipv4(const struct l2tp_session *s,
		const uint32_t saddr)
{
	return is_l2tp_ipv4(s)
		&& s->s_addr.ipv4.s_addr == saddr;
}

static inline int l2tp_verify_ipv6(const struct l2tp_session *s,
		const struct in6_addr saddr)
{
	return is_l2tp_ipv6(s)
		&& !memcmp(&s->s_addr.ipv6, &saddr, sizeof(struct in6_addr));
}

static inline struct l2tp_session *l2tp_udp_find_session(
			const unsigned char *l2tp)
{
	uint32_t sid;

	if (likely(!is_hdr_l2tp_udp(l2tp)))
		return NULL;

	sid = ((const uint32_t *)l2tp)[1];
	if (sid == 0)
		return NULL;

	return l2tp_session_byid(ntohl(sid));
}

/*
 * Following functions are called from ip_deliver() contexts.
 * We are here means all the basic length verifications were done.
 * and we at have at least the required bytes of data.
 *
 * return 0 - packet is processed and consumed
 * return -1: error - not discarded
 * return 1: continue processing.
 */

int l2tp_udpv4_recv_encap(struct rte_mbuf *m, const struct iphdr *ip,
			  const struct udphdr *udp)
{
	const uint8_t *l2tp = (const uint8_t *)(udp + 1);
	struct l2tp_session *s;
	unsigned int offset;

	if (pktmbuf_get_vrf(m) != VRF_DEFAULT_ID)
		return 1;

	offset = l2tp - rte_pktmbuf_mtod(m, const uint8_t *);
	if (rte_pktmbuf_data_len(m) < offset + L2TP_UDP_SESSION_HEADER_SIZE)
		return 1;

	s = l2tp_udp_find_session(l2tp);
	if (s == NULL)
		return 1;

	/* verify addresses and ports */
	if (!l2tp_verify_udpv4(s, ip->daddr, ip->saddr,
					udp->dest, udp->source))
		return 1;

	return l2tp_recv_encap(m, l2tp + L2TP_UDP_SESSION_HEADER_SIZE, s);
}

int l2tp_ipv4_recv_encap(struct rte_mbuf *m, const struct iphdr *ip)
{
	const uint8_t *l2tp = pktmbuf_mtol4(m, const uint8_t *);
	struct l2tp_session *s;
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	unsigned int offset;
	uint32_t sid;

	if (vrfid != VRF_DEFAULT_ID)
		return 1;

	offset = l2tp - rte_pktmbuf_mtod(m, const uint8_t *);
	if (rte_pktmbuf_data_len(m) < offset + L2TP_IP_SESSION_HEADER_SIZE)
		return 1;

	sid = *((const uint32_t *)l2tp);
	if (sid == 0)
		return 1;

	s = l2tp_session_byid(ntohl(sid));
	if (s == NULL)
		return 1;

	/* verify addresses and ports */
	if (!l2tp_verify_ipv4(s, ip->daddr))
		return 1;

	return l2tp_recv_encap(m, l2tp + L2TP_IP_SESSION_HEADER_SIZE, s);
}

int l2tp_udpv6_recv_encap(struct rte_mbuf *m, const struct ip6_hdr *ip6,
			  const struct udphdr *udp)
{
	const uint8_t *l2tp = (const uint8_t *)(udp + 1);
	struct l2tp_session *s;
	unsigned int offset;

	if (pktmbuf_get_vrf(m) != VRF_DEFAULT_ID)
		return 1;

	offset = l2tp - rte_pktmbuf_mtod(m, const uint8_t *);
	if (rte_pktmbuf_data_len(m) < offset + L2TP_UDP_SESSION_HEADER_SIZE)
		return 1;

	s = l2tp_udp_find_session(l2tp);
	if (s == NULL)
		return 1;

	/* verify addresses and ports */
	if (!l2tp_verify_udpv6(s, ip6->ip6_dst, ip6->ip6_src,
				udp->dest, udp->source))
		return 1;

	return l2tp_recv_encap(m, l2tp + L2TP_UDP_SESSION_HEADER_SIZE, s);
}

int l2tp_ipv6_recv_encap(struct rte_mbuf *m, const struct ip6_hdr *ip6,
			 const unsigned char *l2tp)
{
	struct l2tp_session *s;
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	unsigned int offset;
	uint32_t sid;

	if (vrfid != VRF_DEFAULT_ID)
		return 1;

	offset = l2tp - rte_pktmbuf_mtod(m, const unsigned char *);
	if (rte_pktmbuf_data_len(m) < offset + L2TP_IP_SESSION_HEADER_SIZE)
		return 1;

	sid = *((const uint32_t *)l2tp);
	if (sid == 0)
		return 1;

	s = l2tp_session_byid(ntohl(sid));
	if (s == NULL)
		return 1;

	/* verify addresses and ports */
	if (!l2tp_verify_ipv6(s, ip6->ip6_dst))
		return 1;

	return l2tp_recv_encap(m, l2tp + L2TP_IP_SESSION_HEADER_SIZE, s);
}

static int l2tp_undo_vlan_decap(struct rte_mbuf *m,
				const struct ifnet *ifp)
{
	if (unlikely(vid_encap(m->vlan_tci, &m, if_tpid(ifp)) == NULL))
		return -1;	/* no space for tag */

	m->ol_flags &= ~PKT_RX_VLAN;
	return 0;
}

/*
 * Functions called for undoing the decapsulation before forwarding to local.
 */

int l2tp_undo_decap(const struct ifnet *ifp, struct rte_mbuf *m)
{
	if (ifp->if_parent) {
		ifp = ifp->if_parent;

		if (l2tp_undo_vlan_decap(m, ifp) < 0)
			return -1;
	}

	const struct l2tp_softc *sc = rcu_dereference(ifp->if_softc);
	if (unlikely(sc == NULL))
		return -1;

	const struct l2tp_session *session = rcu_dereference(sc->sclp_session);
	if (unlikely(session == NULL))
		return -1;

	uint16_t len = rte_pktmbuf_pkt_len(m) + session->hdr_len;
	if (rte_pktmbuf_prepend(m, session->hdr_len + ETHER_HDR_LEN) == NULL)
		return -1;

	/* fix outer IP length to account for possible trimming */
	struct ether_hdr *eth = ethhdr(m);
	if (eth->ether_type == htons(ETHER_TYPE_IPv4)) {
		struct iphdr *ip = (struct iphdr *)(eth + 1);
		uint16_t ip_len = htons(len);

		if (ip_len != ip->tot_len) {
			uint16_t hlen = ip->ihl << 2;

			ip->check = 0;
			ip->tot_len = ip_len;
			ip->check = ip_checksum(ip, hlen);

			if (session->flags & L2TP_ENCAP_UDP) {
				struct udphdr *udp = (struct udphdr *)
					((char *)ip + hlen);

				udp->len = htons(len - hlen);
				udp->check = 0;
			}
		}
	} else if (eth->ether_type == htons(ETHER_TYPE_IPv6)) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)(eth + 1);
		uint16_t plen = htons(len - sizeof(*ip6));

		if (plen != ip6->ip6_plen) {
			ip6->ip6_plen = plen;

			if (ip6->ip6_nxt == IPPROTO_UDP) {
				struct udphdr *udp
					= (struct udphdr *)(ip6 + 1);

				udp->len = plen;
				/* XXX not technically correct per RFC */
				udp->check = 0;
			}
		}
	}

	return 0;
}

/*
 * For bridged packets, fix the l2tp headers
 */
int l2tp_undo_decap_br(const struct ifnet *brif, struct rte_mbuf *m)
{
	struct bridge_softc *brsc = brif->if_softc;
	struct cds_list_head *entry;
	struct bridge_port *port;
	struct ifnet *ifp;

	/* Possibly this came via l2tpeth.
	 * slow look up and unroll.
	 */
	bridge_for_each_brport(port, entry, brsc) {
		struct l2tp_softc *sc;
		struct l2tp_session *s;
		uint32_t sid;
		unsigned int l2tp_offset;

		ifp = bridge_port_get_interface(port);
		if (likely(!((ifp->if_type == IFT_L2TPETH) ||
			     (ifp->if_parent &&
			      (ifp->if_parent->if_type == IFT_L2TPETH)))))
			continue;

		if (ifp->if_parent)
			sc = rcu_dereference(ifp->if_parent->if_softc);
		else
			sc = rcu_dereference(ifp->if_softc);

		if (unlikely(sc == NULL))
			continue;

		s = rcu_dereference(sc->sclp_session);
		if (unlikely(s == NULL))
			continue;

		if (rte_pktmbuf_headroom(m) < s->hdr_len)
			continue;

		/* Match session id */
		if (ifp->if_parent)
			l2tp_offset = l2tp_opt_hdrlen(s) + 4 + 4;
		else
			l2tp_offset = l2tp_opt_hdrlen(s) + 4;

		sid = ntohl(*(uint32_t *)(rte_pktmbuf_mtod(m, unsigned char *)
				- l2tp_offset));

		if (sid != s->session_id)
			continue;

		if (ifp->if_parent && l2tp_undo_vlan_decap(m, ifp->if_parent) < 0)
			return -1;

		if (!rte_pktmbuf_prepend(m, s->hdr_len + ETHER_HDR_LEN))
			return -1;

		return 0;
	}
	return 0;
}
