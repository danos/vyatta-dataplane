/*
 * L2TPETH Forwarding
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/l2tp.h> // conflicts with netinet/in.h
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto/crypto_forward.h"
#include "ether.h"
#include "if_var.h"
#include "in_cksum.h"
#include "ip_funcs.h"
#include "l2tpeth.h"
#include "netinet6/ip6_funcs.h"
#include "pktmbuf.h"
#include "urcu.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf.h"

#define L2TP_HDR_VER_3 0x0003

static int
l2tp_undo_encap(struct ifnet *ifp, struct rte_mbuf *m,
		struct l2tp_session *session, uint16_t rx_vlan,
		bool tx_vlan)
{
	struct ether_hdr *eh;
	uint16_t vlan = 0;

	if (tx_vlan) {
		struct ether_vlan_hdr *vhdr = (struct ether_vlan_hdr *)
			(rte_pktmbuf_mtod(m, char *) +
			 session->hdr_len + ETHER_HDR_LEN);
		eh = (struct ether_hdr *)
			((char *)vhdr +  sizeof(struct vlan_hdr));

		memmove(&vhdr->eh, eh, 2 * ETHER_ADDR_LEN);
		vlan = sizeof(struct vlan_hdr);
	} else
		eh = (struct ether_hdr *)
			(rte_pktmbuf_mtod(m, char *) +
			 session->hdr_len + ETHER_HDR_LEN);

	/* Replace the dest addr to be the shadow if's if we have
	   replaced the original ether-hdr in routed case.
	*/
	if (ether_addr_equal(&eh->s_addr, &ifp->eth_addr)) {
		const struct ifnet *dp_ifp = ifnet_byport(m->port);

		if (dp_ifp)
			ether_addr_copy(&dp_ifp->eth_addr, &eh->d_addr);
		else
			return -1;
	}

	if (rte_pktmbuf_adj(m, session->hdr_len + ETHER_HDR_LEN + vlan)
		== NULL)
		return -1;

	if (rx_vlan) {
		m->ol_flags |= PKT_RX_VLAN;
		m->ol_flags &= ~PKT_TX_VLAN_PKT;
		m->vlan_tci &= ~VLAN_VID_MASK;
		m->vlan_tci |= rx_vlan;
	}

	return 0;
}

static int l2tp_add_vlan(struct rte_mbuf *m, uint8_t offset)
{
	struct ether_vlan_hdr *vhdr = (struct ether_vlan_hdr *)
		(rte_pktmbuf_mtod(m, char *) + offset);

	struct ether_hdr *eh = (struct ether_hdr *)
		((char *)vhdr +  sizeof(struct vlan_hdr));

	memmove(&vhdr->eh, eh, 2 * ETHER_ADDR_LEN);
	vhdr->eh.ether_type = htons(ETHER_TYPE_VLAN);
	vhdr->vh.vlan_tci = htons(m->vlan_tci);
	vhdr->vh.eth_proto = eh->ether_type;
	m->ol_flags &= ~PKT_TX_VLAN_PKT;

	return 0;
}

/* Send a packet out. */
void
l2tp_output(struct ifnet *ifp, struct rte_mbuf *m, uint16_t rx_vlan)
{
	uint8_t ip_hdr_len = sizeof(struct iphdr);
	uint8_t flags = 0;
	struct ether_hdr *orig_ethhdr = ethhdr(m);
	uint16_t etype = ntohs(orig_ethhdr->ether_type);
	struct iphdr *orig_ip = iphdr(m);
	struct l2tp_session *session;
	char *l2tp_hdr;
	struct ifnet *orig_ifp = ifp;
	bool tx_vlan = m->ol_flags & PKT_TX_VLAN_PKT;
	struct l2tp_softc *sc = rcu_dereference(ifp->if_softc);

	if (unlikely(sc == NULL)) {
		RTE_LOG(ERR, L2TP, "invalid softc from ifp %s\n", ifp->if_name);
		goto drop;
	}

	session = rcu_dereference(sc->sclp_session);
	if (unlikely(session == NULL)) {
		RTE_LOG(ERR, L2TP, "invalid session from sc %s\n",
			ifp->if_name);
		goto drop;
	}

	uint8_t encap_len = session->hdr_len + ETHER_HDR_LEN;
	struct l2tpv3_encap *encap = (struct l2tpv3_encap *)
		rte_pktmbuf_prepend(m, encap_len +
				    (tx_vlan ? sizeof(struct vlan_hdr) : 0));
	if (unlikely(encap == NULL)) {
		DP_DEBUG(L2TP, ERR, L2TP,
			"Not enough space in mbuf to allocate l2tp hdr\n");
		goto drop;
	}
	pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	/*
	 * L2tp interface supports only default VRF as of yet
	 * hence set the vrf to default
	 */
	pktmbuf_set_vrf(m, VRF_DEFAULT_ID);

	if (tx_vlan)
		l2tp_add_vlan(m, encap_len);

	uint16_t orig_pkt_len = rte_pktmbuf_pkt_len(m) - encap_len;

	flags = session->flags;

	/* ip hdr */
	uint8_t tos = 0;
	uint8_t ttl = 255;
	uint8_t proto = 0;
	uint8_t offset = 0;

	if (etype == ETHER_TYPE_IPv4) {
		tos = orig_ip->tos;
		ttl = orig_ip->ttl;
		proto = orig_ip->protocol;
		offset = sizeof(struct iphdr);
	} else if (etype == ETHER_TYPE_IPv6) {
		tos = ip6_tclass(*(uint32_t *)orig_ip);
		ttl = ((struct ip6_hdr *)orig_ip)->ip6_hlim;
		proto = ((struct ip6_hdr *)orig_ip)->ip6_nxt;
		offset = sizeof(struct ip6_hdr);
	}

	if (session->ttl)
		ttl = session->ttl;

	if (flags & L2TP_ENCAP_IPV4) {
		struct iphdr *ip_header = (struct iphdr *)encap->iphdr;

		encap->ether_header.ether_type = htons(ETHER_TYPE_IPv4);

		ip_header->ihl = sizeof(struct iphdr) >> 2;
		ip_header->version = IPVERSION;
		ip_header->tos = tos;
		ip_header->tot_len = htons(session->hdr_len + orig_pkt_len);
		ip_header->frag_off = 0;
		ip_header->id = 0;
		ip_header->ttl = ttl;
		ip_header->protocol = (flags & L2TP_ENCAP_UDP) ?
			IPPROTO_UDP : IPPROTO_L2TP;
		memcpy(&ip_header->saddr, &session->s_addr, sizeof(uint32_t));
		memcpy(&ip_header->daddr, &session->d_addr, sizeof(uint32_t));

		ip_header->check = 0;
		ip_header->check = in_cksum_hdr(ip_header);
		pktmbuf_l3_len(m) = ip_header->ihl << 2;
	} else {
		struct ip6_hdr *ip_header = (struct ip6_hdr *)encap->iphdr;

		encap->ether_header.ether_type = htons(ETHER_TYPE_IPv6);
		ip_hdr_len = sizeof(struct ip6_hdr);

		ip6_ver_tc_flow_hdr(ip_header, tos, 0);
		ip_header->ip6_plen = htons(session->hdr_len +
					    orig_pkt_len - sizeof(struct ip6_hdr));
		ip_header->ip6_nxt = (flags & L2TP_ENCAP_UDP) ?
			IPPROTO_UDP : IPPROTO_L2TP;
		ip_header->ip6_hlim = ttl;
		memcpy(&ip_header->ip6_src, &session->s_addr,
		       sizeof(struct in6_addr));
		memcpy(&ip_header->ip6_dst, &session->d_addr,
		       sizeof(struct in6_addr));
	}

	/* udp hdr */
	uint16_t *udp_cksum = NULL;
	uint16_t orig_cksum;
	struct ip6_hdr *ip6hdr = NULL;
	struct udp_hdr *udp_header = (struct udp_hdr *)
		((char *)encap->iphdr + ip_hdr_len);
	if (unlikely(flags & L2TP_ENCAP_UDP)) {
		uint16_t pkt_len = session->hdr_len - ip_hdr_len + orig_pkt_len;

		udp_header->src_port = htons(session->sport);
		udp_header->dst_port = htons(session->dport);
		udp_header->dgram_len = htons(pkt_len);
		if (flags & L2TP_ENCAP_IPV4)
			udp_header->dgram_cksum = 0;
		else {
			if (proto == IPPROTO_TCP)
				orig_cksum = ((struct tcp_hdr *)
					   ((char *)orig_ip + offset))->cksum;
			else if (proto == IPPROTO_UDP)
				orig_cksum = ((struct udp_hdr *)
				    ((char *)orig_ip + offset))->dgram_cksum;

			ip6hdr = (struct ip6_hdr *)encap->iphdr;
			udp_cksum = &udp_header->dgram_cksum;

		}
	}

	/* l2tp header */
	if (flags & L2TP_ENCAP_UDP) {
		struct l2tpv3_udp_hdr *v3udp_hdr = (struct l2tpv3_udp_hdr *)
		  ((char *)encap->iphdr + ip_hdr_len + sizeof(struct udp_hdr));
		v3udp_hdr->ver = htons(L2TP_HDR_VER_3);
		v3udp_hdr->zero = 0;
		l2tp_hdr = (char *)&v3udp_hdr->session_id;
	} else
		l2tp_hdr = (char *)encap->iphdr + ip_hdr_len;

	*((uint32_t *)l2tp_hdr) = htonl(session->peer_session_id);
	l2tp_hdr += 4;

	if (session->cookie_len) {
		memcpy(l2tp_hdr, (char *)&session->cookie[0],
		       session->cookie_len);
		l2tp_hdr += session->cookie_len;
	}

	if (unlikely(flags & L2TP_ENCAP_SEQ)) {
		*((uint32_t *)l2tp_hdr) = htonl(0x40000000 |
						session->local_seq);
		session->local_seq = (session->local_seq + 1) & 0xffffff;
	}

	/* udp checksum for ipv6 + udp encap. */
	if (udp_cksum) {
		if (orig_cksum == 0) {
			udp_header->dgram_cksum = htons(in6_cksum(ip6hdr,
						     IPPROTO_UDP,
						     sizeof(*ip6hdr),
						     udp_header->dgram_len));
		} else {
			uint16_t cksum = ntohs(orig_cksum) +
				in6_cksum(ip6hdr, IPPROTO_UDP,
					  sizeof(*ip6hdr),
					  session->hdr_len - ip_hdr_len);
			cksum = ~cksum & 0xffff;
			udp_header->dgram_cksum = htons(cksum);
		}
	}

	bool is_ipv4 = flags & L2TP_ENCAP_IPV4;

	uint16_t eth_type
		= is_ipv4 ? htons(ETHER_TYPE_IPv4) : htons(ETHER_TYPE_IPv6);
	struct ifnet *dp_ifp = NULL;

	if (crypto_policy_outbound_match(ifp, &m, eth_type)) {
		dp_ifp = ifnet_byport(m->port);
		if (unlikely(l2tp_undo_encap(ifp, m, session,
					     rx_vlan, tx_vlan) < 0))
			goto drop;

		/*
		 * The following drop must happen in the context
		 * of a crypto match. Common to outer if, else
		 * but do not move it outside.
		 */
		if (!dp_ifp)
			goto drop;
	}

	/*
	 * Over-ride intf due to crypto match or fallback to
	 * original interface (e.g. child vif interface) while routing.
	 */
	ifp = dp_ifp ? dp_ifp : orig_ifp;
	pktmbuf_prepare_encap_out(m);
	if_incr_out(ifp, m);
	if (is_ipv4)
		ip_lookup_and_originate(m, ifp);
	else
		ip6_lookup_and_originate(m, ifp);

	return;
drop:
	if_incr_oerror(ifp);
	rte_pktmbuf_free(m);
}
