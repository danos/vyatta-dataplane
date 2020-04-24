/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * ip v6 forward
 */

#include <arpa/inet.h>
#include <assert.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/snmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "compat.h"
#include "compiler.h"
#include "crypto/crypto.h"
#include "crypto/crypto_forward.h"
#include "ether.h"
#include "if/bridge/bridge_port.h"
#include "if/macvlan.h"
#include "if_var.h"
#include "in6.h"
#include "ip_forward.h"
#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "ip_mcast.h"
#include "l2tp/l2tpeth.h"
#include "main.h"
#include "mpls/mpls.h"
#include "mpls/mpls_forward.h"
#include "nd6_nbr.h"
#include "nh.h"
#include "npf/npf.h"
#include "npf/fragment/ipv6_rsmbl.h"
#include "npf/npf_cache.h"
#include "npf/npf_if.h"
#include "npf/zones/npf_zone_public.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "route_flags.h"
#include "route_v6.h"
#include "snmp_mib.h"
#include "udp_handler.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"
#include "vrf_internal.h"

enum ip6_packet_validity {
	IP6_PKT_VALID,
	IP6_PKT_BAD_HDR,
	IP6_PKT_TRUNCATED,
	IP6_PKT_BAD_ADDR,
};

/*
 * Resolve the L3 nexthop and add the L2 encap
 */
ALWAYS_INLINE bool
dp_ip6_l2_nh_output(struct ifnet *in_ifp, struct rte_mbuf *m,
		    struct next_hop *nh, uint16_t proto)
{
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
		.l3_hdr = ip6hdr(m),
		.in_ifp = in_ifp,
		.out_ifp = dp_nh_get_ifp(nh),
		.nxt.v6 = nh,
		.l2_proto = proto,
	};

	if (!pipeline_fused_ipv6_encap_only(&pl_pkt))
		return false;

	if_output(pl_pkt.out_ifp, m, in_ifp, proto);

	return true;
}

/*
 * Returns true if the packet should be sent, false if consumed.
 */
ALWAYS_INLINE bool
dp_ip6_l2_intf_output(struct ifnet *in_ifp, struct rte_mbuf *m,
		      struct ifnet *out_ifp, uint16_t proto)
{
	struct next_hop nh6;

	memset(&nh6, 0, sizeof(nh6));
	nh_set_ifp(&nh6, out_ifp);
	return dp_ip6_l2_nh_output(in_ifp, m, &nh6, proto);
}

/*
 * l2tp can't use any of the ports registered via udp_handler_register
 */
int ip6_udp_tunnel_in(struct rte_mbuf *m, struct ifnet *ifp)
{
	return udp_input(m, AF_INET6, ifp);
}

/*
 * deal with fastpath tunnels.
 * Only UDP and l2tpv3 is handled - we can't process any options.
 * Returns:
 * No options handling.
 * 0 - processed
 * -1 some error
 * 1 not consumed,
 */

int ip6_l4_input(struct rte_mbuf *m, struct ifnet *ifp)
{
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.in_ifp = ifp,
	};

	pipeline_fused_ipv6_l4(&pl_pkt);

	return 0;
}

/*
 * Deliver local destined packet to slow path
 */
void __cold_func
ip6_local_deliver(struct ifnet *ifp, struct rte_mbuf *m)
{
	/* Check if the nd will take care of the packet. */
	if (nd6_input(ifp, m) == 0)
		return;

	/* Real MTU on slow path maybe lower
	   because of the overhead of GRE header */
	struct ip6_hdr *ip6 = ip6hdr(m);
	if (slowpath_mtu
	    && ntohs(ip6->ip6_plen) + sizeof(*ip6) > slowpath_mtu) {
		IP6STAT_INC_MBUF(m, IPSTATS_MIB_FRAGFAILS);
		icmp6_error(ifp, m, ICMP6_PACKET_TOO_BIG, 0,
			    htonl(slowpath_mtu));
		return;
	}

	/*
	 * CPP input firewall. Enables RFC-6192.
	 *
	 * Run the local firewall,  and discard if so instructed.
	 */
	if (npf_local_fw(ifp, &m, htons(ETHER_TYPE_IPv6)))
		goto discard;

	IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INDELIVERS);
	local_packet(ifp, m);
	return;
discard:
	IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INDISCARDS);
	rte_pktmbuf_free(m);
}

void mcast_ip6_deliver(struct ifnet *ifp, struct rte_mbuf *m)
{
	ip6_local_deliver(ifp, m);
}

void ip6_unreach(struct ifnet *ifp, struct rte_mbuf *m)
{
	IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INNOROUTES);
	icmp6_error(ifp, m, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOROUTE,
		    htonl(0));
}

#define IPV6_MAX_FRAGS 64
#define IPV6_FRAG_OVRHD (sizeof(struct ip6_hdr) + sizeof(struct ip6_frag))
int ip6_fragment_mtu(struct ifnet *ifp, unsigned int mtu_size,
		     struct rte_mbuf *m_in, void *ctx,
		     ip6_output_fn_t frag_out)
{
	struct rte_mbuf *m_table[IPV6_MAX_FRAGS];
	struct ip6_hdr *in_ip6, *frag_ip6;
	struct ether_hdr *eth_hdr;
	struct ip6_frag *ip6f;
	struct rte_mbuf *m_frag;
	uint32_t fh_id = random();
	uint32_t remaining, copy_len;
	uint16_t frag_off = 0;
	int nfrags = 0, mf, i;

	in_ip6 = ip6hdr(m_in);
	remaining = htons(in_ip6->ip6_plen);

	while (remaining > 0) {
		if (nfrags == IPV6_MAX_FRAGS)
			goto failed;

		m_frag = pktmbuf_allocseg(m_in->pool, pktmbuf_get_vrf(m_in),
					  mtu_size);
		if (!m_frag)
			goto failed;

		/*
		 * Fragment size must be a multiple of 8 bytes
		 */
		if (remaining + IPV6_FRAG_OVRHD < mtu_size)
			copy_len = remaining;
		else
			copy_len = (mtu_size - IPV6_FRAG_OVRHD) & ~7;

		/*
		 * Copy into fragment
		 * Leave room for the fragment headers
		 */
		m_frag->data_len += IPV6_FRAG_OVRHD;
		m_frag->pkt_len += IPV6_FRAG_OVRHD;
		if (ip_mbuf_copy(m_frag, m_in,
				 dp_pktmbuf_l2_len(m_in) +
				 sizeof(struct ip6_hdr) + frag_off,
				 copy_len)) {
			rte_pktmbuf_free(m_frag);
			goto failed;
		}

		remaining -= copy_len;

		/*
		 * Fixup fragment ipv6 header
		 */
		frag_ip6 = rte_pktmbuf_mtod(m_frag, struct ip6_hdr *);
		memcpy(frag_ip6, in_ip6, sizeof(struct ip6_hdr));
		frag_ip6->ip6_nxt = IPPROTO_FRAGMENT;
		frag_ip6->ip6_plen = htons(copy_len + sizeof(struct ip6_frag));
		pktmbuf_copy_meta(m_frag, m_in);
		m_frag->l3_len = IPV6_FRAG_OVRHD;

		/*
		 * Fixup fragment frag header
		 */
		ip6f = (struct ip6_frag *)(frag_ip6 + 1);
		ip6f->ip6f_nxt = in_ip6->ip6_nxt;
		ip6f->ip6f_reserved = 0;
		ip6f->ip6f_ident = htonl(fh_id);
		mf = (remaining > 0) ? 1 : 0;
		ip6f->ip6f_offlg = htons(RTE_IPV6_SET_FRAG_DATA(frag_off, mf));
		frag_off += copy_len;

		/*
		 * Fixup fragment L2 header
		 */
		rte_pktmbuf_prepend(m_frag, sizeof(struct ether_hdr));
		eth_hdr = rte_pktmbuf_mtod(m_frag, struct ether_hdr *);
		eth_hdr->ether_type = htons(ETHER_TYPE_IPv6);
		m_frag->l2_len = sizeof(struct ether_hdr);

		m_table[nfrags++] = m_frag;
	}
	rte_pktmbuf_free(m_in);

	/*
	 * Send the fragments
	 */
	for (i = 0; i < nfrags; i++) {
		if (!m_table[i])
			break;
		frag_out(ifp, m_table[i], ctx);
	}

	return nfrags;
failed:
	while (nfrags)
		rte_pktmbuf_free(m_table[--nfrags]);
	return nfrags;
}

/*
 * Re-fragment a packet that we reassembled on input.  Reassembly will
 * *only* have occurred if the packet had to pass though Firewall or
 * PBR.  We do *not* fragment anything that wasn't previously
 * fragmented when received.
 *
 * 'addr' may be NULL, and should be passed though to the
 * output function and not used in ip6_refragment_packet.
 */
void
ip6_refragment_packet(struct ifnet *o_ifp, struct rte_mbuf *m,
		      void *ctx, ip6_output_fn_t output_fn)
{
	struct rte_mbuf *m_table[IPV6_MAX_FRAGS_PER_SET];
	struct ether_hdr *eth_hdr, eth_copy;
	uint16_t l2_len;
	int32_t nfrags;
	uint32_t fh_id;
	uint32_t mtu;

	/*
	 * We need two values that were cached from the packet
	 * reassembly - the gleaned mtu and the fragment header ID.
	 */
	mtu = npf_cache_mtu();
	fh_id = npf_cache_frag_ident();

	/*
	 * Copy the ethernet header from the reassembled packet and
	 * write this to each outgoing fragment.  The output function
	 * may or may not recalculate the ethernet source and dest
	 * addresses, but we don't know that just yet so just copy the
	 * complete header.
	 */
	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	ether_addr_copy(&eth_hdr->d_addr, &eth_copy.d_addr);
	ether_addr_copy(&eth_hdr->s_addr, &eth_copy.s_addr);
	eth_copy.ether_type = eth_hdr->ether_type;

	/*
	 * Remove layer 2 header since
	 * rte_ipv6_fragment_packet is l2 agnostic
	 */
	l2_len = m->l2_len;
	rte_pktmbuf_adj(m, l2_len);
	m->l2_len = 0;

	/*
	 * rte_ipv6_fragment_packet does not handle packets with
	 * non-fragmentable extension headers.  When this changes, we
	 * need to change npf_check_frag_reassembly to allow such
	 * packets to be reassembled.
	 */
	nfrags = rte_ipv6_fragment_packet(m, m_table,
					  (uint16_t)IPV6_MAX_FRAGS_PER_SET,
					  mtu, m->pool, m->pool);

	/* Free the input packet */
	rte_pktmbuf_free(m);
	m = NULL;

	if (nfrags > 0 && nfrags <= IPV6_MAX_FRAGS_PER_SET) {
		int i;

		for (i = 0; i < nfrags; i++) {
			m = m_table[i];
			if (m == NULL)
				break;

			struct ip6_frag *fh;

			/*
			 * Several fixups are required to be done to packets
			 * we get from rte_ipv6_fragment_packet:
			 *
			 * 1. Add a fragment ID value (re-use the original
			 *    value if we are re-fragmenting a reassembled
			 *     packet)
			 * 2. Adjust the mbuf to allow for an l2 header
			 * 3. Write the ethernet header.
			 */
			fh = (struct ip6_frag *)
				(rte_pktmbuf_mtod(m, char *) +
				 sizeof(struct ipv6_hdr));
			fh->ip6f_ident = htonl(fh_id);

			/* Prepend space for l2 hdr */
			rte_pktmbuf_prepend(m, sizeof(struct ether_hdr));
			m->l2_len = sizeof(struct ether_hdr);

			/*
			 * Write the ethernet header
			 */
			eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

			ether_addr_copy(&eth_copy.d_addr, &eth_hdr->d_addr);
			ether_addr_copy(&eth_copy.s_addr, &eth_hdr->s_addr);
			eth_hdr->ether_type = eth_copy.ether_type;

			(*output_fn)(o_ifp, m, ctx);
		}
	}
}

/*
 * Nexthop lookup in the dataplane
 * If NULL is returned, the packet has been consumed
 */
static ALWAYS_INLINE
struct next_hop *ip6_lookup(struct rte_mbuf *m, struct ifnet *ifp,
			    struct ip6_hdr *ip6, uint32_t tbl_id,
			    bool hlim_decremented)
{
	struct next_hop *nxt;

	/* Lookup route */
	nxt = dp_rt6_lookup(&ip6->ip6_dst, tbl_id, m);

	/* no nexthop found, send icmp error */
	if (unlikely(!nxt)) {
		ip6_unreach(ifp, m);
		return NULL;
	}

	/* Is the destination interface outside of the dataplane? */
	if (nxt->flags & (RTF_SLOWPATH | RTF_LOCAL))
		goto slow_path;

	return nxt;

 slow_path: __cold_label;
	if (hlim_decremented)
		ip6->ip6_hlim += IPV6_HLIMDEC;
	ip6_l4_input(m, ifp);
	return NULL;
}

/*
 * ip6_out_features
 *
 * The use of pipeline fused-mode functions here is an interim step
 * towards this function or its users being converted into pipeline
 * nodes and an appropriate pipeline graph. It should not be seen as
 * an example newly-written code.
 */
ALWAYS_INLINE
void ip6_out_features(struct rte_mbuf *m, struct ifnet *ifp,
		      struct ip6_hdr *ip6, struct next_hop *nxt,
		      enum ip6_features ip6_feat, uint16_t npf_flags)
{
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.nxt.v6 = nxt,
		.l3_hdr = ip6,
		.npf_flags = npf_flags,
		.in_ifp = ifp,
	};

	/* nxt->ifp may be changed by netlink messages. */
	struct ifnet *nxt_ifp = dp_nh_get_ifp(nxt);

	/* Destination device is not up? */
	if (!nxt_ifp || !(nxt_ifp->if_flags & IFF_UP)) {
		icmp6_error(ifp, m, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_ADDR, htonl(0));
		return;
	}

	pktmbuf_clear_rx_vlan(m);

	if (!(ip6_feat & (IP6_FEA_ORIGINATE|IP6_FEA_DECAPPED))) {
		/*
		 * If forwarding packet using same interface that it came in on,
		 * perhaps should send a redirect to sender to shortcut a hop.
		 * Only send redirect if source is sending directly to us,
		 * Also, don't send redirect if forwarding using a default route
		 * or a route modified by a redirect.
		 */
		if (unlikely(nxt_ifp == ifp)) {
			/*
			 * If the incoming interface is equal to the
			 * outgoing one, and the link attached to the
			 * interface is point-to-point, then it will be
			 * highly probable that a routing loop occurs.
			 * Thus, we immediately drop the packet and
			 * send an ICMPv6 error message.
			 *
			 * type/code is based on suggestion by Rich
			 * Draves. not sure if it is the best pick.
			 */
			if ((ifp->if_flags & IFF_POINTOPOINT) != 0 ||
			    is_tunnel(ifp)) {
				icmp6_error(ifp, m, ICMP6_DST_UNREACH,
					    ICMP6_DST_UNREACH_ADDR,
					    htonl(0));
				return;
			}
			icmp6_redirect(ifp, m, nxt);
		}
	}

	/* macvlan mac passthrough check & replace ifp */
	pl_pkt.out_ifp = macvlan_check_vrrp_if(nxt_ifp);

	if (ip6_feat & IP6_FEA_ORIGINATE)
		pl_pkt.npf_flags |= NPF_FLAG_FROM_US;

	pipeline_fused_ipv6_out(&pl_pkt);
	return;
}

static ALWAYS_INLINE
void ip6_switch(struct rte_mbuf *m, struct ifnet *ifp,
		struct ip6_hdr *ip6, struct next_hop *nxt,
		enum ip6_features ip6_feat, uint16_t npf_flags)
{
	/* Immediately drop blackholed traffic. */
	if (unlikely(nxt->flags & RTF_BLACKHOLE)) {
		rte_pktmbuf_free(m);
		return;
	}

	if (nxt->flags & RTF_REJECT) {
		icmp6_error(ifp, m, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_ADDR, 0);
		return;
	}

	/* MPLS imposition required because nh has given us a label */
	if (unlikely(nh_outlabels_present(&nxt->outlabels))) {
		mpls_unlabeled_input(ifp, m, NH_TYPE_V6GW, nxt,
				     ip6->ip6_hops);
		return;
	}

	ip6_out_features(m, ifp, ip6, nxt, ip6_feat, npf_flags);
}

static ALWAYS_INLINE
enum ip6_packet_validity
ip6_validate_packet(struct rte_mbuf *m, const struct ip6_hdr *ip6)
{
	unsigned int len, ip6_len;

	/*
	 * Is packet big enough.
	 * (i.e is there a valid IP header in first segment)
	 */
	if (rte_pktmbuf_data_len(m) < dp_pktmbuf_l2_len(m) + sizeof(*ip6))
		goto bad_packet;

	/*
	 * Is it IPv6?
	 */
	if (unlikely((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION))
		goto bad_packet;

	/* Runt? */
	len = rte_pktmbuf_pkt_len(m) - dp_pktmbuf_l2_len(m) - sizeof(*ip6);
	ip6_len = ntohs(ip6->ip6_plen);

	/* Packet is less than what the ip header tell us */
	if (unlikely(len < ip6_len))
		goto pkt_truncated;

	dp_pktmbuf_l3_len(m) = sizeof(*ip6);

	/*
	 * Is packet longer than IP header tells us?
	 */
	if (unlikely(len > ip6_len))
		rte_pktmbuf_trim(m, len - ip6_len);

	/*
	 * RFC 4291 - Source address sanity checks.
	 *    The following are not allowed: multicast, loopback
	 * draft-itojun-v6ops-v4mapped-harmful-02:
	 *    Don't allow V4 mapped source either.
	 */
	if (unlikely(IN6_IS_ADDR_MULTICAST(&ip6->ip6_src)) ||
	    unlikely(IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src)) ||
	    unlikely(IN6_IS_ADDR_V4MAPPED(&ip6->ip6_src)))
		goto bad_addr;

	/*
	 * RFC 4291 - Multicast destination address sanity checks.
	 *    The following are not allowed: m/c scope of 0 or 1.
	 * The former is a reserved value,  the latter should stay within
	 * the originating node.
	 */
	if (unlikely(IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) &&
	    IPV6_ADDR_MC_SCOPE(&ip6->ip6_dst) < IPV6_ADDR_SCOPE_LINKLOCAL)
		goto bad_addr;

	return IP6_PKT_VALID;

bad_packet: __cold_label;
	/* Incorrectly formatted packet, drop */
	return IP6_PKT_BAD_HDR;

bad_addr: __cold_label;
	return IP6_PKT_BAD_ADDR;

pkt_truncated: __cold_label;
	return IP6_PKT_TRUNCATED;
}

bool ip6_valid_packet(struct rte_mbuf *m, const struct ip6_hdr *ip6)
{
	return ip6_validate_packet(m, ip6) == IP6_PKT_VALID;
}

ALWAYS_INLINE
bool ip6_validate_packet_and_count(struct rte_mbuf *m,
				   const struct ip6_hdr *ip6,
				   struct ifnet *ifp)
{
	enum ip6_packet_validity pkt_validity;

	pkt_validity = ip6_validate_packet(m, ip6);
	if (unlikely(pkt_validity != IP6_PKT_VALID)) {
		switch (pkt_validity) {
		case IP6_PKT_BAD_ADDR:
			IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INADDRERRORS);
			break;
		case IP6_PKT_TRUNCATED:
			IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INTRUNCATEDPKTS);
			break;
		default: /* really only IP6_PKT_BAD_HDR */
			IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INHDRERRORS);
			break;
		}
		return false;
	}
	return true;
}

/*
 * A packet is to be forwarded after it has been IPsec decrypted.
 *
 * This is only used for the non VTI case where the post decrypted
 * packet is seen to arrive from the same interface as the original
 * encrypted (ESP) packet arrived on.
 *
 * No input features are run from this path.
 */
void ip6_input_from_ipsec(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct ip6_hdr *ip6 = ip6hdr(m);

	if (unlikely(!ip6_validate_packet_and_count(m, ip6, ifp)))
		goto drop;

	/* Lookahead in route table */
	rt6_prefetch(m, &ip6->ip6_dst);

	if (unlikely(ip6->ip6_nxt == IPPROTO_HOPOPTS)) {
		uint32_t rtalert = ~0u;

		if (ip6_hopopts_input(m, ifp, &rtalert))
			return;

		if (rtalert != ~0u)
			goto slow_path;
	}

	if (unlikely(IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))) {
		IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INMCASTPKTS);
		mcast_ip6(ip6, ifp, m);
		return;
	}

	/*
	 * Check if forwarding is enabled
	 */
	if (unlikely(pl_node_is_feature_enabled(
			     &ipv6_in_no_forwarding_feat, ifp)))
		goto drop;

	/* Give IPsec a chance to consume it */
	if (unlikely(crypto_policy_check_outbound(ifp, &m, RT_TABLE_MAIN,
						  htons(ETHER_TYPE_IPv6),
						  NULL)))
		return;

	ip6_lookup_and_forward(m, ifp, false, NPF_FLAG_CACHE_EMPTY);
	return;

 drop:	__cold_label;
	IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INDISCARDS);
	rte_pktmbuf_free(m);
	return;

 slow_path: __cold_label;
	ip6_l4_input(m, ifp);
}

ALWAYS_INLINE
void ip6_output(struct rte_mbuf *m, bool srced_forus)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct next_hop *nxt;
	struct ifnet *ifp;

	/* Lookup route */
	nxt = dp_rt6_lookup(srced_forus ? &ip6->ip6_src : &ip6->ip6_dst,
			    RT_TABLE_MAIN, m);
	if (!nxt) {
		/*
		 * Since there is no output interface count against
		 * the VRF associated with the packet.
		 */
		IP6STAT_INC_MBUF(m, IPSTATS_MIB_OUTNOROUTES);
		goto drop;
	}

	/* ifp can be changed by nxt->ifp. use protected deref. */
	ifp = dp_nh_get_ifp(nxt);

	if (unlikely(ifp == NULL)) {
		if (net_ratelimit()) {
			char b[INET6_ADDRSTRLEN];

			RTE_LOG(ERR, ROUTE,
				"ipv6 output called for %s which is slowpath\n",
				inet_ntop(AF_INET6, &ip6->ip6_dst, b,
					  sizeof(b)));
		}
		goto drop;
	}

	if (!(ifp->if_flags & IFF_UP))
		goto drop;

	ip6_switch(m, ifp, ip6, nxt, 0, NPF_FLAG_CACHE_EMPTY);

	return;

drop:
	rte_pktmbuf_free(m);
}

/*
 * This should only be called for locally generated packets where
 * the IP source address is one of ours,  i.e. not spoofing the
 * packet source. Fragments must never be injected here.
 *
 * Packets injected here will skip the outbound forwarding firewall.
 * Note that despite having input i/f == output i/f,  they will not
 * generate ICMP redirects.
 */
void
ip6_lookup_and_originate(struct rte_mbuf *m, struct ifnet *in_ifp)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct next_hop *nxt;
	struct next_hop ll_nh;

	/*
	 * RFC 4291 - Do not try to transmit to unspecified or loopback
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst)) {
		rte_pktmbuf_free(m);
		return;
	}

	if (unlikely(IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst))) {
		ll_nh = (struct next_hop) {
			.u.ifp = in_ifp,
		};
		nxt = &ll_nh;
	} else {
		nxt = ip6_lookup(m, in_ifp, ip6, RT_TABLE_MAIN, false);
		if (unlikely(!nxt)) {
			return;
		}
	}

	enum ip6_features ip6_feat = IP6_FEA_ORIGINATE;
	ip6_switch(m, in_ifp, ip6, nxt, ip6_feat, NPF_FLAG_CACHE_EMPTY);
}

/*
 * This should not be called for locally generated packets,
 * only for forwarded packets.  The packet passed in here may be
 * a fragment,  in which case if the firewall is enabled,
 * it will be subject to reassembly.
 */
void
ip6_lookup_and_forward(struct rte_mbuf *m, struct ifnet *in_ifp,
		       bool hlim_decremented, uint16_t npf_flags)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct next_hop *nxt;

	/*
	 * RFC 4291 - Source address of unspecified must never be forwarded.
	 */
	if (unlikely(IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src))) {
		IP6STAT_INC_IFP(in_ifp, IPSTATS_MIB_INADDRERRORS);
		rte_pktmbuf_free(m);
		return;
	}

	/*
	 * RFC 4291 - Do not try to transmit to unspecified or loopback
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst)) {
		IP6STAT_INC_IFP(in_ifp, IPSTATS_MIB_INADDRERRORS);
		rte_pktmbuf_free(m);
		return;
	}

	nxt = ip6_lookup(m, in_ifp, ip6, RT_TABLE_MAIN, hlim_decremented);
	if (!nxt)
		return;

	if (!hlim_decremented)
		ip6->ip6_hlim -= IPV6_HLIMDEC;

	enum ip6_features ip6_feat = IP6_FEA_REASSEMBLE;
	ip6_switch(m, in_ifp, ip6, nxt, ip6_feat, npf_flags);
}

/*
 * A wrapper around if_output so that it can be passed to
 * ip6_refragment_packet as a function pointer.
 */
static void
ip6_spath_frag_output(struct ifnet *ifp __unused, struct rte_mbuf *m, void *ctx)
{
	struct ifnet *l2_ifp = ctx;

	if_output(l2_ifp, m, NULL, ETH_P_IPV6);
}

/*
 * IPv6 slow output path filter.
 *
 * Run the output firewall,  and drop the packet if required.
 *
 * Return an indication of if the packet was consumed.
 *   -1 => Consumed by filter
 *    0 => Not consumed
 *   +1 => Consumed by reassembly
 */
static int
ip6_spath_filter_internal(struct ifnet *ifp, struct ifnet *l2_ifp,
			  struct rte_mbuf **mp)
{
	uint16_t npf_flags = NPF_FLAG_CACHE_EMPTY;
	struct rte_mbuf *m = *mp;
	struct ip6_hdr *ip6 = ip6hdr(m);

	/*
	 * The kernel can still forward some packets,  and only
	 * 'From us' packets should always skip the firewall
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) ||
	    is_local_ipv6(if_vrfid(ifp), &ip6->ip6_src)) {
		npf_flags |= NPF_FLAG_FROM_US | NPF_FLAG_FROM_LOCAL;
		if (npf_zone_local_is_set())
			npf_flags |= NPF_FLAG_FROM_ZONE;
	}

	/*
	 * The kernel can L2 forward some bridged packets (i.e. IP broadcasts
	 * and multicasts), and as such they should not experience the L3
	 * firewall.
	 */
	if ((npf_flags & NPF_FLAG_FROM_US) == 0 && ifp != l2_ifp)
		return 0;	/* packet not filtered */

	struct pl_packet pl_pkt = {
		.mbuf = *mp,
		.nxt.v6 = NULL,
		.l3_hdr = ip6,
		.npf_flags = npf_flags,
		.in_ifp = NULL,
		.out_ifp = ifp,
	};

	if (!pipeline_fused_ipv6_defrag_out_spath(&pl_pkt))
		return 1;

	if (unlikely(m != pl_pkt.mbuf))
		*mp = pl_pkt.mbuf;

	return 0;	/* packet not filtered */
}

int
ip6_spath_filter(struct ifnet *l2_ifp, struct rte_mbuf **mp)
{
	struct bridge_port *brport;
	struct ifnet *ifp;

	/* The ifp may be a member link of a bridge */
	brport = rcu_dereference(l2_ifp->if_brport);
	if (brport)
		ifp = bridge_port_get_bridge(brport);
	else
		ifp = l2_ifp;

	return ip6_spath_filter_internal(ifp, l2_ifp, mp);
}

/*
 * IPv6 slow path output.
 * Attempts to apply post-routing features and output the packet.
 * Packet is consumed.
 */
int
ip6_spath_output(struct ifnet *l2_ifp, struct rte_mbuf *m)
{
	struct bridge_port *brport;
	struct ifnet *ifp;

	/* The ifp may be a member link of a bridge */
	brport = rcu_dereference(l2_ifp->if_brport);
	if (brport)
		ifp = bridge_port_get_bridge(brport);
	else
		ifp = l2_ifp;

	int filtered = ip6_spath_filter_internal(ifp, l2_ifp, &m);
	if (filtered < 0)	/* filtered */
		return -1;
	if (filtered > 0)	/* consumed */
		return 0;

	/* Refragment if needed */
	if (pktmbuf_mdata_exists(m, PKT_MDATA_DEFRAG)) {
		ip6_refragment_packet(ifp, m, l2_ifp,
				      ip6_spath_frag_output);
		return 0;
	}

	if_output(l2_ifp, m, NULL, ETH_P_IPV6);
	return 0;
}
