/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * ip forward
 */

#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if.h>
#include <linux/mpls.h>
#include <linux/snmp.h>
#include <rte_atomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "arp.h"
#include "compat.h"
#include "compiler.h"
#include "config_internal.h"
#include "crypto/crypto.h"
#include "crypto/crypto_forward.h"
#include "if/bridge/bridge_port.h"
#include "if/gre.h"
#include "if/macvlan.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "in_cksum.h"
#include "ip_forward.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "ip_mcast.h"
#include "ip_options.h"
#include "ip_ttl.h"
#include "l2tp/l2tpeth.h"
#include "main.h"
#include "mpls/mpls.h"
#include "mpls/mpls_forward.h"
#include "nh.h"
#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf/zones/npf_zone_public.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "route.h"
#include "route_flags.h"
#include "snmp_mib.h"
#include "udp_handler.h"
#include "urcu.h"
#include "ip_addr.h"
#include "vrf_internal.h"

/* MTU cutoff for PMTU in IP processing */
unsigned int slowpath_mtu;

/* SNMP statistics for UDP in tunnels */
uint64_t udpstats[UDP_MIB_MAX];

ALWAYS_INLINE bool
dp_ip_l2_nh_output(struct ifnet *in_ifp, struct rte_mbuf *m,
		   struct next_hop *nh, uint16_t proto)
{
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
		.l3_hdr = iphdr(m),
		.in_ifp = in_ifp,
		.out_ifp = dp_nh4_get_ifp(nh),
		.nxt.v4 = nh,
		.l2_proto = proto,
	};

	if (!pipeline_fused_ipv4_encap_only(&pl_pkt))
		return false;

	if_output(pl_pkt.out_ifp, m, in_ifp, proto);

	return true;
}

ALWAYS_INLINE bool
dp_ip_l2_intf_output(struct ifnet *in_ifp, struct rte_mbuf *m,
		     struct ifnet *out_ifp, uint16_t proto)
{
	struct next_hop nh;

	memset(&nh, 0, sizeof(nh));
	nh4_set_ifp(&nh, out_ifp);

	return dp_ip_l2_nh_output(in_ifp, m, &nh, proto);
}

/*
 * l2tp can't use any of the ports registered via udp_handler_register
 */
int ip_udp_tunnel_in(struct rte_mbuf **m, struct iphdr *ip,
		     struct ifnet *ifp)
{
	struct rte_mbuf *m0 = *m;

	if (ip_is_fragment(ip)) {
		m0 = ipv4_handle_fragment(*m);
		if (!m0)
			return 0;
		*m = m0;
	}

	return udp_input(m0, AF_INET, ifp);
}

/*
 * deal with fastpath tunnels.
 * Returns 0 on success, -1 if error
 * Returns 1 - not consumed.
 */
int l4_input(struct rte_mbuf **m, struct ifnet *ifp)
{
	struct pl_packet pl_pkt = {
		.mbuf = *m,
		.in_ifp = ifp,
	};

	pipeline_fused_ipv4_l4(&pl_pkt);

	return 0;
}

/*
 * Deliver local destined packet to slow path
 */
void __cold_func
ip_local_deliver(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct vrf *vrf = if_vrf(ifp);
	struct iphdr *ip = iphdr(m);

	/* Real MTU on slow path maybe lower
	 *  because of the overhead of GRE header
	 */
	if (slowpath_mtu && ntohs(ip->tot_len) > slowpath_mtu) {
		if (ip->frag_off & htons(IP_DF)) {
			/* Handle with icmp reply needfrag
			 * for TCP MTU discovery
			 */
			IPSTAT_INC_VRF(vrf, IPSTATS_MIB_FRAGFAILS);
			icmp_error(ifp, m, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				   htons(slowpath_mtu));
			rte_pktmbuf_free(m);
			return;
		}
		/* Let raw socket in kernel handle fragmentation */
	}

	/*
	 * CPP input firewall. Enables RFC-6192.
	 *
	 * Run the local firewall,  and discard if so instructed.
	 */
	if (npf_local_fw(ifp, &m, htons(ETHER_TYPE_IPv4)))
		goto discard;

	IPSTAT_INC_VRF(vrf, IPSTATS_MIB_INDELIVERS);
	local_packet(ifp, m);
	return;

discard:
	IPSTAT_INC_VRF(vrf, IPSTATS_MIB_INDISCARDS);
	rte_pktmbuf_free(m);
}

void mcast_ip_deliver(struct ifnet *ifp, struct rte_mbuf *m)
{
	/* output interface is moot so count against pkts vrf */
	IPSTAT_INC_IFP(ifp, IPSTATS_MIB_OUTMCASTPKTS);
	ip_local_deliver(ifp, m);
}

static void ip_unreach(struct ifnet *ifp, struct rte_mbuf *m)
{
	IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INNOROUTES);
	icmp_error(ifp, m, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, 0);
	rte_pktmbuf_free(m);
}

static ALWAYS_INLINE
struct next_hop *ip_lookup(struct rte_mbuf *m, struct ifnet *ifp,
			   struct iphdr *ip, uint32_t tbl_id,
			   bool ttl_decremented)
{
	struct next_hop *nxt;

	/*
	 * Lookup route
	 */
	nxt = dp_rt_lookup(ip->daddr, tbl_id, m);

	/*
	 * No route to destination?
	 */
	if (nxt == NULL) {
		ip_unreach(ifp, m);
		return NULL;
	}

	/*
	 * Either route destination is an interface outside of dataplane
	 * or dst is local
	 */
	if (nxt->flags & (RTF_SLOWPATH | RTF_LOCAL))
		goto slow_path;

	return nxt;

 slow_path: __cold_label;
	if (ttl_decremented)
		increment_ttl(ip);
	ip_local_deliver(ifp, m);
	return NULL;
}

/*
 * ip_out_features
 *
 * The use of pipeline fused-mode functions here is an interim step
 * towards this function or its users being converted into pipeline
 * nodes and an appropriate pipeline graph. It should not be seen as
 * an example newly-written code.
 */
ALWAYS_INLINE
void ip_out_features(struct rte_mbuf *m, struct ifnet *ifp,
		     struct iphdr *ip, struct next_hop *nxt,
		     in_addr_t addr, enum ip4_features ip4_feat,
		     uint16_t npf_flags)
{
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.nxt.v4 = nxt,
		.l3_hdr = ip,
		.npf_flags = npf_flags,
		.in_ifp = ifp,
	};

	/* nxt->ifp may be changed by netlink messages. */
	struct ifnet *nxt_ifp = dp_nh4_get_ifp(nxt);

	/* Destination device is not up? */
	if (!nxt_ifp || !(nxt_ifp->if_flags & IFF_UP)) {
		icmp_error(ifp, m, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
		goto drop;
	}

	pktmbuf_clear_rx_vlan(m);

	if (!(ip4_feat & (IP4_FEA_ORIGINATE|IP4_FEA_DECAPPED))) {
		/*
		 * If forwarding packet using same interface that it came in on,
		 * perhaps should send a redirect to sender to shortcut a hop.
		 * Only send redirect if source is sending directly to us,
		 * Also, don't send redirect if forwarding using a default route
		 * or a route modified by a redirect.
		 */
		if (unlikely(nxt_ifp == ifp)) {
			if (ip_same_network(ifp, addr, ip->saddr) &&
			    ip_redirects_get())
				icmp_error(ifp, m, ICMP_REDIRECT,
					   ICMP_REDIR_HOST, addr);
		}
	}

	/* macvlan mac passthrough check & replace ifp */
	pl_pkt.out_ifp = macvlan_check_vrrp_if(nxt_ifp);

	if (ip4_feat & IP4_FEA_ORIGINATE)
		pl_pkt.npf_flags |= NPF_FLAG_FROM_US;

	pipeline_fused_ipv4_out(&pl_pkt);
	return;

 drop:	__cold_label;
	rte_pktmbuf_free(m);
	return;
}

static ALWAYS_INLINE
void ip_switch(struct rte_mbuf *m, struct ifnet *ifp,
	       struct iphdr *ip, struct next_hop *nxt,
	       enum ip4_features ip4_feat, uint16_t npf_flags)
{
	in_addr_t addr;

	/*
	 * Immediately drop blackholed traffic, and directed broadcasts
	 * for either the all-ones or all-zero subnet addresses on
	 * locally attached networks.
	 */
	if (nxt->flags & (RTF_BLACKHOLE|RTF_BROADCAST))
		goto drop;

	if (nxt->flags & RTF_REJECT) {
		icmp_error(ifp, m, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
		goto drop;
	}

	/* MPLS imposition required because nh has given us a label */
	if (unlikely(nh_outlabels_present(&nxt->outlabels))) {
		union next_hop_v4_or_v6_ptr mpls_nh = { .v4 = nxt };

		mpls_unlabeled_input(ifp, m, NH_TYPE_V4GW, mpls_nh, ip->ttl);
		return;
	}

	/* Store next hop address  */
	if (nxt->flags & RTF_GATEWAY)
		addr = nxt->gateway4;
	else
		addr = ip->daddr;

	ip_out_features(m, ifp, ip, nxt, addr, ip4_feat, npf_flags);
	return;

 drop:	__cold_label;
	/*
	 * The LPM is used to perform loopback destination addr check,
	 * so increment appropriate stats for such a destination here.
	 */
	if (unlikely(IN_LOOPBACK(ntohl(ip->daddr))))
		IPSTAT_INC(if_vrfid(ifp), IPSTATS_MIB_INADDRERRORS);
	rte_pktmbuf_free(m);
}

static ALWAYS_INLINE
enum ip_packet_validity ip_validate_packet(
	struct rte_mbuf *m, const struct iphdr *ip, bool *needs_slow_path)
{
	unsigned int len, ip_len, pkt_len;
	uint16_t hlen;

	assert(dp_pktmbuf_l2_len(m) ==
	       (const char *)ip - rte_pktmbuf_mtod(m, char *));

	*needs_slow_path = false;

	/*
	 * Is packet big enough.
	 * (i.e is there a valid IP header in first segment)
	 */
	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);
	if (len < sizeof(struct iphdr))
		goto bad_hdr;

	/*
	 * Is it IPv4?
	 */
	if (ip->version != IPVERSION)
		goto bad_hdr;

	/*
	 * Is IP header length correct and is it in first mbuf?
	 */
	hlen = ip->ihl << 2;
	if (hlen < sizeof(struct iphdr) || hlen > len)
		goto bad_hdr;
	dp_pktmbuf_l3_len(m) = hlen;

	/*
	 * Checksum correct?
	 */
	if (ip_checksum(ip, hlen))
		goto bad_hdr;

	/*
	 * Is IP header malformed (tot length < header length)
	 */
	ip_len = ntohs(ip->tot_len);
	if (ip_len < hlen)
		goto bad_hdr;

	/*
	 * Validate IP options if any
	 * ip_dooptions returns 1 when an error was detected.
	 */
	if (hlen > sizeof(struct iphdr) &&
	    ip_dooptions(m, needs_slow_path))
		goto bad_hdr;

	pkt_len = rte_pktmbuf_pkt_len(m) - dp_pktmbuf_l2_len(m);

	/*
	 * Is IP length longer than packet we have got?
	 */
	if (unlikely(pkt_len < ip_len))
		goto pkt_truncated;

	/*
	 * Is packet longer than IP header tells us?
	 */
	if (unlikely(pkt_len > ip_len))
		rte_pktmbuf_trim(m, pkt_len - ip_len);

	/*
	 * Is packet from or to 127/8?
	 */
	if (unlikely(IN_LOOPBACK(ntohl(ip->saddr))))
		return IP_PKT_BAD_ADDR;

	return IP_PKT_VALID;
bad_hdr: __cold_label;
	return IP_PKT_BAD_HDR;
pkt_truncated: __cold_label;
	return IP_PKT_TRUNCATED;
}

bool ip_valid_packet(struct rte_mbuf *m, const struct iphdr *ip)
{
	bool ra_present = false;

	return ip_validate_packet(m, ip, &ra_present) == IP_PKT_VALID;
}

ALWAYS_INLINE
bool ip_validate_packet_and_count(struct rte_mbuf *m, const struct iphdr *ip,
				  struct ifnet *ifp, bool *needs_slow_path)
{
	enum ip_packet_validity pkt_validity;

	pkt_validity = ip_validate_packet(m, ip, needs_slow_path);
	if (unlikely(pkt_validity != IP_PKT_VALID)) {
		switch (pkt_validity) {
		case IP_PKT_BAD_ADDR:
			IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INADDRERRORS);
			break;
		case IP_PKT_TRUNCATED:
			IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INTRUNCATEDPKTS);
			break;
		default: /* really only IP_PKT_BAD_HDR */
			IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INHDRERRORS);
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
void ip_input_from_ipsec(struct ifnet *ifp, struct rte_mbuf *m)
{
	bool needs_slow_path;
	struct iphdr *ip = iphdr(m);
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.l2_pkt_type = L2_PKT_UNICAST,
		.in_ifp = ifp,
		.l3_hdr = ip,
		.tblid = RT_TABLE_MAIN,
		.npf_flags = NPF_FLAG_CACHE_EMPTY,
	};

	if (unlikely(!ip_validate_packet_and_count(m, ip, ifp,
						   &needs_slow_path))) {
		rte_pktmbuf_free(m);
		return;
	}

	pl_pkt.val_flags |= needs_slow_path ?
		NEEDS_SLOWPATH : NEEDS_EMPTY;

	pipeline_fused_ipv4_route_lookup(&pl_pkt);
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
ip_lookup_and_originate(struct rte_mbuf *m, struct ifnet *in_ifp)
{
	struct iphdr *ip = iphdr(m);
	struct next_hop *nxt;

	nxt = ip_lookup(m, in_ifp, ip, RT_TABLE_MAIN, false);
	if (!nxt)
		return;

	enum ip4_features ip4_feat = IP4_FEA_ORIGINATE;
	ip_switch(m, in_ifp, ip, nxt, ip4_feat, NPF_FLAG_CACHE_EMPTY);
}

void
ip_input_decap(struct ifnet *in_ifp, struct rte_mbuf *m,
	       enum l2_packet_type l2_pkt_type __unused)
{
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.l2_pkt_type = L2_PKT_UNICAST,
		.in_ifp = in_ifp,
	};
	pipeline_fused_ipv4_validate(&pl_pkt);
}

/*
 * This should not be called for locally generated packets,
 * only for forwarded packets.  The packet passed in here may be
 * a fragment,  in which case if NAT or the firewall is enabled,
 * it will be subject to reassembly.
 */
void
ip_lookup_and_forward(struct rte_mbuf *m, struct ifnet *in_ifp,
		      bool ttl_decremented, uint16_t npf_flags)
{
	struct iphdr *ip = iphdr(m);
	struct next_hop *nxt;

	/* Don't forward packets with unspecified source address */
	if (unlikely(!ip->saddr)) {
		IPSTAT_INC_IFP(in_ifp, IPSTATS_MIB_INADDRERRORS);
		rte_pktmbuf_free(m);
		return;
	}

	nxt = ip_lookup(m, in_ifp, ip, RT_TABLE_MAIN, ttl_decremented);
	if (!nxt)
		return;

	if (!ttl_decremented)
		decrement_ttl(ip);

	enum ip4_features ip4_feat = IP4_FEA_REASSEMBLE;
	ip_switch(m, in_ifp, ip, nxt, ip4_feat, npf_flags);
}

/* Output func for spath fragmentation */
static void ip_spath_frag_output(struct ifnet *ifp __unused,
				 struct rte_mbuf *m, void *ctx)
{
	struct ifnet *l2_ifp = ctx;

	if_output(l2_ifp, m, NULL, ETH_P_IP);
}

/*
 * IPv4 slow output path filter.
 *
 * Run the output firewall,  and drop the packet if required.
 *
 * Return an indication of if the packet was consumed.
 *    0 => Not consumed
 *    1 => Consumed by reassembly or filter
 */
static int
ip_spath_filter_internal(struct ifnet *ifp, struct ifnet *l2_ifp,
			 struct rte_mbuf **mp)
{
	uint16_t npf_flags = NPF_FLAG_CACHE_EMPTY;
	struct rte_mbuf *m = *mp;
	struct iphdr *ip = iphdr(m);

	dp_pktmbuf_l3_len(m) = ip->ihl << 2;

	/* The kernel can still forward some packets, identify them.  */
	if (!ip->saddr || is_local_ipv4(if_vrfid(ifp), ip->saddr)) {
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
		.nxt.v4 = NULL,
		.l3_hdr = ip,
		.npf_flags = npf_flags,
		.in_ifp = NULL,
		.out_ifp = ifp,
	};

	if (!pipeline_fused_ipv4_defrag_out_spath(&pl_pkt))
		return 1;

	if (unlikely(m != pl_pkt.mbuf))
		*mp = pl_pkt.mbuf;

	return 0;	/* packet not filtered */
}

int
ip_spath_filter(struct ifnet *l2_ifp, struct rte_mbuf **mp)
{
	struct bridge_port *brport;
	struct ifnet *ifp;

	/* The ifp may be a member link of a bridge */
	brport = rcu_dereference(l2_ifp->if_brport);
	if (brport)
		ifp = bridge_port_get_bridge(brport);
	else
		ifp = l2_ifp;

	return ip_spath_filter_internal(ifp, l2_ifp, mp);
}

/*
 * IPv4 slow path output.
 * Attempts to apply post-routing features and output the packet.
 * Packet is consumed.
 */
int
ip_spath_output(struct ifnet *l2_ifp, struct rte_mbuf *m)
{
	struct bridge_port *brport;
	struct ifnet *ifp;

	/* The ifp may be a member link of a bridge */
	brport = rcu_dereference(l2_ifp->if_brport);
	if (brport)
		ifp = bridge_port_get_bridge(brport);
	else
		ifp = l2_ifp;

	if (ip_spath_filter_internal(ifp, l2_ifp, &m))
		return 0;	/* filtered or reassembled */

	/* re-frag if needed */
	struct iphdr *ip = iphdr(m);
	if (unlikely(ntohs(ip->tot_len) > ifp->if_mtu)) {
		if (ip->frag_off & htons(IP_DF))
			goto drop;
		ip_fragment(ifp, m, l2_ifp, ip_spath_frag_output);
		return 0;
	}

	if_output(l2_ifp, m, NULL, ETH_P_IP);
	return 0;

drop:
	rte_pktmbuf_free(m);
	return -1;
}
