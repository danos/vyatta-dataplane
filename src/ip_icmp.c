/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ip_icmp.c	8.2 (Berkeley) 1/4/94
 */

#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <urcu/list.h>

#include "if/macvlan.h"
#include "if_var.h"
#include "in_cksum.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "pktmbuf_internal.h"
#include "route.h"
#include "snmp_mib.h"
#include "urcu.h"
#include "util.h"
#include "nh_common.h"
#include "npf/npf_nat.h"
#include "npf/cgnat/cgn.h"
#include "fal.h"
#include "netinet6/ip6_funcs.h"
#include "vplane_log.h"

/*
 * RFC4884 extended header
 */
struct ih_exthdr {
	u_int8_t  iex_pad;
	u_int8_t  iex_length;
} ih_exthdr;

struct icmp_ext_hdr {
	u_int8_t  ieh_version;		/* only high nibble used */
	u_int8_t  ieh_res;		/* reserved, must be zero */
	u_int16_t ieh_cksum;		/* ones complement cksum of ext hdr */
};

#define ICMP_EXT_HDR_VERSION	0x20
#define ICMP_EXT_HDR_VMASK	0xf0
#define ICMP_EXT_OFFSET		128

struct icmp_ext_obj_hdr {
	u_int16_t ieo_length;		/* length of obj incl this header */
	u_int8_t  ieo_cnum;		/* class number */
	u_int8_t  ieo_ctype;		/* sub class type */
};

static bool ip_redirects = true;
uint64_t icmpstats[ICMP_MIB_MAX];

static void icmp_out_inc(vrfid_t vrf_id, uint8_t type)
{
	switch (type) {
	case ICMP_DEST_UNREACH:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTDESTUNREACHS);
		break;
	case ICMP_TIME_EXCEEDED:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTTIMEEXCDS);
		break;
	case ICMP_PARAMETERPROB:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTPARMPROBS);
		break;
	case ICMP_SOURCE_QUENCH:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTSRCQUENCHS);
		break;
	case ICMP_REDIRECT:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTREDIRECTS);
		break;
	case ICMP_ECHO:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTECHOS);
		break;
	case ICMP_ECHOREPLY:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTECHOREPS);
		break;
	case ICMP_TIMESTAMP:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTTIMESTAMPS);
		break;
	case ICMP_TIMESTAMPREPLY:
		ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTTIMESTAMPREPS);
		break;
	}

	ICMPSTAT_INC(vrf_id, ICMP_MIB_OUTMSGS);
}

void ip_redirects_set(bool enable)
{
	int ret;
	const struct fal_attribute_t attr[1] = {
		{FAL_SWITCH_ATTR_RX_ICMP_REDIR_ACTION,
		 .value.u32 = enable ? FAL_PACKET_ACTION_TRAP :
		 FAL_PACKET_ACTION_FORWARD} };

	ip_redirects = enable;
	if (ip6_redirects_get())
		return;

	ret = fal_set_switch_attr(attr);
	if (ret < 0) {
		RTE_LOG(NOTICE, DATAPLANE,
			"FAL Unable to %sable ICMP Redirects\n",
			enable ? "en" : "dis");
	}
}

bool ip_redirects_get(void)
{
	return ip_redirects;
}

void
icmp_prepare_send(struct rte_mbuf *m)
{
	struct iphdr *ip;
	int hlen;
	struct icmphdr *icp;

	ip = iphdr(m);
	hlen = ip->ihl << 2;
	ip->id = dp_ip_randomid(0);
	ip->check = 0;
	ip->check = in_cksum(ip, hlen);

	icp = (struct icmphdr *) ((char *)ip + hlen);
	icp->checksum = 0;
	icp->checksum = in_cksum(icp, ntohs(ip->tot_len) - hlen);
}

/*
 * Send an icmp packet back to the ip level,
 * after supplying a checksum.
 */
static void
icmp_send(struct rte_mbuf *m, bool srced_forus)
{
	struct iphdr *ip;
	int hlen;
	struct icmphdr *icp;

	icmp_prepare_send(m);

	ip = iphdr(m);
	hlen = ip->ihl << 2;
	icp = (struct icmphdr *) ((char *)ip + hlen);

	icmp_out_inc(pktmbuf_get_vrf(m), icp->type);

	ip_output(m, srced_forus);
}

/*
 * Send an ICMP packet *without* doing a route lookup.  Assumes that the dest
 * ether address already contains the next-hop ether address.
 */
static bool
icmp_send_no_route(struct rte_mbuf *m, struct ifnet *in_ifp,
		   struct ifnet *out_ifp)
{
	struct iphdr *ip;
	int hlen;
	struct icmphdr *icp;
	struct next_hop singlehop_nh;
	struct next_hop *nh = NULL;

	if (!(out_ifp->if_flags & IFF_UP)) {
		rte_pktmbuf_free(m);
		return false;
	}

	icmp_prepare_send(m);

	ip = iphdr(m);
	hlen = ip->ihl << 2;
	icp = (struct icmphdr *) ((char *)ip + hlen);

	icmp_out_inc(pktmbuf_get_vrf(m), icp->type);

	memset(&singlehop_nh, 0, sizeof(singlehop_nh));
	nh_set_ifp(&singlehop_nh, out_ifp);
	nh = &singlehop_nh;

	if (dp_ip_l2_nh_output(in_ifp, m, nh, ETH_P_IP)) {
		IPSTAT_INC_IFP(out_ifp, IPSTATS_MIB_OUTPKTS);
		return true;
	}

	return false;
}

/*
 * Reflect the ip packet back to the source
 *
 * Vyatta: this is simplified from the BSD code
 */
static void
icmp_reflect(const struct ifnet *ifp, struct rte_mbuf *m)
{
	struct iphdr *ip = iphdr(m);
	in_addr_t t;
	bool srced_forus;

	if (IN_MULTICAST(ntohl(ip->saddr)) ||
	    IN_EXPERIMENTAL(ntohl(ip->saddr)) ||
	    IN_ZERONET(ntohl(ip->saddr)))
		goto drop;

	t = ip->daddr;
	ip->daddr = ip->saddr;

	/*
	 * Are we sourcing a packet that is for ourselves
	 * i.e icmp can not frag.
	 */
	srced_forus = is_local_ipv4(if_vrfid(ifp), ip->daddr);
	if (srced_forus) {
		ip->saddr = t;
	} else {
		t = ip_select_source(ifp, ip->saddr);
		if (t) {
			ip->saddr = t;
		} else {
			/*
			 * Should never get here. it means packet was received
			 * on an interface without any IP address
			 */
			ICMPSTAT_INC(pktmbuf_get_vrf(m), ICMP_MIB_OUTERRORS);
			goto drop;
		}
	}

	ip->ttl = IPDEFTTL;
	icmp_send(m, srced_forus);
	return;
drop:
	rte_pktmbuf_free(m);
}

/*
 * Check if address is on this interface.
 */
bool ip_same_network(const struct ifnet *ifp, in_addr_t nxt_gateway,
		     in_addr_t addr)
{
	struct if_addr *ifa;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr_in *sin
			= satosin((struct sockaddr *) &ifa->ifa_addr);
		uint8_t len = 32 - ifa->ifa_prefixlen;

		if (sin->sin_family != AF_INET)
			continue;

		if ((htonl(sin->sin_addr.s_addr) >> len
		    == htonl(addr) >> len) &&
		    (htonl(addr) >> len == htonl(nxt_gateway) >> len))
			return 1;
	}

	return 0;
}

/*
 * Generalized version of  Source selection for ICMP replies
 *
 * returns 0 if no address is known
 */
in_addr_t ip_select_source(const struct ifnet *ifp, in_addr_t dst)
{
	struct if_addr *ifa;
	in_addr_t source_addr = 0;

	/*
	 * If the incoming packet was addressed directly to one of our
	 * own addresses, use dst as the src for the reply.
	 */
	if (is_local_ipv4(if_vrfid(ifp), dst))
		return dst;

	/*
	 * If the incoming packet was addressed to one of our broadcast
	 * addresses, use the first non-broadcast address which corresponds
	 * to the incoming interface.
	 */
	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;
		if (sa->sa_family != AF_INET)
			continue;

		struct sockaddr *ba
			= (struct sockaddr *) &ifa->ifa_broadcast;
		if (satosin(ba)->sin_addr.s_addr == dst)
			return satosin(sa)->sin_addr.s_addr;
	}

	/*
	 * If the packet was transiting through us, use the address of
	 * the interface the packet came through in.  If that interface
	 * doesn't have a suitable IP address, the normal selection
	 * criteria apply.
	 */
	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr_in *sin
			= satosin((struct sockaddr *) &ifa->ifa_addr);

		if (sin->sin_family != AF_INET)
			continue;

		uint8_t len = 32 - ifa->ifa_prefixlen;
		if (!source_addr)
			source_addr = sin->sin_addr.s_addr;

		if (htonl(sin->sin_addr.s_addr) >> len
		    == htonl(dst) >> len) {
			return sin->sin_addr.s_addr;
		}
	}
	return source_addr;
}

/* Check if this is Ethernet broadcast or multicast. */
static bool is_link_multicast(struct rte_mbuf *m)
{
	enum l2_packet_type type = pkt_mbuf_get_l2_traffic_type(m);

	return type == L2_PKT_MULTICAST || type == L2_PKT_BROADCAST;
}

/* Is this not an ICMP error (but an info request instead) */
static bool is_icmp_info(const struct icmphdr *icmp)
{
	return icmp->type == ICMP_ECHOREPLY ||
		icmp->type == ICMP_ECHO ||
		icmp->type == ICMP_ROUTERADVERT ||
		icmp->type == ICMP_ROUTERSOLICIT ||
		icmp->type == ICMP_TSTAMP ||
		icmp->type == ICMP_TSTAMPREPLY ||
		icmp->type == ICMP_IREQ ||
		icmp->type == ICMP_IREQREPLY ||
		icmp->type == ICMP_MASKREQ ||
		icmp->type == ICMP_MASKREPLY;
}

/*
 * Generate an error packet of type error
 * in response to bad packet ip.
 */
struct rte_mbuf *
icmp_do_error(struct rte_mbuf *n, int type, int code, uint32_t info,
	      const struct ifnet *inif, const struct ifnet *outif)
{
	const struct iphdr *oip = iphdr(n);
	struct iphdr *nip;
	unsigned int oiphlen, mlen;
	struct icmphdr *icp;
	struct rte_mbuf *m;
	unsigned int icmplen, icmpelen, pktlen;

	if (n->ol_flags & PKT_RX_SEEN_BY_CRYPTO) {
		if (!inif || (inif->if_type != IFT_TUNNEL_VTI))
			return NULL;
	}

	oiphlen = dp_pktmbuf_l3_len(n);

	/*
	 * Don't send error:
	 *  if not the first fragment of message.
	 *  in response to a multicast or broadcast packet.
	 *  if the old packet protocol was an ICMP error message.
	 */
	if (oip->frag_off & ~htons(IP_MF|IP_DF))
		return NULL;

	if (is_link_multicast(n))
		return NULL;

	if (oip->protocol == IPPROTO_ICMP &&
	    type != ICMP_REDIRECT &&
	    rte_pktmbuf_data_len(n) >= oiphlen + ICMP_MINLEN &&
	    !is_icmp_info((const struct icmphdr *) ((const char *)oip + oiphlen)))
		return NULL;

	/* Drop if IP header plus 8 bytes is not contiguous in first mbuf. */
	pktlen = rte_pktmbuf_data_len(n) - dp_pktmbuf_l2_len(n);
	if (oiphlen + sizeof(struct icmphdr) > pktlen)
		return NULL;

	/*
	 * Calculate length to quote from original packet and
	 * prevent the ICMP mbuf from overflowing.
	 */
	icmpelen = RTE_MAX(8u, RTE_MIN(576u, ntohs(oip->tot_len) - oiphlen));
	icmplen = RTE_MIN(oiphlen + icmpelen, pktlen);
	if (icmplen < sizeof(struct ip))
		return NULL;

	m = pktmbuf_alloc(n->pool, pktmbuf_get_vrf(n));
	if (m == NULL)
		return NULL;

	/* Undo any NAT on a copy or clone of the trigger packet */
	struct rte_mbuf *unnat = NULL;
	if (pktmbuf_mdata_exists(n, PKT_MDATA_SNAT|PKT_MDATA_DNAT)) {

		/* Cannot undo both SNAT/DNAT and CGNAT just now */
		if (pktmbuf_mdata_exists(n, PKT_MDATA_CGNAT_IN |
					 PKT_MDATA_CGNAT_OUT)) {
			rte_pktmbuf_free(m);
			return NULL;
		}

		if (type == ICMP_REDIRECT)
			unnat = npf_nat_copy_and_undo(n, inif, outif);
		else
			unnat = npf_nat_clone_and_undo(n, inif, outif);

		if (!unnat) {
			rte_pktmbuf_free(m);
			return NULL;
		}

		n = unnat;
		oip = iphdr(n);
	}

	if (pktmbuf_mdata_exists(n, PKT_MDATA_CGNAT_IN|PKT_MDATA_CGNAT_OUT)) {
		bool copy = (type == ICMP_REDIRECT);

		/* Copy or clone pkt, and undo translation */
		unnat = cgn_copy_or_clone_and_undo(n, inif, outif, copy);
		if (!unnat) {
			rte_pktmbuf_free(m);
			return NULL;
		}

		n = unnat;
		oip = iphdr(n);
	}

	/* preserve the input port number for use by shadow interface */
	m->port = n->port;

	/*
	 * Set up ICMP message mbuf and copy old IP header (without options)
	 * in front of ICMP message.
	 * If the original mbuf was meant to bypass the firewall, the error
	 * reply should bypass as well.
	 */
	mlen = sizeof(struct iphdr) + sizeof(struct icmphdr) + icmplen;
	rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m) =
		mlen + dp_pktmbuf_l2_len(n);
	dp_pktmbuf_l2_len(m) = dp_pktmbuf_l2_len(n);

	nip = iphdr(m);
	icp = (struct icmphdr *) ((char *) nip + sizeof(struct iphdr));
	memset(icp, 0, sizeof(struct icmphdr));
	icp->type      = type;
	icp->code      = code;
	if (code == ICMP_FRAG_NEEDED)
		icp->un.frag.mtu = info;
	else
		icp->un.gateway = info;

	/* Note: Linux copies options from original packet
	 *	 BSD doesn't
	 */
	nip->ihl	= 5;
	nip->version	= IPVERSION;
	nip->tos	= IPTOS_PREC_INTERNETCONTROL;
	nip->tot_len	= htons(mlen);
	nip->frag_off	= 0;
	nip->protocol	= IPPROTO_ICMP;
	nip->check	= 0;

	/* header swapped in icmp_reflect */
	nip->saddr	= oip->saddr;
	nip->daddr	= oip->daddr;

	/* Copy header for original packet */
	memcpy(icp + 1, oip, icmplen);

	if (unnat)
		rte_pktmbuf_free(unnat);

	pktmbuf_mdata_set(m, PKT_MDATA_FROM_US);
	return m;
}

static void icmp_do_reflect(const struct ifnet *rcvif, struct rte_mbuf *m_in,
			    struct rte_mbuf *m_out)
{
	struct rte_ether_hdr *eh;
	struct ifnet *vrrp_ifp;

	if (!m_out)
		return;

	eh = rte_pktmbuf_mtod(m_in, struct rte_ether_hdr *);
	vrrp_ifp = macvlan_get_vrrp_if(rcvif,
				       (struct rte_ether_addr *)&eh->d_addr);
	if (vrrp_ifp)
		icmp_reflect(vrrp_ifp, m_out);
	else
		icmp_reflect(rcvif, m_out);

}

void
icmp_error(const struct ifnet *rcvif, struct rte_mbuf *n,
	   int type, int code, uint32_t info)
{
	struct rte_mbuf *m;

	m = icmp_do_error(n, type, code, info, rcvif, NULL);
	icmp_do_reflect(rcvif, n, m);
}

void
icmp_error_out(const struct ifnet *rcvif, struct rte_mbuf *n,
	       int type, int code, uint32_t info,
	       const struct ifnet *outif)
{
	struct rte_mbuf *m;

	m = icmp_do_error(n, type, code, info, rcvif, outif);
	icmp_do_reflect(rcvif, n, m);
}

/*
 * Send ICMP echo reply out the rcv interface in response to an echo request.
 */
static struct rte_mbuf *
icmp_do_echo_reply(struct ifnet *ifp, struct rte_mbuf *n, bool reflect)
{
	const struct iphdr *oip = iphdr(n);
	struct iphdr *nip;
	struct icmphdr *nicmp;
	struct rte_mbuf *m;
	uint pktlen;

	/* Drop if there are any IP options */
	if (dp_pktmbuf_l3_len(n) > sizeof(struct iphdr))
		return NULL;

	/* Drop if IP header plus 8 bytes is not contiguous in first mbuf. */
	pktlen = rte_pktmbuf_data_len(n) - dp_pktmbuf_l2_len(n);

	if (sizeof(struct iphdr) + sizeof(struct icmphdr) > pktlen)
		return NULL;

	/* Make a copy of the ICMP Request packet */
	m = pktmbuf_copy(n, n->pool);
	if (m == NULL)
		return NULL;

	/*
	 * Drop if the new packet is not all in the one mbuf.  The ICMP
	 * checksum is calculated over the ICMP header and ICMP data, and this
	 * assumes these are contiguous.
	 */
	if (rte_pktmbuf_data_len(m) != rte_pktmbuf_pkt_len(m)) {
		rte_pktmbuf_free(m);
		return NULL;
	}

	/* preserve the input port number for use by shadow interface */
	m->port = n->port;

	struct rte_ether_hdr *neh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* Ethernet source addr is interface address */
	rte_ether_addr_copy(&ifp->eth_addr, &neh->s_addr);

	if (reflect) {
		/* Echo req source ether is echo reply dest ether */
		struct rte_ether_hdr *oeh =
				rte_pktmbuf_mtod(n, struct rte_ether_hdr *);
		rte_ether_addr_copy(&oeh->s_addr, &neh->d_addr);
	}

	nip = iphdr(m);

	/* Swap source and dest IP addrs from icmp request */
	nip->saddr	= oip->daddr;
	nip->daddr	= oip->saddr;

	nip->ihl	= 5;
	nip->version	= IPVERSION;
	nip->tos	= 0;
	nip->tot_len	= oip->tot_len;
	nip->frag_off	= 0;
	nip->protocol	= IPPROTO_ICMP;
	nip->ttl	= IPDEFTTL;

	/* Change the icmp type to ICMP_ECHOREPLY */
	nicmp = (struct icmphdr *)((char *)nip + sizeof(struct iphdr));
	nicmp->type = ICMP_ECHOREPLY;

	pktmbuf_mdata_set(m, PKT_MDATA_FROM_US);
	return m;
}

/*
 * Send ICMP echo reply out the receive interface in response to an echo
 * request.
 *
 * Returns true if successful.
 */
bool icmp_echo_reply_out(struct ifnet *rcvifp, struct rte_mbuf *n,
			 bool reflect)
{
	struct rte_mbuf *m;
	bool rv = true;

	m = icmp_do_echo_reply(rcvifp, n, reflect);
	if (!m)
		return false;

	if (reflect)
		/* Reflect reply directly back to sender */
		rv = icmp_send_no_route(m, rcvifp, rcvifp);
	else
		icmp_send(m, false);

	return rv;
}

u_int16_t
icmp_common_exthdr(struct rte_mbuf *m, uint16_t cnum, uint8_t ctype,
		   void *buf, void *ip_hdr, int hlen, u_int16_t ip_total_len,
		   void *dataun, unsigned int len)
{
	int off, padding;
	struct ih_exthdr *ih_exthdr;
	struct icmp_ext_hdr *ieh;
	struct {
		struct icmp_ext_hdr     ieh;
		struct icmp_ext_obj_hdr ieo;
	} hdr;

	ih_exthdr = dataun;
	if (ih_exthdr->iex_length != 0)
		/* exthdr already present, giving up */
		return 0;

	/* the actual offset starts after the common ICMP header */
	hlen += ICMP_MINLEN;
	/* exthdr must start on a word boundary */
	off = roundup(ip_total_len - hlen, sizeof(uint32_t));
	/* ... and at an offset of ICMP_EXT_OFFSET or bigger */
	off = MAX(off, ICMP_EXT_OFFSET);
	ih_exthdr->iex_length = off / sizeof(uint32_t);

	memset(&hdr, 0, sizeof(hdr));
	hdr.ieh.ieh_version = ICMP_EXT_HDR_VERSION;
	hdr.ieo.ieo_length = htons(sizeof(struct icmp_ext_obj_hdr) + len);
	hdr.ieo.ieo_cnum = cnum;
	hdr.ieo.ieo_ctype = ctype;

	/* sanity check there is enough room in the buffer */
	padding = hlen + off - ip_total_len;
	if (padding < 0)
		padding = 0;
	if (padding + sizeof(hdr) + len > rte_pktmbuf_tailroom(m))
		return 0;

	/* fill in extended header and zero-fill any gap */
	if (padding)
		memset((char *)ip_hdr + ip_total_len, 0, padding);
	memcpy((char *)ip_hdr + hlen + off, &hdr, sizeof(hdr));
	memcpy((char *)ip_hdr + hlen + off + sizeof(hdr), buf, len);

	/* calculate checksum */
	ieh = (struct icmp_ext_hdr *)((char *)ip_hdr + hlen + off);
	ieh->ieh_cksum = in_cksum(ieh, sizeof(hdr) + len);

	rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m) =
		hlen + off + sizeof(hdr) + len + dp_pktmbuf_l2_len(m);

	return hlen + off + sizeof(hdr) + len;
}

int
icmp_do_exthdr(struct rte_mbuf *m, uint16_t class, uint8_t ctype, void *buf,
	       unsigned int len)
{
	struct iphdr *ip = iphdr(m);
	u_int16_t total_len;
	struct icmphdr *icp;
	int hlen;

	hlen = dp_pktmbuf_l3_len(m);
	icp = (struct icmphdr *) ((char *) ip + hlen);
	if (icp->type != ICMP_TIME_EXCEEDED && icp->type != ICMP_DEST_UNREACH &&
	    icp->type != ICMP_PARAMETERPROB)
		/* exthdr not supported */
		return 0;

	total_len = icmp_common_exthdr(m, class, ctype, buf, ip, hlen,
				       ntohs(ip->tot_len), &icp->un, len);

	if (total_len)
		ip->tot_len = htons(total_len);

	return 0;
}
