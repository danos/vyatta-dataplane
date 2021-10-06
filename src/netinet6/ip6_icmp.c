/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * IPv6 ICMP
 */

#include <linux/snmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <urcu/list.h>

#include "ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "in6.h"
#include "in6_var.h"
#include "in_cksum.h"
#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "nd6_nbr.h"
#include "pktmbuf_internal.h"
#include "route_flags.h"
#include "route_v6.h"
#include "snmp_mib.h"
#include "urcu.h"
#include "ip_icmp.h"
#include "vplane_log.h"
#include "fal.h"
#include "protobuf.h"
#include "protobuf/ICMPRateLimConfig.pb-c.h"

/*
 * ICMP6 payload size. The below code assumes the size includes an
 * allowance for the ICMP6 header. There is also the assumption that
 * the size of any generated ICMP6 packet is less than the minimum
 * IPv6 MTU size.
 */
#define ICMP6_PLD_MAXLEN (ICMP6_PAYLOAD_SIZE + sizeof(struct icmp6_hdr))
static_assert(ICMP6_PLD_MAXLEN + sizeof(struct ip6_hdr) < 1280,
		"ICMP6 payload too large");
/* Option Formats
   Length	8-bit unsigned integer.  The length of the option (including
		the type and length fields) in units of 8 octets.   */
#define ICMP6_OPT_LEN(opttype, len) (((sizeof(struct opttype) + (len)) + 7) / 8)

static bool ip6_redirects = true;

/* Traffic class value to be used when dataplane sending ICMP error packets. */
static uint8_t icmp6_error_tclass = IPTOS_CLASS_CS6;

/*
 * ICMP Rate limiting state for configurable types. Entry 0 holds
 * default values.
 */
struct icmp_ratelimit_state icmp6_ratelimit_state[] = {
	[ICMP6_DST_UNREACH] = {.name = "destination-unreachable"},
	[ICMP6_PACKET_TOO_BIG] = {.name = "too-big"},
	[ICMP6_TIME_EXCEEDED] = {.name = "time-exceeded"},
	[ICMP6_PARAM_PROB] = {.name = "parameter-problem"},
};

struct icmp_ratelimit_state *icmp6_get_rl_state(void)
{
	return icmp6_ratelimit_state;
}

uint8_t icmp6_get_rl_state_entries(void)
{
	return sizeof(icmp6_ratelimit_state)/sizeof(struct icmp_ratelimit_state);
}

/*
 * Get a value for an address' scope
 *
 * As defined by RFC6724 s3.1.
 */
static int ip6_address_scope(const struct in6_addr *addr)
{
	if (IN6_IS_ADDR_MC_NODELOCAL(addr))
		return 0x1;

	if (IN6_IS_ADDR_MC_LINKLOCAL(addr) || IN6_IS_ADDR_LINKLOCAL(addr))
		return 0x2;

	if (IN6_IS_ADDR_MC_SITELOCAL(addr) || IN6_IS_ADDR_SITELOCAL(addr))
		return 0x5;

	if (IN6_IS_ADDR_MC_ORGLOCAL(addr))
		return 0x8;

	/* otherwise unicast or multicast global */
	return 0xe;
}

/*
 * Select source address for ICMP
 *
 * Behaviour specified by RFC6724 s5.
 */
const struct in6_addr *
ip6_select_source(struct ifnet *ifp, const struct in6_addr *addr)
{
	struct if_addr *ifa;
	struct in6_addr *best = NULL;
	int scope_addr = -1;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;
		int scope_best;
		int scope_ifa;

		if (sa->sa_family != AF_INET6)
			continue;

		/* RFC rule 1: Prefer same address */
		if (IN6_ARE_ADDR_EQUAL(addr, IFA_IN6(ifa)))
			return addr;

		if (!best) {
			best = IFA_IN6(ifa);
			continue;
		}

		/*
		 * Rule 2: Prefer appropriate scope.
		 *
		 * If Scope(SA) < Scope(SB): If Scope(SA) < Scope(D),
		 * then prefer SB and otherwise prefer SA.  Similarly,
		 * if Scope(SB) < Scope(SA): If Scope(SB) < Scope(D),
		 * then prefer SA and otherwise prefer SB.
		 */
		scope_best = ip6_address_scope(best);
		if (scope_addr < 0)
			scope_addr = ip6_address_scope(addr);
		scope_ifa = ip6_address_scope(IFA_IN6(ifa));
		if (scope_best < scope_ifa && scope_best < scope_addr)
			best = IFA_IN6(ifa);
		else if (scope_ifa < scope_best && scope_ifa >= scope_addr)
			best = IFA_IN6(ifa);
	}

	return best;
}

/*
 * Send the ip packet back to the source
 */
void
icmp6_reflect(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct rte_ether_hdr *eh = ethhdr(m);

	eh->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ICMP6STAT_INC(pktmbuf_get_vrf(m), ICMP6_MIB_OUTMSGS);
	ip6_lookup_and_originate(m, ifp);
}

void
icmp6_prepare_send(struct rte_mbuf *m)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct icmp6_hdr *icmp6;

	icmp6 = (struct icmp6_hdr *) ((char *)ip6 + sizeof(*ip6));
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in6_cksum(ip6, IPPROTO_ICMPV6,
				       sizeof(*ip6), ntohs(ip6->ip6_plen));
}

static bool icmp6_ignore(struct rte_mbuf *m)
{
	struct icmp6_hdr *icmp6;
	uint16_t off;

	switch (ip6_findpayload(m, &off)) {
	/* bad or truncated packet */
	case IPPROTO_MAX:
	/* only send an error for the first fragment */
	case IPPROTO_FRAGMENT:
		return true;
	case IPPROTO_ICMPV6:
		icmp6 = ip6_exthdr(m, off, sizeof(*icmp6));
		if (!icmp6)
			return true;
		/*
		 * RFC 4443, 2.4 (e.1): do not send a response to an
		 * ICMPv6 error message i.e. ignore if not informational
		 */
		return (icmp6->icmp6_type & ICMP6_INFOMSG_MASK) == 0;
	default:
		return false;
	}
}

int
icmp6_do_exthdr(struct rte_mbuf *m, uint16_t class, uint8_t ctype, void *buf,
		unsigned int len)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct icmp6_hdr *icmpv6;
	u_int16_t total_len;
	int hlen;

	hlen = dp_pktmbuf_l3_len(m);
	icmpv6 = (struct icmp6_hdr *) ((char *) ip6 + hlen);
	switch (icmpv6->icmp6_type) {
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_DST_UNREACH:
		break;
	default:
		/* exthdr not supported */
		return 0;
	}

	total_len = icmp_common_exthdr(m, class, ctype, buf, ip6, hlen,
				       ntohs(ip6->ip6_plen) + sizeof(*ip6),
				       &icmpv6->icmp6_dataun, len);
	if (total_len)
		ip6->ip6_plen = htons(total_len - hlen);

	return 0;
}

struct icmp6_lookup_minscope {
	int minscope;
	struct ifnet *rcvif;
	struct in6_addr *saddr;
};

static void icmp6_lookup_minscope(struct ifnet *ifp, void *arg)
{
	struct icmp6_lookup_minscope *ctx = arg;
	struct if_addr *ifa;

	/* The first one will do. */
	if (ctx->saddr != NULL)
		return;

	/* Just look at loopback interfaces for now, in same vrf. */
	if (ifp->if_type != IFT_LOOP || ifp->if_vrfid != ctx->rcvif->if_vrfid)
		return;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;

		if (sa->sa_family != AF_INET6)
			continue;

		if (IN6_IS_ADDR_LOOPBACK(IFA_IN6(ifa)))
			continue;

		if (ip6_address_scope(IFA_IN6(ifa)) >= ctx->minscope) {
			ctx->saddr = IFA_IN6(ifa);
			return;
		}
	}
}

/*
 * Generate an error packet of type error in response to bad IP6 packet.
 * param should be in network order.
 */
struct rte_mbuf *icmp6_do_error(struct ifnet *rcvif, struct rte_mbuf *n,
				int type, int code, uint32_t param,
				int minscope)
{
	const struct ip6_hdr *oip6 = ip6hdr(n);

	/*
	 * If the destination address of the erroneous packet is a multicast
	 * address, or the packet was sent using link-layer multicast,
	 * we should basically suppress sending an error (RFC 4443, Section
	 * 2.4).
	 * We have two exceptions (the item e.2 in that section):
	 * - the Packet Too Big message can be sent for path MTU discovery.
	 * - the Parameter Problem Message that can be allowed an icmp6 error
	 *   in the option type field.  This check has been done in
	 *   ip6_unknown_opt(), so we can just check the type and code.
	 */
	if (IN6_IS_ADDR_MULTICAST(&oip6->ip6_dst) &&
	    (type != ICMP6_PACKET_TOO_BIG &&
	     (type != ICMP6_PARAM_PROB ||
	      code != ICMP6_PARAMPROB_OPTION)))
		return NULL;

	/*
	 * RFC 4443, 2.4 (e.5): source address check. Anycast or unspecified
	 * addresses are ignored by checking for an interface id of zero.
	 */
	if (IN6_IS_ADDR_MULTICAST(&oip6->ip6_src) ||
	    in6_is_addr_id_zero(&oip6->ip6_src))
		return NULL;

	if (icmp6_ignore(n))
		return NULL;

	if (icmp_ratelimit_drop(type, AF_INET6, icmp6_ratelimit_state,
				icmp6_get_rl_state_entries()))
		return NULL;

	/* Find our source address on the interface */
	const struct in6_addr *saddr
		= ip6_select_source(rcvif, &oip6->ip6_dst);
	if (minscope && saddr != NULL && minscope > ip6_address_scope(saddr)) {
		/* See if we can find a suitable address elsewhere */
		struct icmp6_lookup_minscope ctx = {
			.minscope = minscope,
			.rcvif = rcvif,
			.saddr = NULL,
		};
		dp_ifnet_walk(icmp6_lookup_minscope, &ctx);
		saddr = ctx.saddr;
	}

	if (saddr == NULL) {
		ICMP6STAT_INC(pktmbuf_get_vrf(n), ICMP6_MIB_OUTERRORS);
		return NULL;
	}

	struct rte_mbuf *m = pktmbuf_alloc(n->pool, pktmbuf_get_vrf(n));
	if (m == NULL)
		return NULL;

	/* Copy up to ICPMV6_PLD_MAXLEN bytes from the orignal packet */
	unsigned int icmplen = RTE_MIN(ICMP6_PLD_MAXLEN -
				       sizeof(struct icmp6_hdr),
				       (unsigned int) rte_pktmbuf_data_len(n)
				       - dp_pktmbuf_l2_len(n));
	uint16_t plen = sizeof(struct icmp6_hdr) + icmplen;
	if (!rte_pktmbuf_append(m,
			dp_pktmbuf_l2_len(n) + sizeof(struct ip6_hdr) + plen))
		rte_panic("out of space to append icmp\n");

	dp_pktmbuf_l2_len(m) = dp_pktmbuf_l2_len(n);

	/* preserve the input port number for use by shadow interface */
	m->port = n->port;

	/*
	 * OK, ICMP6 can be generated.
	 */
	struct ip6_hdr *nip6 = ip6hdr(m);
	nip6->ip6_src = *saddr;
	nip6->ip6_dst = oip6->ip6_src;
	nip6->ip6_flow = oip6->ip6_flow & IPV6_FLOWLABEL_MASK;
	nip6->ip6_flow |= htonl(icmp6_error_tclass << 20);
	nip6->ip6_vfc |= IPV6_VERSION;

	nip6->ip6_plen = htons(plen);
	nip6->ip6_nxt = IPPROTO_ICMPV6;
	nip6->ip6_hlim = IPV6_DEFAULT_HOPLIMIT;

	struct icmp6_hdr *icmp6
		= (struct icmp6_hdr *)(nip6 + 1);
	icmp6->icmp6_type = type;
	icmp6->icmp6_code = code;
	icmp6->icmp6_pptr = param;

	memcpy(icmp6 + 1, oip6, icmplen);

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = in6_cksum(nip6, IPPROTO_ICMPV6,
				       sizeof(*nip6), plen);
	/*
	 * RFC 4291 Source/destination address of unspecified must never be
	 * forwarded. (Destination already checked above.)
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&nip6->ip6_src)) {
		IP6STAT_INC(pktmbuf_get_vrf(m), IPSTATS_MIB_INADDRERRORS);
		return NULL;
	}

	/*
	 * RFC 4291 A destination address of loopback must never be sent
	 * outside of a single node.
	 * Drop packets not on loopback interface that have a loopback
	 * destination address.
	 */
	if (in6_setscope(&nip6->ip6_src, rcvif, NULL) ||
	    in6_setscope(&nip6->ip6_dst, rcvif, NULL)) {
		IP6STAT_INC(pktmbuf_get_vrf(m), IPSTATS_MIB_INADDRERRORS);
		return NULL;
	}

	pktmbuf_mdata_set(m, PKT_MDATA_FROM_US);
	return m;
}

void icmp6_error(struct ifnet *rcvif, struct rte_mbuf *n,
		 int type, int code, uint32_t param)
{
	struct rte_mbuf *m;

	m = icmp6_do_error(rcvif, n, type, code, param, 0);
	if (m)
		icmp6_reflect(rcvif, m);

	dp_pktmbuf_notify_and_free(n);
}

void ip6_redirects_set(bool enable)
{
	int ret;
	const struct fal_attribute_t attr[1] = {
		{FAL_SWITCH_ATTR_RX_ICMP_REDIR_ACTION,
		 .value.u32 = enable ? FAL_PACKET_ACTION_TRAP :
		 FAL_PACKET_ACTION_FORWARD} };

	ip6_redirects = enable;
	if (ip_redirects_get())
		return;

	ret = fal_set_switch_attr(attr);
	if (ret < 0) {
		RTE_LOG(NOTICE, DATAPLANE,
			"FAL Unable to %sable ICMPv6 Redirects\n",
			enable ? "en" : "dis");
	}
}

inline bool ip6_redirects_get(void)
{
	return ip6_redirects;
}

/*
 * Send Neighbour Discovery redirect
 * Does not modify original packet (n)
 */
void icmp6_redirect(struct ifnet *ifp, struct rte_mbuf *n,
		    const struct next_hop *nxt)
{
	const struct ip6_hdr *sip6 = ip6hdr(n);
	struct in6_addr saddr6 = sip6->ip6_src;

	if (!ip6_redirects_get())
		return;

	/*
	 * Address check:
	 *  the source address must identify a neighbor, and
	 *  the destination address must not be a multicast address
	 *  [RFC 2461, sec 8.2]
	 */
	if (in6ifa_ifplocaladdr(ifp, &saddr6) == NULL)
		return;

	if (IN6_IS_ADDR_MULTICAST(&sip6->ip6_dst))
		return;

	/* get ip6 linklocal address for ifp(my outgoing interface). */
	struct if_addr *ifa = in6ifa_ifpforlinklocal(ifp);
	if (ifa == NULL)
		return;

	saddr6 = satosin6((struct sockaddr *)&ifa->ifa_addr)->sin6_addr;

	/* get ip6 linklocal address for the router. */
	struct in6_addr taddr;
	if (nxt->flags & RTF_GATEWAY) {
		taddr = nxt->gateway.address.ip_v6;
		if (!IN6_IS_ADDR_LINKLOCAL(&taddr))
			return;
	} else
		taddr = sip6->ip6_dst;

	/* add a Target Link address option if next hop is resolved */
	struct llentry *ln = nd6_lookup(&taddr, ifp);
	bool add_target_ll = ln && (ln->la_flags & LLE_VALID);

	/* offset for the Redirected Header option */
	uint16_t rd_hdr_off = sizeof(struct nd_redirect);
	if (add_target_ll)
		rd_hdr_off += ICMP6_OPT_LEN(nd_opt_hdr,
					    RTE_ETHER_ADDR_LEN) << 3;

	/* how much of the original packet can we fit? */
	uint16_t origoff = rd_hdr_off + sizeof(struct nd_opt_rd_hdr);
	uint16_t origlen = rte_pktmbuf_data_len(n) - RTE_ETHER_HDR_LEN;
	origlen = RTE_MIN(origlen, ICMP6_PLD_MAXLEN - origoff);

	/* RFC4861 and comments in KAME say the original packet should be
	 * padded to have a size % 8, as in: */
	/* uint16_t origpad = (8 - (origlen % 8)) % 8; */
	/* Actual code in KAME and the wireshark dissector say the original
	 * packet shoud be truncated % 8, as in: */
	uint16_t origpad = 0;
	origlen -= origlen % 8;

	uint16_t plen = origoff + origlen + origpad;
	uint16_t totallen = RTE_ETHER_HDR_LEN + sizeof(struct ip6_hdr) + plen;

	struct rte_mbuf *m = pktmbuf_alloc(n->pool, pktmbuf_get_vrf(n));

	if (m == NULL)
		return;
	if (!rte_pktmbuf_append(m, totallen))
		rte_panic("out of space to append icmp\n");

	dp_pktmbuf_l2_len(m) = dp_pktmbuf_l2_len(n);

	/* preserve the input port number for use by shadow interface */
	m->port = n->port;

	/* ip6 */
	struct ip6_hdr *ip6 = ip6hdr(m);
	ip6->ip6_src = saddr6;
	ip6->ip6_dst = sip6->ip6_src;
	ip6->ip6_flow = sip6->ip6_flow & IPV6_FLOWLABEL_MASK;
	ip6->ip6_flow |= htonl(nd6_tclass_get() << 20);
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = IPV6_ONLINK_HOPLIMIT;
	ip6->ip6_plen = htons(plen);

	/* ND Redirect */
	struct nd_redirect *nd_rd = (struct nd_redirect *)(ip6 + 1);
	nd_rd->nd_rd_type = ND_REDIRECT;
	nd_rd->nd_rd_code = 0;
	nd_rd->nd_rd_reserved = 0;
	nd_rd->nd_rd_target = taddr;
	nd_rd->nd_rd_dst = sip6->ip6_dst;

	/* Maybe add target link address option */
	if (add_target_ll) {
		struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(nd_rd + 1);
		nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		nd_opt->nd_opt_len = ICMP6_OPT_LEN(nd_opt_hdr,
						   RTE_ETHER_ADDR_LEN);
		rte_ether_addr_copy(&ln->ll_addr, (void *)(nd_opt + 1));
	}

	/* Add Redirected Header option */
	struct nd_opt_rd_hdr *rd_hdr = (struct nd_opt_rd_hdr *)
		((char *) nd_rd + rd_hdr_off);
	rd_hdr->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
	rd_hdr->nd_opt_rh_reserved1 = 0;
	rd_hdr->nd_opt_rh_reserved2 = 0;
	rd_hdr->nd_opt_rh_len = ICMP6_OPT_LEN(nd_opt_rd_hdr, origlen);
	char *datastart = (char *) (rd_hdr + 1);
	memcpy(datastart, sip6, origlen);
	memset(datastart + origlen, '\0', origpad);

	nd_rd->nd_rd_cksum = 0;
	nd_rd->nd_rd_cksum = in6_cksum(ip6, IPPROTO_ICMPV6, sizeof(*ip6), plen);

	pktmbuf_mdata_set(m, PKT_MDATA_FROM_US);
	icmp6_reflect(ifp, m);
}

bool icmp6_msg_type_to_icmp_type(uint8_t msgtype, uint8_t *icmptype)
{
	switch (msgtype) {
	case ICMPRATE_LIM_CONFIG__TYPE__DEFAULT:
		*icmptype = 0;
		return true;

	case ICMPRATE_LIM_CONFIG__TYPE__TOOBIG:
		*icmptype = ICMP6_PACKET_TOO_BIG;
		return true;

	case ICMPRATE_LIM_CONFIG__TYPE__TIMEEXCEEDED:
		*icmptype = ICMP6_TIME_EXCEEDED;
		return true;

	case ICMPRATE_LIM_CONFIG__TYPE__DESTUNREACH:
		*icmptype = ICMP6_DST_UNREACH;
		return true;

	case ICMPRATE_LIM_CONFIG__TYPE__PARAMPROB:
		*icmptype = ICMP6_PARAM_PROB;
		return true;

	default:
		return false;
	}
}

void icmp6_error_tclass_set(uint8_t tclass)
{
	icmp6_error_tclass = tclass;
}

uint8_t icmp6_error_tclass_get(void)
{
	return icmp6_error_tclass;
}
