/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef IP6_FUNCS_H
#define IP6_FUNCS_H

/*
 * ip6 fast forward header
 */

#include <libmnl/libmnl.h>
#include <netinet/ip6.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "ip_funcs.h"
#include "ip_forward.h"

#define IPV6_HLIMDEC 1

/*
 * How much of the original packet are we going to include in any
 * generated ICMP6 frame. Note that this plus the headers (IP6, ICMP6
 * and any MPLS label stack) must be less than the IPv6 minimum MTU
 * (1280).
 */
#define ICMP6_PAYLOAD_SIZE (1024)

#define V4MAPPED_IPV6_TO_IPV4(A)	((A).s6_addr32[3])

enum ip6_features {
	IP6_FEA_REASSEMBLE	= (1u << 0),
	IP6_FEA_ORIGINATE	= (1u << 1),
	/*
	 * Packet originally came in encapsulated, i.e. don't perform
	 * same interface.
	 */
	IP6_FEA_DECAPPED	= (1u << 2),
};

struct ifnet;

static inline struct ip6_hdr *ip6hdr(const struct rte_mbuf *m)
{
	return dp_pktmbuf_mtol3(m, struct ip6_hdr *);
}

static inline void ip6_ver_tc_flow_hdr(struct ip6_hdr *hdr, uint32_t tc,
				       uint32_t fl)
{
	*(uint32_t *)hdr = htonl(0x60000000 | (tc << 20) | fl);
}

static inline uint8_t ip6_tclass(uint32_t flowinfo)
{
	return ntohl(flowinfo & 0xFFF) >> 20;
}

static inline uint8_t ipv6_hdr_get_tos(const struct ip6_hdr *ip6)
{
	return ntohs(*(const uint16_t *)ip6) >> 4;
}

static inline void ip6_tos_ecn_set(struct ip6_hdr *ip6, uint16_t new_tos)
{
	*(uint32_t *)ip6 |= htonl(new_tos << 20);
}

static inline void ip6_tos_set_ecn_ce(struct ip6_hdr *ip6)
{
	uint16_t old_tos = ipv6_hdr_get_tos(ip6);

	if (old_tos == IPTOS_ECN_NOT_ECT)
		return; /* not-ECT */

	ip6_tos_ecn_set(ip6, IPTOS_ECN_CE);
}

static inline uint8_t ip6_dscp_get(const struct ip6_hdr *ip6)
{
	return ipv6_hdr_get_tos(ip6) >> 2;
}

void ip6_init(void);

uint32_t ip6time(void);

int ip6_same_network(struct ifnet *, struct in6_addr);

/* Param is in network order */
void icmp6_error(struct ifnet *, struct rte_mbuf *, int, int, uint32_t param)
	__cold_func;
struct rte_mbuf *icmp6_do_error(struct ifnet *, struct rte_mbuf *, int,
				int, uint32_t, int)
	__cold_func;
void icmp6_reflect(struct ifnet *, struct rte_mbuf *)
	__cold_func;

int
icmp6_do_exthdr(struct rte_mbuf *m, uint16_t class, uint8_t ctype, void *buf,
		unsigned int len);
void icmp6_prepare_send(struct rte_mbuf *m);

struct next_hop;
/* Send icmp6 redirect without modifying original packet */
void icmp6_redirect(struct ifnet *ifp, struct rte_mbuf *n,
		    const struct next_hop *nxt);
void ip6_redirects_set(bool enable);
bool ip6_redirects_get(void);
typedef void (*ip6_output_fn_t)(struct ifnet *, struct rte_mbuf *, void *);
int ip6_fragment_mtu(struct ifnet *ifp, unsigned int mtu_size,
		     struct rte_mbuf *m_in, void *ctx,
		     ip6_output_fn_t frag_out);
bool ip6_valid_packet(struct rte_mbuf *m, const struct ip6_hdr *ip6);
bool ip6_validate_packet_and_count(struct rte_mbuf *m,
				   const struct ip6_hdr *ip6,
				   struct ifnet *ifp);
void ip6_output(struct rte_mbuf *, bool srced_forus)
	__hot_func;
void ip6_input_from_ipsec(struct ifnet *, struct rte_mbuf *);
void ip6_lookup_and_originate(struct rte_mbuf *m, struct ifnet *ifp)
	__hot_func;
void ip6_lookup_and_forward(struct rte_mbuf *m, struct ifnet *ifp,
			    bool hlim_decremented, uint16_t npf_flags)
	__hot_func;
void ip6_out_features(struct rte_mbuf *m, struct ifnet *ifp,
		      struct ip6_hdr *ip6, struct next_hop *nxt,
		      enum ip6_features ip6_feat, uint16_t npf_flags);

int ip6_hopopts_input(struct rte_mbuf *m, struct ifnet *iif,
		      uint32_t *rtalertp);

void ipv6_netconf_change(struct ifnet *ifp, struct nlattr *tb[]);

const struct in6_addr *
ip6_select_source(struct ifnet *ifp, const struct in6_addr *addr);

void ip6_unreach(struct ifnet *ifp, struct rte_mbuf *m);

int ipv6_originate_filter_flags(struct ifnet *ifp, struct rte_mbuf *m,
		uint16_t npf_flags);

void
ip6_local_deliver(struct ifnet *ifp, struct rte_mbuf *m)
	__cold_func;

bool
ip6_l2_resolve(struct ifnet *in_ifp, struct rte_mbuf *m,
	       const struct next_hop *nh, uint16_t proto);
void
ip6_refragment_packet(struct ifnet *o_ifp, struct rte_mbuf *m,
		      void *ctx, ip6_output_fn_t output_fn);

int ip6_udp_tunnel_in(struct rte_mbuf *m, struct ifnet *ifp);
int ip6_l4_input(struct rte_mbuf *m, struct ifnet *ifp);

struct icmp_ratelimit_state *icmp6_get_rl_state(void);
uint8_t icmp6_get_rl_state_entries(void);
bool icmp6_msg_type_to_icmp_type(uint8_t msgtype, uint8_t *icmptype);

#endif /* IP6_FUNCS_H */
