/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef IP_FUNCS_H
#define IP_FUNCS_H
/*
 * IP utilities
 */
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_ether.h>

#include "compiler.h"
#include "ip.h"
#include "iptun_common.h"
#include "pktmbuf_internal.h"
#include "util.h"

/* Is this address limited broadcast */
#define IN_LBCAST(a)     ((((in_addr_t) (a)) & 0xffffffff) == 0xffffffff)

/* Defined in BSD version of in.h */
#define IN_LINKLOCAL(i)	(((in_addr_t)(i) & 0xffff0000) == 0xa9fe0000)
#define IN_LOOPBACK(i)	(((in_addr_t)(i) & 0xff000000) == 0x7f000000)
#define IN_ZERONET(i)	(((in_addr_t)(i) & 0xff000000) == 0)

#define IN_LOCAL_GROUP(i) (((in_addr_t)(i) & 0xffffff00) == 0xe0000000)

#define IN_HOSTEQ(s, t)	((s).s_addr == (t).s_addr)

enum ip4_features {
	IP4_FEA_REASSEMBLE	= (1u << 0),
	IP4_FEA_ORIGINATE	= (1u << 1),
	IP4_FEA_DECAPPED	= (1u << 2),
};

enum ip_packet_validity {
	IP_PKT_VALID,
	IP_PKT_BAD_HDR,
	IP_PKT_TRUNCATED,
	IP_PKT_BAD_ADDR,
};

struct ifnet;
struct next_hop;

static inline struct iphdr *iphdr(const struct rte_mbuf *m)
{
	return dp_pktmbuf_mtol3(m, struct iphdr *);
}

static inline bool ip_is_fragment(const struct iphdr *ip)
{
	return (ip->frag_off & htons(IP_MF | IP_OFFMASK)) != 0;
}

bool ip_valid_packet(struct rte_mbuf *m, const struct iphdr *ip);

enum l2_packet_type;

void ip_input_from_ipsec(struct ifnet *, struct rte_mbuf *);
void ip_input_decap(struct ifnet *in_ifp, struct rte_mbuf *m,
		    enum l2_packet_type l2_pkt_type)
	__hot_func;
void ip_output(struct rte_mbuf *, bool);
void ip_lookup_and_originate(struct rte_mbuf *m, struct ifnet *ifp)
	__hot_func;
void ip_lookup_and_forward(struct rte_mbuf *m, struct ifnet *ifp,
			   bool ttl_decremented, uint16_t npf_flags)
	__hot_func;
void ip_out_features(struct rte_mbuf *m, struct ifnet *ifp,
		     struct iphdr *ip, struct next_hop *nxt,
		     in_addr_t addr, enum ip4_features ip4_feat,
		     uint16_t npf_flags)
	__hot_func;

typedef void (output_t)(struct ifnet *, struct rte_mbuf *, void *);

void ip_fragment(struct ifnet *, struct rte_mbuf *, void *ctx, output_t)
	__hot_func;
void ip_fragment_mtu(struct ifnet *, unsigned int mtu,
		 struct rte_mbuf *, void *ctx, output_t)
	__hot_func;
int ip_mbuf_copy(struct rte_mbuf *m, const struct rte_mbuf *n,
		 unsigned int off, unsigned int len);

struct rte_mbuf *ipv4_handle_fragment(struct rte_mbuf *m);

int ip_spath_filter(struct ifnet *, struct rte_mbuf **);
int ip_spath_output(struct ifnet *l2_ifp, struct ifnet *in_ifp,
		    struct rte_mbuf *m);
int ip6_spath_filter(struct ifnet *, struct rte_mbuf **);
int ip6_spath_output(struct ifnet *l2_ifp, struct ifnet *in_ifp,
		    struct rte_mbuf *m);

int ipv4_originate_filter(struct ifnet *ifp, struct rte_mbuf *m);
int ipv4_originate_filter_flags(struct ifnet *out_ifp, struct rte_mbuf *m,
		uint16_t npf_flags);

void ip_local_deliver(struct ifnet *ifp, struct rte_mbuf *m)
	__cold_func;

int l4_input(struct rte_mbuf **m, struct ifnet *ifp);

int ip_udp_tunnel_in(struct rte_mbuf **m, struct iphdr *ip,
		     struct ifnet *ifp);

void ip_forward_egress(struct ifnet *out_ifp, struct rte_mbuf *,
		       in_addr_t nh_addr, struct ifnet *in_ifp)
	__hot_func;
int
ip_spath_output_with_eth_encap(struct ifnet *out_ifp, struct rte_mbuf *m,
			       in_addr_t nh_addr);

struct nlattr;

static inline void ip_tos_ecn_clear(uint8_t *tos)
{
	*tos = *tos & ~IPTOS_ECN_MASK;
}

static inline void ip_dscp_set(unsigned int dscp, struct iphdr *ip)
{
	dscp &= ~IPTOS_ECN_MASK;
	ip->tos = (ip->tos & IPTOS_ECN_MASK) | dscp;
}

static inline uint8_t ip_dscp_get(const struct iphdr *ip)
{
	return IPTOS_DSCP(ip->tos) >> 2;
}

/* Set new TOS value */
static inline void
ip_tos_ecn_set(struct iphdr *ip4, uint16_t new_tos)
{
	uint8_t old_tos = IPTOS_ECN(ip4->tos);

	if (old_tos == new_tos)
		return;

	ip4->tos &= ~IPTOS_ECN_MASK;
	ip4->tos |= new_tos;
	/*
	 * The 3 possible changes to the ECN are:
	 *
	 * ect0 -> ect1  : 2 -> 1 : += htons(0x0001)
	 *   - total is 1 less - same as a ttl dec
	 *
	 * ect0 -> ce    : 2 -> 3 : += htons(0xFFFE)
	 * ect1 -> ce    : 1 -> 3 : += htons(0xFFFD)
	 *   - total is higher.
	 */
	if (new_tos > old_tos) {
		/* Adding to total. */
		uint32_t check = ip4->check + htons(0xFFFF)
			- htons(new_tos - old_tos);

		ip4->check = check + (check >= 0xFFFF);
	} else {
		/* Similar to ttl decrement. */
		const uint16_t val = ~htons(1);

		if (ip4->check >= val)
			ip4->check -= val;
		else
			ip4->check += ~val;
	}

}

static inline void ip_tos_set_ecn_ce(struct iphdr *ip)
{
	uint8_t old_tos = IPTOS_ECN(ip->tos);

	if (old_tos == IPTOS_ECN_NOT_ECT)
		return; /* not ECN capable */

	ip_tos_ecn_set(ip, IPTOS_ECN_CE);
}

void ip_id_init(void);
u_int16_t icmp_common_exthdr(struct rte_mbuf *m, uint16_t cnum, uint8_t ctype,
			     void *buf, void *ip_hdr, int hlen,
			     u_int16_t ip_total_len, void *dataun,
			     unsigned int len);

bool ip_l2_resolve(struct ifnet *in_ifp, struct rte_mbuf *m,
		   struct next_hop *nh, uint16_t proto);

bool ip_validate_packet_and_count(struct rte_mbuf *m, const struct iphdr *ip,
				  struct ifnet *ifp, bool *needs_slow_path);

#endif /* IP_FUNCS_H */
