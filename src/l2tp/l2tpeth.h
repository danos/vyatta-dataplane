/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef L2TPETH_H
#define L2TPETH_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <linux/l2tp.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <urcu/list.h>

#include "urcu.h"

struct rte_mbuf;
struct ifnet;

#define IPPROTO_L2TPV3	0x73
#define L2TP_UDP_SESSION_HEADER_SIZE	8
#define L2TP_IP_SESSION_HEADER_SIZE	4


struct l2tp_softc {
	struct l2tp_session *sclp_session;
	struct rcu_head	sclp_rcu;
};

struct l2tp_stats {
	uint64_t rx_oos_discards;
	uint64_t rx_cookie_discards;
} __rte_cache_aligned;

struct l2tp_tunnel_cfg {
	struct rcu_head tunnel_rcu;
	uint8_t  flags;
#define L2TP_TUNNEL_ENCAP_IPV4    0x1
#define L2TP_TUNNEL_ENCAP_UDP     0x2
	enum l2tp_encap_type encap;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} s_addr;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} d_addr;
	uint32_t tunnel_id;
	uint32_t peer_tunnel_id;
	uint16_t local_udp_port;
	uint16_t peer_udp_port;
	struct cds_list_head tunnel_list; /* list of tunnels */
	rte_atomic16_t refcnt;
};

struct l2tp_session {
	uint8_t  hdr_len;
	uint8_t  flags;
	uint16_t mtu;
#define L2TP_ENCAP_IPV4    0x1
#define L2TP_ENCAP_UDP     0x2
#define L2TP_ENCAP_SEQ     0x4
#define L2TP_LNS_MODE      0x8
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} s_addr;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} d_addr;
	uint8_t  cookie_len;
	uint8_t  peer_cookie_len;
	rte_atomic16_t refcnt;
	uint32_t session_id;
	uint32_t peer_session_id;
	uint32_t xconnect_ifidx;
	uint16_t sport;
	uint16_t dport;
	struct ifnet *ifp;
	uint8_t  cookie[8];
	uint8_t  peer_cookie[8];
	struct cds_lfht_node session_node;
	struct rcu_head session_rcu;
	struct l2tp_tunnel_cfg *tunnel; /* pointer to tunnel */
	uint32_t local_seq;
	uint32_t peer_seq;
	uint8_t  ttl;

	/* stats must be last */
	struct l2tp_stats stats[1] __rte_cache_aligned;
};

/* L2TPv3 headers */
struct l2tpv3_ip_hdr {
	uint32_t session_id;
	uint32_t cookie[2];
	uint32_t x1:1,
		s:1,
		x3:1,
		x4:1,
		x5:1,
		x6:1,
		x7:1,
		x8:1,
		seq_num:24;
} __attribute__((packed));

struct l2tpv3_udp_hdr {
	uint16_t ver;
	uint16_t zero;
	uint32_t session_id;
	uint32_t cookie[2];
	uint32_t x1:1,
		s:1,
		x3:1,
		x4:1,
		x5:1,
		x6:1,
		x7:1,
		x8:1,
		seq_num:1;
} __attribute__((packed));

struct l2tpv3_hdr {
	union {
		struct l2tpv3_ip_hdr ip_encap;
		struct l2tpv3_udp_hdr udp_encap;
	} hdr;
};

struct l2tpv3_udp_encap {
	struct iphdr ip_header __attribute__((packed));
	struct udphdr udp_header;
	struct l2tpv3_hdr l2tp_header;
} __attribute__((packed));

struct l2tpv3_ip_encap {
	struct iphdr ip_header __attribute__((packed));
	struct l2tpv3_hdr l2tp_header;
} __attribute__((packed));

struct l2tpv3_encap {
	struct rte_ether_hdr ether_header;
	char iphdr[0];
} __attribute__((packed)) __attribute__((aligned(2)));


typedef void l2tp_iter_func_t(void *, void *arg);
struct ifnet *l2tpeth_create(int ifindex, const char *ifname,
				   unsigned int mtu,
			     const struct rte_ether_addr *addr);
struct l2tp_session *l2tp_session_byid(uint32_t session_id);
void l2tp_init_stats(struct l2tp_session *sess);
void l2tp_session_walk(l2tp_iter_func_t func, void *arg);
void l2tp_tunnel_walk(l2tp_iter_func_t func, void *arg);
void l2tp_output(struct ifnet *ifp, struct rte_mbuf *m, uint16_t rx_vlan);
void l2tp_stats(const struct l2tp_session *session,
		       struct l2tp_stats *stats);
int l2tp_set_xconnect(char *cmd, char *, char*, char *);

int l2tp_udpv4_recv_encap(struct rte_mbuf *m, const struct iphdr *ip,
			  const struct udphdr *udp);
int l2tp_ipv4_recv_encap(struct rte_mbuf *m, const struct iphdr *ip);
int l2tp_udpv6_recv_encap(struct rte_mbuf *m, const struct ip6_hdr *ip6,
			  const struct udphdr *udp);

int l2tp_ipv6_recv_encap(struct rte_mbuf *m, const struct ip6_hdr *ip6,
			const unsigned char *l2tp);
int l2tp_undo_decap(const struct ifnet *ifp, struct rte_mbuf *m);
int l2tp_undo_decap_br(const struct ifnet *brif, struct rte_mbuf *m);
#endif /* L2TPETH_H */
