/*
 * IPv4 multicast routing
 *
 * Implements Vyatta multicast forwarding and routing capabilities
 *
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef IP_MCAST_H
#define IP_MCAST_H

#include <linux/mroute.h>
#include <linux/mroute6.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "util.h"

struct ifnet;
struct ip6_hdr;
struct iphdr;
struct rte_mbuf;

#define EXPIRE_TIMEOUT	(rte_get_timer_hz())	/* 1x / second */
#define UPCALL_EXPIRE	30			/* number of timeouts */

#define SG_CNT_INTERVAL (60 * rte_get_timer_hz())

#define MAX_UPQ	400			/* max. pkts in upcall queue */
#define MAX_UPQ6	MAX_UPQ

#define MFC_HASHSIZE	4096
#define MFC_MAX_MVIFS   IF_SETSIZE

struct vrf;

/* per urcu cds_lfht_new MFC_HASHSIZE must be 2^N, so use fast mod */
#define MFCHASHMOD(h)  ((h) & (MFC_HASHSIZE - 1))

#define in_hosteq(s, t) IN_HOSTEQ(s, t)
#define in_nullhost(x)	((x).s_addr == INADDR_ANY)
#define in_allhosts(x)	((x).s_addr == htonl(INADDR_ALLHOSTS_GROUP))

struct mcast_mgre_tun_walk_ctx {
	uint16_t proto;
	struct ifnet *in_ifp;
	void *out_vif;
	int hdr_len;
	int pkt_len;
	struct rte_mbuf *mbuf;
};

struct mgre_rt_info;

void
mcast_mgre_tunnel_endpoint_send(struct ifnet *out_ifp,
				struct mgre_rt_info *remote, void *arg);

typedef union {
	uint64_t as_int;
	struct rte_ether_addr as_addr;
} mcast_dst_eth_addr_t;

/*
 * Construct Ethernet multicast address from IPv4 multicast address.
 * Citing RFC 1112, section 6.4:
 * "An IP host group address is mapped to an Ethernet multicast address
 * by placing the low-order 23-bits of the IP address into the low-order
 * 23 bits of the Ethernet multicast address 01-00-5E-00-00-00 (hex)."
 */
#define ETHER_ADDR_FOR_IPV4_MCAST(x)	\
	(rte_cpu_to_be_64(0x01005e000000ULL | ((x) & 0x7fffff)) >> 16)

static inline mcast_dst_eth_addr_t mcast_dst_eth_addr(u_int32_t daddr)
{
	mcast_dst_eth_addr_t dst_eth_addr;

	dst_eth_addr.as_int = ETHER_ADDR_FOR_IPV4_MCAST(ntohl(daddr));
	return dst_eth_addr;
}

/*
 * Construct Ethernet multicast address from IPv6 multicast address.
 * Citing RFC 2464, section 7:
 * "An IPv6 packet with a multicast destination address DST, consisting
 * of the sixteen octets DST[1] through DST[16], is transmitted to the
 * Ethernet multicast address whose first two octets are the value 3333
 * hexadecimal and whose last four octets are the last four octets of DST."
 */
#define ETHER_ADDR_FOR_IPV6_MCAST(x)	\
	(rte_cpu_to_be_64(0x333300000000ULL | ((x) & 0xffffffff)) >> 16)

static inline mcast_dst_eth_addr_t mcast6_dst_eth_addr(struct in6_addr *daddr)
{
	mcast_dst_eth_addr_t dst_eth_addr;
	uint32_t addr = (daddr->s6_addr[12] << 24) |
		(daddr->s6_addr[13] << 16) |
		(daddr->s6_addr[14] << 8) |
		(daddr->s6_addr[15]);

	dst_eth_addr.as_int = ETHER_ADDR_FOR_IPV6_MCAST(addr);
	return dst_eth_addr;
}

struct rte_mbuf *mcast_create_l2l3_header(struct rte_mbuf *m_header,
					  struct rte_mbuf *m_data,
					  int iphdrlen);

struct vif *get_vif_by_ifindex(unsigned int ifindex);
struct mif6 *get_mif_by_ifindex(unsigned int ifindex);

struct vmfcctl;
struct vmf6cctl;

int add_mfc(vrfid_t, struct vmfcctl *);
int add_vif(int);
int del_mfc(vrfid_t, struct vmfcctl *);
int del_vif(vifi_t);

int add_m6fc(vrfid_t vrf_id, struct vmf6cctl *mfccp);
int add_m6if(mifi_t);
int del_m6fc(vrfid_t vrf_id, struct vmf6cctl *mfccp);
int del_m6if(mifi_t);

void mc_debug_if_flags(struct ifnet *ifp, unsigned int new_flags,
		       unsigned int msg_type);

/* Multicast Fastpath Route Lookup */
int mcast_ip(struct iphdr *, struct ifnet *, struct rte_mbuf *);
int mcast_ip6(struct ip6_hdr *, struct ifnet *, struct rte_mbuf *);

/* Local deliver */
void mcast_ip_deliver(struct ifnet *ifp, struct rte_mbuf *m);
void mcast_ip6_deliver(struct ifnet *ifp, struct rte_mbuf *m);

int mcast_vrf_init(struct vrf *vrf);
void mcast_vrf_uninit(struct vrf *vrf);

int mcast6_vrf_init(struct vrf *vrf);
void mcast6_vrf_uninit(struct vrf *vrf);

struct mcast_vrf;

/* Dump all */
void mc_dumpall(FILE *f, struct vrf *vrf);

/* Dump mroute/vif info to a file. */
void mrt_dump(FILE *f, struct vrf *vrf);
void mfc_stat(FILE *f, struct vrf *vrf);
void mrt_stat(FILE *f, struct vrf *vrf);
void mvif_dump(FILE *f, struct vrf *vrf);

/* Dump mroute/vif info to a file. */
void mrt6_dump(FILE *f, struct vrf *vrf);
void mfc6_stat(FILE *f, struct vrf *vrf);
void mrt6_stat(FILE *f, struct vrf *vrf);
void mvif6_dump(FILE *f, struct vrf *vrf);

void send_sg_cnt(struct sioc_sg_req *rq, vrfid_t vrf_id, uint32_t flags);
void send_sg6_cnt(struct sioc_sg_req6 *rq, vrfid_t vrf_id, uint32_t flags);

int mcast_iftable_get_free_slot(struct if_set *mfc_ifset, int ifindex,
				unsigned char *vif_index);

#endif /* IP_MCAST_H */
