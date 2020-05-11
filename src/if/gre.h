/*-
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GRE_H
#define GRE_H
/*
 * GRE tunnel local termination
 */

#include <linux/if_link.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <rte_timer.h>

#include "json_writer.h"
#include "fal_plugin.h"
#include "shadow.h"
#include "urcu.h"
#include "util.h"

struct rte_ether_addr;
struct ifnet;
struct ndmsg;
struct rte_mbuf;

#define ETH_P_NHRP           0x2001
#define ETH_P_ERSPAN_TYPEII  0x88BE
#define ETH_P_ERSPAN_TYPEIII 0x22EB

struct vrf;

/* GRE header used for encapsulation */
struct gre_hdr {
	__be16 flags;
	__be16 ptype;
};

/*
 * Store GRE information
 */
struct gre_info_st {
	struct cds_lfht_node gre_node;
	uint32_t               key;
	__be16                 flags;
	uint16_t               ptype;
	union {
		struct iphdr   iph;
		struct ip6_hdr iph6;
	};
	struct ifnet           *ifp;
	vrfid_t                t_vrfid; /* Transport VRF ID */
	uint16_t               gre_size;
	bool                   ignore_df;
	uint8_t                family;
	uint32_t               i_seqno;
	uint32_t               o_seqno;
	struct mgre_rt_info    *rtinfo;
	struct rcu_head        gre_rcu;
	fal_object_t           fal_tun;
	struct rt_tracker_info *ti_info;
};

struct mgre_rt_info {
	struct cds_lfht_node rtinfo_node_tun;
	struct cds_lfht_node rtinfo_node_nbma;
	struct in_addr       tun_addr;
	vrfid_t              nbma_vrfid;
	struct iphdr         iph;
	uint32_t             rt_info_bits;
	struct rcu_head      rtinfo_rcu;
	struct gre_info_st   *greinfo;
};

/*
 * mgre_timer period is half the default base_reachable_time kernel parameter.
 */
#define RT_INFO_USED_TIMER   15

/* Masks for rt_info_bits */
#define RT_INFO_BIT_IS_USED  0x1 /* rt_info is used since timer reset */
#define RT_INFO_BIT_WAS_USED 0x2 /* rt_info was used when timer reset it. */

struct gre_infotbl_st {
	struct cds_lfht *gi_grehash;
	unsigned long   gi_greseed;
};

struct mgre_rt_info;

typedef void gre_tunnel_peer_iter_func_t(struct ifnet *ifp,
					 struct mgre_rt_info *peer, void *arg);

int gre_table_init(struct vrf *vrf);
void gre_table_uninit(struct vrf *vrf);

/* GRE Tunnel Intf Functions */
struct ifnet *gre_tunnel_create(int ifindex, const char *ifname,
				const struct rte_ether_addr *eth_addr,
				const unsigned int mtu, struct nlattr *data);
void gre_tunnel_modify(struct ifnet *ifp, struct nlattr *data);

void gre_tunnel_peer_walk(struct ifnet *ifp,
			  gre_tunnel_peer_iter_func_t func, void *arg);

/* GRE packet handler functions */
int ip_gre_tunnel_in(struct rte_mbuf **m, struct iphdr *ip);
void
gre_tunnel_send(struct ifnet *input_ifp, struct ifnet *tunnel_ifp,
		struct rte_mbuf *m, const uint16_t proto);
void
gre_tunnel_fragment_and_send(struct ifnet *input_ifp, struct ifnet *tunnel_ifp,
			     const in_addr_t *nxt_ip,
			     struct rte_mbuf *m, const uint16_t proto);
bool
gre_tunnel_encap(struct ifnet *input_ifp, struct ifnet *tunnel_ifp,
		 const in_addr_t *nxt_ip, struct rte_mbuf *m,
		 uint16_t proto);


/* mGRE neig notifications */
int mgre_ipv4_neigh_change(struct ifnet *ifp, const struct nlmsghdr *nlh,
			   const struct ndmsg *ndm, struct nlattr *tb[]);
const in_addr_t *
mgre_nbma_to_tun_addr(struct ifnet *ifp, const in_addr_t *addr);

static inline bool gre_encap_l2_frame(uint16_t proto)
{
	return proto == ETH_P_TEB ||
	       proto == ETH_P_ERSPAN_TYPEII ||
	       proto == ETH_P_ERSPAN_TYPEIII;
}

bool gre_tunnel_ignore_df(const struct ifnet *ifp);

int ip6_gre_tunnel_in(struct rte_mbuf **m, struct ip6_hdr *ip6);

#endif /* GRE_H */
