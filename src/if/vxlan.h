/*-
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VXLAN_H
#define VXLAN_H
/*
 * Vxlan encapsulation
 */

#include <linux/if_link.h>
#include <netinet/in.h>
#include <rte_atomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <rte_ether.h>
#include <rte_timer.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

#include "control.h"
#include "ip_addr.h"
#include "ip_funcs.h"
#include "json_writer.h"
#include "urcu.h"
#include "util.h"

struct ifinfomsg;
struct ifnet;
struct ip_addr;
struct ndmsg;
struct rte_mbuf;

enum vxlan_type {
	VXLAN_L2,
	VXLAN_GPE
};

/*
 * Next protocol field in VXLAN-GPE header
 */
enum vgpe_nxt_proto {
	VGPE_NXT_NONE = 0,
	VGPE_NXT_IPV4 = 1,
	VGPE_NXT_IPV6 = 2,
	VGPE_NXT_ETHER = 3,
	VGPE_NXT_NSH = 4,
	VGPE_NXT_MPLS = 5,
	VGPE_NXT_MAX
};

#define VXLAN_VALIDFLAG	        0x08000000
#define VXLAN_NXTPROTO_FLAG     0x04000000
#define VXLAN_OAM_FLAG          0x01000000

#define VXLAN_NXTPROTO_MASK     0x000000ff

#define VXLAN_PORT 4789		/* IANA assigned value (not Linux default) */
#define VXLAN_GPE_PORT 4790     /* IANA assigned value as per NVO3 GPE draft */
#define VXLAN_PORT_LOW 10000
#define VXLAN_PORT_HIGH 10500

/*
 * VXLAN route node.
 */
struct vxlan_rtnode {
	struct cds_lfht_node	vxlrt_node;	/* hash table node  */
	struct in_addr		vxlrt_dst;	/* destination endpoint */
	struct in6_addr         vxlrt_dst_v6;   /* destination endpoint - v6 */
	rte_atomic32_t		vxlrt_unused;	/* 0 = used */
	uint8_t			vxlrt_flags;	/* address flags */
	uint16_t		vxlrt_expire;
	struct rte_ether_addr	vxlrt_addr;
	struct rcu_head		vxlrt_rcu;	/* for deletion via rcu */
	uint32_t                vni;            /* destination vni */
};

/* VXLAN FLAGS */
#define VXLAN_FLAG_GPE        0x00000001
/*
 * Store vni to ifp relationship
 */
struct vxlan_vninode {
	struct cds_lfht_node	vni_node;
	struct rcu_head		vni_rcu;	/* for deletion via rcu */
	struct ifnet		*ifp;
	uint32_t		vni;
	in_addr_t		g_addr;
	in_addr_t		s_addr;
	struct in6_addr         s_addr_v6;
	uint16_t		port_low;
	uint16_t		port_high;
	uint8_t			tos;
	uint8_t			learning;
	uint8_t			ttl;
	uint32_t                flags;
	vrfid_t                 t_vrfid; /* Transport VRF ID */
};

struct vxlan_vnitbl {
	struct cds_lfht		*vtbl_vnihash;	/* vni hash table linkage */
	unsigned long		vtbl_vniseed;
};

struct vxlan_ipv4_encap {
	struct rte_ether_hdr	ether_header;
	struct iphdr		ip_header __attribute__ ((__packed__));
	struct rte_udp_hdr		udp_header;
	struct rte_vxlan_hdr	vxlan_header;
} __attribute__ ((__packed__)) __attribute__((aligned(2)));

struct vxlan_ipv6_encap {
	struct rte_ether_hdr	ether_header;
	struct ip6_hdr		ip6_header __attribute__ ((__packed__));
	struct rte_udp_hdr		udp_header;
	struct rte_vxlan_hdr	vxlan_header;
} __attribute__ ((__packed__)) __attribute__((aligned(2)));

#define VXLAN_OVERHEAD (sizeof(struct vxlan_ipv6_encap))
#define VXLAN_MTU (1500 - VXLAN_OVERHEAD)

/* VXLAN Functions */
void vxlan_output(struct ifnet *ifp, struct rte_mbuf *m, uint16_t proto);
struct ifnet *vxlan_create(const struct ifinfomsg *ifi, const char *ifname,
			   const struct rte_ether_addr *eth_addr,
			   struct nlattr *tb[], struct nlattr *data,
			   enum cont_src_en cont_src);
void vxlan_modify(struct ifnet *ifp, uint flags, struct nlattr *tb[],
		  struct nlattr *data);
struct ifnet *vxlan_find_if(uint32_t vni);
int vxlan_neigh_change(const struct nlmsghdr *nlh,
			      const struct ndmsg *ndm,
			      struct nlattr *tb[]);

typedef void (*vxlan_walker_t)(struct vxlan_vninode *node, void *ctx);
void vxlan_tbl_walk(vxlan_walker_t walk_func, void *ctx);

/* update MTU of all VXLANs bound to specified device */
void vxlan_mtu_update(struct ifnet *ifp);

/*
 * vxlan flags
 */
void vxlan_set_flags(struct ifnet *ifp, uint32_t flags, bool set);
uint32_t vxlan_get_flags(struct ifnet *ifp);

/* associate ethernet device with vxlan */
void vxlan_set_device(struct ifnet *vxl_ifp, struct ifnet *ifp);
/* set vxlan transport vrf */
void vxlan_set_t_vrfid(struct ifnet *ifp, vrfid_t t_vrfid);
/* Send already l3 encapped packet for vxlan */
void vxlan_send_encapped(struct rte_mbuf *m, struct ifnet *ifp, uint8_t af);

uint32_t vxlan_get_vni(struct ifnet *ifp);

int cmd_vxlan(FILE *f, int argc, char **argv);

#endif /* VXLAN_H */
