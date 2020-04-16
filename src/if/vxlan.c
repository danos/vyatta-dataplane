/*
 * VXLAN forwarding database
 *
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <czmq.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_link.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_timer.h>
#include <rte_udp.h>

#include "capture.h"
#include "compat.h"
#include "compiler.h"
#include "config_internal.h"
#include "crypto/crypto_forward.h"
#include "dp_event.h"
#include "ether.h"
#include "if/bridge/bridge_port.h"
#include "if_var.h"
#include "in6.h"
#include "in_cksum.h"
#include "ip_addr.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "json_writer.h"
#include "main.h"
#include "mpls/mpls.h"
#include "netinet6/ip6_funcs.h"
#include "netinet6/route_v6.h"
#include "nh_common.h"
#include "nsh.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "route.h"
#include "route_flags.h"
#include "shadow.h"
#include "snmp_mib.h"
#include "udp_handler.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "vxlan.h"

#define VXLAN_VNI_SIZE		3

/* Size of the vxlan forwarding table.	Must be a power of two. */
#define VXLAN_RTHASH_MIN	32
#define	VXLAN_RTHASH_MAX	65536
#define	VXLAN_RTHASH_BITS	24

#define VXLAN_RTABLE_PRUNE_HZ	5
#define VXLAN_RTABLE_EXPIRE	((30 * 60) / VXLAN_RTABLE_PRUNE_HZ)

/* Forwarding table */
#define	IFBAF_TYPEMASK	0x03	/* address type mask */
#define	IFBAF_DYNAMIC	0x00	/* dynamically learned address */
#define	IFBAF_STATIC	0x01	/* static address */
#define	IFBAF_LOCAL	0x02	/* address of local interface */
#define IFBAF_ADDR_V4   0x04
#define IFBAF_ADDR_V6   0x08

struct vxlan_softc {
	struct cds_lfht		*scvx_rthash;	/* fdb hash table linkage */
	uint32_t		scvx_vni;

	/* administrative */
	struct rte_timer	scvx_timer;
	struct rcu_head		scvx_rcu;
};

enum VXLAN_STATS {
	VXLAN_STATS_INPKTS,
	VXLAN_STATS_INDISCARDS_OPTIONS,
	VXLAN_STATS_INDISCARDS_BADHEADER,
	VXLAN_STATS_INDISCARDS_BADPAYLOAD,
	VXLAN_STATS_INDISCARDS_VNINOTFOUND,
	VXLAN_STATS_INDISCARDS_PKT_HEADROOM,
	VXLAN_STATS_INDISCARDS_SHORTPAYLOAD,
	VXLAN_STATS_OUTPKTS,
	VXLAN_STATS_OUTDISCARDS,
	VXLAN_STATS_OUTDISCARDS_ARP_FAILED,
	VXLAN_STATS_OUTDISCARDS_NO_VTEP_SRC,
	VXLAN_STATS_OUTDISCARDS_ENCAP_FAILED,
	VXLAN_STATS_OUTDISCARDS_ND_FAILED,
	VXLAN_STATS_OUTDISCARDS_UNKNOWN_PAYLOAD,
	VXLAN_STATS_MAX
};

static const char *vxlan_cntr_names[VXLAN_STATS_MAX] = {
	[VXLAN_STATS_INPKTS] = "InPkts",
	[VXLAN_STATS_INDISCARDS_OPTIONS] = "InDiscardsOptions",
	[VXLAN_STATS_INDISCARDS_BADHEADER] = "InDiscardsBadHeader",
	[VXLAN_STATS_INDISCARDS_BADPAYLOAD] = "InDiscardsBadPayload",
	[VXLAN_STATS_INDISCARDS_VNINOTFOUND] = "InDiscardsVniNotFound",
	[VXLAN_STATS_INDISCARDS_PKT_HEADROOM] = "InDiscardsPktHeadroom",
	[VXLAN_STATS_INDISCARDS_SHORTPAYLOAD] = "InDiscardsShortPayload",
	[VXLAN_STATS_OUTPKTS] = "OutPkts",
	[VXLAN_STATS_OUTDISCARDS] = "OutDiscards",
	[VXLAN_STATS_OUTDISCARDS_ARP_FAILED] = "ARPFailed",
	[VXLAN_STATS_OUTDISCARDS_NO_VTEP_SRC] = "OutDiscardsNoVTEPSrc",
	[VXLAN_STATS_OUTDISCARDS_ENCAP_FAILED] = "OutDiscardsEncapFailed",
	[VXLAN_STATS_OUTDISCARDS_ND_FAILED] = "NDFailed",
	[VXLAN_STATS_OUTDISCARDS_UNKNOWN_PAYLOAD] = "OutDiscardsUnknownPayload",
};

unsigned long vxlan_stats[RTE_MAX_LCORE][VXLAN_STATS_MAX] __rte_cache_aligned;

#define VXLAN_STAT_INC(type)	(vxlan_stats[dp_lcore_id()][type]++)

/* Table of active VNIs */
static struct vxlan_vnitbl *vxlans;

/*
 * Forward references
 */
static void vxlan_timer(struct rte_timer *, void *);
static void vxlan_rtupdate(struct ifnet *ifp,
			  struct ip_addr *addr,
			  const struct rte_ether_addr *dst);
static struct vxlan_rtnode *
vxlan_rtnode_lookup(struct vxlan_softc *sc,
		    const struct rte_ether_addr *addr);

/*
 * VNI Table functions
 */
static inline unsigned long
vxlan_vni_hash(const void *key, unsigned long seed)
{
	return rte_jhash_1word(*(const uint32_t *)key, seed);
}

static inline int vxlan_vni_match(struct cds_lfht_node *node, const void *key)
{
	const struct vxlan_vninode *vni
		= caa_container_of(node, const struct vxlan_vninode, vni_node);

	return vni->vni == *(const uint32_t *)key;
}

static struct vxlan_vninode *
vxlan_vni_lookup(uint32_t vni)
{
	struct cds_lfht_iter iter;

	cds_lfht_lookup(vxlans->vtbl_vnihash,
			vxlan_vni_hash(&vni, vxlans->vtbl_vniseed),
			vxlan_vni_match, &vni, &iter);
	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);

	if (node)
		return caa_container_of(node, struct vxlan_vninode, vni_node);
	else
		return NULL;
}

/* Insert the specified vxlan node into the VNI table. */
static int
vxlan_vni_insert(struct vxlan_vninode *vni)
{
	struct cds_lfht_node *ret_node;

	cds_lfht_node_init(&vni->vni_node);
	unsigned long hash = vxlan_vni_hash(&vni->vni, vxlans->vtbl_vniseed);

	ret_node = cds_lfht_add_unique(vxlans->vtbl_vnihash, hash,
				       vxlan_vni_match, &vni->vni,
				       &vni->vni_node);

	return (ret_node != &vni->vni_node) ? EEXIST : 0;
}

static void
vxlan_vni_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct vxlan_vninode, vni_rcu));
}

/* Destroy a vxlan rtnode. */
static void
vxlan_vni_destroy(struct vxlan_vninode *vni)
{
	if (vni)
		call_rcu(&vni->vni_rcu, vxlan_vni_free);
}

struct ifnet *vxlan_find_if(uint32_t vni)
{
	struct vxlan_vninode *vni_node = vxlan_vni_lookup(vni);

	if (vni_node)
		return vni_node->ifp;

	return NULL;
}

ALWAYS_INLINE
uint32_t vxlan_get_vni(struct ifnet *ifp)
{
	struct vxlan_softc *sc = ifp->if_softc;

	return sc->scvx_vni;
}

static void vxlan_walker_update_mtu(struct vxlan_vninode *vni,
				    void *ctx)
{
	struct ifnet *dev = ctx;

	if (vni->ifp->if_parent == dev) {
		vni->ifp->if_mtu = dev->if_mtu - VXLAN_OVERHEAD;
	}
}

void vxlan_tbl_walk(vxlan_walker_t walk_func, void *ctx)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_first(vxlans->vtbl_vnihash, &iter);
	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {
		struct vxlan_vninode *vni
			= caa_container_of(node, struct vxlan_vninode,
					   vni_node);

		walk_func(vni, ctx);
		cds_lfht_next(vxlans->vtbl_vnihash, &iter);
	}
}

/* Display vxlan info in JSON */
static void
vxlan_show_info(json_writer_t *wr, struct ifnet *ifp)
{
	struct vxlan_vninode *vni = vxlan_vni_lookup(vxlan_get_vni(ifp));
	char b[INET_ADDRSTRLEN];

	if (vni == NULL)
		return;

	jsonw_uint_field(wr, "vni", vxlan_get_vni(ifp));

	jsonw_name(wr, "vxlan");
	jsonw_start_object(wr);
	if (ifp->if_parent)
		jsonw_string_field(wr, "parent", ifp->if_parent->if_name);
	jsonw_uint_field(wr, "vni", vxlan_get_vni(ifp));
	if (vni->g_addr != 0)
		jsonw_string_field(wr, "group",
				   inet_ntop(AF_INET, &vni->g_addr,
					     b, sizeof(b)));
	if (vni->s_addr != 0)
		jsonw_string_field(wr, "source",
				   inet_ntop(AF_INET, &vni->s_addr,
					     b, sizeof(b)));
	jsonw_uint_field(wr, "tos", vni->tos);
	jsonw_uint_field(wr, "ttl", vni->ttl);
	jsonw_name(wr, "portrange");
	jsonw_start_array(wr);
	jsonw_uint(wr, vni->port_low);
	jsonw_uint(wr, vni->port_high);
	jsonw_end_array(wr);
	jsonw_uint_field(wr, "learning", vni->learning);
	jsonw_end_object(wr);
}

/*
 * Packet input and output
 */
static ALWAYS_INLINE
uint16_t vxlan_get_src_port(struct vxlan_vninode *vnode, uint8_t *entropy,
			    uint32_t entropy_len, struct rte_mbuf *m)
{
	unsigned int range = (vnode->port_high - vnode->port_low) + 1;
	uint32_t hash = m->hash.rss;

	if (hash == 0)
		hash = rte_jhash(entropy, entropy_len, (uint32_t) IPPROTO_UDP);
	return (((uint64_t) hash * range) >> 32) + vnode->port_low;
}

static ALWAYS_INLINE
int vxlan_ipv4_set_encap(struct vxlan_vninode *vnode, struct rte_mbuf *m,
			 uint8_t tos, struct ip_addr *sip,
			 struct ip_addr *dip, struct udp_hdr **udp,
			 struct vxlan_hdr **vxhdr)
{
	uint16_t orig_pkt_data_len = rte_pktmbuf_pkt_len(m);
	struct iphdr *iph;
	struct vxlan_ipv4_encap *vhdr;

	vhdr = (struct vxlan_ipv4_encap *)
		rte_pktmbuf_prepend(m,
				    (uint16_t)sizeof(struct vxlan_ipv4_encap));
	if (unlikely(vhdr == NULL))
		return -ENOMEM;

	/* Update L2 length in packet as vxlan_ipv4_encap includes ether_hdr */
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	/* ethernet header */
	vhdr->ether_header.ether_type = htons(ETHER_TYPE_IPv4);

	/* IPv4 header construction */
	iph = &vhdr->ip_header;
	iph->ihl = 5;
	iph->version = 4;
	iph->check = 0;
	if (vnode->ttl == 0)
		iph->ttl = IPDEFTTL;
	else
		iph->ttl = vnode->ttl;

	if (vnode->tos != 0)
		iph->tos = vnode->tos;
	else
		iph->tos = tos;
	iph->id = 0;
	iph->frag_off = htons(IP_DF);
	iph->protocol = IPPROTO_UDP;
	iph->tot_len = htons(sizeof(vhdr->ip_header) +
			     sizeof(struct udp_hdr) +
			     sizeof(struct vxlan_hdr) +
			     orig_pkt_data_len);
	iph->saddr = sip->address.ip_v4.s_addr;
	iph->daddr = dip->address.ip_v4.s_addr;
	iph->check = dp_in_cksum_hdr(iph);

	*udp = &vhdr->udp_header;
	*vxhdr = &vhdr->vxlan_header;
	return 0;
}

static ALWAYS_INLINE
int vxlan_ipv6_set_encap(struct vxlan_vninode *vnode, struct rte_mbuf *m,
			 uint8_t tc, struct ip_addr *sip,
			 struct ip_addr *dip, struct udp_hdr **udp,
			 struct vxlan_hdr **vxhdr)
{
	uint16_t orig_pkt_data_len = rte_pktmbuf_pkt_len(m);
	struct ip6_hdr *ip6h;
	struct vxlan_ipv6_encap *vhdr;
	uint8_t tos = 0;

	vhdr = (struct vxlan_ipv6_encap *)
		rte_pktmbuf_prepend(m, (uint16_t)
				    sizeof(struct vxlan_ipv6_encap));
	if (unlikely(vhdr == NULL))
		return -ENOMEM;

	/* Update L2 length in packet as vxlan_ipv6_encap includes ether_hdr */
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	/* ethernet header */
	vhdr->ether_header.ether_type = htons(ETHER_TYPE_IPv6);

	/* IPv6 header construction */
	ip6h = &vhdr->ip6_header;
	if (vnode->tos != 0)
		tos = vnode->tos;
	else
		tos = tc;
	ip6h->ip6_flow = htonl((IPV6_VERSION << 4 | tos) << 20);
	ip6h->ip6_nxt = IPPROTO_UDP;
	ip6h->ip6_hlim = IPV6_DEFAULT_HOPLIMIT;
	ip6h->ip6_src = sip->address.ip_v6;
	ip6h->ip6_dst = dip->address.ip_v6;
	ip6h->ip6_plen = htons(sizeof(struct udp_hdr) +
			       sizeof(struct vxlan_hdr) +
			       orig_pkt_data_len);
	*udp = &vhdr->udp_header;
	*vxhdr = &vhdr->vxlan_header;
	return 0;
}

static ALWAYS_INLINE
void vxlan_udp_encap(struct vxlan_vninode *vnode, uint16_t orig_len,
		     struct rte_mbuf *m, uint8_t *entropy,
		     uint32_t entropy_len,
		     struct udp_hdr *udp, enum vxlan_type vxl_type)
{
	uint16_t pkt_len;

	/* UDP header */
	pkt_len = (uint16_t)
		(sizeof(struct udp_hdr) +
		 sizeof(struct vxlan_hdr) +
		 orig_len);

	/* TBD: With GPE, source port calculation needs to change for other
	 * types of payloads
	 */
	udp->src_port =
		htons(vxlan_get_src_port(vnode, entropy, entropy_len, m));
	udp->dgram_len = htons(pkt_len);
	udp->dgram_cksum = 0; /* No UDP checksum. */
	if (vxl_type == VXLAN_L2)
		udp->dst_port = htons(VXLAN_PORT);
	else if (vxl_type == VXLAN_GPE)
		udp->dst_port = htons(VXLAN_GPE_PORT);
}

static ALWAYS_INLINE
int vxlan_vhdr_encap(struct vxlan_vninode *vnode,
		     struct vxlan_hdr *vhdr,
		     enum vxlan_type vxl_type,
		     enum vgpe_nxt_proto nxt_proto,
		     bool oam)
{
	if (unlikely(vxl_type == VXLAN_L2 && nxt_proto != VGPE_NXT_NONE))
		return -EINVAL;

	/* VXLAN header */
	vhdr->vx_vni = htonl(vnode->vni << 8);

	/*
	 * main differences between VXLAN & GPE headers
	 * - UDP port numbers are different
	 * - Next protocol bit is set in GPE
	 * - Next protocol field is populated in GPE
	 */
	if (vxl_type == VXLAN_L2)
		vhdr->vx_flags = htonl(VXLAN_VALIDFLAG);
	else if (vxl_type == VXLAN_GPE)
		vhdr->vx_flags =
			htonl(VXLAN_VALIDFLAG | VXLAN_NXTPROTO_FLAG |
			      nxt_proto | (oam ? VXLAN_OAM_FLAG : 0));

	return 0;
}

static ALWAYS_INLINE
int vxlan_encap(struct vxlan_vninode *vnode, struct ip_addr *sip,
		struct ip_addr *dip, struct rte_mbuf *m,
		uint8_t *entropy, uint32_t entropy_len, uint8_t tos_tc,
		enum vxlan_type vxl_type, enum vgpe_nxt_proto nxtproto,
		bool oam)
{
	int err = 0;
	uint16_t orig_pkt_data_len = rte_pktmbuf_pkt_len(m);
	struct udp_hdr *udp;
	struct vxlan_hdr *vxh;

	if (dip->type == AF_INET)
		err = vxlan_ipv4_set_encap(vnode, m, tos_tc, sip, dip, &udp,
					   &vxh);
	else if (dip->type == AF_INET6)
		err = vxlan_ipv6_set_encap(vnode, m, tos_tc, sip, dip, &udp,
					   &vxh);
	else
		err = -EINVAL;

	if (err == 0) {
		vxlan_udp_encap(vnode, orig_pkt_data_len, m, entropy,
				entropy_len, udp, vxl_type);
		err = vxlan_vhdr_encap(vnode, vxh, vxl_type, nxtproto, oam);
	}
	return err;
}


static ALWAYS_INLINE
int vxlan_select_ipv4_src(struct vxlan_vninode *vnode, struct ip_addr *dip,
			  struct rte_mbuf *m,
			  struct ifnet **oifp, struct ip_addr *sip,
			  struct ip_addr *nhip)
{
	struct next_hop *nxt;
	struct ifnet *dif;

	/* Lookup destination */
	nxt = dp_rt_lookup(dip->address.ip_v4.s_addr, RT_TABLE_MAIN, m);
	if (unlikely(nxt == NULL))
		return -ENOENT;

	dif = dp_nh_get_ifp(nxt);
	if (unlikely(dif == NULL))
		return -ENOENT;

	if (!(dif->if_flags & IFF_UP))
		return -ENOENT;

	*oifp = dif;

	/* Store next hop address  */
	if (nxt->flags & RTF_GATEWAY)
		nhip->address.ip_v4.s_addr = nxt->gateway4;
	else
		nhip->address.ip_v4.s_addr = dip->address.ip_v4.s_addr;

	if (vnode->s_addr == 0) {
		DP_DEBUG(VXLAN, INFO, VXLAN,
			 "Using IP source address selection.\n");
		sip->address.ip_v4.s_addr =
			ip_select_source(dif,
					 dip->address.ip_v4.s_addr);
	} else {
		sip->address.ip_v4.s_addr = vnode->s_addr;
	}

	return 0;
}

static ALWAYS_INLINE
int vxlan_select_ipv6_src(struct vxlan_vninode *vnode, struct ip_addr *dip,
			  struct rte_mbuf *m,
			  struct ifnet **oifp, struct ip_addr *sip,
			  struct ip_addr *nhip)
{
	struct next_hop *nxt6;
	const struct in6_addr *saddr_v6;
	struct ifnet *dif;

	nxt6 = dp_rt6_lookup(&dip->address.ip_v6, RT_TABLE_MAIN, m);
	if (unlikely(nxt6 == NULL))
		return -ENOENT;

	dif = dp_nh_get_ifp(nxt6);
	if (unlikely(dif == NULL))
		return -ENOENT;

	if (!(dif->if_flags & IFF_UP))
		return -ENOENT;

	*oifp = dif;

	if (nxt6->flags & RTF_GATEWAY)
		nhip->address.ip_v6 = nxt6->gateway6;
	else
		nhip->address.ip_v6 = dip->address.ip_v6;

	if (IN6_IS_ADDR_UNSPECIFIED(&vnode->s_addr_v6)) {
		DP_DEBUG(VXLAN, INFO, VXLAN,
			 "Using IPv6 source address selection.\n");
		saddr_v6 = ip6_select_source(dif, &dip->address.ip_v6);
		if (saddr_v6)
			sip->address.ip_v6 = *saddr_v6;
		else
			return -ENOENT;
	} else {
		sip->address.ip_v6 = vnode->s_addr_v6;
	}
	return 0;
}

/*
 * select source address and interface to use for VXLAN based on specified dst.
 */
static ALWAYS_INLINE
int vxlan_select_src(struct vxlan_vninode *vnode,
		     struct ip_addr *dip, struct rte_mbuf *m,
		     struct ifnet **oifp, struct ip_addr *sip,
		     struct ip_addr *nhip)
{
	int err = 0;

	nhip->type = dip->type;
	sip->type = dip->type;
	switch (dip->type) {
	case AF_INET:
		err = vxlan_select_ipv4_src(vnode, dip, m, oifp, sip,
					    nhip);
		break;
	case AF_INET6:
		err = vxlan_select_ipv6_src(vnode, dip, m, oifp, sip,
					    nhip);
		break;
	default:
		err = EINVAL;
	}

	if (unlikely(err != 0))
		DP_DEBUG(VXLAN, ERR, VXLAN,
			 "No source IP address for VTEP for %s.\n",
			 vnode->ifp->if_name);
	return err;
}

static
void vxlan_query_payload_mpls(uint32_t *hdr, uint8_t *tc,
			      uint8_t **entropy, uint32_t *entropy_len)
{
	*tc = mpls_ls_get_exp(*hdr);
	if (entropy == NULL || entropy_len == NULL)
		return;

	/*
	 * Use the label stack as entropy. Should we be using the whole stack?
	 */
	*entropy = (uint8_t *)hdr;
	*entropy_len = sizeof(*hdr) * 1;
}

static ALWAYS_INLINE
void vxlan_query_payload_ip6(struct ip6_hdr *ip6h, uint8_t *tc,
			uint8_t **entropy, uint32_t *entropy_len)
{
	*tc = ((ntohl(ip6h->ip6_flow) & IPV6_FLOWINFO_MASK) >> 20);
	if (entropy == NULL || entropy_len == NULL)
		return;

	*entropy = (uint8_t *)&ip6h->ip6_src;
	*entropy_len = sizeof(struct in6_addr) * 2;
}

static ALWAYS_INLINE
void vxlan_query_payload_ip4(struct iphdr *iph, uint8_t *tos,
			     uint8_t **entropy, uint32_t *entropy_len)
{
	*tos = iph->tos;
	if (entropy == NULL || entropy_len == NULL)
		return;

	*entropy = (uint8_t *)&iph->saddr;
	*entropy_len = sizeof(struct in_addr) * 2;
}

static ALWAYS_INLINE
void vxlan_query_payload_eth(struct ether_hdr *eh, uint8_t *tos_tc,
			     uint8_t **entropy, uint32_t *entropy_len)
{
	struct ip6_hdr *ip6h;
	struct iphdr *iph;

	if (eh->ether_type == htons(ETHER_TYPE_IPv4)) {
		iph = (struct iphdr *)((uintptr_t)eh + sizeof(*eh));
		vxlan_query_payload_ip4(iph, tos_tc, NULL, NULL);
	} else if (eh->ether_type == htons(ETHER_TYPE_IPv6)) {
		ip6h = (struct ip6_hdr *)((uintptr_t)eh + sizeof(*eh));
		vxlan_query_payload_ip6(ip6h, tos_tc, NULL, NULL);
	}

	*entropy = (uint8_t *)eh;
	*entropy_len = ETHER_ADDR_LEN * 2;
}

/*
 * Find payload details that the vxlan encap requires.
 *
 * Returns:
 * tos_tc: set to the payload IPv4 tos or IPv6 tc
 * entropy: pointer to the start of entropy data
 * entropy_len: length of entropy data
 */
static ALWAYS_INLINE
bool vxlan_query_payload(enum vxlan_type vxl_type, enum vgpe_nxt_proto nxtproto,
			 struct rte_mbuf *m, uint8_t *tos_tc,
			 uint8_t **entropy, uint32_t *entropy_len)
{
	void *nsh_payload;
	enum nsh_np nsh_proto;

	switch (vxl_type) {
	case VXLAN_L2:
		if (nxtproto != VGPE_NXT_NONE)
			return false;
		vxlan_query_payload_eth(ethhdr(m), tos_tc, entropy,
					entropy_len);
		return true;
	case VXLAN_GPE:
		switch (nxtproto) {
		case VGPE_NXT_ETHER:
			vxlan_query_payload_eth(ethhdr(m), tos_tc, entropy,
						entropy_len);
			return true;
		case VGPE_NXT_IPV4:
			vxlan_query_payload_ip4(iphdr(m), tos_tc, entropy,
						entropy_len);
			return true;
		case VGPE_NXT_IPV6:
			vxlan_query_payload_ip6(ip6hdr(m), tos_tc, entropy,
						entropy_len);
			return true;
		case VGPE_NXT_MPLS:
			vxlan_query_payload_mpls(
				rte_pktmbuf_mtod(m, uint32_t *),
				tos_tc, entropy,
				entropy_len);
			return true;
		case VGPE_NXT_NSH:
			if (nsh_get_payload(rte_pktmbuf_mtod(m, struct nsh *),
					    &nsh_proto, &nsh_payload) != 0)
				return false;
			switch (nsh_proto) {
			case NSH_NP_ETHER:
				vxlan_query_payload_eth(nsh_payload,
							tos_tc, entropy,
							entropy_len);
				return true;
			case NSH_NP_IPv4:
				vxlan_query_payload_ip4(nsh_payload,
							tos_tc, entropy,
							entropy_len);
				return true;
			case NSH_NP_IPv6:
				vxlan_query_payload_ip6(nsh_payload,
							tos_tc, entropy,
							entropy_len);
				return true;
			case NSH_NP_MPLS:
				vxlan_query_payload_mpls(nsh_payload,
							 tos_tc, entropy,
							 entropy_len);
			return true;
			default:
				break;
			}
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return false;
}

/* Resolve l2 and send pak*/
static int vxlan_resolve_send_pak(struct rte_mbuf *m, struct ip_addr *nhip,
				  struct ip_addr *dip, struct ifnet *ifp,
				  struct ifnet *dif)
{
	if (likely(dip->type == AF_INET)) {
		struct next_hop nh = {.flags = RTF_GATEWAY,
				      .gateway4 = nhip->address.ip_v4.s_addr,
				      .u.ifp = dif};

		if (!dp_ip_l2_nh_output(ifp, m, &nh, ETH_P_IP)) {
			VXLAN_STAT_INC(VXLAN_STATS_OUTDISCARDS_ARP_FAILED);
			goto err;
		}
		IPSTAT_INC_IFP(dif, IPSTATS_MIB_OUTPKTS);
	} else if (likely(dip->type == AF_INET6)) {
		struct next_hop nh = {.flags = RTF_GATEWAY,
				      .gateway6 = nhip->address.ip_v6,
				      .u.ifp = dif};

		if (!dp_ip6_l2_nh_output(ifp, m, &nh, ETH_P_IPV6)) {
			VXLAN_STAT_INC(VXLAN_STATS_OUTDISCARDS_ND_FAILED);
			goto err;
		}
		IP6STAT_INC_IFP(dif, IPSTATS_MIB_OUTPKTS);
	} else {
		rte_pktmbuf_free(m);
		goto err;
	}

	VXLAN_STAT_INC(VXLAN_STATS_OUTPKTS);
	return 0;
 err:
	return -EFAULT;

}

static int
vxlan_send_packet(struct ifnet *ifp, uint32_t vni, struct ip_addr *dip,
		  struct rte_mbuf *m, enum vxlan_type vxl_type,
		  enum vgpe_nxt_proto nxtproto, bool multicast, bool oam)
{
	struct ifnet *dif = NULL;
	struct vxlan_vninode *vnode;
	struct ip_addr sip, nhip;
	int err;
	uint8_t tos_tc = 0;
	uint8_t *entropy;
	uint32_t entropy_len;

	vnode = vxlan_vni_lookup(vni);
	if (unlikely(vnode == NULL))
		goto drop;

	if (!vxlan_query_payload(vxl_type, nxtproto, m, &tos_tc, &entropy,
				 &entropy_len)) {
		VXLAN_STAT_INC(VXLAN_STATS_OUTDISCARDS_UNKNOWN_PAYLOAD);
		goto drop;
	}

	/* Do multicast */
	/* TBD: support for IPv6 multicast groups */
	if (unlikely(multicast)) {
		if (dip->type == AF_INET) {
			if (vnode->g_addr != 0)
				dip->address.ip_v4.s_addr = vnode->g_addr;
			else
				goto drop;
		}
	}

	/* Outer IP addressing uses the transport VRF */
	pktmbuf_set_vrf(m, vnode->t_vrfid);
	pktmbuf_prepare_encap_out(m);

	err = vxlan_select_src(vnode, dip, m, &dif, &sip, &nhip);
	if (unlikely(err != 0)) {
		VXLAN_STAT_INC(VXLAN_STATS_OUTDISCARDS_NO_VTEP_SRC);
		goto drop;
	}

	/* encapsulate the packet. Add VXLAN + UDP + OUTER IP hdr */
	err = vxlan_encap(vnode, &sip, dip, m, entropy, entropy_len, tos_tc,
			  vxl_type, nxtproto, oam);
	if (unlikely(err != 0)) {
		VXLAN_STAT_INC(VXLAN_STATS_OUTDISCARDS_ENCAP_FAILED);
		goto drop;
	}
	return vxlan_resolve_send_pak(m, &nhip, dip, ifp, dif);

 drop:
	rte_pktmbuf_free(m);
	IPSTAT_INC_IFP(ifp, IPSTATS_MIB_OUTDISCARDS);
	if_incr_dropped(ifp);
	return -EFAULT;
}

/* Use this API for sending already encapped vxlan packet */
void vxlan_send_encapped(struct rte_mbuf *m, struct ifnet *ifp, uint8_t af)
{
	struct ifnet *dif = NULL;
	uint32_t vni;
	struct vxlan_vninode *vnode;
	struct ip_addr sip, dip, nhip;
	int err;

	struct iphdr *ip;
	struct ip6_hdr *ip6;

	if (!ifp)
		return;

	vni = vxlan_get_vni(ifp);

	if (af == AF_INET) {
		ip = iphdr(m);
		dip.type = AF_INET;
		dip.address.ip_v4.s_addr = ip->daddr;

	} else {
		ip6 = ip6hdr(m);
		dip.type = AF_INET6;
		dip.address.ip_v6 = ip6->ip6_dst;
	}
	vnode = vxlan_vni_lookup(vni);
	if (unlikely(vnode == NULL))
		goto drop;

	err = vxlan_select_src(vnode, &dip, m, &dif, &sip, &nhip);
	if (unlikely(err != 0))
		goto drop;

	(void)vxlan_resolve_send_pak(m, &nhip, &dip, ifp, dif);
	return;
 drop:
	rte_pktmbuf_free(m);
	IPSTAT_INC_IFP(ifp, IPSTATS_MIB_OUTDISCARDS);
	if_incr_dropped(ifp);
}

static void
vxlan_snoop(enum vgpe_nxt_proto nxtproto, struct ifnet *ifp,
	    struct rte_mbuf *m __unused,
	    uint16_t ether_type, void *l3hdr, struct vxlan_hdr *vxlan)
{
	void *vxlan_end = vxlan + 1;
	struct ip_addr ipaddr;

	if (ether_type == htons(ETHER_TYPE_IPv4)) {
		const struct iphdr *oip = l3hdr;

		ipaddr.type = AF_INET;
		ipaddr.address.ip_v4.s_addr = oip->saddr;
	} else if (ether_type == htons(ETHER_TYPE_IPv6)) {
		const struct ip6_hdr *oip6 = l3hdr;

		ipaddr.type = AF_INET6;
		ipaddr.address.ip_v6 = oip6->ip6_src;
	} else
		return;

	/* where is the inner ether header? */
	struct ether_hdr *eh;

	if (nxtproto == VGPE_NXT_NONE || nxtproto == VGPE_NXT_ETHER)
		/* trivial for vxlan, or vxlan-gpe followed by ether */
		eh = vxlan_end;
	else if (nxtproto == VGPE_NXT_NSH) {
		/* can also use NSH, if followed by ether */
		void *nsh_payload;
		enum nsh_np nsh_proto;

		if (nsh_get_payload(vxlan_end, &nsh_proto, &nsh_payload) != 0 ||
		    nsh_proto != NSH_NP_ETHER)
			return;

		eh = nsh_payload;
	} else
		return;

	/* Don't learn my own address,
	 *  other side might be setup the same way
	 */
	if (unlikely(rte_ether_addr_equal(&eh->s_addr, &ifp->eth_addr)))
		return;

	struct bridge_port *brport = rcu_dereference(ifp->if_brport);

	if (unlikely(brport &&
		     rte_ether_addr_equal(
			     &eh->s_addr,
			     &bridge_port_get_bridge(brport)->eth_addr)))
		return;

	vxlan_rtupdate(ifp, &ipaddr, &eh->s_addr);
}

static void
vxlan_recv_encap(struct rte_mbuf *m, uint16_t ether_type,
		 void *l3hdr, struct udphdr *udp)
{
	struct ifnet *ifp;
	struct vxlan_vninode *vnode;
	uint32_t vni;
	int cntr = VXLAN_STATS_INPKTS;
	unsigned int udp_encap_len;
	struct vxlan_hdr *vxhdr;
	uint32_t vx_flags;
	uint16_t hdr_len;

	udp_encap_len = (char *)(udp + 1) - rte_pktmbuf_mtod(m, char *);
	hdr_len = udp_encap_len + sizeof(struct vxlan_hdr);
	if (rte_pktmbuf_data_len(m) < hdr_len) {
		cntr = VXLAN_STATS_INDISCARDS_BADHEADER;
		goto drop;
	}
	vxhdr = (struct vxlan_hdr *)(udp + 1);

	vni = ntohl(vxhdr->vx_vni);
	if (vni & 0xff) {
		cntr = VXLAN_STATS_INDISCARDS_BADHEADER;
		goto drop;
	}

	enum vxlan_type vxl_type;
	uint8_t nxtproto = VGPE_NXT_NONE;

	vx_flags = ntohl(vxhdr->vx_flags);
	if (udp->uh_dport == htons(VXLAN_PORT)) {
		if (vx_flags != VXLAN_VALIDFLAG) {
			cntr = VXLAN_STATS_INDISCARDS_BADHEADER;
			goto drop;
		}
		vxl_type = VXLAN_L2;
	} else if (udp->uh_dport == htons(VXLAN_GPE_PORT)) {
		if (!(vx_flags & (VXLAN_VALIDFLAG | VXLAN_NXTPROTO_FLAG))) {
			cntr = VXLAN_STATS_INDISCARDS_BADHEADER;
			goto drop;
		}
		nxtproto = vx_flags & VXLAN_NXTPROTO_MASK;

		if (nxtproto == VGPE_NXT_NONE || nxtproto >= VGPE_NXT_MAX) {
			cntr = VXLAN_STATS_INDISCARDS_BADHEADER;
			goto drop;
		}
		vxl_type = VXLAN_GPE;
	} else {
		cntr = VXLAN_STATS_INDISCARDS_BADHEADER;
		goto drop;
	}

	vni >>= 8;
	vnode = vxlan_vni_lookup(vni);

	if (unlikely(vnode == NULL)) {
		cntr = VXLAN_STATS_INDISCARDS_VNINOTFOUND;
		goto drop;
	}

	ifp = vnode->ifp;
	if (vnode->learning)
		vxlan_snoop(nxtproto, ifp, m, ether_type, l3hdr, vxhdr);

	rte_pktmbuf_adj(m, hdr_len);
	VXLAN_STAT_INC(cntr);
	if_incr_in(ifp, m);

	pktmbuf_prepare_decap_reswitch(m);

	switch (vxl_type) {
	case VXLAN_L2:
		if (rte_pktmbuf_data_len(m) < sizeof(struct ether_hdr)) {
			cntr = VXLAN_STATS_INDISCARDS_SHORTPAYLOAD;
			goto drop;
		}

		set_spath_rx_meta_data(m, ifp, ETHER_TYPE_TEB,
				       TUN_META_FLAGS_DEFAULT);
		ether_input(ifp, m);
		return;
	case VXLAN_GPE:
		switch (nxtproto) {
		case VGPE_NXT_ETHER:
			if (rte_pktmbuf_data_len(m) <
			    sizeof(struct ether_hdr)) {
				cntr = VXLAN_STATS_INDISCARDS_SHORTPAYLOAD;
				goto drop;
			}

			set_spath_rx_meta_data(m, ifp, ETHER_TYPE_TEB,
					       TUN_META_FLAGS_DEFAULT);
			ether_input(ifp, m);
			return;
		case VGPE_NXT_IPV4:
			/* The vxlan payload had no L2 header, add one now. */
			if (ethhdr_prepend(m, ETHER_TYPE_IPv4) == NULL) {
				cntr = VXLAN_STATS_INDISCARDS_PKT_HEADROOM;
				goto drop;
			}
			/* Later VNI may determine VRF instead of ifp */
			struct pl_packet pl_pkt = {
				.mbuf = m,
				.l2_pkt_type = L2_PKT_UNICAST,
				.in_ifp = ifp,
			};
			set_spath_rx_meta_data(m, ifp, ETHER_TYPE_IPv4,
					       TUN_META_FLAGS_DEFAULT);
			if (unlikely(ifp->capturing))
				capture_burst(ifp, &m, 1);
			pipeline_fused_ipv4_validate(&pl_pkt);
			return;
		case VGPE_NXT_IPV6: {
			if (ethhdr_prepend(m, ETHER_TYPE_IPv6) == NULL) {
				cntr = VXLAN_STATS_INDISCARDS_PKT_HEADROOM;
				goto drop;
			}
			/* Later VNI may determine VRF instead of ifp */
			struct pl_packet pl_pkt = {
				.mbuf = m,
				.in_ifp = ifp,
			};
			set_spath_rx_meta_data(m, ifp, ETHER_TYPE_IPv6,
					       TUN_META_FLAGS_DEFAULT);
			if (unlikely(ifp->capturing))
				capture_burst(ifp, &m, 1);
			pipeline_fused_ipv6_validate(&pl_pkt);
			return;
		}
		case VGPE_NXT_NSH:
		case VGPE_NXT_NONE:
		default:
			cntr = VXLAN_STATS_INDISCARDS_BADPAYLOAD;
			goto drop;
		}
	}

drop:
	VXLAN_STAT_INC(cntr);
	rte_pktmbuf_free(m);
}

static int vxlan_recv_encap_ipv4(struct rte_mbuf *m,
				 void *l3hdr,
				 struct udphdr *udp,
				 struct ifnet *ifp __unused)
{
	struct iphdr *ip = l3hdr;

	if (ip->ihl << 2 != sizeof(struct iphdr)) {
		/* no IP options allowed in outer header */
		VXLAN_STAT_INC(VXLAN_STATS_INDISCARDS_OPTIONS);
		rte_pktmbuf_free(m);
		return 0;
	}

	vxlan_recv_encap(m, htons(ETHER_TYPE_IPv4), ip, udp);
	return 0;
}

static int vxlan_recv_encap_ipv6(struct rte_mbuf *m,
				 void *l3hdr,
				 struct udphdr *udp,
				 struct ifnet *ifp __unused)
{
	struct ip6_hdr *ip6 = l3hdr;

	vxlan_recv_encap(m, htons(ETHER_TYPE_IPv6), ip6, udp);
	return 0;
}

/* Send a packet out of a vxlan interface. */
void
vxlan_output(struct ifnet *ifp, struct rte_mbuf *m, uint16_t proto)
{
	const struct ether_hdr *eh;
	struct vxlan_softc *sc = ifp->if_softc;
	struct vxlan_rtnode *vxlrt = NULL;
	struct ip_addr dip;
	struct vxlan_vninode *vninode;
	bool is_multicast = false;
	enum vgpe_nxt_proto nxtproto;

	vninode = vxlan_vni_lookup(sc->scvx_vni);
	if (!vninode)
		goto drop;

	enum vxlan_type vxl_type = (vninode->flags & VXLAN_FLAG_GPE) ?
				    VXLAN_GPE : VXLAN_L2;

	eh = ethhdr(m);
	/* Keep L2 hdr under the following conditions:
	 *  - if we are forwarding L2
	 *  - always for VXLAN-L2
	 *  - for non-IP packets for VXLAN-GPE
	 */
	if (proto == ETH_P_TEB || vxl_type == VXLAN_L2 ||
	    (eh->ether_type != htons(ETH_P_IP) &&
	     eh->ether_type != htons(ETH_P_IPV6))) {
		nxtproto = (vxl_type == VXLAN_L2) ?
			VGPE_NXT_NONE : VGPE_NXT_ETHER;
		is_multicast = rte_is_multicast_ether_addr(&eh->d_addr);
		vxlrt = vxlan_rtnode_lookup(sc, &eh->d_addr);
		if (vxlrt) {
			if (vxlrt->vxlrt_flags & IFBAF_ADDR_V4) {
				dip.type = AF_INET;
				dip.address.ip_v4 = vxlrt->vxlrt_dst;
			} else if (vxlrt->vxlrt_flags & IFBAF_ADDR_V6) {
				dip.type = AF_INET6;
				memcpy(&dip.address.ip_v6, &vxlrt->vxlrt_dst_v6,
				       sizeof(vxlrt->vxlrt_dst_v6));
			} else
				goto drop;

			/* Mark entry as used */
			rte_atomic32_clear(&vxlrt->vxlrt_unused);
		}
	} else {
		if (eh->ether_type == htons(ETH_P_IP))
			nxtproto = VGPE_NXT_IPV4;
		else if (eh->ether_type == htons(ETH_P_IPV6))
			nxtproto = VGPE_NXT_IPV6;
		else
			goto drop;
		rte_pktmbuf_adj(m, m->l2_len);
		m->l2_len = 0;
	}

	if (!vxlrt) {
		if (!vninode->g_addr)
			goto drop;

		dip.type = AF_INET;
		dip.address.ip_v4.s_addr = vninode->g_addr;
	}
	(void)vxlan_send_packet(ifp, sc->scvx_vni, &dip, m, vxl_type, nxtproto,
				is_multicast, false);
	return;

drop:
	VXLAN_STAT_INC(VXLAN_STATS_OUTDISCARDS);
	rte_pktmbuf_free(m);
}

/*
 * FDB functions
 */
/* Given key (ether address) generate a hash */
static inline unsigned long
vxlan_rtnode_hash(const struct rte_ether_addr *key)
{
	return eth_addr_hash(key, VXLAN_RTHASH_BITS);
}

/* Test if ether address matches value for this entry */
static int vxlan_rtnode_match(struct cds_lfht_node *node,
			      const void *key)
{
	const struct vxlan_rtnode *vxlrt
		= caa_container_of(node, const struct vxlan_rtnode, vxlrt_node);

	return rte_ether_addr_equal(&vxlrt->vxlrt_addr, key);
}

/* Look up a vxlan route node for the specified destination. */
static struct vxlan_rtnode *
vxlan_rtnode_lookup(struct vxlan_softc *sc,
		    const struct rte_ether_addr *addr)
{
	struct cds_lfht_iter iter;

	cds_lfht_lookup(sc->scvx_rthash,
			vxlan_rtnode_hash(addr),
			vxlan_rtnode_match, addr, &iter);

	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);

	if (node)
		return caa_container_of(node, struct vxlan_rtnode, vxlrt_node);
	else
		return NULL;
}

/* Insert the specified vxlan node into the route table. */
static int
vxlan_rtnode_insert(struct vxlan_softc *sc, struct vxlan_rtnode *vxlrt)
{
	struct cds_lfht_node *ret_node;

	cds_lfht_node_init(&vxlrt->vxlrt_node);

	unsigned long hash = vxlan_rtnode_hash(&vxlrt->vxlrt_addr);

	ret_node = cds_lfht_add_unique(sc->scvx_rthash, hash,
				       vxlan_rtnode_match, &vxlrt->vxlrt_addr,
				       &vxlrt->vxlrt_node);
	return (ret_node != &vxlrt->vxlrt_node) ? EEXIST : 0;
}

/* Update existing forwarding table entry */
static void
vxlan_rtupdate(struct ifnet *ifp,
	       struct ip_addr *addr,
	       const struct rte_ether_addr *dst)
{
	struct vxlan_softc *sc = ifp->if_softc;
	struct vxlan_rtnode *vxlrt;

	/*
	 * A route for this destination might already exist.  If so,
	 * update it.
	 */
	vxlrt = vxlan_rtnode_lookup(sc, dst);
	if (unlikely(vxlrt == NULL)) {
		vxlrt = zmalloc_aligned(sizeof(*vxlrt));
		if (unlikely(vxlrt == NULL))
			return;

		vxlrt->vxlrt_flags = IFBAF_DYNAMIC;
		if (addr->type == AF_INET) {
			vxlrt->vxlrt_dst = addr->address.ip_v4;
			vxlrt->vxlrt_flags |= IFBAF_ADDR_V4;
		} else {
			vxlrt->vxlrt_dst_v6 = addr->address.ip_v6;
			vxlrt->vxlrt_flags |= IFBAF_ADDR_V6;
		}
		vxlrt->vxlrt_addr = *dst;
		vxlrt->vxlrt_expire = 0;

		if (vxlan_rtnode_insert(sc, vxlrt) != 0) {
			free(vxlrt);
			return;
		}
	} else if ((vxlrt->vxlrt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
		if (addr->type == AF_INET) {
			vxlrt->vxlrt_dst = addr->address.ip_v4;
			vxlrt->vxlrt_flags |= IFBAF_ADDR_V4;
		} else {
			vxlrt->vxlrt_dst_v6 = addr->address.ip_v6;
			vxlrt->vxlrt_flags |= IFBAF_ADDR_V6;
		}
	}

	/* Entry is marked used */
	rte_atomic32_clear(&vxlrt->vxlrt_unused);
}

static void
vxlan_rtnode_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct vxlan_rtnode, vxlrt_rcu));
}

/* Destroy a vxlan rtnode. */
static void
vxlan_rtnode_destroy(struct vxlan_rtnode *vxlrt)
{
	call_rcu(&vxlrt->vxlrt_rcu, vxlan_rtnode_free);
}

/* Create lock free hash table. */
static void
vxlan_rtable_init(struct vxlan_softc *sc)
{
	sc->scvx_rthash = cds_lfht_new(VXLAN_RTHASH_MIN,
				     VXLAN_RTHASH_MIN,
				     VXLAN_RTHASH_MAX,
				     CDS_LFHT_AUTO_RESIZE,
				     NULL);
	if (sc->scvx_rthash == NULL)
		rte_panic("Can't allocate rthash\n");
}

/* Should route entry be expired?
 * For dynamic entries only, check if it has been used.
 *  for more than VXLAN_RTABLE_EXPIRE intervals.
 */
static int vxlan_rtexpired(struct vxlan_rtnode *vxlrt)
{
	if ((vxlrt->vxlrt_flags & IFBAF_TYPEMASK) != IFBAF_DYNAMIC)
		return 0;

	if (rte_atomic32_test_and_set(&vxlrt->vxlrt_unused)) {
		if (++vxlrt->vxlrt_expire > VXLAN_RTABLE_EXPIRE)
			return 1;
	} else
		vxlrt->vxlrt_expire = 0;

	return 0;
}

/* walk vxlan forwarding database and timeout old entries */
static void vxlan_timer(struct rte_timer *timer __rte_unused, void *arg)
{
	struct vxlan_softc *sc = arg;
	struct cds_lfht_iter iter;
	struct vxlan_rtnode *vxlrt;

	rcu_read_lock();
	cds_lfht_for_each_entry(sc->scvx_rthash, &iter, vxlrt, vxlrt_node) {
		if (vxlan_rtexpired(vxlrt)) {
			cds_lfht_del(sc->scvx_rthash, &vxlrt->vxlrt_node);
			vxlan_rtnode_destroy(vxlrt);
		}
	}
	rcu_read_unlock();
}


/*
 * Interface management functions
 */

static int vxlan_set_mtu(struct ifnet *ifp, uint32_t mtu)
{
	/*
	 * VXLAN i/f has been created with default MTU. Reduce it if user
	 * has explicitly configured a smaller MTU
	 */
	if (mtu < ifp->if_mtu)
		ifp->if_mtu = mtu;

	return 0;
}

static int
vxlaninfo_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attr to avoid issues with newer kernels */
	if (mnl_attr_type_valid(attr, IFLA_VXLAN_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_VXLAN_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan id attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_VXLAN_GROUP:
		if (mnl_attr_validate2(attr, MNL_TYPE_U32, 4) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan group attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_VXLAN_LOCAL:
		if (mnl_attr_validate2(attr, MNL_TYPE_U32, 4) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan local attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_VXLAN_LINK:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan link attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_VXLAN_TTL:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan ttl attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_VXLAN_TOS:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan tos attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_VXLAN_LEARNING:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan learning attribute %d\n",
				type);
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_VXLAN_PORT_RANGE:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan port range attribute %d\n",
				type);
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_VXLAN_GPE:
		if (mnl_attr_validate(attr, MNL_TYPE_FLAG) < 0) {
			RTE_LOG(NOTICE, VXLAN,
				"invalid vxlan gpe attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	default:
		/*Only parse options we care about*/
		tb[type] = NULL;
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static void set_vxlan_params(struct ifnet *ifp,
			     struct vxlan_vninode *vninode,
			     struct nlattr **vxlaninfo,
			     struct nlattr *tb[], uint flags __unused)
{
	if (vxlaninfo[IFLA_VXLAN_GROUP])
		vninode->g_addr = mnl_attr_get_u32(vxlaninfo[IFLA_VXLAN_GROUP]);
	else
		vninode->g_addr = 0;
	vninode->s_addr = 0;

	if (vxlaninfo[IFLA_VXLAN_LINK]) {
		uint32_t pifi = mnl_attr_get_u32(vxlaninfo[IFLA_VXLAN_LINK]);
		struct ifnet *pifp = dp_ifnet_byifindex(pifi);

		ifp->if_parent = pifp;
		/* Only use link MTU if MTU not explicitly configured */
		if (!tb[IFLA_MTU])
			ifp->if_mtu = pifp->if_mtu - VXLAN_OVERHEAD;

		if (vninode->t_vrfid != pifp->if_vrfid) {
			vrf_delete(vninode->t_vrfid);
			if (vrf_find_or_create(pifp->if_vrfid) == NULL) {
				vninode->t_vrfid = VRF_INVALID_ID;
				RTE_LOG(ERR, VXLAN,
					"vxlan %s(%u) missing vrf %u\n",
					ifp->if_name, ifp->if_index,
					pifp->if_vrfid);
			} else
				vninode->t_vrfid = pifp->if_vrfid;
		}
	}

	if (vxlaninfo[IFLA_VXLAN_TOS])
		vninode->tos = mnl_attr_get_u8(vxlaninfo[IFLA_VXLAN_TOS]);
	else
		vninode->tos = 0;

	if (vxlaninfo[IFLA_VXLAN_LEARNING])
		vninode->learning =
			mnl_attr_get_u8(vxlaninfo[IFLA_VXLAN_LEARNING]);
	else
		vninode->learning = 1;

	if (vxlaninfo[IFLA_VXLAN_TTL])
		vninode->ttl = mnl_attr_get_u8(vxlaninfo[IFLA_VXLAN_TTL]);
	else
		vninode->ttl = 0;

	if (vxlaninfo[IFLA_VXLAN_GPE])
		vninode->flags |= VXLAN_FLAG_GPE;

	/* TODO: dynamically allocate source port range */
	vninode->port_low = VXLAN_PORT_LOW;
	vninode->port_high = VXLAN_PORT_HIGH;
}

/* Handle RTM_NEWLINK netlink on existing vxlan interface */
void vxlan_modify(struct ifnet *ifp, uint flags, struct nlattr *tb[],
		  struct nlattr *data)
{
	uint32_t vni;
	struct nlattr *vxlaninfo[IFLA_VXLAN_MAX+1] = { NULL };
	struct vxlan_vninode *vninode;

	if (!data) {
		RTE_LOG(ERR, DATAPLANE, "vxlan mod: missing linkinfo data\n");
		return;
	}

	if (mnl_attr_parse_nested(data,
				  vxlaninfo_attr, vxlaninfo) != MNL_CB_OK) {
		RTE_LOG(ERR, VXLAN, "Could not get vxlaninfo for: %s\n",
			ifp->if_name);
		return;
	}

	vni = mnl_attr_get_u32(vxlaninfo[IFLA_VXLAN_ID]);
	vninode = vxlan_vni_lookup(vni);
	if (!vninode) {
		RTE_LOG(ERR, VXLAN, "Modify for %s, non-existent VNI %u\n",
			ifp->if_name, vni);
		return;
	}
	set_vxlan_params(ifp, vninode, vxlaninfo, tb, flags);
}

static bool
setup_vxlan(struct ifnet *ifp, uint flags,
	    struct nlattr *tb[], struct nlattr *vxlaninfo[],
	    enum cont_src_en cont_src)
{
	uint32_t vni;
	int error;
	struct vxlan_softc *sc;

	if (tb[IFLA_LINK]) {
		unsigned int iflink = cont_src_ifindex(cont_src,
					      mnl_attr_get_u32(tb[IFLA_LINK]));

		if (iflink != 0) {
			struct ifnet *pifp = dp_ifnet_byifindex(iflink);

			if (pifp)
				ifp->if_parent =  pifp;
		}
	}

	if (!vxlaninfo[IFLA_VXLAN_ID]) {
		RTE_LOG(ERR, VXLAN, "No VNI supplied for: %s\n",
			ifp->if_name);
		return false;
	}

	vni = mnl_attr_get_u32(vxlaninfo[IFLA_VXLAN_ID]);
	if (vxlan_vni_lookup(vni)) {
		RTE_LOG(ERR, VXLAN, "%s duplicate VNI %u\n", ifp->if_name,
			vni);
		return false;
	}

	struct vxlan_vninode *vninode;
	/* Insert into VNI table  */
	vninode = zmalloc_aligned(sizeof(*vninode));
	if (unlikely(vninode == NULL)) {
		RTE_LOG(ERR, VXLAN,
			"%s couldn't allocate memory for vxlan: %u\n",
			ifp->if_name, vni);
		return false;
	}

	vninode->ifp = ifp;
	vninode->vni = vni;
	vninode->flags = 0;

	/*
	 * Assume default VRF for transport, a value may or may not be in
	 * the netlink.
	 */
	if (vrf_find_or_create(VRF_DEFAULT_ID))
		vninode->t_vrfid = VRF_DEFAULT_ID;
	else {
		RTE_LOG(ERR, VXLAN, "%s couldn't find default vrf\n",
			ifp->if_name);
		free(vninode);
		return false;
	}

	error = vxlan_vni_insert(vninode);
	if (unlikely(error != 0)) {
		free(vninode);
		vrf_delete(VRF_DEFAULT_ID);
		return false;
	}

	sc = ifp->if_softc;
	sc->scvx_vni = vni;

	set_vxlan_params(ifp, vninode, vxlaninfo, tb, flags);
	return true;
}

/* Create vxlan in response to netlink */
struct ifnet *
vxlan_create(const struct ifinfomsg *ifi, const char *ifname,
	     const struct rte_ether_addr *addr,
	     struct nlattr *tb[], struct nlattr *data,
	     enum cont_src_en cont_src, const struct nlmsghdr *nlh)
{
	struct nlattr *vxlaninfo[IFLA_VXLAN_MAX+1] = { NULL };
	struct ifnet *ifp;
	/* Use a default value to start with may change in vxlan_setup */
	unsigned int mtu = VXLAN_MTU;
	struct nlattr *if_link;

	if (!data) {
		RTE_LOG(ERR, DATAPLANE, "vxlan: missing linkinfo data\n");
		return NULL;
	}

	if (mnl_attr_parse_nested(data,
				  vxlaninfo_attr, vxlaninfo) != MNL_CB_OK) {
		RTE_LOG(ERR, VXLAN, "Could not get vxlaninfo for: %s\n",
			ifname);
		return NULL;
	}

	if_link = vxlaninfo[IFLA_VXLAN_LINK];
	if (if_link) {
		unsigned int link_idx, if_idx;

		link_idx =
			cont_src_ifindex(cont_src,
					 mnl_attr_get_u32(if_link));
		if_idx = cont_src_ifindex(cont_src,
					  ifi->ifi_index);
		if (link_idx != 0) {
			struct ifnet *pifp = dp_ifnet_byifindex(link_idx);

			if (!pifp) {
				missed_nl_child_link_add(link_idx,
							 if_idx,
							 nlh);
				return NULL;
			}
		}
	}

	ifp = if_alloc(ifname, IFT_VXLAN, mtu, addr, SOCKET_ID_ANY);
	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE,
			"out of memory for vxlan_ifnet\n");
		return NULL;
	}

	if_set_ifindex(ifp, cont_src_ifindex(cont_src, ifi->ifi_index));

	if (!setup_vxlan(ifp, ifi->ifi_flags, tb, vxlaninfo, cont_src)) {
		RTE_LOG(ERR, DATAPLANE,
			"%s failed to setup vxlan\n", ifp->if_name);
		if_free(ifp);
		return NULL;
	}

	return ifp;
}

static int vxlan_if_init(struct ifnet *ifp)
{
	struct vxlan_softc *sc;

	sc = malloc(sizeof(struct vxlan_softc));
	if (!sc) {
		RTE_LOG(ERR, DATAPLANE, "out of memory for vxlan_softc\n");
		return -ENOMEM;
	}
	memset(sc, 0, sizeof(struct vxlan_softc));

	vxlan_rtable_init(sc);

	rte_timer_init(&sc->scvx_timer);
	rte_timer_reset(&sc->scvx_timer,
			rte_get_timer_hz() * VXLAN_RTABLE_PRUNE_HZ,
			PERIODICAL, rte_get_master_lcore(),
			vxlan_timer, sc);

	ifp->if_softc = sc;

	return 0;
}

static void vxlan_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct vxlan_softc, scvx_rcu));
}

/* Cleanup vxlan in response to netlink */
static void vxlan_if_uninit(struct ifnet *ifp)
{
	struct vxlan_softc *sc = ifp->if_softc;

	rte_timer_stop(&sc->scvx_timer);
	cds_lfht_destroy(sc->scvx_rthash, NULL);
	call_rcu(&sc->scvx_rcu, vxlan_free);

	struct vxlan_vninode *vni = vxlan_vni_lookup(sc->scvx_vni);

	if (vni) {
		cds_lfht_del(vxlans->vtbl_vnihash, &vni->vni_node);

		vrf_delete(vni->t_vrfid);
		vxlan_vni_destroy(vni);
	}
}

/*
 * Code for handling netlink message about VXLAN
 */
/* Translate netlink state to BSD flags */
static uint8_t ndmstate_to_flags(uint16_t state)
{
	if (state & NUD_PERMANENT)
		return	IFBAF_LOCAL;
	else if (state & NUD_NOARP)
		return IFBAF_STATIC;
	else
		return IFBAF_DYNAMIC;
}

static void vxlan_newneigh(int ifindex,
			   struct in_addr *addr,
			   const struct rte_ether_addr *dst,
			   uint16_t state)
{
	struct ifnet *ifp;
	struct vxlan_softc *sc;
	struct vxlan_rtnode *vrt;
	int err;

	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp)
		return;	/* not a DPDK interface */

	sc = ifp->if_softc;
	vrt = vxlan_rtnode_lookup(sc, dst);
	if (vrt) {
		/* update exist entry */
		vrt->vxlrt_flags = ndmstate_to_flags(state);
		return;
	}

	vrt = zmalloc_aligned(sizeof(*vrt));
	if (!vrt) {
		RTE_LOG(ERR, VXLAN,
			"out of memory for forwarding entry\n");
		return;
	}

	vrt->vxlrt_dst = *addr;
	vrt->vxlrt_addr = *dst;
	vrt->vxlrt_flags = ndmstate_to_flags(state);
	vrt->vxlrt_expire = 0;
	rte_atomic32_set(&vrt->vxlrt_unused, 1);

	err = vxlan_rtnode_insert(sc, vrt);
	if (err) {
		/* already created (race) */
		free(vrt);
	}
}

static void vxlan_delneigh(int ifindex, const struct rte_ether_addr *dst)
{
	struct ifnet *ifp;
	struct vxlan_softc *sc;

	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp)
		return;	/* not a DPDK interface */

	sc = ifp->if_softc;

	struct vxlan_rtnode *vrt = vxlan_rtnode_lookup(sc, dst);

	if (vrt) {
		cds_lfht_del(sc->scvx_rthash, &vrt->vxlrt_node);

		vxlan_rtnode_destroy(vrt);
	} else {
		rcu_read_unlock();
		RTE_LOG(NOTICE, VXLAN,
			"delneigh for %s but on %s not a in forwarding table\n",
			ether_ntoa(dst), ifp->if_name);
	}
}

int vxlan_neigh_change(const struct nlmsghdr *nlh,
		       const struct ndmsg *ndm,
		       struct nlattr *tb[])
{
	const struct rte_ether_addr *lladdr;
	struct in_addr ipaddr;
	in_addr_t *ip;

	if (tb[NDA_LLADDR])
		lladdr = RTA_DATA(tb[NDA_LLADDR]);
	else {
		RTE_LOG(NOTICE, VXLAN, "missing link addr in NEIGH msg\n");
		return MNL_CB_ERROR;
	}


	DP_DEBUG(VXLAN, INFO, VXLAN,
		 "%s pid %u flags %#x lladdr %s flags %#x state %s\n",
		 nlmsg_type(nlh->nlmsg_type),
		 nlh->nlmsg_pid, nlh->nlmsg_flags,
		 ether_ntoa(lladdr),
		 ndm->ndm_flags, ndm_state(ndm->ndm_state));

	switch (nlh->nlmsg_type) {
	case RTM_NEWNEIGH:
		if (tb[NDA_DST]) {
			if (mnl_attr_get_payload_len(tb[NDA_DST]) !=
							sizeof(uint32_t)) {
				RTE_LOG(NOTICE, VXLAN,
					"Invalid dst len in NEIGH msg\n");
				return MNL_CB_ERROR;
			}

			ip = RTA_DATA(tb[NDA_DST]);
			ipaddr.s_addr = *ip;
		} else {
			RTE_LOG(NOTICE, VXLAN, "no DST in NEIGH msg\n");
			return MNL_CB_ERROR;
		}

		struct ifnet *ifp = dp_ifnet_byifindex(ndm->ndm_ifindex);

		if (is_local_ipv4(if_vrfid(ifp), ipaddr.s_addr)) {
			RTE_LOG(NOTICE, VXLAN,
					"local DST(%s) in NEIGH msg; skipping\n",
					inet_ntoa(ipaddr));
			return MNL_CB_ERROR;
		}
		vxlan_newneigh(ndm->ndm_ifindex, &ipaddr,
			       lladdr, ndm->ndm_state);
		break;

	case RTM_DELNEIGH:
		vxlan_delneigh(ndm->ndm_ifindex, lladdr);
		break;

	default:
		RTE_LOG(NOTICE, VXLAN,
			"unexpected netlink message type %d\n",
			nlh->nlmsg_type);
	}

	return MNL_CB_OK;
}

/* Startup initialization */
static void
vxlan_vniable_init(void)
{
	vxlans->vtbl_vnihash = cds_lfht_new(VXLAN_RTHASH_MIN,
					    VXLAN_RTHASH_MIN,
					    VXLAN_RTHASH_MAX,
					    CDS_LFHT_AUTO_RESIZE,
					    NULL);
	vxlans->vtbl_vniseed = random();
	if (vxlans->vtbl_vnihash == NULL)
		rte_panic("Can't allocate rthash\n");

}

static void
vxlan_init(void)
{
	vxlans = malloc(sizeof(struct vxlan_vnitbl));
	if (!vxlans)
		rte_panic("out of memory for vxlan_softc\n");

	memset(vxlans, 0, sizeof(struct vxlan_vnitbl));
	vxlan_vniable_init();

	if (udp_handler_register(AF_INET, htons(VXLAN_PORT),
				 vxlan_recv_encap_ipv4) != 0)
		rte_panic("cannot initialise vxlan ipv4 handler\n");

	if (udp_handler_register(AF_INET, htons(VXLAN_GPE_PORT),
				 vxlan_recv_encap_ipv4) != 0)
		rte_panic("cannot initialise vxlan-gpe ipv4 handler\n");
	if (udp_handler_register(AF_INET6, htons(VXLAN_PORT),
				 vxlan_recv_encap_ipv6) != 0)
		rte_panic("cannot initialise vxlan ipv6 handler\n");

	if (udp_handler_register(AF_INET6, htons(VXLAN_GPE_PORT),
				 vxlan_recv_encap_ipv6) != 0)
		rte_panic("cannot initialise vxlan-gpe ipv6 handler\n");
}

static void vxlan_destroy(void)
{
	udp_handler_unregister(AF_INET, htons(VXLAN_PORT));
	udp_handler_unregister(AF_INET, htons(VXLAN_GPE_PORT));
	udp_handler_unregister(AF_INET6, htons(VXLAN_PORT));
	udp_handler_unregister(AF_INET6, htons(VXLAN_GPE_PORT));
}

/*
 * vxlan_set_flags
 *
 * set/clear flags that define the behavior of a vxlan
 */
void vxlan_set_flags(struct ifnet *ifp, uint32_t flags, bool set)
{
	struct vxlan_vninode *vnode;

	vnode = vxlan_vni_lookup(vxlan_get_vni(ifp));
	if (vnode) {
		if (set)
			vnode->flags |= flags;
		else
			vnode->flags &= (~flags);
	}
}

uint32_t vxlan_get_flags(struct ifnet *ifp)
{
	if (ifp->if_type != IFT_VXLAN)
		return 0;

	struct vxlan_vninode *vnode = vxlan_vni_lookup(vxlan_get_vni(ifp));

	return vnode ? vnode->flags : 0;
}

/* bind vxlan to specified device. Used to allow delayed binding */
void vxlan_set_device(struct ifnet *vxl_ifp, struct ifnet *ifp)
{
	uint16_t ifmtu = VXLAN_MTU;

	if (ifp)
		ifmtu = ifp->if_mtu - VXLAN_OVERHEAD;

	vxl_ifp->if_parent = ifp;
	vxl_ifp->if_mtu = ifmtu;
}

/* Update mtu of all VXLAN interfaces bound to specified device */
void vxlan_mtu_update(struct ifnet *ifp)
{
	vxlan_tbl_walk(vxlan_walker_update_mtu, ifp);
}

void vxlan_set_t_vrfid(struct ifnet *ifp, vrfid_t t_vrfid)
{
	struct vxlan_vninode *vnode;

	if (ifp == NULL)
		return;
	vnode = vxlan_vni_lookup(vxlan_get_vni(ifp));
	if (vnode == NULL)
		return;
	if (vnode->t_vrfid == t_vrfid)
		return;
	if (t_vrfid == VRF_INVALID_ID)
		return;
	vrf_delete(vnode->t_vrfid);

	if (vrf_find_or_create(t_vrfid) == NULL) {
		vnode->t_vrfid = VRF_INVALID_ID;
		RTE_LOG(ERR, VXLAN, "vxlan %s(%u) missing vrf %u\n",
			ifp->if_name, ifp->if_index, t_vrfid);
	} else
		vnode->t_vrfid = t_vrfid;
}

/*
 * vxlan_show_stats
 *
 * display global vxlan statistics
 */
static void vxlan_show_stats(FILE *f)
{
	int i, j;
	unsigned long agg_stats[VXLAN_STATS_MAX];
	json_writer_t *wr;

	wr = jsonw_new(f);
	memset(&agg_stats, 0, sizeof(agg_stats));
	jsonw_name(wr, "vxlan_stats");
	jsonw_start_object(wr);
	RTE_LCORE_FOREACH(i) {
		for (j = 0; j < VXLAN_STATS_MAX; j++)
			agg_stats[j] += vxlan_stats[i][j];
	}
	for (i = 0; i < VXLAN_STATS_MAX; i++)
		jsonw_uint_field(wr, vxlan_cntr_names[i], agg_stats[i]);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

static void vxlan_clear_stats(FILE *f __unused)
{
	memset(vxlan_stats, 0, sizeof(vxlan_stats));
}

static void vxlan_show_macs_one(struct vxlan_vninode *vni,
				void *ctx)
{
	json_writer_t *wr = ctx;
	struct ifnet *ifp = vni->ifp;
	struct vxlan_softc *sc = ifp->if_softc;
	struct cds_lfht_iter iter;
	struct vxlan_rtnode *vxlrt;
	char addr_str[INET_ADDRSTRLEN];
	uint8_t type;

	rcu_read_lock();
	jsonw_start_object(wr);
	jsonw_string_field(wr, "intf", ifp->if_name);
	jsonw_name(wr, "entries");
	jsonw_start_array(wr);
	cds_lfht_for_each_entry(sc->scvx_rthash, &iter, vxlrt, vxlrt_node) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "mac",
				   ether_ntoa_r(&vxlrt->vxlrt_addr, addr_str));
		if (vxlrt->vxlrt_flags & IFBAF_ADDR_V4)
			inet_ntop(AF_INET, &vxlrt->vxlrt_dst,
				  addr_str, sizeof(addr_str));
		else if (vxlrt->vxlrt_flags & IFBAF_ADDR_V6)
			inet_ntop(AF_INET6, &vxlrt->vxlrt_dst_v6,
				  addr_str, sizeof(addr_str));
		jsonw_string_field(wr, "IPAddr", addr_str);
		jsonw_uint_field(wr, "VNI", vxlrt->vni ? vxlrt->vni : vni->vni);
		type = vxlrt->vxlrt_flags & IFBAF_TYPEMASK;
		if (type == IFBAF_DYNAMIC)
			jsonw_string_field(wr, "type", "dynamic");
		else if (type == IFBAF_STATIC)
			jsonw_string_field(wr, "type", "static");
		else if (type == IFBAF_LOCAL)
			jsonw_string_field(wr, "type", "local");
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
	rcu_read_unlock();
}

static void vxlan_show_macs(FILE *f, int argc __unused, char *argv[] __unused)
{
	json_writer_t *wr = jsonw_new(f);

	if (!wr) {
		fprintf(f, "Could not allocate json writer\n");
		return;
	}
	jsonw_pretty(wr, true);
	jsonw_name(wr, "mac_table");
	jsonw_start_array(wr);
	vxlan_tbl_walk(vxlan_show_macs_one, wr);
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

static void vxlan_clear_intf_macs(struct ifnet *ifp)
{
	struct vxlan_softc *sc = ifp->if_softc;
	struct cds_lfht_iter iter;
	struct vxlan_rtnode *vxlrt;

	cds_lfht_for_each_entry(sc->scvx_rthash, &iter, vxlrt, vxlrt_node) {
		cds_lfht_del(sc->scvx_rthash, &vxlrt->vxlrt_node);
	}
}

static void vxlan_walker_clear_mac(struct vxlan_vninode *vni,
				   void *ctx __unused)
{
	vxlan_clear_intf_macs(vni->ifp);
}

static void vxlan_clear_all_macs(void)
{
	vxlan_tbl_walk(vxlan_walker_clear_mac, NULL);
}


static int vxlan_clear_one_mac(struct ifnet *ifp, struct rte_ether_addr *mac)
{
	struct vxlan_rtnode *vxlrt;
	struct vxlan_softc *sc = ifp->if_softc;

	vxlrt = vxlan_rtnode_lookup(sc, mac);
	if (!vxlrt)
		return -ENOENT;

	cds_lfht_del(sc->scvx_rthash, &vxlrt->vxlrt_node);
	vxlan_rtnode_destroy(vxlrt);
	return 0;
}

static void vxlan_clear_macs(FILE *f, int argc, char *argv[])
{
	struct ifnet *ifp;
	struct rte_ether_addr mac;

	if (argc == 1) {
		vxlan_clear_all_macs();
	} else if (argc == 2) {
		ifp = dp_ifnet_byifname(argv[1]);
		if (!ifp) {
			fprintf(f, "Could not find interface %s\n", argv[1]);
			return;
		}
		vxlan_clear_intf_macs(ifp);
	} else if (argc == 3) {
		ifp = dp_ifnet_byifname(argv[1]);
		if (!ifp) {
			fprintf(f, "Could not find interface %s\n", argv[1]);
			return;
		}
		ether_aton_r(argv[2], &mac);
		if (vxlan_clear_one_mac(ifp, &mac))
			fprintf(f, "Could not find entry for mac %s\n",
				argv[2]);
	} else {
		fprintf(f, "Invalid number of arguments %d\n", argc);
	}
}

static void
vxlan_stats_cmd(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		fprintf(f, "Missing argument : %d", argc);
		return;
	}
	argv++;

	if (strcmp(argv[0], "show") == 0)
		vxlan_show_stats(f);
	else if (strcmp(argv[0], "clear") == 0)
		vxlan_clear_stats(f);
	else {
		fprintf(f, "Unknown vxlan stats command\n");
		return;
	}
}

static void
vxlan_macs_cmd(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		fprintf(f, "Missing argument : %d", argc);
		return;
	}
	argc--, argv++;

	if (strcmp(argv[0], "show") == 0)
		vxlan_show_macs(f, argc, argv);
	else if (strcmp(argv[0], "clear") == 0)
		vxlan_clear_macs(f, argc, argv);
	else {
		fprintf(f, "Unknown vxlan macs command\n");
		return;
	}
}

/*
 * VXLAN commands
 */
int cmd_vxlan(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		fprintf(f, "missing argument : %d", argc);
		return -1;
	}
	argc--, argv++;

	if (strcmp(argv[0], "stats") == 0)
		vxlan_stats_cmd(f, argc, argv);
	else if (strcmp(argv[0], "macs") == 0)
		vxlan_macs_cmd(f, argc, argv);
	else
		fprintf(f, "Invalid command %s", argv[0]);
	return 0;
}

static int
vxlan_if_dump(struct ifnet *ifp, json_writer_t *wr,
	      enum if_dump_state_type type)
{
	switch (type) {
	case IF_DS_STATE:
		vxlan_show_info(wr, ifp);
		break;
	default:
		break;
	}

	return 0;
}

static enum dp_ifnet_iana_type
vxlan_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_TUNNEL;
}

static const struct ift_ops vxlan_if_ops = {
	.ifop_set_mtu = vxlan_set_mtu,
	.ifop_init = vxlan_if_init,
	.ifop_uninit = vxlan_if_uninit,
	.ifop_dump = vxlan_if_dump,
	.ifop_iana_type = vxlan_iana_type,
};

static void vxlan_type_init(void)
{
	int ret;

	vxlan_init();

	ret = if_register_type(IFT_VXLAN, &vxlan_if_ops);
	if (ret < 0)
		rte_panic("Failed to register VXLAN type: %s", strerror(-ret));
}

static const struct dp_event_ops vxlan_events = {
	.init = vxlan_type_init,
	.uninit = vxlan_destroy,
};

DP_STARTUP_EVENT_REGISTER(vxlan_events);
