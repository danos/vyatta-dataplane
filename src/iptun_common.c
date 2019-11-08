/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * Common ip tunnel processing routines
 */

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <stdint.h>
#include <stdio.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "iptun_common.h"
#include "pktmbuf.h"
#include "fal_plugin.h"
#include "fal.h"
#include "vplane_log.h"

static void
ip_tos_ecn_set_inner(void *inner_hdr, uint16_t prot, uint8_t new_inner)
{
	if (prot == ETH_P_IP)
		ip_tos_ecn_set(inner_hdr, new_inner);
	else if (prot == ETH_P_IPV6)
		ip6_tos_ecn_set(inner_hdr, new_inner);
}

void
ip6_tos_copy_inner(uint32_t *outer_flow, uint32_t *inner_flow)
{
	uint32_t outer = ntohl(*outer_flow);
	uint32_t inner = ntohl(*inner_flow);

	outer &= ~IPV6_FLOW_TOS;
	outer |= inner & IPV6_FLOW_TOS;
	*outer_flow = htonl(outer);
}

/* Copy dscp from inner Ipv6 to outer IPv4 */
void ip_ip6_dscp_copy_inner(uint8_t *outer_tos, uint32_t *inner_flow)
{
	uint32_t inner = ntohl(*inner_flow);

	*outer_tos |= (inner & IPV6_FLOW_TOS_NOECN) >> IPV6_FLOW_TOS_SHIFT;
}

/* Copy dscp from inner Ipv4 to outer IPv6 */
void ip6_ip_dscp_copy_inner(uint32_t *outer_flow, uint8_t inner_tos)
{
	uint32_t outer = ntohl(*outer_flow);

	outer &= ~IPV6_FLOW_TOS_NOECN;
	outer |= (inner_tos &= ~IPTOS_ECN_MASK) << IPV6_FLOW_TOS_SHIFT;
	*outer_flow = htonl(outer);
}

void
ip6_tos_copy_outer_noecn(uint32_t *outer_flow, uint32_t *inner_flow)
{
	uint32_t outer = ntohl(*outer_flow);
	uint32_t inner = ntohl(*inner_flow);

	/*
	 * Set inner TOS to outer TOS, leaving ECN unchanged
	 */
	outer &= IPV6_FLOW_TOS_NOECN;
	inner = (inner & ~IPV6_FLOW_TOS_NOECN) | outer;
	*inner_flow = htonl(inner);
}

/*
 * RFC 3168, section 9.1.1 full functionality.
 * Copy the ECN codepoint of the inside header to the outside header
 * on encapsulation if the inside header is not-ECT or ECT, and to
 * set the ECN codepoint of the outside header to ECT(0) if the ECN
 * codepoint of the inside header is CE.
 */
void
ip_tos_ecn_encap(uint8_t *outer_tos, uint8_t inner_tos)
{
	*outer_tos &= ~IPTOS_ECN_MASK;
	*outer_tos |= ((inner_tos & IPTOS_ECN_MASK) == IPTOS_ECN_MASK) ?
		IPTOS_ECN_ECT0 : inner_tos & IPTOS_ECN_MASK;
}

void
ip6_tos_ecn_encap(uint32_t *outer_flow, uint32_t *inner_flow)
{
	uint32_t outer = ntohl(*outer_flow);
	uint32_t inner = ntohl(*inner_flow);

	outer &= ~IPV6_FLOW_ECN_MASK;
	if ((inner & IPV6_FLOW_ECN_MASK) == IPV6_FLOW_ECN_MASK)
		outer |= IPV6_FLOW_ECN_ECT0;
	else
		outer |= inner & IPV6_FLOW_ECN_MASK;
	*outer_flow = htonl(outer);
}

/* ecn encap when outer is IPv6 and inner is IPv4 */
void
ip6_ip_ecn_encap(uint32_t *outer_flow, uint8_t inner_tos)
{
	uint32_t outer = ntohl(*outer_flow);

	outer &= ~IPV6_FLOW_ECN_MASK;
	if ((inner_tos & IPTOS_ECN_MASK) == IPTOS_ECN_MASK)
		outer |= IPV6_FLOW_ECN_ECT0;
	else
		outer |= (inner_tos & IPTOS_ECN_MASK) << IPV6_FLOW_TOS_SHIFT;
	*outer_flow = htonl(outer);
}

/* ecn encap when outer is IPv4 and inner is IPv6 */
void
ip_ip6_ecn_encap(uint8_t *outer_tos, uint32_t *inner_flow)
{
	uint32_t inner = ntohl(*inner_flow);

	*outer_tos &= ~IPTOS_ECN_MASK;
	if ((inner & IPV6_FLOW_ECN_MASK) == IPV6_FLOW_ECN_MASK)
		*outer_tos |= (IPV6_FLOW_ECN_ECT0 >> IPV6_FLOW_TOS_SHIFT);
	else
		*outer_tos |=
			((inner & IPV6_FLOW_ECN_MASK) >> IPV6_FLOW_TOS_SHIFT);
}

/*
 * RFC 6040: section 4.2, Tunnel egress behaviour ECN.
 *
 * To decapsulate the inner header at the tunnel egress, a compliant
 * tunnel egress MUST set the outgoing ECN field to the codepoint at the
 * intersection of the appropriate arriving inner header (row) and outer
 * header (column) in Figure 4 (the IPv4 header checksum also changes
 * whenever the ECN field is changed).  There is no need for more than
 * one mode of decapsulation, as these rules cater for all known
 * requirements.
 *
 *          +---------+------------------------------------------------+
 *          |Arriving |            Arriving Outer Header               |
 *          |   Inner +---------+------------+------------+------------+
 *          |  Header | Not-ECT | ECT(0)     | ECT(1)     |     CE     |
 *          +---------+---------+------------+------------+------------+
 *          | Not-ECT | Not-ECT |Not-ECT(!!!)|Not-ECT(!!!)| <drop>(!!!)|
 *          |  ECT(0) |  ECT(0) | ECT(0)     | ECT(1)     |     CE     |
 *          |  ECT(1) |  ECT(1) | ECT(1) (!) | ECT(1)     |     CE     |
 *          |    CE   |      CE |     CE     |     CE(!!!)|     CE     |
 *          +---------+---------+------------+------------+------------+
 *
 *                 Figure 4: New IP in IP Decapsulation Behaviour
 *
 * Return: 1 if the packet should be dropped.
 */
int
ip_tos_ecn_decap(uint8_t outer_tos, char *inner_hdr, uint16_t prot)
{
	uint8_t inner_tos;

	if (prot == ETH_P_IP)
		inner_tos = ((struct iphdr *)(inner_hdr))->tos;
	else if (prot == ETH_P_IPV6)
		inner_tos = ipv6_hdr_get_tos((struct ip6_hdr *)inner_hdr);
	else
		return 0;

	if ((inner_tos & IPTOS_ECN_MASK) == IPTOS_ECN_NOT_ECT) {
		if ((outer_tos & IPTOS_ECN_MASK) == IPTOS_ECN_CE)
			return 1;
	}

	if ((inner_tos & IPTOS_ECN_MASK) == IPTOS_ECN_ECT0) {
		if ((outer_tos & IPTOS_ECN_MASK) == IPTOS_ECN_ECT1) {
			/* Change inner to ECT_1 */
			ip_tos_ecn_set_inner(inner_hdr, prot, IPTOS_ECN_ECT1);
		}
		if ((outer_tos & IPTOS_ECN_MASK) == IPTOS_ECN_CE) {
			/* Change inner to CE */
			ip_tos_ecn_set_inner(inner_hdr, prot, IPTOS_ECN_CE);
		}
	}

	if ((inner_tos & IPTOS_ECN_MASK) == IPTOS_ECN_ECT1) {
		if ((outer_tos & IPTOS_ECN_MASK) == IPTOS_ECN_CE) {
			/* Change inner to CE */
			ip_tos_ecn_set_inner(inner_hdr, prot, IPTOS_ECN_CE);
		}
	}
	return 0;
}

/*
 * Return a pointer to the inner IP header if there is one. If the initial
 * packet does not have the complete inner IP header, or the complete GRE
 * header if there is no inner IP, then copy it from the following segments
 * into the first segment, and fixup appropriately.
 */
char *
mbuf_get_inner_ip(struct rte_mbuf *m, const char *outer, char *inner,
		  uint16_t *next_prot)
{
	unsigned int len;

	/* Is there enough data in the first segment to find the inner hdr. */
	len = rte_pktmbuf_data_len(m) - pktmbuf_l2_len(m);

	if (*next_prot == ETH_P_IP) {
		if (len >= (inner - outer) + sizeof(struct iphdr))
			return inner;

	} else if (*next_prot == ETH_P_IPV6) {
		if (len >= (inner - outer) + sizeof(struct ip6_hdr))
			return inner;
	}

	return NULL;
}

int
iptun_eth_hdr_fixup(struct rte_mbuf *m, uint16_t next_prot,
		     uint16_t decap_size)
{
	struct ether_hdr *orig_eth;
	struct ether_hdr *new_eth;

	/*
	 * Have found a tunnel, so remove the outer IP and other
	 * protocol headers. Need to leave the mbuf such that if we
	 * were to pass the packet to the kernel, the L2 header
	 * protocol accurately reflects the next header and has a
	 * correct dest addr set.
	 */
	orig_eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	new_eth = (struct ether_hdr *)rte_pktmbuf_adj(m, decap_size);
	if (unlikely(!new_eth))
		return -1;

	new_eth->ether_type = htons(next_prot);
	new_eth->d_addr = orig_eth->d_addr;
	return 0;
}

void iptun_create_fal_tep(struct ifnet *ifp, struct tun_info_st *tun_info,
			  fal_object_t *obj)
{
	int ret = 0;
	unsigned int l3_nattrs = 0;
	struct fal_attribute_t l3_attrs[12];

	switch (ifp->if_type) {
	case IFT_TUNNEL_GRE:
		break;
	default:
		/* Unsupported */
		return;
	}
	l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_TYPE;
	l3_attrs[l3_nattrs].value.u8 = tun_info->tun_type;
	l3_nattrs++;

	switch (tun_info->tun_type) {
	case FAL_TUNNEL_TYPE_L3INIP_GRE:
	case FAL_TUNNEL_TYPE_L3INIP6_GRE:
		l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_LOCAL_IP;
		fal_attr_set_ip_addr(&l3_attrs[l3_nattrs], &tun_info->local);
		l3_nattrs++;

		l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_REMOTE_IP;
		fal_attr_set_ip_addr(&l3_attrs[l3_nattrs], &tun_info->remote);
		l3_nattrs++;

		l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_NEXTHOP;
		fal_attr_set_ip_addr(&l3_attrs[l3_nattrs], &tun_info->nh_ip);
		l3_nattrs++;
		break;
	default:
		return;
	}
	l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_UNDERLAY_INTERFACE;
	l3_attrs[l3_nattrs].value.u32 = tun_info->ul_intf;
	l3_nattrs++;
	l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_OVERLAY_INTERFACE;
	l3_attrs[l3_nattrs].value.u32 = tun_info->ol_intf;
	l3_nattrs++;
	l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_ENCAP_TTL_MODE;
	l3_attrs[l3_nattrs].value.u8 = tun_info->ttl_mode;
	l3_nattrs++;
	if (tun_info->ttl_mode == FAL_TUNNEL_TTL_MODE_PIPE_MODEL) {
		l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_ENCAP_TTL_VAL;
		l3_attrs[l3_nattrs].value.u8 = tun_info->ttl_val;
		l3_nattrs++;
	}
	l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_ENCAP_DSCP_MODE;
	l3_attrs[l3_nattrs].value.u8 = tun_info->dscp_mode;
	l3_nattrs++;
	if (tun_info->dscp_mode == FAL_TUNNEL_DSCP_MODE_PIPE_MODEL) {
		l3_attrs[l3_nattrs].id = FAL_TUNNEL_ATTR_ENCAP_DSCP_VAL;
		l3_attrs[l3_nattrs].value.u8 = tun_info->dscp_val;
		l3_nattrs++;
	}

	ret = fal_create_tunnel(l3_nattrs, l3_attrs, obj);
	if (((ret < 0) && (ret != -EOPNOTSUPP)) ||
	    (!*obj))
		RTE_LOG(ERR, DATAPLANE,
			"Failed to create FAL tun object for GRE tun: %s\n",
			ifp->if_name);
}

void iptun_delete_fal_tep(struct ifnet *ifp, fal_object_t obj)
{
	int ret = 0;
	uint8_t ift = ifp->if_type;

	switch (ift) {
	case IFT_TUNNEL_GRE:
		break;
	default:
		/* Unsupported */
		return;
	}
	ret = fal_delete_tunnel(obj);
	if ((ret < 0) && (ret != -EOPNOTSUPP))
		RTE_LOG(ERR, DATAPLANE,
			"Failed to delete FAL tun object for GRE tun: %s\n",
			ifp->if_name);
}

void iptun_set_fal_tep_attr(struct ifnet *ifp, fal_object_t obj,
			    uint32_t nattrs,
			    struct fal_attribute_t *attr_list)
{
	uint8_t ift = ifp->if_type;
	int ret = 0;

	if (!obj)
		return;

	switch (ift) {
	case IFT_TUNNEL_GRE:
		ret = fal_set_tunnel_attr(obj, nattrs, attr_list);
		break;
	default:
		/* Unsupported */
		return;
	}
	if ((ret < 0) && (ret != -EOPNOTSUPP))
		RTE_LOG(ERR, DATAPLANE,
			"Failed set attr for FAL tun object for GRE tun: %s\n",
			ifp->if_name);
}
