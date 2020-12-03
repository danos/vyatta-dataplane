/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Common IP tunnel functions
 */

#ifndef IPTUN_COMMON_H
#define IPTUN_COMMON_H

#include <stdint.h>
#include "util.h"
#include "fal_plugin.h"
#include "interface.h"
#include "ip_addr.h"

struct iphdr;
struct rte_mbuf;

struct tun_info_st {
	uint32_t ul_intf;
	uint32_t ol_intf;
	/* Underlay/transport VRF */
	vrfid_t ul_vrf_id;
	/* Next-hop in the underlay network to reach the TEP */
	struct ip_addr nh_ip;
	/* TEP local address */
	struct ip_addr local;
	/* TEP local address */
	struct ip_addr remote;
	uint8_t tun_type;
	uint8_t ttl_mode;
	uint8_t ttl_val;
	uint8_t dscp_mode;
	uint8_t dscp_val;
};

#define IPV6_FLOW_TOS 0x0ff00000
#define IPV6_FLOW_TOS_NOECN 0x0fc00000
#define IPV6_FLOW_ECN_MASK 0x00300000
#define IPV6_FLOW_ECN_ECT0 0x00200000
#define IPV6_FLOW_TOS_SHIFT 20

void ip6_tos_copy_inner(uint32_t *outer_flow, const uint32_t *inner_flow);
void ip6_ip_dscp_copy_inner(uint32_t *outer_flow, uint8_t inner_tos);
void ip_ip6_dscp_copy_inner(uint8_t *outer_tos, const uint32_t *inner_flow);
void ip6_tos_copy_outer_noecn(const uint32_t *outer_flow, uint32_t *inner_flow);
void ip_tos_ecn_encap(uint8_t *outer_tos, uint8_t inner_tos);
void ip6_tos_ecn_encap(uint32_t *outer_flow, const uint32_t *inner_flow);
void ip6_ip_ecn_encap(uint32_t *outer_flow, uint8_t inner_tos);
void ip_ip6_ecn_encap(uint8_t *outer_tos, const uint32_t *inner_flow);
int ip_tos_ecn_decap(uint8_t outer_tos, char *inner_hdr, uint16_t prot);
char *
mbuf_get_inner_ip(struct rte_mbuf *m, const char *outer, char *inner,
		  const uint16_t *next_prot);
int iptun_eth_hdr_fixup(struct rte_mbuf *m, uint16_t next_prot,
			uint16_t decap_size);

void iptun_create_fal_tep(struct ifnet *ifp, struct tun_info_st *tun_info,
			  fal_object_t *obj);

void iptun_delete_fal_tep(struct ifnet *ifp, fal_object_t obj);
void iptun_set_fal_tep_attr(struct ifnet *ifp, fal_object_t obj,
			    uint32_t nattrs, struct fal_attribute_t *attr_list);

#endif /* IPTUN_COMMON_H */
