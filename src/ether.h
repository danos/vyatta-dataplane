/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef ETHER_H
#define ETHER_H

#include <endian.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "compiler.h"
#include "if_var.h"
#include "main.h"
#include "pktmbuf_internal.h"
#include "util.h"

struct ifnet;

struct ether_vlan_hdr {
	struct rte_ether_hdr eh;
	struct rte_vlan_hdr  vh;
};

#define VLAN_HDR_LEN  sizeof(struct ether_vlan_hdr)

/* Length of HW address string buffer used in debug output */
#define ETH_ADDR_STR_LEN 18	/* "00:00:00:00:00:00" plus terminator */

void ether_input(struct ifnet *ifp, struct rte_mbuf *m)
	__hot_func __rte_cache_aligned;
void ether_input_no_dyn_feats(struct ifnet *ifp, struct rte_mbuf *m)
	__hot_func __rte_cache_aligned;

static inline struct rte_ether_hdr *ethhdr(struct rte_mbuf *m)
{
	return rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
}

/* ethtype in host byte order, return ptr to pkmbuf new data_start */
static inline char *ethhdr_prepend(struct rte_mbuf *m, uint16_t ethtype)
{
	char *data_start = rte_pktmbuf_prepend(m, ETHER_HDR_LEN);
	struct rte_ether_hdr *eh;

	if (!data_start)
		return NULL;
	m->l2_len = ETHER_HDR_LEN;
	eh = ethhdr(m);
	eh->d_addr.addr_bytes[0] &= ~ETHER_GROUP_ADDR; /* Clear multicast bit */
	eh->ether_type = htons(ethtype);
	return data_start;
}

/* Get real ether type ether-type which could be after vlan hdr */
static inline uint16_t ethtype(const struct rte_mbuf *m,
			       uint16_t vlan_proto)
{
	struct ether_vlan_hdr *vhdr =
		rte_pktmbuf_mtod(m, struct ether_vlan_hdr *);

	if (vhdr->eh.ether_type == htons(vlan_proto))
		return vhdr->vh.eth_proto;
	else
		return vhdr->eh.ether_type;
}

static inline uint16_t vid_from_pkt(struct rte_mbuf *m, uint16_t etype)
{
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (eth->ether_type != htons(etype))
		return 0;

	struct rte_vlan_hdr *vh = (struct rte_vlan_hdr *) (eth + 1);

	return ntohs(vh->vlan_tci) & VLAN_VID_MASK;
}

static inline bool pcp_from_pkt(struct rte_mbuf *m, uint16_t vlan_proto,
				uint8_t *pcp)
{
	struct ether_vlan_hdr *vhdr =
		rte_pktmbuf_mtod(m, struct ether_vlan_hdr *);

	if (vhdr->eh.ether_type != htons(vlan_proto))
		return false;

	*pcp =  (ntohs(vhdr->vh.vlan_tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;
	return true;
}

static inline uint16_t vid_decap(struct rte_mbuf *m, uint16_t etype)
{
	struct ether_vlan_hdr *eth =
		rte_pktmbuf_mtod(m, struct ether_vlan_hdr *);
	uint16_t vid;

	if (eth->eh.ether_type != htons(etype))
		return 0;

	vid = ntohs(eth->vh.vlan_tci);
	memmove((char *) eth + sizeof(struct rte_vlan_hdr),
		eth, 2 * ETHER_ADDR_LEN);

	rte_pktmbuf_adj(m, sizeof(struct rte_vlan_hdr));

	return vid;
}

static inline struct rte_mbuf *vid_encap(uint16_t if_vlan,
				  struct rte_mbuf **m, uint16_t etype)
{
	if (unlikely(pktmbuf_prepare_for_header_change(m,
		     sizeof(struct rte_ether_hdr)) != 0))
		return NULL;

	struct rte_ether_hdr *eth =
				rte_pktmbuf_mtod(*m, struct rte_ether_hdr *);
	struct ether_vlan_hdr *vhdr;

	vhdr = (struct ether_vlan_hdr *) rte_pktmbuf_prepend(*m,
		sizeof(struct rte_vlan_hdr));

	if (unlikely(vhdr == NULL))
		return NULL;

	memmove(&vhdr->eh, eth, 2 * ETHER_ADDR_LEN);
	vhdr->vh.eth_proto = eth->ether_type;
	vhdr->eh.ether_type = htons(etype);
	vhdr->vh.vlan_tci = htons(if_vlan);
	/* NB VLAN_HDR_LEN includes the ethernet header as well */
	dp_pktmbuf_l2_len(*m) = VLAN_HDR_LEN;

	return *m;
}

/*
 * These functions work by aliasing the 6 byte Ethernet address
 * into a 64 bit value. The macro shift16, removes the extra
 * bytes with the correct shift depending on byte order.
 * clear_lsn clears the lower nibble the least significant byte of
 * the ether addr in 64-bit format.
 * Ethernet link-local address is the range 01:80:C2:00:00:0x
 */
#ifdef __BYTE_ORDER
  #if __BYTE_ORDER == __BIG_ENDIAN
    #define shift16(s) (s >> 16)
    #define clear_lsn(s) (s & 0xFFFFFFFFFFFFFFF0UL)
    #define ETHER_LL_64 0x00000180c2000000UL
  #else
    #define shift16(s) (s << 16)
    #define clear_lsn(s) (s & 0xF0FFFFFFFFFFFFFFUL)
    #define ETHER_LL_64 0x000000c280010000UL
  #endif
#endif

IGNORE_SANITIZER
static inline int rte_ether_addr_equal(const struct rte_ether_addr *e1,
				   const struct rte_ether_addr *e2)
{
	uint64_t e1_addr = shift16(*(const uint64_t *) e1);
	uint64_t e2_addr = shift16(*(const uint64_t *) e2);

	return (e1_addr == e2_addr);
}

/*
 * A safe version of rte_ether_addr_equal() that can be used safely
 * with rte_ether_addr_copy(). The compiler might choose to re-order
 * parts of rte_ether_addr_equal() before a copy.
 */
static inline int rte_ether_addr_equal_safe(
					const struct rte_ether_addr *ea_from,
					const struct rte_ether_addr *ea_to)
{
	return memcmp(ea_from, ea_to, sizeof(*ea_from)) == 0;
}

IGNORE_SANITIZER
static inline uint32_t eth_addr_hash(const struct rte_ether_addr *ea,
				     unsigned int bits)
{
	uint64_t val = shift16(*(const uint64_t *) ea);

	return hash64(val, bits);
}

static inline bool ether_is_empty(const struct rte_ether_addr *mac)
{
	const struct rte_ether_addr empty_mac = { { 0 } };

	return rte_ether_addr_equal_safe(mac, &empty_mac);
}

/*
 * is_link_local_ether_addr - Determine if given Ethernet address is
 * link-local.  Includes Spanning Tree multicast address.
 */
static inline bool is_link_local_ether_addr(const struct rte_ether_addr *ea)
{
	uint64_t ea_addr = clear_lsn(shift16(*(const uint64_t *) ea));

	return (ea_addr == ETHER_LL_64);
}

typedef void (*packet_input_t)(struct ifnet *ifp, struct rte_mbuf *pkt);

void set_packet_input_func(packet_input_t input_fn);
extern packet_input_t packet_input_func __hot_data;

int ether_if_set_l2_address(struct ifnet *ifp, uint32_t l2_addr_len,
			    void *l2_addr);
int ether_if_set_broadcast(struct ifnet *ifp, bool enable);

#endif /* ETHER_H */
