/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef	PKTMBUF_INTERNAL_H
#define	PKTMBUF_INTERNAL_H
/*
 * Extensions to rte mbuf library
 */
#include <assert.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/if_tun.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_port.h>

#include "compat.h"
#include "ip_addr.h"
#include "main.h"
#include "pktmbuf.h"
#include "util.h"
#include "vrf.h"

struct ifnet;
struct rte_mempool;
struct npf_session;
struct cgn_session;

/* Flags which are overlaid on the ol_flags member of rte_mbuf. */
#define PKT_RX_SEEN_BY_CRYPTO (1ULL << 41)
#define PKT_TX_SEEN_BY_CRYPTO (1ULL << 42)

struct pkt_mdata_nat64 {
	struct npf_session *n64_se;
};

#define TUN_META_FLAGS_NONE	0x0
#define TUN_META_FLAGS_DEFAULT	(TUN_META_FLAG_MARK | TUN_META_FLAG_IIF)

struct pkt_mdata_spath {
	struct tun_pi pi;
	struct tun_meta meta;
} __attribute__ ((__packed__));

struct pkt_mdata_bridge {
	uint32_t member_ifindex;
	uint16_t outer_vlan;
} __attribute__ ((__packed__));

struct pkt_mdata_ifindex {
	uint32_t ifindex;
} __attribute__ ((__packed__));

/*
 * Packet metadata that is invariant for the lifetime of the packet,
 * i.e. even if encapped or decapped, or reswitched through another
 * interface.
 */
enum pkt_mdata_invar_type {
	PKT_MDATA_INVAR_SPATH		= (1 << 0),
	/*
	 * This is invariant because there are certain types of
	 * interface, e.g. l2tp, that expect to punt to the kernel on the
	 * original arriving interface, even after a decap.
	 */
	PKT_MDATA_INVAR_BRIDGE		= (1 << 1),
	PKT_MDATA_INVAR_NAT64		= (1 << 2),
	PKT_MDATA_INVAR_FEATURE_PTRS	= (1 << 3),
	PKT_MDATA_INVAR_MAX,
};

static_assert(DP_PKTMBUF_MAX_INVAR_FEATURE_PTRS == 1,
	      "Too many invar ptr meta data fields - update the non ptr values");

/*
 * Packet metadata that is clear when the key character of the packet
 * is changed, i.e. when changing L3 protocol, when decapped or when
 * encapped.
 */
enum pkt_mdata_type {
	PKT_MDATA_SESSION		= (1 << 0),
	PKT_MDATA_DPI_SEEN		= (1 << 1),
	PKT_MDATA_SESSION_SENTRY	= (1 << 2),
	PKT_MDATA_CRYPTO_PR		= (1 << 3),
	PKT_MDATA_IFINDEX		= (1 << 4),
	PKT_MDATA_FAL_FRAMED		= (1 << 5),
	PKT_MDATA_L2_RCV_TYPE		= (1 << 6),
	PKT_MDATA_SNAT			= (1 << 7),
	PKT_MDATA_DNAT			= (1 << 8),
	PKT_MDATA_FROM_US		= (1 << 9), /* Locally generated pkt */
	PKT_MDATA_DEFRAG		= (1 << 10), /* Reassembled */
	PKT_MDATA_CGNAT_OUT		= (1 << 11),
	PKT_MDATA_CGNAT_IN		= (1 << 12),
	PKT_MDATA_CGNAT_SESSION		= (1 << 13),
	PKT_MDATA_CRYPTO_OP             = (1 << 14),
};

struct npf_session;

struct pktmbuf_mdata {
	/* PKT_MDATA_SESSION_SENTRY */
	struct sentry *md_sentry;

	/* PKT_MDATA_SESSION */
	struct npf_session *md_session;

	/* PKT_MDATA_CGNAT_SESSION */
	struct cgn_session *md_cgn_session;

	/* PKT_MDATA_INVAR_NAT64 */
	struct pkt_mdata_nat64 md_nat64;

	/* PKT_MDATA_INVAR_SPATH */
	struct pkt_mdata_spath md_spath;

	/* PKT_MDATA_CRYPTO_PR */
	struct policy_rule *pr;

	/* PKT_MDATA_INVAR_BRIDGE */
	struct pkt_mdata_bridge md_bridge;

	/* PKT_MDATA_IFINDEX */
	struct pkt_mdata_ifindex md_ifindex;

	/* PKT_MDATA_L2_RCV_TYPE */
	enum l2_packet_type md_l2_rcv_type;

	/* PKT_MDATA_CRYPTO_OP */
	struct rte_crypto_op *cop;

	/* Pointers that features can register for ownership of */
	void *md_feature_ptrs[DP_PKTMBUF_MAX_INVAR_FEATURE_PTRS];

} __rte_aligned(RTE_CACHE_LINE_SIZE * 2);

/* Ensure struct fits in two cache lines */
static_assert(sizeof(struct pktmbuf_mdata) <= 128,
	      "struct is too large");

static inline struct pktmbuf_mdata *
pktmbuf_mdata(const struct rte_mbuf *m)
{
	assert(m->priv_size >= sizeof(struct pktmbuf_mdata));
	return (struct pktmbuf_mdata *)
		RTE_MBUF_METADATA_UINT8_PTR(m, sizeof(struct rte_mbuf));
}

static inline void
pktmbuf_mdata_invar_set(struct rte_mbuf *m,
			enum pkt_mdata_invar_type pkt_meta_flags)
{
	/* userdata repurposed as flags + vrf field */
	m->udata64 |= (pkt_meta_flags & UINT16_MAX) << 16;
}

/*
 * 2nd mbuf cache line check, to see if there is mdata in the 3rd cache line
 */
static inline bool
pktmbuf_mdata_invar_exists(const struct rte_mbuf *m,
			   enum pkt_mdata_invar_type pkt_meta_flags)
{
	return m->udata64 & ((pkt_meta_flags & UINT16_MAX) << 16);
}

static inline void
pktmbuf_mdata_invar_clear(struct rte_mbuf *m,
			  enum pkt_mdata_invar_type pkt_meta_flags)
{
	m->udata64 &= ~((uint64_t)((pkt_meta_flags & UINT16_MAX) << 16));
}

static inline void
pktmbuf_mdata_set(struct rte_mbuf *m, enum pkt_mdata_type pkt_meta_flags)
{
	/* userdata repurposed as flags + vrf field */
	m->udata64 |= (pkt_meta_flags & UINT16_MAX);
}

/*
 * 2nd mbuf cache line check, to see if there is mdata in the 3rd cache line
 */
static inline bool
pktmbuf_mdata_exists(const struct rte_mbuf *m,
		     enum pkt_mdata_type pkt_meta_flags)
{
	return m->udata64 & (pkt_meta_flags & UINT16_MAX);
}

static inline void
pktmbuf_mdata_clear(struct rte_mbuf *m, enum pkt_mdata_type pkt_meta_flags)
{
	m->udata64 &= ~((uint64_t)(pkt_meta_flags & UINT16_MAX));
}

static inline void
pktmbuf_mdata_clear_all(struct rte_mbuf *m)
{
	m->udata64 = 0;
}

/* clear all variant flags */
static inline void
pktmbuf_mdata_clear_variant(struct rte_mbuf *m)
{
	m->udata64 &= ~UINT16_MAX;
}

static inline void
pktmbuf_set_vrf(struct rte_mbuf *m, vrfid_t vrf_id)
{
	m->udata64 &= UINT32_MAX;
	m->udata64 |= ((uint64_t)(vrf_id) << 32);
}

static inline vrfid_t
pktmbuf_get_vrf(const struct rte_mbuf *m)
{
	return (uint32_t)(m->udata64 >> 32);
}

/**
 * Allocate mbuf and initialize meta data
 *
 * This routine is wrapper around rte_pktmbuf_alloc that also
 * initalizes other fields in mbuf which are not set by default
 * in DPDK.
 *
 * @param mp
 *   The mempool from which the mbuf is allocated.
 * @return
 *   - The pointer to the new mbuf on success.
 *   - NULL if allocation failed.
 */
static inline struct rte_mbuf *pktmbuf_alloc(struct rte_mempool *mp,
					     vrfid_t vrf_id)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(mp);

	if (likely(m != NULL)) {
		pktmbuf_mdata_clear_all(m);
		pktmbuf_set_vrf(m, vrf_id);
	}

	return m;
}

/**
 * Free array of mbuf's
 *
 * @param pkts
 *   The address of an array of *n* pointers to *rte_mbuf* structures
 *   which contain the packets to be freed.
 * @param n
 *   The number of packets to free.
 */
void pktmbuf_free_bulk(struct rte_mbuf *pkts[], unsigned int n);

/**
 * A macro to clear the header lengths in the given mbuf.
 *
 * @param m
 *   The packet mbuf.
 */
#define pktmbuf_clear_header_lengths(m) ((m)->tx_offload = 0)

/**
 * Allocate a multi segment mbuf
 *
 * @param mpool
 *    The memory pool to allocate from
 * @param size
 *    Number of bytes required
 * @return
 *    New mbuf or NULL if pool is empty.
 */
struct rte_mbuf *pktmbuf_allocseg(struct rte_mempool *mpool, vrfid_t vrf_id,
				  int space);
char *pktmbuf_append_alloc(struct rte_mbuf *m, uint16_t len);

/**
 * Moves the mdata metadata from one mbuf to another. This is intended for
 * when an mbuf with multiple references is copied due to needing to change it.
 *
 * The source mbuf has its metadata cleared. This is to ensure that there
 * is no issue with features such as which expect there to be
 * only one mbuf containing the same metadata. It is expected that the
 * source mbuf is subsequently freed, or no longer the first segment of the
 * packet.
 *
 * @param ms
 *   The packet mbuf where the mdata is to be moved from.
 * @param md
 *   The packet mbuf whose mdata is to be moved to.
 */
void pktmbuf_move_mdata(struct rte_mbuf *md, struct rte_mbuf *ms);

/**
 * Creates a copy of the given packet mbuf.
 *
 * Walks through all segments of the given packet mbuf, and for each of them:
 *  - Creates a new packet mbuf from the given pool.
 *  - Copy segment to newly created mbuf.
 * Then updates pkt_len and nb_segs of the new packet mbuf to match values
 * from the original packet mbuf.
 *
 * @param ms
 *   The packet mbuf to be copied.
 * @param mp
 *   The mempool from which the mbufs are allocated.
 * @return
 *   - The pointer to the new mbuf on success.
 *   - NULL if allocation fails.
 */
struct rte_mbuf *pktmbuf_copy(const struct rte_mbuf *ms,
			      struct rte_mempool *mp);

/**
 * Copy the mbuf metadata from one mbuf to another.
 *
 * @param ms
 *   The packet mbuf where the metadata is to be copied to.
 * @param ms
 *   The packet mbuf whose metadata is to be copied.
 */
void pktmbuf_copy_meta(struct rte_mbuf *md, const struct rte_mbuf *ms);

/**
 * Creates a "clone" of the given packet mbuf.
 *
 * Walks through all segments of the given packet mbuf, and for each of them:
 *  - Creates a new packet mbuf from the given pool.
 *  - Attaches newly created mbuf to the segment.
 * Then updates pkt_len and nb_segs of the "clone" packet mbuf to match values
 * from the original packet mbuf.
 *
 * @param md
 *   The packet mbuf to be cloned.
 * @param mp
 *   The mempool from which the "clone" mbufs are allocated.
 * @return
 *   - The pointer to the new "clone" mbuf on success.
 *   - NULL if allocation fails.
 */
static inline struct rte_mbuf *pktmbuf_clone(struct rte_mbuf *md,
					     struct rte_mempool *mp)
{
	struct rte_mbuf *m = rte_pktmbuf_clone(md, mp);

	if (likely(m != NULL)) {
		pktmbuf_mdata_clear_all(m);
		pktmbuf_set_vrf(m, pktmbuf_get_vrf(md));
	}

	return m;
}

/**
 * Prepare for changing a possibly shared mbuf.
 *
 * If wanting to change an mbuf this ensures that changes will not affect
 * those sharing the mbuf, if any. For a shared (or possibly shared) mbuf
 * it will either copy the requested number of bytes or all the buffers.
 * Note that if copying is done mdata will be moved to ensure it is
 * in the resulting mbuf.
 *
 * @param m
 *   The pointer to the packet mbuf pointer to be prepared for changing.
 *   If a new mbuf is allocated this will be changed to point to it.
 * @param header_len
 *   The header length that the change will be in, and so this length will
 *   be copied. If this is 0 then all segments will be copied.
 * @return
 *   0 on success or -errno on failure (currently -ENOMEM indicating an
 *   allocation failure). On failure the mbuf passed in will be unchanged.
 */
int pktmbuf_prepare_for_header_change(struct rte_mbuf **m, uint16_t header_len);

/**
 * Sets the ECN bit for IPv4/IPv6 packets.
 *
 * Sets the ECN congestion experienced bit in packet header
 * for IP packets (other unaffected).
 *
 * @param m
 *   The affected packet mbuf
 */
void pktmbuf_ecn_set_ce(struct rte_mbuf *m);

/**
 * Creates a copy of the given memory area into the packet mbuf.
 *
 * This function must get called on the head mbuf and never on a segment mbuf.
 *
 * @param m
 *   The destination packet mbuf.
 * @param src
 *   The source memory area to be copied.
 * @param offset
 *   The offset in the destination packet mbuf.
 * @param length
 *   The number of bytes to copy.
 */
void *memcpy_to_mbuf(struct rte_mbuf *m, const void *src, unsigned int offset,
		     unsigned int length);

/**
 * Creates a copy of the packet mbuf in the given memory area.
 *
 * This function must get called on the head mbuf and never on a segment mbuf.
 *
 * @param dest
 *   The destination memory area.
 * @param m
 *   The source packet mbuf to be copied.
 * @param offset
 *   The offset in the source packet mbuf.
 * @param length
 *   The number of bytes to copy.
 */
void *memcpy_from_mbuf(void *dest, struct rte_mbuf *m, unsigned int offset,
		       unsigned int length);

#define VLAN_PCP_SHIFT		13
#define VLAN_PCP_MASK		0xe000	/* Priority Code Point */
#define VLAN_VID_MASK		0x0fff	/* Vlan Identifier */
#define VLAN_DE_VID_MASK	0x1fff	/* VID + Drop Expected */
#define VLAN_N_VID		4096

/* Get to be sent VLAN tag, if not present return 0 */
static inline uint16_t pktmbuf_get_txvlanid(const struct rte_mbuf *m)
{
	if (m->ol_flags & PKT_TX_VLAN_PKT)
		return m->vlan_tci & VLAN_VID_MASK;
	else
		return 0;
}

/* Get to be sent VLAN tag, if not present return 0 */
static inline uint16_t pktmbuf_get_rxvlanid(const struct rte_mbuf *m)
{
	if (m->ol_flags & PKT_RX_VLAN)
		return m->vlan_tci & VLAN_VID_MASK;
	else
		return 0;
}

/* Get 802.1 transmit Priority Code Point */
static inline uint8_t pktmbuf_get_vlan_pcp(const struct rte_mbuf *m)
{
	return (m->vlan_tci & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;
}

/* Insert 802.1 Priority Code Point */
static inline void pktmbuf_set_vlan_pcp(struct rte_mbuf *m, uint8_t pcp)
{
	uint16_t tag;

	tag = m->vlan_tci;
	tag &= ~VLAN_PCP_MASK;
	tag |= pcp << VLAN_PCP_SHIFT;
	m->vlan_tci = tag;
}

static inline void pktmbuf_convert_rx_to_tx_vlan(struct rte_mbuf *m)
{
	m->ol_flags &= ~PKT_RX_VLAN;
	m->ol_flags |= PKT_TX_VLAN_PKT;
}

static inline void pktmbuf_clear_rx_vlan(struct rte_mbuf *m)
{
	m->ol_flags &= ~PKT_RX_VLAN;
	m->vlan_tci = 0;
}

static inline void pktmbuf_clear_tx_vlan(struct rte_mbuf *m)
{
	m->ol_flags &= ~PKT_TX_VLAN_PKT;
	m->vlan_tci = 0;
}

static inline uint16_t pktmbuf_get_tx_vlan_tci(const struct rte_mbuf *m)
{
	if (m->ol_flags & PKT_TX_VLAN_PKT)
		return m->vlan_tci;
	else
		return 0;
}

static inline uint16_t pktmbuf_get_rx_vlan_tci(const struct rte_mbuf *m)
{
	if (m->ol_flags & PKT_RX_VLAN)
		return m->vlan_tci;
	else
		return 0;
}

static inline void pktmbuf_set_vlan_and_pcp(struct rte_mbuf *m,
					    uint16_t tag, uint8_t pcp)
{
	tag &= ~VLAN_PCP_MASK;
	tag |= pcp << VLAN_PCP_SHIFT;
	m->vlan_tci = tag;
}

void pktmbuf_save_ifp(struct rte_mbuf *m, struct ifnet *ifp);
struct ifnet *pktmbuf_restore_ifp(struct rte_mbuf *m);

/**
 * Prepares a packet for a reswitch through the forwarding path after
 * decap
 *
 * Clears the necessary mbuf metadata and pktmbuf_mdata to allow the
 * packet to be sent through the L2 or L3 forwarding path again
 * following a decap.
 *
 * @param m
 *   The packet mbuf to be prepared for a reswitch.
 */
static inline void
pktmbuf_prepare_decap_reswitch(struct rte_mbuf *m)
{
	pktmbuf_clear_rx_vlan(m);

	pktmbuf_mdata_clear_variant(m);
}

/**
 * Prepares a packet for a sending viah the forwarding path after
 * encap
 *
 * Clears the necessary mbuf metadata and pktmbuf_mdata to allow the
 * packet to be sent through the L2 or L3 forwarding path again
 * following an encap.
 *
 * @param m
 *   The packet mbuf to be prepared for a reswitch.
 */
static inline void
pktmbuf_prepare_encap_out(struct rte_mbuf *m)
{
	pktmbuf_mdata_clear_variant(m);
}

int pktmbuf_tcp_header_is_usable(struct rte_mbuf *m);
int pktmbuf_udp_header_is_usable(struct rte_mbuf *m);

/*
 * Set the L2 type of a packet.
 *
 * @param m
 *   The packet mbuf to be prepared for a reswitch.
 * @param type
 *   The packet type so store in the mbuf. Default value is L2_PKT_UNICAST
 *   so does not need to be set to this value.
 */
static inline void
pkt_mbuf_set_l2_traffic_type(struct rte_mbuf *m, enum l2_packet_type type)
{
	struct pktmbuf_mdata *mdata;

	mdata = pktmbuf_mdata(m);
	mdata->md_l2_rcv_type = type;
	pktmbuf_mdata_set(m, PKT_MDATA_L2_RCV_TYPE);
}

static inline  enum l2_packet_type
pkt_mbuf_get_l2_traffic_type(struct rte_mbuf *m)
{
	if (pktmbuf_mdata_exists(m, PKT_MDATA_L2_RCV_TYPE)) {
		struct pktmbuf_mdata *mdata;

		mdata = pktmbuf_mdata(m);
		return mdata->md_l2_rcv_type;
	}
	return L2_PKT_UNICAST;
}

#endif /* PKTMBUF_INTERNAL_H */
