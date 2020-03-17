/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Library of functions for packet creation and handling
 */
#ifndef __DP_PKTMBUF_LIB_INTERNAL_H__
#define __DP_PKTMBUF_LIB_INTERNAL_H__

#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include "dp_test/dp_test_pktmbuf_lib.h"

/*
 * TCP flags not defined in netinet/tcp.h
 */
#if !defined TH_CWR
#define TH_CWR 0x80
#endif

#if !defined TH_ECE
#define TH_ECE 0x40
#endif

struct gre_base_hdr {
	uint16_t flags;
	uint16_t protocol;
};

#define ERSPAN_TYPEII	1

struct erspan_type2_hdr {
	uint32_t ver_sid;
	uint32_t idx_dir;
};

#define ETHER_TYPE_MPLS 0x8847
typedef uint32_t label_t;
#ifndef MPLS_LS_LABEL_SHIFT
# define MPLS_LS_LABEL_SHIFT     12
#endif

#ifndef MPLS_LS_S_SHIFT
# define MPLS_LS_S_SHIFT         8
#endif


/* default packet values */
#define DP_TEST_PAK_DEFAULT_TOS       0
#define DP_TEST_PAK_DEFAULT_FRAG_OFF  0
#define DP_TEST_PAK_DEFAULT_ID        0
#define DP_TEST_PAK_DEFAULT_TTL       64
#define DP_TEST_PAK_DEFAULT_IHL       5
#define DP_TEST_PAK_DEFAULT_UDP_SRC_PORT       21000
#define DP_TEST_PAK_DEFAULT_UDP_DST_PORT       21

/* Ethernet types */
#define DP_TEST_ET_BANYAN 0x0BAD /* Banyan Vines */
#define DP_TEST_ET_ATALK  0x809B /* Appletalk */
#define DP_TEST_ET_LLDP   0x88CC /* Link-Layer Discovery Protocol */

/**
 * Type to allow the user to define an mbuf alloc function.
 */
typedef struct rte_mbuf *
(*dp_test_mbuf_alloc_fn)(struct rte_mempool *mp);

/**
 * Set the mbuf alloc function to be used by the functions
 * in this file.
 *
 * @param fn     [in] The mbuf alloc function to use.
 */
void
dp_test_pktmbuf_set_alloc_fn(dp_test_mbuf_alloc_fn func);

/**
 * Set the mempool to be used by functions in this file
 * when allocating mbufs.
 *
 * @param mp [in] The mempool to use when allocating mbufs.
 */
void
dp_test_pktmbuf_set_mempool(struct rte_mempool *mp);

/**
 * Get the mempool thats currently being used for allocating mbufs.
 *
 * @return The mempool thats used when allocating mbufs.
 */
struct rte_mempool *
dp_test_pktmbuf_get_mempool(void);

/**
 * Check two byte arrays are equal.  Calls FAIL if not.
 */
bool
dp_test_check_bytes_equal(const char *descr, const uint8_t *expected,
			  const uint8_t *actual, size_t len);

/**
 * Create a chain of mbufs'
 *
 * @param n	     [in] Number of mbufs to create
 * @param plen	     [in] Pointer to size 'n' array of payload lengths
 * @param hlen	     [in] Layer 3 and 4 header size, to be added to first
 *			  payload length
 * @return  Pointer to mbuf chain if successful, else NULL
 *
 * The data_len of first mbuf will be be "hlen + len[0]".  data_len of
 * second mbuf will be "len[1]" etc. e.g.:
 *
 * int plen[] = {32, 60};
 * uint16_t hlen = sizeof(struct iphdr) + sizeof(udphdr);
 * pak = dp_test_create_mbuf_chain(ARRAY_SIZE(plen), plen, hlen);
 */
struct rte_mbuf *
dp_test_create_mbuf_chain(int n, const int *plen, uint16_t hlen);

void
dp_test_pktmbuf_dmac_get(struct rte_mbuf *m, char *dmac);

void
dp_test_pktmbuf_smac_get(struct rte_mbuf *m, char *smac);

void
dp_test_pktmbuf_dmac_set(struct rte_mbuf *m, const char *mac_str);

void
dp_test_pktmbuf_smac_set(struct rte_mbuf *m, const char *mac_str);


struct rte_ether_hdr *
dp_test_pktmbuf_eth_prepend(struct rte_mbuf *m, const char *d_addr,
			    const char *s_addr, uint16_t ether_type);

/**
 * Replace m_target ethernet header with ethernet header from m_origin
 * If m_target l2_len is 0, prepend 14 bytes.
 *
 * @param m_origin [in] Pointer to packet origin mbuf
 * @param m_target [in] Pointer to packet target mbuf
 *
 */
void
dp_test_pktmbuf_eth_hdr_replace(struct rte_mbuf *m_target,
				struct rte_mbuf *m_origin);

/**
 * Initialize IPv4 header. Assumes m->data_off is set to l2 header,
 * and m->l2_len is initialized.  Fails if there is not space for the
 * IP header in the first mbuf.
 *
 * @param m   [in]  Pointer to packet mbuf
 * @param src [in]  Source address string, e.g. "10.0.1.0"
 * @param dst [in]  Dest address string
 * @param protocol [in]	 Protocol, e.g. IPPROTO_UDP
 *
 * @return  Pointer to IP header if successful, else NULL
 */
struct iphdr *
dp_test_pktmbuf_ip_init(struct rte_mbuf *m,
			const char *src,
			const char *dst,
			uint8_t protocol);

struct iphdr *
dp_test_pktmbuf_ip_prepend(struct rte_mbuf *m, const char *src,
			   const char *dst, uint8_t protocol);

/**
 * Initialize IPv6 header. Assumes m->data_off is set to l2 header,
 * and m->l2_len is initialized.  Fails if there is not space for the
 * IPv6 header in the first mbuf.
 *
 * @param m [in]   Pointer to packet mbuf
 * @param src [in] Source address string, e.g. "2001:101:8::1"
 * @param dst [in] Dest address string
 * @param protocol [in]	 Protocol, e.g. IPPROTO_UDP
 *
 * @return  Pointer to IPv6 header if successful, else NULL
 */
struct ip6_hdr *
dp_test_pktmbuf_ip6_init(struct rte_mbuf *m,
			 const char *src,
			 const char *dst,
			 uint8_t protocol);

/**
 * Calculate IPv4 ICMP checksum.
 *
 * The ICMP checksum must be set to 0 in the packet by the caller. The
 * ICMP header must be in the first mbuf.
 *
 * @param m [in]      Pointer to the mbuf chain
 * @param l4_hdr [in] Pointer to the beginning of the ICMP header
 * @return
 *   The complemented checksum to set in the IPv4 ICMP header
 */
uint16_t
dp_test_ipv4_icmp_cksum(const struct rte_mbuf *m, const void *l4_hdr);

/**
 * Calculate IPv6 ICMP checksum.
 *
 * The ICMP checksum must be set to 0 in the packet by the caller. The
 * ICMP header must be in the first mbuf.
 *
 * @param m [in]      Pointer to the mbuf chain
 * @param ip6 [in]    Pointer to the contiguous IPv6 header.
 * @param l4_hdr [in] Pointer to the beginning of the ICMP header
 * @return
 *   The complemented checksum to set in the IPv6 ICMP header
 */
uint16_t
dp_test_ipv6_icmp_cksum(const struct rte_mbuf *m, const struct ip6_hdr *ip6,
			const void *l4_hdr);

/**
 * Initialize UDP header.  Assumes l2 and l3 headers already setup.
 * Assumes payload is already setup.  If not, then UDP checksum would
 * need recalculated.
 *
 * @param m	[in] Pointer to packet mbuf
 * @param sport [in] Source port
 * @param dport [in] Dest port
 * @param is_v4 [in] true if IPv4 packet, false if IPv6
 *
 * @return  Pointer to UDP header if successful, else NULL
 */
struct udphdr *
dp_test_pktmbuf_udp_init(struct rte_mbuf *m, uint16_t sport,
			 uint16_t dport, bool is_v4);

struct udphdr *
dp_test_pktmbuf_udp_prepend(struct rte_mbuf *m, uint16_t sport,
			    uint16_t dport, bool is_v4);
struct udphdr *
dp_test_pktmbuf_udp_prepend_no_crc(struct rte_mbuf *m, uint16_t sport,
				   uint16_t dport, bool is_v4);
/**
 * Initialize TCP header.  Assumes l2 and l3 headers already setup.
 * Assumes payload is already setup.  If not, then TCP checksum would
 * need recalculated.
 *
 * @param m     [in]  Pointer to packet mbuf
 * @param sport [in]  TCP source port
 * @param dport [in]  TCP dest port
 * @param flags [in]  TCP header flags
 * @param seq   [in]  TCP sequence number
 * @param ack   [in]  TCP acknowledgment number
 * @param win   [in]  TCP window value (host order)
 * @param opts  [in]  Byte array of TCP options.  See below.
 * @param is_v4 [in]  true if IPv4, false if IPv6
 *
 * @return  Pointer to TCP header if successful, else NULL
 *
 * TCP options - type (1 byte), length (1 byte), value (length-2 bytes), e.g.
 *
 * uint8_t opts[] = {
 *     2, 4, 0x18, 0x02,
 *     1,
 *     3, 3, 1,
 *     0
 * };
 *
 * The options list is terminated when 'type' is 0 (EOL).  Note that when
 * 'type' is 1 (NOP) then there is no length value.  This is commonly used to
 * separate options in a header.
 */
struct tcphdr *
dp_test_pktmbuf_tcp_init(struct rte_mbuf *m,
			 uint16_t sport, uint16_t dport, uint8_t flags,
			 uint32_t seq, uint32_t ack, uint16_t win,
			 const uint8_t *opts, bool is_v4);

/*
 * Conversion of ICMP header data to uint32_t and back.
 */
#define DPT_ICMP_ECHO_DATA(_id, _seq) ((_seq) << 16 | (_id))
#define DPT_ICMP_ECHO_ID(data) ((data) & 0xFFFF)
#define DPT_ICMP_ECHO_SEQ(data) ((data) >> 16)
#define DPT_ICMP_FRAG_DATA(_mtu)      ((_mtu) << 16)
#define DPT_ICMP_UNREACH_DATA(_gw)    (_gw)

/**
 * Initialize ICMP IPv4 header.	 Assumes l2 and l3 headers already
 * setup.
 *
 * @param m [in]     Pointer to packet mbuf
 * @param icmp_type [in] ICMP type
 * @param icmp_code [in] ICMP code
 * @param data      [in] ICMP data in host byte order
 *
 * @return  Pointer to ICMP header if successful, else NULL
 *
 * Note, Conversion of 'data' parameter to network byte order occurs in
 * dp_test_pktmbuf_icmp_init for types ICMP_ECHO, ICMP_ECHOREPLY,
 * ICMP_REDIRECT, and ICMP_DEST_UNREACH only.
 */
struct icmphdr *
dp_test_pktmbuf_icmp_init(struct rte_mbuf *m, uint8_t icmp_type,
			  uint8_t icmp_code, uint32_t data);


/*
 * Conversion of ICMP header data to a uint32_t in host byte order.
 */
#define DPT_ICMP6_ECHO_DATA(_id, _seq)  ((_seq) << 16 | (_id))

/**
 * Initialize ICMP IPv6 header.	 Assumes l2 and l3 headers already
 * setup.
 *
 * @param m [in]     Pointer to packet mbuf
 * @param icmp6_type [in] IPv6 ICMP type
 * @param icmp6_code [in] IPv6 ICMP code
 * @param data [in] IPv6 ICMP data
 *
 * @return  Pointer to ICMP header if successful, else NULL
 */
struct icmp6_hdr *
dp_test_pktmbuf_icmp6_init(struct rte_mbuf *m, uint8_t icmp6_type,
			   uint8_t icmp6_code, uint32_t data);

/**
 * Initialize GRE header.  Assumes l2 and l3 headers already setup.
 *
 * @param  m    [in]  Pointer to packet mbuf
 * @param  prot [in]  Protocol in host byte order
 * @param  key  [in]  Key in host byte order
 * @param  seq  [in]  Sequence number in host byte order
 * @return Pointer to GRE header if successful, else NULL
 */
struct gre_base_hdr *
dp_test_pktmbuf_gre_init(struct rte_mbuf *m, uint16_t prot, uint32_t key,
			 uint32_t seq);

struct gre_base_hdr *
dp_test_pktmbuf_gre_prepend(struct rte_mbuf *m, uint16_t prot, uint32_t key);

void
dp_test_pktmbuf_gre_adj(struct rte_mbuf *m);

struct rte_vxlan_hdr *
dp_test_pktmbuf_vxlan_init(struct rte_mbuf *m, uint32_t vx_flags,
			   uint32_t vx_vni);

struct rte_vxlan_hdr *
dp_test_pktmbuf_vxlan_prepend(struct rte_mbuf *m, uint32_t vx_flags,
			      uint32_t vx_vni);

/**
 * Initialize packet payload.  Handles chained mbufs'.
 *
 * @param m	  [in] Pointer to packet mbuf
 * @param off	  [in] Offset, relative to m->data_off, of where to write
 *		       the payload to. Typically this will be the sum of
 *		       the l2, l3, and l4 header lengths.
 * @param payload [in] Payload to write to the packet.	May be NULL, in
 *		       which case a test pattern is used.
 * @param plen	  [in] Length of payload
 * @return Number of bytes written
 */
uint16_t
dp_test_pktmbuf_payload_init(struct rte_mbuf *m, uint16_t off,
			     const char *payload, uint16_t plen);


/**
 * Wrapper for inet_pton() with error handling.
 *
 * @param af	  [in] Address family
 * @param src	  [in] String representation of IP address.
 * @param dest    [in] Pointer to buffer to write IP address.
 * @return        Return value of inet_pton().
 */
int
dp_test_inet_pton(int af, const char *src, void *dst);

/**
 * Create and initialise an L2 packet
 *
 * @param d_addr     [in] Dest mac string, e.g. "aa:bb:cc:dd:ee:ff"
 * @param s_addr     [in] Source mac string
 * @param ether_type [in] Ethernet type (host order), may be 0
 * @param n	     [in] Number of mbufs
 * @param len	     [in] Array of per-mbuf payload lengths
 *
 * @return pak	      Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_l2_pak(const char *d_addr,
		      const char *s_addr,
		      uint16_t ether_type,
		      int n, const int *len);

/**
 * Initialize packet to emulate reception on vlan.
 *
 * @param m          [in] Pointer to packet mbuf
 * @param vlan       [in] vlan id
 *
 */
void
dp_test_pktmbuf_vlan_init(struct rte_mbuf *m,
			  uint16_t vlan);

void
dp_test_pktmbuf_vlan_clear(struct rte_mbuf *m);

/**
 * Create and initialise an  802.1Q tagged packet
 *
 * @param d_addr     [in] Dest mac string, e.g. "aa:bb:cc:dd:ee:ff"
 * @param s_addr     [in] Source mac string
 * @param vlan_id    [in] Vlan id for the packet
 * @param vlan_ether_type [in] Vlan header ether type
 * @param payload_ether_type [in] Next ether type for the packet
 * @param n          [in] Number of mbufs
 * @param len        [in] Array of per-mbuf payload lengths
 *
 * @return pak       Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_8021q_l2_pak(const char *d_addr,
			    const char *s_addr,
			    uint16_t vlan_id,
			    uint16_t vlan_ether_type,
			    uint16_t payload_ether_type,
			    int n, const int *len);

/**
 * Prepend a 802.1Q header to a packet
 *
 * @param pak        [in] Pointer to packet
 * @param vlan_id    [in] Vlan id for the packet
 * @param vlan_ether_type [in] Vlan header ether type
 * @param payload_ether_type [in] Next ether type for the packet
 */
void
dp_test_insert_8021q_hdr(struct rte_mbuf *pak, uint16_t vlan_id,
			 uint16_t vlan_ether_type,
			 uint16_t payload_ether_type);

/**
 * Create and initialise an IPv4 ICMP packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param icmp_type [in]  ICMP type
 * @param icmp_code [in]  ICMP code
 * @param data      [in]  ICMP header data
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 * @param payload [in] Payload to copy into packet, or NULL to fill
 *                     with default pattern
 * @param ipp   [out] pointer to the struct iphdr within the packet
 * @param icmpp [out] pointer to the struct icmphdr within the packet
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 *
 * Note, Conversion of 'data' parameter to network byte order occurs in
 * dp_test_pktmbuf_icmp_init for types ICMP_ECHO, ICMP_ECHOREPLY,
 * ICMP_REDIRECT, and ICMP_DEST_UNREACH only.
 */
struct rte_mbuf *
dp_test_create_icmp_ipv4_pak(const char *saddr, const char *daddr,
			     uint8_t icmp_type, uint8_t icmp_code,
			     uint32_t data, int n, const int *len,
			     const void *payload,
			     struct iphdr **ipp, struct icmphdr **icmpp);

/**
 * Create and initialise an IPv6 ICMP packet
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param icmp_type [in]  ICMPv6 type
 * @param icmp_code [in]  ICMPv6 code
 * @param data [in]  ICMPv6 data in host byte order
 * @param n	[in]  Number of mbufs
 * @param len	[in]  Array of 'n' per-mbuf payload lengths
 * @param payload [in] Payload to copy into packet, or NULL to fill
 *                     with default pattern
 * @param ipp   [out] pointer to the struct iphdr within the packet
 * @param icmpp [out] pointer to the struct icmphdr within the packet
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_icmp_ipv6_pak(const char *saddr, const char *daddr,
			     uint8_t icmp_type, uint8_t icmp_code,
			     uint32_t data, int n, const int *len,
			     const void *payload, struct ip6_hdr **ip6p,
			     struct icmp6_hdr **icmp6p);

/**
 * Create and initialise an IPv4 GRE packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 * @param gre_prot [in]  GRE payload protocol in host byte order
 * @param gre_key  [in]  GRE key in host byte order
 * @param gre_seq  [in]  GRE sequence number in host byte order
 * @param payload [out]  Pointer to start of payload of GRE packet
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_gre_ipv4_pak(const char *saddr, const char *daddr,
			    int n, const int *len, uint16_t gre_prot,
			    uint32_t gre_key, uint32_t gre_seq,
			    void **payload);

/**
 * Create and initialise an IPv6 GRE packet
 *
 * @param saddr [in]  Source address string, e.g. "10:0:1:0"
 * @param daddr [in]  Dest address string
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 * @param gre_prot [in]  GRE payload protocol in host byte order
 * @param gre_key  [in]  GRE key in host byte order
 * @param gre_seq  [in]  GRE sequence number in host byte order
 * @param payload [out]  Pointer to start of payload of GRE packet
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_gre_ipv6_pak(const char *saddr, const char *daddr,
			    int n, const int *len, uint16_t gre_prot,
			    uint32_t gre_key, uint32_t gre_seq,
			    void **payload);

/**
 * Create and initialise an IPv4 PPTP packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 * @param gre_cid [in]  PPTP call id in host byte order
 * @param gre_seq  [in]  PPTP sequence number  in host byte order
 * @param gre_ack  [in]  PPTP acknowledgment in host byte order
 * @param payload [out]  Pointer to start of payload of GRE packet
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_gre_pptp_ipv4_pak(const char *saddr, const char *daddr,
			    int n, const int *len, uint16_t gre_cid,
			    uint32_t gre_seq, uint32_t gre_ack,
			    void **payload);

/**
 * Create and initialise an IPv4 ERSPAN packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 * @param gre_prot [in]  ERSPAN payload protocol in host byte order
 * @param erspanid [in]  ERSPAN session ID
 * @param srcidx [in]  ERSPAN source interface index
 * @param vlan [in]  ERSPAN payload vlan ID
 * @param dir [in]  ERSPAN direction
 * @param payload [out]  Pointer to start of payload of ERSPAN packet
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_erspan_ipv4_pak(const char *saddr, const char *daddr,
			       const int *len, uint16_t gre_prot,
			       uint16_t erspanid, uint8_t srcidx,
			       uint16_t vlan, uint8_t dir, void **payload);

/**
 * Create and initialise an MPLS packet
 *
 * @param payload_pak [in]  mbuf containing payload pak
 * @param nlabels     [in]  number of mpls labels
 * @param labels      [in]  array of labels
 * @oaram payload     [in]  L3 pak to encapsulate
 * @return pak        Pointer to mbuf if successful, else NULL
 */
#define dp_test_create_mpls_pak(nlabels, labels, mpls_ttl, payload)	\
	_dp_test_create_mpls_pak(nlabels, labels, mpls_ttl, payload)

struct rte_mbuf *
_dp_test_create_mpls_pak(uint8_t nlabels,
			 label_t *labels, uint8_t mpls_ttl[],
			 const struct rte_mbuf *payload);

/**
 * Get the payload of an MPLS packet
 *
 * @param m [in]  Pointer to mbuf
 *
 * @return payload	Pointer to payload
 */
void *
dp_test_get_mpls_pak_payload(const struct rte_mbuf *m);

/*
 * Create a new pak and copy the contents of m_origin to it.
 *
 * @param m_origin	     [in] The pak to copy from.
 *
 * @return  A pointer to the new pak.
 */
struct rte_mbuf *
dp_test_cp_pak(struct rte_mbuf *m_origin);

/**
 * Copy the entire packet from an mbuf chain to a contiguous buffer.
 *
 * @param m	[in] The mbuf chain to copy from.
 * @param buf	[in] The buffer to copy to.  If NULL, a buffer is malloced
 *
 * @return The buffer the packet has been copied to.  If the input
 *         'buf' parameter is NULL then the returned value should be
 *         free'd when finished with.
 */
char *
dp_test_cp_mbuf_to_buf(struct rte_mbuf *m, char *buf);

/**
 * Is this IPv6 protocol a non-fragmentable extension header as
 * understood by vyatta-dataplane?
 *
 * @param pcol	[in]  Protocol
 *
 * @return true if this is a non-fragmentable extension
 */
bool
dp_test_non_frag_ext_hdr(uint8_t pcol);

/**
 * Set IPv6 non-fragmentable extension header length
 *
 * @param ip6e	[in]  Pointer to generic ext hdr struct
 * @param pcol	[in]  Protocol
 * @param len	[in]  Length in bytes
 *
 * @return true if successful
 */
bool
dp_test_non_frag_ext_hdr_set_len(struct ip6_ext *ip6e, uint8_t pcol,
				 uint8_t len);

/**
 * Return the length in bytes of an IPv6 non-fragmentable extension
 * header.  Input parameters are the protocol and length fields from
 * the ext hdr.
 *
 * @param pcol	[in]  Extension hdr protocol value
 * @param ip6e_len [in]  Length value from the extension hdr
 *
 * @return Length of ext hdr in bytes
 */
uint8_t
dp_test_non_frag_ext_hdr_get_len(uint8_t pcol, uint8_t ip6e_len);

/**
 * Returns pointer to last non-fragmentable extension header, or NULL
 * if no ext hdrs.  *l3_len is set to the sum of the IPv6 hdr, non
 * frag ext hfrs and frag hdr.  i.e. a value such that l3_len can be
 * used to get the UCP/TCP/ICMP hdr.
 *
 * @param l3_len [in/out]  Pointer to l3_len. Updated with the length of
 *                         the IPv6 header and all extension headers.
 * @param last_pcol [in/out] The protocol type of the last extension header
 *                           Will return the one before the TCP, UDP or ICMP
 *                           hdr.
 *
 * @return Pointer to last extension header
 */
struct ip6_ext *
dp_test_ipv6_scan_non_frag_hdrs(struct rte_mbuf *m, uint8_t *l3_len,
				uint8_t *last_pcol);
/**
 * Fragment an IPv6 packet, and store resulting fragments in the
 * pkts_out array.  Returns number of fragments created on success, <
 * 0 on error.  Handles packets with or without an l2
 * header. pkt_in->l3_len must be set.
 *
 * @param pkt_in	[in] The mbuf chain to copy from.
 * @param pkts_out	[out] Pointer to array to store fragments in
 * @param nb_pkts_out	[in] Size of pkts_out array
 * @param frag_sizes	[in] L3 size of each fragment
 * @param fh_id		[in] Fragment header ID field
 *
 * @return  nfrags Number of fragments written to array if successful,
 *          else < 0 if an error occurred.
 */
int
dp_test_ipv6_fragment_packet(struct rte_mbuf *pkt_in,
			     struct rte_mbuf **pkts_out,
			     uint16_t nb_pkts_out,
			     const uint16_t *frag_size,
			     uint32_t fh_id);

/**
 * Fragment an IPv4 packet, and store resulting fragments in the
 * pkts_out array.  Returns number of fragments created on success, <
 * 0 on error.  Handles packets with or without an l2
 * header. pkt_in->l3_len must be set.
 *
 * @param pkt_in	[in] The mbuf chain to copy from.
 * @param pkts_out	[out] Pointer to array to store fragments in
 * @param nb_pkts_out	[in] Size of pkts_out array
 * @param frag_sizes	[in] L3 size of each fragment
 * @param fh_id		[in] Fragment header ID field
 *
 * @return  nfrags Number of fragments written to array if successful,
 *          else < 0 if an error occurred.
 */
int
dp_test_ipv4_fragment_packet(struct rte_mbuf *pkt_in,
			     struct rte_mbuf **pkts_out,
			     uint16_t nb_pkts_out,
			     const uint16_t *frag_sizes,
			     uint32_t fh_id);

/**
 * Insert 'len' bytes into a packet at 'offs' bytes from start of
 * packet. Updates data_len and pkt_len.  Currently only handles simple
 * case of inserting bytes into first mbuf.
 *
 * @param m	[in] The mbuf chain to operate on.
 * @param offs	[in] Offset from start of pkt to add the space
 * @param len	[in] Number of bytes to insert
 *
 * @return Pointer to the inserted space if successful, else NULL.
 */
char *
dp_test_pktmbuf_insert(struct rte_mbuf *m, uint16_t offs, uint16_t len);

/**
 * Append an IPv6 non-fragmentable extension header to after the last
 * non-frag ext hdr.
 */
struct ip6_ext *
dp_test_ipv6_append_non_frag_ext_hdr(struct rte_mbuf *m,
				     uint8_t proto, uint16_t len);

/*
 * API to allow us to get a given field within the ip / ip6 header in a buffer.
 */
enum dp_test_pak_field_ip {
	DP_TEST_GET_SRC_ADDR,
	DP_TEST_GET_DST_ADDR,
	DP_TEST_GET_TOS,
	DP_TEST_GET_PROTOCOL,
};

void
dp_test_get_pak_eth_ip_field_addr(const struct rte_mbuf *m,
				  enum dp_test_pak_field_ip field,
				  struct dp_test_addr *ip_addr);

void
dp_test_get_pak_eth_ip_field_u8(const struct rte_mbuf *m,
				enum dp_test_pak_field_ip field,
				uint8_t *val);

void
dp_test_get_pak_eth_ip_field_u32(const struct rte_mbuf *m,
				 enum dp_test_pak_field_ip field,
				 uint32_t *val);

void
dp_test_ipv4_remark_tos(struct rte_mbuf *m, unsigned char tos);

/*
 * Create a packet from an array of data
 *
 * Assumes that data points to an array of bytes containing a complete packet,
 * starting with an ethernet header.

 * 'len' is exactly the size of the returned mbuf.
 *
 * If d_addr and s_addr are non-NULL then the new packets eth header
 * destination and source MAC addresses are overwritten from these.  If the
 * ether_type is not zero, then that is also written.
 */
struct rte_mbuf *
dp_test_create_l2_pak_from_data(const char *d_addr, const char *s_addr,
				uint16_t ether_type, char *data, int len);

/*
 * Create a packet from a file.
 *
 * If d_addr and s_addr are non-NULL then the new packets eth header
 * destination and source MAC addresses are overwritten from these.  If the
 * ether_type is not zero, then that is also written.
 *
 * Supports two file types: Wireshark offset hext text and Wireshark hex
 * stream.
 *
 * Note, the dp_test packet dump may be cut'n'pasted to a file, and read
 * in as a Wireshark offset hex text file.
 */
enum dp_test_pak_filetype {
	DP_TEST_FILE_WS_HEX,	/* Wireshark hex stream */
	DP_TEST_FILE_WS_OHT	/* Wireshark offset hex text */
};

struct rte_mbuf *
dp_test_create_l2_pak_from_file(const char *d_addr, const char *s_addr,
				uint16_t etype, const char *filename,
				enum dp_test_pak_filetype filetype);

/*
 * Returns true if the given mbuf seems to have a version number of v4.
 */
bool dp_test_mbuf_is_ipv4(struct rte_mbuf *m);

/*
 * Returns true if the given mbuf seems to have a version number of v6.
 */
bool dp_test_mbuf_is_ipv6(struct rte_mbuf *m);

/*
 * Returns true if mbuf ethertype is v4 or v6.
 */
bool
dp_test_mbuf_ethertype_is_ip(struct rte_mbuf *m);

/*
 * Returns true if mbuf ethertype is MPLS
 */
bool
dp_test_mbuf_ethertype_is_mpls(struct rte_mbuf *m);

/*
 * sha: Sender Hardware Address
 * tha: Target Hardware Address
 * spa: Sender Protocol Address
 * tpa: Target Protocol Address
 */
struct rte_mbuf *
dp_test_create_arp_pak(ushort op, const char *s_mac, const char *d_mac,
		       const char *sha, const char *tha,
		       const char *spa_addr, const char *tpa_addr,
		       uint16_t vlan_id);

#endif /* __DP_PKTMBUF_LIB_INTERNAL_H__ */
