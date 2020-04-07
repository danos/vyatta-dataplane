/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dp_pktmbuf_lib.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <util.h>
#include <ip_funcs.h>

#include "compiler.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "in_cksum.h"
#include "netinet6/ip6_funcs.h"

#define DP_PKTMBUF_IPV6_FINFO	0x0fffffff	/* flow info mask (28 bits) */

#ifdef DP_PKTMBUF_DEBUG
#define DP_PKTMBUF_DBG(ARGS...) printf(ARGS)
#else
#define DP_PKTMBUF_DBG(ARGS...) do {} while (0)
#endif


#ifdef DP_PKTMBUF_DEBUG
static char byte_str[120];

static char *
byte_string(uint8_t *bytes, int n)
{
	int slen = sizeof(byte_str) - 1;
	char *str = byte_str;
	if (!str)
		return NULL;

	int i, len = 0;
	for (i = 0; i < n; i++) {
		len += snprintf(str+len, slen-len, "%02X%s",
				bytes[i], i+1 < n ? "-":"");
	}
	return str;
}
#endif

#define DBG_CTXT_BEFORE 8
#define DBG_CTXT_AFTER 8

bool
dp_test_check_bytes_equal(const char *descr __unused, const uint8_t *expected,
			  const uint8_t *actual, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {

		if (expected[i] != actual[i]) {
#ifdef DP_PKTMBUF_DEBUG
			size_t n, start;
			DP_PKTMBUF_DBG("%s, differ at pos %zu\n",
				       descr, i);
			n = i > DBG_CTXT_BEFORE ? DBG_CTXT_BEFORE : i;
			start = i - n;
			n += (i + DBG_CTXT_AFTER < len ?
			      DBG_CTXT_AFTER : len - i);

			DP_PKTMBUF_DBG("  Expected[%zu]: %s\n",
				       start,
				       byte_string(expected+start, n));
			DP_PKTMBUF_DBG("  Actual[%zu]:   %s\n",
				       start,
				       byte_string(actual+start, n));
#endif
			return false;
		}
	}

	return true;
}

/*
 * Memory pool from which all packets are allocated. Can be changed as and
 * when required.
 */
static struct rte_mempool *dp_test_mempool;

void
dp_test_pktmbuf_set_mempool(struct rte_mempool *mp)
{
	dp_test_mempool = mp;
}

struct rte_mempool *
dp_test_pktmbuf_get_mempool(void)
{
	return dp_test_mempool;
}

static dp_test_mbuf_alloc_fn dp_test_alloc_mbuf_fn;

void
dp_test_pktmbuf_set_alloc_fn(dp_test_mbuf_alloc_fn func)
{
	dp_test_alloc_mbuf_fn = func;
}

/**
 * Allocate a mbuf.
 */
static struct rte_mbuf *
dp_test_pktmbuf_alloc(struct rte_mempool *mp)
{
	return dp_test_alloc_mbuf_fn(mp);
}

/**
 * Create a chain of mbufs'
 *
 * @param n          [in] Number of mbufs to create
 * @param plen       [in] Pointer to size 'n' array of payload lengths
 * @param hlen       [in] Layer 3 and 4 header size, to be added to first
 *                        payload length
 *
 * The data_len of first mbuf will be be "hlen + len[0]".  data_len of
 * second mbuf will be "len[1]" etc. e.g.:
 *
 * int plen[] = {32, 60};
 * uint16_t hlen = sizeof(struct iphdr) + sizeof(udphdr);
 * pak = dp_test_create_mbuf_chain(ARRAY_SIZE(plen), plen, hlen);
 */
struct rte_mbuf *
dp_test_create_mbuf_chain(int n, const int *plen, uint16_t hlen)
{
	int seg;
	struct rte_mbuf *prev = NULL, *first = NULL;

	for (seg = 0; seg < n; seg++) {
		struct rte_mbuf *m;

		m = dp_test_pktmbuf_alloc(dp_test_mempool);
		if (!m) {
			return NULL;
		}

		if (!rte_pktmbuf_append(m, hlen + plen[seg])) {
			rte_pktmbuf_free(m);
			DP_PKTMBUF_DBG("Failed to append space to seg\n");
			return NULL;
		}
		if (!prev) {
			first = m;
			hlen = 0;
		} else {
			prev->next = m;
			first->nb_segs += 1;
			first->pkt_len += m->data_len;
		}
		prev = m;
	}
	return first;
}

static void
dp_test_pktmbuf_mac_set(struct rte_mbuf *m, const char *mac_str, bool src_mac)
{
	struct ether_addr *mac_field;
	struct ether_hdr *eth;

	assert(m);
	assert(mac_str);
	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	if (src_mac)
		mac_field = &eth->s_addr;
	else
		mac_field = &eth->d_addr;

	if (ether_aton_r(mac_str, mac_field) == NULL)
		assert(false);
}

void
dp_test_pktmbuf_smac_set(struct rte_mbuf *m, const char *smac_str)
{
	dp_test_pktmbuf_mac_set(m, smac_str, true);
}

void
dp_test_pktmbuf_dmac_set(struct rte_mbuf *m, const char *dmac_str)
{
	dp_test_pktmbuf_mac_set(m, dmac_str, false);
}

static void
dp_test_pktmbuf_mac_get(struct rte_mbuf *m, char *mac, bool src_mac)
{
	struct ether_addr *mac_field;
	struct ether_hdr *eth;

	assert(m);
	assert(mac);
	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	if (src_mac)
		mac_field = &eth->s_addr;
	else
		mac_field = &eth->d_addr;

	if (ether_ntoa_r(mac_field, mac) == NULL)
		assert(false);
}

void
dp_test_pktmbuf_smac_get(struct rte_mbuf *m, char *smac_str)
{
	dp_test_pktmbuf_mac_get(m, smac_str, true);
}

void
dp_test_pktmbuf_dmac_get(struct rte_mbuf *m, char *dmac_str)
{
	dp_test_pktmbuf_mac_get(m, dmac_str, false);
}

/**
 * Initialize ethernet hdr.  If l2_len is 0, prepend 14 bytes and set
 * m->l2_len to 14.
 *
 * @param m          [in] Pointer to packet mbuf
 * @param d_addr     [in] Pointer to dest mac, may be NULL
 * @param s_addr     [in] Pointer to src mac, may be NULL
 * @param ether_type [in] Ethernet type (host order), may be 0
 *
 * @return  Pointer to eth header if successful, else NULL
 */
static struct ether_hdr *
dp_test_pktmbuf_eth(struct rte_mbuf *m,
		    const char *d_addr,
		    const char *s_addr,
		    uint16_t ether_type,
		    bool prepend)
{
	struct ether_hdr *eth;

	if (m->l2_len == 0 || prepend) {
		m->l2_len = sizeof(struct ether_hdr);
		eth = (struct ether_hdr *)rte_pktmbuf_prepend(m, m->l2_len);
		if (!eth) {
			DP_PKTMBUF_DBG("Failed to prepend eth header\n");
			return NULL;
		}
	} else {
		eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	}

	eth->ether_type = htons(ether_type);

	if (!d_addr)
		d_addr = "00:00:00:00:00:00";
	if (ether_aton_r(d_addr, &eth->d_addr) == NULL)
		assert(false);
	if (!s_addr)
		s_addr = "00:00:00:00:00:00";
	if (ether_aton_r(s_addr, &eth->s_addr) == NULL)
		assert(false);

	return eth;
}

struct ether_hdr *
dp_test_pktmbuf_eth_init(struct rte_mbuf *m, const char *d_addr,
			 const char *s_addr, uint16_t ether_type)
{
	return dp_test_pktmbuf_eth(m, d_addr, s_addr, ether_type, false);
}

struct ether_hdr *
dp_test_pktmbuf_eth_prepend(struct rte_mbuf *m, const char *d_addr,
			    const char *s_addr, uint16_t ether_type)
{
	return dp_test_pktmbuf_eth(m, d_addr, s_addr, ether_type, true);
}

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
				struct rte_mbuf *m_origin)
{
	struct ether_hdr *eth_target, *eth_origin;

	assert(m_target);
	assert(m_origin);
	if (m_target->l2_len == 0) {
		m_target->l2_len = sizeof(struct ether_hdr);
		eth_target = (struct ether_hdr *)
			rte_pktmbuf_prepend(m_target, m_target->l2_len);
		if (!eth_target) {
			DP_PKTMBUF_DBG("Failed to replace eth header\n");
			return;
		}
	}
	assert(m_origin->l2_len >= sizeof(struct ether_hdr));
	eth_target = rte_pktmbuf_mtod(m_target, struct ether_hdr *);
	eth_origin = rte_pktmbuf_mtod(m_origin, struct ether_hdr *);
	memcpy(eth_target, eth_origin, sizeof(struct ether_hdr));
	m_origin->l2_len = sizeof(struct ether_hdr);
}

/**
 * Initialize IPv4 header. Assumes m->data_off is set to l2 header,
 * and m->l2_len is initialized.  Fails if there is not space for the
 * IP header in the first mbuf.
 *
 * @param m   [in]  Pointer to packet mbuf
 * @param src [in]  Source address string, e.g. "10.0.1.0"
 * @param dst [in]  Dest address string
 * @param protocol [in]  Protocol, e.g. IPPROTO_UDP
 *
 * @return  Pointer to IP header if successful, else NULL
 */
static struct iphdr *
dp_test_pktmbuf_ip(struct rte_mbuf *m, const char *src, const char *dst,
		   uint8_t protocol, bool prepend)
{
	struct iphdr *ip;
	uint32_t addr;
	uint16_t hlen;

	if (prepend) {
		ip = (struct iphdr *)
			rte_pktmbuf_prepend(m, sizeof(struct iphdr));
		if (!ip) {
			DP_PKTMBUF_DBG("Failed to prepend ip header\n");
			return NULL;
		}
		m->l2_len = 0;
		m->l3_len = sizeof(struct iphdr);
	} else {
		m->l3_len = sizeof(struct iphdr);
		ip = dp_pktmbuf_mtol3(m, struct iphdr *);
	}

	hlen = m->l2_len + sizeof(*ip);

	/* Is there room for IP hdr in first mbuf? */
	if (hlen > m->data_len) {
		DP_PKTMBUF_DBG("Not enough space for IP header");
		DP_PKTMBUF_DBG("Required >= %d, actual %d\n",
			       hlen, m->data_len);
		return NULL;
	}

	ip->ihl = DP_TEST_PAK_DEFAULT_IHL;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(m->pkt_len - m->l2_len);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = DP_TEST_PAK_DEFAULT_TTL;
	ip->protocol = protocol;

	if (inet_pton(AF_INET, src, &addr) != 1) {
		DP_PKTMBUF_DBG("Couldn't create ip address");
		return NULL;
	}
	ip->saddr = addr;

	if (inet_pton(AF_INET, dst, &addr) != 1) {
		DP_PKTMBUF_DBG("Couldn't create ip address");
		return NULL;
	}
	ip->daddr = addr;

	/* Set checksum */
	ip->check = 0;
	ip->check = rte_ipv4_cksum((const struct ipv4_hdr *)ip);

	return ip;
}

struct iphdr *
dp_test_pktmbuf_ip_init(struct rte_mbuf *m, const char *src,
			const char *dst, uint8_t protocol)
{
	return dp_test_pktmbuf_ip(m, src, dst, protocol, false);
}

struct iphdr *
dp_test_pktmbuf_ip_prepend(struct rte_mbuf *m, const char *src,
			   const char *dst, uint8_t protocol)
{
	return dp_test_pktmbuf_ip(m, src, dst, protocol, true);
}

/**
 * Initialize IPv6 header. Assumes m->data_off is set to l2 header,
 * and m->l2_len is initialized.  Fails if there is not space for the
 * IPv6 header in the first mbuf.
 *
 * @param m [in]   Pointer to packet mbuf
 * @param src [in] Source address string, e.g. "2001:101:8::1"
 * @param dst [in] Dest address string
 * @param protocol [in]  Protocol, e.g. IPPROTO_UDP
 *
 * @return  Pointer to IPv6 header if successful, else NULL
 */
struct ip6_hdr *
dp_test_pktmbuf_ip6_init(struct rte_mbuf *m,
			 const char *src,
			 const char *dst,
			 uint8_t protocol)
{
	struct ip6_hdr *ip6;
	uint16_t plen, hlen;
	struct in6_addr addr6;

	hlen = m->l2_len + sizeof(*ip6);

	/* Is there room for the headers in first mbuf? */
	if (hlen > m->data_len) {
		DP_PKTMBUF_DBG("Required >= %d, actual %d\n", hlen,
			       m->data_len);
		DP_PKTMBUF_DBG("Not enough space for IPv6 header");
		return NULL;
	}

	ip6 = dp_pktmbuf_mtol3(m, struct ip6_hdr *);
	m->l3_len = sizeof(*ip6);
	plen = m->pkt_len - m->l2_len - m->l3_len;

	if (inet_pton(AF_INET6, src, &addr6) != 1) {
		DP_PKTMBUF_DBG("Couldn't create ipv6 address");
		return NULL;
	}
	memcpy(ip6->ip6_src.s6_addr, addr6.s6_addr, 16);

	if (inet_pton(AF_INET6, dst, &addr6) != 1) {
		DP_PKTMBUF_DBG("Couldn't create ipv6 address");
		return NULL;
	}
	memcpy(ip6->ip6_dst.s6_addr, addr6.s6_addr, 16);

	ip6->ip6_flow = 0; /* Before ip6_vfc is set */
	ip6->ip6_vfc = 0x60;
	ip6->ip6_nxt = protocol;
	ip6->ip6_plen = htons(plen);
	ip6->ip6_hlim = DP_TEST_PAK_DEFAULT_TTL;

	return ip6;
}

/**
 * Calculate IPv4 UDP or TCP checksum.
 *
 * The IPv4 header should not contains options. The layer 4 checksum
 * must be set to 0 in the packet by the caller. The l4 header must be
 * in the first mbuf.
 *
 * @param m [in]      Pointer to the mbuf chain
 * @param ip [in]     Pointer to the contiguous IP header.
 * @param l4_hdr [in] Pointer to the beginning of the L4 header
 * @return
 *   The complemented checksum to set in the IPv4 UDP/TCP header
 */
uint16_t
dp_test_ipv4_udptcp_cksum(const struct rte_mbuf *m, const struct iphdr *ip,
			  void *l4_hdr)
{
	struct rte_mbuf *seg;
	uint32_t l4_len;
	char buf[65536] = {0};
	uint32_t cur_len = 0;

	/*
	 * Copy into an extra buf first as we can not checksum odd segment
	 * lengths properly due to summing 16 bits at a time.
	 */
	l4_len = rte_pktmbuf_mtod(m, const char *) + m->data_len -
		(const char *)l4_hdr;
	memcpy(buf + cur_len, l4_hdr, l4_len);
	cur_len += l4_len;

	for (seg = m->next; seg != NULL; seg = seg->next) {
		void *data = rte_pktmbuf_mtod(seg, void *);
		memcpy(buf + cur_len, data, seg->data_len);
		cur_len += seg->data_len;
	}

	return rte_ipv4_udptcp_cksum((const struct ipv4_hdr *)ip, buf);
}

/**
 * Calculate IPv6 UDP or TCP checksum.
 *
 * The layer 4 checksum must be set to 0 in the packet by the caller.
 *
 * @param ip6
 *   The pointer to the contiguous IPv6 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header (must be in first mbuf).
 * @return
 *   The complemented checksum to set in the IPv6 UDP/TCP header
 */
uint16_t
dp_test_ipv6_udptcp_cksum(const struct rte_mbuf *m, const struct ip6_hdr *ip6,
			  const void *l4_hdr)
{
	struct rte_mbuf *seg;
	uint32_t cksum = 0;
	uint32_t l4_len;

	/* Checksum all mbufs other than the first */
	for (seg = m->next; seg != NULL; seg = seg->next) {
		void *data = rte_pktmbuf_mtod(seg, void *);
		cksum += rte_raw_cksum(data, seg->data_len);
		cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	}

	/* checksum l4 hdr and payload in first mbuf */
	l4_len = rte_pktmbuf_mtod(m, const char *) + m->data_len -
		(const char *)l4_hdr;
	cksum += rte_raw_cksum(l4_hdr, l4_len);
	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);

	/* checksum pseudo IPv6 header */
	cksum += rte_ipv6_phdr_cksum((const struct ipv6_hdr *)ip6, 0);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}

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
dp_test_ipv4_icmp_cksum(const struct rte_mbuf *m, const void *l4_hdr)
{
	struct rte_mbuf *seg;
	uint32_t cksum = 0;
	uint32_t l4_len;

	/* Checksum all mbufs other than the first */
	for (seg = m->next; seg != NULL; seg = seg->next) {
		void *data = rte_pktmbuf_mtod(seg, void *);
		cksum += rte_raw_cksum(data, seg->data_len);
		cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	}

	/* checksum l4 hdr and payload in first mbuf */
	l4_len = rte_pktmbuf_mtod(m, const char *) + m->data_len -
		(const char *)l4_hdr;
	cksum += rte_raw_cksum(l4_hdr, l4_len);
	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);

	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}

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
			const void *l4_hdr)
{
	struct rte_mbuf *seg;
	uint32_t cksum = 0;
	uint32_t l4_len;

	/* Checksum all mbufs other than the first */
	for (seg = m->next; seg != NULL; seg = seg->next) {
		void *data = rte_pktmbuf_mtod(seg, void *);
		cksum += rte_raw_cksum(data, seg->data_len);
		cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	}

	/* checksum l4 hdr and payload in first mbuf */
	l4_len = rte_pktmbuf_mtod(m, const char *) + m->data_len -
		(const char *)l4_hdr;
	cksum += rte_raw_cksum(l4_hdr, l4_len);
	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);

	/* checksum pseudo IPv6 header */
	cksum += rte_ipv6_phdr_cksum((const struct ipv6_hdr *)ip6, 0);
	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);

	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}

static struct vxlan_hdr *
dp_test_pktmbuf_vxlan(struct rte_mbuf *m, uint32_t vx_flags, uint32_t vx_vni,
		      bool prepend)
{
	struct vxlan_hdr *vxlan;
	uint16_t hlen;

	if (prepend) {
		vxlan = (struct vxlan_hdr *)
			rte_pktmbuf_prepend(m, sizeof(struct vxlan_hdr));
		if (!vxlan) {
			DP_PKTMBUF_DBG("Failed to prepend vxlan header\n");
			return NULL;
		}
		m->l2_len = 0;
		m->l3_len = 0;
		m->l4_len = 0;
	} else {
		/* There is no _mtol5 function so calc l5 */
		vxlan = dp_pktmbuf_mtol4(m, struct vxlan_hdr *) + 1;
	}

	hlen = m->l2_len + m->l3_len + m->l4_len + sizeof(struct vxlan_hdr);

	/* Is there room for VXLAN hdr in first mbuf? */
	if (hlen > m->data_len) {
		DP_PKTMBUF_DBG("Not enough space for VXLAN header");
		DP_PKTMBUF_DBG("Required >= %d, actual %d\n", hlen,
			       m->data_len);
		return NULL;
	}
	vxlan->vx_flags = htonl(vx_flags);
	vxlan->vx_vni = htonl(vx_vni << 8); /* VNI is 3 bytes */

	return vxlan;
}

struct vxlan_hdr *
dp_test_pktmbuf_vxlan_init(struct rte_mbuf *m, uint32_t vx_flags,
			   uint32_t vx_vni)
{
	return dp_test_pktmbuf_vxlan(m, vx_flags, vx_vni, false);
}

struct vxlan_hdr *
dp_test_pktmbuf_vxlan_prepend(struct rte_mbuf *m, uint32_t vx_flags,
			      uint32_t vx_vni)
{
	return dp_test_pktmbuf_vxlan(m, vx_flags, vx_vni, true);
}

/**
 * Initialize UDP header.  Assumes l2 and l3 headers already setup.
 * Assumes payload is already setup.  If not, then UDP checksum would
 * need recalculated.
 *
 * @param m     [in] Pointer to packet mbuf chain
 * @param sport [in] Source port
 * @param dport [in] Dest port
 * @param is_v4 [in] true if IPv4 packet, false if IPv6
 * @param crc   [in] true fill UDP checksum field
 * @param prepend [in] true prepend to the mbuf
 *
 * @return  Pointer to UDP header if successful, else NULL
 */
static struct udphdr *
dp_test_pktmbuf_udp(struct rte_mbuf *m, uint16_t sport, uint16_t dport,
		    bool is_v4, bool crc, bool prepend)
{
	struct udphdr *udp;
	uint16_t hlen;
	char *l3hdr;

	if (prepend) {
		udp = (struct udphdr *)
			rte_pktmbuf_prepend(m, sizeof(struct udphdr));
		if (!udp) {
			DP_PKTMBUF_DBG("Failed to prepend UDP header\n");
			return NULL;
		}
		m->l2_len = 0;
		m->l3_len = 0;
		m->l4_len = sizeof(struct udphdr);
	} else {
		m->l4_len = sizeof(struct udphdr);
	}

	hlen = m->l2_len + m->l3_len + m->l4_len;

	/* Is there room for UDP hdr in first mbuf? */
	if (hlen > m->data_len) {
		DP_PKTMBUF_DBG("Not enough space for UDP header");
		DP_PKTMBUF_DBG("Required >= %d, actual %d\n", hlen, m->data_len);
		return NULL;
	}

	udp = dp_pktmbuf_mtol4(m, struct udphdr *);

	memset(udp, 0, sizeof(*udp));
	udp->source = htons(sport);
	udp->dest = htons(dport);
	udp->len = htons(m->pkt_len - m->l2_len - m->l3_len);

	if (!crc) {
		udp->check = 0;
		return udp;
	}

	l3hdr = (char *)udp - m->l3_len;
	if (is_v4)
		udp->check =
			dp_test_ipv4_udptcp_cksum(m, (struct iphdr *)l3hdr,
						  udp);
	else
		udp->check =
			dp_test_ipv6_udptcp_cksum(m, (struct ip6_hdr *)l3hdr,
						  udp);
	return udp;
}

struct udphdr *
dp_test_pktmbuf_udp_init(struct rte_mbuf *m, uint16_t sport,
			 uint16_t dport, bool is_v4)
{
	return dp_test_pktmbuf_udp(m, sport, dport, is_v4, true, false);
}

struct udphdr *
dp_test_pktmbuf_udp_prepend(struct rte_mbuf *m, uint16_t sport,
			    uint16_t dport, bool is_v4)
{
	return dp_test_pktmbuf_udp(m, sport, dport, is_v4, true, true);
}

struct udphdr *
dp_test_pktmbuf_udp_prepend_no_crc(struct rte_mbuf *m, uint16_t sport,
				   uint16_t dport, bool is_v4)
{
	return dp_test_pktmbuf_udp(m, sport, dport, is_v4, false, true);
}

/*
 * Determine actual header space needed for TCP options, where input is of the
 * form:
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
static uint
dp_test_pktmbuf_tcp_opts_len(const uint8_t *opts)
{
	uint opts_len = 0;
	uint count = 0;

	if (!opts)
		return 0;

	while (count++ < 255 && opts[0] != TCPOPT_EOL) {

		switch (opts[0]) {
		case TCPOPT_EOL:
			break;
		case TCPOPT_NOP:
			opts_len += 1;
			opts += 1;
			break;
		default:
			opts_len += opts[1];
			opts += opts[1];
			break;
		}
	}

	if ((opts_len & 0x3) == 0)
		return opts_len;

	/* Round up to 4 bytes */
	return (opts_len/4 + 1) * 4;
}

/**
 * Initialize TCP header
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
			 const uint8_t *opts, bool is_v4)
{
	struct tcphdr *tcp;
	char *l3hdr;
	uint16_t hlen;
	uint16_t l4_len;

	l4_len = sizeof(*tcp) + dp_test_pktmbuf_tcp_opts_len(opts);
	hlen = m->l2_len + m->l3_len + l4_len;

	/* Is there room for TCP hdr in first mbuf? */
	if (hlen > m->data_len) {
		DP_PKTMBUF_DBG("Not enough space for TCP header");
		DP_PKTMBUF_DBG("Required >= %d, actual %d\n", hlen, m->data_len);
		return NULL;
	}

	tcp = dp_pktmbuf_mtol4(m, struct tcphdr *);

	memset(tcp, 0, l4_len);
	tcp->source = htons(sport);
	tcp->dest = htons(dport);
	tcp->doff = l4_len >> 2;
	tcp->th_flags = flags;
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(ack);
	tcp->window = htons(win);

	if (opts) {
		uint8_t *p = (uint8_t *)(tcp + 1);

		while (opts[0] != TCPOPT_EOL) {

			switch (opts[0]) {
			case TCPOPT_EOL:
				break;
			case TCPOPT_NOP:
				*p = TCPOPT_NOP;
				p += 1;
				opts += 1;
				break;
			default:
				memcpy(p, opts, opts[1]);
				p += opts[1];
				opts += opts[1];
				break;
			}
		}
	}

	l3hdr = (char *)tcp - m->l3_len;

	if (is_v4)
		tcp->check =
			dp_test_ipv4_udptcp_cksum(m, (struct iphdr *)l3hdr,
						  tcp);
	else
		tcp->check =
			dp_test_ipv6_udptcp_cksum(m, (struct ip6_hdr *)l3hdr,
						  tcp);

	return tcp;
}

/**
 * Initialize ICMP IPv4 header.  Assumes l2 and l3 headers already
 * setup.
 *
 * @param m [in]     Pointer to packet mbuf
 * @param icmp_type [in] ICMP type
 * @param icmp_code [in] ICMP code
 * @param data      [in]  ICMP header data
 *
 * @return  Pointer to ICMP header if successful, else NULL
 */
struct icmphdr *
dp_test_pktmbuf_icmp_init(struct rte_mbuf *m, uint8_t icmp_type,
			  uint8_t icmp_code, uint32_t data)
{
	struct icmphdr *icmp;
	uint16_t hlen;

	hlen = m->l2_len + m->l3_len + sizeof(*icmp);

	/* Is there room for ICMP hdr in first mbuf? */
	if (hlen > m->data_len) {
		DP_PKTMBUF_DBG("Not enough space for ICMP header");
		DP_PKTMBUF_DBG("Required >= %d, actual %d\n", hlen, m->data_len);
		return NULL;
	}

	union {
		uint32_t udata32;
		uint16_t udata16[2];
	} du;

	du.udata32 = data;

	icmp = dp_pktmbuf_mtol4(m, struct icmphdr *);
	memset(icmp, 0, sizeof(*icmp));
	icmp->type = icmp_type;
	icmp->code = icmp_code;

	switch (icmp_type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		icmp->un.echo.id = htons(du.udata16[0]);
		icmp->un.echo.sequence = htons(du.udata16[1]);
		break;
	case ICMP_REDIRECT:
		icmp->un.gateway = htonl(du.udata32);
		break;
	case ICMP_DEST_UNREACH:
		icmp->un.frag.mtu = htons(du.udata16[1]);
		break;
	}

	icmp->checksum = dp_test_ipv4_icmp_cksum(m, icmp);

	return icmp;
}

/**
 * Initialize ICMP IPv6 header.  Assumes l2 and l3 headers already
 * setup.
 *
 * @param m [in]     Pointer to packet mbuf
 * @param icmp6_type [in] IPv6 ICMP type
 * @param icmp6_code [in] IPv6 ICMP code
 * @param data [in] IPv6 ICMP data in host byte order
 *
 * @return  Pointer to ICMP header if successful, else NULL
 */
struct icmp6_hdr *
dp_test_pktmbuf_icmp6_init(struct rte_mbuf *m, uint8_t icmp6_type,
			   uint8_t icmp6_code, uint32_t data)
{
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *ip6;
	uint16_t hlen;

	hlen = m->l2_len + m->l3_len + sizeof(*icmp6);

	/* Is there room for ICMPv6 hdr in first mbuf? */
	if (hlen > m->data_len) {
		DP_PKTMBUF_DBG("Not enough space for ICMPv6 header");
		DP_PKTMBUF_DBG("Required >= %d, actual %d\n", hlen, m->data_len);
		return NULL;
	}

	ip6 = dp_pktmbuf_mtol3(m, struct ip6_hdr *);
	icmp6 = dp_pktmbuf_mtol4(m, struct icmp6_hdr *);
	memset(icmp6, 0, sizeof(*icmp6));
	icmp6->icmp6_type = icmp6_type;
	icmp6->icmp6_code = icmp6_code;

	switch (icmp6_type) {
	case ICMP6_ECHO_REQUEST:
	case ICMP6_ECHO_REPLY:
		icmp6->icmp6_id = htons(DPT_ICMP_ECHO_ID(data));
		icmp6->icmp6_seq = htons(DPT_ICMP_ECHO_SEQ(data));
		break;
	default:
		icmp6->icmp6_data32[0] = htonl(data);
		break;
	}

	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(m, ip6, icmp6);

	return icmp6;
}

/* GRE flags */
#define DP_TEST_GRE_SEQ  ntohs(0x1000)
#define DP_TEST_GRE_KEY  ntohs(0x2000)
#define DP_TEST_GRE_CSUM ntohs(0x8000)

/*
 * GRE header length depends on the flags, calculate it.
 * gre_flags is in host byte order
 */
static uint16_t
dp_test_pktmbuf_gre_hdr_len(uint16_t gre_flags)
{
	uint16_t gre_hdr_len = sizeof(struct gre_base_hdr);

	if (gre_flags & DP_TEST_GRE_CSUM)
		gre_hdr_len += 4;
	if (gre_flags & DP_TEST_GRE_KEY)
		gre_hdr_len += 4;
	if (gre_flags & DP_TEST_GRE_SEQ)
		gre_hdr_len += 4;

	return gre_hdr_len;
}

/*
 * Remove gre header. Assumes gre header is at the beginning of packet data.
 */
void
dp_test_pktmbuf_gre_adj(struct rte_mbuf *m)
{
	struct gre_base_hdr *gre = rte_pktmbuf_mtod(m, struct gre_base_hdr *);

	rte_pktmbuf_adj(m, dp_test_pktmbuf_gre_hdr_len(gre->flags));
}

static struct gre_base_hdr *
dp_test_pktmbuf_gre(struct rte_mbuf *m, uint16_t prot, uint32_t checksum,
		    uint32_t key, uint32_t seq, bool prepend)
{
	uint16_t gre_flags = 0; /* host byte order */

	if (checksum != 0)
		gre_flags |= DP_TEST_GRE_CSUM;
	if (key != 0)
		gre_flags |= DP_TEST_GRE_KEY;
	if (seq != 0)
		gre_flags |= DP_TEST_GRE_SEQ;

	struct gre_base_hdr *gre;
	uint16_t gre_hdr_len = dp_test_pktmbuf_gre_hdr_len(gre_flags);

	if (prepend) {
		gre = (struct gre_base_hdr *)
			rte_pktmbuf_prepend(m, gre_hdr_len);
		if (!gre) {
			DP_PKTMBUF_DBG("Failed to prepend GRE header\n");
			return NULL;
		}
		m->l2_len = 0;
		m->l3_len = 0;
	} else {
		assert(m->l2_len);
		assert(m->l3_len);
		gre = dp_pktmbuf_mtol4(m, struct gre_base_hdr *);

	}

	uint16_t hlen = m->l2_len + m->l3_len + gre_hdr_len;

	/* Is there room for GRE hdr in first mbuf? */
	if (hlen > m->data_len) {
		DP_PKTMBUF_DBG("Not enough space for GRE header");
		DP_PKTMBUF_DBG(" Required >= %d, actual %d\n", hlen,
			       m->data_len);
		return NULL;
	}

	memset(gre, 0, gre_hdr_len);
	gre->flags = gre_flags;
	gre->protocol = htons(prot);

	/* | flags 2B | protocol 2B | ? checksum 4B | ? Key 4B | ? Seq 4B */
	uint8_t *cursor = (uint8_t *)gre + sizeof(struct gre_base_hdr);
	uint32_t *u32p;

	if (gre_flags & DP_TEST_GRE_CSUM) {
		u32p = (uint32_t *)cursor;
		*u32p = htonl(checksum);
		cursor += sizeof(checksum);
	}

	if (gre_flags & DP_TEST_GRE_KEY) {
		u32p = (uint32_t *)cursor;
		*u32p = htonl(key);
		cursor += sizeof(key);
	}

	if (gre_flags & DP_TEST_GRE_SEQ) {
		u32p = (uint32_t *)cursor;
		*u32p = htonl(seq);
		cursor += sizeof(seq);
	}

	return gre;
}

static struct erspan_type2_hdr *
dp_test_pktmbuf_erspan_init(struct rte_mbuf *m, uint16_t erspanid,
			    uint8_t hdr_type, uint16_t vlan,
			    uint16_t idx, uint8_t dir)
{
	if (hdr_type == ERSPAN_TYPEII) {
		char *hdr;
		struct erspan_type2_hdr *erspan;
		hdr = dp_pktmbuf_mtol4(m, char *) + sizeof(*erspan);
		erspan = (struct erspan_type2_hdr *)hdr;
		erspan->ver_sid = htonl((hdr_type << 28) |
					(vlan << 16) |
					((vlan ? 0x2 : 0x0) << 11) |
					erspanid);
		erspan->idx_dir = htonl(idx << 4 | dir);
		return erspan;
	} else
		return NULL;
}

/**
 * Initialize GRE header.  Assumes l2 and l3 headers already setup.
 *
 * @param  m    [in]  Pointer to packet mbuf
 * @param  prot [in]  Protocol in host byte order
 * @return Pointer to GRE header if successful, else NULL
 */
struct gre_base_hdr *
dp_test_pktmbuf_gre_init(struct rte_mbuf *m, uint16_t prot, uint32_t key,
			 uint32_t seq)
{
	return dp_test_pktmbuf_gre(m, prot, 0, key, seq, false);
}

struct gre_base_hdr *
dp_test_pktmbuf_gre_prepend(struct rte_mbuf *m, uint16_t prot, uint32_t key)
{
	return dp_test_pktmbuf_gre(m, prot, 0, key, 0, true);
}

/*
 * Test pattern for initializing packet payload with something
 * interesting.  Leaving the payload as all-zero's may mask some
 * ckecksum problems.
 */
static char *
test_pattern_create(int len)
{
	char *p;
	int i;

	p = (char *)malloc(len);
	if (!p)
		return NULL;

	for (i = 0; i < len; i++) {
		p[i] = i;
	}
	return p;
}

static void
test_pattern_free(char *p)
{
	if (p)
		free(p);
}

/**
 * Initialize packet payload.  Handles chained mbufs'.
 *
 * @param m       [in] Pointer to packet mbuf
 * @param off     [in] Offset, relative to m->data_off, of where to write
 *                     the payload to. Typically this will be the sum of
 *                     the l2, l3, and l4 header lengths.
 * @param payload [in] Payload to write to the packet.  May be NULL, in
 *                     which case a test pattern is used.
 * @param plen    [in] Length of payload
 * @return Number of bytes written
 */
uint16_t
dp_test_pktmbuf_payload_init(struct rte_mbuf *m, uint16_t off,
			     const char *payload, uint16_t plen)
{
	uint16_t mlen, poff;
	char *test_pattern = NULL;

	/*
	 * Find starting mbuf
	 */
	while (m && off >= m->data_len) {
		off -= m->data_len;
		m = m->next;
	}
	if (!m)
		return 0;

	if (payload == NULL) {
		test_pattern = test_pattern_create(plen);
		assert(test_pattern);
		payload = test_pattern;
	}

	poff = 0; /* payload offset */

	while (m && plen > 0) {
		uint16_t len;

		/* Space in this mbuf */
		mlen = m->data_len - off;

		if (plen < mlen)
			len = plen;
		else
			len = mlen;

		memcpy((char *)m->buf_addr + m->data_off + off,
		       payload + poff, len);
		plen -= len;
		poff += len;

		m = m->next;
		off = 0;
	}

	test_pattern_free(test_pattern);

	return poff; /* Return the number of bytes written */
}


/*
 * An ethernet header will be automatically prepended onto the packet.  So for
 * a minimum sized IP packet, len[0] should be 30 bytes.  For a minimum sized
 * IPv6 packet , len[0] should be 10 bytes.  And for other ethernet types
 * (where hlen is 0), len[0] should be 50 bytes.
 */
struct rte_mbuf *
dp_test_create_l2_pak(const char *d_addr,
		      const char *s_addr,
		      uint16_t ether_type,
		      int n, const int *len)
{
	struct rte_mbuf *pak;
	uint16_t hlen = 0;

       /*
	* Determine l3 and l4 header lengths from ether type.  This length is
	* added to the first mbuf of the chain in dp_test_create_mbuf_chain.
	*/
	switch (ether_type) {

	case ETHER_TYPE_IPv4:
		hlen =  sizeof(struct iphdr);
		break;
	case ETHER_TYPE_IPv6:
		hlen =  sizeof(struct ip6_hdr);
		break;
	default:
		/* Add support for other types as required */
		break;
	}
	pak = dp_test_create_mbuf_chain(n, len, hlen);

	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, d_addr, s_addr, ether_type)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	if (pak->pkt_len - pak->l2_len &&
	    dp_test_pktmbuf_payload_init(pak, pak->l2_len, NULL,
					 pak->pkt_len - pak->l2_len) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}

/**
 * Initialize packet to emulate reception on vlan.
 *
 * @param m          [in] Pointer to packet mbuf
 * @param vlan       [in] vlan id
 *
 */
void
dp_test_pktmbuf_vlan_init(struct rte_mbuf *m,
			  uint16_t vlan)
{
	assert(m);

	m->vlan_tci = vlan;
	m->ol_flags |= PKT_RX_VLAN;
}

void
dp_test_pktmbuf_vlan_clear(struct rte_mbuf *m)
{
	assert(m);

	m->vlan_tci = 0;
	m->ol_flags &= ~PKT_RX_VLAN;
}

struct ether_vlan_hdr {
	struct ether_hdr eh;
	struct vlan_hdr vh;
};

void
dp_test_insert_8021q_hdr(struct rte_mbuf *pak, uint16_t vlan_id,
			 uint16_t vlan_ether_type,
			 uint16_t payload_ether_type)
{
	struct ether_hdr *eth = rte_pktmbuf_mtod(pak, struct ether_hdr *);
	struct ether_vlan_hdr *vhdr = (struct ether_vlan_hdr *)
		rte_pktmbuf_prepend(pak, sizeof(struct vlan_hdr));

	assert(vhdr != NULL);

	memmove(&vhdr->eh, eth, 2 * ETHER_ADDR_LEN);
	vhdr->eh.ether_type = htons(vlan_ether_type);
	vhdr->vh.vlan_tci = htons(vlan_id);
	vhdr->vh.eth_proto = htons(payload_ether_type);
	dp_pktmbuf_l2_len(pak) += sizeof(struct vlan_hdr);
}

struct rte_mbuf *
dp_test_create_8021q_l2_pak(const char *d_addr,
			    const char *s_addr,
			    uint16_t vlan_id,
			    uint16_t vlan_ether_type,
			    uint16_t payload_ether_type,
			    int n, const int *len)
{
	struct rte_mbuf *pak;

	pak = dp_test_create_l2_pak(d_addr, s_addr,
				    payload_ether_type, n, len);

	if (!pak)
		return NULL;

	if (vlan_ether_type == ETH_P_8021Q)
		/* see if_tpid_offload and ifp->tpid_offloaded
		 * dpdk driver will strip out 802.1Q header
		 */
		dp_test_pktmbuf_vlan_init(pak, vlan_id);
	else
		dp_test_insert_8021q_hdr(pak, vlan_id, vlan_ether_type,
					 payload_ether_type);

	return pak;
}

int
dp_test_inet_pton(int af, const char *src, void *dst)
{
	int rc;

	rc = inet_pton(af, src, dst);
	if (rc != 1)
		DP_PKTMBUF_DBG("Error %d formatting IP address", rc);

	return rc;
}

struct rte_mbuf *
dp_test_create_ipv4_pak(const char *saddr, const char *daddr,
			int n, const int *len)
{
	return dp_test_create_udp_ipv4_pak(saddr, daddr,
					   DP_TEST_PAK_DEFAULT_UDP_SRC_PORT,
					   DP_TEST_PAK_DEFAULT_UDP_DST_PORT,
					   n, len);
}

struct rte_mbuf *
dp_test_create_raw_ipv4_pak(const char *saddr, const char *daddr,
			    uint8_t ipproto, int n, const int *len)
{
	struct rte_mbuf *pak;
	struct iphdr *ip;
	uint16_t hlen;

	/* Create mbuf chain */
	hlen = sizeof(*ip);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	/*
	 * Init headers in first mbuf
	 */
	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv4)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip = dp_test_pktmbuf_ip_init(pak, saddr, daddr, ipproto);
	if (!ip) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len;
	uint32_t plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	if (plen && dp_test_pktmbuf_payload_init(pak, poff, NULL, plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}


/**
 * Create and initialise an IPv4 UDP packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param sport [in]  UDP source port (host order)
 * @param dport [in]  UDP dest port
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_udp_ipv4_pak(const char *saddr, const char *daddr,
			    uint16_t sport, uint16_t dport,
			    int n, const int *len)
{
	struct rte_mbuf *pak;
	struct udphdr *udp;
	struct iphdr *ip;
	uint16_t hlen;

	/* Create mbuf chain */
	hlen = sizeof(*ip) + sizeof(*udp);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	/*
	 * Init headers in first mbuf
	 */
	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv4)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip = dp_test_pktmbuf_ip_init(pak, saddr, daddr, IPPROTO_UDP);
	if (!ip) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + sizeof(*udp);
	uint32_t plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	if (dp_test_pktmbuf_payload_init(pak, poff, NULL, plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Write UDP header after payload is initialized */
	udp = dp_test_pktmbuf_udp_init(pak, sport, dport, true);
	if (!udp) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}

struct rte_mbuf *
dp_test_create_raw_ipv6_pak(const char *saddr, const char *daddr,
			    uint8_t protocol, int n, const int *len)
{
	struct rte_mbuf *pak;
	struct ip6_hdr *ip6;
	uint16_t hlen;

	/* Create mbuf chain */
	hlen = sizeof(*ip6);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv6)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip6 = dp_test_pktmbuf_ip6_init(pak, saddr, daddr, protocol);
	if (!ip6) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len;
	uint32_t plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	if (plen && dp_test_pktmbuf_payload_init(pak, poff, NULL, plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}

/**
 * Create and initialise an IPv6 packet with protocol and payload
 * length set to 0.
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_ipv6_pak(const char *saddr, const char *daddr,
			int n, const int *len)
{
	return dp_test_create_raw_ipv6_pak(saddr, daddr, IPPROTO_NONE, n,
					   len);
}

/**
 * Create and initialise an IPv6 UDP packet
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param sport [in]  UDP source port (host order)
 * @param dport [in]  UDP dest port
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_udp_ipv6_pak(const char *saddr, const char *daddr,
			    uint16_t sport, uint16_t dport,
			    int n, const int *len)
{
	struct rte_mbuf *pak;
	struct udphdr *udp;
	struct ip6_hdr *ip6;
	uint16_t hlen;

	/* Create mbuf chain */
	hlen = sizeof(*ip6) + sizeof(*udp);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv6)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip6 = dp_test_pktmbuf_ip6_init(pak, saddr, daddr,
				       IPPROTO_UDP);
	if (!ip6) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + sizeof(*udp);
	uint32_t plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	if (dp_test_pktmbuf_payload_init(pak, poff, NULL, plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	udp = dp_test_pktmbuf_udp_init(pak, sport, dport, false);
	if (!udp) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}

/**
 * Create and initialise an IPv4 TCP packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param sport [in]  TCP source port (host order)
 * @param dport [in]  TCP dest port
 * @param flags [in]  TCP header flags
 * @param seq   [in]  TCP sequence number
 * @param ack   [in]  TCP acknowledgment number
 * @param win   [in]  TCP window value (host order)
 * @param opts  [in]  Byte array of TCP options.  See below.
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak        Pointer to mbuf if successful, else NULL
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
struct rte_mbuf *
dp_test_create_tcp_ipv4_pak(const char *saddr, const char *daddr,
			    uint16_t sport, uint16_t dport, uint8_t flags,
			    uint32_t seq, uint32_t ack, uint16_t win,
			    const uint8_t *opts, int n, const int *len)
{
	struct rte_mbuf *pak;
	struct tcphdr *tcp;
	struct iphdr *ip;
	uint16_t hlen;
	uint16_t l4_len;

	l4_len = sizeof(*tcp) + dp_test_pktmbuf_tcp_opts_len(opts);

	/* Create mbuf chain */
	hlen = sizeof(*ip) + l4_len;
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv4)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip = dp_test_pktmbuf_ip_init(pak, saddr, daddr, IPPROTO_TCP);
	if (!ip) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + l4_len;
	uint32_t plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	if (plen > 0 && dp_test_pktmbuf_payload_init(pak, poff, NULL,
						     plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	tcp = dp_test_pktmbuf_tcp_init(pak, sport, dport, flags, seq, ack,
				       win, opts, true);
	if (!tcp) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}

/*
 * Create and initialise an IPv6 TCP packet
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param sport [in]  TCP source port (host order)
 * @param dport [in]  TCP dest port
 * @param flags [in]  TCP header flags
 * @param seq   [in]  TCP sequence number
 * @param ack   [in]  TCP acknowledgment number
 * @param win   [in]  TCP window value (host order)
 * @param opts  [in]  Byte array of TCP options.  See above.
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_tcp_ipv6_pak(const char *saddr, const char *daddr,
			    uint16_t sport, uint16_t dport, uint8_t flags,
			    uint32_t seq, uint32_t ack, uint16_t win,
			    const uint8_t *opts, int n, const int *len)
{
	struct rte_mbuf *pak;
	struct tcphdr *tcp;
	struct ip6_hdr *ip6;
	uint16_t hlen;
	uint16_t l4_len;

	l4_len = sizeof(*tcp) + dp_test_pktmbuf_tcp_opts_len(opts);

	/* Create mbuf chain */
	hlen = sizeof(*ip6) + l4_len;
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv6)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip6 = dp_test_pktmbuf_ip6_init(pak, saddr, daddr, IPPROTO_TCP);
	if (!ip6) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + l4_len;
	uint32_t plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	if (plen > 0 && dp_test_pktmbuf_payload_init(pak, poff, NULL,
						     plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	tcp = dp_test_pktmbuf_tcp_init(pak, sport, dport, flags, seq, ack,
				       win, opts, false);
	if (!tcp) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	return pak;
}

/**
 * Create and initialise an IPv4 ICMP packet
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param icmp_type [in]  ICMP type
 * @param icmp_code [in]  ICMP code
 * @param data  [in]  ICMP header data
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
			     const void *payload, struct iphdr **ipp,
			     struct icmphdr **icmpp)
{
	struct rte_mbuf *pak;
	struct icmphdr *icmp;
	struct iphdr *ip;
	uint16_t hlen;

	/* Create mbuf chain */
	hlen = sizeof(*ip) + sizeof(*icmp);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv4)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip = dp_test_pktmbuf_ip_init(pak, saddr, daddr, IPPROTO_ICMP);
	if (!ip) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	if (ipp)
		*ipp = ip;

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + sizeof(*icmp);
	uint32_t plen = pak->pkt_len - poff;

	if (payload) {
		memcpy(dp_pktmbuf_mtol4(pak, struct icmphdr *) + 1,
		       payload, plen);
	} else {
		/* Write test pattern to mbuf payload */
		if (dp_test_pktmbuf_payload_init(pak, poff, NULL, plen) == 0) {
			rte_pktmbuf_free(pak);
			return NULL;
		}
	}

	icmp = dp_test_pktmbuf_icmp_init(pak, icmp_type, icmp_code, data);
	if (!icmp) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	if (icmpp)
		*icmpp = icmp;

	return pak;
}

/**
 * Create and initialise an IPv6 ICMP packet
 *
 * @param saddr [in]  Source address string, e.g. "2001:101:8::1"
 * @param daddr [in]  Dest address string
 * @param icmp_type [in]  ICMPv6 type
 * @param icmp_code [in]  ICMPv6 code
 * @param data  [in]  ICMPv6 data in host byte order
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
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
			     struct icmp6_hdr **icmp6p)
{
	struct rte_mbuf *pak;
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *ip6;
	uint16_t hlen;

	/* Create mbuf chain */
	hlen = sizeof(*ip6) + sizeof(*icmp6);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv6)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip6 = dp_test_pktmbuf_ip6_init(pak, saddr, daddr, IPPROTO_ICMPV6);
	if (!ip6) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	if (ip6p)
		*ip6p = ip6;

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + sizeof(*icmp6);
	uint32_t plen = pak->pkt_len - poff;

	if (payload) {
		memcpy(dp_pktmbuf_mtol4(pak, struct icmp6_hdr *) + 1,
		       payload, plen);
	} else {
		/* Write test pattern to mbuf payload */
		if (dp_test_pktmbuf_payload_init(pak, poff, NULL, plen) == 0) {
			rte_pktmbuf_free(pak);
			return NULL;
		}
	}

	icmp6 = dp_test_pktmbuf_icmp6_init(pak, icmp_type, icmp_code,
					   data);
	if (!icmp6) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	if (icmp6p)
		*icmp6p = icmp6;

	return pak;
}

static struct rte_mbuf *
dp_test_create_gre_pak(uint16_t ethertype, const char *saddr, const char *daddr,
		       int n, const int *len, uint16_t gre_prot,
		       uint32_t gre_key, uint32_t gre_seq,
		       void **payload)
{
	struct rte_mbuf *pak;
	struct gre_base_hdr *gre;
	struct iphdr *ip;
	struct ip6_hdr *ip6;
	uint16_t hlen;

	/* Create mbuf chain */
	if (ethertype == ETHER_TYPE_IPv4)
		hlen = sizeof(*ip) + sizeof(*gre);
	else
		hlen = sizeof(*ip6) + sizeof(*gre);
	pak = dp_test_create_mbuf_chain(n, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ethertype)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	if (ethertype == ETHER_TYPE_IPv4) {
		ip = dp_test_pktmbuf_ip_init(pak, saddr, daddr, IPPROTO_GRE);
		if (!ip) {
			rte_pktmbuf_free(pak);
			return NULL;
		}
	} else {
		ip6 = dp_test_pktmbuf_ip6_init(pak, saddr, daddr, IPPROTO_GRE);
		if (!ip6) {
			rte_pktmbuf_free(pak);
			return NULL;
		}
	}

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + sizeof(*gre);
	uint32_t plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	if (dp_test_pktmbuf_payload_init(pak, poff, NULL, plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	gre = dp_test_pktmbuf_gre_init(pak, gre_prot, gre_key, gre_seq);
	if (!gre) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	if (payload)
		*payload = gre + 1;

	return pak;
}

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
			    void **payload)
{
	return dp_test_create_gre_pak(ETHER_TYPE_IPv4, saddr, daddr, n,
				      len, gre_prot, gre_key, gre_seq,
				      payload);
}

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
			    void **payload)
{
	return dp_test_create_gre_pak(ETHER_TYPE_IPv6, saddr, daddr, n,
				      len, gre_prot, gre_key, gre_seq,
				      payload);
}

#define GRE_FLAG_VER_1	0x2000
#define GRE_FLAG_KEY	0x04
#define GRE_FLAG_SEQ	0x08
#define GRE_FLAG_ACK	0x100

/**
 * Create and initialise an IPv4 GRE PPTP packet
 *
 * This is a GRE packet with a version of 1, a protocol of 0x880B, and a
 * callid.
 *
 * @param saddr [in]  Source address string, e.g. "10.0.1.0"
 * @param daddr [in]  Dest address string
 * @param n     [in]  Number of mbufs
 * @param len   [in]  Array of 'n' per-mbuf payload lengths
 * @param call_id [in]  PTPP call id in host byte order.
 * @param gre_seq  [in]  GRE sequence number in host byte order
 * @param gre_ack  [in]  GRE acknowledgment in host byte order
 * @param payload [out]  Pointer to start of payload of GRE packet
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
dp_test_create_gre_pptp_ipv4_pak(const char *saddr, const char *daddr,
			    int n, const int *len, uint16_t cid,
			    uint32_t gre_seq, uint32_t gre_ack,
			    void **payload)
{
	struct rte_mbuf *m;
	struct gre_base_hdr *gre;
	struct iphdr *ip;
	uint16_t flags;
	uint16_t hlen;
	uint16_t gre_hlen;

	/* Create mbuf chain */
	gre_hlen = sizeof(*gre);
	if (gre_seq) { /* optional */
		gre_hlen += 4;
		if (gre_ack)
			gre_hlen += 4;
	} else if (gre_ack)
		gre_hlen += 8;

	hlen = sizeof(*ip) + gre_hlen;
	m = dp_test_create_mbuf_chain(n, len, hlen);
	if (!m)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(m, NULL, NULL, ETHER_TYPE_IPv4)) {
		rte_pktmbuf_free(m);
		return NULL;
	}
	ip = dp_test_pktmbuf_ip_init(m, saddr, daddr, IPPROTO_GRE);
	if (!ip) {
		rte_pktmbuf_free(m);
		return NULL;
	}

	/* Payload offset and length */
	uint32_t poff = m->l2_len + m->l3_len + gre_hlen;
	uint32_t plen = m->pkt_len - poff;

	/*
	 * Init the bits and flags.  We only set the key bit,
	 * ack bit (if present) and version to 1.
	 */
	gre = dp_pktmbuf_mtol4(m, struct gre_base_hdr *);
	memset(gre, 0, gre_hlen);

	flags = GRE_FLAG_KEY | GRE_FLAG_VER_1;
	if (gre_seq)
		flags |= GRE_FLAG_SEQ;
	if (gre_ack)
		flags |= GRE_FLAG_ACK;

	/*
	 * | flags 2B | protocol 2B | key_len 2B | callid 2B |
	 *						? Seq 4B | ? Ack 4B
	 */
	gre->flags = htons(flags);
	gre->protocol = htons(0x880B);

	uint8_t *cursor = (uint8_t *) gre + sizeof(struct gre_base_hdr);
	uint32_t *u32p;
	uint16_t *u16p;

	u16p = (uint16_t *) cursor;
	*u16p = htons(plen);
	cursor += sizeof(uint16_t);

	u16p = (uint16_t *) cursor;
	*u16p = htons(cid);
	cursor += sizeof(uint16_t);

	if (gre_seq || gre_ack) {
		u32p = (uint32_t *) cursor;
		*u32p = htonl(gre_seq);
		cursor += sizeof(uint32_t);

		if (gre_ack) {
			u32p = (uint32_t *) cursor;
			*u32p = htonl(gre_ack);
		}
	}

	/* Write test pattern to mbuf payload */
	if (dp_test_pktmbuf_payload_init(m, poff, NULL, plen) == 0) {
		rte_pktmbuf_free(m);
		return NULL;
	}

	if (payload)
		*payload = dp_pktmbuf_mtol4(m, char *) + hlen  + 1;

	return m;
}

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
			       uint16_t vlan, uint8_t dir, void **payload)
{
	struct rte_mbuf *pak;
	struct gre_base_hdr *gre;
	struct erspan_type2_hdr *erspan;
	struct iphdr *ip;
	uint16_t hlen;

	/* Create mbuf chain
	 * ERSPAN GRE header has sequence number bit set, add 4 bytes to
	 * GRE base header for ERSPAN sequence number
	 */
	hlen = sizeof(*ip) + sizeof(*gre) + 4 + sizeof(*erspan);
	pak = dp_test_create_mbuf_chain(1, len, hlen);
	if (!pak)
		return NULL;

	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_IPv4)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	ip = dp_test_pktmbuf_ip_init(pak, saddr, daddr, IPPROTO_GRE);
	if (!ip) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Payload offset and length */
	uint32_t poff = pak->l2_len + pak->l3_len + sizeof(*gre) +
			sizeof(*erspan);
	uint32_t plen = pak->pkt_len - poff;

	/* Write test pattern to mbuf payload */
	if (dp_test_pktmbuf_payload_init(pak, poff, NULL, plen) == 0) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/* Create ERSPAN GRE header with sequence number. The sequence
	 * number is hard coded to 1. This value is used to set the sequence
	 * number bit in ERSPAN GRE header. The sequence number itself is
	 * disregarded in the tests, since the sequence number in expected
	 * test packet will not be the same as the actual packet. GRE code
	 * does not initialize sequence numbers to 0, and could have any
	 * random number as initial value.
	 */
	gre = dp_test_pktmbuf_gre(pak, gre_prot, 0, 0, 1, false);
	if (!gre) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	erspan = dp_test_pktmbuf_erspan_init(pak, erspanid, 1, vlan,
					     srcidx, dir);
	if (!erspan) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	if (payload)
		*payload = erspan + 1;

	return pak;
}

/**
 * Create and initialise an MPLS packet
 *
 * @param payload_pak [in]  mbuf containing payload pak
 * @param nlabels     [in]  number of mpls labels
 * @param labels      [in]  array of labels
 *
 * @return pak        Pointer to mbuf if successful, else NULL
 */
struct rte_mbuf *
_dp_test_create_mpls_pak(uint8_t nlabels,
			label_t *labels, uint8_t mpls_ttls[],
			const struct rte_mbuf *payload)
{
	struct rte_mbuf *pak;
	label_t *lbl_stack;
	int i;

	assert(nlabels > 0);

	/* Create mbuf chain */
	pak = dp_test_pktmbuf_alloc(dp_test_mempool);
	if (!pak)
		return NULL;

	/*
	 * Init L2
	 */
	if (!dp_test_pktmbuf_eth_init(pak, NULL, NULL, ETHER_TYPE_MPLS)) {
		rte_pktmbuf_free(pak);
		return NULL;
	}

	/*
	 * Init mpls head
	 */
	lbl_stack = dp_pktmbuf_mtol3(pak, label_t *);

	for (i = 0; i < nlabels; i++)
		*lbl_stack++ = htonl(labels[i] << MPLS_LS_LABEL_SHIFT |
				     mpls_ttls[i]);


	/* set BOS bit on last label */
	*(lbl_stack - 1) |= htonl(1 << MPLS_LS_S_SHIFT);


	/*
	 * set the data len to the end of the mpls header
	 */
	rte_pktmbuf_data_len(pak) =
		sizeof(struct ether_hdr) + (nlabels * sizeof(label_t));
	pak->l2_len = rte_pktmbuf_data_len(pak);
	pak->pkt_len = rte_pktmbuf_data_len(pak);


	if (payload) {
		/*
		 * Current assumption is that payload is ipv4 - later
		 * check the ethertype.
		 */
		struct iphdr *ip, *copy_from;
		/*
		 * Copy l3 from payload into our l3
		 */
		copy_from = dp_pktmbuf_mtol3(payload, struct iphdr *);
		ip = dp_pktmbuf_mtol3(pak, struct iphdr *);
		memcpy(ip, copy_from, rte_pktmbuf_data_len(payload) -
		       payload->l2_len);
		pak->l3_len = sizeof(struct iphdr);
		rte_pktmbuf_pkt_len(pak) += rte_pktmbuf_data_len(payload) -
			payload->l2_len;
		rte_pktmbuf_data_len(pak) = rte_pktmbuf_pkt_len(pak);
		/*
		 * If we are done adding the payload here then reset
		 * l2 header to be end of the ethernet header as that
		 * is what the dplane expects when receiving a packet.
		 */
		pak->l2_len = sizeof(struct ether_hdr);
	}
	return pak;
}

void *
dp_test_get_mpls_pak_payload(const struct rte_mbuf *m)
{
	label_t *lbl_stack;

	lbl_stack = dp_pktmbuf_mtol3(m, label_t *);

	for (; ; lbl_stack++) {
		if (ntohl(*lbl_stack) & (1 << MPLS_LS_S_SHIFT)) {
			lbl_stack++;
			break;
		}
	}

	return lbl_stack;
}

/*
 * Create and return a pointer to a copy of m_origin.
 */
struct rte_mbuf *
dp_test_cp_pak(struct rte_mbuf *m_origin)
{
	struct rte_mbuf *copy;

	assert(rte_pktmbuf_data_len(m_origin) != 0);
	copy = pktmbuf_copy(m_origin, m_origin->pool);
	assert(copy);
	assert(rte_pktmbuf_data_len(copy) != 0);
	return copy;
}

/*
 * Copy a packet in an mbuf chain to a single contiguous malloced
 * buffer.  If 'buf' is NULL then malloc the buffer.
 */
char *
dp_test_cp_mbuf_to_buf(struct rte_mbuf *m, char *buf)
{
	struct rte_mbuf *seg;
	uint off;

	if (!buf) {
		buf = malloc(m->pkt_len);
		if (!buf)
			return NULL;
	}

	/* Copy input pkt to a contiguous buffer */
	off = 0;
	for (seg = m; seg != NULL; seg = seg->next) {
		/* Shouldn't happen - data_len sum doesn't match pkt_len */
		assert(off + seg->data_len <= m->pkt_len);
		memcpy(buf + off, rte_pktmbuf_mtod(seg, char *),
		       seg->data_len);
		off += seg->data_len;
	}

	return buf;
}

/*
 * IPv6 non-fragmentable extension headers understood by
 * vyatta-dataplane
 */
bool
dp_test_non_frag_ext_hdr(uint8_t pcol)
{
	switch (pcol) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_AH:
	case IPPROTO_FRAGMENT:
		return true;
	default:
		break;
	}
	return false;
}

/*
 * IPv6 non-fragmentable extension header length field to length in
 * bytes
 */
uint8_t
dp_test_non_frag_ext_hdr_get_len(uint8_t pcol, uint8_t ip6e_len)
{
	switch (pcol) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
		return (ip6e_len + 1) << 3;
	case IPPROTO_AH:
		return (ip6e_len + 2) << 2;
	case IPPROTO_FRAGMENT:
		return sizeof(struct ip6_frag);
	default:
		DP_PKTMBUF_DBG("Unknown proto %d\n", pcol);
		break;
	}
	return 0;
}

/*
 * Set IPv6 non-fragmentable extension header length
 */
bool
dp_test_non_frag_ext_hdr_set_len(struct ip6_ext *ip6e, uint8_t pcol,
				 uint8_t len)
{
	switch (pcol) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
		/* Units of octets, not incl. first octet */
		ip6e->ip6e_len = (len >> 3) - 1;
		break;
	case IPPROTO_AH:
		/* Units of 4 bytes, not incl. first 8 bytes */
		ip6e->ip6e_len = (len >> 2) - 2;
		break;
	case IPPROTO_FRAGMENT:
		/* frag hdr has no length field */
		break;
	default:
		DP_PKTMBUF_DBG("Unknown proto %d\n", pcol);
		return false;
	}
	return true;
}

/*
 * Returns pointer to last non-fragmentable extension header, or NULL
 * if no ext hdrs.  *l3_len is set to the sum of the IPv6 hdr, non
 * frag ext hfrs and frag hdr.  i.e. a value such that l3_len can be
 * used to get the UCP/TCP hdr.
 *
 * @param l3_len [in/out]  Pointer to l3_len. Updated with the length of
 *                         the IPv6 header and all extension headers.
 * @param last_pcol [in/out] The protocol type of the last extension header
 *                           Will return the one before the TCP, UDP or ICMP hdr.
 *
 * @return Pointer to last extension header; NULL on error
 */
struct ip6_ext *
dp_test_ipv6_scan_non_frag_hdrs(struct rte_mbuf *m, uint8_t *l3_len,
				uint8_t *last_pcol)
{
	struct ip6_hdr *ip6;
	struct ip6_ext *ip6e, *prev;
	uint8_t *n_ptr;
	uint8_t nxt, len;

	ip6 = dp_pktmbuf_mtol3(m, struct ip6_hdr *);
	*l3_len = sizeof(*ip6);
	n_ptr = (uint8_t *)ip6 + sizeof(*ip6);
	*last_pcol = ip6->ip6_nxt;

	nxt = ip6->ip6_nxt;
	ip6e = (struct ip6_ext *)n_ptr;
	prev = NULL;

	while (dp_test_non_frag_ext_hdr(nxt)) {
		len = dp_test_non_frag_ext_hdr_get_len(nxt, ip6e->ip6e_len);
		if (len == 0)
			return NULL;
		*l3_len += len;
		n_ptr += len;

		*last_pcol = nxt;
		nxt = ip6e->ip6e_nxt;
		prev = ip6e;
		ip6e = (struct ip6_ext *)n_ptr;
		if (*last_pcol == IPPROTO_FRAGMENT)
			break;
	}
	return prev;
}

/*
 * Setup IPv6 headers of a packet fragment.
 *
 * Copies the IPv6 header and non-fragmentable extension headers;
 * adjusts the new IPv6 header; populates the fragmentation header.
 *
 * l3_len should be set to the size of the IPv6 header plus any
 * non-fragmentable extension headers.
 */
static void
dp_test_fill_ipv6hdr_frag(struct rte_mbuf *pkt_in, struct rte_mbuf *pkt_out,
			  uint16_t plen,
			  uint16_t fofs, uint32_t mf, uint32_t fh_id)
{
	struct ipv6_hdr *dst, *src;
	struct ip6_frag *fh;
	uint16_t offlg;
	int l3_len;
	uint8_t nxt_proto;

	src = dp_pktmbuf_mtol3(pkt_in, struct ipv6_hdr *);
	dst = dp_pktmbuf_mtol3(pkt_out, struct ipv6_hdr *);
	l3_len = pkt_in->l3_len;

	/*
	 * Fragment payload length includes non-fragmentable
	 * ext. headers and the fragmentation header itself,
	 * but not the IPv6 header.
	 */
	plen += l3_len + sizeof(struct ip6_frag) - sizeof(struct ipv6_hdr);

	memcpy(dst, src, l3_len);
	dst->payload_len = htons(plen);

	struct ip6_ext *ip6e;
	uint8_t frag_l3_len, frag_last_pcol;

	/*
	 * Scan headers to get the last non-frag ext hdr.
	 */
	ip6e = dp_test_ipv6_scan_non_frag_hdrs(pkt_out,
					       &frag_l3_len,
					       &frag_last_pcol);
	if (ip6e) {
		nxt_proto = ip6e->ip6e_nxt;
		ip6e->ip6e_nxt = IPPROTO_FRAGMENT;
	} else {
		nxt_proto = dst->proto;
		dst->proto = IPPROTO_FRAGMENT;
	}

	offlg = fofs | (mf ? 1 : 0);

	fh = (struct ip6_frag *)((char *)dst + l3_len);
	fh->ip6f_nxt = nxt_proto;
	fh->ip6f_offlg = htons(offlg);
	fh->ip6f_reserved = 0;
	fh->ip6f_ident = htonl(fh_id);
}

/*
 * Fragment an IPv6 packet, and store resulting fragments in the
 * pkts_out array.  Returns number of fragments created on success, <
 * 0 on error.  Handles packets with or without an l2 header.  Handles
 * packets with non-fragmentable extension headers.
 */
int
dp_test_ipv6_fragment_packet(struct rte_mbuf *pkt_in,
			     struct rte_mbuf **pkts_out,
			     uint16_t nb_pkts_out,
			     const uint16_t *frag_size,
			     uint32_t fh_id)
{
	struct ip6_hdr *ip6;
	uint32_t pkt_len;
	char *buf;

	if (pkt_in->l3_len < sizeof(struct ipv6_hdr))
		return -EINVAL;

	/* Check header length matches mbuf pkt_len */
	ip6 = dp_pktmbuf_mtol3(pkt_in, struct ip6_hdr *);
	pkt_len = ntohs(ip6->ip6_plen) + pkt_in->l2_len + sizeof(struct ip6_hdr);

	if (pkt_len != pkt_in->pkt_len)
		return -EINVAL;

	int hlen = pkt_in->l2_len + pkt_in->l3_len;
	uint16_t in_plen = pkt_in->pkt_len - hlen;

	/*
	 * Efficiency is not an issue, so copy input mbuf chain into a
	 * temporary buffer to give a single contiguous packet, and
	 * thus greatly simplify this function.
	 */
	buf = dp_test_cp_mbuf_to_buf(pkt_in, NULL);
	if (!buf)
		return -ENOMEM;

	int i, rv;
	int offset = 0;
	uint16_t out_pkt_pos = 0;
	char *payload = buf + hlen;
	int bytes_remaining = in_plen;

	while (bytes_remaining) {
		struct rte_mbuf *out_pkt;
		uint16_t plen;

		if (out_pkt_pos >= nb_pkts_out) {
			rv = -EINVAL;
			goto error;
		}

		out_pkt = pktmbuf_alloc(pkt_in->pool, pktmbuf_get_vrf(pkt_in));
		if (!out_pkt) {
			rv = -ENOMEM;
			goto error;
		}

		/*
		 * plen is the number of bytes copied from input pkt
		 * payload to fragment mayload
		 */
		if (bytes_remaining < frag_size[out_pkt_pos]) {
			rv = -EINVAL;
			goto error;
		}
		plen = frag_size[out_pkt_pos];
		bytes_remaining -= plen;

		if (pkt_in->l2_len > 0) {
			/* Copy l2 header */
			char *src = rte_pktmbuf_mtod(pkt_in, char *);
			char *dst = rte_pktmbuf_append(out_pkt,
						       pkt_in->l2_len);

			memcpy(dst, src, pkt_in->l2_len);
			out_pkt->l2_len = pkt_in->l2_len;
		}

		/* Append space for IPv6 and fragmentation headers */
		rte_pktmbuf_append(out_pkt, pkt_in->l3_len +
				   sizeof(struct ip6_frag));

		/* Copy IPv6 hdr, and populate frag hdr */
		dp_test_fill_ipv6hdr_frag(pkt_in, out_pkt,
					  plen, offset,
					  bytes_remaining > 0, fh_id);

		/* Append space to fragment, and write fragment payload */
		memcpy(rte_pktmbuf_append(out_pkt, plen), payload + offset,
		       plen);
		offset += plen;

		/* Write the fragment to the output list */
		pkts_out[out_pkt_pos] = out_pkt;
		out_pkt_pos++;
	}

	free(buf);
	return out_pkt_pos;
error:
	for (i = 0; i < out_pkt_pos; i++)
		rte_pktmbuf_free(pkts_out[i]);
	free(buf);
	return rv;
}

/*
 * Insert 'len' bytes into a packet at 'offs' bytes from start of
 * packet. Update data_len and pkt_len.  Currently only handles simple
 * case of inserting bytes into first mbuf.
 */
char *
dp_test_pktmbuf_insert(struct rte_mbuf *m, uint16_t offs, uint16_t len)
{
	/*
	 * Is there space to move the packet up 'len' bytes?
	 */
	if (len > rte_pktmbuf_tailroom(m))
		return NULL;

	/*
	 * Move data up
	 */
	char *src = rte_pktmbuf_mtod(m, char *) + offs;
	char *dst = src + len;

	memmove(dst, src, m->data_len - offs);
	m->data_len += len;
	m->pkt_len += len;

	return src;
}

/*
 * Append an IPv6 non-fragmentable extension header to after the last
 * non-frag ext hdr.
 */
struct ip6_ext *
dp_test_ipv6_append_non_frag_ext_hdr(struct rte_mbuf *m,
				     uint8_t proto, uint16_t len)
{
	struct ip6_ext *last_ext, *new_ext;
	uint8_t frag_l3_len, frag_last_pcol, nxt_proto;
	uint16_t plen;
	struct ip6_hdr *ip6;

	/*
	 * Scan headers to get the last non-frag ext hdr.
	 */
	last_ext = dp_test_ipv6_scan_non_frag_hdrs(m,
						   &frag_l3_len,
						   &frag_last_pcol);
	if (frag_l3_len != m->l3_len)
		return NULL;

	ip6 = dp_pktmbuf_mtol3(m, struct ip6_hdr *);

	/* Insert space between last ext hdr and l4 hdr */
	new_ext = (struct ip6_ext *)dp_test_pktmbuf_insert(m,
				    m->l2_len + m->l3_len, len);

	/*
	 * Update last ext header
	 */
	if (last_ext) {
		nxt_proto = last_ext->ip6e_nxt;
		last_ext->ip6e_nxt = proto;
	} else {
		nxt_proto = ip6->ip6_nxt;
		ip6->ip6_nxt = proto;
	}

	/* Write new hdr proto and len fields */
	new_ext->ip6e_nxt = nxt_proto;
	dp_test_non_frag_ext_hdr_set_len(new_ext, proto, len);

	/* Update IPv6 payload length and mbuf l3_len */
	m->l3_len += len;
	plen = ntohs(ip6->ip6_plen) + len;
	ip6->ip6_plen = htons(plen);

	return new_ext;
}

/*
 * Fragment an IPv4 packet, and store resulting fragments in the
 * pkts_out array.  Returns number of fragments created on success, <
 * 0 on error.  Handles packets with or without an l2 header.
 */
int
dp_test_ipv4_fragment_packet(struct rte_mbuf *pkt_in,
			     struct rte_mbuf **pkts_out,
			     uint16_t nb_pkts_out,
			     const uint16_t *frag_size,
			     uint32_t fh_id __unused)
{
	struct iphdr *ip;
	uint32_t pkt_len;
	char *buf;

	if (pkt_in->l3_len < sizeof(struct iphdr))
		return -EINVAL;

	/* Check header length matches mbuf pkt_len */
	ip = dp_pktmbuf_mtol3(pkt_in, struct iphdr *);
	pkt_len = ntohs(ip->tot_len) + pkt_in->l2_len;

	if (pkt_len != pkt_in->pkt_len)
		return -EINVAL;

	int hlen = pkt_in->l2_len + pkt_in->l3_len;
	uint16_t in_plen = pkt_in->pkt_len - hlen;

	/*
	 * Efficiency is not an issue, so copy input mbuf chain into a
	 * temporary buffer to give a single contiguous packet, and
	 * thus greatly simplify this function.
	 */
	buf = dp_test_cp_mbuf_to_buf(pkt_in, NULL);
	if (!buf)
		return -ENOMEM;

	int i, rv;
	int offset = frag_size[nb_pkts_out - 1];
	uint16_t out_pkt_pos = 0;
	char *payload = buf + hlen;
	int bytes_remaining = in_plen;

	while (bytes_remaining) {
		struct rte_mbuf *out_pkt;
		uint16_t plen;

		if (out_pkt_pos >= nb_pkts_out) {
			rv = -EINVAL;
			goto error;
		}

		out_pkt = pktmbuf_alloc(pkt_in->pool, pktmbuf_get_vrf(pkt_in));
		if (!out_pkt) {
			rv = -ENOMEM;
			goto error;
		}

		/*
		 * plen is the number of bytes copied from input pkt
		 * payload to fragment mayload
		 */
		if (bytes_remaining < frag_size[out_pkt_pos]) {
			rv = -EINVAL;
			goto error;
		}
		plen = frag_size[out_pkt_pos];
		bytes_remaining -= plen;

		if (pkt_in->l2_len > 0) {
			/* Copy l2 header */
			char *src = rte_pktmbuf_mtod(pkt_in, char *);
			char *dst = rte_pktmbuf_append(out_pkt, pkt_in->l2_len);

			memcpy(dst, src, pkt_in->l2_len);
			out_pkt->l2_len = pkt_in->l2_len;
		}

		struct iphdr *src_ip, *dst_ip;

		/* Append space for IP header, and copy */
		src_ip = dp_pktmbuf_mtol3(pkt_in, struct iphdr *);
		dst_ip = (struct iphdr *)rte_pktmbuf_append(out_pkt,
							    pkt_in->l3_len);
		memcpy(dst_ip, src_ip, pkt_in->l3_len);
		out_pkt->l3_len = pkt_in->l3_len;

		/* first part of fragment is sent last */
		if (out_pkt_pos == nb_pkts_out - 1)
			offset = 0;

		/* Fixup IP header */
		dst_ip->frag_off = htons(offset >> 3) |
			(dst_ip->frag_off & htons(0xE000));
		if (out_pkt_pos != nb_pkts_out - 2)
			dst_ip->frag_off |= htons(IP_MF);
		dst_ip->tot_len = htons(plen + out_pkt->l3_len);
		dst_ip->check = 0;
		dst_ip->check = rte_ipv4_cksum((const struct ipv4_hdr *)dst_ip);

		/* Append space to fragment, and write fragment payload */
		memcpy(rte_pktmbuf_append(out_pkt, plen), payload + offset,
		       plen);
		offset += plen;

		/* Write the fragment to the output list */
		pkts_out[out_pkt_pos] = out_pkt;
		out_pkt_pos++;
	}

	free(buf);
	return out_pkt_pos;
error:
	for (i = 0; i < out_pkt_pos; i++)
		rte_pktmbuf_free(pkts_out[i]);
	free(buf);
	return rv;
}

void
dp_test_set_pak_ip_field(struct iphdr *ip,
			 enum dp_test_pak_field_ field,
			 uint32_t val)
{
	uint16_t frag_flags;

	switch (field) {
	case DP_TEST_SET_VERSION:
		ip->version = val;
		break;
	case DP_TEST_SET_SRC_ADDR_IPV4:
		ip->saddr = val;
		break;

	case DP_TEST_SET_DST_ADDR_IPV4:
		ip->daddr = val;
		break;

	case DP_TEST_SET_IP_ECN:
		/* last 2 bits of tos field. */
		ip->tos &= ~IPTOS_ECN_MASK;
		ip->tos |= (val & IPTOS_ECN_MASK);
		break;

	case DP_TEST_SET_DF:
		if (val)
			ip->frag_off |= htons(IP_DF);
		else
			ip->frag_off &= ~IP_DF;
		break;

	case DP_TEST_SET_FRAG_MORE:
		if (val)
			ip->frag_off |= htons(IP_MF);
		else
			ip->frag_off &= ~IP_MF;
		break;

	case DP_TEST_SET_FRAG_OFFSET:
		frag_flags = (ip->frag_off & htons(0xE000));
		/* 3 MSB (network) of field are flags which we don't set */
		ip->frag_off = htons((uint16_t)val);
		ip->frag_off |= frag_flags;
		break;

	case DP_TEST_SET_TOS:
		ip->tos = (uint8_t)val;
		break;

	case DP_TEST_SET_TTL:
		ip->ttl = (uint8_t)val;
		break;

	case DP_TEST_SET_PROTOCOL:
		ip->protocol = (uint8_t)val;
		break;

	case DP_TEST_SET_IP_ID:
		ip->id = htons((uint16_t)val);
	}
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
}

void
dp_test_set_pak_ip6_field(struct ip6_hdr *ip6,
			 enum dp_test_pak_field_ field,
			 uint32_t val)
{
	uint32_t flow = ntohl(ip6->ip6_flow);

	switch (field) {
	case DP_TEST_SET_TOS:
		/* last 2 bits of tos field */
		flow &= ~IPV6_FLOW_TOS;
		flow |= ((uint8_t)val) << 20;
		ip6->ip6_flow = htonl(flow);
		break;
	default:
		/* Not handled yet */
		return;
	}
}

/*
 * Take an mbuf and get the value of a field in an IPv4 or IPv6 header.
 * Addresses are returned in ip_addr, otherwise the value is returned
 * in val.
 */
static void
dp_test_get_pak_eth_ip_field(const struct rte_mbuf *m,
			     enum dp_test_pak_field_ip field,
			     struct dp_test_addr *ip_addr, uint32_t *val)
{
	struct ether_hdr *eth;
	struct ip6_hdr *ip6h;
	struct iphdr *iph;

	assert(m->l2_len == sizeof(struct ether_hdr));
	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	switch (ntohs(eth->ether_type)) {
	case ETHER_TYPE_IPv4:
		assert(m->l3_len >= sizeof(struct iphdr));
		iph = iphdr(m);
		assert(m->l3_len == iph->ihl * 4);
		switch (field) {
		case DP_TEST_GET_SRC_ADDR:
			ip_addr->family = AF_INET;
			ip_addr->addr.ipv4 = iph->daddr;
			return;
		case DP_TEST_GET_DST_ADDR:
			ip_addr->family = AF_INET;
			ip_addr->addr.ipv4 = iph->daddr;
			return;
		case DP_TEST_GET_TOS:
			*val = iph->tos;
			return;
		case DP_TEST_GET_PROTOCOL:
			*val = iph->protocol;
			return;
		default:
			assert(false);
		}
		break;
	case ETHER_TYPE_IPv6:
		assert(m->l3_len >= sizeof(struct ip6_hdr));
		ip6h = (struct ip6_hdr *)((uintptr_t)eth + sizeof(*eth));
		switch (field) {
		case DP_TEST_GET_SRC_ADDR:
			ip_addr->family = AF_INET6;
			memcpy(&ip_addr->addr.ipv6, &ip6h->ip6_src,
			       sizeof(struct in6_addr));
			return;
		case DP_TEST_GET_DST_ADDR:
			ip_addr->family = AF_INET6;
			memcpy(&ip_addr->addr.ipv6, &ip6h->ip6_dst,
			       sizeof(struct in6_addr));
			return;
		case DP_TEST_GET_TOS:
			*val = ((ntohl(ip6h->ip6_flow) & DP_PKTMBUF_IPV6_FINFO)
				>> 20);
			return;
		case DP_TEST_GET_PROTOCOL:
			*val = ip6h->ip6_nxt;
			return;
		default:
			assert(false);
		}
		break;
	default:
		break;
	}
	assert(false);
}

void
dp_test_get_pak_eth_ip_field_addr(const struct rte_mbuf *m,
				  enum dp_test_pak_field_ip field,
				  struct dp_test_addr *ip_addr)
{
	assert(field == DP_TEST_GET_SRC_ADDR
	       || field == DP_TEST_GET_DST_ADDR);
	dp_test_get_pak_eth_ip_field(m, field, ip_addr, NULL);
}

void
dp_test_get_pak_eth_ip_field_u32(const struct rte_mbuf *m,
				 enum dp_test_pak_field_ip field,
				 uint32_t *u32_val)
{
	assert(field == DP_TEST_GET_TOS);
	dp_test_get_pak_eth_ip_field(m, field, NULL, u32_val);
}

void
dp_test_get_pak_eth_ip_field_u8(const struct rte_mbuf *m,
				enum dp_test_pak_field_ip field,
				uint8_t *u8_val)
{
	uint32_t u32_val;

	assert(field == DP_TEST_GET_TOS);
	dp_test_get_pak_eth_ip_field(m, field, NULL, &u32_val);
	*u8_val = (uint8_t)u32_val;
}

/*
 * Decrement TTL and recalculate checksum
 */
void
dp_test_ipv4_decrement_ttl(struct rte_mbuf *m)
{
	struct iphdr *ip;

	if (!m)
		return;
	ip = iphdr(m);
	ip->ttl = ip->ttl - 1;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
}

void
dp_test_ipv6_decrement_ttl(struct rte_mbuf *m)
{
	struct ip6_hdr *ip6;

	if (!m)
		return;
	ip6 = dp_pktmbuf_mtol3(m, struct ip6_hdr *);
	ip6->ip6_hlim = ip6->ip6_hlim - 1;
}

/*
 * Change the TOS value and recalculate checksum
 */
void
dp_test_ipv4_remark_tos(struct rte_mbuf *m, unsigned char tos)
{
	struct iphdr *ip;

	if (!m)
		return;
	ip = iphdr(m);
	ip->tos = tos;
	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl * 4);
}

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
				uint16_t ether_type, char *data, int len)
{
	struct rte_mbuf *m;
	struct ether_hdr *eth;

	m = dp_test_create_mbuf_chain(1, &len, 0);
	if (!m)
		return NULL;

	/* Copy data to the packet */
	if (dp_test_pktmbuf_payload_init(m, 0, data, len) == 0) {
		rte_pktmbuf_free(m);
		return NULL;
	}

	m->l2_len = 14;

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	/* Optionally overwrite ethernet header */
	if (d_addr && s_addr) {
		ether_aton_r(d_addr, &eth->d_addr);
		ether_aton_r(s_addr, &eth->s_addr);

		if (ether_type != 0)
			eth->ether_type = htons(ether_type);
	}

	/*
	 * If the data is the output of Wireshark 'Copy -> Bytes -> Hex data'
	 * then the IP header checksum will be zero.  Set it here regardless.
	 */

	if (eth->ether_type == htons(ETHER_TYPE_IPv4)) {
		/* Set IP checksum (its zero in hex stream from Wireshark) */
		struct iphdr *ip;

		ip = (struct iphdr *)(rte_pktmbuf_mtod(m, char *) + m->l2_len);
		ip->check = 0;
		ip->check = rte_ipv4_cksum((const struct ipv4_hdr *)ip);
	}

	return m;
}

/*
 * Read a Wireshark 'offset hex text' packet export (Copy -> Bytes) into an
 * allocated array.  Returns pointer to the allocated array, and the length of
 * array in '*len'.  Caller should free the array once it is finished with.
 *
 * The input file contents should be of the form:
 *
 * 0000   52 54 00 1a a1 53 02 0c ca a5 07 49 08 00 45 00  RT...S.....I..E.
 * 0010   01 db bb ab 00 00 80 11  fa 12 c0 a8 01 01 c0 a8  ........ ........
 * ...
 * 01f0   50 43 4d 55 2f 38 30 30 30 0d 0a                 PCMU/8000..
 */
#define LINE_LEN_MAX         80
#define HEX_PAIRS_PER_LINE   16

static char *
dp_test_read_wireshark_oht_from_file(const char *filename, uint *len)
{
	FILE *fp = fopen(filename, "r");
	char *data = NULL;
	long bufsize;

	if (fp == NULL)
		return NULL;

	/* Go to the end of the file. */
	if (fseek(fp, 0L, SEEK_END) < 0)
		goto error;

	/* Get the size of the file. */
	bufsize = ftell(fp);

	if (bufsize == -1)
		goto error;

	/* Go back to the start of the file. */
	if (fseek(fp, 0L, SEEK_SET) != 0)
		goto error;

	/*
	 * Simply allocate an array thats half the size of the file buffer
	 * size.
	 */
	uint datasize = (uint)bufsize / 2;
	data = calloc(1, datasize);
	if (!data)
		goto error;

	char line[LINE_LEN_MAX + 1];
	uint dcount = 0;
	char *endptr;
	uint line_len;
	uint i, j, k;

	while (fgets(line, sizeof(line), fp) != NULL) {

		if (dcount + HEX_PAIRS_PER_LINE > datasize)
			goto error;

		line_len = strlen(line);
		i = 0;

		/* Find space after offset */
		while (i < line_len && line[i] != ' ')
			i++;

		/* Move past space */
		while (i < line_len && line[i] == ' ')
			i++;

		for (j = 0; j < HEX_PAIRS_PER_LINE; j++) {

			if (i + 1 >= line_len)
				goto error;

			if (line[i] == ' ')
				break;

			char buf[5] = {'0', 'x', line[i], line[i+1], 0};

			data[dcount++] = strtol(buf, &endptr, 0);

			if (endptr[0] != '\0')
				/* non-hexadecimal character encountered */
				goto error;

			i += 2; /* Move past the two chars just read */

			/*
			 * Move past a maximum of 'n' space characters.
			 * We limit 'n' to 3 so that we dont increment to the
			 * ascii chars at the end of the line.
			 */
			k = 0;
			while (i < line_len && line[i] == ' ' && k < 3) {
				i++;
				k++;
			}
		}
	}

	fclose(fp);

	*len = dcount;
	return data;

error:
	fclose(fp);
	if (data)
		free(data);
	return NULL;
}

/*
 * Read from a text file into an allocated buffer.  Returns a pointer to the
 * buffer. Caller should free the buffer once finished with it.  NULL
 * terminates the buffer.
 */
static char *
dp_test_read_text_file(const char *filename)
{
	char *data = NULL;
	FILE *fp = fopen(filename, "r");
	long bufsize;

	if (fp == NULL)
		return NULL;

	/* Go to the end of the file. */
	if (fseek(fp, 0L, SEEK_END) < 0)
		goto error;

	/* Get the size of the file. */
	bufsize = ftell(fp);

	if (bufsize == -1)
		goto error;

	/* Allocate our buffer to that size. */
	data = calloc(1, bufsize + 1);
	if (!data)
		goto error;

	/* Go back to the start of the file. */
	if (fseek(fp, 0L, SEEK_SET) != 0)
		goto error;

	/* Read the entire file into memory. */
	size_t new_len = fread(data, sizeof(char), bufsize, fp);

	if (new_len == 0)
		goto error;

	/* Remove any trailing newline character */
	if (data[new_len - 1] == '\n')
		new_len--;

	data[new_len] = '\0';

	fclose(fp);

	return data;

error:
	fclose(fp);
	if (data)
		free(data);
	return NULL;
}

/*
 * Convert a hex string to a byte array, up to a length of 'len'.  Return -1
 * if there is an error, else return the number of bytes written to the array.
 */
static int
dp_test_hex2data(char *data, const char *hexstring, uint len)
{
	const char *pos = hexstring;
	char *endptr;
	uint count;

	/* Check hexstring contains data and is not an odd length */
	if ((hexstring[0] == '\0') || (strlen(hexstring) % 2))
		return -1;

	for (count = 0; count < len && pos[0] != '\0'; count++) {
		char buf[5] = {'0', 'x', pos[0], pos[1], 0};
		data[count] = strtol(buf, &endptr, 0);
		pos += 2 * sizeof(char);

		if (endptr[0] != '\0')
			/* non-hexadecimal character encountered */
			return -1;
	}

	return count;
}

/*
 * Read a Wireshark 'hex stream' packet export into an allocated array.
 * Returns pointer to array, and length of array in '*len'.  Caller should
 * free the array.
 *
 * File contains a stream of hex characters:
 *
 * 5254001aa153020ccaa50749080045 ...
 */
static char *
dp_test_read_wireshark_hex_from_file(const char *filename, uint *len)
{
	char *hexstring, *hexdata = NULL;
	uint hlen, dlen, written;

	hexstring = dp_test_read_text_file(filename);
	if (!hexstring)
		return NULL;

	hlen = strlen(hexstring);

	/* We expect an even number of characters */
	if (hlen == 0 || (hlen & 1) != 0)
		goto error;

	dlen = hlen / 2;

	hexdata = calloc(1, dlen);
	if (!hexdata)
		goto error;

	written = dp_test_hex2data(hexdata, hexstring, dlen);

	if (written != dlen)
		goto error;

	free(hexstring);

	*len = dlen;
	return hexdata;

error:
	if (hexstring)
		free(hexstring);
	if (hexdata)
		free(hexdata);

	return NULL;
}

/*
 * Create a packet from a file.
 *
 * If d_addr and s_addr are non-NULL then the new packets eth header
 * destination and source MAC addresses are overwritten from these.  If the
 * ether_type is not zero, then that is also written.
 *
 * Supports two file types: Wireshark offset hext text and Wireshark hex
 * stream.
 */
struct rte_mbuf *
dp_test_create_l2_pak_from_file(const char *d_addr, const char *s_addr,
				uint16_t etype, const char *filename,
				enum dp_test_pak_filetype filetype)
{
	struct rte_mbuf *mbuf;
	char *hexdata = NULL;
	uint dlen = 0;

	switch (filetype) {
	case DP_TEST_FILE_WS_OHT:
		hexdata = dp_test_read_wireshark_oht_from_file(filename, &dlen);
		break;
	case DP_TEST_FILE_WS_HEX:
		hexdata = dp_test_read_wireshark_hex_from_file(filename, &dlen);
		break;
	}

	if (!hexdata)
		return NULL;

	if (dlen == 0) {
		free(hexdata);
		return NULL;
	}

	mbuf = dp_test_create_l2_pak_from_data(d_addr, s_addr, etype, hexdata,
					       dlen);
	free(hexdata);

	return mbuf;
}

bool dp_test_mbuf_is_ipv4(struct rte_mbuf *m)
{
	struct iphdr *iph = iphdr(m);

	return iph->version == 4;
}

bool dp_test_mbuf_is_ipv6(struct rte_mbuf *m)
{
	struct ip6_hdr *ip6h = ip6hdr(m);

	return (ip6h->ip6_vfc & 0xf0) == 0x60;
}

static uint16_t
dp_test_mbuf_ethertype(struct rte_mbuf *pak)
{
	struct ether_hdr *eth;

	if (pak->l2_len < sizeof(struct ether_hdr))
		return 0;

	eth = rte_pktmbuf_mtod(pak, struct ether_hdr *);

	return ntohs(eth->ether_type);
}

bool
dp_test_mbuf_ethertype_is_ip(struct rte_mbuf *m)
{
	uint16_t ether_type = dp_test_mbuf_ethertype(m);

	return (ether_type == ETHER_TYPE_IPv4) ||
		(ether_type == ETHER_TYPE_IPv6);
}

bool
dp_test_mbuf_ethertype_is_mpls(struct rte_mbuf *m)
{
	uint16_t ether_type = dp_test_mbuf_ethertype(m);

	return (ether_type == ETHER_TYPE_MPLS);
}

struct ether_arp {
	struct	arphdr ea_hdr;		/* fixed-size header */
	struct ether_addr arp_sha;      /* sender hardware address */
	in_addr_t arp_spa;		/* sender protocol address */
	struct ether_addr arp_tha;      /* target hardware address */
	in_addr_t arp_tpa;		/* target protocol address */
} __attribute__ ((__packed__));

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
		       uint16_t vlan_id)
{
	struct rte_mbuf  *pak;
	struct ether_hdr *eth;
	struct ether_arp *arp;
	in_addr_t         ipaddr;
	int               len = 0;

	pak = dp_test_create_mbuf_chain(1, &len, sizeof(*arp));
	if (!pak)
		return NULL;

	eth = dp_test_pktmbuf_eth_init(pak, d_mac, s_mac, ETHER_TYPE_ARP);
	if (!eth) {
		rte_pktmbuf_free(pak);
		return NULL;
	}
	if (vlan_id)
		dp_test_pktmbuf_vlan_init(pak, vlan_id);

	arp = (struct ether_arp *) (eth+1);
	arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp->ea_hdr.ar_pro = htons(ETHER_TYPE_IPv4);
	arp->ea_hdr.ar_hln = ETHER_ADDR_LEN;
	arp->ea_hdr.ar_pln = sizeof(in_addr_t);
	arp->ea_hdr.ar_op = htons(op);
	if (ether_aton_r(sha, &arp->arp_sha) == NULL)
		return NULL;

	if (ether_aton_r(tha, &arp->arp_tha) == NULL)
		return NULL;

	if (dp_test_inet_pton(AF_INET, spa_addr, &ipaddr) != 1)
		return NULL;

	arp->arp_spa = ipaddr;

	if (dp_test_inet_pton(AF_INET, tpa_addr, &ipaddr) != 1)
		return NULL;

	arp->arp_tpa = ipaddr;

	return pak;
}
