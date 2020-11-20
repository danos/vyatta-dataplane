/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <stdint.h>
/*
 * Equal-cost multi-path routing
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/mpls.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "commands.h"
#include "ecmp.h"
#include "if_var.h"
#include "ip_forward.h"
#include "ip_funcs.h"
#include "json_writer.h"
#include "mpls/mpls.h"
#include "mpls/mpls_forward.h"
#include "netinet6/in6.h"
#include "pktmbuf_internal.h"
#include "util.h"
#include "vplane_log.h"

/* Global ECMP mode */
static uint8_t ecmp_mode = ECMP_HRW;

/* ECMP modes */
static const char *ecmp_modes[ECMP_MAX] = {
	[ECMP_DISABLED]		= "disable",
	[ECMP_HASH_THRESHOLD]	= "hash-threshold",
	[ECMP_HRW]		= "hrw",
	[ECMP_MODULO_N]		= "modulo-n",
};

/*
 * All of the common L4 transport protocols (TCP/UDP/SCTP/UDP-Lite/DCCP)
 * have their port numbers at the same offset.  Also ESP has a 32 bit
 * SPI field there which can serve the same purpose.
 */
static uint32_t l4_key(const struct rte_mbuf *m, unsigned int l4offs,
		       uint8_t proto)
{
	const void *l4hdr = rte_pktmbuf_mtod(m, const char *) + l4offs;

	if (unlikely(rte_pktmbuf_data_len(m) < l4offs + sizeof(uint32_t)))
		return 0;

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ESP:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
	case IPPROTO_UDPLITE:
		return *(const uint32_t *)l4hdr;

	default:
		return 0;
	}
}

uint32_t ecmp_iphdr_hash(const struct iphdr *ip, uint32_t l4key)
{
	return rte_jhash_3words(ip->saddr, ip->daddr, l4key, ip->protocol);
}

uint32_t ecmp_ipv4_hash(const struct rte_mbuf *m, unsigned int l3offs)
{
	const struct iphdr *ip = (const struct iphdr *)
		(rte_pktmbuf_mtod(m, const char *) + l3offs);
	unsigned int l4offs = l3offs + (ip->ihl << 2);
	uint32_t l4key = ip_is_fragment(ip) ? ip->id : l4_key(m, l4offs,
							      ip->protocol);
	return ecmp_iphdr_hash(ip, l4key);
}

uint32_t ecmp_ip6hdr_hash(const struct ip6_hdr *ip6, uint32_t l4_key)
{
	uint32_t hkey[9];

	memcpy(hkey,     &ip6->ip6_src, sizeof(struct in6_addr));
	memcpy(hkey + 4, &ip6->ip6_dst, sizeof(struct in6_addr));

	/* RFC 6437 - Flow label spec. If set do not look further.  */
	hkey[8] = l4_key;

	return rte_jhash_32b(hkey, 9, ip6->ip6_nxt);
}

uint32_t ecmp_ipv6_hash(const struct rte_mbuf *m, unsigned int l3offs)
{
	const struct ip6_hdr *ip6 = (const struct ip6_hdr *)
		(rte_pktmbuf_mtod(m, const char *) + l3offs);
	unsigned int l4offs = l3offs + sizeof(*ip6);
	uint32_t flow = ip6->ip6_flow & IPV6_FLOWLABEL_MASK;

	return ecmp_ip6hdr_hash(ip6, flow ? : l4_key(m, l4offs, ip6->ip6_nxt));
}

/*
 * Weighted random function
 * Based on original Highest Random Weight paper:
 *   Thaler, David; Chinya Ravishankar.
 *   "A Name-Based Mapping Scheme for Rendezvous".
 *   University of Michigan Technical Report CSE-TR-316-96
 */
static uint32_t wrand2(uint32_t key, uint32_t i)
{
	const uint32_t a = 1103515245;
	const uint32_t b = 12345;
	const uint32_t m = (1u << 31) - 1;

	return (a * ((a * (key & m) + b) ^ i) + b) & m;
}

static unsigned int ecmp_hrw(uint32_t key, uint32_t size)
{
	unsigned int nxt, selected = 0;
	uint32_t hweight = wrand2(key, 0);

	for (nxt = 1; nxt < size; nxt++) {
		uint32_t weight = wrand2(key, nxt);
		if (weight > hweight) {
			hweight = weight;
			selected = nxt;
		}
	}

	return selected;
}

/*
 * Calculate flow key based protocols fields
 */
ALWAYS_INLINE uint32_t
ecmp_mbuf_hash(const struct rte_mbuf *m, uint16_t ether_type)
{
	if (!m)
		return 0;

	if (ether_type == ETH_P_MPLS_UC)
		return mpls_ecmp_hash(m);
	if (ether_type == RTE_ETHER_TYPE_IPV6)
		return ecmp_ipv6_hash(m, dp_pktmbuf_l2_len(m));
	return ecmp_ipv4_hash(m, dp_pktmbuf_l2_len(m));
}

static unsigned int
ecmp_lookup_alg(enum ecmp_modes ecmp_alg, uint32_t size, uint32_t key)
{
	switch (ecmp_alg) {
	case ECMP_HASH_THRESHOLD:
		return key / (UINT32_MAX / size);

	case ECMP_HRW:
		return ecmp_hrw(key, size);

	case ECMP_MODULO_N:
		return key % size;

	default:
		return 0;
	}
}

/*
 * ECMP nexthop lookup based on configured algorithm
 */
unsigned int ecmp_lookup(uint32_t size, uint32_t key)
{
	return ecmp_lookup_alg(ecmp_mode, size, key);
}

static void ecmp_show(json_writer_t *json)
{
	jsonw_string_field(json, "mode", ecmp_modes[ecmp_mode]);
	jsonw_uint_field(json, "max-path", UINT16_MAX);
}

static int ecmp_set_mode(const char *mode)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ecmp_modes); i++) {
		const char *name = ecmp_modes[i];

		if (name && strcmp(mode, name) == 0) {
			ecmp_mode = i;
			return 0;
		}
	}

	return -1;
}

#define ECMP_MODES \
	"hash-threshold|hrw|modulo-n|disable"

#define CMD_ECMP_USAGE                     \
	"Usage: ecmp show\n"               \
"       ecmp mode <"ECMP_MODES">\n"

/*
 * Commands:
 *      ecmp show - show ecmp options
 *      ecmp mode - set ecmp mode
 */
int cmd_ecmp(FILE *f, int argc, char **argv)
{
	json_writer_t *json;

	if (argc == 3 && !strcmp(argv[1], "mode")) {
		if (strstr(ECMP_MODES, argv[2]))
			return ecmp_set_mode(argv[2]);
	} else if (argc == 2 && !strcmp(argv[1], "show")) {
		json = jsonw_new(f);
		jsonw_name(json, "ecmp_show");
		jsonw_start_object(json);
		ecmp_show(json);
		jsonw_end_object(json);
		jsonw_destroy(&json);
		return 0;
	}

	fprintf(f, CMD_ECMP_USAGE);
	return -1;
}

uint32_t dp_ecmp_hash(const struct ecmp_hash_param *hash_param)
{
	struct iphdr iph;
	struct ip6_hdr ip6h;
	uint32_t hash = 0;
	uint32_t l4key = htonl((hash_param->src_port << 16) |
				hash_param->dst_port);

	if (hash_param->src_ip.type == hash_param->dst_ip.type) {
		if (hash_param->src_ip.type == AF_INET) {
			iph.saddr = hash_param->src_ip.address.ip_v4.s_addr;
			iph.daddr = hash_param->dst_ip.address.ip_v4.s_addr;
			iph.protocol = hash_param->protocol;
			hash = ecmp_iphdr_hash(&iph, l4key);
		} else if (hash_param->src_ip.type == AF_INET6) {
			ip6h.ip6_src = hash_param->src_ip.address.ip_v6;
			ip6h.ip6_dst = hash_param->dst_ip.address.ip_v6;
			ip6h.ip6_nxt = hash_param->protocol;
			hash = ecmp_ip6hdr_hash(&ip6h, l4key);
		}
	}
	return hash;
}
