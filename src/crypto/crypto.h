/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <linux/xfrm.h> // conflicts with netinet/in.h
#include <linux/types.h>

#include "util.h"
#include "vrf_internal.h"

struct iphdr;
struct udphdr;

#define ESP_PORT 4500
#define IKE_PORT 500

struct ifnet;
struct rte_mbuf;

struct crypto_fragment_ctx {
	xfrm_address_t *dst;
	struct ifnet *in_ifp;
	uint8_t orig_family;
	uint8_t family;
	uint32_t reqid;
	int pmd_dev_id;
	uint32_t spi;
};

/*
 *
 * TODO: Where should we get this from? Why doesn't
 * netinet/in.h provide it? This comes from linux/in.h,
 * but you can't include both
 */
struct ip_esp_hdr {
	__be32 spi;
	__be32 seq_no;		/* Sequence number */
	__u8  enc_data[0];	/* Variable len but >=8.  Mind the 64
				 * bit alignment!
				 */
};

static inline
int crypto_retrieve_spi(unsigned char *data)
{
	struct ip_esp_hdr *esp =
		(struct ip_esp_hdr *)data;
	return esp->spi;
}

void crypto_enqueue_fragment(struct ifnet *ifp, struct rte_mbuf *m, void *ctx);
int crypto_enqueue_inbound_v4(struct rte_mbuf *m, const struct iphdr *ip,
			      struct ifnet *input_if, uint32_t spi);
int crypto_enqueue_inbound_v6(struct rte_mbuf *m, struct ifnet *input_if,
			      uint32_t spi);
void crypto_enqueue_outbound(struct rte_mbuf *m, uint16_t orig_family,
			     uint16_t family,
			     xfrm_address_t *dst, struct ifnet *in_ifp,
			     struct ifnet *nxt_ifp, uint32_t reqid,
			     int pmd_dev_id, uint32_t spi);
int udp_esp_dp(struct rte_mbuf *m, void *ip,
	       struct udphdr *udp, struct ifnet *ifp);
int udp_esp_dp6(struct rte_mbuf *m, void *ip,
		struct udphdr *udp, struct ifnet *ifp);

void crypto_sadb_show_summary(FILE *f, vrfid_t vrfid);
void crypto_policy_show_summary(FILE *f, vrfid_t vrfid, bool brief);
void crypto_policy_bind_show_summary(FILE *f, vrfid_t vrfid);
void crypto_show_summary(FILE *f);
void crypto_add_listener(const char *url);
void crypto_show_pmd(FILE *f);
void crypto_sadb_show_spi_mapping(FILE *f, vrfid_t vrfid);
int crypto_engine_set(uint8_t *bytes, uint8_t len);
int crypto_engine_probe(FILE *f);
void crypto_show_cache(FILE *f, const char *str);
int crypto_flow_cache_init_lcore(unsigned int lcore_id);
int crypto_flow_cache_teardown_lcore(unsigned int lcore_id);
int crypto_flow_cache_init(void);
unsigned long hash_xfrm_address(const xfrm_address_t *addr,
				const uint16_t family);
uint8_t crypto_sa_alloc_fwd_core(void);
void crypto_sa_free_fwd_core(uint8_t fwd_core);

#endif /* CRYPTO_H */
