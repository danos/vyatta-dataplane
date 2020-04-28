/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef RTE_ECMP_H
#define RTE_ECMP_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>

#include "nh_common.h"

struct nlattr;

/* Global ECMP max path param */
extern uint16_t ecmp_max_path;

/* ECMP modes */
enum ecmp_modes {
	ECMP_DISABLED,
	ECMP_HASH_THRESHOLD,
	ECMP_HRW,
	ECMP_MODULO_N,
	ECMP_MAX
};

uint32_t ecmp_iphdr_hash(const struct iphdr *ip, uint32_t l4key);
uint32_t ecmp_ipv4_hash(const struct rte_mbuf *m, unsigned int l3offs);
uint32_t ecmp_ip6hdr_hash(const struct ip6_hdr *ip6, uint32_t l4_key);
uint32_t ecmp_ipv6_hash(const struct rte_mbuf *m, unsigned int l3offs);
uint32_t ecmp_mbuf_hash(const struct rte_mbuf *m, uint16_t ether_type);

unsigned int ecmp_lookup(uint32_t size, uint32_t key);

struct next_hop *ecmp_create(struct nlattr *mpath, uint32_t *count,
			     bool *missing_ifp);
struct next_hop *ecmp6_create(struct nlattr *mpath, uint32_t *count,
			      bool *missing_ifp);
struct next_hop *ecmp_mpls_create(struct nlattr *mpath, uint32_t *count,
				  enum nh_type *nh_type,
				  bool *missing_ifp);

#endif
