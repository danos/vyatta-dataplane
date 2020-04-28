/*
 * MPLS Forwarding
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef MPLS_FORWARD_H
#define MPLS_FORWARD_H

#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>

#include "if_var.h"
#include "mpls.h"
#include "nh_common.h"

struct ifnet;
struct rte_mbuf;

#define ETH_P_MPLS_UC 0x8847    /* MPLS Unicast traffic   */
#define ETH_P_MPLS_MC 0x8848    /* MPLS Multicast traffic */

bool mpls_global_get_ipttlpropagate(void);
void mpls_global_set_ipttlpropagate(bool enable);
int mpls_global_get_defaultttl(void);
void mpls_global_set_defaultttl(int ttl);

uint32_t mpls_ecmp_hash(const struct rte_mbuf *m);

void mpls_labeled_input(struct ifnet *ifp, struct rte_mbuf *m)
	__attribute__((hot));
void mpls_unlabeled_input(struct ifnet *ifp, struct rte_mbuf *m,
			  enum nh_type nh_type,
			  struct next_hop *ip_nh, uint8_t ttl)
	__attribute__((hot));

#endif
