/*
 * Public functions defined in ip_icmp.c
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef IP_ICMP_H
#define IP_ICMP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct ifnet;
struct rte_mbuf;

bool ip_same_network(const struct ifnet *ifp, in_addr_t nxt_gateway,
		     in_addr_t addr);
in_addr_t ip_select_source(const struct ifnet *ifp, in_addr_t dst);
void ip_redirects_set(bool enable);
bool ip_redirects_get(void);
void icmp_error(const struct ifnet *rcvif, struct rte_mbuf *n,
		   int type, int code, uint32_t info)
	 __attribute__((cold));
void icmp_error_out(const struct ifnet *rcvif, struct rte_mbuf *n,
			int type, int code, uint32_t info,
			const struct ifnet *outif)
	__attribute__((cold));
struct rte_mbuf *icmp_do_error(struct rte_mbuf *n, int type, int code,
				uint32_t info, const struct ifnet *in,
				const struct ifnet *out);
int icmp_do_exthdr(struct rte_mbuf *m, uint16_t class, uint8_t ctype, void *buf,
			unsigned int len);
void icmp_prepare_send(struct rte_mbuf *m);

#endif
