/*
 * Public functions defined in ip_icmp.c
 *
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
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

#include "compiler.h"

struct ifnet;
struct rte_mbuf;

bool ip_same_network(const struct ifnet *ifp, in_addr_t nxt_gateway,
		     in_addr_t addr);
in_addr_t ip_select_source(const struct ifnet *ifp, in_addr_t dst);
void ip_redirects_set(bool enable);
bool ip_redirects_get(void);
void icmp_error(const struct ifnet *rcvif, struct rte_mbuf *n,
		   int type, int code, uint32_t info)
	 __cold_func;
void icmp_error_out(const struct ifnet *rcvif, struct rte_mbuf *n,
			int type, int code, uint32_t info,
			const struct ifnet *outif)
	__cold_func;
struct rte_mbuf *icmp_do_error(struct rte_mbuf *n, int type, int code,
				uint32_t info, const struct ifnet *in,
				const struct ifnet *out);
int icmp_do_exthdr(struct rte_mbuf *m, uint16_t class, uint8_t ctype, void *buf,
			unsigned int len);
void icmp_prepare_send(struct rte_mbuf *m);
bool icmp_echo_reply_out(struct ifnet *rcvifp, struct rte_mbuf *n,
			 bool reflect);
void icmp_error_tos_set(uint8_t tos);
uint8_t icmp_error_tos_get(void);

int cmd_icmp_rl(FILE *f, int argc, char **argv);

#define ICMP_RATELIMIT_STATS_INTERVAL 20
#define NUM_INTERVALS_PER_MIN (60/ICMP_RATELIMIT_STATS_INTERVAL)
#define NUM_DROP_INTERVALS (300/ICMP_RATELIMIT_STATS_INTERVAL)

struct icmp_ratelimit_state;

void icmp_ratelimit_init(void);

/*
 * Test if we should drop generated ICMP packet
 */
bool icmp_ratelimit_drop(uint8_t type, struct icmp_ratelimit_state *rl, uint8_t entries);

struct icmp_ratelimit_state {
	char		*name;				/* type name */
	uint32_t	max_rate;			/* limit per sec */
	uint32_t	tokens;				/* remaining tokens for current second */
	uint32_t	total_sent;
	uint32_t	total_dropped;
	uint32_t	drop_stats[NUM_DROP_INTERVALS];	/* drop counts per stats interval */
	bool		limiting;			/* is rate limiting configured */
	bool		explicit;			/* limiting is explicit, not default */
};
#endif
