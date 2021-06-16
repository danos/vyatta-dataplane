/*
 * Copyright (c) 2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * TWAMP offload support, internal (private) definitions.
 */
#ifndef TWAMP_INTERNAL_H
#define TWAMP_INTERNAL_H

#include "urcu.h"
#include "ip_addr.h"

struct tw_hash_match_args {
	vrfid_t vrfid;
	const struct udphdr *udp;
	union {
		const struct iphdr *ip4;
		const struct ip6_hdr *ip6;
	};
};

struct tw_session {
	struct ip_addr laddr;
	struct ip_addr raddr;
	uint16_t lport;
	uint16_t rport;
	vrfid_t vrfid;
	uint64_t rx_bad;
	uint64_t rx_pkts;
	uint64_t tx_bad;
	uint64_t tx_pkts;
	uint32_t seqno;
	uint16_t rxpayloadlen;
	uint16_t txpayloadlen;
	uint8_t minrxpktsize;
	uint8_t mintxpktsize;
	uint8_t af;
	uint8_t mode;
	const char *dbgstr;
};

struct tw_session_entry {
	struct tw_session session;
	struct cds_lfht_node tw_node;
	struct rcu_head rcu;
};

extern struct cds_lfht *tw_session_table;

int twamp_hash_match_ipv4(struct cds_lfht_node *node, const void *arg);
uint32_t twamp_hash_ipv4(vrfid_t vrfid, const struct iphdr *ip,
			 const struct udphdr *udp);
int twamp_input_ipv4(struct rte_mbuf *m, void *l3hdr,
		     struct udphdr *udp, struct ifnet *ifp);

int twamp_hash_match_ipv6(struct cds_lfht_node *node, const void *arg);
uint32_t twamp_hash_ipv6(vrfid_t vrfid, const struct ip6_hdr *ip6,
			 const struct udphdr *udp);
int twamp_input_ipv6(struct rte_mbuf *m, void *l3hdr,
		     struct udphdr *udp, struct ifnet *ifp);

#endif
