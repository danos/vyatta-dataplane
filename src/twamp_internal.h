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
	struct cds_list_head list;
	struct rcu_head rcu;
};

extern struct cds_list_head tw_session_list_head;

int twamp_input_ipv4(struct rte_mbuf *m, void *l3hdr,
		     struct udphdr *udp, struct ifnet *ifp);

int twamp_input_ipv6(struct rte_mbuf *m, void *l3hdr,
		     struct udphdr *udp, struct ifnet *ifp);

#endif
