/*
 * Handlers for well known UDP ports, registered at init time.
 *
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017,2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <rte_debug.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <sys/socket.h>

#include "compiler.h"
#include "l2tp/l2tpeth.h"
#include "pktmbuf_internal.h"
#include "snmp_mib.h"
#include "udp_handler.h"

struct ifnet;

/*
 * rte_hash is a fixed size table. For best performance, utilisation
 * should be kept <25%. Please consider increasing this value as you add
 * port handlers.
 */
#define UDP_PORT_TABLE_MAX 16

static struct rte_hash *ipv4_udp_table;
static struct rte_hash *ipv6_udp_table;

/*
 * Thread safe lookup
 * returns -ENOENT if entry not found, >=0 (key index) on success
 */
int udp_handler_lookup(short af, uint32_t dest_port, udp_port_handler *handler)
{
	return rte_hash_lookup_data(af == AF_INET ? ipv4_udp_table :
				    ipv6_udp_table, &dest_port,
				    (void **)handler);
}

/* Not thread safe, must be called on main thread */
int udp_handler_register(short af, uint32_t dest_port, udp_port_handler handler)
{
	return rte_hash_add_key_data(af == AF_INET ? ipv4_udp_table :
				     ipv6_udp_table, &dest_port, handler);
}

/* Not thread safe, must be called on main thread */
void udp_handler_unregister(short af, uint32_t dest_port)
{
	rte_hash_del_key(af == AF_INET ? ipv4_udp_table : ipv6_udp_table,
			 &dest_port);
}

/* Optimised 1 word hash */
static inline uint32_t udp_port_hash(const void *key, uint32_t length __unused,
				     uint32_t initval)
{
	return rte_jhash_1word(*(uint32_t *)key, initval);
}

void udp_handler_init(void)
{
	static const struct rte_hash_parameters ipv4_udp_hash_params = {
		.name = "ipv4_udp_port_hash",
		.entries = UDP_PORT_TABLE_MAX,
		.key_len = sizeof(uint32_t),
		.hash_func = udp_port_hash,
		.socket_id = SOCKET_ID_ANY,
	};
	static const struct rte_hash_parameters ipv6_udp_hash_params = {
		.name = "ipv6_udp_port_hash",
		.entries = UDP_PORT_TABLE_MAX,
		.key_len = sizeof(uint32_t),
		.hash_func = udp_port_hash,
		.socket_id = SOCKET_ID_ANY,
	};

	ipv4_udp_table = rte_hash_create(&ipv4_udp_hash_params);
	if (!ipv4_udp_table)
		rte_panic("Cannot initialise ipv4 udp handlers table\n");

	ipv6_udp_table = rte_hash_create(&ipv6_udp_hash_params);
	if (!ipv6_udp_table)
		rte_panic("Cannot initialise ipv6 udp handlers table\n");
}

void udp_handler_destroy(void)
{
	rte_hash_free(ipv4_udp_table);
	rte_hash_free(ipv6_udp_table);
}

int udp_input(struct rte_mbuf *m, int af, struct ifnet *input_ifp)
{
	udp_port_handler handler;
	struct udphdr *udp;

	if (!pktmbuf_udp_header_is_usable(m)) {
		UDPSTAT_INC(UDP_MIB_INERRORS);
		return -1;
	}

	udp = dp_pktmbuf_mtol4(m, struct udphdr *);

	if ((udp_handler_lookup(af, udp->dest, &handler) >= 0) &&
	    !handler(m, dp_pktmbuf_mtol3(m, void *), udp, input_ifp)) {
		UDPSTAT_INC(UDP_MIB_INDATAGRAMS);
		return 0;
	}

	if (af == AF_INET)
		return l2tp_udpv4_recv_encap(
			m, dp_pktmbuf_mtol3(m, const void *), udp);
	else
		return l2tp_udpv6_recv_encap(
			m, dp_pktmbuf_mtol3(m, const void *), udp);
}
