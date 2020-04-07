/*
 * Handlers for well known UDP ports, registered at init time.
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef UDP_HANDLER_H
#define UDP_HANDLER_H

#include <netinet/udp.h>
#include <stdint.h>

#include "interface.h"

struct rte_mbuf;
struct udphdr;

typedef int (*udp_port_handler)(struct rte_mbuf *m,
				void *l3,
				struct udphdr *udp,
				struct ifnet *ifp);
int udp_handler_lookup(short af, uint32_t dest_port, udp_port_handler *handler);
int udp_handler_register(short af, uint32_t dest_port,
			 udp_port_handler handler);
void udp_handler_unregister(short af, uint32_t dest_port);

void udp_handler_init(void);
void udp_handler_destroy(void);
int udp_input(struct rte_mbuf *m, int af, struct ifnet *input_ifp);

#endif /* UDP_HANDLER_H */
