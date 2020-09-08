/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * DPDK Ethernet interfaces
 */

#ifndef DPDK_ETH_LINKWATCH_H
#define DPDK_ETH_LINKWATCH_H

enum linkwatch_flags {
	LINKWATCH_FLAG_NONE,
	LINKWATCH_FLAG_FORCE_LINK_DOWN = (1 << 0),
	LINKWATCH_FLAG_FORCE_NOTIFY = (1 << 1),
};

void linkwatch_timer(struct rte_timer *tim, void *arg);
int linkwatch_port_config(portid_t portid);
void linkwatch_port_unconfig(portid_t portid);
void linkwatch_update_port_status(portid_t port, enum linkwatch_flags flags);

#endif /* DPDK_ETH_LINKWATCH_H */
