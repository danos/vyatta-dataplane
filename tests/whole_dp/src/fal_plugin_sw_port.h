/*-
 * Copyright (c) 2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef __FAL_PLUGIN_SW_PORT_H__
#define __FAL_PLUGIN_SW_PORT_H__

struct fal_sw_port;

void fal_plugin_sw_ports_create(void);

int
fal_plugin_get_sw_port_info(struct fal_sw_port *fal_sw_port, uint16_t *proto,
			    uint8_t *dev, uint8_t *port);
int
fal_plugin_add_ut_framer_hdr(const char *name, struct rte_mbuf *mbuf);

int
fal_plugin_queue_rx_direct(const char *name, struct rte_mbuf *mbuf);

bool fal_plugin_ut_enable_rx_framer(bool enabled);

int
fal_plugin_backplane_from_sw_port(const char *name, uint16_t *dpdk_port);

#endif
