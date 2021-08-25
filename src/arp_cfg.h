/*
 * Copyright (c) 2018-2019,2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef ARP_CFG_H
#define ARP_CFG_H

enum garp_pkt_action {
	GARP_PKT_DROP = 0,
	GARP_PKT_UPDATE = 1
};

struct garp_cfg {
	uint8_t garp_req_default : 1;
	uint8_t garp_rep_default : 1;
	uint8_t garp_req_action  : 3;
	uint8_t garp_rep_action  : 3;
};

void get_garp_cfg(struct garp_cfg *cfg);

void set_garp_cfg(int op, enum garp_pkt_action action);

#endif /* ARP_CFG_H */
