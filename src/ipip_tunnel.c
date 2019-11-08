/*
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * IPIP tunnel interface implementation
 */

#include <stdint.h>
#include <rte_debug.h>

#include "dp_event.h"
#include "if_var.h"

static const struct ift_ops ipip_tun_if_ops = {
};

static void ipip_tun_init(void)
{
	int ret = if_register_type(IFT_TUNNEL_OTHER, &ipip_tun_if_ops);
	if (ret < 0)
		rte_panic("Failed to register IPIP tunnel type: %s",
			  strerror(-ret));
}

static const struct dp_event_ops ipip_tun_events = {
	.init = ipip_tun_init,
};

DP_STARTUP_EVENT_REGISTER(ipip_tun_events);
