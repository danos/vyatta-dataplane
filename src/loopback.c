/*
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Loopback interface implementation
 */

#include <stdint.h>
#include <rte_debug.h>

#include "dp_event.h"
#include "if_var.h"

static const struct ift_ops lo_if_ops = {
};

static void lo_type_init(void)
{
	int ret = if_register_type(IFT_LOOP, &lo_if_ops);
	if (ret < 0)
		rte_panic("Failed to register loopback type: %s",
			  strerror(-ret));
}

static const struct dp_event_ops loopback_events = {
	.init = lo_type_init,
};

DP_STARTUP_EVENT_REGISTER(loopback_events);
