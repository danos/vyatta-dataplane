/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "if_var.h"
#include "dp_event.h"

#include "npf/npf_event.h"
#include "npf/npf_if.h"
#include "npf/npf_vrf.h"
#include "npf_shim.h"


static const struct dp_event_ops npf_event_ops = {
	.if_index_set = npf_if_enable,
	.if_index_unset = npf_if_disable,
	.if_rename = npf_if_rename,
	.if_addr_add = npf_if_addr_change,
	.if_addr_delete = npf_if_addr_change,
	.reset_config = npf_reset_config,
	.vrf_create = npf_vrf_create,
	.vrf_delete = npf_vrf_delete,
};

void npf_event_init(void)
{
	dp_event_register(&npf_event_ops);
}
