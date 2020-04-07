/*
 * IPv6 no forwarding feature
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"

/* Register Features */
PL_REGISTER_FEATURE(ipv6_in_no_forwarding_feat) = {
	.name = "vyatta:ipv6-in-no-forwarding",
	.node_name = "ipv6-route-lookup-host",
	.feature_point = "ipv6-validate",
	.visit_after = "ipv6-in-no-address",
	.id = PL_L3_V6_IN_FUSED_FEAT_NO_FORWARDING,
};
