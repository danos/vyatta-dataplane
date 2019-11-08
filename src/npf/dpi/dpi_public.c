/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Public APIs for DPI.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "compiler.h"
#include "pl_node.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "dpi_public.h"
#include "npf/dpi/dpi.h"
#include "npf/npf_session.h"
#include "npf/npf_if.h"
#include "if_feat.h"

struct ifnet;
struct rte_mbuf;

static int dpi_enabled_count;

static void dpi_if_feature_enable(struct ifnet *ifp)
{
	if (if_feat_refcnt_incr(ifp, IF_FEAT_DPI)) {
		pl_node_add_feature_by_inst(&ipv4_dpi_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_dpi_in_feat, ifp);
		pl_node_add_feature_by_inst(&ipv4_dpi_out_feat, ifp);
		pl_node_add_feature_by_inst(&ipv6_dpi_out_feat, ifp);
	}
}

static void dpi_if_feature_disable(struct ifnet *ifp)
{
	if (if_feat_refcnt_decr(ifp, IF_FEAT_DPI)) {
		pl_node_remove_feature_by_inst(&ipv6_dpi_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_dpi_out_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv6_dpi_in_feat, ifp);
		pl_node_remove_feature_by_inst(&ipv4_dpi_in_feat, ifp);
	}
}

/* Enable DPI on the given interface. */
int
dpi_enable(struct ifnet *ifp)
{
	if (!dpi_init())
		return -ENOMEM;

	if (!ifp)
		return -EINVAL;

	dpi_if_feature_enable(ifp);
	dpi_enabled_count++;

	return 0;
}

/* Disable DPI on the given interface. */
int
dpi_disable(struct ifnet *ifp)
{
	if (!ifp)
		return -EINVAL;

	dpi_if_feature_disable(ifp);
	assert(dpi_enabled_count > 0);
	if (dpi_enabled_count > 0)
		dpi_enabled_count--;

	return 0;
}

/* Indicate whether DPI is enabled. */
bool
dpi_is_enabled(void)
{
	return (dpi_enabled_count != 0);
}

/* Return the L7 DPI application ID. */
uint32_t
dpi_get_app_id(struct rte_mbuf *mbuf)
{
	/* First find the session - this should already be present */
	npf_session_t *se = npf_session_find_cached(mbuf);
	if (!se)
		return DPI_APP_NA;

	/* Hopefully it has DPI flow information attached */
	struct dpi_flow *dpi_flow = npf_session_get_dpi(se);
	if (!dpi_flow)
		return DPI_APP_NA;

	if (dpi_flow_get_error(dpi_flow))
		return DPI_APP_ERROR;

	return dpi_flow_get_app_name(dpi_flow);
}
