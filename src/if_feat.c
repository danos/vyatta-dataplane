/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Pipeline feature reference counts and control.  Uses per-feature counters
 * in struct ifnet to control enabling and disabling of pipeline feature
 * nodes.
 */

#include <stdbool.h>
#include <stdio.h>
#include <urcu.h>

#include "util.h"
#include "vrf.h"
#include "if_var.h"
#include "dpi_public.h"
#include "pl_node.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "vplane_log.h"
#include "if_feat.h"

#define IFF_ENABLE  true
#define IFF_DISABLE false

#define IFF_NAME_SZ 15

struct if_feat {
	/* Enable/disable function pointer */
	if_feat_enable_t	enable;
	char			name[IFF_NAME_SZ];
};

static struct if_feat if_feat[IF_FEAT_COUNT];

/*
 * Initialize the function pointer for enabling and disabling a feature
 */
void if_feat_init(if_feat_enable_t fp, const char *name, enum if_feat_enum feat)
{
	if (feat <= IF_FEAT_LAST) {
		if_feat[feat].enable = fp;
		snprintf(if_feat[feat].name, IFF_NAME_SZ, "%s", name);
	}
}

/*
 * if_feat_refcnt_incr
 *
 * Increment feature ref count for an interface.  Feature is enabled when ref
 * count changes from 0 to 1.  Returns true when count changes from 0 to 1.
 */
bool if_feat_refcnt_incr(struct ifnet *ifp, enum if_feat_enum feat)
{
	if (feat > IF_FEAT_LAST)
		return false;

	assert(ifp->if_feat_refcnt[feat] < USHRT_MAX);
	if (ifp->if_feat_refcnt[feat] >= USHRT_MAX) {
		RTE_LOG(ERR, DATAPLANE,
			"Cannot increment %s %s feature count above max\n",
			if_feat_name(feat), ifp->if_name);
		return false;
	}

	if (ifp->if_feat_refcnt[feat]++ == 0) {
		if (if_feat[feat].enable)
			if_feat[feat].enable(ifp, IFF_ENABLE);
		return true;
	}
	return false;
}

/*
 * if_feat_refcnt_decr
 *
 * Decrement feature ref count for an interface.  Feature is disabled when ref
 * count changes from 1 to 0.  Returns true when count changes from 1 to 0.
 */
bool if_feat_refcnt_decr(struct ifnet *ifp, enum if_feat_enum feat)
{
	if (feat > IF_FEAT_LAST)
		return false;

	assert(ifp->if_feat_refcnt[feat] > 0);
	if (ifp->if_feat_refcnt[feat] == 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Cannot decrement %s %s feature count below zero\n",
			if_feat_name(feat), ifp->if_name);
		return false;
	}

	if (--ifp->if_feat_refcnt[feat] == 0) {
		if (if_feat[feat].enable)
			if_feat[feat].enable(ifp, IFF_DISABLE);
		return true;
	}
	return false;
}

/*
 * if_feat_intf_multi_refcnt_incr
 *
 * Increment each feature set in feature-flag bitmask.
 */
void if_feat_intf_multi_refcnt_incr(struct ifnet *ifp, enum if_feat_flag ffl)
{
	enum if_feat_enum ft;

	for (ft = IF_FEAT_FIRST; ft <= IF_FEAT_LAST; ft++)
		if (IF_FEAT_IS_SET(ft, ffl))
			if_feat_refcnt_incr(ifp, ft);
}

/*
 * if_feat_intf_multi_refcnt_decr
 *
 * Decrement each feature set in feature-flag bitmask.
 */
void if_feat_intf_multi_refcnt_decr(struct ifnet *ifp, enum if_feat_flag ffl)
{
	enum if_feat_enum ft;

	for (ft = IF_FEAT_FIRST; ft <= IF_FEAT_LAST; ft++)
		if (IF_FEAT_IS_SET(ft, ffl))
			if_feat_refcnt_decr(ifp, ft);
}

/*
 * if_feat_all_refcnt_incr
 *
 * Increment each feature set in feature-flag bitmask for all interfaces.
 */
static void
if_feat_all_refcnt_incr_cb(struct ifnet *ifp, void *arg)
{
	enum if_feat_flag *fflp = arg;
	if_feat_intf_multi_refcnt_incr(ifp, *fflp);
}

void if_feat_all_refcnt_incr(enum if_feat_flag ffl)
{
	ifnet_walk(if_feat_all_refcnt_incr_cb, &ffl);
}

/*
 * if_feat_all_refcnt_decr
 *
 * Decrement each feature set in feature-flag bitmask for all interfaces.
 */
static void
if_feat_all_refcnt_decr_cb(struct ifnet *ifp, void *arg)
{
	enum if_feat_flag *fflp = arg;
	if_feat_intf_multi_refcnt_decr(ifp, *fflp);
}

void if_feat_all_refcnt_decr(enum if_feat_flag ffl)
{
	ifnet_walk(if_feat_all_refcnt_decr_cb, &ffl);
}

/*
 * if_feat_enum to name
 */
const char *if_feat_name(enum if_feat_enum feat)
{
	if (feat <= IF_FEAT_LAST)
		return if_feat[feat].name;
	return "unkn";
}
