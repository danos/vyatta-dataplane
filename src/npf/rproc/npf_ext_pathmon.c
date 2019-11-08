/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Path Monitor
 */

#include <errno.h>
#include <stdbool.h>

#include "compiler.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_session.h"
#include "pathmonitor/pathmonitor.h"

struct ifnet;
struct rte_mbuf;


/* Create the specified pathmonitor rule. */
static int
pathmon_ctor(npf_rule_t *rl __unused, const char *params, void **handle)
{
	/*
	 * Register for the specified pathmon entry.
	 *
	 * The monitor and policy are received from the config layer
	 * as a string.
	 *
	 * Store the returned pathmon pointer in the handle for later matching.
	 */
	*handle = pathmon_register(params);
	return *handle ? 0 : -ENOMEM;
}

/* Delete the specified pathmonitor rule. */
static void
pathmon_dtor(void *handle)
{
	pathmon_deregister(handle);
}

/*
 * Match the mbuf against the specified pathmonitor rule
 * using the name that was saved earlier.
 */
static bool
pathmon_match(npf_cache_t *npc __unused, struct rte_mbuf *mbufi __unused,
	      const struct ifnet *ifp __unused, int dir __unused,
	      npf_session_t *se __unused, void *handle)
{
	/* Return true if the path monitor is compliant. */
	return pathmon_get_status(handle) == PM_COMPLIANT;
}

/* Pathmonitor RPROC ops. */
const npf_rproc_ops_t npf_pathmon_ops = {
	.ro_name   = "pathmon",
	.ro_type   = NPF_RPROC_TYPE_MATCH,
	.ro_id     = NPF_RPROC_ID_PATHMON,
	.ro_bidir  = false,
	.ro_ctor   = pathmon_ctor,
	.ro_dtor   = pathmon_dtor,
	.ro_match  = pathmon_match,
};
