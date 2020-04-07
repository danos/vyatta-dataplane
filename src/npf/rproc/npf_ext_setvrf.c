/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_ruleset.h"
#include "pktmbuf_internal.h"
#include "vplane_log.h"

struct ifnet;
struct rte_mbuf;

/*
 * Extract and store the vrf value to set
 */
static int
npf_setvrf_create(npf_rule_t *rl __unused, const char *params, void **handle)
{
	uintptr_t vrf = 0;
	char *endp;

	if (!params) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: need parameter for setvrf rproc\n");
		return -EINVAL;
	}

	vrf = strtoull(params, &endp, 10);
	if (endp == params || vrf > 0xFFFFFFFF) {
		RTE_LOG(ERR, FIREWALL, "NPF: bad vrf parameter \"%s\" for "
			"setvrf rproc\n", params);
		return -EINVAL;
	}

	*handle = (void *)vrf;
	return 0;
}

static bool
npf_setvrf(npf_cache_t *npc __unused, struct rte_mbuf **m, void *arg,
	   npf_session_t *se __unused, npf_rproc_result_t *result)
{
	vrfid_t vrfid;
	struct vrf *vrf;

	if (result->decision == NPF_DECISION_BLOCK)
		return true;

	vrfid = (uintptr_t)arg;
	vrf = dp_vrf_get_rcu_from_external(vrfid);
	pktmbuf_set_vrf(*m, vrf ? vrf->v_id : VRF_INVALID_ID);
	return true;
}

const npf_rproc_ops_t npf_setvrf_ops = {
	.ro_name   = "setvrf",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_SETVRF,
	.ro_bidir  = false,
	.ro_ctor   = npf_setvrf_create,
	.ro_action = npf_setvrf,
};
