/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
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
#include "npf/npf_cache.h"
#include "npf/rproc/npf_rproc.h"
#include "pktmbuf.h"
#include "vplane_log.h"

struct ifnet;
struct rte_mbuf;

/*
 * Extract and store the tag value to set
 */
static int
npf_tag_create(npf_rule_t *rl __unused, const char *params, void **handle)
{
	uint64_t tag = 0;
	char *endp;

	if (!params) {
		RTE_LOG(ERR, FIREWALL,
			"NPF: need parameter for tag rproc\n");
		return -EINVAL;
	}

	tag = strtoull(params, &endp, 10);
	if (endp == params || tag > 0xFFFFFFFF) {
		RTE_LOG(ERR, FIREWALL, "NPF: bad tag parameter \"%s\" for "
			"tag rproc\n", params);
		return -EINVAL;
	}

	*handle = (void *)tag;
	return 0;
}

const npf_rproc_ops_t npf_tag_ops = {
	.ro_name   = "tag",
	.ro_type   = NPF_RPROC_TYPE_HANDLE,
	.ro_id     = NPF_RPROC_ID_TAG,
	.ro_bidir  = false,
	.ro_ctor   = npf_tag_create,
};
