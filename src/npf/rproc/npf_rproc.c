/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 2009-2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NPF extension and rule procedure interface.
 */

#include <stdlib.h>
#include <string.h>

#include "npf/rproc/npf_rproc.h"
#include "npf/npf_ruleset.h"
#include "util.h"

extern const npf_rproc_ops_t	npf_policer_ops, npf_markdscp_ops,
				npf_markpcp_ops, npf_log_ops, npf_dpi_ops,
				npf_appfw_ops, npf_pathmon_ops,
				npf_session_limiter_ops, npf_setvrf_ops,
				npf_action_group_ops, npf_app_ops, npf_tag_ops,
				npf_nptv6_ops, npf_nat64_ops, npf_nat46_ops,
				npf_ctrdef_ops, npf_ctrref_ops, npf_counter_ops;

/*
 * All rproc handlers
 */
static const npf_rproc_ops_t *npf_rproc_handlers[] = {
	[NPF_RPROC_ID_APPFW]     = &npf_appfw_ops,
	[NPF_RPROC_ID_POLICER]   = &npf_policer_ops,
	[NPF_RPROC_ID_MARKDSCP]  = &npf_markdscp_ops,
	[NPF_RPROC_ID_MARKPCP]   = &npf_markpcp_ops,
	[NPF_RPROC_ID_LOG]       = &npf_log_ops,
	[NPF_RPROC_ID_APP]       = &npf_app_ops,
	[NPF_RPROC_ID_DPI]       = &npf_dpi_ops,
	[NPF_RPROC_ID_PATHMON]   = &npf_pathmon_ops,
	[NPF_RPROC_ID_SLIMIT]    = &npf_session_limiter_ops,
	[NPF_RPROC_ID_SETVRF]    = &npf_setvrf_ops,
	[NPF_RPROC_ID_ACTIONGRP] = &npf_action_group_ops,
	[NPF_RPROC_ID_TAG]       = &npf_tag_ops,
	[NPF_RPROC_ID_NPTV6]     = &npf_nptv6_ops,
	[NPF_RPROC_ID_NAT64]     = &npf_nat64_ops,
	[NPF_RPROC_ID_NAT46]     = &npf_nat46_ops,
	[NPF_RPROC_ID_CTR_DEF]   = &npf_ctrdef_ops,
	[NPF_RPROC_ID_CTR_REF]   = &npf_ctrref_ops,
	[NPF_RPROC_ID_COUNTER]   = &npf_counter_ops,
	[NPF_RPROC_ID_LAST]      = NULL
};

static_assert(ARRAY_SIZE(npf_rproc_handlers) - 1 == NPF_RPROC_ID_LAST,
	      "npf rproc handlers iswrong size");


unsigned int npf_rproc_max_rprocs(void)
{
	return	ARRAY_SIZE(npf_rproc_handlers) - 1;
}

const char *npf_rproc_type2string(enum npf_rproc_type ro_type)
{
	switch (ro_type) {
	case NPF_RPROC_TYPE_MATCH:
		return "match";
	case NPF_RPROC_TYPE_ACTION:
		return "rproc";
	case NPF_RPROC_TYPE_HANDLE:
		return "handle";
	};
	return NULL;
}

/*
 * Rule procedure management.
 */

int
npf_create_rproc(const npf_rproc_ops_t *ops, npf_rule_t *rl, const char *args,
		 void **handle)
{
	assert(npf_rproc_max_rprocs() == NPF_RPROC_ID_LAST);

	if (!ops->ro_ctor) {
		*handle = NULL;
		return 0;
	}

	return ops->ro_ctor(rl, args, handle);
}

void
npf_destroy_rproc(const npf_rproc_ops_t *ops, void *arg)
{
	if (ops && ops->ro_dtor)
		ops->ro_dtor(arg);
}

/*
 * Find an rproc handler by name and type
 */
const npf_rproc_ops_t *
npf_find_rproc(char *name, enum npf_rproc_type ro_type)
{
	enum npf_rproc_id id;

	for (id = 0; id < NPF_RPROC_ID_LAST; id++) {
		/* Match type then name */
		if (ro_type == npf_rproc_handlers[id]->ro_type &&
		    !strcmp(name, npf_rproc_handlers[id]->ro_name))
			return npf_rproc_handlers[id];
	}

	return NULL;
}

/*
 * Find an rproc handler by id
 */
const npf_rproc_ops_t *
npf_find_rproc_by_id(enum npf_rproc_id ro_id)
{
	if (ro_id >= NPF_RPROC_ID_LAST)
		return NULL;
	return npf_rproc_handlers[ro_id];
}

/*
 * Given an rproc ops struct, return its id.
 */
enum npf_rproc_id
npf_rproc_get_id(const npf_rproc_ops_t *ops)
{
	if (!ops)
		return NPF_RPROC_ID_LAST;

	return ops->ro_id;
}
