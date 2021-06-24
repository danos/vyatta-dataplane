/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <rte_log.h>

#include "dp_session.h"
#include "npf/npf_session.h"
#include "npf/npf_nat.h"
#include "npf/npf_nat64.h"
#include "npf/npf_pack.h"
#include "session/session_feature.h"
#include "vplane_debug.h"
#include "vplane_log.h"

uint32_t dp_session_buf_size_max(void)
{
	return NPF_PACK_NEW_SESSION_MAX_SIZE;
}
