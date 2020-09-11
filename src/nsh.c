/*-
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017,2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <errno.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stddef.h>

#include "compat.h"
#include "nsh.h"
#include "vplane_debug.h"
#include "vplane_log.h"

int nsh_get_payload(struct nsh *nsh_start, enum nsh_np *nxtproto,
		    void **nsh_payload)
{
	struct nsh nsh_local;

	nsh_local.bh_u.bh = ntohl(nsh_start->bh_u.bh);
	if (nsh_local.nsh_nxtproto == NSH_NP_NONE ||
	    nsh_local.nsh_nxtproto >= NSH_NP_MAX) {
		DP_DEBUG(NSH, ERR, NSH,
			 "Invalid next protocol %d\n", nsh_local.nsh_nxtproto);
			return -EINVAL;
	}
	*nsh_payload = (uint8_t *)nsh_start +
		(nsh_local.nsh_len * NSH_LEN_UNIT);
	*nxtproto = nsh_local.nsh_nxtproto;
	return 0;
}
