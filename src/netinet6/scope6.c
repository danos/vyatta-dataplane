/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <stdint.h>
#include <string.h>

#include "if_var.h"
#include "in6.h"
#include "in6_var.h"

static int
in6_setzoneid(struct in6_addr *in6, uint32_t zoneid)
{
	if (IN6_IS_SCOPE_EMBEDDABLE(in6))
		in6->s6_addr16[1] = htons(zoneid & 0xffff);

	return 0;
}

/*
 * Determine the appropriate scope zone ID for in6 and ifp.  If ret_id is
 * non NULL, it is set to the zone ID.  If the zone ID needs to be embedded
 * in the in6_addr structure, in6 will be modified.
 * Vyatta: zoneid == 0
 */
int
in6_setscope(struct in6_addr *in6, const struct ifnet *ifp, uint32_t *ret_id)
{
	uint32_t zoneid = 0;

	/*
	 * special case: the loopback address can only belong to a loopback
	 * interface.
	 */
	if (IN6_IS_ADDR_LOOPBACK(in6)) {
		if (!(ifp->if_flags & IFF_LOOPBACK))
			return EINVAL;
		else {
			if (ret_id != NULL)
				*ret_id = 0; /* there's no ambiguity */
			return 0;
		}
	}

	if (ret_id != NULL)
		*ret_id = 0;

	return in6_setzoneid(in6, zoneid);
}
