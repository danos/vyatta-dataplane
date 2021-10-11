/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <sys/socket.h>

#include "ip_nud_ulr.h"
#include "nd6_nbr.h"
#include "if_ether.h"

/*
 *  Receives upper layer reachability notifications
 */
void dp_ip_nud_ulr_notify(struct ifnet *ifp, struct ip_addr *dst, enum ulr_msg_t msg)
{
	if (dst->type == AF_INET)
		lladdr_ulr_update(ifp, &dst->address.ip_v4, msg == REACHABLITY_CONFIRMED);
	else
		nd6_lladdr_ulr_update(ifp, &dst->address.ip_v6, msg == REACHABLITY_CONFIRMED);
}
