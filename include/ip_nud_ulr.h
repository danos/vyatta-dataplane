/*
 * API for IP neighbour Reachability Confirmation
 *
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VYATTA_DATAPLANE_IP_NUD_ULR_H
#define VYATTA_DATAPLANE_IP_NUD_ULR_H

struct ifnet;
struct ip_addr;

enum ulr_msg_t {
	REACHABLITY_CONFIRMED,
	REACHABLITY_NOT_CONFIRMED
};

/*
 * Receives upper layer reachability notifications
 *
 * @param[in] pointer to the ifnet structure containing interface information
 * @param[in] pointer to the ip_addr structure containing the destination ip
 * @param[in] msg of type ulr_msg_t indicating the reachability state
 */
void dp_ip_nud_ulr_notify(struct ifnet *ifp, struct ip_addr *dst, enum ulr_msg_t msg);

#endif /* VYATTA_DATAPLANE_IP_NUD_ULR_H */
