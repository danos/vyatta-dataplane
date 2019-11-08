/*-
 * Copyright (c) 2017-2018, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VRF_IF_H
#define VRF_IF_H

#include <stdint.h>

#include "json_writer.h"
#include "urcu.h"
#include "vrf.h"

struct ifnet;

struct vrf_softc {
	uint32_t        vrfsc_tableid;
	struct rcu_head	vrfsc_rcu;
};

struct ifnet *vrfmaster_create(const char *ifname, uint32_t if_index,
			       uint32_t vrf_tableid);

vrfid_t vrfmaster_get_vrfid(struct ifnet *ifp);
vrfid_t vrfmaster_get_tableid(struct ifnet *ifp);

struct ifnet *vrfmaster_lookup_by_tableid(uint32_t tableid);

#endif /* VRF_IF_H */
