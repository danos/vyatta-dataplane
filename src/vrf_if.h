/*-
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VRF_IF_H
#define VRF_IF_H

#include <stdint.h>

#include "json_writer.h"
#include "urcu.h"
#include "vrf_internal.h"

struct ifnet;

struct vrf_softc {
	uint32_t        vrfsc_tableid;
	struct rcu_head	vrfsc_rcu;
};

struct ifnet *vrf_if_create(const char *ifname, uint32_t if_index,
			       uint32_t vrf_tableid);

vrfid_t vrf_if_get_vrfid(struct ifnet *ifp);
vrfid_t vrf_if_get_tableid(struct ifnet *ifp);

int vrf_lookup_by_tableid(uint32_t kernel_tableid, vrfid_t *vrfid,
			  uint32_t *user_tableid);

#endif /* VRF_IF_H */
