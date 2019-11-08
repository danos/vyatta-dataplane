#ifndef _NPF_VRF_H_
#define _NPF_VRF_H_
/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "vrf.h"
#include "util.h"
#include "npf/config/npf_ruleset_type.h"

struct vrf;
struct npf_config;

void vrf_set_npf_timeout(struct vrf *vrf, struct npf_timeout *to);
struct npf_timeout *vrf_get_npf_timeout(struct vrf *vrf);
struct npf_timeout *vrf_get_npf_timeout_rcu(vrfid_t vrf_id);

void vrf_set_npf_alg(struct vrf *vrf, struct npf_alg_instance *ai);
struct npf_alg_instance *vrf_get_npf_alg(struct vrf *vrf);
struct npf_alg_instance *vrf_get_npf_alg_rcu(vrfid_t vrf_id);

void npf_vrf_if_index_set(struct ifnet *ifp);
void npf_vrf_if_index_unset(struct ifnet *ifp);

void npf_gbl_rs_count_incr(enum npf_ruleset_type rs_type);
void npf_gbl_rs_count_decr(enum npf_ruleset_type rs_type);

#endif
