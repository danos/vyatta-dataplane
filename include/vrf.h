/*
 * Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VYATTA_DATAPLANE_VRF_H
#define VYATTA_DATAPLANE_VRF_H

/*
 * This declares vrf related  APIs exported by dataplane
 */

/* Opaque vrf structure */
struct vrf;

/* vrfid type */
typedef uint32_t vrfid_t;

#define  VRF_INVALID_ID      0
#define  VRF_DEFAULT_ID      1

/*
 * get vrf id for  vrf structure pointer
 *
 * @param[in] vrf Pointer to vrf structure
 *
 * @return vrf id
 */
vrfid_t dp_vrf_get_vid(struct vrf *vrf);

/*
 * get external vrf id from internal vrf id
 *
 * @param[in] internal_id Internal vrf id
 * @return External vrf id
 */
vrfid_t dp_vrf_get_external_id(vrfid_t internal_id);

/*
 * get vrf struct pointer from external vrf id
 *
 * @param[in] external_id external vrf id
 * @return Pointer to vrf structure
 *
 */
struct vrf *dp_vrf_get_rcu_from_external(vrfid_t external_id);

#endif /* VYATTA_DATAPLANE_VRF_H */
