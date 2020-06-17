/*
 * Copyright (c) 2017,2019-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "bridge_vlan_set.h"

#include <rte_bitmap.h>
#include <stdlib.h>

#include "compiler.h"
#include "pktmbuf_internal.h"
#include "util.h"

/*
 * A bitset of VLANs for each bridge port for use in VLAN aware mode.
 * Uses rte_bitmap but provides a simplier interface that allows
 * us to replace the implementation later if required.
 */
struct bridge_vlan_set {
	uint8_t           *store;
	struct rte_bitmap *map;
};

struct bridge_vlan_set __externally_visible *
bridge_vlan_set_create(void)
{
	struct bridge_vlan_set *set = zmalloc_aligned(sizeof(*set));
	if (set == NULL)
		return NULL;
	uint32_t setsz = rte_bitmap_get_memory_footprint(VLAN_N_VID);
	set->store = zmalloc_aligned(setsz);
	if (set->store == NULL) {
		free(set);
		return NULL;
	}
	set->map = rte_bitmap_init(VLAN_N_VID, set->store, setsz);
	return set;
}

void __externally_visible
bridge_vlan_set_free(struct bridge_vlan_set *set)
{
	free(set->store);
	free(set);
}

void __externally_visible
bridge_vlan_set_add(struct bridge_vlan_set *set, uint16_t vlan)
{
	rte_bitmap_set(set->map, vlan);
}

void __externally_visible
bridge_vlan_set_remove(struct bridge_vlan_set *set, uint16_t vlan)
{
	rte_bitmap_clear(set->map, vlan);
}

bool __externally_visible
bridge_vlan_set_is_member(struct bridge_vlan_set *set, uint16_t vlan)
{
	if (vlan > VLAN_N_VID)
		return false;
	return rte_bitmap_get(set->map, vlan);
}

void __externally_visible
bridge_vlan_set_clear(struct bridge_vlan_set *set)
{
	rte_bitmap_reset(set->map);
}

bool __externally_visible
bridge_vlan_set_is_empty(struct bridge_vlan_set *set)
{
	uint32_t pos = 0;
	uint64_t slab = 0;

	if (rte_bitmap_scan(set->map, &pos, &slab))
		return false;

	return true;
}

void __externally_visible
bridge_vlan_set_synchronize(struct bridge_vlan_set *old,
			    struct bridge_vlan_set *new,
			    bridge_vlan_synchronize_cb add_cb,
			    bridge_vlan_synchronize_cb remove_cb,
			    void *cb_data)
{
	for (int i = 0; i < VLAN_N_VID; i++) {
		if (bridge_vlan_set_is_member(old, i)) {
			if (!bridge_vlan_set_is_member(new, i))
				remove_cb(i, cb_data);
		} else if (bridge_vlan_set_is_member(new, i)) {
			add_cb(i, cb_data);
		}
	}
}
