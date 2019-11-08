/*-
 * Copyright (c) 2017, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef BRIDGE_VLAN_SET_H
#define BRIDGE_VLAN_SET_H

#include <stdint.h>
#include <stdbool.h>

/*
 * A VLAN set is a set data-structure large enough to hold
 * a bit for each VLAN
 */
struct bridge_vlan_set;

/*
 * Utility routines for bridge_vlan_set.
 */

/*
 * Creates a new VLAN set.
 */
struct bridge_vlan_set *bridge_vlan_set_create(void);

/*
 * Releases the resources used for the VLAN set
 */
void bridge_vlan_set_free(struct bridge_vlan_set *set);

/*
 * Make the provided VLAN a member of the set.
 */
void bridge_vlan_set_add(struct bridge_vlan_set *set, uint16_t vlan);

/*
 * Remove the specified VLAN from membership of the set.
 */
void bridge_vlan_set_remove(struct bridge_vlan_set *set, uint16_t vlan);

/*
 * Check if the specified VLAN is a member of the set.
 */
bool bridge_vlan_set_is_member(struct bridge_vlan_set *set, uint16_t vlan);

/*
 * Emptys the VLAN set.
 */
void bridge_vlan_set_clear(struct bridge_vlan_set *set);

/*
 * Callback for synchronization algorithm, takes a vlan id and the cb_data
 * that is passed to the synchronize function.
 */
typedef void (*bridge_vlan_synchronize_cb) (uint16_t vlan, void *cb_data);

/*
 * Synchronizes two VLAN sets, using supplied callbacks.  add_cb() and
 * remove_cb() are required. cb_data will be passed unmodified to the
 * callback functions.
 */
void bridge_vlan_set_synchronize(struct bridge_vlan_set *old,
				 struct bridge_vlan_set *new,
				 bridge_vlan_synchronize_cb add_cb,
				 bridge_vlan_synchronize_cb remove_cb,
				 void *cb_data);

#endif /* BRIDGE_VLAN_SET_H */
