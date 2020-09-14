/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * Bridge port configuration information
 */
#ifndef BRIDGE_PORT_H
#define BRIDGE_PORT_H

#include <stdbool.h>
#include <stdint.h>

#include "bridge_flags.h"
#include "bridge_vlan_set.h"

/*
 * For VLAN aware mode, each bridged interface needs to track some
 * additional state related to the vlans to be allowed as well as
 * the PVID and the VLANs to untag on egress.
 */
struct bridge_port;
struct cds_list_head;
struct ifnet;

/*
 * Creates a new bridge port
 */
struct bridge_port *bridge_port_create(struct ifnet *ifp_port,
				       struct ifnet *ifp_bridge);

/*
 * Free the memory associated with a bridge port
 */
void bridge_port_free(struct bridge_port *port);

/*
 * Destroy an RCU managed bridge port
 */
void bridge_port_destroy(struct bridge_port *port);

/*
 * Change the state of the MSTP instance (MSTI) for this bridge port
 */
void bridge_port_set_state_msti(struct bridge_port *port, int mstiindex,
				uint8_t state);

/*
 * Get the state of the MSTP instance (MSTI) associated with a vlan on
 * this bridge port, i.e. map the vlan to a MSTI and return the state.
 */
uint8_t bridge_port_get_state_vlan(struct bridge_port *port, uint16_t vlan);

/*
 * Change the bridge port's STP state
 */
void bridge_port_set_state(struct bridge_port *port, uint8_t state);

/*
 * Get the STP state of the bridge port
 */
uint8_t bridge_port_get_state(struct bridge_port *port);

/*
 * The following functions manipulate the allowed VLAN list
 * the allowed list is which VLANs will be allowed on ingress and egress
 * from this port. If a frame is received from a VLAN not in this list
 * then it will be dropped on egress. If a frame is forwarded to this port
 * and belongs to a VLAN not part of this list it will be dropped on egress.
 */

/*
 * Check if a VLAN is in the allowed list for this bridge port
 */
bool bridge_port_lookup_vlan(struct bridge_port *port, uint16_t vlan);

/*
 * Synchronize the VLANs in the allowed list with the new_vlans list.
 * Returns true if any changed, false otherwise.
 */
bool bridge_port_synchronize_vlans(struct bridge_port *port,
	struct bridge_vlan_set *new_vlans);

/*
 * Get the VLANs in the allowed list.
 * Returns true if to_vlans changed, false otherwise.
 */
bool bridge_port_get_vlans(
	struct bridge_port *port, struct bridge_vlan_set *to_vlans);

/*
 * The following functions are related to a port's PVID.
 * The PVID is the VLAN id that all untagged packets get tagged
 * with on ingress by this port. 0 means that there is no PVID and
 * all untagged traffic will be dropped.
 */
/*
 * Set the PVID for a bridge port.
 */
void bridge_port_set_pvid(struct bridge_port *port, uint16_t vlan);

/*
 * Get the PVID for a bridge port.
 */
uint16_t bridge_port_get_pvid(struct bridge_port *port);

/*
 * The following functions manipulate the untag VLAN list for egress traffic.
 * If a VLAN belongs to this list it will be removed from the frame on egress
 * from the bridge code.
 */

/*
 * Check if a VLAN is in the untag list for this bridge port
 */
bool bridge_port_lookup_untag_vlan(struct bridge_port *port, uint16_t vlan);

/*
 * Synchronize the VLANs in the untagged list with the new list.
 * Returns true if any changed, false otherwise.
 */
bool bridge_port_synchronize_untag_vlans(struct bridge_port *port,
	struct bridge_vlan_set *new_untagged);

/*
 * Get the VLANs in the untagged list.
 * Returns true if to_vlans changed, false otherwise.
 */
bool bridge_port_get_untag_vlans(
	struct bridge_port *port, struct bridge_vlan_set *to_vlans);

/*
 * Get the interface the bridge port is associated with.
 */
struct ifnet *bridge_port_get_interface(struct bridge_port *port);

/*
 * Get the bridge interface the bridge port is part of.
 */
struct ifnet *bridge_port_get_bridge(struct bridge_port *port);

/*
 * Get the bridge port from its entry in the list of bridge ports.
 */
struct bridge_port *bridge_port_from_list_entry(struct cds_list_head *entry);

/*
 * Add the bridge port to the given list of bridge ports in the bridge
 * interface.
 */
void bridge_port_add_to_list(struct bridge_port *port,
			     struct cds_list_head *list);

/*
 * test if a bridge port is a member of specified vlan
 * it checks for tagged, untagged and pvid association
 */
bool bridge_port_is_vlan_member(struct bridge_port *port,
				uint16_t vlan);

/*
 * Set state to note that bridge-port has been created in the FAL
 */
void bridge_port_set_fal_created(struct bridge_port *port, bool created);

/*
 * Retrieve state for whether bridge-port has been created in the FAL
 */
bool bridge_port_is_fal_created(struct bridge_port *port);

#endif /* BRIDGE_PORT_H */
