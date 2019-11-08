/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "bridge_port.h"

#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>

#include "bridge_vlan_set.h"
#include "mstp.h"
#include "urcu.h"
#include "util.h"
#include "fal.h"

struct bridge_vlan_set;

struct bridge_sync_ctx {
	struct bridge_vlan_set *old;
	bool any_changed;
};

static void
bridge_vlan_set_add_sync_cb(uint16_t vlan, void *cb_data)
{
	struct bridge_sync_ctx *ctx = cb_data;

	bridge_vlan_set_add(ctx->old, vlan);
	ctx->any_changed = true;
}

static void
bridge_vlan_set_remove_sync_cb(uint16_t vlan, void *cb_data)
{
	struct bridge_sync_ctx *ctx = cb_data;

	bridge_vlan_set_remove(ctx->old, vlan);
	ctx->any_changed = true;
}

static bool
bridge_port_set_synchronize(struct bridge_vlan_set *old,
			    struct bridge_vlan_set *new)
{
	struct bridge_sync_ctx ctx = {
		.old = old,
		.any_changed = false,
	};
	bridge_vlan_set_synchronize(old, new,
				    bridge_vlan_set_add_sync_cb,
				    bridge_vlan_set_remove_sync_cb,
				    &ctx);
	return ctx.any_changed;
}

/*
 * For VLAN aware mode, each bridged interface needs to track some
 * additional state related to the vlans to be allowed as well as
 * the PVID and the VLANs to untag on egress.
 */
struct bridge_port {
	struct ifnet            *ifp;
	struct ifnet            *bridge_ifp;
	struct bridge_vlan_set  *vlans;
	struct bridge_vlan_set  *untag_vlans;
	struct cds_list_head    brlink; /* list of ports in bridge */
	uint16_t                pvid;
	uint8_t                 state[MSTP_MSTI_COUNT];

	/* Administrative */
	struct rcu_head		    rcu;
};

struct bridge_port *
bridge_port_create(struct ifnet *port_ifp, struct ifnet *bridge_ifp)
{
	struct bridge_port *port = zmalloc_aligned(sizeof(*port));
	if (!port)
		return NULL;

	port->vlans = bridge_vlan_set_create();
	if (!port->vlans) {
		free(port);
		return NULL;
	}

	port->untag_vlans = bridge_vlan_set_create();
	if (!port->untag_vlans) {
		bridge_vlan_set_free(port->vlans);
		free(port);
		return NULL;
	}

	int mstiindex;
	for (mstiindex = 0; mstiindex < MSTP_MSTI_COUNT; mstiindex++)
		port->state[mstiindex] = STP_IFSTATE_DISABLED;

	port->ifp = port_ifp;
	port->bridge_ifp = bridge_ifp;

	return port;
}

void
bridge_port_free(struct bridge_port *port)
{
	bridge_vlan_set_free(port->vlans);
	bridge_vlan_set_free(port->untag_vlans);
	free(port);
}

static void
bridge_port_rcu_free(struct rcu_head *head)
{
	struct bridge_port *port =
		caa_container_of(head, struct bridge_port, rcu);
	bridge_port_free(port);
}

void
bridge_port_destroy(struct bridge_port *port)
{
	cds_list_del_rcu(&port->brlink);

	call_rcu(&port->rcu, bridge_port_rcu_free);
}

void
bridge_port_set_state_msti(struct bridge_port *port, int mstiindex,
			   uint8_t state)
{
	CMM_STORE_SHARED(port->state[mstiindex], state);

	const struct fal_attribute_t attr_list[2] = {
		{FAL_STP_PORT_ATTR_INSTANCE,
		 .value.objid = mstp_fal_stp_object(
			 port->bridge_ifp, mstiindex)
		},
		{FAL_STP_PORT_ATTR_STATE, .value.u16 = state}
	};

	fal_stp_set_port_attribute(port->ifp->if_index, 2, &attr_list[0]);
}

uint8_t
bridge_port_get_state_vlan(struct bridge_port *port, uint16_t vlan)
{
	int mstiindex = mstp_vlan2msti_index(port->bridge_ifp, vlan);

	return CMM_LOAD_SHARED(port->state[mstiindex]);
}

void
bridge_port_set_state(struct bridge_port *port, uint8_t state)
{
	CMM_STORE_SHARED(port->state[MSTP_MSTI_IST], state);

	const struct fal_attribute_t attr_list[2] = {
		{FAL_STP_PORT_ATTR_INSTANCE,
		 .value.objid = bridge_fal_stp_object(port->bridge_ifp)},
		{FAL_STP_PORT_ATTR_STATE, .value.u16 = state}
	};

	fal_stp_set_port_attribute(port->ifp->if_index, 2, &attr_list[0]);
}

uint8_t
bridge_port_get_state(struct bridge_port *port)
{
	return CMM_LOAD_SHARED(port->state[MSTP_MSTI_IST]);
}

void
bridge_port_flush_vlans(struct bridge_port *port)
{
	bridge_vlan_set_clear(port->vlans);
}

bool
bridge_port_lookup_vlan(struct bridge_port *port, uint16_t vlan)
{
	return bridge_vlan_set_is_member(port->vlans, vlan);
}

bool
bridge_port_synchronize_vlans(struct bridge_port *port,
	struct bridge_vlan_set *new_vlans)
{
	return bridge_port_set_synchronize(port->vlans, new_vlans);
}

void
bridge_port_set_pvid(struct bridge_port *port, uint16_t vlan)
{
	CMM_STORE_SHARED(port->pvid, vlan);
}

uint16_t
bridge_port_get_pvid(struct bridge_port *port)
{
	return CMM_LOAD_SHARED(port->pvid);
}

void
bridge_port_add_untag_vlan(struct bridge_port *port, uint16_t vlan)
{
	bridge_vlan_set_add(port->untag_vlans, vlan);
}

void
bridge_port_remove_untag_vlan(struct bridge_port *port, uint16_t vlan)
{
	bridge_vlan_set_remove(port->untag_vlans, vlan);
}

void
bridge_port_flush_untag_vlans(struct bridge_port *port)
{
	bridge_vlan_set_clear(port->untag_vlans);
}

bool
bridge_port_lookup_untag_vlan(struct bridge_port *port, uint16_t vlan)
{
	return bridge_vlan_set_is_member(port->untag_vlans, vlan);
}

bool
bridge_port_synchronize_untag_vlans(struct bridge_port *port,
	struct bridge_vlan_set *new_untagged)
{
	return bridge_port_set_synchronize(port->untag_vlans, new_untagged);
}

void
bridge_port_reset(struct bridge_port *port)
{
	bridge_port_flush_vlans(port);
	bridge_port_flush_untag_vlans(port);
	bridge_port_set_pvid(port, 0);
}

struct ifnet *bridge_port_get_interface(struct bridge_port *port)
{
	return port->ifp;
}

struct ifnet *bridge_port_get_bridge(struct bridge_port *port)
{
	return port->bridge_ifp;
}

struct bridge_port *bridge_port_from_list_entry(struct cds_list_head *entry)
{
	return cds_list_entry(entry, struct bridge_port, brlink);
}

void bridge_port_add_to_list(struct bridge_port *port,
			     struct cds_list_head *list)
{
	cds_list_add_tail_rcu(&port->brlink, list);
}

bool bridge_port_is_vlan_member(struct bridge_port *port,
				uint16_t vlan)
{
	if (bridge_port_lookup_untag_vlan(port, vlan) ||
	    bridge_port_lookup_vlan(port, vlan) ||
	    bridge_port_get_pvid(port) == vlan)
		return true;

	return false;
}

