/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Multiple Spanning Tree Protocol (MSTP).
 */

#ifndef MSTP_H
#define MSTP_H

#include "bridge_flags.h"
#include "if/bridge/bridge.h"
#include "if_var.h"

/*
 * Impose an arbitrary limit on the number of MSTP Instances. The
 * control-plane (YANG) has already imposed a limit, this is just a
 * backstop.
 */
#define MSTP_MSTI_COUNT (STP_INST_COUNT)
#define MSTP_MSTI_IST   (STP_INST_IST)

static_assert(STP_INST_COUNT == MSTP_MSTI_COUNT,
	      "stp and mstp values don't match");
static_assert(STP_INST_IST == MSTP_MSTI_IST,
	      "stp and mstp values don't match");

struct mstp_vlan2mstiindex {
	int8_t vlan2mstiindex[VLAN_N_VID];
	struct rcu_head rcu;
};

/*
 * Maps a VLAN ID into an MSTI index value for subsequent lookup of
 * the STP state for the associated MSTI (see
 * bridge_port_get_state_vlan()).
 */
static inline int
mstp_vlan2msti_index(const struct ifnet *bridge, uint16_t vlanid)
{
	struct bridge_softc *sc = bridge->if_softc;
	struct mstp_vlan2mstiindex *v2mi =
		rcu_dereference(sc->scbr_vlan2mstiindex);
	int mstiindex = MSTP_MSTI_IST;

	if ((vlanid != 0) && (v2mi != NULL))
		mstiindex = v2mi->vlan2mstiindex[vlanid];

	return mstiindex;
}

fal_object_t mstp_fal_stp_object(const struct ifnet *bridge, int mstiindex);

void mstp_upd_hw_forwarding(const struct ifnet *bridge,
			    const struct ifnet *port);

int
cmd_mstp(FILE *f, int argc, char **argv);
int
cmd_mstp_op(FILE *f, int argc, char **argv);
int
cmd_mstp_ut(FILE *f, int argc, char **argv);
#endif
