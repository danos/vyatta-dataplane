/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Multiple Spanning Tree Protocol (MSTP).
 */

#include <stdlib.h>

#include "assert.h"
#include "if/bridge/bridge.h"
#include "bridge_flags.h"
#include "if_var.h"
#include "mstp.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "util.h"
#include "fal.h"

#include <linux/if_bridge.h> // conflicts with netinet/in.h

#define MSTP_MSTID_MIN 1
#define MSTP_MSTID_MAX 4094
#define MSTP_MSTID_COUNT 4095

/*
 * The below descriptor is a control-plane housekeeping object, it is
 * not used during run-time switching
 */
struct mstp_bridge {
	/*
	 * Maps an MSTI index value back to the corresponding MSTI
	 * identifier. A value of 0 indicates that the index is "free"
	 * (no assigned MSTI identifier)
	 */
	uint16_t index2mstid[MSTP_MSTI_COUNT];
	/*
	 * Maps an MSTI identifier to an MSTI index value.
	 */
	int8_t mstid2index[MSTP_MSTID_COUNT];

	/*
	 * Table of MSTP instance objects produced by the FAL plugin.
	 */
	fal_object_t fal_msti[MSTP_MSTI_COUNT];

	char name[33];
	int revision;
};

static inline struct mstp_bridge *
mstp_bridge_get(const struct ifnet *bridge)
{
	return ((struct bridge_softc *)bridge->if_softc)->scbr_mstp;
}

static int
mstp_mstid_count(const struct mstp_bridge *mstp)
{
	int count = 0;
	int i;

	for (i = 1; i < MSTP_MSTI_COUNT; i++)
		if (mstp->index2mstid[i] > 0)
			count++;

	return count;
}

static int
mstp_mstid2index_lookup(const struct ifnet *bridge, uint16_t mstid)
{
	const struct mstp_bridge *mstp = mstp_bridge_get(bridge);

	return mstp->mstid2index[mstid];
}

static int
mstp_mstid2index_assign(const struct ifnet *bridge, uint16_t mstid)
{
	struct mstp_bridge *mstp = mstp_bridge_get(bridge);
	int i;

	for (i = 1; i < MSTP_MSTI_COUNT; i++)
		if (mstp->index2mstid[i] == 0) {
			mstp->index2mstid[i] = mstid;
			mstp->mstid2index[mstid] = i;
			return i;
		}

	return -1;
}

static void
mstp_mstid2index_release(const struct ifnet *bridge, uint16_t mstid)
{
	struct mstp_bridge *mstp = mstp_bridge_get(bridge);
	int mstiidindex;

	mstiidindex = mstp->mstid2index[mstid];
	mstp->mstid2index[mstid] = -1;
	if (mstiidindex > 0)
		mstp->index2mstid[mstiidindex] = 0;
}

static void
mstp_vlan2mstiindex_free(struct rcu_head *head)
{
	struct mstp_vlan2mstiindex *v2mi =
		caa_container_of(head, struct mstp_vlan2mstiindex, rcu);
	free(v2mi);
}

static struct mstp_vlan2mstiindex *
mstp_vlan2mstiindex_clone(const struct ifnet *bridge)
{
	struct bridge_softc *sc = bridge->if_softc;
	struct mstp_vlan2mstiindex *v2minew;
	struct mstp_vlan2mstiindex *v2miold =
		rcu_dereference(sc->scbr_vlan2mstiindex);

	v2minew = zmalloc_aligned(sizeof(*v2minew));
	if ((v2minew != NULL) && (v2miold != NULL)) {
		memcpy(v2minew->vlan2mstiindex, v2miold->vlan2mstiindex,
		       sizeof(v2minew->vlan2mstiindex));
	}

	return v2minew;
}

fal_object_t mstp_fal_stp_object(const struct ifnet *bridge, int mstiindex)
{
	const struct mstp_bridge *mstp = mstp_bridge_get(bridge);

	return mstp->fal_msti[mstiindex];
}

void mstp_upd_hw_forwarding(const struct ifnet *bridge,
			    const struct ifnet *port)
{
	const struct mstp_bridge *mstp = mstp_bridge_get(bridge);
	int mstiindex;

	if (mstp == NULL)
		return;

	/*
	 * Let the FAL know that the switching state of this port has
	 * changed so that it can add/remove the port from the
	 * hardware spanning tree instances.
	 */
	for (mstiindex = 1; mstiindex < MSTP_MSTI_COUNT; mstiindex++) {
		int mstid = mstp->index2mstid[mstiindex];

		if (mstid == 0)
			continue;

		fal_stp_upd_hw_forwarding(
			mstp_fal_stp_object(bridge, mstiindex),
			port->if_index,
			port->hw_forwarding);
	}
}

static void
mstp_msti_flush(struct ifnet *bridge, struct ifnet *port, uint16_t mstid)
{
	struct bridge_softc *sc = bridge->if_softc;
	int mstidindex = mstp_mstid2index_lookup(bridge, mstid);
	struct mstp_vlan2mstiindex *v2mi =
		rcu_dereference(sc->scbr_vlan2mstiindex);
	uint16_t vid;

	assert(v2mi != NULL);
	DP_DEBUG(BRIDGE, INFO, BRIDGE,
		 "MSTP MSTI %s:%d(%d): flush %s\n",
		 bridge->if_name, mstid, mstidindex, port->if_name);

	/*
	 * Delete all entries with a matching VLAN ID (and a matching
	 * port)
	 */
	if (mstidindex > 0)
		for (vid = 0; vid < VLAN_N_VID; vid++)
			if (v2mi->vlan2mstiindex[vid] == mstidindex)
				bridge_fdb_dynamic_flush_vlan(bridge, port,
							      vid);
}

static void
mstp_msti_state_change(struct ifnet *bridge, struct ifnet *port, uint16_t mstid,
		       enum bridge_ifstate state)
{
	int mstidindex = mstp_mstid2index_lookup(bridge, mstid);

	DP_DEBUG(BRIDGE, INFO, BRIDGE,
		 "MSTP MSTI %s:%d(%d): state change %s %s\n",
		 bridge->if_name, mstid, mstidindex, port->if_name,
		 bridge_get_ifstate_string(state));

	if (mstidindex > 0)
		bridge_port_set_state_msti(port->if_brport, mstidindex, state);
}

static void
mstp_msti_delete(struct ifnet *bridge, uint16_t mstid)
{
	struct mstp_vlan2mstiindex *v2minew;
	int mstidindex;

	/*
	 * Find the index associated with this MSTI
	 */
	mstidindex = mstp_mstid2index_lookup(bridge, mstid);
	if (mstidindex < 0) {
		DP_DEBUG(BRIDGE, DEBUG, BRIDGE,
			 "MSTP MSTI %s:%d: delete of unknown MSTID\n",
			 bridge->if_name, mstid);
		return;
	}

	/*
	 * Take a copy of the mapping table and delete all the VLANs
	 * associated with this MSTI
	 */
	v2minew = mstp_vlan2mstiindex_clone(bridge);
	if (v2minew == NULL) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "MSTP MSTI %s:%d(%d): failed to clone VLAN2MSTIINDEX\n",
			 bridge->if_name, mstid, mstidindex);
		return;
	}

	int vid;

	for (vid = 0; vid < VLAN_N_VID; vid++)
		if (v2minew->vlan2mstiindex[vid] == mstidindex)
			v2minew->vlan2mstiindex[vid] = 0;

	/*
	 * Update the run-time pointers and release the old mapping
	 * table.
	 */
	struct bridge_softc *sc = bridge->if_softc;
	struct mstp_bridge *mstp = sc->scbr_mstp;
	struct mstp_vlan2mstiindex *v2miold =
		rcu_xchg_pointer(&sc->scbr_vlan2mstiindex, v2minew);

	call_rcu(&v2miold->rcu, mstp_vlan2mstiindex_free);
	mstp_mstid2index_release(bridge, mstid);

	/*
	 * Finally set the state to DISABLED for all the VLANs that
	 * were mapped to this MSTI. Note that the actual port state
	 * (MSTI index 0) remains untouched.
	 */
	struct cds_list_head *entry;
	struct bridge_port *port;

	bridge_for_each_brport(port, entry, sc)
		bridge_port_set_state_msti(port, mstidindex,
					   STP_IFSTATE_DISABLED);

	DP_DEBUG(BRIDGE, INFO, BRIDGE,
		 "MSTP MSTI %s:%d(%d): delete\n",
		 bridge->if_name, mstid, mstidindex);

	int ret = fal_stp_upd_msti(mstp->fal_msti[mstidindex], 0, NULL);

	if (ret < 0)
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "MSTP MSTI %s:%d: FAL update failed: '%s'\n",
			 bridge->if_name, mstid, strerror(-ret));

	fal_stp_delete(mstp->fal_msti[mstidindex]);
}

static void
mstp_msti_update(struct ifnet *bridge, uint16_t mstid,
		 int vlancount, const uint16_t *vlans)
{
	struct mstp_vlan2mstiindex *v2minew;
	int mstidindex;
	bool update = true;

	/*
	 * Does the MSTI exist (an index exists) or is this
	 * something new?
	 */
	mstidindex = mstp_mstid2index_lookup(bridge, mstid);
	if (mstidindex < 0) {
		mstidindex = mstp_mstid2index_assign(bridge, mstid);
		if (mstidindex < 0) {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				 "MSTP MSTI %s:%d: no free index\n",
				 bridge->if_name, mstid);
			return;
		}
		update = false;
	}

	/*
	 * Either create a new mapping table (MSTI create) or clone
	 * the existing table (MSTI update)
	 */
	v2minew = mstp_vlan2mstiindex_clone(bridge);
	if (v2minew == NULL) {
		mstp_mstid2index_release(bridge, mstid);
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "MSTP MSTI %s:%d(%d): failed to clone VLAN2MSTIINDEX\n",
			 bridge->if_name, mstid, mstidindex);
		return;
	}

	/*
	 * If its an MSTI update, remove the existing VLAN entries
	 * that map to this MSTI. Then update the map with the new
	 * VLANs.
	 */
	if (update) {
		int vid;

		for (vid = 0; vid < VLAN_N_VID; vid++)
			if (v2minew->vlan2mstiindex[vid] == mstidindex)
				v2minew->vlan2mstiindex[vid] = 0;
	}

	int i;

	for (i = 0; i < vlancount; i++)
		v2minew->vlan2mstiindex[vlans[i]] = mstidindex;

	/*
	 * Finally update the run-time pointers and release any old
	 * mapping table.
	 */
	struct bridge_softc *sc = bridge->if_softc;
	struct mstp_vlan2mstiindex *v2miold =
		rcu_xchg_pointer(&sc->scbr_vlan2mstiindex, v2minew);

	if (v2miold != NULL)
		call_rcu(&v2miold->rcu, mstp_vlan2mstiindex_free);

	DP_DEBUG(BRIDGE, INFO, BRIDGE,
		 "MSTP MSTI %s:%d(%d): %s\n",
		 bridge->if_name, mstid, mstidindex,
		 update ? "update" : "create");

	assert(STP_INST_COUNT == MSTP_MSTI_COUNT);
	assert(STP_INST_IST == MSTP_MSTI_IST);

	struct mstp_bridge *mstp = sc->scbr_mstp;
	int ret = 0;

	if (!update) {
		const struct fal_attribute_t attr_list[2] = {
			{FAL_STP_ATTR_INSTANCE, .value.u8 = mstidindex},
			{FAL_STP_ATTR_MSTI, .value.u16 = mstid}
		};

		ret = fal_stp_create(bridge->if_index, 2, &attr_list[0],
				     &mstp->fal_msti[mstidindex]);
	}

	if (ret == 0)
		ret = fal_stp_upd_msti(mstp->fal_msti[mstidindex],
				       vlancount, vlans);

	if (ret < 0)
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "MSTP MSTI %s:%d: FAL update failed: '%s'\n",
			 bridge->if_name, mstid, strerror(-ret));
}

static void
mstp_bridge_delete(struct ifnet *bridge)
{
	struct bridge_softc *sc = bridge->if_softc;
	struct mstp_bridge *mstp = sc->scbr_mstp;

	struct mstp_vlan2mstiindex *v2mi =
		rcu_dereference(sc->scbr_vlan2mstiindex);

	if (v2mi != NULL) {
		rcu_assign_pointer(sc->scbr_vlan2mstiindex, NULL);
		call_rcu(&v2mi->rcu, mstp_vlan2mstiindex_free);
	}

	sc->scbr_mstp = NULL;
	DP_DEBUG(BRIDGE, INFO, BRIDGE,
		 "MSTP REGION %s:%s(%d): delete\n",
		 bridge->if_name, mstp->name, mstp->revision);
	free(mstp);
}

static void
mstp_bridge_update(struct ifnet *bridge, const char *name, int revision)
{
	struct bridge_softc *sc = bridge->if_softc;
	struct mstp_bridge *mstp = sc->scbr_mstp;
	const char *action = "update";

	if (mstp == NULL) {
		mstp = malloc(sizeof(*mstp));
		if (mstp == NULL) {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				 "MSTP REGION %s:%s(%d): "
				 "failed to create MSTP\n",
				 bridge->if_name, name, revision);
			return;
		}

		memset(mstp, 0, sizeof(*mstp));

		int i;
		for (i = 0; i < MSTP_MSTID_COUNT; i++)
			mstp->mstid2index[i] = -1;

		mstp->index2mstid[0] = 0;
		sc->scbr_mstp = mstp;
		action = "create";
	}

	mstp->revision = revision;
	snprintf(mstp->name, sizeof(mstp->name), "%s", name);

	DP_DEBUG(BRIDGE, INFO, BRIDGE,
		 "MSTP REGION %s:%s(%d): %s\n",
		 bridge->if_name, name, revision, action);
}

static bool
mstp_fal_get_stp_state(const struct ifnet *bridge,
		       struct bridge_port *port,
		       int stpinst, enum bridge_ifstate *brstate)
{
	struct fal_attribute_t attr_list[2];

	attr_list[0].id = FAL_STP_PORT_ATTR_INSTANCE;
	attr_list[1].id = FAL_STP_PORT_ATTR_STATE;

	if (stpinst == MSTP_MSTI_IST)
		attr_list[0].value.objid = bridge_fal_stp_object(bridge);
	else
		attr_list[0].value.objid = mstp_fal_stp_object(bridge, stpinst);

	if (fal_stp_get_port_attribute(
		    bridge_port_get_interface(port)->if_index,
		    2, &attr_list[0]) == 1) {
		*brstate = attr_list[1].value.u8;
		return true;
	}

	return false;
}

static void
mstp_show_add_ports(json_writer_t *wr, const struct ifnet *bridge)
{
	struct bridge_softc *sc = bridge->if_softc;
	struct cds_list_head *entry;
	struct bridge_port *port;
	enum bridge_ifstate fal_state;

	jsonw_name(wr, "switch-ports");
	jsonw_start_array(wr);
	bridge_for_each_brport(port, entry, sc) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "port",
				   bridge_port_get_interface(port)->if_name);
		jsonw_string_field(wr, "state",
				   bridge_get_ifstate_string(
					   bridge_port_get_state(port)));
		if (mstp_fal_get_stp_state(bridge, port,
					   MSTP_MSTI_IST,
					   &fal_state))
			jsonw_string_field(wr,
					   "HW-state",
					   bridge_get_ifstate_string(
						   fal_state));
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
}

static void
mstp_show_add_vlans(json_writer_t *wr, const struct mstp_bridge *mstp,
		    const struct ifnet *bridge,
		    const struct mstp_vlan2mstiindex *v2mi,
		    uint16_t vlanid)
{
	struct bridge_softc *sc = bridge->if_softc;
	int mstidindex = v2mi->vlan2mstiindex[vlanid];
	int mstid = mstp->index2mstid[mstidindex];

	if (mstid <= 0)
		return;

	jsonw_start_object(wr);
	jsonw_int_field(wr, "vlanid", vlanid);
	jsonw_int_field(wr, "mstid", mstid);

	struct cds_list_head *entry;
	struct bridge_port *port;
	enum bridge_ifstate fal_state;

	jsonw_name(wr, "switch-ports");
	jsonw_start_array(wr);
	bridge_for_each_brport(port, entry, sc) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "port",
				   bridge_port_get_interface(port)->if_name);
		jsonw_string_field(wr, "state",
				   bridge_get_ifstate_string(
					   bridge_port_get_state_vlan(
						   port, vlanid)));
		if (mstp_fal_get_stp_state(bridge, port,
					   mstidindex,
					   &fal_state))
			jsonw_string_field(wr,
					   "HW-state",
					   bridge_get_ifstate_string(
						   fal_state));
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
}

static void
mstp_show_add_mstis(json_writer_t *wr, const struct mstp_bridge *mstp,
		    const struct mstp_vlan2mstiindex *v2mi,
		    int index)
{
	uint16_t mstpid = mstp->index2mstid[index];
	uint16_t vid;

	if (mstpid == 0)
		return;

	jsonw_start_object(wr);
	jsonw_int_field(wr, "mstid", mstpid);
	jsonw_int_field(wr, "mstid-index", index);

	jsonw_name(wr, "vlans");
	jsonw_start_array(wr);
	if (v2mi != NULL)
		for (vid = 0; vid < VLAN_N_VID; vid++)
			if (v2mi->vlan2mstiindex[vid] == index)
				jsonw_uint(wr, vid);
	jsonw_end_array(wr);

	jsonw_end_object(wr);
}

static void
mstp_bridge_show(json_writer_t *wr, const struct ifnet *bridge)
{
	const struct bridge_softc *sc = bridge->if_softc;
	const struct mstp_bridge *mstp = sc->scbr_mstp;
	const struct mstp_vlan2mstiindex *v2mi =
		rcu_dereference(sc->scbr_vlan2mstiindex);
	int i;

	if (mstp == NULL)
		return;

	jsonw_name(wr, "region");
	jsonw_start_object(wr);
	jsonw_string_field(wr, "switch", bridge->if_name);
	jsonw_string_field(wr, "name", mstp->name);
	jsonw_int_field(wr, "revision", mstp->revision);
	jsonw_int_field(wr, "msti-count", mstp_mstid_count(mstp));
	jsonw_end_object(wr);

	mstp_show_add_ports(wr, bridge);

	jsonw_name(wr, "msti-list");
	jsonw_start_array(wr);
	for (i = 0; i < MSTP_MSTI_COUNT; i++)
		mstp_show_add_mstis(wr, mstp, v2mi, i);
	jsonw_end_array(wr);

	jsonw_name(wr, "vlan-list");
	jsonw_start_array(wr);
	if (v2mi != NULL)
		for (i = 0; i < VLAN_N_VID; i++)
			mstp_show_add_vlans(wr, mstp, bridge, v2mi, i);
	jsonw_end_array(wr);
}

/*
 ******************************************************************************
 *
 * Parsing and configuration functions
 *
 ******************************************************************************
 */

enum mstp_cfg_action {
	mstp_cfg_act_add,
	mstp_cfg_act_update,
	mstp_cfg_act_delete
};

enum mstp_cfg_object {
	mstp_cfg_obj_region,
	mstp_cfg_obj_msti,
	mstp_cfg_obj_state
};

struct mstp_cmd {
	FILE *f;
	int argc;
	char **argv;
	enum mstp_cfg_action action;
	enum mstp_cfg_object object;
	const char *name;
	struct ifnet *bridge;
	struct ifnet *port;
	unsigned int revision;
	int mstid;
	enum bridge_ifstate msti_state;
	int msti_vlan_count;
	uint16_t msti_vlans[VLAN_N_VID];
};

__attribute__((format(printf, 2, 3))) static int
mstp_cmd_error(const struct mstp_cmd *cmd, const char *format, ...)
{
	char line[1024];
	va_list ap;

	va_start(ap, format);
	vsnprintf(line, sizeof(line), format, ap);
	va_end(ap);

	DP_DEBUG(BRIDGE, ERR, BRIDGE, "MSTP (%s): %s\n", cmd->bridge->if_name,
		 line);
	fprintf(cmd->f, "MSTP %s\n", line);
	return -1;
}

static int
mstp_get_msti(struct mstp_cmd *cmd, const char *mstistr, int *msti)
{
	int value;

	if (get_signed(mstistr, &value) < 0)
		return mstp_cmd_error(cmd,
				      "invalid MSTI string: %s",
				      mstistr);

	if ((value < MSTP_MSTID_MIN) || (value > MSTP_MSTID_MAX))
		return mstp_cmd_error(cmd,
				      "invalid MSTI number: %u",
				      value);

	*msti = value;
	return 0;
}

/*
 * clear macs port <port> msti <msti>
 */
static int
mstp_clear(struct mstp_cmd *cmd)
{
	if (!streq(cmd->argv[0], "macs"))
		return mstp_cmd_error(cmd, "unknown clear command: %s",
				      cmd->argv[0]);

	cmd->argc--, cmd->argv++;
	if (cmd->argc < 4)
		return mstp_cmd_error(cmd, "missing clear parameters: %d",
				      cmd->argc);

	if (!streq(cmd->argv[0], "port"))
		return mstp_cmd_error(cmd, "unknown clear keyword: %s",
				      cmd->argv[0]);

	cmd->port = bridge_cmd_get_port(cmd->f, cmd->bridge, cmd->argv[1]);
	if (cmd->port == NULL)
		return -1;

	if (!streq(cmd->argv[2], "msti"))
		return mstp_cmd_error(cmd, "unknown clear keyword: %s",
				      cmd->argv[2]);

	if (mstp_get_msti(cmd, cmd->argv[3], &cmd->mstid) < 0)
		return -1;

	if (mstp_bridge_get(cmd->bridge) == NULL)
		DP_DEBUG(BRIDGE, DEBUG, BRIDGE,
			 "MSTP MSTI %s:%d: missing bridge for flush\n",
			 cmd->bridge->if_name, cmd->mstid);
	else
		mstp_msti_flush(cmd->bridge, cmd->port, cmd->mstid);

	return 0;
}

/*
 * show state
 */
static int
mstp_show(struct mstp_cmd *cmd)
{
	if (!streq(cmd->argv[0], "state"))
		return mstp_cmd_error(cmd, "unknown show command: %s",
				      cmd->argv[0]);

	json_writer_t *wr = jsonw_new(cmd->f);

	if (wr == NULL)
		return mstp_cmd_error(cmd, "cannot create json_writer_t");

	mstp_bridge_show(wr, cmd->bridge);

	jsonw_destroy(&wr);
	return 0;
}

/*
 * Map the Linux bridge state, as generated by MSTPd, into the
 * equivalent STP state as used by the bridge modules. The two look to
 * be identical, but play safe and check the input from the daemon.
 *
 * Note that for display purposes, MSTPd maps the bridge state into
 * different strings. The BR_STATE_DISABLED, BR_STATE_BLOCKING &
 * BR_STATE_LISTENING states are all mapped to "discarding".
 */
static bool
mstp_map_msti_state(int msti_state, enum bridge_ifstate *brstate)
{
	switch (msti_state) {
	case BR_STATE_DISABLED:
		*brstate = STP_IFSTATE_DISABLED;
		return true;
	case BR_STATE_LISTENING:
		*brstate = STP_IFSTATE_LISTENING;
		return true;
	case BR_STATE_LEARNING:
		*brstate = STP_IFSTATE_LEARNING;
		return true;
	case BR_STATE_FORWARDING:
		*brstate = STP_IFSTATE_FORWARDING;
		return true;
	case BR_STATE_BLOCKING:
		*brstate = STP_IFSTATE_BLOCKING;
		return true;
	default:
		break;
	}

	return false;
}

static int
mstp_parse_state(struct mstp_cmd *cmd)
{
	int msti_state;
	enum bridge_ifstate brstate;

	cmd->object = mstp_cfg_obj_state;

	if (cmd->argc < 2)
		return mstp_cmd_error(cmd,
				      "missing state parameters: %d",
				      cmd->argc);

	if (get_signed(cmd->argv[1], &msti_state) < 0)
		return mstp_cmd_error(cmd,
				      "invalid state string: %s",
				      cmd->argv[1]);

	if (!mstp_map_msti_state(msti_state, &brstate))
		return mstp_cmd_error(cmd,
				      "invalid MSTI state: %i",
				      msti_state);

	if (!streq(cmd->argv[2], "port"))
		return mstp_cmd_error(cmd, "unknown state keyword: %s",
				      cmd->argv[2]);

	cmd->port = bridge_cmd_get_port(cmd->f, cmd->bridge, cmd->argv[3]);
	if ((cmd->port == NULL) && (cmd->action != mstp_cfg_act_delete))
		return -1;

	if (!streq(cmd->argv[4], "msti"))
		return mstp_cmd_error(cmd, "unknown state keyword: %s",
				      cmd->argv[4]);

	if (mstp_get_msti(cmd, cmd->argv[5], &cmd->mstid) < 0)
		return -1;

	cmd->msti_state = brstate;
	return 0;
}

static void
mstp_parse_vlans(struct mstp_cmd *cmd, char *vlanstr)
{
	const char *vidstr;
	char *saveptr = NULL;

	if (vlanstr == NULL)
		return;

	for (vidstr = strtok_r(vlanstr, ":", &saveptr);
	     vidstr != NULL;
	     vidstr = strtok_r(NULL, ":", &saveptr)) {
		unsigned int vid;

		if (get_unsigned(vidstr, &vid) < 0 ||
		    (vid < 1 || vid >= VLAN_N_VID)) {
			DP_DEBUG(BRIDGE, INFO, BRIDGE,
				 "MSTP MSTI %s:%d: ignoring invalid VLAN-ID: %s\n",
				 cmd->bridge->if_name, cmd->mstid, vidstr);
			continue;
		}

		if (cmd->msti_vlan_count >= VLAN_N_VID) {
			DP_DEBUG(BRIDGE, INFO, BRIDGE,
				 "MSTP MSTI %s:%d: too many VLAN-IDs: %d\n",
				 cmd->bridge->if_name, cmd->mstid,
				 cmd->msti_vlan_count);
			break;
		}

		cmd->msti_vlans[cmd->msti_vlan_count] = vid;
		cmd->msti_vlan_count++;
	}
}

static int
mstp_parse_msti(struct mstp_cmd *cmd)
{
	cmd->object = mstp_cfg_obj_msti;
	cmd->msti_vlan_count = 0;

	if (cmd->argc < 2)
		return mstp_cmd_error(cmd,
				      "missing MSTI number: %u",
				      cmd->argc);

	if (mstp_get_msti(cmd, cmd->argv[1], &cmd->mstid) < 0)
		return -1;

	if (cmd->argc == 2)
		return 0;

	if (!streq(cmd->argv[2], "vlans"))
		return mstp_cmd_error(cmd, "unknown MSTI keyword: '%s'",
				      cmd->argv[2]);

	mstp_parse_vlans(cmd, cmd->argv[3]);
	if (cmd->msti_vlan_count == 0)
		return mstp_cmd_error(cmd, "missing list of VLAN-IDs");

	return 0;
}

static int
mstp_parse_region(struct mstp_cmd *cmd)
{
	cmd->object = mstp_cfg_obj_region;
	if (cmd->argc < 3)
		return mstp_cmd_error(cmd,
				      "missing region parameters: %u",
				      cmd->argc);

	if (!streq(cmd->argv[1], "name"))
		return mstp_cmd_error(cmd, "missing region name keyword: '%s'",
				      cmd->argv[1]);
	cmd->name = cmd->argv[2];

	if (cmd->action != mstp_cfg_act_delete) {
		if (cmd->argc < 5)
			return mstp_cmd_error(cmd,
					      "missing region revision: %u",
					      cmd->argc);

		if (!streq(cmd->argv[3], "revision"))
			return mstp_cmd_error(cmd,
					      "missing region revision "
					      "keyword: '%s'", cmd->argv[3]);

		if (get_unsigned(cmd->argv[4], &cmd->revision) < 0)
			return mstp_cmd_error(cmd,
					      "invalid revision string: %s",
					      cmd->argv[4]);
		if (cmd->revision > USHRT_MAX)
			return mstp_cmd_error(cmd,
					      "invalid revision number: %u",
					      cmd->revision);
	}

	return 0;
}

static void
mstp_config_set_state(const struct mstp_cmd *cmd)
{
	if (cmd->action == mstp_cfg_act_delete) {
		DP_DEBUG(BRIDGE, INFO, BRIDGE,
			 "MSTP MSTI %s:%d: ignoring state delete: %d\n",
			 cmd->bridge->if_name, cmd->mstid,
			 cmd->msti_state);
		return;
	}

	if (mstp_bridge_get(cmd->bridge) == NULL)
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "MSTP MSTI %s:%d: missing descriptor "
			 "for state change\n",
			 cmd->bridge->if_name, cmd->mstid);
	else
		mstp_msti_state_change(cmd->bridge, cmd->port,
				       cmd->mstid, cmd->msti_state);
}

static void
mstp_config_msti(const struct mstp_cmd *cmd)
{
	if (mstp_bridge_get(cmd->bridge) == NULL) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "MSTP MSTI %s:%d: missing descriptor\n",
			 cmd->bridge->if_name, cmd->mstid);
		return;
	}

	if (cmd->action == mstp_cfg_act_delete)
		mstp_msti_delete(cmd->bridge, cmd->mstid);
	else
		mstp_msti_update(cmd->bridge, cmd->mstid,
				 cmd->msti_vlan_count,
				 cmd->msti_vlans);
}

static void
mstp_config_bridge(const struct mstp_cmd *cmd)
{
	if (cmd->action != mstp_cfg_act_delete) {
		mstp_bridge_update(cmd->bridge, cmd->name, cmd->revision);
		return;
	}

	if (mstp_bridge_get(cmd->bridge) != NULL) {
		mstp_bridge_delete(cmd->bridge);
		return;
	}

	DP_DEBUG(BRIDGE, DEBUG, BRIDGE,
		 "MSTP REGION %s:%s: spurious delete\n",
		 cmd->bridge->if_name, cmd->name);
}

/*
 * config action [delete|update] region name <name> revision <revision>
 * config action [delete|update] msti <id> [vlans <id-list>]
 * config action [delete|update] state <state> port <port> msti <id>
 */
static int
mstp_config(struct mstp_cmd *cmd)
{
	int ret;

	if (!streq(cmd->argv[0], "action"))
		return mstp_cmd_error(cmd, "missing action keyword: '%s'",
				      cmd->argv[0]);
	cmd->argc--, cmd->argv++;
	if (streq(cmd->argv[0], "update"))
		cmd->action = mstp_cfg_act_update;
	else if (streq(cmd->argv[0], "delete"))
		cmd->action = mstp_cfg_act_delete;
	else
		return mstp_cmd_error(cmd, "unknown action: '%s'",
				      cmd->argv[0]);

	cmd->argc--, cmd->argv++;
	if (cmd->argc == 0)
		return mstp_cmd_error(cmd, "missing configuration object");

	if (streq(cmd->argv[0], "region"))
		ret = mstp_parse_region(cmd);
	else if (streq(cmd->argv[0], "msti"))
		ret = mstp_parse_msti(cmd);
	else if (streq(cmd->argv[0], "state"))
		ret = mstp_parse_state(cmd);
	else
		return mstp_cmd_error(cmd, "unknown object: '%s'",
				      cmd->argv[0]);

	if (ret == 0)
		switch (cmd->object) {
		case mstp_cfg_obj_region:
			mstp_config_bridge(cmd);
			break;
		case mstp_cfg_obj_msti:
			mstp_config_msti(cmd);
			break;
		case mstp_cfg_obj_state:
			mstp_config_set_state(cmd);
			break;
		}

	return ret;
}

static int
mstp_setup_cmd(FILE *f, int argc, char **argv, int minargs, const char *func,
	       struct mstp_cmd *cmd, const char **cmdstr)
{
	struct ifnet *bridge;

	if (argc < minargs) {
		fprintf(f, "%s: missing arguments: %d", func, argc);
		return -1;
	}

	argc--, argv++; /* skip 'mstp' */
	bridge = dp_ifnet_byifname(argv[0]);
	if (!bridge || !bridge->if_softc ||
	    bridge->if_type != IFT_BRIDGE) {
		fprintf(f, "Unknown bridge: %s\n", argv[0]);
		return -1;
	}

	argc--, argv++; /* skip '<bridge>' */
	*cmdstr = argv[0];
	argc--, argv++; /* skip '<cmd>' */

	assert(argc > 0);
	assert(argv[0] != NULL);

	cmd->f = f;
	cmd->argc = argc;
	cmd->argv = argv;
	cmd->bridge = bridge;
	cmd->port = NULL;
	cmd->name = NULL;
	cmd->revision = 0;
	cmd->mstid = -1;
	cmd->msti_vlan_count = 0;
	cmd->msti_state = __STP_IFSTATE_MAX;
	return 0;
}

/*
 * mstp <bridge> config ...
 */
int
cmd_mstp(FILE *f, int argc, char **argv)
{
	struct mstp_cmd cmd;
	const char *cmdstr;

	if (mstp_setup_cmd(f, argc, argv, 4, __func__, &cmd, &cmdstr) < 0)
		return -1;

	if (streq(cmdstr, "config"))
		return mstp_config(&cmd);

	return mstp_cmd_error(&cmd, "unknown command: %s", cmdstr);
}

/*
 * mstp-op <bridge> clear ...
 * mstp-op <bridge> show ...
 */
int
cmd_mstp_op(FILE *f, int argc, char **argv)
{
	struct mstp_cmd cmd;
	const char *cmdstr;

	if (mstp_setup_cmd(f, argc, argv, 4, __func__, &cmd, &cmdstr) < 0)
		return -1;

	if (streq(cmdstr, "clear"))
		return mstp_clear(&cmd);

	if (streq(cmdstr, "show"))
		return mstp_show(&cmd);

	return mstp_cmd_error(&cmd, "unknown opmode command: %s", cmdstr);
}

int
cmd_mstp_ut(FILE *f, int argc, char **argv)
{
	return cmd_mstp(f, argc, argv);
}
