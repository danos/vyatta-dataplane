/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <libmnl/libmnl.h>
#include <rte_debug.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <stdint.h>
/*
 * VRF implementation
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "crypto/vti.h"
#include "dp_event.h"
#include "if/gre.h"
#include "ip_mcast.h"
#include "lpm/lpm.h"
#include "main.h"
#include "npf/fragment/ipv4_rsmbl.h"
#include "npf_shim.h"
#include "route_v6.h"
#include "rt_tracker.h"
#include "session/session.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "vrf_if.h"

struct nlattr;

struct vrf *vrf_table[VRF_ID_MAX] __hot_data = {NULL};

/*
 * Infrastructure to handle table maps received out of order
 * w.r.t netlink.
 */
struct tablemap_list_entry {
	struct cds_list_head  le_node;
	vrfid_t		      vrfid;
	uint32_t	      kernel_tblids[PBR_TABLEID_MAX + 1];
};

struct tablemap_list {
	struct cds_list_head  list;
	int                   list_count;
};

static struct tablemap_list *tablemap_list;

static struct tablemap_list *tablemap_list_create(void)
{
	struct tablemap_list *tablemap_list;

	tablemap_list = zmalloc_aligned(sizeof(*tablemap_list));
	if (!tablemap_list) {
		RTE_LOG(ERR, DATAPLANE, "Unable to create tablemap list\n");
		return NULL;
	}

	CDS_INIT_LIST_HEAD(&tablemap_list->list);
	tablemap_list->list_count = 0;

	return tablemap_list;
}

static struct tablemap_list_entry *
tablemap_list_lookup(struct tablemap_list *tablemap_list,
		     vrfid_t vrfid)
{
	struct tablemap_list_entry *le;

	if (!tablemap_list)
		return NULL;

	cds_list_for_each_entry(le, &tablemap_list->list, le_node) {
		if (le->vrfid == vrfid)
			return le;
	}

	return NULL;
}

static int tablemap_list_add(struct tablemap_list *tablemap_list,
			     vrfid_t vrfid, uint8_t pbr_tblid,
			     uint32_t kernel_tblid)
{
	struct tablemap_list_entry *le;

	if (!tablemap_list) {
		RTE_LOG(ERR, DATAPLANE, "No tablemap to add\n");
		return -ENOENT;
	}

	le = tablemap_list_lookup(tablemap_list, vrfid);
	if (!le) {
		le = zmalloc_aligned(sizeof(*le));
		if (!le) {
			RTE_LOG(ERR, DATAPLANE,
				"Can't allocate tablemap entry\n");
			return -ENOMEM;
		}

		le->vrfid = vrfid;

		cds_list_add_tail(&le->le_node, &tablemap_list->list);
		tablemap_list->list_count++;
	}

	le->kernel_tblids[pbr_tblid] = kernel_tblid;

	return 0;
}

static int
tablemap_list_del(struct tablemap_list *tablemap_list, vrfid_t vrfid)
{
	struct tablemap_list_entry *le;

	if (!tablemap_list || tablemap_list->list_count == 0)
		return -ENOENT;

	le = tablemap_list_lookup(tablemap_list, vrfid);
	if (!le)
		return -ENOENT;

	cds_list_del(&le->le_node);
	tablemap_list->list_count--;

	free(le);

	return 0;
}

static void
vrf_destroy(struct rcu_head *head)
{
	struct vrf *self = caa_container_of(head, struct vrf, rcu);

	if (self) {
		route_uninit(self, &self->v_rt4_head);
		route_v6_uninit(self, &self->v_rt6_head);
		gre_table_uninit(self);
		vti_table_uninit(self);
		fragment_tables_uninit(self);
		mcast_vrf_uninit(self);
		mcast6_vrf_uninit(self);
		npf_vrf_destroy(self);
		rt_tracker_uninit(self);

		if (self->v_pbrtablemap)
			free(self->v_pbrtablemap);

		free(self);
	}
}

/*
 * Ref count records one count per -
 * 1. Interface bound to the VRF
 * 2. Explicit vrf creation cmd - each of these is interpreted
 * as denoting the existence of a 'reference' held in the
 * kernel or above until an explicit delete is received.
 * 3. Other features referencing VRF
 */
static inline void
vrf_inc_ref_count(struct vrf *vrf)
{
	assert(vrf->v_ref_count < UINT32_MAX);
	vrf->v_ref_count++;
}

/*
 * Check if tablemap was received from controller before the
 * relevant VRF was created.
 */
static void vrf_find_saved_tablemap(struct vrf *vrf)
{
	struct tablemap_list_entry *tle;
	vrfid_t vrf_id = vrf->v_external_id;

	tle = tablemap_list_lookup(tablemap_list, vrf_id);

	if (tle) {
		int i;

		for (i = 0; i <= PBR_TABLEID_MAX; i++) {
			if (tle->kernel_tblids[i])
				vrf->v_pbrtablemap[i] = tle->kernel_tblids[i];
		}
		tablemap_list_del(tablemap_list, vrf_id);
	}
}

static struct vrf *
vrf_alloc(vrfid_t vrf_id)
{
	struct vrf *vrf_var;

	vrf_var = zmalloc_aligned(sizeof(struct vrf) +
				  (get_lcore_max() + 1) *
				  sizeof(struct vrf_per_core_stats));
	if (!vrf_var)
		goto err;

	vrf_var->v_id = vrf_id;

	if (route_init(vrf_var) < 0)
		goto err;

	if (route_v6_init(vrf_var) < 0)
		goto err;

	if (gre_table_init(vrf_var) < 0)
		goto err;

	if (vti_table_init(vrf_var) < 0)
		goto err;

	if (fragment_tables_init(vrf_var) < 0)
		goto err;

	if (mcast_vrf_init(vrf_var) < 0)
		goto err;

	if (mcast6_vrf_init(vrf_var) < 0)
		goto err;

	if (vrf_id != VRF_DEFAULT_ID) {
		vrf_var->v_pbrtablemap = calloc(PBR_TABLEID_MAX + 1,
						sizeof(uint32_t));
		if (vrf_var->v_pbrtablemap == NULL) {
			DP_LOG_W_VRF(ERR, ROUTE, vrf_id,
				     "Unable to create table map\n");
			goto err;
		}
	}

	return vrf_var;
err:
	if (vrf_var)
		vrf_destroy(&vrf_var->rcu);

	return NULL;
}

static struct vrf*
vrf_create(vrfid_t vrf_id)
{
	struct vrf *vrf_var;

	if (vrf_id >= VRF_ID_MAX) {
		DP_LOG_W_VRF(ERR, DATAPLANE, vrf_id, "ID > %d\n",
			     VRF_ID_MAX);
		return NULL;
	}

	vrf_var = get_vrf(vrf_id);
	if (vrf_var) {
		/*  this is an error - if the vrf might exist already then
		 *  the caller should have called vrf_find_or_create() instead.
		 */
		DP_LOG_W_VRF(ERR, DATAPLANE, vrf_id,
			     "VRF already exists\n");
		return NULL;
	}

	vrf_var = vrf_alloc(vrf_id);
	if (vrf_var == NULL)
		return NULL;

	vrf_inc_ref_count(vrf_var);
	rcu_assign_pointer(vrf_table[vrf_id], vrf_var);
	return vrf_var;
}

/*
 * Find or create a vrf struct given its ID.
 * Return a reference having incremented the refcount
 * of the vrf to reflect this..
 */
struct vrf *
vrf_find_or_create(vrfid_t vrf_id)
{
	struct vrf *vrf_var;

	vrf_var = get_vrf(vrf_id);
	if (!vrf_var) {
		vrf_var = vrf_create(vrf_id);
		if  (!vrf_var) {
			DP_LOG_W_VRF(ERR, DATAPLANE, vrf_id,
				     "Failed to create VRF\n");
			return NULL;
		}
	} else {
		vrf_inc_ref_count(vrf_var);
	}
	return vrf_var;
}

void vrf_delete_by_ptr(struct vrf *vrf)
{
	vrfid_t vrf_id;

	if (unlikely(vrf == NULL)) {
		DP_LOG_W_VRF(ERR, DATAPLANE, VRF_INVALID_ID,
			     "VRF is already NULL\n");
		return;
	}

	vrf_id = vrf->v_id;

	/* refcount of invalid vrf is fixed at 1 */
	if (vrf_id == VRF_INVALID_ID && running)
		return;

	assert(vrf->v_ref_count != 0);

	vrf->v_ref_count--;

	if (vrf->v_ref_count > 0) {
		/* Still a few folks are referring to me */
		return;
	}
	DP_DEBUG_W_VRF(VRF, DEBUG, DATAPLANE, vrf_id,
		       "Deleted VRF successfully\n");

	dp_event(DP_EVT_VRF_DELETE, 0, vrf, 0, 0, NULL);

	/* All references must be gone, and all threads using
	 * pointer are done, safe to remove.
	 */
	vrf_table[vrf_id] = NULL;

	call_rcu(&vrf->rcu, vrf_destroy);
}

void vrf_delete(vrfid_t vrf_id)
{
	struct vrf *vrf_var = get_vrf(vrf_id);

	if (vrf_var == NULL)
		DP_LOG_W_VRF(ERR, DATAPLANE, vrf_id,
			     "No VRF found\n");

	vrf_delete_by_ptr(vrf_var);
}

struct ifnet *vrfmaster_create(const char *ifname, uint32_t if_index,
			       uint32_t vrf_tableid)
{
	struct vrf_softc *vrsc;
	struct ifnet *ifp;

	ifp = if_alloc(ifname, IFT_VRFMASTER, 65535, NULL, SOCKET_ID_ANY);
	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE,
			"out of memory for vrf_ifnet\n");
		return NULL;
	}

	vrsc = malloc(sizeof(*vrsc));
	if (!vrsc) {
		if_free(ifp);
		return NULL;
	}
	vrsc->vrfsc_tableid = vrf_tableid;
	ifp->if_softc = vrsc;

	if_set_ifindex(ifp, if_index);

	return ifp;
}

static void vrfmaster_free_rcu(struct rcu_head *head)
{
	struct vrf_softc *vrsc =
		caa_container_of(head, struct vrf_softc, vrfsc_rcu);

	free(vrsc);
}

static void vrfmaster_delete(struct ifnet *ifp)
{
	struct vrf_softc *vrsc = ifp->if_softc;

	call_rcu(&vrsc->vrfsc_rcu, vrfmaster_free_rcu);
}

static void vrfmaster_show_info(json_writer_t *wr, struct ifnet *ifp)
{
	struct vrf_softc *vrsc = ifp->if_softc;

	jsonw_name(wr, "vrfmaster");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "tableid", vrsc->vrfsc_tableid);
	jsonw_end_object(wr);
}

vrfid_t vrfmaster_get_vrfid(struct ifnet *ifp)
{
	struct vrf *vrf;
	vrfid_t i;

	assert(ifp->if_type == IFT_VRFMASTER);

	if (ifp->if_vrfid != VRF_DEFAULT_ID)
		return ifp->if_vrfid;

	/* Newly created - find first available id */
	for (i = 0; i < VRF_ID_MAX; i++) {
		vrf = get_vrf(i);
		if (!vrf)
			return i;
	}

	/* All out of IDs - shouldn't happen */
	return VRF_INVALID_ID;
}

void vrf_set_external_id(struct vrf *vrf, vrfid_t xid)
{
	vrf->v_external_id = xid;
	vrf_find_saved_tablemap(vrf);
}

vrfid_t dp_vrf_get_external_id(uint32_t internal_id)
{
	struct vrf *vrf;

	if (!is_nondefault_vrf(internal_id))
		return internal_id;

	vrf = vrf_get_rcu(internal_id);
	return vrf ? vrf->v_external_id : VRF_INVALID_ID;
}

vrfid_t vrfmaster_get_tableid(struct ifnet *ifp)
{
	struct vrf_softc *vrsc = ifp->if_softc;

	assert(ifp->if_type == IFT_VRFMASTER);

	return vrsc->vrfsc_tableid;
}

vrfid_t dp_vrf_get_vid(struct vrf *vrf)
{
	return vrf->v_id;
}

struct vrfmaster_lookup_by_tableid_ctx {
	uint32_t kernel_tableid;
	struct ifnet *ifp;
	uint32_t user_tableid;
};

static void vrfmaster_lookup_by_tableid_worker(struct ifnet *ifp, void *arg)
{
	struct vrfmaster_lookup_by_tableid_ctx *ctx = arg;
	struct vrf *vrf;
	unsigned int i;

	if (ctx->ifp || ifp->if_type != IFT_VRFMASTER)
		return;

	if (vrfmaster_get_tableid(ifp) == ctx->kernel_tableid) {
		ctx->ifp = ifp;
		ctx->user_tableid = RT_TABLE_MAIN;
	} else {
		vrf = vrf_get_rcu(vrfmaster_get_vrfid(ifp));
		for (i = 0; i <= PBR_TABLEID_MAX; i++) {
			if (vrf->v_pbrtablemap[i] == ctx->kernel_tableid) {
				ctx->ifp = ifp;
				ctx->user_tableid = i;
			}
		}
	}
}

int vrf_lookup_by_tableid(uint32_t kernel_tableid, vrfid_t *vrfid,
			  uint32_t *user_tableid)
{
	struct vrfmaster_lookup_by_tableid_ctx ctx = {
		.kernel_tableid = kernel_tableid,
		.ifp = NULL,
	};
	dp_ifnet_walk(vrfmaster_lookup_by_tableid_worker, &ctx);
	if (!ctx.ifp)
		return -ENOENT;

	*vrfid = vrfmaster_get_vrfid(ctx.ifp);
	*user_tableid = ctx.user_tableid;

	return 0;
}

struct vrf *dp_vrf_get_rcu_from_external(vrfid_t external_id)
{
	struct ifnet *master_ifp;

	if (!is_nondefault_vrf(external_id))
		return vrf_get_rcu(external_id);

	master_ifp = dp_ifnet_byifindex(external_id);
	if (!master_ifp || master_ifp->if_type != IFT_VRFMASTER)
		return VRF_INVALID_ID;

	return vrf_get_rcu(vrfmaster_get_vrfid(master_ifp));
}

static void vrf_save_tablemap_for_replay(vrfid_t vrf_id, uint8_t pbr_tblid,
					 uint32_t kernel_tblid)
{
	if (tablemap_list == NULL) {
		tablemap_list = tablemap_list_create();
		if (tablemap_list == NULL)
			return;
	}

	tablemap_list_add(tablemap_list, vrf_id, pbr_tblid, kernel_tblid);
}

int cmd_tablemap_cfg(FILE *f, int argc, char **argv)
{
	struct vrf *vrf;
	vrfid_t vrf_id;
	uint8_t pbr_tblid;
	uint32_t kernel_tblid;

	if (argc != 5) {
		fprintf(f, "tablemap: require vrfname pbrtid kerneltid vrfid");
		return -1;
	}

	pbr_tblid = atoi(argv[2]);
	kernel_tblid = atoi(argv[3]);
	vrf_id = atoi(argv[4]);

	RTE_LOG(INFO, DATAPLANE, "tablemap: %s vrf %s/%d table(s) %d %s\n",
			kernel_tblid ? "Map" : "Unmap",
			argv[1], vrf_id, pbr_tblid,
			kernel_tblid ? argv[3] : "");

	if (!tableid_in_pbr_range(pbr_tblid))
		return 0;

	vrf = dp_vrf_get_rcu_from_external(vrf_id);
	if (vrf && vrf->v_id == VRF_DEFAULT_ID)
		return 0;

	if (vrf == NULL)
		vrf_save_tablemap_for_replay(vrf_id, pbr_tblid, kernel_tblid);
	else {
		vrf->v_pbrtablemap[pbr_tblid] = kernel_tblid;

		/*
		 * Routes may have been incomplete pending the
		 * appearance of this tablemap, so try to complete
		 * them now.
		 */
		incomplete_routes_make_complete();
	}

	return 0;
}

static int
vrfmaster_dump(struct ifnet *ifp, json_writer_t *wr,
	       enum if_dump_state_type type)
{
	switch (type) {
	case IF_DS_STATE:
		vrfmaster_show_info(wr, ifp);
		break;
	default:
		break;
	}

	return 0;
}

static enum dp_ifnet_iana_type
vrfmaster_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_OTHER;
}

static const struct ift_ops vrfmaster_if_ops = {
	.ifop_uninit = vrfmaster_delete,
	.ifop_dump = vrfmaster_dump,
	.ifop_iana_type = vrfmaster_iana_type,
};

void vrf_init(void)
{
	int ret = if_register_type(IFT_VRFMASTER, &vrfmaster_if_ops);

	if (ret < 0)
		rte_panic("Failed to register VRF Master type: %s",
			  strerror(-ret));

	/*
	 * Take an extra refcount on the default and invalid vrf as
	 * they should never be destroyed. The invalid VRF
	 * is a special VRF structure that we will keep
	 * 'empty'; interfaces set into this VRF will
	 * drop all received traffic.
	 *
	 * We also ensure we send a create notification event for
	 * these two vrs which are not associated with a vrfmaster
	 * interface.
	 */
	struct vrf *vrf;

	vrf = vrf_find_or_create(VRF_DEFAULT_ID);
	if (!vrf)
		rte_panic("Can't init the default vrf\n");
	dp_event(DP_EVT_VRF_CREATE, 0, vrf, 0, 0, NULL);

	vrf = vrf_find_or_create(VRF_INVALID_ID);
	if (!vrf)
		rte_panic("Can't init the invalid vrf\n");
	dp_event(DP_EVT_VRF_CREATE, 0, vrf, 0, 0, NULL);
}

void vrf_cleanup(void)
{
	vrf_delete(VRF_DEFAULT_ID);
	vrf_delete(VRF_INVALID_ID);
}
