/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */
/*-
 * Copyright (c) 1989 Stephen Deering
 * Copyright (c) 1992, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ip_mroute.c 8.2 (Berkeley) 11/15/93
 */

/*
 * IP multicast forwarding procedures
 *
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 * Modified by Mark J. Steiglitz, Stanford, May, 1991
 * Modified by Van Jacobson, LBL, January 1993
 * Modified by Ajit Thyagarajan, PARC, August 1993
 * Modified by Bill Fenner, PARC, April 1995
 * Modified by Ahmed Helmy, SGI, June 1996
 * Modified by George Edmond Eddy (Rusty), ISI, February 1998
 * Modified by Pavlin Radoslavov, USC/ISI, May 1998, August 1999, October 2000
 * Modified by Hitoshi Asaeda, WIDE, August 2000
 * Modified by Pavlin Radoslavov, ICSI, October 2002
 *
 * MROUTING Revision: 3.5
 * and PIM-SMv2 and PIM-DM support, advanced API support,
 * bandwidth metering and signaling
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/snmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/mroute.h>
#include <linux/icmp.h>


#include <netinet/in.h>
#include <netinet/ip.h>
/* rte_meter_srtcm_config does not work without experimental API */
#define ALLOW_EXPERIMENTAL_API 1
#include <rte_meter.h>
#undef ALLOW_EXPERIMENTAL_API
#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_timer.h>

#include "crypto/vti.h"
#include "if/gre.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "ip_mcast.h"
#include "ipmc_pd_show.h"
#include "ip_mroute.h"
#include "ip_ttl.h"
#include "json_writer.h"
#include "netinet/ip_mroute.h"
#include "pd_show.h"
#include "pktmbuf_internal.h"
#include "route_flags.h"
#include "snmp_mib.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "fal.h"
#include "ip_mcast_fal_interface.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "npf.h"

/*
 * Multicast packets are punted to the slow path when they cannot be
 * immedately forwarded by the fast path. They are punted at 1 PPS and
 * the excess dropped. This allows the linux kernel and pimd in the
 * slow path to correctly manage the mfc, but does not overwhelm it.
 */
#define PUNT_1PKT		(10000)
#define PUNT_FUZZ		(100)

static struct rte_meter_srtcm_params mfc_meter_params = {
	.cir = PUNT_1PKT + PUNT_FUZZ,	        /* 1 PPS */
	.cbs = PUNT_1PKT + PUNT_FUZZ,	        /* 1 PPS */
	.ebs = PUNT_FUZZ	                /* effectively zero */
};

static struct rte_meter_srtcm_profile mfc_meter_profile;

static struct rte_timer mrt_stats_timer;
static void mrt_stats(struct rte_timer *, void *arg);

#define UPCALL_TIMER 1
#ifdef UPCALL_TIMER
static struct rte_timer expire_upcalls_ch;
static void	expire_upcalls(struct rte_timer *, void *arg);
#endif

static void	expire_mfc(struct vrf *, struct mfc *);
static int	ip_mdq(struct mcast_vrf *, struct rte_mbuf *, struct ip *ip,
		 struct ifnet *, struct mfc *);
static void sg_cnt_update(struct vrf *vrf, struct mfc *rt,
			  bool last_mfc_deletion);

/* track the state of fal objects for the platform dependent show commands */
static uint32_t mroute_hw_stats[PD_OBJ_STATE_LAST];

uint32_t *mroute_hw_stats_get(void)
{
	return mroute_hw_stats;
}

struct rt_show_subset {
	json_writer_t *json;
	enum pd_obj_state subset;
	vrfid_t vrf;
};

static void rt_display(json_writer_t *json, struct in_addr *src,
		       struct in_addr *dst, int ifindex)
{
	char source[INET_ADDRSTRLEN];
	char group[INET_ADDRSTRLEN];
	const char *ifname = ifnet_indextoname(ifindex);

	if (!ifname)
		ifname = "<null>";

	jsonw_start_object(json);

	inet_ntop(AF_INET, src, source, sizeof(source));
	inet_ntop(AF_INET, dst, group, sizeof(group));
	jsonw_string_field(json, "source", source);
	jsonw_string_field(json, "group", group);
	jsonw_int_field(json, "ifindex", ifindex);
	jsonw_string_field(json, "ifname", ifname);

	jsonw_end_object(json);
}

static void rt_show_subset(struct vrf *vrf, struct mfc *rt, void *arg)
{
	struct rt_show_subset *subset = arg;

	if (subset->vrf != vrf->v_id) {
		subset->vrf = vrf->v_id;
		jsonw_start_object(subset->json);
		jsonw_uint_field(subset->json, "vrf_id",
				 dp_vrf_get_external_id(vrf->v_id));
		jsonw_end_object(subset->json);
	}

	if (subset->subset == rt->mfc_pd_state)
		rt_display(subset->json, &rt->mfc_origin, &rt->mfc_mcastgrp,
			   rt->mfc_parent);
}

/*
 * Return the json for the given subset of stats.
 */
int mroute_get_pd_subset_data(json_writer_t *json, enum pd_obj_state subset)
{
	struct cds_lfht_iter iter;
	struct mfc *rt;
	vrfid_t vrf_id;
	struct vrf *vrf;
	struct rt_show_subset arg = {
		.json = json,
		.subset = subset,
		.vrf = VRF_INVALID_ID,
	};

	VRF_FOREACH(vrf, vrf_id) {
		struct mcast_vrf mvrf = vrf->v_mvrf4;

		cds_lfht_for_each_entry(mvrf.mfchashtbl, &iter, rt, node) {
			rt_show_subset(vrf, rt, &arg);
		}
	}

	return 0;
}

__attribute__((format(printf, 4, 5)))
static void mfc_debug(vrfid_t vrf_id,
		      struct in_addr *mfc_source,
		      struct in_addr *mfc_group,
		      const char *format, ...)
{
	char source[INET_ADDRSTRLEN];
	char group[INET_ADDRSTRLEN];
	char debug_string[1024];
	va_list ap;

	if (unlikely(dp_debug & DP_DBG_MULTICAST)) {
		va_start(ap, format);
		vsnprintf(debug_string, sizeof(debug_string), format, ap);
		va_end(ap);

		inet_ntop(AF_INET, mfc_source, source, sizeof(source));
		inet_ntop(AF_INET, mfc_group, group, sizeof(group));

		DP_LOG_W_VRF(INFO, MCAST, vrf_id,
			     "(%s, %s): %s\n",
			     source, group, debug_string);
	}
}

static int mfc_match(struct cds_lfht_node *node, const void *_key)
{
	struct mfc *rt = caa_container_of(node, struct mfc, node);
	const struct mfc_key *key = (const struct mfc_key *) _key;
	return ((key->mfc_origin.s_addr == rt->mfc_origin.s_addr) &&
	       (key->mfc_mcastgrp.s_addr == rt->mfc_mcastgrp.s_addr));
}

static void mfc_free(struct rcu_head *head)
{
	struct mfc *rt = caa_container_of(head, struct mfc, rcu_head);
	free(rt);
}

static int vif_match(struct cds_lfht_node *node, const void *_key)
{
	struct vif *vifp = caa_container_of(node, struct vif, node);
	const unsigned int *key = _key;
	return *key == vifp->v_if_index;
}

static void vif_free(struct rcu_head *head)
{
	struct vif *vifp = caa_container_of(head, struct vif, rcu_head);
	free(vifp);
}

/*
 * Find a route for a given origin IP address and multicast group address.
 * Statistics must be updated by the caller.
 */
static inline struct mfc *mfc_find(struct mcast_vrf *mvrf,
				     struct in_addr *o,
				     struct in_addr *g)
{
	struct mfc *rt = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *retnode;
	struct mfc_key key;
	unsigned long hash;

	key.mfc_origin = *o;
	key.mfc_mcastgrp = *g;

	hash = rte_jhash_32b((uint32_t *)&key, MFCKEYLEN, 0);
	cds_lfht_lookup(mvrf->mfchashtbl, hash, mfc_match, &key, &iter);
	retnode = cds_lfht_iter_get_node(&iter);
	if (retnode)
		rt = caa_container_of(retnode, struct mfc, node);
	return rt;
}

/*
 * This MUST be called with a rcu_read_lock and only unlocked after vif is
 * no longer used.
 */
struct vif *get_vif_by_ifindex(unsigned int ifindex)
{
	struct vif *vifp = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *retnode;
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);
	struct vrf *vrf;

	if (!ifp)
		return NULL;

	vrf = vrf_get_rcu(if_vrfid(ifp));
	if (!vrf)
		return NULL;

	cds_lfht_lookup(vrf->v_mvrf4.viftable, ifindex, vif_match, &ifindex,
			&iter);
	retnode = cds_lfht_iter_get_node(&iter);
	if (retnode) {
		vifp = caa_container_of(retnode, struct vif, node);
	}
	return vifp;
}


void mrt4_purge(struct ifnet *ifp)
{
	struct vif *vifp;
	unsigned int v_if_index;
	struct mfc *rt;
	struct cds_lfht_iter iter;
	struct vrf *vrf = vrf_get_rcu(if_vrfid(ifp));

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Purging IPv4 MFCs for %s.\n", ifp->if_name);

	if (!vrf) {
		DP_DEBUG_W_VRF(MULTICAST, INFO, MCAST, ifp->if_vrfid,
			       "Nothing to purge for %s (going down).\n",
			       ifp->if_name);
		return;
	}

	/*
	 * Tear down multicast forwarder state associated with this ifnet.
	 * 1. Match the vif against this ifnet.
	 * 2. Walk the multicast forwarding cache (mfc) looking for
	 *    inner matches with this vif's index.
	 * 3. Expire any matching multicast forwarding cache entries.
	 * 4. Free vif state. This should disable ALLMULTI on the interface.
	*/
	vifp = get_vif_by_ifindex(ifp->if_index);
	if (!vifp) {
		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "No IPv4 VIF for %s (which is going down).\n",
			 ifp->if_name);
		return;
	}
	v_if_index = vifp->v_if_index;
	cds_lfht_for_each_entry(vrf->v_mvrf4.mfchashtbl, &iter, rt, node) {
		if (rt->mfc_parent == v_if_index) {
			mfc_debug(vrf->v_id, &rt->mfc_origin,
				  &rt->mfc_mcastgrp,
				  "%s is input interface so delete MFC.",
				  ifp->if_name);
			expire_mfc(vrf, rt);
		} else if (IF_ISSET(vifp->v_vif_index, &rt->mfc_ifset)) {
			mfc_debug(vrf->v_id, &rt->mfc_origin,
				  &rt->mfc_mcastgrp,
				  "Removing %s from olist.",
				  ifp->if_name);
			IF_CLR(vifp->v_vif_index, &rt->mfc_ifset);
		}
	}
	del_vif(v_if_index);
}

/*
 * Add a vif to the vif table
 */
int add_vif(int ifindex)
{
	struct vif *vifp;
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);
	struct cds_lfht_node *retnode;
	struct cds_lfht *viftable;
	unsigned char vif_index;
	struct vrf *vrf;

	if (!ifp) {
		DP_DEBUG(MULTICAST, ERR, MCAST,
			 "Failure adding IPv4 VIF index %d.\n", ifindex);
		return -EINVAL;
	}

	vrf =  vrf_get_rcu(if_vrfid(ifp));

	if (!vrf)
		return -EINVAL;

	if (ifindex <= 0)
		return -EINVAL;

	if (get_vif_by_ifindex(ifindex))
		return -EEXIST;

	viftable = vrf->v_mvrf4.viftable;

	if (!viftable)
		return -EINVAL;

	if (mcast_iftable_get_free_slot(&vrf->v_mvrf4.mfc_ifset, ifindex,
					&vif_index) != 0)
		return -EDQUOT;

	DP_DEBUG(MULTICAST, INFO, MCAST, "Adding IPv4 VIF to slot %d (%d).\n",
		 vif_index, ifindex);

	vifp = calloc(1, sizeof(struct vif));
	if (!vifp) {
		IF_CLR(vif_index, &vrf->v_mvrf4.mfc_ifset);
		return -ENOMEM;
	}

	vifp->v_if_index  = ifindex;
	vifp->v_vif_index = vif_index;
	vifp->v_ifp       = ifp;
	vifp->v_threshold = 1;

	vifp->v_flags = VIFF_USE_IFINDEX;
	vifp->v_flags |= (is_tunnel_pimreg(ifp)) ? VIFF_REGISTER:0;
	vifp->v_flags |= (is_tunnel(ifp)) ? VIFF_TUNNEL:0;

	cds_lfht_node_init(&vifp->node);
	retnode = cds_lfht_add_replace(viftable, vifp->v_if_index,
			vif_match, &vifp->v_if_index, &vifp->node);
	if (retnode) {
		vifp = caa_container_of(retnode, struct vif, node);
		IF_CLR(vifp->v_vif_index, &vrf->v_mvrf4.mfc_ifset);
		call_rcu(&vifp->rcu_head, vif_free);
	}

	ip_mcast_fal_int_enable(vifp, viftable);
	if (!(ifp->if_flags & IFF_MULTICAST))
		return -EOPNOTSUPP;
	if_allmulti(ifp, 1);

	return 0;
}


/*
 * Delete a vif from the vif table
 */
int del_vif(vifi_t vifi)
{
	struct vif *vifp;
	struct ifnet *ifp = dp_ifnet_byifindex(vifi);
	struct vrf *vrf;

	if (!ifp)
		return -EINVAL;

	vrf =  vrf_get_rcu(if_vrfid(ifp));

	if (!vrf)
		return -EINVAL;

	vifp = get_vif_by_ifindex(vifi);
	if (!vifp)
		return -EINVAL;

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Deleting IPv4 VIF %s.\n",
		 ifnet_indextoname(vifi));

	if (vifp->v_ifp)
		if_allmulti(vifp->v_ifp, 0);

	IF_CLR(vifp->v_vif_index, &vrf->v_mvrf4.mfc_ifset);
	if (!cds_lfht_del(vrf->v_mvrf4.viftable, &vifp->node)) {
		ip_mcast_fal_int_disable(vifp, vrf->v_mvrf4.viftable);
		call_rcu(&vifp->rcu_head, vif_free);
	}
	return 0;
}

static void debug_update_mfc_count(vrfid_t vrf_id, struct mfc *rt,
				    struct vmfcctl *mfccp)
{
	struct vif *vifp;
	struct cds_lfht_iter iter;
	int i;
	struct vrf *vrf = vrf_get_rcu(vrf_id);
	struct cds_lfht *viftable;

	if (vrf == NULL) {
		mfc_debug(vrf_id, &rt->mfc_origin, &rt->mfc_mcastgrp,
			  "MFC invalid vrf ID");
		return;
	}

	viftable = vrf->v_mvrf4.viftable;

	mfc_debug(vrf_id, &rt->mfc_origin, &rt->mfc_mcastgrp,
		  "MFC count parameters being updated/initialised.");

	cds_lfht_for_each_entry(viftable, &iter, vifp, node) {
		i = vifp->v_vif_index;

		if (IF_ISSET(i, &rt->mfc_ifset) !=
		    IF_ISSET(i, &mfccp->mfcc_ifset)) {
			if (IF_ISSET(i, &mfccp->mfcc_ifset)) {
				rt->mfc_olist_size++;
				mfc_debug(vrf_id, &rt->mfc_origin,
					  &rt->mfc_mcastgrp,
					  "%s added to olist (new olist size is %u).",
					  ifnet_indextoname(vifp->v_if_index),
					  rt->mfc_olist_size);
			} else {
				if (rt->mfc_olist_size)
					rt->mfc_olist_size--;
				mfc_debug(vrf_id, &rt->mfc_origin,
					  &rt->mfc_mcastgrp,
					  "%s removed from olist (new olist size is %u).",
					  ifnet_indextoname(vifp->v_if_index),
					  rt->mfc_olist_size);
			}
		} else if (IF_ISSET(i, &rt->mfc_ifset)) {
			mfc_debug(vrf_id, &rt->mfc_origin,
				  &rt->mfc_mcastgrp,
				  "%s already present in olist (size is %u).",
				  ifnet_indextoname(vifp->v_if_index),
				  rt->mfc_olist_size);
		}
	}
}
/*
 * update an mfc entry without resetting counters and S,G addresses.
 */
static void update_mfc_params(vrfid_t vrf_id, struct mfc *rt,
			      struct vmfcctl *mfccp)
{
	int controller = 0;
	struct vif *vifp;
	struct vrf *vrf = vrf_get_rcu(vrf_id);
	struct cds_lfht_iter iter;
	int i;

	if (!vrf)
		return;

	if (rt->mfc_parent != mfccp->mfcc_parent) {
		mfc_debug(vrf_id, &rt->mfc_origin, &rt->mfc_mcastgrp,
			  "Input interface changed from %s (%u) to %s (%u)",
			  ifnet_indextoname(rt->mfc_parent),
			  rt->mfc_parent,
			  ifnet_indextoname(mfccp->mfcc_parent),
			  mfccp->mfcc_parent);
	}

	rt->mfc_parent = mfccp->mfcc_parent;
	rt->mfc_ifset = mfccp->mfcc_ifset;

	cds_lfht_for_each_entry(vrf->v_mvrf4.viftable, &iter, vifp, node) {
		i = vifp->v_vif_index;

		if (!IF_ISSET(i, &rt->mfc_ifset))
			continue;

		/* VIF is a register interface so no further processing */
		if ((!vifp->v_ifp) || (vifp->v_flags & VIFF_REGISTER)) {
			controller++;
			mfc_debug(vrf_id, &rt->mfc_origin,
				  &rt->mfc_mcastgrp,
				  "%s is register VIF.",
				  ifnet_indextoname(vifp->v_if_index));
			continue;
		}

		/*
		 * VIF is in oifl AND the iif, which is a problem.
		 * Punt stream to controller to let PIM do wrong-vif
		 * processing to fix this problem.
		 */
		if (vifp->v_if_index == rt->mfc_parent) {
			controller++;
			mfc_debug(vrf_id, &rt->mfc_origin,
				  &rt->mfc_mcastgrp,
				  "%s is both incoming and outgoing interface.",
				  ifnet_indextoname(vifp->v_if_index));
		}
	}

	rt->mfc_controller = controller;
	if (controller) {
		mfc_debug(vrf_id, &rt->mfc_origin,
			  &rt->mfc_mcastgrp,
			  "Cannot forward on this mroute in data plane; punting all packets.");
	}
}

static inline void init_mfc_counters(struct mfc *rt)
{
	/* initialize pkt counters per src-grp */
	rt->mfc_pkt_cnt       = 0;
	rt->mfc_byte_cnt      = 0;
	rt->mfc_wrong_if      = 0;
	rt->mfc_ctrl_pkts     = 0;
	rt->mfc_expire        = 0;
	rt->mfc_last_assert   = 0;
	rt->mfc_punted        = 0;
	rt->mfc_punts_dropped = 0;
	rt->mfc_controller    = 0;
	rt->mfc_punt          = 0;
}

/*
 * fully initialize an mfc entry from the parameter
 */
static bool init_mfc_params(vrfid_t vrf_id,
		struct mfc *rt, struct vmfcctl *mfccp)
{
	int ret;

	rt->mfc_origin = mfccp->mfcc_origin;
	rt->mfc_mcastgrp = mfccp->mfcc_mcastgrp;

	init_mfc_counters(rt);
	debug_update_mfc_count(vrf_id, rt, mfccp);
	update_mfc_params(vrf_id, rt, mfccp);

	ret = rte_meter_srtcm_profile_config(&mfc_meter_profile,
						&mfc_meter_params);
	if (ret == 0)
		ret = rte_meter_srtcm_config(&rt->meter, &mfc_meter_profile);
	if (ret != 0) {
		RTE_LOG(NOTICE, MCAST,
			"Failure configuring metering algorithm; pkts will not be punted to slow path (Err = %d)\n",
			ret);
		return false;
	}

	return true;
}

static u_int32_t mvrf_mfc_size(struct mcast_vrf *mvrf)
{
	unsigned long mrt_cnt = 0;
	long dummy;

	cds_lfht_count_nodes(mvrf->mfchashtbl, &dummy, &mrt_cnt, &dummy);
	return (u_int32_t) mrt_cnt;
}

static void expire_mfc(struct vrf *vrf, struct mfc *rt)
{
	int rc;
	fal_object_t mfc_fal_obj;
	enum pd_obj_state old_pd_state;

	mfc_debug(vrf->v_id, &rt->mfc_origin, &rt->mfc_mcastgrp,
		  "MFC being expired.");

	rt->mfc_punt = 0;

	/* Inform controller if last mroute in VRF about to be deleted */
	if (mvrf_mfc_size(&vrf->v_mvrf4) == 1)
		sg_cnt_update(vrf, rt, true);

	old_pd_state = rt->mfc_pd_state;
	mfc_fal_obj = rt->mfc_fal_obj;

	rc = fal_ip4_del_mroute(rt);
	if (rc && rc != -EOPNOTSUPP)
		mfc_debug(vrf->v_id, &rt->mfc_origin,
			  &rt->mfc_mcastgrp,
			  "FAL object delete 0x%lx failed: %s",
			  mfc_fal_obj, strerror(-rc));

	mroute_hw_stats[old_pd_state]--;

	if (!cds_lfht_del(vrf->v_mvrf4.mfchashtbl, &rt->node))
		call_rcu(&rt->rcu_head, mfc_free);
}

static void
ip_mroute_add_fal_objects(vrfid_t vrf_id, struct vmfcctl *mfccp, struct mfc *rt)
{
	enum pd_obj_state old_pd_state;
	int rc;
	struct vrf *vrf = vrf_get_rcu(vrf_id);

	if (!vrf)
		return;

	old_pd_state = rt->mfc_pd_state;
	if (rt->mfc_fal_obj) {
		mfc_debug(vrf_id, &rt->mfc_origin, &rt->mfc_mcastgrp,
			  "Updating FAL object 0x%lx for mroute",
			  rt->mfc_fal_obj);
		rc = fal_ip4_upd_mroute(rt->mfc_fal_obj, rt, mfccp,
					vrf->v_mvrf4.viftable);
		if (rc && rc != -EOPNOTSUPP)
			mfc_debug(vrf_id, &rt->mfc_origin,
				  &rt->mfc_mcastgrp,
				  "FAL object 0x%lx update failed: %s",
				  rt->mfc_fal_obj, strerror(-rc));
	} else {
		if (mfccp->mfcc_parent && mfccp->if_count)
			mfc_debug(vrf_id, &rt->mfc_origin,
				  &rt->mfc_mcastgrp,
				  "Creating FAL object for mroute");

		rc = fal_ip4_new_mroute(vrf_id, mfccp, rt,
					vrf->v_mvrf4.viftable);
		if (rc && rc != -EOPNOTSUPP)
			mfc_debug(vrf_id, &rt->mfc_origin,
				  &rt->mfc_mcastgrp,
				  "FAL entry object create failed: %s",
				  strerror(-rc));
	}

	if (rt->mfc_fal_obj || rc) {
		rt->mfc_pd_state = fal_state_to_pd_state(rc);
		mroute_hw_stats[old_pd_state]--;
		mroute_hw_stats[rt->mfc_pd_state]++;
	}
}

/*
 * Add an mfc entry
 */
int add_mfc(vrfid_t vrf_id, struct vmfcctl *mfccp)
{
	struct mfc *rt;
	unsigned long hash = 0;
	struct vrf *vrf = vrf_get_rcu(vrf_id);

	if (!vrf) {
		vrf = vrf_find_or_create(vrf_id);
		if (!vrf)
			return -ENOENT;
	} else if (!mvrf_mfc_size(&vrf->v_mvrf4)) {
		/* increment vrf ref when first mrt is added */
		vrf_find_or_create(vrf_id);
	}

	rt = mfc_find(&vrf->v_mvrf4, &mfccp->mfcc_origin,
			&mfccp->mfcc_mcastgrp);

	if (rt && (rt->mfc_punt == 0)) {
		/* If an entry already exists, just update the changed fields */
		ip_mroute_add_fal_objects(vrf_id, mfccp, rt);
		debug_update_mfc_count(vrf_id, rt, mfccp);
		update_mfc_params(vrf_id, rt, mfccp);
		return 0;
	}

	/* Find the entry for which the upcall was made and update */
	if (rt) {
		mfc_debug(vrf_id, &rt->mfc_origin, &rt->mfc_mcastgrp,
			  "Updating MFC for previously punted packet.");
		ip_mroute_add_fal_objects(vrf_id, mfccp, rt);
		init_mfc_params(vrf_id, rt, mfccp);
		return 0;
	}

	/* It is possible that an entry is being inserted without an upcall */
	rt = calloc(1, sizeof(*rt));
	if (!rt) {
		/* decrement ref cnt when first mfc insertion is failed */
		if (!mvrf_mfc_size(&vrf->v_mvrf4))
			vrf_delete_by_ptr(vrf);
		return -ENOMEM;
	}

	mfc_debug(vrf_id, &mfccp->mfcc_origin, &mfccp->mfcc_mcastgrp,
		  "Creating new MFC (due to Netlink message).");

	init_mfc_params(vrf_id, rt, mfccp);
	rt->mfc_pd_state = PD_OBJ_STATE_NOT_NEEDED;
	mroute_hw_stats[rt->mfc_pd_state]++;

	/* insert new entry at head of hash chain */
	hash = rte_jhash_32b((uint32_t *)mfccp, MFCKEYLEN, 0);
	cds_lfht_add(vrf->v_mvrf4.mfchashtbl, hash, &rt->node);

	return 0;
}

/*
 * Delete an mfc entry
 */
int del_mfc(vrfid_t vrf_id, struct vmfcctl *mfccp)
{
	int rc;
	struct mfc *rt;
	fal_object_t mfc_fal_obj;
	enum pd_obj_state old_pd_state;
	struct vrf *vrf = vrf_get_rcu(vrf_id);

	if (!vrf)
		return -ENOENT;

	rt = mfc_find(&vrf->v_mvrf4, &mfccp->mfcc_origin,
			&mfccp->mfcc_mcastgrp);
	if (!rt || rt->mfc_punt)
		return -EADDRNOTAVAIL;


	mfc_debug(vrf_id, &rt->mfc_origin, &rt->mfc_mcastgrp,
		  "MFC being deleted.");

	/* Inform controller if last mroute in VRF about to be deleted */
	if (mvrf_mfc_size(&vrf->v_mvrf4) == 1)
		sg_cnt_update(vrf, rt, true);

	old_pd_state = rt->mfc_pd_state;
	mfc_fal_obj = rt->mfc_fal_obj;

	rc = fal_ip4_del_mroute(rt);
	if (rc && rc != -EOPNOTSUPP)
		mfc_debug(vrf_id, &rt->mfc_origin,
			  &rt->mfc_mcastgrp,
			  "FAL object delete 0x%lx failed: %s",
			  mfc_fal_obj, strerror(-rc));

	mroute_hw_stats[old_pd_state]--;

	if (!cds_lfht_del(vrf->v_mvrf4.mfchashtbl, &rt->node))
		call_rcu(&rt->rcu_head, mfc_free);

	/* decrement vrf ref when last mrt is deleted */
	if (!mvrf_mfc_size(&vrf->v_mvrf4))
		vrf_delete_by_ptr(vrf);

	return 0;
}

/*
 * Determine if this a packet on this flow should be punted or
 * dropped due to rate limiting.
 */
static bool ip_punt_rate_limit(struct mfc *rt)
{
	enum rte_color color;

#ifdef PUNT_RATE_LIMIT_DEBUG
	char oa[INET_ADDRSTRLEN];
	char ga[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &rt->mfc_origin, oa, sizeof(oa));
	inet_ntop(AF_INET, &rt->mfc_mcastgrp, ga, sizeof(ga));
#endif
	color = rte_meter_srtcm_color_blind_check(&rt->meter,
						   &mfc_meter_profile,
						   rte_rdtsc(),
						   PUNT_1PKT);
	if (color == RTE_COLOR_GREEN) {
		rt->mfc_punted++;

#ifdef PUNT_RATE_LIMIT_DEBUG
		RTE_LOG(INFO, METER, "RTE_METER_GREEN %s %s punt %d drop %d\n",
			oa, ga, (uint)rt->mfc_punted,
			(uint)rt->mfc_punts_dropped);
#endif
		return false;
	} else if (color == RTE_COLOR_YELLOW) {
		rt->mfc_punted++;

#ifdef PUNT_RATE_LIMIT_DEBUG
		RTE_LOG(INFO, METER, "RTE_METER_YELL %s %s drop %d, punt %d\n",
			oa, ga, (uint)rt->mfc_punts_dropped,
			(uint)rt->mfc_punted);
#endif
		return false;
	} else {
		rt->mfc_punts_dropped++;

#ifdef PUNT_RATE_LIMIT_DEBUG
		RTE_LOG(INFO, METER, "RTE_METER_RED %s %s drop %d, punt %d\n",
			oa, ga, (uint)rt->mfc_punts_dropped,
			(uint)rt->mfc_punted);
#endif
		return true;
	}
}

/*
 * IP multicast forwarding function. This function assumes that the packet
 * pointed to by "ip" has arrived on (or is about to be sent to) the interface
 * pointed to by "ifp", and the packet is to be relayed to other networks
 * that have members of the packet's destination IP multicast group.
 *
 * The packet is returned unscathed to the caller.
 *
 * Return values:
 * < 0:	fatal error encountered in processing; discard and account stats
 *   0:	no error encountered in processing, packets forwarded
 *   Other, see caller. (fil this in)
 */
static int ip_mforward(vrfid_t vrf_id, struct mcast_vrf *mvrf,
		struct ip *ip, struct ifnet *ifp, struct rte_mbuf *m)
{
	struct mfc *rt;
	struct vif *vifp;
	struct vmfcctl mfcc;
	unsigned long hash;

	switch (ip->ip_p) {
	/* is this covered by IN_LOCAL_GROUP */
	case IPPROTO_IGMP:
		MRTSTAT_INC(mvrf, mrts_igmp_in);
		return RTF_SLOWPATH;
		break;

	case IPPROTO_ICMP:
		MRTSTAT_INC(mvrf, mrts_icmp_in);
		return RTF_SLOWPATH;
		break;

	case IPPROTO_PIM:
		MRTSTAT_INC(mvrf, mrts_pim_in);
		return RTF_SLOWPATH;
		break;

	default:
		break;
	}

	if (IN_LOCAL_GROUP(ntohl(ip->ip_dst.s_addr))) {
		MRTSTAT_INC(mvrf, mrts_localgrp_in);
		return RTF_SLOWPATH;
	}

	if (ifp->ip_mc_forwarding == 0)
		return RTF_SLOWPATH;

	if (ip->ip_ttl <= 1) {
		MRTSTAT_INC(mvrf, mrts_ttl);
		icmp_error(ifp, m, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
		return 0;
	}

	/* Determine forwarding vifs from the forwarding cache table */
	MRTSTAT_INC(mvrf, mrts_mfc_lookups);
	rt = mfc_find(mvrf, &ip->ip_src, &ip->ip_dst);

	/* Entry exists, so forward if necessary */
	if (rt && (rt->mfc_punt == 0))
		return ip_mdq(mvrf, m, ip, ifp, rt);

	/* If we don't have a route for this origin, send to routing daemon */
	MRTSTAT_INC(mvrf, mrts_mfc_misses);

	/* is there an upcall waiting for this flow ? */
	if (!rt) {
		/* Locate the vifi for the incoming interface for this packet.
		 * If none found, drop packet.  */
		vifp = get_vif_by_ifindex(ifp->if_index);
		if (!vifp)
			return -EINVAL;

		/* no upcall, so make a new entry */
		rt = calloc(1, sizeof(*rt));
		if (!rt)
			return -ENOMEM;

		MRTSTAT_INC(mvrf, mrts_upcalls);

		/* insert new entry at head of hash chain */
		memset(&mfcc, 0, sizeof(mfcc));
		mfcc.mfcc_origin.s_addr = ip->ip_src.s_addr;
		mfcc.mfcc_mcastgrp.s_addr = ip->ip_dst.s_addr;
		mfc_debug(vrf_id, &mfcc.mfcc_origin, &mfcc.mfcc_mcastgrp,
			  "Creating new MFC (due to traffic).");
		init_mfc_params(vrf_id, rt, &mfcc);
		rt->mfc_expire = UPCALL_EXPIRE;

		/* increment vrf ref when first mrt is added */
		if (!mvrf_mfc_size(mvrf))
			vrf_find_or_create(vrf_id);

		/* link into table */
		hash = rte_jhash_2words(ip->ip_src.s_addr, ip->ip_dst.s_addr,
					0);
		cds_lfht_add(mvrf->mfchashtbl, hash, &rt->node);
		rt->mfc_punt++;
		rt->mfc_ctrl_pkts++;
		rt->mfc_punted++;
		rt->mfc_pd_state = PD_OBJ_STATE_NOT_NEEDED;
		mroute_hw_stats[rt->mfc_pd_state]++;
	} else {
		/* determine if queue has overflowed */
		if (ip_punt_rate_limit(rt)) {
			MRTSTAT_INC(mvrf, mrts_upq_ovflw);
			return RTF_BLACKHOLE;
		}
	}

	return RTF_SLOWPATH;
}

#ifdef UPCALL_TIMER
/* Clean up the cache entry if upcall is not serviced */
static void expire_upcalls(__attribute__((unused)) struct rte_timer *rtetm,
			   __attribute__((unused)) void *arg)
{
	struct mfc *rt;
	struct cds_lfht_iter iter;
	vrfid_t vrf_id;
	struct vrf *vrf;

	VRF_FOREACH(vrf, vrf_id) {
		struct mcast_vrf *mvrf = &vrf->v_mvrf4;
		cds_lfht_for_each_entry(mvrf->mfchashtbl, &iter, rt, node) {
			if (rt->mfc_punt == 0)
				continue;
			if ((rt->mfc_expire == 0) || (--rt->mfc_expire > 0))
				continue;

			mfc_debug(vrf->v_id, &rt->mfc_origin, &rt->mfc_mcastgrp,
				"Upcall not serviced so delete MFC.");
			expire_mfc(vrf, rt);
			MRTSTAT_INC(mvrf, mrts_cache_cleanups);
		}
	}
}
#endif

static int mcast_ethernet_send(struct ifnet *in_ifp,
			       struct vif *out_vifp,
			       struct rte_mbuf *m, int plen)
{
	struct iphdr *ip;

	ip = iphdr(m);
	decrement_ttl(ip);

	out_vifp->v_pkt_out++;
	out_vifp->v_bytes_out += plen;

	struct ifnet *out_ifp = out_vifp->v_ifp;

	if (unlikely(!(out_ifp->if_flags & IFF_UP)))
		return -1;

	struct next_hop nh = {
		.flags = RTF_MULTICAST,
		.u.ifp = out_ifp,
	};
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
		.l3_hdr = ip,
		.in_ifp = in_ifp,
		.out_ifp = out_ifp,
		.nxt.v4 = &nh,
		.l2_proto = ETH_P_IP,
		.npf_flags = NPF_FLAG_CACHE_EMPTY,
	};

	pipeline_fused_ipv4_out(&pl_pkt);

	return 0;
}

static void mcast_tunnel_send(struct ifnet *in_ifp,  struct vif *out_vifp,
			      struct rte_mbuf *m, int plen)
{
	struct ifnet *out_ifp;
	struct vrf *vrf;
	struct iphdr *ip;
	struct mcast_mgre_tun_walk_ctx mgre_tun_walk_ctx;

	out_ifp = out_vifp->v_ifp;
	ip = iphdr(m);

	switch (out_ifp->if_type) {
	case IFT_TUNNEL_GRE:
		decrement_ttl(ip);

		/* Call GRE API which will invoke specified callback
		 * for each end point in P2P or P2MP tunnel
		 */
		mgre_tun_walk_ctx.proto = ETH_P_IP;
		mgre_tun_walk_ctx.mbuf = m;
		mgre_tun_walk_ctx.in_ifp = in_ifp;
		mgre_tun_walk_ctx.pkt_len = plen;
		mgre_tun_walk_ctx.out_vif = out_vifp;
		mgre_tun_walk_ctx.hdr_len = sizeof(struct iphdr);
		gre_tunnel_peer_walk(out_ifp,
				     mcast_mgre_tunnel_endpoint_send,
				     &mgre_tun_walk_ctx);
		/*
		 * Decrement ref count on original mbuf as new mbuf
		 * was transmitted in replication loop.
		 */
		rte_pktmbuf_free(m);
		return;
	case IFT_TUNNEL_VTI:
		decrement_ttl(ip);
		out_vifp->v_pkt_out++;
		out_vifp->v_bytes_out += plen;
		IPSTAT_INC_VRF(if_vrf(in_ifp), IPSTATS_MIB_OUTMCASTPKTS);
		vti_tunnel_out(in_ifp, out_ifp, m, ETH_P_IP);
		return;
	default:
		/*
		 * Punt for any tunnels unsupported in data plane.
		 * Note that if packet successfully switched out
		 * of some other interfaces in the olist in the
		 * data plane, a  duplicate packet may be sent out
		 * of these interfaces by the kernel. Essentially,
		 * as things stand, option is potentially duplicate
		 * packets on some interfaces or fail to transmit
		 * packets on other interfaces in the olist.
		 */
		vrf = vrf_get_rcu(if_vrfid(in_ifp));
		if (vrf) {
			struct mcast_vrf *mvrf = &vrf->v_mvrf4;
			MRTSTAT_INC(mvrf, mrts_slowpath);
		}
		out_vifp->v_pkt_out_punt++;
		out_vifp->v_bytes_out_punt += plen;
		mcast_ip_deliver(in_ifp, m);
	}
}

/*
 * Packet transmission routine for VIF in olist.  Select appropriate send
 * function based on underlying interface type.
 */
static void vif_send(struct ifnet *in_ifp, struct vif *out_vifp,
		     struct rte_mbuf *m, int plen)
{
	if (unlikely(out_vifp->v_flags & VIFF_TUNNEL)) {
		mcast_tunnel_send(in_ifp,
				  out_vifp, m, plen);
		return;
	}

	mcast_ethernet_send(in_ifp, out_vifp, m, plen);
}

/*
 * Packet forwarding routine once entry in the cache is made
 */
static int ip_mdq(struct mcast_vrf *mvrf, struct rte_mbuf *m, struct ip *ip,
		  struct ifnet *ifp, struct mfc *rt)
{
	struct vif *vifp;
	int plen = ntohs(ip->ip_len);
	struct cds_lfht_iter iter;
	struct rte_mbuf *md, *mh;

	/* Don't forward if it didn't arrive on parent vif for its origin. */
	vifp = get_vif_by_ifindex(rt->mfc_parent);
	if (!vifp || (vifp->v_if_index != ifp->if_index)) {
		MRTSTAT_INC(mvrf, mrts_wrong_if);
		++rt->mfc_wrong_if;

		/* Rate limit this punted packet */
		if (ip_punt_rate_limit(rt)) {
			MRTSTAT_INC(mvrf, mrts_upq_ovflw);
			return RTF_BLACKHOLE;
		} else {
			rt->mfc_ctrl_pkts++;
			return RTF_SLOWPATH;
		}
	}

	/* Rate limit this punted packet */
	if (rt->mfc_controller) {
		rt->mfc_ctrl_pkts++;
		if (ip_punt_rate_limit(rt)) {
			MRTSTAT_INC(mvrf, mrts_upq_ovflw);
			return RTF_BLACKHOLE;
		} else {
			return RTF_SLOWPATH;
		}
	}

	vifp->v_pkt_in++;
	vifp->v_bytes_in += plen;
	rt->mfc_pkt_cnt++;
	rt->mfc_byte_cnt += plen;

	/* Take a reference to the data portion of the packet (beyond the
	 * IP header). This allows this to be shared over all replications
	 * avoiding an expensive copy */
	md = pktmbuf_clone(m, m->pool);
	if (!md)
		return -ENOBUFS;

	rte_pktmbuf_adj(md, dp_pktmbuf_l2_len(md) + sizeof(struct iphdr));

	/* For each dataplane vif, forward if:
	 *	- the ifset bit is set for this interface.
	 *	- there are group members downstream on interface */
	cds_lfht_for_each_entry(mvrf->viftable, &iter, vifp, node) {
		if (IF_ISSET(vifp->v_vif_index, &rt->mfc_ifset) &&
		    ip->ip_ttl > vifp->v_threshold) {
			if (!vifp->v_ifp)
				continue;

			mh = mcast_create_l2l3_header(m, md,
						      sizeof(struct iphdr));
			if (mh) {
				/* send the newly created packet chain */
				vif_send(ifp, vifp, mh, plen);
			} else {
				rte_pktmbuf_free(md);
				return -ENOBUFS;
			}
		}
	}
	/* We still hold a lock on the newly created initial data segment and
	 *  its children, so release that now */
	rte_pktmbuf_free(md);
	return 0;
}

/*
 * Send per-mroute stats block to controller.  Called when last mroute in
 * VRF being deleted or during periodic iteration over all VRFs & mroutes.
 */
static void sg_cnt_update(struct vrf *vrf, struct mfc *rt,
			  bool last_mfc_deletion)
{
	struct sioc_sg_req req;
	uint32_t flags = 0;

	enum fal_ip_mcast_entry_stat_type cntr_ids[] = {
		FAL_IP_MCAST_GROUP_STAT_IN_PACKETS,
		FAL_IP_MCAST_GROUP_STAT_IN_OCTETS
	};
	uint64_t cntrs[ARRAY_SIZE(cntr_ids)];
	int ret;

	ret = fal_ip_mcast_get_stats(rt->mfc_fal_obj, ARRAY_SIZE(cntr_ids),
				     &cntr_ids[0], &cntrs[0]);
	if (ret < 0) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "failed to collect v4 hardware counters: %s\n",
				 strerror(-ret));
	} else {
		rt->mfc_hw_pkt_cnt +=
			cntrs[FAL_IP_MCAST_GROUP_STAT_IN_PACKETS];
		rt->mfc_hw_byte_cnt +=
			cntrs[FAL_IP_MCAST_GROUP_STAT_IN_OCTETS];
	}

	req.src = rt->mfc_origin;
	req.grp = rt->mfc_mcastgrp;
	req.pktcnt = rt->mfc_pkt_cnt + rt->mfc_hw_pkt_cnt;
	req.bytecnt = rt->mfc_byte_cnt + rt->mfc_hw_byte_cnt;
	req.wrong_if = rt->mfc_wrong_if;

	/*
	 * Indicate if the last mroute in the VRF is about to be deleted
	 * so controller can tidy up appropriately.
	 */
	if (last_mfc_deletion) {
		mfc_debug(vrf->v_id, &rt->mfc_origin,
			  &rt->mfc_mcastgrp,
			  "Last mroute in VRF about to be deleted.");
		flags = 1;
	}

	send_sg_cnt(&req, dp_vrf_get_external_id(vrf->v_id), flags);
}

/*
 * Called by handler for periodic stats timer; iterate over all VRFs and,
 * for each mroute in the VRF, send stats block to controller.
 */
static void sg_cnt_dump(void)
{
	struct cds_lfht_iter iter;
	struct mfc *rt;
	vrfid_t vrf_id;
	struct vrf *vrf;

	VRF_FOREACH(vrf, vrf_id) {
		struct mcast_vrf mvrf = vrf->v_mvrf4;
		cds_lfht_for_each_entry(mvrf.mfchashtbl, &iter, rt, node) {
			sg_cnt_update(vrf, rt, false);
		}
	}
}

static void mrt_stats(__attribute__((unused)) struct rte_timer *rtetm,
		      __attribute__((unused)) void *arg)
{
	sg_cnt_dump();
}


void mrt_dump(FILE *f, struct vrf *vrf)
{
	struct mfc *rt;
	char oa[INET_ADDRSTRLEN];
	char ga[INET_ADDRSTRLEN];
	struct cds_lfht_iter iter;
	struct cds_lfht_iter iter_vif;
	struct vif *vifp;
	char olist_buf[(IFNAMSIZ+1) * MFC_MAX_MVIFS];
	int olist_index;

	json_writer_t *wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "route");
	jsonw_start_array(wr);

	memset(olist_buf, 0, (IFNAMSIZ+1) * MFC_MAX_MVIFS);
	
	cds_lfht_for_each_entry(vrf->v_mvrf4.mfchashtbl, &iter, rt, node) {
		olist_index = 0;

		cds_lfht_for_each_entry(vrf->v_mvrf4.viftable, &iter_vif,
					vifp, node) {
			if (IF_ISSET(vifp->v_vif_index, &rt->mfc_ifset)) {
				olist_index += snprintf(olist_buf + olist_index,
							sizeof(olist_buf) -
							olist_index,
							"%s",
							ifnet_indextoname_safe(
							  vifp->v_if_index));
				olist_index += snprintf(olist_buf + olist_index,
							sizeof(olist_buf) -
							olist_index,
							" ");
			}
		}

		if (olist_index)
			olist_buf[olist_index-1] = '\0';

		jsonw_start_object(wr);
		jsonw_string_field(wr, "source",
			inet_ntop(AF_INET, &rt->mfc_origin, oa, sizeof(oa)));
		jsonw_string_field(wr, "group",
			inet_ntop(AF_INET, &rt->mfc_mcastgrp, ga, sizeof(ga)));
		jsonw_string_field(wr, "input",
			ifnet_indextoname_safe(rt->mfc_parent));
		jsonw_string_field(wr, "output(s)", olist_buf);
		if (rt->mfc_fal_obj)
			jsonw_string_field(wr, "forwarding",
					   "hardware");
		else
			jsonw_string_field(wr, "forwarding",
					   rt->mfc_controller ?
					   "slow/controller" :
					   "fast/dataplane");

		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

void mfc_stat(FILE *f, struct vrf *vrf)
{
	struct mfc *rt;
	struct cds_lfht_iter iter;
	char oa[INET_ADDRSTRLEN];
	char ga[INET_ADDRSTRLEN];

	json_writer_t *wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "fcstat");
	jsonw_start_array(wr);

	cds_lfht_for_each_entry(vrf->v_mvrf4.mfchashtbl, &iter, rt, node) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "origin",
			inet_ntop(AF_INET, &rt->mfc_origin, oa, sizeof(oa)));
		jsonw_string_field(wr, "group",
			inet_ntop(AF_INET, &rt->mfc_mcastgrp, ga, sizeof(ga)));
		jsonw_uint_field(wr, "packets", rt->mfc_pkt_cnt);
		jsonw_uint_field(wr, "bytes", rt->mfc_byte_cnt);
		jsonw_uint_field(wr, "hw_packets", rt->mfc_hw_pkt_cnt);
		jsonw_uint_field(wr, "hw_bytes", rt->mfc_hw_byte_cnt);
		jsonw_uint_field(wr, "wrong_if", rt->mfc_wrong_if);
		jsonw_uint_field(wr, "controller", rt->mfc_controller);
		jsonw_uint_field(wr, "ctrl_pkts", rt->mfc_ctrl_pkts);
		jsonw_int_field(wr, "expire", rt->mfc_expire);
		jsonw_uint_field(wr, "punted", rt->mfc_punted);
		jsonw_uint_field(wr, "punts_dropped",
			rt->mfc_punts_dropped);
		jsonw_uint_field(wr, "punt", rt->mfc_punt);
		jsonw_uint_field(wr, "olist_size", rt->mfc_olist_size);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

void mrt_stat(FILE *f, struct vrf *vrf)
{
	struct mcast_vrf *mvrf = &vrf->v_mvrf4;
	json_writer_t *wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "rtstat");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "mfc_lookups", mvrf->stat.mrts_mfc_lookups);
	jsonw_uint_field(wr, "mfc_misses", mvrf->stat.mrts_mfc_misses);
	jsonw_uint_field(wr, "upcalls", mvrf->stat.mrts_upcalls);
	jsonw_uint_field(wr, "wrong_if", mvrf->stat.mrts_wrong_if);
	jsonw_uint_field(wr, "upcall_ovfl", mvrf->stat.mrts_upq_ovflw);
	jsonw_uint_field(wr, "no_upcall", mvrf->stat.mrts_cache_cleanups);
	jsonw_uint_field(wr, "slowpath", mvrf->stat.mrts_slowpath);
	jsonw_uint_field(wr, "drop", mvrf->stat.mrts_drop);
	jsonw_uint_field(wr, "ttl", mvrf->stat.mrts_ttl);
	jsonw_uint_field(wr, "igmp_in", mvrf->stat.mrts_igmp_in);
	jsonw_uint_field(wr, "pim_in", mvrf->stat.mrts_pim_in);
	jsonw_uint_field(wr, "icmp_in", mvrf->stat.mrts_icmp_in);
	jsonw_uint_field(wr, "localgrp_in", mvrf->stat.mrts_localgrp_in);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

void mvif_dump(FILE *f, __attribute__((unused)) struct vrf *vrf)
{
	struct cds_lfht_iter iter;
	struct vif *vifp;

	json_writer_t *wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "mif");
	jsonw_start_array(wr);

	cds_lfht_for_each_entry(vrf->v_mvrf4.viftable, &iter, vifp, node) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "interface", vifp->v_ifp ?
				  vifp->v_ifp->if_name : "non-vplane");
		jsonw_int_field(wr, "if_index",	vifp->v_vif_index);
		jsonw_int_field(wr, "threshold", vifp->v_threshold);
		jsonw_int_field(wr, "flags", vifp->v_flags);
		jsonw_uint_field(wr, "pkt_in", vifp->v_pkt_in);
		jsonw_uint_field(wr, "pkt_out",	vifp->v_pkt_out);
		jsonw_uint_field(wr, "pkt_out_punt", vifp->v_pkt_out_punt);
		jsonw_uint_field(wr, "bytes_in", vifp->v_bytes_in);
		jsonw_uint_field(wr, "bytes_out", vifp->v_bytes_out);
		jsonw_uint_field(wr, "bytes_out_punt", vifp->v_bytes_out_punt);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

/*
 * Multicast Fastpath
 */
int mcast_ip(struct iphdr *ip, struct ifnet *ifp, struct rte_mbuf *m)
{
	int err;
	struct vrf *vrf = vrf_get_rcu(pktmbuf_get_vrf(m));

	if (unlikely(!vrf)) {
		err = -ENOENT;
		goto free;
	}

	struct mcast_vrf *mvrf = &vrf->v_mvrf4;
	err = ip_mforward(vrf->v_id, mvrf, (struct ip *) ip, ifp, m);
	switch (err) {
	case 0: /* delivered. free mbuf */
		goto free;
		break;
	case RTF_REJECT: /* not delivered. free mbuf */
		goto reject;
		break;
	case RTF_BLACKHOLE:
		goto drop;
		break;
	case RTF_SLOWPATH: /* send to controller */
		goto deliver;
		break;
	default: /* error < 0 */
		goto reject;
		break;
	}
deliver:
	MRTSTAT_INC(mvrf, mrts_slowpath);
	mcast_ip_deliver(ifp, m);
	return err;

reject:
	/* There is no output if so count against pkt's VRF */
	IPSTAT_INC_MBUF(m, IPSTATS_MIB_OUTNOROUTES);
drop:
	MRTSTAT_INC(mvrf, mrts_drop);
free:
	rte_pktmbuf_free(m);
	return err;
}

/* per vrf mcache */
int mcast_vrf_init(struct vrf *vrf)
{
	struct cds_lfht *mfctbl = cds_lfht_new(MFC_HASHSIZE,
				MFC_HASHSIZE, MFC_HASHSIZE,
				CDS_LFHT_ACCOUNTING, NULL);
	if (!mfctbl) {
		RTE_LOG(ERR, MCAST,
			"%s: cds_lfht_new mfchashtbl failed\n", __func__);
		return -1;
	}

	vrf->v_mvrf4.v_fal_obj = 0;
	vrf->v_mvrf4.v_fal_rpf = 0;
	vrf->v_mvrf4.v_fal_rpf_lst = NULL;

	vrf->v_mvrf4.mfchashtbl = mfctbl;
	vrf->v_mvrf4.viftable = cds_lfht_new(MFC_MAX_MVIFS, MFC_MAX_MVIFS,
					     MFC_MAX_MVIFS, CDS_LFHT_ACCOUNTING,
					     NULL);
	if (!vrf->v_mvrf4.viftable) {
		RTE_LOG(ERR, MCAST, "%s: cds_lfht_new viftable failed vrf %s\n",
			__func__, vrf->v_name);
		return -1;
	}
	memset(&(vrf->v_mvrf4.mfc_ifset), 0, sizeof(struct if_set));
	return 0;
}

void mcast_vrf_uninit(struct vrf *vrf)
{
	struct cds_lfht_iter iter;
	struct mfc *rt;

	if (!vrf->v_mvrf4.mfchashtbl)
		return;

	cds_lfht_for_each_entry(vrf->v_mvrf4.mfchashtbl, &iter, rt, node)
		expire_mfc(vrf, rt);

	dp_ht_destroy_deferred(vrf->v_mvrf4.mfchashtbl);
	vrf->v_mvrf4.mfchashtbl = NULL;

	dp_ht_destroy_deferred(vrf->v_mvrf4.viftable);
	vrf->v_mvrf4.viftable = NULL;

}

int mcast_stop_ipv4(void)
{
#ifdef UPCALL_TIMER
	rte_timer_stop(&expire_upcalls_ch);
#endif
	rte_timer_stop(&mrt_stats_timer);

	return 0;
}

static const struct ift_ops pimreg_if_ops = {
};

void mcast_init_ipv4(void)
{
	int ret;

	ret = if_register_type(IFT_TUNNEL_PIMREG, &pimreg_if_ops);
	if (ret < 0)
		rte_panic("Failed to register PIMREG type: %s", strerror(-ret));

#ifdef UPCALL_TIMER
	rte_timer_init(&expire_upcalls_ch);
	rte_timer_reset(&expire_upcalls_ch, EXPIRE_TIMEOUT, PERIODICAL,
			rte_get_master_lcore(), expire_upcalls, NULL);
#endif
	rte_timer_init(&mrt_stats_timer);
	rte_timer_reset(&mrt_stats_timer, SG_CNT_INTERVAL, PERIODICAL,
			rte_get_master_lcore(), mrt_stats, NULL);
}
