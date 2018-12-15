/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */
/*-
 * Copyright (C) 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$KAME: ip6_mroute.c,v 1.58 2001/12/18 02:36:31 itojun Exp $
 */

/*-
 * Copyright (c) 1989 Stephen Deering
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)ip_mroute.c	8.2 (Berkeley) 11/15/93
 *	BSDI ip_mroute.c,v 2.10 1996/11/14 00:29:52 jch Exp
 */

/*
 * IP multicast forwarding procedures
 *
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 * Modified by Mark J. Steiglitz, Stanford, May, 1991
 * Modified by Van Jacobson, LBL, January 1993
 * Modified by Ajit Thyagarajan, PARC, August 1993
 * Modified by Bill Fenner, PARC, April 1994
 *
 * MROUTING Revision: 3.5.1.2 + PIM-SMv2 (pimd) Support
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/mroute.h>
#include <linux/snmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/mroute6.h>
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
#include "in6.h"
#include "in6_var.h"
#include "ip6_funcs.h"
#include "ip6_mroute.h"
#include "ip_mcast.h"
#include "ipmc_pd_show.h"
#include "json_writer.h"
#include "main.h"
#include "netinet6/ip6_mroute.h"
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
	.cir = PUNT_1PKT + PUNT_FUZZ,	/* 1 PPS */
	.cbs = PUNT_1PKT + PUNT_FUZZ,	        /* 1 PPS */
	.ebs = PUNT_FUZZ	                /* effectively zero */
};

static struct rte_meter_srtcm_profile mfc_meter_profile;

#define UPCALL_TIMER 1
#ifdef UPCALL_TIMER
static struct rte_timer expire_upcalls_ch;
static void expire_upcalls(struct rte_timer *rtetm, void *arg);
#endif
static struct rte_timer mrt6_stats_timer;
static void mrt6_stats(struct rte_timer *, void *arg);

static int ip6_mdq(struct mcast6_vrf *, struct rte_mbuf *,
		   struct ifnet *, struct mf6c *);
static void expire_mf6c(struct vrf *vrf, struct mf6c *rt);
static void sg6_cnt_update(struct vrf *vrf, struct mf6c *rt,
			   bool last_mfc_deletion);

/* track the state of fal objects for the platform dependent show commands */
static uint32_t mroute6_hw_stats[PD_OBJ_STATE_LAST];

uint32_t *mroute6_hw_stats_get(void)
{
	return mroute6_hw_stats;
}

struct rt_show_subset {
	json_writer_t *json;
	enum pd_obj_state subset;
	vrfid_t vrf;
};

static void rt6_display(json_writer_t *json, struct in6_addr *src,
			struct in6_addr *dst, int ifindex)
{
	char source[INET6_ADDRSTRLEN];
	char group[INET6_ADDRSTRLEN];
	const char *ifname = ifnet_indextoname(ifindex);

	if (!ifname)
		ifname = "<null>";

	jsonw_start_object(json);

	inet_ntop(AF_INET6, src, source, sizeof(source));
	inet_ntop(AF_INET6, dst, group, sizeof(group));
	jsonw_string_field(json, "source", source);
	jsonw_string_field(json, "group", group);
	jsonw_int_field(json, "ifindex", ifindex);
	jsonw_string_field(json, "ifname", ifname);

	jsonw_end_object(json);
}

static void rt6_show_subset(struct vrf *vrf, struct mf6c *rt, void *arg)
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
		rt6_display(subset->json, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
			    rt->mf6c_parent);
}

/*
 * Return the json for the given subset of stats.
 */
int mroute6_get_pd_subset_data(json_writer_t *json, enum pd_obj_state subset)
{
	struct cds_lfht_iter iter;
	struct mf6c *rt;
	vrfid_t vrf_id;
	struct vrf *vrf;
	struct rt_show_subset arg = {
		.json = json,
		.subset = subset,
		.vrf = VRF_INVALID_ID,
	};

	VRF_FOREACH(vrf, vrf_id) {
		struct mcast6_vrf mvrf6 = vrf->v_mvrf6;

		cds_lfht_for_each_entry(mvrf6.mf6ctable, &iter, rt, node) {
			rt6_show_subset(vrf, rt, &arg);
		}
	}

	return 0;
}

__attribute__((format(printf, 4, 5)))
static void mfc6_debug(vrfid_t vrf_id,
		       struct in6_addr *mfc_source,
		       struct in6_addr *mfc_group,
		       const char *format, ...)
{
	char source[INET6_ADDRSTRLEN];
	char group[INET6_ADDRSTRLEN];
	char debug_string[1024];
	va_list ap;

	if (unlikely(dp_debug & DP_DBG_MULTICAST)) {
		va_start(ap, format);
		vsnprintf(debug_string, sizeof(debug_string), format, ap);
		va_end(ap);

		inet_ntop(AF_INET6, mfc_source, source, sizeof(source));
		inet_ntop(AF_INET6, mfc_group, group, sizeof(group));

		RTE_LOG(INFO, MCAST,
			"vrf %u:(%s, %s): %s\n",
			vrf_id, source, group, debug_string);
	}
}

static int mf6c_match(struct cds_lfht_node *node, const void *_key)
{
	struct mf6c *rt = caa_container_of(node, struct mf6c, node);
	const struct mf6c_key *key = _key;

	return IN6_ARE_ADDR_EQUAL(&key->mf6c_origin, &rt->mf6c_origin) &&
		IN6_ARE_ADDR_EQUAL(&key->mf6c_mcastgrp, &rt->mf6c_mcastgrp);
}

static void mf6c_free(struct rcu_head *head)
{
	struct mf6c *rt = caa_container_of(head, struct mf6c, rcu_head);
	free(rt);
}

static int mif6_match(struct cds_lfht_node *node, const void *_key)
{
	struct mif6 *mifp = caa_container_of(node, struct mif6, node);
	const unsigned int *key = _key;

	return *key == mifp->m6_if_index;
}

static void mif6_free(struct rcu_head *head)
{
	struct mif6 *mifp = caa_container_of(head, struct mif6, rcu_head);

	free(mifp);
}

/*
 * Find a route for a given origin IPv6 address and Multicast group address.
 */
static struct mf6c *mf6c_find(struct mcast6_vrf *mvrf6,
			struct in6_addr *o, struct in6_addr *g)
{
	struct mf6c *rt = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *retnode;
	struct mf6c_key key;
	unsigned long hash;

	key.mf6c_origin = *o;
	key.mf6c_mcastgrp = *g;

	hash = rte_jhash_32b((uint32_t *)&key, MF6CKEYLEN, 0);

	cds_lfht_lookup(mvrf6->mf6ctable, hash, mf6c_match, &key, &iter);
	retnode = cds_lfht_iter_get_node(&iter);
	if (retnode)
		rt = caa_container_of(retnode, struct mf6c, node);
	return rt;
}

/*
 * This MUST be called with a rcu_read_lock and only unlocked after mif6 is
 * no longer used.
 */
struct mif6* get_mif_by_ifindex(unsigned int ifindex)
{
	struct mif6 *mifp = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *retnode;
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);
	struct vrf *vrf;

	if (!ifp)
		return NULL;

	vrf = vrf_get_rcu(if_vrfid(ifp));
	if (!vrf)
		return NULL;

	cds_lfht_lookup(vrf->v_mvrf6.mif6table, ifindex, mif6_match, &ifindex,
			&iter);
	retnode = cds_lfht_iter_get_node(&iter);
	if (retnode)
		mifp = caa_container_of(retnode, struct mif6, node);

	return mifp;
}

void mrt6_purge(struct ifnet *ifp)
{
	struct mif6 *mifp;
	struct mf6c *rt;
	struct cds_lfht_iter iter;
	struct vrf *vrf = vrf_get_rcu(if_vrfid(ifp));

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Purging IPv6 MFCs for %s.\n", ifp->if_name);

	if (!vrf)
		return;

	/*
	 * Tear down multicast forwarder state associated with this ifnet.
	 * 1. Walk the vif list, matching vifs against this ifnet.
	 * 2. Walk the multicast forwarding cache (mfc) looking for
	 *    inner matches with this vif's index.
	 * 3. Expire any matching multicast forwarding cache entries.
	 * 4. Free vif state. This should disable ALLMULTI on the interface.
	 */
	mifp = get_mif_by_ifindex(ifp->if_index);
	if (!mifp) {
		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "No IPv6 VIF for %s (which is going down).\n",
			 ifp->if_name);
		return;
	}
	cds_lfht_for_each_entry(vrf->v_mvrf6.mf6ctable, &iter, rt, node) {
		if (rt->mf6c_parent == mifp->m6_if_index) {
			mfc6_debug(vrf->v_id, &rt->mf6c_origin,
				   &rt->mf6c_mcastgrp,
				   "%s is input interface so delete MFC.",
				   ifp->if_name);
			expire_mf6c(vrf, rt);
		} else if (IF_ISSET(mifp->m6_mif_index, &rt->mf6c_ifset)) {
			mfc6_debug(vrf->v_id, &rt->mf6c_origin,
				   &rt->mf6c_mcastgrp,
				   "Removing %s from olist.",
				   ifp->if_name);
			IF_CLR(mifp->m6_mif_index, &rt->mf6c_ifset);
		}
	}
	del_m6if(mifp->m6_if_index);
}

/*
 * Add a mif to the mif table
 */
int add_m6if(mifi_t ifindex)
{
	struct mif6 *mifp;
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);
	struct cds_lfht_node *retnode;
	struct cds_lfht *mif6table;
	unsigned char mif6_index;
	struct vrf *vrf;

	if (!ifp) {
		DP_DEBUG(MULTICAST, ERR, MCAST,
			 "Failure adding IPv6 MIF index %d.\n", ifindex);
		return -EINVAL;
	}

	vrf =  vrf_get_rcu(if_vrfid(ifp));

	if (!vrf)
		return -EINVAL;

	if (ifindex <= 0)
		return -EINVAL;

	if (get_mif_by_ifindex(ifindex))
		return -EEXIST;

	mif6table = vrf->v_mvrf6.mif6table;
	if (!mif6table)
		return -EINVAL;

	if (mcast_iftable_get_free_slot(&vrf->v_mvrf6.mf6c_ifset, ifindex,
					&mif6_index) != 0)
		return -EDQUOT;

	DP_DEBUG(MULTICAST, INFO, MCAST, "Adding IPv6 VIF to slot %d (%d).\n",
		 mif6_index, ifindex);

	mifp = calloc(1, sizeof(struct mif6));
	if (!mifp) {
		IF_CLR(mif6_index, &vrf->v_mvrf6.mf6c_ifset);
		return -ENOMEM;
	}

	mifp->m6_if_index = ifindex;
	mifp->m6_mif_index = mif6_index;
	mifp->m6_ifp	  = ifp;
	mifp->m6_flags	  = VIFF_USE_IFINDEX;
	mifp->m6_flags	  |= (is_tunnel_pimreg(ifp)) ? VIFF_REGISTER:0;
	mifp->m6_flags    |= (ifp && is_tunnel(ifp)) ? VIFF_TUNNEL:0;

	cds_lfht_node_init(&mifp->node);
	retnode = cds_lfht_add_replace(mif6table, mifp->m6_if_index,
			mif6_match, &mifp->m6_if_index, &mifp->node);
	if (retnode) {
		mifp = caa_container_of(retnode, struct mif6, node);
		IF_CLR(mifp->m6_mif_index, &vrf->v_mvrf6.mf6c_ifset);
		call_rcu(&mifp->rcu_head, mif6_free);
	}

	ip6_mcast_fal_int_enable(mifp, mif6table);
	if (!(ifp->if_flags & IFF_MULTICAST))
		return -EOPNOTSUPP;
	if_allmulti(ifp, 1);

	return 0;
}

static void update_mfc6_count(vrfid_t vrf_id, struct mf6c *rt,
			      struct vmf6cctl *mfccp)
{
	struct mif6 *mifp;
	struct cds_lfht_iter iter;
	int i;
	struct vrf *vrf = vrf_get_rcu(vrf_id);
	struct cds_lfht *mif6table;

	if (vrf == NULL) {
		DP_DEBUG(MULTICAST, ERR, MCAST, "MFC invalid vrf ID %d\n",
			 vrf_id);
		return;
	}

	mif6table = vrf->v_mvrf6.mif6table;

	cds_lfht_for_each_entry(mif6table, &iter, mifp, node) {
		i = mifp->m6_mif_index;
		if (IF_ISSET(i, &rt->mf6c_ifset) !=
		    IF_ISSET(i, &mfccp->mf6cc_ifset)) {

			if (IF_ISSET(i, &mfccp->mf6cc_ifset))
				rt->mf6c_olist_size++;
			else if (rt->mf6c_olist_size)
				rt->mf6c_olist_size--;


			if (unlikely(dp_debug & DP_DBG_MULTICAST)) {
				mfc6_debug(vrf_id, &rt->mf6c_origin,
					   &rt->mf6c_mcastgrp,
					   "%s %s olist (new olist size is %u).",
					   ifnet_indextoname(i),
					   (IF_ISSET(i, &rt->mf6c_ifset) ?
					    "removed from " : "added to"),
					   rt->mf6c_olist_size);
			}
		} else if (unlikely(dp_debug & DP_DBG_MULTICAST)) {
			if (IF_ISSET(i, &rt->mf6c_ifset)) {
				mfc6_debug(vrf_id, &rt->mf6c_origin,
					   &rt->mf6c_mcastgrp,
					   "%s already present (olist size %u).",
					   ifnet_indextoname(i),
					   rt->mf6c_olist_size);
			}
		}
	}
}
static void debug_update_mfc6_params(vrfid_t vrf_id, struct mf6c *rt,
			struct vmf6cctl *mfccp)
{
	if (unlikely(dp_debug & DP_DBG_MULTICAST)) {
		mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
			   "MFC parameters being updated/initialised.");

		if (rt->mf6c_parent != mfccp->mf6cc_parent)
			mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
				   "Input interface changed from %s (%u) to %s (%u)",
				   ifnet_indextoname(rt->mf6c_parent),
				   rt->mf6c_parent,
				   ifnet_indextoname(mfccp->mf6cc_parent),
				   mfccp->mf6cc_parent);
	}

}

static void update_mfc6_params(vrfid_t vrf_id, struct mf6c *rt,
			struct vmf6cctl *mfccp)
{
	int controller = 0;
	struct mif6 *mifp;
	struct vrf *vrf = vrf_get_rcu(vrf_id);
	struct cds_lfht_iter iter;
	int i;

	if (!vrf)
		return;

	debug_update_mfc6_params(vrf_id, rt, mfccp);

	rt->mf6c_parent = mfccp->mf6cc_parent;
	rt->mf6c_ifset	= mfccp->mf6cc_ifset;

	cds_lfht_for_each_entry(vrf->v_mvrf6.mif6table, &iter, mifp, node) {
		i = mifp->m6_mif_index;
		if (!IF_ISSET(i, &rt->mf6c_ifset))
			continue;

		/* If ifp is NULL this is not a dataplane interface.  */
		if ((!mifp->m6_ifp) || (mifp->m6_flags & VIFF_REGISTER)) {
			controller++;
			mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
				   "%s is register VIF.",
				  ifnet_indextoname(i));
			continue;
		}

		/*
		 * Do not attempt to forward in the dataplane if there
		 * is any unsupported tunnel in the olist. The kernel
		 * replicates all punted packets to all interfaces in
		 * the olist.
		 */
		if (mifp->m6_ifp->if_type == IFT_TUNNEL_OTHER) {
			controller++;
			mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
				   "%s is an unsupported tunnel VIF.",
				  ifnet_indextoname(i));
			continue;
		}
		if (i == rt->mf6c_parent) {
			controller++;
			mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
				   "%s is both incoming and outgoing interface.",
				   ifnet_indextoname(i));

		}
	}

	rt->mf6c_controller = controller;
	if (controller) {
		mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
			   "Cannot forward on this mroute in data plane; punting all packets.");
	}
}

/*
 * Delete a mif from the mif table
 */
int del_m6if(mifi_t mifi)
{
	struct mif6 *mifp;
	struct ifnet *ifp = dp_ifnet_byifindex(mifi);
	struct vrf *vrf;

	if (!ifp)
		return -EINVAL;

	vrf =  vrf_get_rcu(if_vrfid(ifp));

	if (!vrf)
		return -EINVAL;

	mifp = get_mif_by_ifindex(mifi);
	if (mifp == NULL)
		return -EINVAL;

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Deleting IPv6 VIF %s.\n",
		 ifnet_indextoname(mifi));

	if_allmulti(ifp, 0);

	IF_CLR(mifp->m6_mif_index, &vrf->v_mvrf6.mf6c_ifset);
	if (!cds_lfht_del(vrf->v_mvrf6.mif6table, &mifp->node)) {
		ip6_mcast_fal_int_disable(mifp, vrf->v_mvrf6.mif6table);
		call_rcu(&mifp->rcu_head, mif6_free);
	}

	return 0;
}

static inline void init_m6fc_counters(struct mf6c *rt)
{
	/* initialize pkt counters per src-grp */
	rt->mf6c_pkt_cnt     = 0;
	rt->mf6c_byte_cnt    = 0;
	rt->mf6c_wrong_if    = 0;
	rt->mf6c_expire      = 0;
	rt->mf6c_last_assert = 0;
	rt->mf6c_punted      = 0;
	rt->mf6c_punts_dropped = 0;
	rt->mf6c_controller  = 0;
	rt->mf6c_punt        = 0;
}

/* fully initialize an mfc entry from the parameter */
static bool init_m6fc_params(vrfid_t vrf_id, struct mf6c *rt,
		struct vmf6cctl *mfccp)
{
	int ret;

	rt->mf6c_origin	    = mfccp->mf6cc_origin.sin6_addr;
	rt->mf6c_mcastgrp   = mfccp->mf6cc_mcastgrp.sin6_addr;

	init_m6fc_counters(rt);
	update_mfc6_count(vrf_id, rt, mfccp);
	update_mfc6_params(vrf_id, rt, mfccp);

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

static u_int32_t mvrf_m6fc_size(struct mcast6_vrf *mvrf)
{
	unsigned long mrt_cnt = 0;
	long dummy;

	cds_lfht_count_nodes(mvrf->mf6ctable, &dummy, &mrt_cnt, &dummy);
	return (u_int32_t) mrt_cnt;
}

static void
ip6_mroute_add_fal_objects(vrfid_t vrf_id, struct vmf6cctl *mfccp,
			   struct mf6c *rt)
{
	enum pd_obj_state old_pd_state;
	int rc;
	struct vrf *vrf = vrf_get_rcu(vrf_id);

	if (!vrf)
		return;

	old_pd_state = rt->mfc_pd_state;

	if (rt->mf6c_fal_obj) {
		mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
			   "Updating FAL object 0x%lx for mroute",
			   rt->mf6c_fal_obj);
		rc = fal_ip6_upd_mroute(rt->mf6c_fal_obj, rt, mfccp,
					vrf->v_mvrf6.mif6table);
		if (rc && rc != -EOPNOTSUPP)
			mfc6_debug(vrf_id, &rt->mf6c_origin,
				   &rt->mf6c_mcastgrp,
				   "FAL object 0x%lx update failed: %s",
				   rt->mf6c_fal_obj, strerror(-rc));
	} else {
		if (mfccp->mf6cc_parent && mfccp->if_count)
			mfc6_debug(vrf_id, &rt->mf6c_origin,
				   &rt->mf6c_mcastgrp,
				   "Creating FAL objects for mroute");

		rc = fal_ip6_new_mroute(vrf_id, mfccp, rt,
					vrf->v_mvrf6.mif6table);
		if (rc && rc != -EOPNOTSUPP)
			mfc6_debug(vrf_id, &rt->mf6c_origin,
				   &rt->mf6c_mcastgrp,
				   "FAL entry object create failed: %s",
				   strerror(-rc));
	}

	if (rt->mf6c_fal_obj || rc) {
		rt->mfc_pd_state = fal_state_to_pd_state(rc);
		mroute6_hw_stats[old_pd_state]--;
		mroute6_hw_stats[rt->mfc_pd_state]++;
	}
}

/* Add an mfc entry */
int add_m6fc(vrfid_t vrf_id, struct vmf6cctl *mfccp)
{
	struct mf6c *rt;
	unsigned long hash;
	struct vrf *vrf = vrf_get_rcu(vrf_id);
	struct mf6c_key key;

	if (!vrf) {
		vrf = vrf_find_or_create(vrf_id);
		if (!vrf)
			return -ENOENT;
	} else if (!mvrf_m6fc_size(&vrf->v_mvrf6)) {
		/* increment vrf ref cnt when first mrt is added */
		vrf_find_or_create(vrf_id);
	}

	rt = mf6c_find(&vrf->v_mvrf6, &mfccp->mf6cc_origin.sin6_addr,
		 &mfccp->mf6cc_mcastgrp.sin6_addr);

	/* If an entry already exists, just update the fields */
	if (rt && (rt->mf6c_punt == 0)) {
		ip6_mroute_add_fal_objects(vrf_id, mfccp, rt);
		update_mfc6_count(vrf_id, rt, mfccp);
		update_mfc6_params(vrf_id, rt, mfccp);
		return 0;
	}

	/* Find the entry for which the upcall was made and update */
	if (rt) {
		mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
			   "Updating MFC for previously punted packet.");
		ip6_mroute_add_fal_objects(vrf_id, mfccp, rt);
		init_m6fc_params(vrf_id, rt, mfccp);
		return 0;
	}

	/* It is possible that an entry is being inserted without an upcall */
	rt = calloc(1, sizeof(*rt));
	if (!rt) {
		/* decrement vrf ref cnt when first mrt add failed */
		if (!mvrf_m6fc_size(&vrf->v_mvrf6))
			vrf_delete_by_ptr(vrf);
		return -ENOBUFS;
	}

	mfc6_debug(vrf_id, &mfccp->mf6cc_origin.sin6_addr,
		   &mfccp->mf6cc_mcastgrp.sin6_addr,
		   "Creating new MFC (due to Netlink message).");

	init_m6fc_params(vrf_id, rt, mfccp);
	rt->mfc_pd_state = PD_OBJ_STATE_NOT_NEEDED;
	mroute6_hw_stats[rt->mfc_pd_state]++;

	/* link into table */
	key.mf6c_origin = mfccp->mf6cc_origin.sin6_addr;
	key.mf6c_mcastgrp = mfccp->mf6cc_mcastgrp.sin6_addr;

	hash = rte_jhash_32b((uint32_t *)&key, MF6CKEYLEN, 0);
	cds_lfht_add(vrf->v_mvrf6.mf6ctable, hash, &rt->node);

	return 0;
}

/*
 * Delete an mfc entry
 */
int del_m6fc(vrfid_t vrf_id, struct vmf6cctl *mfccp)
{
	int rc;
	struct mf6c *rt;
	fal_object_t mfc_fal_obj;
	enum pd_obj_state old_pd_state;
	struct vrf *vrf = vrf_get_rcu(vrf_id);

	if (!vrf)
		return -ENOENT;

	rt = mf6c_find(&vrf->v_mvrf6, &mfccp->mf6cc_origin.sin6_addr,
			&mfccp->mf6cc_mcastgrp.sin6_addr);
	if (!rt || rt->mf6c_punt)
		return -EADDRNOTAVAIL;

	mfc6_debug(vrf_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
		   "MFC being deleted.");

	/* Inform controller if last mroute in VRF about to be deleted */
	if (mvrf_m6fc_size(&vrf->v_mvrf6) == 1)
		sg6_cnt_update(vrf, rt, true);

	old_pd_state = rt->mfc_pd_state;
	mfc_fal_obj = rt->mf6c_fal_obj;

	rc = fal_ip6_del_mroute(rt);
	if (rc && rc != -EOPNOTSUPP)
		mfc6_debug(vrf_id, &rt->mf6c_origin,
			   &rt->mf6c_mcastgrp,
			   "FAL object delete 0x%lx failed: %s",
			   mfc_fal_obj, strerror(-rc));

	mroute6_hw_stats[old_pd_state]--;

	if (!cds_lfht_del(vrf->v_mvrf6.mf6ctable, &rt->node))
		call_rcu(&rt->rcu_head, mf6c_free);

	/* decrement vrf ref cnt when last mrt deleted */
	if (!mvrf_m6fc_size(&vrf->v_mvrf6))
		vrf_delete_by_ptr(vrf);

	return 0;
}

/*
 * Determine if this a packet on this flow should be punted or
 * dropped due to rate limiting.
 */
static bool ip6_punt_rate_limit(struct mf6c *rt)
{
	enum rte_color color;

	color = rte_meter_srtcm_color_blind_check(&rt->meter,
						   &mfc_meter_profile,
						   rte_rdtsc(),
						   PUNT_1PKT);
	if (color != RTE_COLOR_RED) {
		rt->mf6c_punted++;
		return false;
	} else {
		rt->mf6c_punts_dropped++;
		return true;
	}
}

/*
 * IPv6 multicast forwarding function. This function assumes that the packet
 * pointed to by "ip6" has arrived on (or is about to be sent to) the interface
 * pointed to by "ifp", and the packet is to be relayed to other networks
 * that have members of the packet's destination IPv6 multicast group.
 *
 * The packet is returned unscathed to the caller, unless it is
 * erroneous, in which case a non-zero return value tells the caller to
 * discard it.
 *
 * NOTE: this implementation assumes that m->m_pkthdr.rcvif is NULL iff
 * this function is called in the originating context (i.e., not when
 * forwarding a packet from other node).  ip6_output(), which is currently the
 * only function that calls this function is called in the originating context,
 * explicitly ensures this condition.  It is caller's responsibility to ensure
 * that if this function is called from somewhere else in the originating
 * context in the future.
 */
static int ip6_mforward(vrfid_t vrf_id, struct mcast6_vrf *mvrf6,
		struct ip6_hdr *ip6, struct ifnet *ifp, struct rte_mbuf *m)
{
	struct mf6c *rt;
	struct mif6 *mifp;
	struct vmf6cctl mfcc;
	unsigned long hash;

	if (IN6_IS_ADDR_MC_INTFACELOCAL(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&ip6->ip6_dst))
		return RTF_SLOWPATH;

	if (ifp->ip6_mc_forwarding == 0)
		return RTF_SLOWPATH;

	/* Don't forward packet with Hop limit of zero or one */
	if (ip6->ip6_hlim <= 1) {
		MRT6STAT_INC(mvrf6, mrt6s_hlim);
		return 0;
	}

	/* Determine forwarding mifs from the forwarding cache table */
	MRT6STAT_INC(mvrf6, mrt6s_mfc_lookups);
	rt = mf6c_find(mvrf6, &ip6->ip6_src, &ip6->ip6_dst);

	if (rt && (rt->mf6c_punt == 0))
		return ip6_mdq(mvrf6, m, ifp, rt);

	/* If we don't have a route for packet's origin, punt the packet.
	 * todo: rate-limit future punting of packets in this flow.  */
	MRT6STAT_INC(mvrf6, mrt6s_mfc_misses);

	/* is there an upcall waiting for this packet? */
	if (!rt) {
		mifp = get_mif_by_ifindex(ifp->if_index);
		if (!mifp)
			return -EINVAL;

		/* no upcall, so make a new entry */
		rt = calloc(1, sizeof(*rt));
		if (!rt)
			return -ENOMEM;

		/* insert new entry at head of hash chain */
		memset(&mfcc, 0, sizeof(mfcc));
		mfcc.mf6cc_origin.sin6_addr = ip6->ip6_src;
		mfcc.mf6cc_mcastgrp.sin6_addr = ip6->ip6_dst;
		mfcc.mf6cc_parent = MIFI_INVALID;
		mfc6_debug(vrf_id, &mfcc.mf6cc_origin.sin6_addr,
			   &mfcc.mf6cc_mcastgrp.sin6_addr,
			   "Creating new MFC (due to traffic).");
		init_m6fc_params(vrf_id, rt, &mfcc);
		rt->mf6c_expire = UPCALL_EXPIRE;

		/* increment vrf ref cnt when first mrt is added */
		if (!mvrf_m6fc_size(mvrf6))
			vrf_find_or_create(vrf_id);

		/* link into table */
		hash = rte_jhash_32b((uint32_t *)&(ip6->ip6_src),
						MF6CKEYLEN, 0);
		cds_lfht_add(mvrf6->mf6ctable, hash, &rt->node);
		rt->mf6c_punt++;
		rt->mf6c_punted++;
		rt->mfc_pd_state = PD_OBJ_STATE_NOT_NEEDED;
		mroute6_hw_stats[rt->mfc_pd_state]++;
	} else {
		/* determine if q has overflowed */
		if (ip6_punt_rate_limit(rt)) {
			MRT6STAT_INC(mvrf6, mrt6s_upq_ovflw);
			return RTF_BLACKHOLE;
		}
	}

	MRT6STAT_INC(mvrf6, mrt6s_upcalls);
	return RTF_SLOWPATH;
}

#ifdef UPCALL_TIMER
/* Clean up cache entries if upcalls are not serviced */
static void expire_upcalls(__attribute__((unused)) struct rte_timer *rtetm,
			   __attribute__((unused)) void *arg)
{
	struct mf6c *mfc;
	struct cds_lfht_iter iter;
	vrfid_t vrf_id;
	struct vrf *vrf;

	VRF_FOREACH(vrf, vrf_id) {
		struct mcast6_vrf *mvrf6 = &vrf->v_mvrf6;
		rcu_read_lock();
		cds_lfht_for_each_entry(mvrf6->mf6ctable, &iter, mfc, node) {
			/* Skip real cache entries. Make sure it wasn't
			 * marked to not expire (shouldn't happen)
			 * If it expires now
			 */
			if (mfc->mf6c_punt && mfc->mf6c_expire &&
					(--mfc->mf6c_expire == 0)) {
				mfc6_debug(vrf->v_id, &mfc->mf6c_origin,
						&mfc->mf6c_mcastgrp,
						"Upcall not serviced so delete MFC.");
				expire_mf6c(vrf, mfc);
				MRT6STAT_INC(mvrf6, mrt6s_cache_cleanups);
			}
		}
		rcu_read_unlock();
	}
}
#endif

static void mcast6_tunnel_send(struct ifnet *in_ifp, struct mif6 *out_mifp,
			      struct rte_mbuf *m, int plen)
{
	struct ifnet *out_ifp;
	struct mcast_mgre_tun_walk_ctx mgre_tun_walk_ctx;

	out_ifp = out_mifp->m6_ifp;

	/* Call GRE API which will invoke specified callback
	 * for each end point in P2P or P2MP tunnel
	 */
	mgre_tun_walk_ctx.proto = ETH_P_IPV6;
	mgre_tun_walk_ctx.mbuf = m;
	mgre_tun_walk_ctx.in_ifp = in_ifp;
	mgre_tun_walk_ctx.pkt_len = plen;
	mgre_tun_walk_ctx.out_vif = out_mifp;
	mgre_tun_walk_ctx.hdr_len = sizeof(struct ip6_hdr);
	gre_tunnel_peer_walk(out_ifp, mcast_mgre_tunnel_endpoint_send,
			     &mgre_tun_walk_ctx);
	/*
	 * Decrement ref count on original mbuf as new mbuf
	 * was transmitted in replication loop.
	 */
	rte_pktmbuf_free(m);
}

/*
 * Packet transmission routine for VIF in olist.  Select appropriate send
 * function based on underlying interface type.
 */
static void mif6_send(struct ifnet *in_ifp, struct mif6 *out_mifp,
		      struct rte_mbuf *m, int plen)
{
	struct ifnet *out_ifp = out_mifp->m6_ifp;

	/*
	 * Punt for any tunnels unsupported in data plane.
	 *
	 * Note that if a packet is successfully switched out of some
	 * other interfaces in the olist in the data plane, a duplicate
	 * packet may be sent out of these interfaces by the kernel.
	 * Essentially, as things stand, the option is to potentially
	 * duplicate packets on some interfaces or fail to transmit
	 * packets on other interfaces in the olist.
	 */
	if (unlikely(out_ifp->if_type == IFT_TUNNEL_OTHER)) {
		struct vrf *vrf = vrf_get_rcu(if_vrfid(in_ifp));
		if (vrf) {
			struct mcast6_vrf *mvrf6 = &vrf->v_mvrf6;
			MRT6STAT_INC(mvrf6, mrt6s_slowpath);
		}
		out_mifp->m6_pkt_out_punt++;
		out_mifp->m6_bytes_out_punt += plen;
		mcast_ip6_deliver(in_ifp, m);
		return;
	}

	struct ip6_hdr *ip6 = ip6hdr(m);

	/*
	 * Time to decrement ttl since packet is being forwarded, not
	 * just punted. It was previously tested to ensure it is greater
	 * than 1 so there is no need to test for ttl expire here.
	 */
	ip6->ip6_hlim--;

	if (unlikely(out_ifp->if_type == IFT_TUNNEL_GRE &&
		     !(out_ifp->if_flags & IFF_NOARP))) {
		mcast6_tunnel_send(in_ifp, out_mifp, m, plen);
		return;
	}

	/* OIL replication counts */
	out_mifp->m6_pkt_out++;
	out_mifp->m6_bytes_out += plen;

	/*
	 * Send the packet down the pipeline graph.
	 */
	struct next_hop nh = {
		.flags = RTF_MULTICAST,
		.u.ifp = out_ifp,
	};
	struct pl_packet pl_pkt = {
		.mbuf = m,
		.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
		.l3_hdr = ip6,
		.in_ifp = in_ifp,
		.out_ifp = out_ifp,
		.nxt.v6 = &nh,
		.l2_proto = ETH_P_IPV6,
		.npf_flags = NPF_FLAG_CACHE_EMPTY,
	};

	pipeline_fused_ipv6_out(&pl_pkt);
}

/*
 * Packet forwarding routine once entry in the cache is made
 */
static int ip6_mdq(struct mcast6_vrf *mvrf6, struct rte_mbuf *m,
		   struct ifnet *in_ifp, struct mf6c *rt)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct mif6 *mifp;
	int plen = rte_pktmbuf_pkt_len(m);
	u_int32_t iszone, idzone;
	struct cds_lfht_iter iter;
	struct rte_mbuf *md, *mh;

	/* Don't forward if it didn't arrive on parent mif* for its origin.  */
	mifp = get_mif_by_ifindex(rt->mf6c_parent);
	if (mifp == NULL || mifp->m6_if_index != in_ifp->if_index) {
		/* if wrong iif */
		MRT6STAT_INC(mvrf6, mrt6s_wrong_if);
		rt->mf6c_wrong_if++;

		/* Rate limit this punted packet */
		if (ip6_punt_rate_limit(rt)) {
			MRT6STAT_INC(mvrf6, mrt6s_upq_ovflw);
			return RTF_BLACKHOLE;
		} else {
			return RTF_SLOWPATH;
		}
	}

	/* Rate limit this punted packet */
	if (rt->mf6c_controller) {
		if (ip6_punt_rate_limit(rt)) {
			return RTF_BLACKHOLE;
		} else {
			return RTF_SLOWPATH;
		}
	}

	/*
	 * RFC 4291 The unspecified address must not be used as the destination
	 * address. Source address of unspecified must never be forwarded.
	 * The requiremnt is to not forward, not drop all.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_dst)) {
		IP6STAT_INC_IFP(in_ifp, IPSTATS_MIB_INADDRERRORS);
		return RTF_BLACKHOLE;
	}

	/*
	 * RFC 4291 The loopback address must not be used as the source address
	 * in IPv6 packets that are sent outside of a single node.  A
	 * destination address of loopback must never be sent outside of a
	 * single node.
	 * Drop packets not on loopback interface that have a loopback source
	 * or destination address.
	 */
	if (in6_setscope(&ip6->ip6_src, in_ifp, &iszone) ||
	    in6_setscope(&ip6->ip6_dst, in_ifp, &idzone))
		return RTF_REJECT;

	mifp->m6_pkt_in++;
	mifp->m6_bytes_in += plen;
	rt->mf6c_pkt_cnt++;
	rt->mf6c_byte_cnt += plen;

	/* Take a reference to the data portion of the packet (beyond the
	 *  IP header). This allows this to be shared over all replications
	 * avoiding an expensive copy */
	md = pktmbuf_clone(m, m->pool);
	if (!md)
		return -ENOBUFS;

	rte_pktmbuf_adj(md, dp_pktmbuf_l2_len(md) + sizeof(struct ip6_hdr));

	/* For each mif, forward a copy of the packet if there are group
	 * members downstream on the interface. */
	cds_lfht_for_each_entry(mvrf6->mif6table, &iter, mifp, node) {
		if (IF_ISSET(mifp->m6_mif_index, &rt->mf6c_ifset)) {
			struct ifnet *out_ifp = mifp->m6_ifp;

			if (!out_ifp)
				continue;
			const bool if_up = (out_ifp->if_flags & IFF_UP);
			if (!if_up)
				continue;

			mh = mcast_create_l2l3_header(m, md,
						      sizeof(struct ip6_hdr));
			if (mh) {
				/* send the newly created packet chain */
				mif6_send(in_ifp, mifp, mh, plen);
			} else {
				rte_pktmbuf_free(md);
				return -ENOBUFS;
			}
		}
	}
	rte_pktmbuf_free(md);
	return 0;
}

/*
 * Send per-mroute stats block to controller.  Called when last mroute in
 * VRF being deleted or during periodic iteration over all VRFs & mroutes.
 */
static void sg6_cnt_update(struct vrf *vrf, struct mf6c *rt,
			   bool last_mfc_deletion)
{
	struct sioc_sg_req6 sr;
	uint32_t flags = 0;

	enum fal_ip_mcast_entry_stat_type cntr_ids[] = {
		FAL_IP_MCAST_GROUP_STAT_IN_PACKETS,
		FAL_IP_MCAST_GROUP_STAT_IN_OCTETS
	};
	uint64_t cntrs[ARRAY_SIZE(cntr_ids)];
	int ret;

	ret = fal_ip_mcast_get_stats(rt->mf6c_fal_obj, ARRAY_SIZE(cntr_ids),
				     &cntr_ids[0], &cntrs[0]);
	if (ret < 0) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "failed to collect v6 hardware counters: %s\n",
				 strerror(-ret));
	} else {
		rt->mf6c_hw_pkt_cnt +=
			cntrs[FAL_IP_MCAST_GROUP_STAT_IN_PACKETS];
		rt->mf6c_hw_byte_cnt +=
			cntrs[FAL_IP_MCAST_GROUP_STAT_IN_OCTETS];
	}

	sr.src.sin6_addr = rt->mf6c_origin;
	sr.grp.sin6_addr = rt->mf6c_mcastgrp;
	sr.pktcnt = rt->mf6c_pkt_cnt + rt->mf6c_hw_pkt_cnt;
	sr.bytecnt = rt->mf6c_byte_cnt + rt->mf6c_hw_byte_cnt;
	sr.wrong_if = rt->mf6c_wrong_if;

	/*
	 * Indicate if the last mroute in the VRF is about to be deleted
	 * so controller can tidy up appropriately.
	 */
	if (last_mfc_deletion) {
		mfc6_debug(vrf->v_id, &rt->mf6c_origin,
			   &rt->mf6c_mcastgrp,
			   "Last mroute in VRF about to be deleted.");
		flags = 1;
	}

	send_sg6_cnt(&sr, dp_vrf_get_external_id(vrf->v_id), flags);
}

/*
 * Called by handler for periodic stats timer; iterate over all VRFs and,
 * for each mroute in the VRF, send stats block to controller.
 */
static void sg6_cnt_dump(void)
{
	struct cds_lfht_iter iter;
	struct mf6c *rt;
	vrfid_t vrf_id;
	struct vrf *vrf;

	VRF_FOREACH(vrf, vrf_id) {
		struct mcast6_vrf mvrf6 = vrf->v_mvrf6;
		cds_lfht_for_each_entry(mvrf6.mf6ctable, &iter, rt, node) {
			sg6_cnt_update(vrf, rt, false);
		}
	}
}

static void mrt6_stats(__attribute__((unused)) struct rte_timer *rtetm,
		      __attribute__((unused)) void *arg)
{
	sg6_cnt_dump();
}


void mrt6_dump(FILE *f, struct vrf *vrf)
{
	struct mf6c *mfc;
	struct in6_addr *addr;
	char oa[INET6_ADDRSTRLEN];
	char ga[INET6_ADDRSTRLEN];
	struct cds_lfht_iter iter;
	struct cds_lfht_iter iter_mif;
	struct mif6 *mifp;
	char olist_buf[(IFNAMSIZ+1) * MFC_MAX_MVIFS];
	int olist_index;

	json_writer_t *wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "route6");
	jsonw_start_array(wr);

	memset(olist_buf, 0, (IFNAMSIZ+1) * MFC_MAX_MVIFS);

	cds_lfht_for_each_entry(vrf->v_mvrf6.mf6ctable, &iter, mfc, node) {
		olist_index = 0;
		olist_buf[olist_index] = '\0';

		cds_lfht_for_each_entry(vrf->v_mvrf6.mif6table, &iter_mif,
					mifp, node) {
			if (IF_ISSET(mifp->m6_mif_index, &mfc->mf6c_ifset)) {

				olist_index += snprintf(olist_buf + olist_index,
							sizeof(olist_buf) -
							olist_index,
							"%s",
							ifnet_indextoname_safe(
							  mifp->m6_if_index));
				olist_index += snprintf(olist_buf + olist_index,
							sizeof(olist_buf)
							- olist_index,
							" ");
			}
		}

		if (olist_index)
			olist_buf[olist_index-1] = '\0';

		addr = &mfc->mf6c_origin;
		strcpy(oa, ip6_sprintf(addr));
		addr = &mfc->mf6c_mcastgrp;
		strcpy(ga, ip6_sprintf(addr));

		jsonw_start_object(wr);
		jsonw_string_field(wr, "source", oa);
		jsonw_string_field(wr, "group", ga);
		jsonw_string_field(wr, "input",
			ifnet_indextoname_safe(mfc->mf6c_parent));
		jsonw_string_field(wr, "output(s)", olist_buf);
		if (mfc->mf6c_fal_obj)
			jsonw_string_field(wr, "forwarding",
					   "hardware");
		else
			jsonw_string_field(wr, "forwarding",
					   mfc->mf6c_controller ?
					   "slow/controller" :
					   "fast/dataplane");
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

void mfc6_stat(FILE *f, struct vrf *vrf)
{
	struct mf6c *rt;
	struct in6_addr *addr;
	struct cds_lfht_iter iter;
	char oa[INET6_ADDRSTRLEN];
	char ga[INET6_ADDRSTRLEN];

	json_writer_t *wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "fcstat6");
	jsonw_start_array(wr);

	cds_lfht_for_each_entry(vrf->v_mvrf6.mf6ctable, &iter, rt, node) {

		jsonw_start_object(wr);
		addr = &rt->mf6c_origin;
		strcpy(oa, ip6_sprintf(addr));
		addr = &rt->mf6c_mcastgrp;
		strcpy(ga, ip6_sprintf(addr));

		jsonw_string_field(wr, "origin", oa);
		jsonw_string_field(wr, "group", ga);
		jsonw_uint_field(wr, "packets", rt->mf6c_pkt_cnt);
		jsonw_uint_field(wr, "bytes", rt->mf6c_byte_cnt);
		jsonw_uint_field(wr, "hw_packets", rt->mf6c_hw_pkt_cnt);
		jsonw_uint_field(wr, "hw_bytes", rt->mf6c_hw_byte_cnt);
		jsonw_uint_field(wr, "wrongif", rt->mf6c_wrong_if);
		jsonw_uint_field(wr, "controller", rt->mf6c_controller);
		jsonw_int_field(wr, "expire", rt->mf6c_expire);
		jsonw_uint_field(wr, "punted", rt->mf6c_punted);
		jsonw_uint_field(wr, "punts_dropped", rt->mf6c_punts_dropped);
		jsonw_uint_field(wr, "punt", rt->mf6c_punt);
		jsonw_uint_field(wr, "olist_size", rt->mf6c_olist_size);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

void mrt6_stat(FILE *f, struct vrf *vrf)
{
	struct mcast6_vrf *mvrf6 = &vrf->v_mvrf6;
	json_writer_t *wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "rtstat6");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "mfc_lookups", mvrf6->stat.mrt6s_mfc_lookups);
	jsonw_uint_field(wr, "mfc_misses", mvrf6->stat.mrt6s_mfc_misses);
	jsonw_uint_field(wr, "upcalls", mvrf6->stat.mrt6s_upcalls);
	jsonw_uint_field(wr, "wrong_if", mvrf6->stat.mrt6s_wrong_if);
	jsonw_uint_field(wr, "upcall_ovfl", mvrf6->stat.mrt6s_upq_ovflw);
	jsonw_uint_field(wr, "no_upcall", mvrf6->stat.mrt6s_cache_cleanups);
	jsonw_uint_field(wr, "slowpath", mvrf6->stat.mrt6s_slowpath);
	jsonw_uint_field(wr, "drop", mvrf6->stat.mrt6s_drop);
	jsonw_uint_field(wr, "hlim", mvrf6->stat.mrt6s_hlim);
	jsonw_uint_field(wr, "pkttoobig", mvrf6->stat.mrt6s_pkttoobig);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

void mvif6_dump(FILE *f, __attribute__((unused)) struct vrf *vrf)
{
	struct cds_lfht_iter iter;
	struct mif6 *mifp;

	json_writer_t *wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "mif6");
	jsonw_start_array(wr);

	cds_lfht_for_each_entry(vrf->v_mvrf6.mif6table, &iter, mifp, node) {
		if (mifp->m6_flags) {
			jsonw_start_object(wr);
			jsonw_string_field(wr, "interface", mifp->m6_ifp ?
					  mifp->m6_ifp->if_name : "non-vplane");
			jsonw_int_field(wr, "if_index", mifp->m6_mif_index);
			jsonw_int_field(wr, "flags", mifp->m6_flags);
			jsonw_uint_field(wr, "pkt_in", mifp->m6_pkt_in);
			jsonw_uint_field(wr, "pkt_out",	mifp->m6_pkt_out);
			jsonw_uint_field(wr, "pkt_out_punt",
					 mifp->m6_pkt_out_punt);
			jsonw_uint_field(wr, "bytes_in", mifp->m6_bytes_in);
			jsonw_uint_field(wr, "bytes_out", mifp->m6_bytes_out);
			jsonw_uint_field(wr, "bytes_out_punt",
					 mifp->m6_bytes_out_punt);
			jsonw_end_object(wr);
		}
	}

	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

int mcast_ip6(struct ip6_hdr *ip6, struct ifnet *ifp, struct rte_mbuf *m)
{
	int err = 0;
	struct vrf *vrf = vrf_get_rcu(pktmbuf_get_vrf(m));

	if (unlikely(!vrf)) {
		err = -ENOENT;
		goto free;
	}

	struct mcast6_vrf *mvrf6 = &vrf->v_mvrf6;
	err = ip6_mforward(vrf->v_id, mvrf6, ip6, ifp, m);
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
	MRT6STAT_INC(mvrf6, mrt6s_slowpath);
	mcast_ip6_deliver(ifp, m);
	return err;

reject:
	/* There is no output if so count against pkt's VRF */
	IP6STAT_INC_MBUF(m, IPSTATS_MIB_OUTNOROUTES);
drop:
	MRT6STAT_INC(mvrf6, mrt6s_drop);
free:
	rte_pktmbuf_free(m);
	return err;
}

int mcast6_vrf_init(struct vrf *vrf)
{
	struct cds_lfht *mf6ctable = cds_lfht_new(MFC_HASHSIZE,
			MFC_HASHSIZE, MFC_HASHSIZE, CDS_LFHT_ACCOUNTING, NULL);

	if (!mf6ctable) {
		RTE_LOG(ERR, MCAST,
			"%s:cds_lfht_new mf6ctable failed\n", __func__);
		return -1;
	}

	vrf->v_mvrf6.v_fal_obj = 0;
	vrf->v_mvrf6.v_fal_rpf = 0;
	vrf->v_mvrf6.v_fal_rpf_lst = NULL;

	vrf->v_mvrf6.mf6ctable = mf6ctable;

	vrf->v_mvrf6.mif6table = cds_lfht_new(MFC_MAX_MVIFS, MFC_MAX_MVIFS,
					MFC_MAX_MVIFS, CDS_LFHT_ACCOUNTING,
					NULL);
	if (!vrf->v_mvrf6.mif6table) {
		RTE_LOG(ERR, MCAST,
			"%s: cds_lfht_new mif6table failed vrf %s\n", __func__,
			vrf->v_name);
		return -1;
	}
	memset(&(vrf->v_mvrf6.mf6c_ifset), 0, sizeof(struct if_set));
	return 0;
}

void mcast6_vrf_uninit(struct vrf *vrf)
{
	struct mf6c *rt;
	struct cds_lfht_iter iter;

	if (!vrf->v_mvrf6.mf6ctable)
		return;

	cds_lfht_for_each_entry(vrf->v_mvrf6.mf6ctable, &iter, rt, node)
		expire_mf6c(vrf, rt);

	dp_ht_destroy_deferred(vrf->v_mvrf6.mf6ctable);
	vrf->v_mvrf6.mf6ctable = NULL;

	dp_ht_destroy_deferred(vrf->v_mvrf6.mif6table);
	vrf->v_mvrf6.mif6table = NULL;

}

int mcast_stop_ipv6(void)
{
#ifdef UPCALL_TIMER
	rte_timer_stop(&expire_upcalls_ch);
#endif

	return 0;
}

static void expire_mf6c(struct vrf *vrf, struct mf6c *rt)
{
	int rc;
	fal_object_t mfc_fal_obj;
	enum pd_obj_state old_pd_state;

	mfc6_debug(vrf->v_id, &rt->mf6c_origin, &rt->mf6c_mcastgrp,
		   "MFC being expired.");
	rt->mf6c_punt = 0;

	/* Inform controller if last mroute in VRF about to be deleted */
	if (mvrf_m6fc_size(&vrf->v_mvrf6) == 1)
		sg6_cnt_update(vrf, rt, true);

	old_pd_state = rt->mfc_pd_state;
	mfc_fal_obj = rt->mf6c_fal_obj;

	rc = fal_ip6_del_mroute(rt);
	if (rc && rc != -EOPNOTSUPP)
		mfc6_debug(vrf->v_id, &rt->mf6c_origin,
			   &rt->mf6c_mcastgrp,
			   "FAL object delete 0x%lx failed: %s",
			   mfc_fal_obj, strerror(-rc));

	mroute6_hw_stats[old_pd_state]--;

	if (!cds_lfht_del(vrf->v_mvrf6.mf6ctable, &rt->node))
		call_rcu(&rt->rcu_head, mf6c_free);
}

void mcast_init_ipv6(void)
{

#ifdef UPCALL_TIMER
	rte_timer_init(&expire_upcalls_ch);
	rte_timer_reset(&expire_upcalls_ch, EXPIRE_TIMEOUT, PERIODICAL,
			rte_get_master_lcore(), expire_upcalls, NULL);
#endif
	rte_timer_init(&mrt6_stats_timer);
	rte_timer_reset(&mrt6_stats_timer, SG_CNT_INTERVAL, PERIODICAL,
			rte_get_master_lcore(), mrt6_stats, NULL);
}
