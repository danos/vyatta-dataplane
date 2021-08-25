/*
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */
/*-
 * Copyright (c) 1989 Stephen Deering.
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
 *	@(#)ip_mroute.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD$
 */

#ifndef IP_MROUTE_H
#define IP_MROUTE_H

#include <linux/mroute.h>
#include <linux/mroute6.h>
#include <netinet/in.h>
#include <rte_meter.h>
#include <stdint.h>
#include <time.h>
#include "fal_plugin.h"
#include "pd_show.h"

#include "urcu.h"

/*
 * Definitions for IP multicast forwarding.
 *
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 * Modified by Ajit Thyagarajan, PARC, August 1993.
 * Modified by Ajit Thyagarajan, PARC, August 1994.
 * Modified by Ahmed Helmy, SGI, June 1996.
 * Modified by Pavlin Radoslavov, ICSI, October 2002.
 *
 * MROUTING Revision: 3.3.1.3
 * and PIM-SMv2 and PIM-DM support, advanced API support,
 * bandwidth metering and signaling.
 */

/*
 * this structure is a copy of the kernel mfcctl structure substituting an
 * ifset bitmask structure for the old ttls array. This allows us to better
 * scale the number of multicast enabled interfaces supported.
 */
struct vmfcctl {
	struct in_addr mfcc_origin;		/* Origin of mcast	*/
	struct in_addr mfcc_mcastgrp;		/* Group in question	*/
	vifi_t	mfcc_parent;			/* Where it arrived	*/
	uint32_t if_count;			/* number of oifs       */
	struct if_set mfcc_ifset;		/* Where it is going	*/
	unsigned int mfcc_pkt_cnt;		/* pkt count for src-grp */
	unsigned int mfcc_byte_cnt;
	unsigned int mfcc_wrong_if;
	int	     mfcc_expire;
};

/*
 * The kernel's multicast routing statistics.
 */
struct mrtstat {
	uint64_t mrts_mfc_lookups;	/* # forw. cache hash table hits   */
	uint64_t mrts_mfc_misses;	/* # forw. cache hash table misses */
	uint64_t mrts_upcalls;		/* # calls to mcast routing daemon */
	uint64_t mrts_wrong_if;		/* arrived on wrong interface	   */
	uint64_t mrts_upq_ovflw;	/* upcall Q overflow		   */
	uint64_t mrts_cache_cleanups;	/* # entries with no upcalls	   */
	uint64_t mrts_slowpath;		/* # mcast pkts sent to  slowpath  */
	uint64_t mrts_drop;		/* # mcast drops due to errors     */
	uint64_t mrts_ttl;		/* # mcast drops due to ttl        */
	uint64_t mrts_igmp_in;		/* # igmp packets received         */
	uint64_t mrts_pim_in;		/* # pim packets received          */
	uint64_t mrts_icmp_in;		/* # icmp packets received         */
	uint64_t mrts_localgrp_in;	/* # matching IN_LOCAL_GROUP       */
};

/*
 * per vrf mfc cache
 */

struct mcast_vrf {
	struct cds_lfht *mfchashtbl;
	struct mrtstat stat;
	struct cds_lfht *viftable;
	struct if_set	mfc_ifset;		/* set of mulicast ifs  */
	fal_object_t	v_fal_obj;	   /* fal object                */
	fal_object_t	v_fal_rpf;	   /* fal rpf group object      */
	struct fal_object_list_t *v_fal_rpf_lst;/* fal rpf members object  */
};

#define	MRTSTAT_ADD(mvrf, name, val)	(mvrf->stat.name += (val))
#define	MRTSTAT_INC(mvrf, name)	MRTSTAT_ADD(mvrf, name, 1)

#define VIFI_INVALID    ((vifi_t) -1)

/*
 * The kernel's virtual-interface structure.
 */
struct vif {
	struct cds_lfht_node	node;
	struct rcu_head	rcu_head;
	unsigned char	v_flags;	   /* VIFF_ flags defined above      */
	unsigned char	v_threshold;	   /* min ttl required to fwd on vif */
	struct ifnet	*v_ifp;		   /* pointer to interface           */
	uint32_t	v_if_index;	   /* interface device index	     */
	unsigned char   v_vif_index;       /* per vrf vif index              */
	uint64_t	v_pkt_in;	   /* # pkts in on interface         */
	uint64_t	v_pkt_out;	   /* # pkts out on interface        */
	uint64_t	v_pkt_out_punt;	   /* # pkts punted at output intf   */
	uint64_t	v_bytes_in;	   /* # bytes in on interface	     */
	uint64_t	v_bytes_out;	   /* # bytes out on interface       */
	uint64_t	v_bytes_out_punt;  /* # bytes punted at output intf  */
};

struct mfc_key {
	struct in_addr  mfc_origin;             /* IP origin of mcasts       */
	struct in_addr  mfc_mcastgrp;           /* multicast group associated*/
};

#define MFCKEYLEN (sizeof(struct mfc_key)/4)

/*
 * The kernel's multicast forwarding cache entry structure
 */
struct mfc {
	struct cds_lfht_node node;
	struct rcu_head rcu_head;
	struct in_addr	mfc_origin;		/* IP origin of mcasts	     */
	struct in_addr  mfc_mcastgrp;		/* multicast group associated*/
	vifi_t		mfc_parent;		/* incoming vif              */
	vifi_t		mfc_controller;		/* all packets to controller */
	struct if_set	mfc_ifset;		/* set of outgoing IFs   */
	unsigned char   mfc_olist_size;         /* number of intfs in olist  */
	struct rte_meter_srtcm meter;		/* punt rate meter           */
	uint64_t	mfc_pkt_cnt;		/* pkt count for src-grp     */
	uint64_t	mfc_byte_cnt;		/* byte count for src-grp    */
	uint64_t	mfc_hw_pkt_cnt;		/* HW pkt count for src-grp  */
	uint64_t	mfc_hw_byte_cnt;	/* HW byte count for src-grp */
	uint64_t	mfc_wrong_if;		/* wrong if for src-grp	     */
	uint64_t	mfc_ctrl_pkts;		/* packets to controller     */
	int		mfc_expire;		/* time to clean entry up    */
	time_t		mfc_last_assert;	/* last time I sent an assert*/
	uint64_t	mfc_punted;		/* # of packets punted       */
	uint64_t	mfc_punts_dropped;	/* # of punts dropped        */
	uint64_t	mfc_punt;		/* punt all packets          */
	enum pd_obj_state mfc_pd_state;		/* platform dependent state  */
	fal_object_t	mfc_fal_obj;		/* fal object                */
	fal_object_t	mfc_fal_rpf;		/* fal rpf group object      */
	struct fal_object_list_t *mfc_fal_rpf_lst;/* fal rpf members object  */
	fal_object_t	mfc_fal_ol;		/* fal olist group object    */
	struct fal_object_list_t *mfc_fal_ol_lst;/* fal olist members object */
};

#endif /* IP_MROUTE_H */
