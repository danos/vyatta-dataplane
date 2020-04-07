/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */
/*-
 * Copyright (C) 1998 WIDE Project.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
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
 *	$KAME: ip6_mroute.h,v 1.19 2001/06/14 06:12:55 suz Exp $
 * $FreeBSD$
 */

/*	BSDI ip_mroute.h,v 2.5 1996/10/11 16:01:48 pjd Exp	*/

/*
 * Definitions for IP multicast forwarding.
 *
 * Written by David Waitzman, BBN Labs, August 1988.
 * Modified by Steve Deering, Stanford, February 1989.
 * Modified by Ajit Thyagarajan, PARC, August 1993.
 * Modified by Ajit Thyagarajan, PARC, August 1994.
 * Modified by Ahmed Helmy, USC, September 1996.
 *
 * MROUTING Revision: 1.2
 */

#ifndef IP6_MROUTE_H
#define IP6_MROUTE_H

#include <linux/mroute6.h>
#include <netinet/in.h>
#include <rte_meter.h>
#include <stdint.h>
#include <time.h>

#include "urcu.h"

#define MIFI_INVALID		ALL_MIFS
#define MF6C_INCOMPLETE_PARENT	ALL_MIFS

/*
 * this structure is a copy of the kernel mf6cctl structure with the addition
 * of an if_count field. This brings it into line with the corresponding v4
 * structure
 */
struct vmf6cctl {
	struct sockaddr_in6 mf6cc_origin;	/* Origin of mcast	*/
	struct sockaddr_in6 mf6cc_mcastgrp;	/* Group in question	*/
	mifi_t	mf6cc_parent;			/* Where it arrived	*/
	struct if_set mf6cc_ifset;		/* Where it is going */
	uint32_t if_count;			/* number of oifs */
};

/*
 * The kernel's multicast routing statistics.
 */
struct mrt6stat {
	uint64_t mrt6s_mfc_lookups;	/* # forw. cache hash table hits   */
	uint64_t mrt6s_mfc_misses;	/* # forw. cache hash table misses */
	uint64_t mrt6s_upcalls;		/* # calls to mcast routing daemon */
	uint64_t mrt6s_wrong_if;	/* arrived on wrong interface	   */
	uint64_t mrt6s_upq_ovflw;	/* upcall Q overflow		   */
	uint64_t mrt6s_cache_cleanups;	/* # entries with no upcalls	   */
	uint64_t mrt6s_slowpath;	/* # pkts sent to the slowpath	   */
	uint64_t mrt6s_drop;		/* # pkts dropped on an error	   */
	uint64_t mrt6s_hlim;		/* # pkts dropped on hop limit	   */
	uint64_t mrt6s_pkttoobig;	/* # pkts whose length exceeds MTU */
};

struct mcast6_vrf {
	struct cds_lfht *mf6ctable;
	struct mrt6stat stat;
	struct cds_lfht *mif6table;
	struct if_set mf6c_ifset;
	fal_object_t	v_fal_obj;	   /* fal object                */
	fal_object_t	v_fal_rpf;	   /* fal rpf group object      */
	struct fal_object_list_t *v_fal_rpf_lst;/* fal rpf members object  */
};

#define	MRT6STAT_ADD(mvrf6, name, val)	(mvrf6->stat.name += (val))
#define	MRT6STAT_INC(mvrf6, name)	MRT6STAT_ADD(mvrf6, name, 1)

/*
 * The kernel's multicast-interface structure.
 */
struct mif6 {
	struct cds_lfht_node node;
	struct rcu_head	     rcu_head;
	unsigned char	     m6_flags;	        /* MIFF flags defined above   */
	struct ifnet	     *m6_ifp;		/* pointer to interface       */
	unsigned int	     m6_if_index;	/* interface device index     */
	unsigned char        m6_mif_index;      /* per-vrf mif index */
	uint64_t	     m6_pkt_in;	        /* # pkts in on interface     */
	uint64_t	     m6_pkt_out;	/* # pkts out on interface    */
	uint64_t	     m6_pkt_out_punt;	/* # pkts punted at output    */
	uint64_t	     m6_bytes_in;	/* # bytes in on interface    */
	uint64_t	     m6_bytes_out;	/* # bytes out on interface   */
	uint64_t	     m6_bytes_out_punt;	/* # bytes punted at output   */
};

struct mf6c_key {
	struct in6_addr		mf6c_origin;
	struct in6_addr	mf6c_mcastgrp;
};

#define MF6CKEYLEN (sizeof(struct mf6c_key) / 4)

/*
 * The kernel's multicast forwarding cache entry structure
 */
struct mf6c {
	struct cds_lfht_node	node;
	struct rcu_head		rcu_head;
	struct in6_addr	mf6c_origin;		 /* IPv6 origin of mcasts    */
	struct in6_addr		mf6c_mcastgrp;	 /* multicast group	     */
	mifi_t			mf6c_parent;	 /* incoming IF              */
	struct if_set		mf6c_ifset;	 /* set of outgoing IFs      */
	unsigned char           mf6c_olist_size; /* number of intfs in olist  */
	struct rte_meter_srtcm  meter;		 /* punt rate meter          */
	int			mf6c_controller; /* forward via controller   */
	uint64_t		mf6c_pkt_cnt;	 /* pkt count for src-grp    */
	uint64_t		mf6c_byte_cnt;	 /* byte count for src-grp   */
	uint64_t		mf6c_hw_pkt_cnt; /* HW pkt count for src-grp */
	uint64_t		mf6c_hw_byte_cnt;/* HW byte count for src-grp */
	uint64_t		mf6c_wrong_if;	 /* wrong if for src-grp     */
	int			mf6c_expire;	 /* time to clean entry up   */
	time_t			mf6c_last_assert;/* last assert		     */
	uint64_t		mf6c_punted;	 /* number packets punted    */
	uint64_t		mf6c_punts_dropped; /* number punts dropped  */
	uint64_t		mf6c_punt;	 /* punt all packets         */
	enum pd_obj_state mfc_pd_state;		 /* platform dependent state */
	fal_object_t		mf6c_fal_obj;	 /* fal entry object	     */
	fal_object_t		mf6c_fal_rpf;	 /* fal rpf group object      */
	struct fal_object_list_t *mf6c_fal_rpf_lst;/* fal rpf members object */
	fal_object_t		mf6c_fal_ol;	   /* fal olist group object */
	struct fal_object_list_t *mf6c_fal_ol_lst; /* fal olist members object*/
};

#endif /* !IP6_MROUTE_H */
