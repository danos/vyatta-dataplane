/*
 * l3_v4_route_lookup.c
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>

#include "compiler.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "ip_mcast.h"
#include "main.h"
#include "pktmbuf_internal.h"

#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "route.h"
#include "snmp_mib.h"
#include "vrf_internal.h"

struct pl_node;

enum ipv4_route_lookup_mode {
	IPV4_LKUP_MODE_ROUTER,
	IPV4_LKUP_MODE_HOST,
};

static inline struct pl_node *
vrf_to_ipv4_route_lookup_node(struct vrf *vrf)
{
	/* our imaginary node */
	return (struct pl_node *)vrf;
}

static inline struct vrf *
ipv4_route_lookup_node_to_vrf(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct vrf *)node;
}

static ALWAYS_INLINE unsigned int
_ipv4_route_lookup_process_common(struct pl_packet *pkt, void *context __unused,
				  enum pl_mode mode,
				  enum ipv4_route_lookup_mode lkup_mode)
{
	struct ifnet *ifp = pkt->in_ifp;
	struct vrf *vrf;
	struct iphdr *ip = pkt->l3_hdr;

	/* Is it a broadcast? */
	if (unlikely(pkt->l2_pkt_type == L2_PKT_BROADCAST)) {
		if (IN_LBCAST(ntohl(ip->daddr)) ||
		    ifa_broadcast(ifp, ip->daddr))
			return IPV4_ROUTE_LOOKUP_L4;

		/* RFC 1122 disallow broadcast sent to L3 unicast */
		IPSTAT_INC(if_vrfid(ifp), IPSTATS_MIB_INADDRERRORS);
		return IPV4_ROUTE_LOOKUP_DROP;
	}

	/* Is it a IP multicast? */
	if (unlikely(IN_MULTICAST(ntohl(ip->daddr)))) {
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INMCASTPKTS);
		mcast_ip(ip, ifp, pkt->mbuf);
		return IPV4_ROUTE_LOOKUP_FINISH;
	}

	vrf = vrf_get_rcu_fast(pktmbuf_get_vrf(pkt->mbuf));
	struct next_hop *nxt = rt_lookup_fast(vrf, ip->daddr,
					      pkt->tblid, pkt->mbuf);

	pkt->nxt.v4 = nxt;

	/*
	 * if nxt == NULL, postpone sending icmp err
	 * till crypto out bound policy check is done
	 */
	if (nxt && nexthop_is_local(nxt))
		return IPV4_ROUTE_LOOKUP_L4;

	/*
	 * If invoked from forwarding disabled interface then drop
	 */
	switch (lkup_mode) {
	case IPV4_LKUP_MODE_ROUTER:
		break;
	case IPV4_LKUP_MODE_HOST:
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INADDRERRORS);
		return IPV4_ROUTE_LOOKUP_DROP;
	}

	/* needs slow path */
	if (unlikely(pkt->val_flags & NEEDS_SLOWPATH))
		return IPV4_ROUTE_LOOKUP_LOCAL;

	/*
	 * Check TTL
	 */
	if (unlikely(ip->ttl <= IPTTLDEC)) {
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INHDRERRORS);
		icmp_error(ifp, pkt->mbuf, ICMP_TIME_EXCEEDED,
			   ICMP_EXC_TTL, 0);
		return IPV4_ROUTE_LOOKUP_DROP;
	}

	/* Don't forward packets with unspecified source address */
	if (unlikely(!ip->saddr)) {
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INADDRERRORS);
		return IPV4_ROUTE_LOOKUP_DROP;
	}

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv4_route_lookup_features(
			    pkt,
			    vrf_to_ipv4_route_lookup_node(vrf)))
			return IPV4_ROUTE_LOOKUP_FINISH;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv4_route_lookup_no_dyn_features(
			    pkt,
			    vrf_to_ipv4_route_lookup_node(vrf)))
			return IPV4_ROUTE_LOOKUP_FINISH;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    ipv4_route_lookup_node_ptr,
			    vrf_to_ipv4_route_lookup_node(vrf),
			    pkt))
			return IPV4_ROUTE_LOOKUP_FINISH;
		break;
	}

	return IPV4_ROUTE_LOOKUP_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_route_lookup_process_common(struct pl_packet *pkt, void *context __unused,
				 enum pl_mode mode)
{
	return _ipv4_route_lookup_process_common(pkt, context, mode,
						 IPV4_LKUP_MODE_ROUTER);
}

ALWAYS_INLINE unsigned int
ipv4_route_lookup_process(struct pl_packet *pkt, void *context)
{
	return _ipv4_route_lookup_process_common(pkt, context, PL_MODE_REGULAR,
						 IPV4_LKUP_MODE_ROUTER);
}

ALWAYS_INLINE unsigned int
ipv4_route_lookup_host_process(struct pl_packet *pkt, void *context)
{
	return _ipv4_route_lookup_process_common(pkt, context, PL_MODE_REGULAR,
						 IPV4_LKUP_MODE_HOST);
}

static int
ipv4_route_lookup_feat_change(struct pl_node *node,
				   struct pl_feature_registration *feat,
				   enum pl_node_feat_action action)
{
	struct vrf *vrf = ipv4_route_lookup_node_to_vrf(node);

	return pl_node_feat_change_u16(&vrf->v_ip_post_rlkup_features,
				       feat, action);
}

ALWAYS_INLINE bool
ipv4_route_lookup_feat_iterate(struct pl_node *node, bool first,
			       unsigned int *feature_id, void **context,
			       void **storage_ctx)
{
	struct vrf *vrf = ipv4_route_lookup_node_to_vrf(node);

	if (first)
		*storage_ctx = NULL;

	return pl_node_feat_iterate_u16(&vrf->v_ip_post_rlkup_features, first,
					feature_id, context);
}

/* Register Node */
PL_REGISTER_NODE(ipv4_route_lookup_node) = {
	.name = "vyatta:ipv4-route-lookup",
	.type = PL_PROC,
	.handler = ipv4_route_lookup_process,
	.feat_change = ipv4_route_lookup_feat_change,
	.feat_iterate = ipv4_route_lookup_feat_iterate,
	.num_next = IPV4_ROUTE_LOOKUP_NUM,
	.next = {
		[IPV4_ROUTE_LOOKUP_ACCEPT] = "ipv4-post-route-lookup",
		[IPV4_ROUTE_LOOKUP_L4]     = "ipv4-l4",
		[IPV4_ROUTE_LOOKUP_LOCAL]  = "ipv4-local",
		[IPV4_ROUTE_LOOKUP_DROP]   = "term-drop",
		[IPV4_ROUTE_LOOKUP_FINISH] = "term-finish"
	}
};

/*
 * The use of a common processing function assumes these definitions
 * are all equivalent, so assert that.
 */
_Static_assert(IPV4_ROUTE_LOOKUP_NUM == (int)IPV4_ROUTE_LOOKUP_HOST_NUM,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV4_ROUTE_LOOKUP_ACCEPT == (int)IPV4_ROUTE_LOOKUP_HOST_ACCEPT,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV4_ROUTE_LOOKUP_L4 == (int)IPV4_ROUTE_LOOKUP_HOST_L4,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV4_ROUTE_LOOKUP_LOCAL == (int)IPV4_ROUTE_LOOKUP_HOST_LOCAL,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV4_ROUTE_LOOKUP_DROP == (int)IPV4_ROUTE_LOOKUP_HOST_DROP,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV4_ROUTE_LOOKUP_FINISH == (int)IPV4_ROUTE_LOOKUP_HOST_FINISH,
	       "route-lookup and route-lookup-host next node defs differ");

PL_REGISTER_NODE(ipv4_route_lookup_host_node) = {
	.name = "vyatta:ipv4-route-lookup-host",
	.type = PL_PROC,
	.handler = ipv4_route_lookup_host_process,
	.num_next = IPV4_ROUTE_LOOKUP_HOST_NUM,
	.next = {
		[IPV4_ROUTE_LOOKUP_HOST_ACCEPT] = "ipv4-post-route-lookup",
		[IPV4_ROUTE_LOOKUP_HOST_L4]     = "ipv4-l4",
		[IPV4_ROUTE_LOOKUP_HOST_LOCAL]  = "ipv4-local",
		[IPV4_ROUTE_LOOKUP_HOST_DROP]   = "term-drop",
		[IPV4_ROUTE_LOOKUP_HOST_FINISH] = "term-finish"
	}
};

struct pl_node_registration *const ipv4_route_lookup_node_ptr =
	&ipv4_route_lookup_node;
