/*
 * l3_v6_route_lookup.c
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/snmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdint.h>

#include "compiler.h"
#include "if_var.h"
#include "ip_mcast.h"
#include "netinet6/ip6_funcs.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "route_flags.h"
#include "route_v6.h"
#include "snmp_mib.h"
#include "vrf_internal.h"

struct pl_node;

enum ipv6_route_lookup_mode {
	IPV6_LKUP_MODE_ROUTER,
	IPV6_LKUP_MODE_HOST,
};

static inline struct pl_node *
vrf_to_ipv6_route_lookup_node(struct vrf *vrf)
{
	/* our imaginary node */
	return (struct pl_node *)vrf;
}

static inline struct vrf *
ipv6_route_lookup_node_to_vrf(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct vrf *)node;
}

static ALWAYS_INLINE unsigned int
_ipv6_route_lookup_process_common(struct pl_packet *pkt, void *context __unused,
				  enum pl_mode mode,
				  enum ipv6_route_lookup_mode lkup_mode)
{
	struct ip6_hdr *ip6 = pkt->l3_hdr;
	struct ifnet *ifp = pkt->in_ifp;
	struct next_hop *nxt;
	struct vrf *vrf;

	if (unlikely(ip6->ip6_nxt == IPPROTO_HOPOPTS)) {
		uint32_t rtalert = ~0u;

		if (ip6_hopopts_input(pkt->mbuf, ifp, &rtalert))
			return IPV6_ROUTE_LOOKUP_FINISH;

		if (rtalert != ~0u)
			return IPV6_ROUTE_LOOKUP_L4;
	}

	vrf = vrf_get_rcu_fast(pktmbuf_get_vrf(pkt->mbuf));
	nxt = rt6_lookup_fast(vrf, &ip6->ip6_dst, pkt->tblid, pkt->mbuf);

	pkt->nxt.v6 = nxt;

	/*
	 * if nxt == NULL, postpone sending icmp6 err
	 * till crypto out bound policy check is done
	 */
	if (nxt && unlikely(nxt->flags & RTF_LOCAL))
		return IPV6_ROUTE_LOOKUP_L4;

	if (unlikely(IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))) {
		IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INMCASTPKTS);
		mcast_ip6(ip6, ifp, pkt->mbuf);
		return IPV6_ROUTE_LOOKUP_FINISH;
	}

	/*
	 * Check hop limit
	 */
	if (unlikely(ip6->ip6_hlim <= IPV6_HLIMDEC)) {
		IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INHDRERRORS);
		icmp6_error(ifp, pkt->mbuf, ICMP6_TIME_EXCEEDED,
			    ICMP6_TIME_EXCEED_TRANSIT, htonl(0));
		return IPV6_ROUTE_LOOKUP_FINISH;
	}

	/*
	 * If invoked from forwarding disabled interface then drop
	 */
	switch (lkup_mode) {
	case IPV6_LKUP_MODE_ROUTER:
		break;
	case IPV6_LKUP_MODE_HOST:
		return IPV6_ROUTE_LOOKUP_DROP;
	}

	/*
	 * RFC 4291 - Source address of unspecified must never be forwarded.
	 */
	if (unlikely(IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src))) {
		IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INADDRERRORS);
		return IPV6_ROUTE_LOOKUP_DROP;
	}

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv6_route_lookup_features(
			    pkt,
			    vrf_to_ipv6_route_lookup_node(vrf)))
			return IPV6_ROUTE_LOOKUP_FINISH;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv6_route_lookup_no_dyn_features(
			    pkt,
			    vrf_to_ipv6_route_lookup_node(vrf)))
			return IPV6_ROUTE_LOOKUP_FINISH;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    ipv6_route_lookup_node_ptr,
			    vrf_to_ipv6_route_lookup_node(vrf),
			    pkt))
			return IPV6_ROUTE_LOOKUP_FINISH;
		break;
	}

	return IPV6_ROUTE_LOOKUP_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv6_route_lookup_process_common(struct pl_packet *pkt, void *context __unused,
				 enum pl_mode mode)
{
	return _ipv6_route_lookup_process_common(pkt, context, mode,
						 IPV6_LKUP_MODE_ROUTER);
}

ALWAYS_INLINE unsigned int
ipv6_route_lookup_process(struct pl_packet *pkt, void *context)
{
	return ipv6_route_lookup_process_common(pkt, context, PL_MODE_REGULAR);
}

ALWAYS_INLINE unsigned int
ipv6_route_lookup_host_process(struct pl_packet *pkt, void *context)
{
	return _ipv6_route_lookup_process_common(pkt, context, PL_MODE_REGULAR,
						 IPV6_LKUP_MODE_HOST);
}

static int
ipv6_route_lookup_feat_change(struct pl_node *node,
			      struct pl_feature_registration *feat,
			      enum pl_node_feat_action action)
{
	struct vrf *vrf = ipv6_route_lookup_node_to_vrf(node);

	return pl_node_feat_change_u16(&vrf->v_ipv6_post_rlkup_features,
				       feat, action);
}

ALWAYS_INLINE bool
ipv6_route_lookup_feat_iterate(struct pl_node *node, bool first,
			       unsigned int *feature_id, void **context,
			       void **storage_ctx)

{
	struct vrf *vrf = ipv6_route_lookup_node_to_vrf(node);

	if (first)
		*storage_ctx = NULL;

	return pl_node_feat_iterate_u16(&vrf->v_ipv6_post_rlkup_features,
					first, feature_id, context);
}

/* Register Node */
PL_REGISTER_NODE(ipv6_route_lookup_node) = {
	.name = "vyatta:ipv6-route-lookup",
	.type = PL_PROC,
	.handler = ipv6_route_lookup_process,
	.feat_change = ipv6_route_lookup_feat_change,
	.feat_iterate = ipv6_route_lookup_feat_iterate,
	.num_next = IPV6_ROUTE_LOOKUP_NUM,
	.next = {
		[IPV6_ROUTE_LOOKUP_ACCEPT] = "ipv6-post-route-lookup",
		[IPV6_ROUTE_LOOKUP_L4]     = "ipv6-l4",
		[IPV6_ROUTE_LOOKUP_DROP]   = "ipv6-drop",
		[IPV6_ROUTE_LOOKUP_FINISH] = "term-finish"
	}
};

/*
 * The use of a common processing function assumes these definitions
 * are all equivalent, so assert that.
 */
_Static_assert(IPV6_ROUTE_LOOKUP_NUM == (int)IPV6_ROUTE_LOOKUP_HOST_NUM,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV6_ROUTE_LOOKUP_ACCEPT == (int)IPV6_ROUTE_LOOKUP_HOST_ACCEPT,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV6_ROUTE_LOOKUP_L4 == (int)IPV6_ROUTE_LOOKUP_HOST_L4,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV6_ROUTE_LOOKUP_DROP == (int)IPV6_ROUTE_LOOKUP_HOST_DROP,
	       "route-lookup and route-lookup-host next node defs differ");
_Static_assert(IPV6_ROUTE_LOOKUP_FINISH == (int)IPV6_ROUTE_LOOKUP_HOST_FINISH,
	       "route-lookup and route-lookup-host next node defs differ");

PL_REGISTER_NODE(ipv6_route_lookup_host_node) = {
	.name = "vyatta:ipv6-route-lookup-host",
	.type = PL_PROC,
	.handler = ipv6_route_lookup_host_process,
	.num_next = IPV6_ROUTE_LOOKUP_HOST_NUM,
	.next = {
		[IPV6_ROUTE_LOOKUP_HOST_ACCEPT] = "ipv6-post-route-lookup",
		[IPV6_ROUTE_LOOKUP_HOST_L4]     = "ipv6-l4",
		[IPV6_ROUTE_LOOKUP_HOST_DROP]   = "ipv6-drop",
		[IPV6_ROUTE_LOOKUP_HOST_FINISH] = "term-finish"
	}
};

struct pl_node_registration *const ipv6_route_lookup_node_ptr =
	&ipv6_route_lookup_node;

struct pl_show_vrf_ctx {
	json_writer_t	*json;
	char		*vrfname;
};

static void
pl_show_ipv6_route_lookup(struct vrf *vrf, struct pl_show_vrf_ctx *ctx)
{
	json_writer_t *wr = ctx->json;
	vrfid_t vrfid = dp_vrf_get_vid(vrf);
	const char *vrfname;

	vrfname = (vrfid == VRF_DEFAULT_ID) ? "default" : vrf_get_name(vrfid);

	if (ctx->vrfname && strcmp(ctx->vrfname, vrfname) &&
	    strcmp(ctx->vrfname, "all"))
		return;

	jsonw_start_object(wr);
	jsonw_name(wr, vrfname);

	jsonw_start_array(wr);
	pl_node_iter_features(ipv6_route_lookup_node_ptr, vrf,
			      pl_print_feats, wr);
	jsonw_end_array(wr);

	jsonw_end_object(wr);
}

/*
 * show features ipv6_route_lookup [vrf <vrfname | default | all>]
 */
static int cmd_pl_show_feat_ipv6_route_lookup(struct pl_command *cmd)
{
	int argc = cmd->argc;
	char **argv = cmd->argv;
	char *opt, *vrfname = NULL;
	json_writer_t *wr;
	vrfid_t vrf_id;
	struct vrf *vrf;

	while (argc > 0) {
		opt = next_arg(&argc, &argv);

		if (!strcmp(opt, "vrf")) {
			vrfname = next_arg(&argc, &argv);
			if (!vrfname)
				return 0;
		}
	}

	wr = jsonw_new(cmd->fp);
	if (!wr)
		return 0;

	struct pl_show_vrf_ctx ctx = {
		.json = wr,
		.vrfname = vrfname,
	};

	jsonw_name(wr, "features");
	jsonw_start_object(wr);

	jsonw_name(wr, "vrf");
	jsonw_start_array(wr);

	VRF_FOREACH(vrf, vrf_id)
		pl_show_ipv6_route_lookup(vrf, &ctx);

	jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}

PL_REGISTER_OPCMD(pl_show_feat_ipv6_route_lookup) = {
	.cmd = "show features ipv6_route_lookup",
	.handler = cmd_pl_show_feat_ipv6_route_lookup,
};
