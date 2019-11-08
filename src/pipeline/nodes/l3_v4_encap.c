/*
 * l3_v4_encap.c
 *
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <linux/if_ether.h>
#include <linux/snmp.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stddef.h>

#include "compiler.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "route.h"
#include "route_flags.h"
#include "nh.h"
#include "arp.h"
#include "snmp_mib.h"

struct pl_node;

static inline struct pl_node *ifp_to_ipv4_encap_node(struct ifnet *ifp)
{
	/* our imaginary node */
	return (struct pl_node *)ifp;
}

static inline struct ifnet *ipv4_encap_node_to_ifp(struct pl_node *node)
{
	/* the node is a fiction of our imagination */
	return (struct ifnet *)node;
}

/*
 * Set the ether encapsulation on the packet.
 * Copy dest mac from NH lle if possible, otherwise try to trigger
 * L2 dest mac resolution, and set from that.
 */
static ALWAYS_INLINE bool
ipv4_encap_eth_from_nh4(struct rte_mbuf *mbuf, const struct next_hop *nh,
			in_addr_t addr)
{
	struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct ifnet *out_ifp = nh4_get_ifp(nh); /* Needed for VRRP */

	ether_addr_copy(&out_ifp->eth_addr, &eth_hdr->s_addr);

	/* If already resolved, use the link level encap */
	struct llentry *lle = nh4_get_lle(nh);
	if (likely(lle != NULL)) {
		if (llentry_copy_mac(lle, &eth_hdr->d_addr))
			return true;
	}

	/* Not yet resolved, so try to do so */
	if (likely(arpresolve_fast(out_ifp, mbuf, addr, &eth_hdr->d_addr) == 0))
		return true;

	return false;
}

/*
 * Returns false to indicate packet consumed.
 */
static ALWAYS_INLINE bool
ipv4_encap_features(struct pl_packet *pkt, enum pl_mode mode)
{
	struct ifnet *out_ifp = pkt->out_ifp;

	/* May be called with pkt->l2_proto != ETH_P_IP */

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv4_encap_features(
			    pkt, ifp_to_ipv4_encap_node(out_ifp)))
			return false;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv4_encap_no_dyn_features(
			    pkt, ifp_to_ipv4_encap_node(out_ifp)))
			return false;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_enabled_features(
			    ipv4_encap_node_ptr,
			    ifp_to_ipv4_encap_node(out_ifp),
			    pkt))
			return false;
		break;
	}

	return true;
}

static ALWAYS_INLINE unsigned int
ipv4_encap_process_internal(struct pl_packet *pkt, enum pl_mode mode)
{
	if (!ipv4_encap_features(pkt, mode))
		return IPV4_ENCAP_DROPPED;

	struct next_hop *nh = pkt->nxt.v4;
	struct ifnet *in_ifp = pkt->in_ifp;
	struct ifnet *out_ifp = pkt->out_ifp;
	struct rte_mbuf *mbuf = pkt->mbuf;
	uint16_t l2_proto = pkt->l2_proto;

	/* Get the nexthop address */
	in_addr_t addr;

	if (nh->flags & RTF_GATEWAY) {
		addr = nh->gateway;
	} else {
		struct iphdr *ip;

		ip = iphdr(mbuf);
		addr = ip->daddr;
	}

	/*
	 * If the interface has IFF_NOARP set then nexthop resolution
	 * isn't required and the interface output function is
	 * responsible for putting the encap on the packet.
	 */
	if (unlikely(out_ifp->if_flags & IFF_NOARP))
		return IPV4_ENCAP_L2_OUT;

	/* Is it mGRE? If so, performed here. */
	if (unlikely(out_ifp->if_type == IFT_TUNNEL_GRE)) {
		if (unlikely(!gre_tunnel_encap(in_ifp, out_ifp, &addr,
					       mbuf, l2_proto)))
			return IPV4_ENCAP_FAIL;
		return IPV4_ENCAP_L2_OUT;
	}

	/* Assume all other interface types use ethernet encap. */
	if (!ipv4_encap_eth_from_nh4(mbuf, nh, addr))
		return IPV4_ENCAP_FAIL;

	return IPV4_ENCAP_L2_OUT;
}

ALWAYS_INLINE unsigned int
ipv4_encap_process_common(struct pl_packet *pkt, enum pl_mode mode)
{
	struct ifnet *out_ifp = pkt->out_ifp;

	int rc = ipv4_encap_process_internal(pkt, mode);

	if (rc == IPV4_ENCAP_L2_OUT)
		IPSTAT_INC_IFP(out_ifp, IPSTATS_MIB_OUTFORWDATAGRAMS);

	return rc;
}

ALWAYS_INLINE unsigned int
ipv4_encap_only_process_common(struct pl_packet *pkt, enum pl_mode mode)
{
	return ipv4_encap_process_internal(pkt, mode);
}

ALWAYS_INLINE unsigned int
ipv4_encap_process(struct pl_packet *p)
{
	return ipv4_encap_process_common(p, PL_MODE_REGULAR);
}

ALWAYS_INLINE unsigned int
ipv4_encap_only_process(struct pl_packet *p)
{
	return ipv4_encap_only_process_common(p, PL_MODE_REGULAR);
}

static int
ipv4_encap_feat_change(struct pl_node *node,
		       struct pl_feature_registration *feat,
		       enum pl_node_feat_action action)
{
	struct ifnet *ifp = ipv4_encap_node_to_ifp(node);

	return pl_node_feat_change_u8(&ifp->ip_encap_features, feat,
				      action);
}

ALWAYS_INLINE bool
ipv4_encap_feat_iterate(struct pl_node *node, bool first,
			unsigned int *feature_id, void **context)
{
	struct ifnet *ifp = ipv4_encap_node_to_ifp(node);

	return pl_node_feat_iterate_u8(&ifp->ip_encap_features, first,
				       feature_id, context);
}

ALWAYS_INLINE bool
ipv4_encap_only_feat_iterate(struct pl_node *node, bool first,
			     unsigned int *feature_id, void **context)
{
	return ipv4_encap_feat_iterate(node, first, feature_id, context);
}

static struct pl_node *
ipv4_encap_node_lookup(const char *name)
{
	struct ifnet *ifp = ifnet_byifname(name);
	return ifp ? ifp_to_ipv4_encap_node(ifp) : NULL;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_encap_node) = {
	.name = "vyatta:ipv4-encap",
	.type = PL_PROC,
	.handler = ipv4_encap_process,
	.feat_change = ipv4_encap_feat_change,
	.feat_iterate = ipv4_encap_feat_iterate,
	.lookup_by_name = ipv4_encap_node_lookup,
	.num_next = IPV4_ENCAP_NUM,
	.next = {
		[IPV4_ENCAP_L2_OUT] = "l2-out",
		[IPV4_ENCAP_DROPPED] = "term-finish",
		[IPV4_ENCAP_FAIL] = "term-finish",
	}
};

/* Register Node */
PL_REGISTER_NODE(ipv4_encap_only_node) = {
	.name = "vyatta:ipv4-encap-only",
	.type = PL_PROC,
	.handler = ipv4_encap_only_process,
	.feat_iterate = ipv4_encap_only_feat_iterate,
	.num_next = IPV4_ENCAP_ONLY_NUM,
	.next = {
		[IPV4_ENCAP_ONLY_L2_OUT] = "term-noop",
		[IPV4_ENCAP_ONLY_DROPPED] = "term-finish",
		[IPV4_ENCAP_ONLY_FAIL] = "term-finish",
	}
};

struct pl_node_registration *const ipv4_encap_node_ptr = &ipv4_encap_node;
